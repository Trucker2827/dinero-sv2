//! Metal compute-backend for SV2 GPU mining on Apple Silicon.
//!
//! One `MetalMiner` owns a device + command queue + precompiled pipeline
//! and is cheap to clone (Metal objects are internally reference-counted).
//! Each `dispatch()` call launches `batch_size` threads, one nonce per
//! thread, and returns either the first found nonce or "no match".

#![cfg(target_os = "macos")]

use anyhow::{Context, Result};
use metal::{
    Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const KERNEL_SRC: &str = include_str!("../shaders/sha256d.metal");
const KERNEL_ENTRY: &str = "sha256d_mine";

#[derive(Clone)]
pub struct MetalMiner {
    inner: Arc<Inner>,
}

struct Inner {
    _device: Device,
    queue: CommandQueue,
    pipeline: ComputePipelineState,
    device_name: String,
    max_threads_per_group: u64,
    // Pre-allocated buffers, re-used across dispatches. Mutex keeps this
    // Sync; each dispatch takes the lock briefly to write inputs + read
    // outputs around the synchronous `wait_until_completed` below.
    buffers: Mutex<DispatchBuffers>,
}

struct DispatchBuffers {
    header: Buffer,         // 128 bytes
    target: Buffer,         // 32 bytes
    nonce_start: Buffer,    //  4 bytes (padded to 16 internally by Metal)
    result_nonce: Buffer,   //  4 bytes
    result_found: Buffer,   //  4 bytes
}

// Metal's `Device`, `CommandQueue`, etc. are internally synchronised and
// safe to use across threads — the Rust bindings just don't mark them
// Send/Sync, so we assert it here.
unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

pub struct DispatchOutcome {
    pub found: bool,
    pub nonce: u32,
    pub elapsed_ms: f64,
}

impl MetalMiner {
    pub fn init() -> Result<Self> {
        let device = Device::system_default().context("no default Metal device")?;
        let device_name = device.name().to_string();
        let queue = device.new_command_queue();
        let library = device
            .new_library_with_source(KERNEL_SRC, &CompileOptions::new())
            .map_err(|e| anyhow::anyhow!("metal library compile: {e}"))?;
        let function = library
            .get_function(KERNEL_ENTRY, None)
            .map_err(|e| anyhow::anyhow!("metal get_function({KERNEL_ENTRY}): {e}"))?;
        let pipeline = device
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|e| anyhow::anyhow!("metal new_compute_pipeline: {e}"))?;
        let max_threads_per_group = pipeline.max_total_threads_per_threadgroup();

        // Allocate all per-dispatch buffers once. StorageModeShared is
        // zero-copy on Apple Silicon's unified memory; CPU and GPU see
        // the same physical bytes without any copy.
        let buffers = DispatchBuffers {
            header: device.new_buffer(128, MTLResourceOptions::StorageModeShared),
            target: device.new_buffer(32, MTLResourceOptions::StorageModeShared),
            nonce_start: device.new_buffer(16, MTLResourceOptions::StorageModeShared),
            result_nonce: device.new_buffer(16, MTLResourceOptions::StorageModeShared),
            result_found: device.new_buffer(16, MTLResourceOptions::StorageModeShared),
        };

        Ok(MetalMiner {
            inner: Arc::new(Inner {
                _device: device,
                queue,
                pipeline,
                device_name,
                max_threads_per_group,
                buffers: Mutex::new(buffers),
            }),
        })
    }

    pub fn device_name(&self) -> &str {
        &self.inner.device_name
    }

    pub fn max_threads_per_group(&self) -> u64 {
        self.inner.max_threads_per_group
    }

    /// Launch a single Metal dispatch covering `batch_size` nonces starting
    /// at `nonce_start`. Blocks until the GPU finishes, then reads back
    /// the found-nonce output. `batch_size` should be picked so that the
    /// total wall-clock dispatch time is small enough to still respond to
    /// a `SetNewPrevHash` arrival (~10-20 ms is typical on Apple Silicon).
    pub fn dispatch(
        &self,
        header_bytes: &[u8; 128],
        target: &[u8; 32],
        nonce_start: u32,
        batch_size: u32,
    ) -> Result<DispatchOutcome> {
        let inner = &self.inner;
        let bufs = inner.buffers.lock().expect("metal buffers mutex");

        // Write inputs directly into the pre-allocated shared buffers.
        // The kernel reads `target` as eight u32 words and compares word-
        // wise to the SHA-256 state (which is big-endian). We store each
        // 4-byte group of `target` as a native u32 so that, on a little-
        // endian host, the kernel-side read sees the big-endian value.
        unsafe {
            std::ptr::copy_nonoverlapping(
                header_bytes.as_ptr(),
                bufs.header.contents() as *mut u8,
                128,
            );
            // Kernel's state[0..7] are raw SHA-256 output words, where
            // state[0] = BE interpretation of raw bytes 0-3. For the
            // kernel's `hash_meets_target` (iterating i=7..0) to match a
            // byte-order lexicographic `hash < share_target` check on
            // CPU, we lay out target[i] = BE u32 of share_target bytes
            // [i*4..i*4+4]. Solo miner's kernel uses the same mapping.
            let tgt_words = bufs.target.contents() as *mut u32;
            for i in 0..8 {
                let w = u32::from_be_bytes([
                    target[i * 4],
                    target[i * 4 + 1],
                    target[i * 4 + 2],
                    target[i * 4 + 3],
                ]);
                std::ptr::write(tgt_words.add(i), w);
            }
            std::ptr::write(bufs.nonce_start.contents() as *mut u32, nonce_start);
            std::ptr::write(bufs.result_nonce.contents() as *mut u32, 0);
            std::ptr::write(bufs.result_found.contents() as *mut u32, 0);
        }

        let t0 = Instant::now();
        let cmd = inner.queue.new_command_buffer();
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(&inner.pipeline);
        enc.set_buffer(0, Some(&bufs.header), 0);
        enc.set_buffer(1, Some(&bufs.target), 0);
        enc.set_buffer(2, Some(&bufs.result_nonce), 0);
        enc.set_buffer(3, Some(&bufs.result_found), 0);
        enc.set_buffer(4, Some(&bufs.nonce_start), 0);

        let threads_per_tg = std::cmp::min(inner.max_threads_per_group, 256u64);
        let grid = MTLSize {
            width: batch_size as u64,
            height: 1,
            depth: 1,
        };
        let tg = MTLSize {
            width: threads_per_tg,
            height: 1,
            depth: 1,
        };
        enc.dispatch_threads(grid, tg);
        enc.end_encoding();
        cmd.commit();
        cmd.wait_until_completed();
        let elapsed = t0.elapsed();

        let found = unsafe { std::ptr::read(bufs.result_found.contents() as *const u32) };
        let nonce = unsafe { std::ptr::read(bufs.result_nonce.contents() as *const u32) };

        Ok(DispatchOutcome {
            found: found != 0,
            nonce,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        })
    }
}
