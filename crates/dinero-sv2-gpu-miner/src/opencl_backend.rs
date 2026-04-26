//! OpenCL compute-backend for SV2 GPU mining on Linux + Windows.
//!
//! Same interface as `metal_backend::MetalMiner`: one `OpenClMiner` owns
//! a context + queue + compiled kernel; cheap to clone (refcounted by
//! `ocl`). Each `dispatch()` enqueues `batch_size` work-items, one nonce
//! per thread, and returns either the first found nonce or "no match".
//!
//! The kernel source (`shaders/sha256d.cl`) is the same one used by the
//! solo miner in `dinero-solo-miner` and by `dinerod`'s built-in OpenCL
//! backend; layout: 128-byte BlockHeader v1 with nonce at offset 112,
//! 256-bit big-endian target at offset 0 of `target` buffer.

#![cfg(not(target_os = "macos"))]

use anyhow::{Context, Result};
use ocl::{flags, Buffer, Context as OclContext, Device, Kernel, Platform, Program, Queue};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const KERNEL_SRC: &str = include_str!("../shaders/sha256d.cl");
const KERNEL_ENTRY: &str = "sha256d_mine";

#[derive(Clone)]
pub struct OpenClMiner {
    inner: Arc<Inner>,
}

struct Inner {
    _context: OclContext,
    _device: Device,
    queue: Queue,
    program: Program,
    device_name: String,
    max_workgroup: u64,
    // Re-used buffers across dispatches; mutex serialises since kernel
    // enqueue + readback both write the result_found / result_nonce
    // outputs. One miner thread is the expected steady state.
    buffers: Mutex<DispatchBuffers>,
}

struct DispatchBuffers {
    header: Buffer<u8>,        // 128 bytes
    target: Buffer<u32>,       //   8 × u32 (big-endian words)
    result_nonce: Buffer<u32>, //   1 × u32
    result_found: Buffer<u32>, //   1 × u32
}

unsafe impl Send for Inner {}
unsafe impl Sync for Inner {}

pub struct DispatchOutcome {
    pub found: bool,
    pub nonce: u32,
    pub elapsed_ms: f64,
}

impl OpenClMiner {
    pub fn init() -> Result<Self> {
        // Pick the first GPU device on any platform. Order of platforms
        // is implementation-defined; we just take whatever the runtime
        // exposes first as a GPU. Multi-GPU fan-out is a follow-up.
        //
        // `Platform::list()` panics if `clGetPlatformIDs` fails (e.g.
        // ICD loader present but zero platforms registered, common on
        // headless servers). Catch the panic so we can return a clean
        // error instead of aborting the whole miner process.
        let platforms = std::panic::catch_unwind(Platform::list)
            .map_err(|_| {
                anyhow::anyhow!(
                    "no OpenCL platforms available — install GPU drivers (ROCm / NVIDIA / Mesa) \
                     or run dinero-sv2-miner (CPU) instead"
                )
            })?;
        let mut device: Option<(Platform, Device)> = None;
        for p in platforms {
            if let Ok(devs) = Device::list(p, Some(flags::DEVICE_TYPE_GPU)) {
                if let Some(d) = devs.into_iter().next() {
                    device = Some((p, d));
                    break;
                }
            }
        }
        let (platform, device) = device.context(
            "no OpenCL GPU device found on any platform — install drivers (ROCm/NVIDIA/Mesa)?",
        )?;

        let context = OclContext::builder()
            .platform(platform)
            .devices(device)
            .build()
            .context("opencl context builder")?;

        let queue = Queue::new(&context, device, None).context("opencl queue")?;

        let program = Program::builder()
            .src(KERNEL_SRC)
            .devices(device)
            .build(&context)
            .context("opencl kernel compile")?;

        let device_name = device
            .name()
            .unwrap_or_else(|_| "unknown OpenCL device".into());
        let max_workgroup = device
            .info(ocl::enums::DeviceInfo::MaxWorkGroupSize)
            .map(|v| match v {
                ocl::enums::DeviceInfoResult::MaxWorkGroupSize(n) => n as u64,
                _ => 256,
            })
            .unwrap_or(256);

        // Allocate buffers once; subsequent dispatches write inputs,
        // launch, read outputs.
        let header = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_ONLY | flags::MEM_HOST_WRITE_ONLY)
            .len(128)
            .build()
            .context("opencl header buffer")?;
        let target = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_ONLY | flags::MEM_HOST_WRITE_ONLY)
            .len(8)
            .build()
            .context("opencl target buffer")?;
        let result_nonce = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_WRITE)
            .len(1)
            .build()
            .context("opencl result_nonce buffer")?;
        let result_found = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_WRITE)
            .len(1)
            .build()
            .context("opencl result_found buffer")?;

        Ok(OpenClMiner {
            inner: Arc::new(Inner {
                _context: context,
                _device: device,
                queue,
                program,
                device_name,
                max_workgroup,
                buffers: Mutex::new(DispatchBuffers {
                    header,
                    target,
                    result_nonce,
                    result_found,
                }),
            }),
        })
    }

    pub fn device_name(&self) -> &str {
        &self.inner.device_name
    }

    pub fn max_threads_per_group(&self) -> u64 {
        self.inner.max_workgroup
    }

    pub fn dispatch(
        &self,
        header_bytes: &[u8; 128],
        target: &[u8; 32],
        nonce_start: u32,
        batch_size: u32,
    ) -> Result<DispatchOutcome> {
        let inner = &self.inner;
        let bufs = inner.buffers.lock().expect("opencl buffers mutex");

        // Pack target as 8 big-endian u32 words — same layout the
        // kernel's `hash_meets_target` walks (state[7]→state[0] BE
        // comparison; `target[i]` is the BE u32 of target_bytes[i*4..]).
        let mut target_words = [0u32; 8];
        for i in 0..8 {
            target_words[i] = u32::from_be_bytes([
                target[i * 4],
                target[i * 4 + 1],
                target[i * 4 + 2],
                target[i * 4 + 3],
            ]);
        }

        bufs.header
            .write(&header_bytes[..])
            .enq()
            .context("write header")?;
        bufs.target
            .write(&target_words[..])
            .enq()
            .context("write target")?;
        bufs.result_nonce.write(&[0u32][..]).enq().context("clear result_nonce")?;
        bufs.result_found.write(&[0u32][..]).enq().context("clear result_found")?;

        let local_size = std::cmp::min(inner.max_workgroup, 256) as usize;
        // Round global size up to a multiple of local_size — OpenCL 1.2
        // requires it. Excess work-items still hash, but their nonce
        // goes past `nonce_start + batch_size`; benign.
        let global_size = (batch_size as usize).div_ceil(local_size) * local_size;

        let kernel = Kernel::builder()
            .program(&inner.program)
            .name(KERNEL_ENTRY)
            .queue(inner.queue.clone())
            .global_work_size(global_size)
            .local_work_size(local_size)
            .arg(&bufs.header)
            .arg(&bufs.target)
            .arg(nonce_start)
            .arg(&bufs.result_nonce)
            .arg(&bufs.result_found)
            .build()
            .context("opencl kernel build")?;

        let t0 = Instant::now();
        unsafe {
            kernel.cmd().enq().context("opencl kernel enqueue")?;
        }
        inner.queue.finish().context("opencl queue finish")?;
        let elapsed = t0.elapsed();

        let mut found = [0u32; 1];
        let mut nonce = [0u32; 1];
        bufs.result_found.read(&mut found[..]).enq().context("read result_found")?;
        bufs.result_nonce.read(&mut nonce[..]).enq().context("read result_nonce")?;

        Ok(DispatchOutcome {
            found: found[0] != 0,
            nonce: nonce[0],
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        })
    }
}
