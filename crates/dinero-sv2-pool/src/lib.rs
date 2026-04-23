//! Library surface for `dinero-sv2-pool`.
//!
//! The crate primarily exists as a binary (`main.rs`); the lib target
//! is only here so integration tests and other crates can reuse the
//! pool's JSON-RPC client, block assembly, target math, and share
//! accounting without duplicating them.

pub mod accounting;
pub mod block;
pub mod mapper;
pub mod rpc;
pub mod target;
