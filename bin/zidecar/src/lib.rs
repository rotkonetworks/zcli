//! zidecar library — re-exports for integration tests

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]

pub mod compact;
pub mod constants;
pub mod epoch;
pub mod error;
pub mod grpc_service;
pub mod header_chain;
pub mod lwd_service;
pub mod middleware;
pub mod prover;
pub mod ring_vrf;
pub mod storage;
pub mod witness;
pub mod zebrad;

// proto modules (same names as main.rs uses)
pub mod zidecar {
    tonic::include_proto!("zidecar.v1");
}

pub mod lightwalletd {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}
