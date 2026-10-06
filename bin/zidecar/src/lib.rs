//! zidecar library — re-exports for integration tests

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]

pub mod compact;
pub mod constants;
pub mod error;
pub mod grpc_service;
pub mod history;
pub mod legacy;
pub mod lwd_service;
pub mod middleware;
pub mod orchard_tree;
pub mod rendezvous;
pub mod ring_vrf;
pub mod storage;
pub mod witness;
pub mod zakura_indexer;
pub mod zebrad;

// proto modules (same names as main.rs uses)
#[allow(clippy::result_large_err, clippy::double_must_use)]
pub mod zidecar {
    tonic::include_proto!("zidecar.v1");
}

#[allow(clippy::result_large_err, clippy::double_must_use)]
pub mod lightwalletd {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

// Zakura node `Indexer` gRPC client (zebra.indexer.rpc). Optional; only used
// when --zakura-indexer-url is set.
pub mod zakura_indexer_proto {
    tonic::include_proto!("zebra.indexer.rpc");
}
