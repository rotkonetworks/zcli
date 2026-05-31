//! gRPC server middleware (Tower layers).
//!
//! Layers stack on `tonic::transport::Server::builder()` and wrap every RPC
//! handler — this keeps cross-cutting concerns (tracing, timeouts) at the
//! boundary instead of duplicated inside every handler body.

use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Default inbound timeout when none is supplied. Bounds unary latency without
/// killing long-running server-streaming RPCs in practice — the TimeoutLayer
/// times the response future, not each streamed message, so block-range
/// streams continue to deliver beyond this window once the initial
/// `Response<Stream>` is constructed (which happens immediately).
pub const DEFAULT_INBOUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default ceiling on concurrent in-flight RPCs per server. Bounds resource
/// usage so a runaway client can't queue unbounded work; new requests wait
/// (queue) until a slot frees, which is gentler than load-shedding for
/// wallet clients that interpret transport errors as connection problems
/// and reconnect more aggressively than they'd retry a single RPC.
pub const DEFAULT_MAX_CONCURRENT_RPCS: usize = 256;

/// gRPC request tracing — uses tower-http's gRPC-aware error classification so
/// gRPC status codes (rather than HTTP) decide what counts as a failure.
pub fn trace_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::GrpcErrorsAsFailures>>
{
    TraceLayer::new_for_grpc()
}

/// Inbound request timeout. Pair with a generous default so server-streaming
/// RPCs aren't capped mid-stream.
pub fn timeout_layer(d: Duration) -> TimeoutLayer {
    TimeoutLayer::new(d)
}

/// Cap simultaneous in-flight RPCs. When at capacity the layer's `poll_ready`
/// is `Pending` — requests queue rather than fail-fast, which matches wallet
/// client retry semantics better than load-shedding would.
pub fn concurrency_limit_layer(max: usize) -> ConcurrencyLimitLayer {
    ConcurrencyLimitLayer::new(max)
}
