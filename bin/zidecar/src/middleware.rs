//! gRPC server middleware (Tower layers).
//!
//! Layers stack on `tonic::transport::Server::builder()` and wrap every RPC
//! handler — this keeps cross-cutting concerns (tracing, timeouts) at the
//! boundary instead of duplicated inside every handler body.

use std::time::Duration;
use tower::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Default inbound timeout when none is supplied. Bounds unary latency without
/// killing long-running server-streaming RPCs in practice — the TimeoutLayer
/// times the response future, not each streamed message, so block-range
/// streams continue to deliver beyond this window once the initial
/// `Response<Stream>` is constructed (which happens immediately).
pub const DEFAULT_INBOUND_TIMEOUT: Duration = Duration::from_secs(30);

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
