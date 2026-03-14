//! gRPC middleware: request tracing

use tower_http::trace::TraceLayer;

/// create the request tracing layer configured for gRPC
pub fn trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::GrpcErrorsAsFailures>,
> {
    TraceLayer::new_for_grpc()
}
