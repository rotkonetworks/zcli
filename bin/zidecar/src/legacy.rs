//! Clear answers for the RPCs that were removed with the Ligerito/NOMT proofs.
//!
//! Without this layer a removed method still answers UNIMPLEMENTED (tonic
//! does that for any method it does not know), but with an empty message.
//! Released clients then report "grpc status 12: unknown error", which tells
//! the person running zcli or zclid nothing about what to do.
//!
//! This layer answers the same status, immediately, with a message that says
//! the method was removed and the client needs an upgrade. It changes no
//! behaviour a client relies on:
//!
//! - zafu 28.x treats any error from these calls as "proof verification
//!   unavailable, will retry" and keeps syncing, as long as the message does
//!   not look like an integrity failure. The message below avoids every phrase
//!   its classifier matches (tested).
//! - zcli/zclid 0.9.x fail their sync on GetHeaderProof whatever the answer;
//!   the only thing a server can improve for them is the error they print.
//!
//! Only POSTs to the retired `zidecar.v1.Zidecar` paths are answered here.
//! Everything else, including CORS preflights, goes to the real services.

use std::task::{Context, Poll};

use futures::future::Either;
use http::{header, HeaderValue, Request, Response};
use tower::{Layer, Service};

/// The RPCs removed from `zidecar.v1.Zidecar` along with Ligerito and NOMT.
pub const REMOVED_RPCS: &[&str] = &[
    "GetHeaderProof",
    "GetTrustlessStateProof",
    "GetVerifiedBlocks",
    "GetCheckpoint",
    "GetEpochBoundary",
    "GetEpochBoundaries",
    "GetCommitmentProof",
    "GetCommitmentProofs",
    "GetNullifierProof",
    "GetNullifierProofs",
];

const SERVICE_PREFIX: &str = "/zidecar.v1.Zidecar/";

/// gRPC status UNIMPLEMENTED.
const UNIMPLEMENTED: &str = "12";

/// Printable ASCII only, and no `%`: zcli prints the header as-is and zafu
/// runs it through decodeURIComponent, so both show exactly this text.
pub const REMOVED_MESSAGE: &str = "removed from zidecar: the Ligerito header \
    proofs and NOMT state proofs are retired. Upgrade the client (zcli/zclid \
    newer than 0.9.0).";

/// The retired method named by `path`, if it is one.
pub fn removed_rpc(path: &str) -> Option<&'static str> {
    let method = path.strip_prefix(SERVICE_PREFIX)?;
    REMOVED_RPCS.iter().copied().find(|m| *m == method)
}

/// Trailers-only UNIMPLEMENTED answer for a retired method. Valid for gRPC
/// over HTTP/2 and for gRPC-web, which both read the status from headers when
/// the body is empty.
pub fn removed_response<ReqBody>(req: &Request<ReqBody>, method: &str) -> Response<tonic::body::BoxBody> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .filter(|v| v.as_bytes().starts_with(b"application/grpc"))
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/grpc"));
    let is_web = content_type.as_bytes().starts_with(b"application/grpc-web");

    let mut resp = Response::new(tonic::body::empty_body());
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, content_type);
    h.insert("grpc-status", HeaderValue::from_static(UNIMPLEMENTED));
    let message = format!("{method} {REMOVED_MESSAGE}");
    if let Ok(v) = HeaderValue::from_str(&message) {
        h.insert("grpc-message", v);
    }
    // Same CORS answer tonic-web gives for the live methods, so a browser
    // can read the status instead of seeing an opaque network error.
    if is_web {
        if let Some(origin) = req.headers().get(header::ORIGIN).cloned() {
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            h.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
            h.insert(header::VARY, HeaderValue::from_static("origin"));
        }
        h.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("grpc-status,grpc-message,grpc-status-details-bin"),
        );
    }
    resp
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RemovedRpcLayer;

impl<S> Layer<S> for RemovedRpcLayer {
    type Service = RemovedRpc<S>;
    fn layer(&self, inner: S) -> Self::Service {
        RemovedRpc { inner }
    }
}

#[derive(Clone, Debug)]
pub struct RemovedRpc<S> {
    inner: S,
}

impl<S, ReqBody> Service<Request<ReqBody>> for RemovedRpc<S>
where
    S: Service<Request<ReqBody>, Response = Response<tonic::body::BoxBody>>,
{
    type Response = Response<tonic::body::BoxBody>;
    type Error = S::Error;
    type Future = Either<std::future::Ready<Result<Self::Response, S::Error>>, S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        if req.method() == http::Method::POST {
            if let Some(method) = removed_rpc(req.uri().path()) {
                return Either::Left(std::future::ready(Ok(removed_response(&req, method))));
            }
        }
        Either::Right(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use tower::ServiceExt;

    fn inner() -> impl Service<
        Request<()>,
        Response = Response<tonic::body::BoxBody>,
        Error = Infallible,
        Future = impl Send,
    > + Clone {
        tower::service_fn(|_req: Request<()>| async {
            let mut r = Response::new(tonic::body::empty_body());
            r.headers_mut().insert("x-inner", HeaderValue::from_static("1"));
            Ok::<_, Infallible>(r)
        })
    }

    fn req(method: http::Method, path: &str, ct: &str, origin: Option<&str>) -> Request<()> {
        let mut b = Request::builder().method(method).uri(path).header(header::CONTENT_TYPE, ct);
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(()).unwrap()
    }

    fn hdr<'a>(r: &'a Response<tonic::body::BoxBody>, k: &str) -> Option<&'a str> {
        r.headers().get(k).and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn every_removed_rpc_answers_unimplemented_with_a_message() {
        for m in REMOVED_RPCS {
            let path = format!("/zidecar.v1.Zidecar/{m}");
            let r = RemovedRpcLayer
                .layer(inner())
                .oneshot(req(http::Method::POST, &path, "application/grpc", None))
                .await
                .unwrap();
            assert_eq!(r.status(), http::StatusCode::OK, "{m}");
            assert_eq!(hdr(&r, "x-inner"), None, "{m} reached the real service");
            assert_eq!(hdr(&r, "grpc-status"), Some("12"), "{m}");
            let msg = hdr(&r, "grpc-message").expect("message");
            assert!(msg.starts_with(m) && msg.contains("Upgrade the client"), "{msg}");
            assert_eq!(hdr(&r, "content-type"), Some("application/grpc"));
        }
    }

    #[tokio::test]
    async fn grpc_web_keeps_its_content_type_and_cors() {
        let r = RemovedRpcLayer
            .layer(inner())
            .oneshot(req(
                http::Method::POST,
                "/zidecar.v1.Zidecar/GetHeaderProof",
                "application/grpc-web+proto",
                Some("chrome-extension://abc"),
            ))
            .await
            .unwrap();
        assert_eq!(hdr(&r, "content-type"), Some("application/grpc-web+proto"));
        assert_eq!(hdr(&r, "access-control-allow-origin"), Some("chrome-extension://abc"));
        assert!(hdr(&r, "access-control-expose-headers").unwrap().contains("grpc-message"));
    }

    #[tokio::test]
    async fn live_methods_and_preflights_reach_the_real_services() {
        for (method, path) in [
            (http::Method::POST, "/zidecar.v1.Zidecar/GetTip"),
            (http::Method::POST, "/zidecar.v1.Zidecar/GetFlyClientProof"),
            (http::Method::POST, "/zidecar.v1.Zidecar/GetHeaderProofs"),
            (http::Method::POST, "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo"),
            (http::Method::OPTIONS, "/zidecar.v1.Zidecar/GetHeaderProof"),
        ] {
            let r = RemovedRpcLayer
                .layer(inner())
                .oneshot(req(method.clone(), path, "application/grpc-web+proto", None))
                .await
                .unwrap();
            assert_eq!(hdr(&r, "x-inner"), Some("1"), "{method} {path}");
        }
    }

    /// zafu 28.x escalates a proof-call error to a hard sync failure when the
    /// message matches this classifier (zcash-worker.ts, verifySyncProofs
    /// catch): /proof root mismatch|unrequested|duplicate|count mismatch|proof invalid/i
    /// Anything else is "unavailable, will retry". Our message must stay on
    /// the retry side, and must survive zcli (raw) and zafu
    /// (decodeURIComponent) unchanged.
    #[test]
    fn message_stays_on_zafus_retry_path() {
        for m in REMOVED_RPCS {
            let full = format!("gRPC {m}: {m} {REMOVED_MESSAGE}").to_lowercase();
            for phrase in [
                "proof root mismatch",
                "unrequested",
                "duplicate",
                "count mismatch",
                "proof invalid",
            ] {
                assert!(!full.contains(phrase), "{m}: message contains {phrase:?}");
            }
        }
        assert!(REMOVED_MESSAGE.bytes().all(|b| (0x20..0x7f).contains(&b) && b != b'%'));
    }
}
