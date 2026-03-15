//! bearer token auth for tcp listener
//!
//! generates a random token on first run, saves to ~/.zcli/zclid.token.
//! tcp requests must include `authorization: bearer <token>`.
//! unix socket requests bypass auth entirely.

use std::path::Path;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use tonic::Status;
use tower::{Layer, Service};
use tracing::warn;

const TOKEN_LEN: usize = 32; // 256 bits

/// load or generate the auth token
pub fn load_or_generate_token(path: &str) -> anyhow::Result<String> {
    let p = Path::new(path);
    if p.exists() {
        let token = std::fs::read_to_string(p)?.trim().to_string();
        if token.len() >= 32 {
            return Ok(token);
        }
    }

    // generate new token via getrandom (no fd needed)
    let mut bytes = [0u8; TOKEN_LEN];
    getrandom::getrandom(&mut bytes)?;
    let token = hex::encode(bytes);

    // create file with restrictive permissions atomically
    // (no race window where file exists but is world-readable)
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(p)?;
        f.write_all(token.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(p, &token)?;
    }

    Ok(token)
}

/// tower layer that checks bearer token with constant-time comparison
#[derive(Clone)]
pub struct AuthLayer {
    expected_bytes: Vec<u8>,
}

impl AuthLayer {
    pub fn new(token: String) -> Self {
        let expected = format!("Bearer {}", token);
        Self {
            expected_bytes: expected.into_bytes(),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            expected_bytes: self.expected_bytes.clone(),
            failure_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    expected_bytes: Vec<u8>,
    failure_count: Arc<AtomicU64>,
}

impl<S, B> Service<http::Request<B>> for AuthService<S>
where
    S: Service<http::Request<B>, Response = http::Response<tonic::body::BoxBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let provided = req
            .headers()
            .get("authorization")
            .and_then(|v| v.as_bytes().into())
            .unwrap_or(&[] as &[u8])
            .to_vec();

        let expected = &self.expected_bytes;

        // constant-time comparison: pad to equal length to prevent length leak
        let auth_ok = if provided.len() == expected.len() {
            provided.ct_eq(expected).into()
        } else {
            // still do a comparison to prevent timing leak on length mismatch
            let dummy = vec![0u8; expected.len()];
            let _ = dummy.ct_eq(expected);
            false
        };

        if !auth_ok {
            let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
            warn!("rejected auth attempt #{}", count);

            return Box::pin(async move {
                // rate limit: 100ms delay on failure to bound brute-force at 10/s
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let status = Status::unauthenticated("invalid or missing bearer token");
                Ok(status.to_http())
            });
        }

        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);
        Box::pin(inner.call(req))
    }
}
