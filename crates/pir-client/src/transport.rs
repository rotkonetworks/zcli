use std::{future::Future, pin::Pin};

use anyhow::Result;

// wasm32 is single-threaded and its `fetch`-backed transport holds `!Send`
// JS handles (js_sys::Function / JsFuture), so the `Send`/`Sync` bounds are
// dropped there. wasm-bindgen-futures drives such `!Send` futures via
// `spawn_local`. Native keeps the original `Send + Sync` contract.
#[cfg(not(target_arch = "wasm32"))]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<TransportResponse>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<TransportResponse>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub trait Transport: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a>;

    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> TransportFuture<'a>;
}

#[cfg(target_arch = "wasm32")]
pub trait Transport {
    fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a>;

    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> TransportFuture<'a>;
}

#[derive(Clone)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
