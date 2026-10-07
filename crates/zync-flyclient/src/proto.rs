//! zidecar's `GetFlyClientProof` messages (bin/zidecar/proto/zidecar.proto),
//! declared by hand so a wasm build needs no protoc. Field tags must match
//! the .proto.

use super::proof::{EpochProof, FlyClientProof, LeafProof};
use super::{FlyError, FlyResult};

#[derive(Clone, PartialEq, prost::Message)]
pub struct FlyLeaf {
    #[prost(uint64, tag = "1")]
    pub index: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub header: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub leaf: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub path: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FlyEpoch {
    #[prost(uint32, tag = "1")]
    pub activation: u32,
    #[prost(uint32, tag = "2")]
    pub branch_id: u32,
    #[prost(uint64, tag = "3")]
    pub n_leaves: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub commit_header: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub auth_data_root: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "6")]
    pub peaks: Vec<Vec<u8>>,
    #[prost(message, repeated, tag = "7")]
    pub leaves: Vec<FlyLeaf>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FlyClientProofResponse {
    #[prost(message, repeated, tag = "1")]
    pub epochs: Vec<FlyEpoch>,
    #[prost(uint32, tag = "2")]
    pub anchor_height: u32,
}

/// A decoded `FlyClientProofResponse`.
pub struct Response {
    pub proof: FlyClientProof,
    pub anchor_height: u32,
}

/// An empty field means "absent" (Heartwood/Canopy epochs).
fn auth_data_root(b: &[u8]) -> FlyResult<Option<[u8; 32]>> {
    match b.len() {
        0 => Ok(None),
        32 => Ok(Some(b.try_into().expect("32 bytes"))),
        _ => Err(FlyError::Tree("auth data root is not 32 bytes")),
    }
}

/// Decode a `FlyClientProofResponse` from its protobuf bytes.
pub fn decode_response(bytes: &[u8]) -> FlyResult<Response> {
    let r = <FlyClientProofResponse as prost::Message>::decode(bytes)
        .map_err(|_| FlyError::Epoch("response is not a FlyClientProofResponse"))?;
    let epochs = r
        .epochs
        .into_iter()
        .map(|e| {
            Ok(EpochProof {
                activation: e.activation,
                branch_id: e.branch_id,
                n_leaves: e.n_leaves,
                commit_header: e.commit_header,
                auth_data_root: auth_data_root(&e.auth_data_root)?,
                peaks: e.peaks,
                leaves: e
                    .leaves
                    .into_iter()
                    .map(|l| LeafProof {
                        index: l.index,
                        header: l.header,
                        leaf: l.leaf,
                        path: l.path,
                    })
                    .collect(),
            })
        })
        .collect::<FlyResult<Vec<_>>>()?;
    Ok(Response {
        proof: FlyClientProof { epochs },
        anchor_height: r.anchor_height,
    })
}
