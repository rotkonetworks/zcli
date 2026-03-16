// frost.rs — thin re-export layer over frost-spend
//
// all orchestration logic lives in frost_spend::orchestrate.
// zcli just wraps errors and provides CLI-specific formatting.

pub use frost_spend::orchestrate;

// re-export core types for any zcli code that needs them directly
pub use frost_spend::{
    frost, frost_keys, dkg, round1, round2,
    aggregate, Identifier, SigningPackage,
    RandomizedParams, Randomizer,
};
pub use frost_spend::message::SignedMessage;
