//! Canonical JSON serialization + SHA-256 fingerprints.
//!
//! Fingerprints are content-addressed: the same logical scenario (regardless of map
//! insertion order or whitespace) produces the same id, so computations can be
//! deduplicated purely by inputs + policy fingerprint.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Convert any serializable value into canonical JSON:
/// objects emit keys in sorted order, no whitespace, non-ASCII is preserved literally.
pub fn to_canonical<T: Serialize>(value: &T) -> serde_json::Value {
    let v = serde_json::to_value(value).expect("scenario serialization cannot fail");
    canonicalize(v)
}

fn canonicalize(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, serde_json::Value> =
                std::collections::BTreeMap::new();
            for (k, child) in map {
                sorted.insert(k, canonicalize(child));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize).collect())
        }
        other => other,
    }
}

pub fn canonical_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(&to_canonical(value)).expect("canonical serialization")
}

pub fn fingerprint_hex<T: Serialize>(value: &T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_string(value).as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable double fingerprint for a scenario: input fingerprint and a combined
/// input+rules fingerprint (rules are part of the input here, but the combined key
/// also folds the engine semantics version so engine upgrades invalidate old runs).
pub const ENGINE_VERSION: u32 = 1;
