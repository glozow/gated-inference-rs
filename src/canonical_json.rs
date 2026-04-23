//! Canonical JSON serialization matching the Python reference:
//!
//!   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
//!
//! Properties:
//!   - keys sorted ascending (bytewise) at every object level
//!   - compact separators (no whitespace)
//!   - UTF-8 bytes; non-ASCII emitted raw (serde_json's default)
//!
//! Caveat: floating-point numbers serialize differently between Python's repr
//! and Rust's ryu. This format is only safe for payloads containing strings,
//! integers, booleans, nulls, arrays, and nested objects. Avoid floats in
//! anything you sign.

use serde_json::{Map, Value};

/// Serialize a JSON value to canonical bytes.
pub fn to_bytes(value: &Value) -> Vec<u8> {
    let sorted = sort_keys(value);
    serde_json::to_vec(&sorted).expect("serde_json::to_vec is infallible on owned Value")
}

fn sort_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> =
                map.iter().map(|(k, v)| (k.clone(), sort_keys(v))).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = Map::with_capacity(entries.len());
            for (k, v) in entries {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_top_level_keys() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        assert_eq!(to_bytes(&v), br#"{"a":2,"b":1,"c":3}"#.to_vec());
    }

    #[test]
    fn sorts_nested_keys() {
        let v = json!({ "outer": { "z": 1, "a": 2 }, "a": 1 });
        assert_eq!(to_bytes(&v), br#"{"a":1,"outer":{"a":2,"z":1}}"#.to_vec());
    }

    #[test]
    fn no_whitespace_between_tokens() {
        let v = json!({ "a": [1, 2, 3], "b": "hello" });
        assert_eq!(to_bytes(&v), br#"{"a":[1,2,3],"b":"hello"}"#.to_vec());
    }

    #[test]
    fn preserves_non_ascii_raw() {
        let v = json!({ "k": "café" });
        assert_eq!(to_bytes(&v), "{\"k\":\"café\"}".as_bytes().to_vec());
    }

    #[test]
    fn matches_python_reference_shape() {
        // Mirrors the shape the Python client produces.
        let v = json!({
            "prompt": "hi",
            "nonce": "abc123",
            "timestamp": 1_700_000_000
        });
        assert_eq!(
            to_bytes(&v),
            br#"{"nonce":"abc123","prompt":"hi","timestamp":1700000000}"#.to_vec()
        );
    }
}
