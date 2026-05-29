use std::collections::BTreeSet;

use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

use crate::hashing::derive_protocol_hash;

use super::backend_status::structural_refusal;

pub(crate) fn object_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

pub(crate) fn string_field<'value>(value: &'value Value, field_name: &str) -> Option<&'value str> {
    object_map(value)?.get(field_name)?.as_str()
}

pub(crate) fn array_field<'value>(
    value: &'value Value,
    field_name: &str,
) -> Option<&'value Vec<Value>> {
    object_map(value)?.get(field_name)?.as_array()
}

pub(crate) fn required_json_field<'value>(
    value: &'value Value,
    field_name: &str,
    object_name: &str,
) -> crate::encoding::CanonicalResult<&'value Value> {
    object_map(value)
        .and_then(|object| object.get(field_name))
        .ok_or_else(|| invalid_json_field(format!("{object_name}.{field_name} is required")))
}

pub(crate) fn required_string_field<'value>(
    value: &'value Value,
    field_name: &str,
    object_name: &str,
) -> crate::encoding::CanonicalResult<&'value str> {
    string_field(value, field_name)
        .ok_or_else(|| invalid_json_field(format!("{object_name}.{field_name} must be a string")))
}

pub(crate) fn is_protocol_hash(value: &str) -> bool {
    value.len() == 128
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_nfc_normalized(value: &str) -> bool {
    value.nfc().eq(value.chars())
}

fn invalid_json_field(message: impl Into<String>) -> crate::encoding::CanonicalError {
    crate::encoding::CanonicalError::new(
        crate::encoding::CanonicalErrorCode::InvalidFixture,
        message,
    )
}

pub(crate) fn unsigned_decimal_string(value: &str) -> bool {
    value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(crate) fn positive_roster_position(value: &Value, field_name: &str) -> Option<u64> {
    let roster_position = object_map(value)?.get(field_name)?.as_u64()?;
    if roster_position == 0 {
        None
    } else {
        Some(roster_position)
    }
}

pub(crate) fn value_without_field(value: &Value, field_name: &str) -> Option<Value> {
    let object = object_map(value)?;
    let mut copied_object = object.clone();
    copied_object.remove(field_name);

    Some(Value::Object(copied_object))
}

pub(crate) fn value_without_fields(value: &Value, field_names: &[&str]) -> Option<Value> {
    let object = object_map(value)?;
    let mut copied_object = object.clone();
    for field_name in field_names {
        copied_object.remove(*field_name);
    }

    Some(Value::Object(copied_object))
}

pub(crate) fn derive_hash(namespace: &str, value: &Value) -> Option<String> {
    derive_protocol_hash(namespace, value).ok()
}

pub(crate) fn receiver_reference_key(value: &Value) -> Option<String> {
    let receiver_identity = string_field(value, "receiverIdentity")?;
    if receiver_identity.is_empty() || !is_nfc_normalized(receiver_identity) {
        return None;
    }

    Some(format!(
        "{}:{}",
        positive_roster_position(value, "receiverRosterPosition")?,
        receiver_identity,
    ))
}

pub(crate) fn collect_receiver_reference_refusals(
    references: Option<&Vec<Value>>,
    object_hash: Option<&str>,
    label: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let mut seen_receiver_references = BTreeSet::new();
    let Some(references) = references else {
        refused_objects.push(structural_refusal(
            format!("{label} must be an array."),
            object_hash,
        ));

        return refused_objects;
    };

    for receiver_reference in references {
        let Some(receiver_reference_key) = receiver_reference_key(receiver_reference) else {
            refused_objects.push(structural_refusal(
                format!("{label} contains an invalid receiver identity or roster position."),
                object_hash,
            ));
            continue;
        };
        if !seen_receiver_references.insert(receiver_reference_key) {
            refused_objects.push(structural_refusal(
                format!("{label} contains a duplicate receiver reference."),
                object_hash,
            ));
        }
    }

    refused_objects
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{collect_receiver_reference_refusals, is_protocol_hash, receiver_reference_key};

    #[test]
    fn protocol_hash_rejects_all_zero_placeholder() {
        assert!(!is_protocol_hash(&"0".repeat(128)));
        assert!(is_protocol_hash(&"1".repeat(128)));
        assert!(!is_protocol_hash(&"g".repeat(128)));
    }

    #[test]
    fn receiver_reference_keys_reject_non_normalized_identities() {
        let normalized_reference = json!({
            "receiverIdentity": "receiver-\u{00e9}",
            "receiverRosterPosition": 1,
        });
        assert_eq!(
            receiver_reference_key(&normalized_reference).as_deref(),
            Some("1:receiver-\u{00e9}")
        );

        let non_normalized_reference = json!({
            "receiverIdentity": "receiver-e\u{0301}",
            "receiverRosterPosition": 1,
        });
        assert!(receiver_reference_key(&non_normalized_reference).is_none());

        let references = vec![non_normalized_reference];
        let refused_objects =
            collect_receiver_reference_refusals(Some(&references), None, "receiver references");
        assert!(
            refused_objects.iter().any(|refusal| refusal["message"]
                .as_str()
                .is_some_and(|message| message.contains("invalid receiver identity"))),
            "non-normalized receiver identity must be rejected: {refused_objects:?}"
        );
    }
}
