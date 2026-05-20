use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::hashing::derive_protocol_digest;

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

pub(crate) fn is_protocol_digest(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

pub(crate) fn derive_digest(namespace: &str, value: &Value) -> Option<String> {
    derive_protocol_digest(namespace, value).ok()
}

pub(crate) fn receiver_reference_key(value: &Value) -> Option<String> {
    let receiver_identity = string_field(value, "receiverIdentity")?;
    if receiver_identity.is_empty() {
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
    object_digest: Option<&str>,
    label: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let mut seen_receiver_references = BTreeSet::new();
    let Some(references) = references else {
        refused_objects.push(structural_refusal(
            format!("{label} must be an array."),
            object_digest,
        ));

        return refused_objects;
    };

    for receiver_reference in references {
        let Some(receiver_reference_key) = receiver_reference_key(receiver_reference) else {
            refused_objects.push(structural_refusal(
                format!("{label} contains an invalid receiver identity or roster position."),
                object_digest,
            ));
            continue;
        };
        if !seen_receiver_references.insert(receiver_reference_key) {
            refused_objects.push(structural_refusal(
                format!("{label} contains a duplicate receiver reference."),
                object_digest,
            ));
        }
    }

    refused_objects
}
