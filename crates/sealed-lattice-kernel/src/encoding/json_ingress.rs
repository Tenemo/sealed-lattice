use core::fmt;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use super::{CanonicalError, CanonicalErrorCode, CanonicalResult};

pub(super) const MAXIMUM_TRANSCRIPT_CORE_COMMAND_BYTE_LENGTH: usize = 64 * 1024 * 1024;

const DUPLICATE_FIELD_ERROR_MARKER: &str = "sealed-lattice duplicate JSON field";
const UNSAFE_INTEGER_ERROR_MARKER: &str = "sealed-lattice unsafe JSON integer";
const NESTING_DEPTH_ERROR_MARKER: &str = "sealed-lattice JSON nesting depth";
const MAXIMUM_INTEROPERABLE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAXIMUM_COMMAND_JSON_CONTAINER_DEPTH: u16 = 64;

pub(super) fn parse_transcript_core_request(input: &[u8]) -> CanonicalResult<Value> {
    parse_transcript_core_request_with_limit(input, MAXIMUM_TRANSCRIPT_CORE_COMMAND_BYTE_LENGTH)
}

fn parse_transcript_core_request_with_limit(
    input: &[u8],
    maximum_byte_length: usize,
) -> CanonicalResult<Value> {
    if input.len() > maximum_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "command JSON exceeds the accepted byte length",
        ));
    }

    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let request = DuplicateRejectingJsonValueSeed { container_depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(map_json_ingress_error)?;
    deserializer.end().map_err(map_json_ingress_error)?;
    if !request.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "command JSON must be an object",
        ));
    }
    Ok(request)
}

fn map_json_ingress_error(error: serde_json::Error) -> CanonicalError {
    let error_message = error.to_string();
    if error_message.contains(DUPLICATE_FIELD_ERROR_MARKER) {
        return CanonicalError::new(
            CanonicalErrorCode::DuplicateField,
            "command JSON contains a duplicate field",
        );
    }
    if error_message.contains(UNSAFE_INTEGER_ERROR_MARKER) {
        return CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "command JSON integer is outside the interoperable safe range",
        );
    }
    if error_message.contains(NESTING_DEPTH_ERROR_MARKER) {
        return CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "command JSON exceeds the accepted nesting depth",
        );
    }
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        format!("command JSON is invalid: {error}"),
    )
}

#[derive(Debug, Clone, Copy)]
struct DuplicateRejectingJsonValueSeed {
    container_depth: u16,
}

impl<'de> DeserializeSeed<'de> for DuplicateRejectingJsonValueSeed {
    type Value = Value;

    fn deserialize<Deserializer>(
        self,
        deserializer: Deserializer,
    ) -> Result<Value, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJsonValueVisitor {
            container_depth: self.container_depth,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct DuplicateRejectingJsonValueVisitor {
    container_depth: u16,
}

impl<'de> Visitor<'de> for DuplicateRejectingJsonValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an interoperable JSON value without duplicate object fields")
    }

    fn visit_bool<Error>(self, value: bool) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        Ok(Value::Bool(value))
    }

    fn visit_i64<Error>(self, value: i64) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        if value.unsigned_abs() > MAXIMUM_INTEROPERABLE_JSON_INTEGER {
            return Err(Error::custom(UNSAFE_INTEGER_ERROR_MARKER));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<Error>(self, value: u64) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        if value > MAXIMUM_INTEROPERABLE_JSON_INTEGER {
            return Err(Error::custom(UNSAFE_INTEGER_ERROR_MARKER));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<Error>(self, value: f64) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        if value.fract() == 0.0 && value.abs() > MAXIMUM_INTEROPERABLE_JSON_INTEGER as f64 {
            return Err(Error::custom(UNSAFE_INTEGER_ERROR_MARKER));
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| Error::custom("JSON number is not finite"))
    }

    fn visit_str<Error>(self, value: &str) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<Error>(self, value: String) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        Ok(Value::String(value))
    }

    fn visit_none<Error>(self) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_unit<Error>(self) -> Result<Value, Error>
    where
        Error: serde::de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_some<Deserializer>(
        self,
        deserializer: Deserializer,
    ) -> Result<Value, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        DuplicateRejectingJsonValueSeed {
            container_depth: self.container_depth,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<Sequence>(self, mut sequence: Sequence) -> Result<Value, Sequence::Error>
    where
        Sequence: SeqAccess<'de>,
    {
        if self.container_depth >= MAXIMUM_COMMAND_JSON_CONTAINER_DEPTH {
            return Err(Sequence::Error::custom(NESTING_DEPTH_ERROR_MARKER));
        }
        let child_seed = DuplicateRejectingJsonValueSeed {
            container_depth: self.container_depth + 1,
        };
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(child_seed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<Object>(self, mut object: Object) -> Result<Value, Object::Error>
    where
        Object: MapAccess<'de>,
    {
        if self.container_depth >= MAXIMUM_COMMAND_JSON_CONTAINER_DEPTH {
            return Err(Object::Error::custom(NESTING_DEPTH_ERROR_MARKER));
        }
        let child_seed = DuplicateRejectingJsonValueSeed {
            container_depth: self.container_depth + 1,
        };
        let mut values = Map::new();
        while let Some(field_name) = object.next_key::<String>()? {
            if values.contains_key(&field_name) {
                return Err(Object::Error::custom(DUPLICATE_FIELD_ERROR_MARKER));
            }
            let value = object.next_value_seed(child_seed)?;
            values.insert(field_name, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_fields_refuse_at_every_object_depth() {
        for request in [
            br#"{"command":"DescribeBgvRnsParameters","command":"DeriveCanonicalObjectHash"}"#.as_slice(),
            br#"{"command":"DeriveCanonicalObjectHash","value":{"objectType":"CanonicalJsonTestObject","objectType":"Other"}}"#.as_slice(),
        ] {
            let error = parse_transcript_core_request(request)
                .expect_err("duplicate JSON fields must refuse");
            assert_eq!(error.code, CanonicalErrorCode::DuplicateField);
        }
    }

    #[test]
    fn non_interoperable_integer_literals_refuse_before_command_dispatch() {
        for unsafe_integer in ["9007199254740992", "-9007199254740992", "1e20"] {
            let request =
                format!("{{\"command\":\"DescribeBgvRnsParameters\",\"value\":{unsafe_integer}}}");
            let error = parse_transcript_core_request(request.as_bytes())
                .expect_err("unsafe JSON integer must refuse");
            assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        }
    }

    #[test]
    fn malformed_json_refuses_as_an_invalid_protocol_object() {
        let error = parse_transcript_core_request(br#"{"#)
            .expect_err("truncated JSON must refuse before command dispatch");
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);

        for scalar_request in [
            b"null".as_slice(),
            br#""DescribeBgvRnsParameters""#.as_slice(),
            b"[]".as_slice(),
        ] {
            let error = parse_transcript_core_request(scalar_request)
                .expect_err("a command request must be an object");
            assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        }
    }

    #[test]
    fn request_nesting_depth_accepts_the_exact_boundary_and_refuses_one_more_container() {
        let request_with_array_depth = |array_depth: usize| {
            format!(
                "{{\"command\":\"DescribeBgvRnsParameters\",\"nested\":{}null{}}}",
                "[".repeat(array_depth),
                "]".repeat(array_depth),
            )
        };

        let exact_boundary =
            request_with_array_depth(usize::from(MAXIMUM_COMMAND_JSON_CONTAINER_DEPTH) - 1);
        parse_transcript_core_request(exact_boundary.as_bytes())
            .expect("the exact command JSON depth boundary must parse");

        let one_container_over =
            request_with_array_depth(usize::from(MAXIMUM_COMMAND_JSON_CONTAINER_DEPTH));
        let error = parse_transcript_core_request(one_container_over.as_bytes())
            .expect_err("one container over the command JSON depth limit must refuse");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }

    #[test]
    fn request_limit_accepts_the_exact_boundary_and_refuses_one_byte_over() {
        let request = br#"{"command":"DescribeBgvRnsParameters"}"#;
        assert!(
            parse_transcript_core_request_with_limit(request, request.len()).is_ok(),
            "the exact request boundary must be accepted"
        );
        let error = parse_transcript_core_request_with_limit(request, request.len() - 1)
            .expect_err("one byte over the request limit must refuse");
        assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    }
}
