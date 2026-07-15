use super::*;

pub(super) fn compare_hash_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = hash_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

pub(super) fn compare_string_field(
    value: &Value,
    field_name: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    let actual = string_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

pub(super) fn compare_unsigned_field(
    value: &Value,
    field_name: &str,
    expected: u64,
    description: &str,
) -> CanonicalResult<()> {
    let actual = unsigned_at_path(value, &[field_name])?;
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}
