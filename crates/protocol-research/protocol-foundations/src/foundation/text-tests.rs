use super::{DisplayTextError, REQUIRED_UNICODE_VERSION, StabilizedDisplayText};

#[test]
fn unicode_version_is_pinned_to_seventeen() {
    assert_eq!(
        unicode_normalization::UNICODE_VERSION,
        REQUIRED_UNICODE_VERSION
    );
}

#[test]
fn ingress_normalizes_once_and_canonical_validation_does_not() {
    let decomposed = "Cafe\u{301}";
    let normalized = StabilizedDisplayText::from_ingress_utf8(decomposed.as_bytes())
        .expect("valid ingress text should normalize");
    assert_eq!(normalized.as_str(), "Caf\u{e9}");

    assert_eq!(
        StabilizedDisplayText::from_canonical_utf8(decomposed.as_bytes()),
        Err(DisplayTextError::NotStabilizedNfc)
    );
    assert_eq!(
        StabilizedDisplayText::from_canonical_utf8(normalized.as_str().as_bytes())
            .expect("normalized bytes should validate"),
        normalized
    );
}

#[test]
fn malformed_surrogate_noncharacter_and_unassigned_inputs_are_rejected() {
    assert_eq!(
        StabilizedDisplayText::from_ingress_utf8(&[0xed, 0xa0, 0x80]),
        Err(DisplayTextError::InvalidUtf8)
    );
    assert_eq!(
        StabilizedDisplayText::from_ingress_utf8("\u{fdd0}".as_bytes()),
        Err(DisplayTextError::Noncharacter { code_point: 0xfdd0 })
    );
    assert_eq!(
        StabilizedDisplayText::from_ingress_utf8("\u{10ffff}".as_bytes()),
        Err(DisplayTextError::Noncharacter {
            code_point: 0x10ffff
        })
    );
    assert_eq!(
        StabilizedDisplayText::from_ingress_utf8("\u{378}".as_bytes()),
        Err(DisplayTextError::UnassignedCodePoint { code_point: 0x378 })
    );
}

#[test]
fn private_use_code_points_are_rejected_across_all_three_ranges() {
    for code_point in [0xe000, 0xf0000, 0x100000] {
        let character = char::from_u32(code_point).expect("test code point is a scalar value");
        let text = format!("label-{character}");
        assert_eq!(
            StabilizedDisplayText::from_ingress_utf8(text.as_bytes()),
            Err(DisplayTextError::PrivateUseCodePoint { code_point })
        );
        assert_eq!(
            StabilizedDisplayText::from_canonical_utf8(text.as_bytes()),
            Err(DisplayTextError::PrivateUseCodePoint { code_point })
        );
    }
}

#[test]
fn unicode_seventeen_assignment_boundary_is_enforced() {
    let newly_assigned = StabilizedDisplayText::from_ingress_utf8("\u{16ea0}".as_bytes())
        .expect("Unicode 17 assigned code point is accepted");
    assert_eq!(newly_assigned.as_str(), "\u{16ea0}");

    assert_eq!(
        StabilizedDisplayText::from_ingress_utf8("\u{16eb9}".as_bytes()),
        Err(DisplayTextError::UnassignedCodePoint {
            code_point: 0x16eb9
        })
    );
}
