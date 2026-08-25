use crate::encoding::{append_bytes, append_varuint};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    authenticated_opening::{
        AUTHENTICATED_SHARE_ARTIFACT_VERSION, AUTHENTICATED_SHARE_OPENING_MAGIC,
        AUTHENTICATED_SHARE_SALT_BYTE_LENGTH, AUTHENTICATED_SHARE_VERIFICATION_KEY_MAGIC,
        AuthenticatedShareCommitment, AuthenticatedShareOpening, AuthenticatedShareVerificationKey,
        authenticated_share_opening_with_tag_for_test, commit_authenticated_share_opening,
        compute_authenticated_share_tag, create_authenticated_share_opening,
        verify_authenticated_share_opening,
    },
};

const CONTEXT_BYTES: &[u8] = b"canonical-preparation-context";
const COORDINATE_BYTES: &[u8] = b"holder-3/input-mask/wire-19";

#[test]
fn scalar_and_label_body_openings_roundtrip_and_verify() {
    let scalar_key = AuthenticatedShareVerificationKey::scalar(field(7), field(11));
    let (scalar_commitment, scalar_opening) = create_authenticated_share_opening(
        CONTEXT_BYTES,
        COORDINATE_BYTES,
        &[field(13)],
        &scalar_key,
        salt(17),
    )
    .unwrap();
    verify_authenticated_share_opening(
        CONTEXT_BYTES,
        COORDINATE_BYTES,
        scalar_commitment,
        &scalar_key,
        &scalar_opening,
    )
    .unwrap();

    let decoded_scalar_key =
        AuthenticatedShareVerificationKey::from_canonical_bytes(&scalar_key.canonical_bytes())
            .unwrap();
    let decoded_scalar_opening =
        AuthenticatedShareOpening::from_canonical_bytes(&scalar_opening.canonical_bytes()).unwrap();
    assert_eq!(decoded_scalar_key.coefficients(), scalar_key.coefficients());
    assert_eq!(decoded_scalar_key.offset(), scalar_key.offset());
    assert_eq!(decoded_scalar_opening.values(), scalar_opening.values());
    assert_eq!(decoded_scalar_opening.tag(), scalar_opening.tag());
    assert_eq!(decoded_scalar_opening.salt(), scalar_opening.salt());

    let label_key =
        AuthenticatedShareVerificationKey::label_body([field(3), field(5), field(9)], field(21));
    let (label_commitment, label_opening) = create_authenticated_share_opening(
        CONTEXT_BYTES,
        b"holder-7/input-label/wire-311/alternative-1/component-4",
        &[field(2), field(8), field(15)],
        &label_key,
        salt(33),
    )
    .unwrap();
    verify_authenticated_share_opening(
        CONTEXT_BYTES,
        b"holder-7/input-label/wire-311/alternative-1/component-4",
        label_commitment,
        &label_key,
        &label_opening,
    )
    .unwrap();
}

#[test]
fn verification_binds_context_coordinate_commitment_value_tag_salt_and_key() {
    let key = AuthenticatedShareVerificationKey::scalar(field(7), field(11));
    let (commitment, opening) = create_authenticated_share_opening(
        CONTEXT_BYTES,
        COORDINATE_BYTES,
        &[field(13)],
        &key,
        salt(17),
    )
    .unwrap();

    for (context, coordinate) in [
        (b"different-context".as_slice(), COORDINATE_BYTES),
        (CONTEXT_BYTES, b"holder-4/input-mask/wire-19".as_slice()),
    ] {
        assert_eq!(
            verify_authenticated_share_opening(context, coordinate, commitment, &key, &opening,),
            Err(TallyPreparationError::AuthenticatedShareCommitmentMismatch)
        );
    }

    let mut wrong_commitment_bytes = commitment.canonical_bytes();
    wrong_commitment_bytes[19] ^= 0x80;
    let wrong_commitment =
        AuthenticatedShareCommitment::from_canonical_bytes(&wrong_commitment_bytes).unwrap();
    assert_eq!(
        verify_authenticated_share_opening(
            CONTEXT_BYTES,
            COORDINATE_BYTES,
            wrong_commitment,
            &key,
            &opening,
        ),
        Err(TallyPreparationError::AuthenticatedShareCommitmentMismatch)
    );

    let wrong_value_opening =
        authenticated_share_opening_with_tag_for_test(&[field(12)], opening.tag(), *opening.salt())
            .unwrap();
    let wrong_value_commitment =
        commit_authenticated_share_opening(CONTEXT_BYTES, COORDINATE_BYTES, &wrong_value_opening)
            .unwrap();
    assert_eq!(
        verify_authenticated_share_opening(
            CONTEXT_BYTES,
            COORDINATE_BYTES,
            wrong_value_commitment,
            &key,
            &wrong_value_opening,
        ),
        Err(TallyPreparationError::AuthenticatedShareTagMismatch)
    );

    let wrong_tag_opening = authenticated_share_opening_with_tag_for_test(
        opening.values(),
        opening.tag().add(BinaryFieldElement256::ONE),
        *opening.salt(),
    )
    .unwrap();
    let wrong_tag_commitment =
        commit_authenticated_share_opening(CONTEXT_BYTES, COORDINATE_BYTES, &wrong_tag_opening)
            .unwrap();
    assert_eq!(
        verify_authenticated_share_opening(
            CONTEXT_BYTES,
            COORDINATE_BYTES,
            wrong_tag_commitment,
            &key,
            &wrong_tag_opening,
        ),
        Err(TallyPreparationError::AuthenticatedShareTagMismatch)
    );

    let wrong_salt_opening =
        authenticated_share_opening_with_tag_for_test(opening.values(), opening.tag(), salt(18))
            .unwrap();
    assert_eq!(
        verify_authenticated_share_opening(
            CONTEXT_BYTES,
            COORDINATE_BYTES,
            commitment,
            &key,
            &wrong_salt_opening,
        ),
        Err(TallyPreparationError::AuthenticatedShareCommitmentMismatch)
    );

    for wrong_key in [
        AuthenticatedShareVerificationKey::scalar(field(6), key.offset()),
        AuthenticatedShareVerificationKey::scalar(
            key.coefficients()[0],
            key.offset().add(BinaryFieldElement256::ONE),
        ),
    ] {
        assert_eq!(
            verify_authenticated_share_opening(
                CONTEXT_BYTES,
                COORDINATE_BYTES,
                commitment,
                &wrong_key,
                &opening,
            ),
            Err(TallyPreparationError::AuthenticatedShareTagMismatch)
        );
    }
}

#[test]
fn codecs_reject_wrong_framing_lengths_limb_counts_and_trailing_bytes() {
    let scalar_key = AuthenticatedShareVerificationKey::scalar(field(7), field(11));
    let (_, scalar_opening) = create_authenticated_share_opening(
        CONTEXT_BYTES,
        COORDINATE_BYTES,
        &[field(13)],
        &scalar_key,
        salt(17),
    )
    .unwrap();

    assert!(matches!(
        AuthenticatedShareCommitment::from_canonical_bytes(&[0_u8; 63]),
        Err(
            TallyPreparationError::AuthenticatedShareCommitmentByteLength {
                expected: 64,
                actual: 63
            }
        )
    ));
    assert_eq!(
        create_authenticated_share_opening(
            b"",
            COORDINATE_BYTES,
            &[field(13)],
            &scalar_key,
            salt(17),
        ),
        Err(TallyPreparationError::AuthenticatedShareContextEmpty)
    );
    assert_eq!(
        create_authenticated_share_opening(CONTEXT_BYTES, b"", &[field(13)], &scalar_key, salt(17),),
        Err(TallyPreparationError::AuthenticatedShareCoordinateEmpty)
    );
    assert!(matches!(
        create_authenticated_share_opening(
            CONTEXT_BYTES,
            COORDINATE_BYTES,
            &[field(1), field(2)],
            &scalar_key,
            salt(17),
        ),
        Err(TallyPreparationError::AuthenticatedShareValueLimbCount { actual: 2 })
    ));

    let mut wrong_opening_magic = scalar_opening.canonical_bytes();
    wrong_opening_magic[1] ^= 1;
    assert!(matches!(
        AuthenticatedShareOpening::from_canonical_bytes(&wrong_opening_magic),
        Err(TallyPreparationError::AuthenticatedShareOpeningMagicMismatch)
    ));
    let mut trailing_opening = scalar_opening.canonical_bytes();
    trailing_opening.push(0);
    assert!(matches!(
        AuthenticatedShareOpening::from_canonical_bytes(&trailing_opening),
        Err(TallyPreparationError::TrailingAuthenticatedShareOpeningBytes)
    ));
    let mut trailing_key = scalar_key.canonical_bytes();
    trailing_key.push(0);
    assert!(matches!(
        AuthenticatedShareVerificationKey::from_canonical_bytes(&trailing_key),
        Err(TallyPreparationError::TrailingAuthenticatedShareVerificationKeyBytes)
    ));

    let invalid_limb_opening = manually_encoded_opening(2, 96);
    assert!(matches!(
        AuthenticatedShareOpening::from_canonical_bytes(&invalid_limb_opening),
        Err(TallyPreparationError::AuthenticatedShareValueLimbCount { actual: 2 })
    ));
    let short_salt_opening = manually_encoded_opening(1, 95);
    assert!(matches!(
        AuthenticatedShareOpening::from_canonical_bytes(&short_salt_opening),
        Err(TallyPreparationError::AuthenticatedShareSaltByteLength {
            expected: 96,
            actual: 95
        })
    ));

    let mut wrong_key_magic = scalar_key.canonical_bytes();
    wrong_key_magic[1] ^= 1;
    assert!(matches!(
        AuthenticatedShareVerificationKey::from_canonical_bytes(&wrong_key_magic),
        Err(TallyPreparationError::AuthenticatedShareVerificationKeyMagicMismatch)
    ));
}

#[test]
fn changed_vector_has_exactly_one_solving_coefficient_after_other_coefficients_are_fixed() {
    let value = [field(5), field(9), field(12)];
    let changed_value = [field(2), field(9), field(15)];
    let original_tag = field(41);
    let changed_tag = field(73);
    let fixed_second_coefficient = field(19);
    let fixed_third_coefficient = field(23);

    let difference = [
        value[0].add(changed_value[0]),
        value[1].add(changed_value[1]),
        value[2].add(changed_value[2]),
    ];
    assert!(!difference[0].is_zero());
    let fixed_inner_product = fixed_second_coefficient
        .multiply(difference[1])
        .add(fixed_third_coefficient.multiply(difference[2]));
    let required_difference = original_tag.add(changed_tag);
    let unique_first_coefficient = required_difference
        .add(fixed_inner_product)
        .divide(difference[0])
        .unwrap();

    let actual_difference = unique_first_coefficient
        .multiply(difference[0])
        .add(fixed_inner_product);
    assert_eq!(actual_difference, required_difference);
    assert_ne!(
        unique_first_coefficient
            .add(BinaryFieldElement256::ONE)
            .multiply(difference[0])
            .add(fixed_inner_product),
        required_difference
    );
}

#[test]
fn scalar_key_reuse_reveals_the_key_and_authenticates_an_arbitrary_value() {
    let actual_key = AuthenticatedShareVerificationKey::scalar(field(37), field(91));
    let first_value = field(5);
    let second_value = field(12);
    let first_tag = compute_authenticated_share_tag(&actual_key, &[first_value]).unwrap();
    let second_tag = compute_authenticated_share_tag(&actual_key, &[second_value]).unwrap();

    let recovered_coefficient = first_tag
        .add(second_tag)
        .divide(first_value.add(second_value))
        .unwrap();
    let recovered_offset = first_tag.add(recovered_coefficient.multiply(first_value));
    assert_eq!(recovered_coefficient, actual_key.coefficients()[0]);
    assert_eq!(recovered_offset, actual_key.offset());

    let recovered_key =
        AuthenticatedShareVerificationKey::scalar(recovered_coefficient, recovered_offset);
    let forged_value = field(255);
    let forged_tag = compute_authenticated_share_tag(&recovered_key, &[forged_value]).unwrap();
    let forged_opening =
        authenticated_share_opening_with_tag_for_test(&[forged_value], forged_tag, salt(99))
            .unwrap();
    let forged_commitment = commit_authenticated_share_opening(
        CONTEXT_BYTES,
        b"reused-key/third-record",
        &forged_opening,
    )
    .unwrap();
    verify_authenticated_share_opening(
        CONTEXT_BYTES,
        b"reused-key/third-record",
        forged_commitment,
        &actual_key,
        &forged_opening,
    )
    .unwrap();
}

fn manually_encoded_opening(value_count: u64, salt_byte_length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, AUTHENTICATED_SHARE_OPENING_MAGIC);
    append_varuint(&mut bytes, AUTHENTICATED_SHARE_ARTIFACT_VERSION);
    append_varuint(&mut bytes, value_count);
    for value_position in 0..value_count {
        append_bytes(
            &mut bytes,
            &field(value_position as u16 + 1).canonical_bytes(),
        );
    }
    append_bytes(&mut bytes, &field(7).canonical_bytes());
    append_bytes(&mut bytes, &vec![0_u8; salt_byte_length]);
    bytes
}

#[allow(dead_code)]
fn manually_encoded_key(coefficient_count: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, AUTHENTICATED_SHARE_VERIFICATION_KEY_MAGIC);
    append_varuint(&mut bytes, AUTHENTICATED_SHARE_ARTIFACT_VERSION);
    append_varuint(&mut bytes, coefficient_count);
    for coefficient_position in 0..coefficient_count {
        append_bytes(
            &mut bytes,
            &field(coefficient_position as u16 + 1).canonical_bytes(),
        );
    }
    append_bytes(&mut bytes, &field(7).canonical_bytes());
    bytes
}

fn field(value: u16) -> BinaryFieldElement256 {
    BinaryFieldElement256::from_low_polynomial_u16(value)
}

fn salt(byte: u8) -> [u8; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH] {
    [byte; AUTHENTICATED_SHARE_SALT_BYTE_LENGTH]
}
