use super::*;
fn profile() -> Profile {
    Profile::new(3, 2).unwrap()
}
fn record() -> (Vec<u8>, Vec<u8>) {
    let profile = profile();
    let key = profile.share_constant_polynomial(0);
    let values = vec![0; profile.setup_polynomial_bytes(key).unwrap()];
    let mut record = Vec::from(b"SAV1".as_slice());
    record.extend([9; 64]);
    for index in profile.contribution_body_polynomials() {
        record.extend(if index == key {
            registration_credentials::identity::identity(PUBLIC_POLYNOMIAL_DOMAIN, &values).unwrap()
        } else {
            [0; 64]
        });
    }
    (record, values)
}
fn push_all(reader: &mut RetainedPolynomialReader, bytes: &[u8]) {
    let width = 1 + profile().family_magnitude_bytes(supported_profile::Family::Sharing);
    let chunk = CHUNK_BYTES / width * width;
    for (ordinal, part) in bytes.chunks(chunk).enumerate() {
        reader.push(ordinal * chunk, part).unwrap();
    }
}
#[test]
fn retained_inputs_check_complete_identity_and_canonical_values() {
    let (record, values) = record();
    let key_index = profile().share_constant_polynomial(0);
    let width = 1 + profile().family_magnitude_bytes(supported_profile::Family::Sharing);
    let inputs = RetainedSetupInputs::parse(profile(), &record, [9; 64]).unwrap();
    let mut reader = inputs.read_polynomial(key_index).unwrap();
    push_all(&mut reader, &values);
    let key = reader.finish().unwrap();
    assert_eq!(key.inventory(), &[9; 64]);
    assert_eq!(key.index(), key_index);
    assert!(
        key.coefficients()
            .iter()
            .all(|value| value == &BigInt::from(0))
    );
    let mut changed = values.clone();
    changed[1] = 1;
    let mut reader = inputs.read_polynomial(key_index).unwrap();
    push_all(&mut reader, &changed);
    assert!(reader.finish().is_err());
    let mut reader = inputs.read_polynomial(key_index).unwrap();
    push_all(&mut reader, &values[..values.len() - width]);
    assert!(reader.finish().is_err());
    let mut negative_zero = values.clone();
    negative_zero[0] = 1;
    let mut reader = inputs.read_polynomial(key_index).unwrap();
    assert!(reader.push(0, &negative_zero[..width]).is_err());
    assert!(reader.push(0, &values[..width]).is_err());
    assert!(reader.finish().is_err());
    assert!(inputs.read_polynomial(0).is_err());
}
#[test]
fn retained_reference_parser_refuses_wrong_inventory_profile_or_framing() {
    let (mut record, _) = record();
    assert!(RetainedSetupInputs::parse(profile(), &record, [8; 64]).is_err());
    assert!(RetainedSetupInputs::parse(profile(), &record[..record.len() - 1], [9; 64]).is_err());
    // A four-participant setup carries two more share encryptions.
    assert!(RetainedSetupInputs::parse(Profile::new(4, 2).unwrap(), &record, [9; 64]).is_err());
    record.push(0);
    assert!(RetainedSetupInputs::parse(profile(), &record, [9; 64]).is_err());
    record.pop();
    record[0] ^= 1;
    assert!(RetainedSetupInputs::parse(profile(), &record, [9; 64]).is_err());
}

#[test]
fn provisional_and_final_reference_grammars_do_not_alias() {
    let (final_reference, _) = record();
    // Local reference operands only: this fixture creates no verified
    // offer, selection-input capability or public setup capability.
    let polynomials = RetainedSetupInputs::parse(profile(), &final_reference, [9; 64])
        .unwrap()
        .into_polynomials();
    let provisional = encode_reference(b"SPI1", profile(), [9; 64], &polynomials).unwrap();
    assert_eq!(
        provisional.len() + registration_credentials::RETAINED_TAG_BYTES,
        crate::selection_reference_bytes(profile())
    );
    assert!(RetainedSetupInputs::parse(profile(), &provisional, [9; 64]).is_err());
    assert!(
        RetainedSetupInputs::parse_with_magic(b"SPI1", profile(), &final_reference, [9; 64])
            .is_err()
    );
    assert!(
        RetainedSetupInputs::parse_with_magic(b"SPI1", profile(), &provisional, [8; 64]).is_err()
    );
    let inputs =
        RetainedSetupInputs::parse_with_magic(b"SPI1", profile(), &provisional, [9; 64]).unwrap();
    assert_eq!(inputs.inventory(), &[9; 64]);
    assert!(
        encode_reference(
            b"SPI1",
            profile(),
            [9; 64],
            &polynomials[..polynomials.len() - 1]
        )
        .is_err()
    );
    let mut reordered = polynomials.clone();
    reordered.swap(0, 1);
    assert!(encode_reference(b"SPI1", profile(), [9; 64], &reordered).is_err());
}
