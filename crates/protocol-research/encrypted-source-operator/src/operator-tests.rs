use super::*;
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use setup_witness::{PolynomialOutput, fhe_key_source::FheKeySource};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use supported_profile::AUXILIARY_DEGREE;
use word_proof::oracles::Witness;

#[derive(Default)]
struct Output {
    polynomials: Vec<Vec<u8>>,
}
impl PolynomialOutput for Output {
    fn polynomial(&mut self, values: &[BigInt], _modulus: &BigInt, width: usize) {
        let mut bytes = vec![0; values.len() * (width + 1)];
        for (value, record) in values.iter().zip(bytes.chunks_exact_mut(width + 1)) {
            statement_stream::coefficient::encode(value, record);
        }
        self.polynomials.push(bytes);
    }
}
fn at(bytes: &[u8], degree: usize, index: usize) -> BigInt {
    let width = bytes.len() / degree;
    let record = &bytes[index * width..(index + 1) * width];
    BigInt::from_bytes_le(
        if record[0] == 1 {
            Sign::Minus
        } else {
            Sign::Plus
        },
        &record[1..],
    )
}
fn reduce(value: BigInt, modulus: &BigInt) -> BigInt {
    let mut value = value % modulus;
    if value.sign() == Sign::Minus {
        value += modulus;
    }
    if &value + &value > *modulus {
        value - modulus
    } else {
        value
    }
}
fn apply(operator: &Operator, columns: &[Vec<u16>]) -> Element {
    let mut result = ZERO;
    for term in &operator.terms {
        let mut powers = ONE;
        let length = match &term.public {
            PublicColumn::Powers(length) | PublicColumn::Ones(length) => *length,
            PublicColumn::Values(values) => values.len(),
        };
        let stride = DEGREE / length;
        for index in 0..length {
            let value = match &term.public {
                PublicColumn::Powers(_) => powers,
                PublicColumn::Ones(_) => ONE,
                PublicColumn::Values(values) => values[index],
            };
            for (column, weight) in &term.weights {
                let word = columns[*column][stride * index];
                if word != 0 {
                    result = field::add(
                        result,
                        field::scale(field::multiply(*weight, value), u128::from(word)),
                    );
                }
            }
            powers = field::multiply(powers, operator.alpha);
        }
    }
    result
}

#[test]
fn layout_extends_every_profile_without_duplicating_the_original_source() {
    assert_eq!(supported_profile::relation::QUERY_COUNT, 704);
    let mut checked = 0;
    for profile in Profile::all() {
        let old = setup_relation(profile);
        let extended = relation(profile);
        assert_eq!(extended.columns(), old.columns() + 6);
        assert_eq!(extended.lookups(), old.lookups() + 6);
        assert_eq!(extended.oracles(), old.oracles() + 21);
        assert_eq!(
            extended.zero_product_pairs.len(),
            old.zero_product_pairs.len() + 1
        );
        assert_eq!(extended.supports.last(), Some(&(1, 128)));
        assert!(old.narrow.contains(&(original_error_column(profile), 512)));
        for (old_pair, new_pair) in old
            .zero_product_pairs
            .iter()
            .zip(&extended.zero_product_pairs)
        {
            assert_eq!(*new_pair, (old_pair.0 + 4, old_pair.1 + 4));
        }
        assert!(extended.message_bytes >= extended.minimum_message_bytes());
        checked += 1;
    }
    assert_eq!(checked, 342);
}

#[test]
fn native_full_degree_contribution_and_source_share_the_same_witness() {
    let profile = Profile::new(3, 2).unwrap();
    let old_relation = setup_relation(profile);
    let package = setup_witness::encrypted_source::EncryptedSource::from_seed(
        profile, &[17; 64], &[31; 64], [47; 64],
    )
    .unwrap();
    let registered_ciphertexts = package.public().ciphertext_records().unwrap();
    let registered_binding = package
        .public()
        .binding(profile, &[17; 64], &[31; 64])
        .unwrap();
    let mut source_verifier = setup_witness::encrypted_source::SourceCiphertextVerifier::new(
        profile,
        &[17; 64],
        &[31; 64],
        registered_binding,
    );
    for record in &registered_ciphertexts {
        for chunk in record.chunks(65_537) {
            source_verifier.push(chunk).unwrap();
        }
    }
    let public = source_verifier
        .finish()
        .unwrap()
        .into_public(profile)
        .unwrap();
    assert_eq!(public.polynomials, package.public().polynomials);
    package.check_ciphertexts(&registered_ciphertexts).unwrap();
    // The source ciphertexts exist before the first contribution operation.
    let mut contribution = package.into_contribution(profile).unwrap();
    let mut output = Output::default();
    for gadget in 0..profile.gadget_length() {
        contribution.gadget(gadget, &mut output).unwrap();
    }
    contribution.begin_shares(&mut output).unwrap();
    // Canonical public recipient inputs are sufficient for this contribution
    // relation; registration authentication is an enclosing protocol step.
    for recipient in 0..profile.participants() {
        let public = vec![BigInt::from(recipient + 1); DEGREE];
        contribution.share(recipient, &public, &mut output).unwrap();
    }
    contribution.finish().unwrap();
    let combined = contribution.into_columns().unwrap();
    let words = old_relation.words;
    let columns: Vec<_> = combined[..words]
        .iter()
        .chain(&combined[words + 4..words + 4 + old_relation.booleans])
        .cloned()
        .collect();
    let error_column = original_error_column(profile);
    let fhe_modulus = BigInt::from_bytes_le(Sign::Plus, &profile.ciphertext_modulus().to_bytes());
    let support: Vec<_> = (0..DEGREE)
        .filter_map(|index| {
            let sign = i32::from(columns[words][index]) - i32::from(columns[words + 1][index]);
            (sign != 0).then_some((index, sign))
        })
        .collect();
    for position in [0, 1, 17, DEGREE / 2, DEGREE - 1] {
        let mut phase = at(&output.polynomials[1], DEGREE, position);
        for &(shift, sign) in &support {
            let (index, signed) = if shift <= position {
                (position - shift, sign)
            } else {
                (DEGREE + position - shift, -sign)
            };
            phase += at(&output.polynomials[0], DEGREE, index) * signed;
        }
        assert_eq!(
            reduce(phase, &fhe_modulus).to_i128().unwrap(),
            i128::from(columns[error_column][position]) - 64
        );
    }
    let alpha = [17, 37, 91];
    let original = original_operator(profile, alpha, &output.polynomials).unwrap();
    assert_eq!(apply(&original, &columns), original.target);
    let original_end = original.lookup_weight;
    let common = common_polynomials();
    let ephemeral: Vec<i8> = (0..DEGREE)
        .map(|index| {
            (combined[old_relation.columns() + 4][index] as i16
                - combined[old_relation.columns() + 5][index] as i16) as i8
        })
        .collect();
    let stride = DEGREE / AUXILIARY_DEGREE;
    assert!(
        ephemeral
            .iter()
            .enumerate()
            .all(|(index, value)| index % stride == 0 || *value == 0)
    );
    let errors: Vec<Vec<i8>> = (0..2)
        .map(|component| {
            combined[words + 2 * component + 1]
                .iter()
                .map(|value| (i32::from(*value) - 64) as i8)
                .collect()
        })
        .collect();
    // Independent wide-integer rows check the precise messages and offsets,
    // rather than only agreement between the producer and its operator.
    for component in 0..2 {
        for position in [0, 7, DEGREE / 2, DEGREE - 1] {
            let message = match component {
                0 => {
                    1 + i64::from(columns[words][position])
                        - i64::from(columns[words + 1][position])
                        + 3 * i64::from(columns[error_column][position])
                }
                _ => 0,
            };
            let mut residual = BigInt::from(errors[component][position])
                + BigInt::from(scale()) * message
                - public.polynomials[2 * component + 1][position];
            for (shift, sign) in ephemeral
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, sign)| *sign != 0)
            {
                let (index, factor) = if shift <= position {
                    (position - shift, sign)
                } else {
                    (DEGREE + position - shift, -sign)
                };
                residual += BigInt::from(common[component][index]) * factor;
            }
            residual -= BigInt::from(modulus())
                * (i32::from(combined[words + 2 * component][position]) - 32768);
            assert_eq!(residual, BigInt::from(0));
        }
    }
    let combined_relation = relation(profile);
    let digest = statement_digest(profile, &output.polynomials, &public).unwrap();
    drop(columns);
    let witness = Witness::from_columns(&combined_relation, digest, combined).unwrap();
    let operator = combine_operator(profile, original, &public).unwrap();
    assert_eq!(apply(&operator, &witness.columns), operator.target);
    assert_eq!(
        operator.lookup_weight,
        field::multiply(original_end, power(alpha, 2 * DEGREE + 2))
    );

    // Isolate the added rows to make each hostile control cheap while keeping
    // the original source columns and their native positions unchanged.
    let source = source_operator(profile, &public, alpha, original_end).unwrap();
    assert_eq!(apply(&source, &witness.columns), source.target);
    let mut rejected = 0;
    for column in [error_column, words, words + 1] {
        let mut changed = witness.columns.clone();
        changed[column][0] = changed[column][0].wrapping_add(1);
        assert_ne!(apply(&source, &changed), source.target);
        rejected += 1;
    }
    let mut alternate_secret = witness.columns.clone();
    let positive = words + 4;
    let at_positive = alternate_secret[positive]
        .iter()
        .position(|value| *value == 1)
        .unwrap();
    let at_empty = (0..DEGREE)
        .find(|index| {
            alternate_secret[positive][*index] == 0 && alternate_secret[positive + 1][*index] == 0
        })
        .unwrap();
    alternate_secret[positive][at_positive] = 0;
    alternate_secret[positive][at_empty] = 1;
    assert_ne!(apply(&source, &alternate_secret), source.target);
    rejected += 1;
    for component in 0..2 {
        let mut changed = public.clone();
        changed.polynomials[2 * component + 1][0] =
            centered(changed.polynomials[2 * component + 1][0] + 1);
        let changed_operator = source_operator(profile, &changed, alpha, original_end).unwrap();
        assert_ne!(
            apply(&changed_operator, &witness.columns),
            changed_operator.target
        );
        rejected += 1;
        assert_ne!(
            statement_digest(profile, &output.polynomials, &changed).unwrap(),
            digest
        );
    }
    let mut malformed = public.clone();
    malformed.polynomials[0][0] = modulus() / 2 + 1;
    assert_eq!(malformed.records().err(), Some(Refusal::Range));
    rejected += 1;
    let mut narrow = witness.columns.clone();
    narrow[words + 1][0] = 128;
    assert!(Witness::from_columns(&combined_relation, digest, narrow).is_err());
    rejected += 1;
    let mut non_boolean = witness.columns.clone();
    non_boolean[combined_relation.words + old_relation.booleans][0] = 2;
    assert!(Witness::from_columns(&combined_relation, digest, non_boolean).is_err());
    rejected += 1;
    let mut unbalanced = witness.columns.clone();
    let ephemeral_positive = combined_relation.words + old_relation.booleans;
    let selected_position = unbalanced[ephemeral_positive]
        .iter()
        .position(|value| *value == 1)
        .unwrap();
    unbalanced[ephemeral_positive][selected_position] = 0;
    assert!(Witness::from_columns(&combined_relation, digest, unbalanced).is_err());
    rejected += 1;
    // The affine packed message alone permits s + 3 and e - 1. The same
    // original Boolean secret columns must still reject that decomposition.
    let mut alias = witness.columns.clone();
    let position = (0..DEGREE)
        .find(|position| alias[error_column][*position] > 0)
        .unwrap();
    alias[positive][position] += 3;
    alias[error_column][position] -= 1;
    assert_eq!(apply(&source, &alias), source.target);
    assert!(Witness::from_columns(&combined_relation, digest, alias).is_err());
    rejected += 1;
    println!(
        "Source-link checks: native degree {DEGREE}, original columns {}, combined columns {}, hostile controls {rejected}",
        old_relation.columns(),
        combined_relation.columns()
    );
    assert_eq!(rejected, 11);

    drop(operator);
    drop(source);
    drop(alternate_secret);
    drop(malformed);
    drop(common);
}

#[test]
fn fixed_common_blocks_match_independent_integer_reduction() {
    let values = common_polynomials();
    let blocks = DEGREE / AUXILIARY_DEGREE;
    for (component, polynomial) in values.iter().enumerate() {
        for block in [0, blocks - 1] {
            let mut state = Shake256::default();
            state.update(b"sealed-lattice/source-common/v1");
            state.update(&[component as u8]);
            state.update(&(block as u32).to_le_bytes());
            let mut reader = state.finalize_xof();
            for coefficient in 0..4 {
                let mut bytes = [0u8; 72];
                reader.read(&mut bytes);
                assert_eq!(
                    reduce(
                        BigInt::from_bytes_le(Sign::Plus, &bytes),
                        &BigInt::from(modulus())
                    )
                    .to_i64()
                    .unwrap(),
                    polynomial[block + blocks * coefficient]
                );
            }
        }
    }
    assert!(values.windows(2).all(|pair| pair[0] != pair[1]));
}

#[test]
fn original_encryption_package_replays_and_refuses_different_sources() {
    let profile = Profile::new(3, 2).unwrap();
    let package = |source_seed: u8, encryption_seed: u8| {
        let mut source_state = Shake256::default();
        source_state.update(b"source package source fixture");
        source_state.update(&[source_seed]);
        let source = FheKeySource::from_reader(profile, &mut source_state.finalize_xof());
        let mut encryption_state = Shake256::default();
        encryption_state.update(b"source package encryption fixture");
        encryption_state.update(&[encryption_seed]);
        source
            .encrypt(&mut encryption_state.finalize_xof())
            .unwrap()
    };
    let original = package(7, 11);
    let ciphertexts = original.public().ciphertext_records().unwrap();
    assert_eq!(ciphertexts.len(), 2);
    assert!(ciphertexts.iter().all(|bytes| bytes.len() == DEGREE * 6));
    original.check_ciphertexts(&ciphertexts).unwrap();
    package(7, 11).check_ciphertexts(&ciphertexts).unwrap();
    assert_eq!(
        package(8, 11).check_ciphertexts(&ciphertexts),
        Err(Refusal::Binding)
    );
    assert_eq!(
        package(7, 12).check_ciphertexts(&ciphertexts),
        Err(Refusal::Binding)
    );
    let mut changed = ciphertexts.clone();
    changed[0][1] ^= 1;
    assert_eq!(original.check_ciphertexts(&changed), Err(Refusal::Binding));
    changed[0].pop();
    assert_eq!(original.check_ciphertexts(&changed), Err(Refusal::Binding));
    let other_family = Profile::all()
        .find(|other| {
            other.ciphertext_modulus().to_bytes() != profile.ciphertext_modulus().to_bytes()
        })
        .unwrap();
    assert!(matches!(
        original.into_contribution(other_family),
        Err(setup_witness::contribution::Refusal::SourceFamily)
    ));
    assert_eq!(
        package(7, 11).into_contribution(profile).unwrap().profile(),
        profile
    );
    println!(
        "Original source package: replay accepted; changed source, encryption, ciphertext, length and family refused"
    );
}

#[test]
fn retained_source_seed_binds_owner_poll_and_family() {
    use setup_witness::encrypted_source::EncryptedSource;
    let profiles: Vec<_> = Profile::all().collect();
    let (profile, same_family) = profiles
        .iter()
        .find_map(|first| {
            profiles
                .iter()
                .find(|second| {
                    (first.participants(), first.options())
                        != (second.participants(), second.options())
                        && first.ciphertext_modulus().to_bytes()
                            == second.ciphertext_modulus().to_bytes()
                        && first.fhe_common_sample_bits() == second.fhe_common_sample_bits()
                })
                .map(|second| (*first, *second))
        })
        .unwrap();
    let original = EncryptedSource::from_seed(profile, &[3; 64], &[5; 64], [7; 64]).unwrap();
    let ciphertexts = original.public().ciphertext_records().unwrap();
    EncryptedSource::from_seed(same_family, &[3; 64], &[5; 64], [7; 64])
        .unwrap()
        .check_ciphertexts(&ciphertexts)
        .unwrap();
    assert_eq!(
        original.into_contribution(same_family).unwrap().profile(),
        same_family
    );
    let mut changed_seed = [7; 64];
    changed_seed[63] ^= 1;
    for changed in [
        EncryptedSource::from_seed(profile, &[4; 64], &[5; 64], [7; 64]),
        EncryptedSource::from_seed(profile, &[3; 64], &[6; 64], [7; 64]),
        EncryptedSource::from_seed(profile, &[3; 64], &[5; 64], changed_seed),
    ] {
        assert_eq!(
            changed.unwrap().check_ciphertexts(&ciphertexts),
            Err(Refusal::Binding)
        );
    }
}
