use super::*;
use ballot_encryption::packing::PackingWitness;
use protocol_foundations::identity::{PUBLIC_POLYNOMIAL_DOMAIN, identity};
use setup_aggregate::{RetainedAggregatePolynomial, RetainedSetupInputs};
use supported_profile::DEGREE;

/// A uniform public key of the family, retained through the same
/// digest-checked reader as a setup aggregate's key.
fn retained_key(profile: Profile, index: usize, seed: u64) -> RetainedAggregatePolynomial {
    let family = profile.setup_family(index).unwrap();
    let modulus = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family));
    let half = &modulus >> 1usize;
    let mut state = seed;
    let values: Vec<BigInt> = (0..profile.family_degree(family))
        .map(|_| {
            let mut value = BigInt::from(0);
            for _ in 0..modulus.bits().div_ceil(64) + 1 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                value = (value << 64usize) + BigInt::from(state);
            }
            let value = value % &modulus;
            if value > half {
                value - &modulus
            } else {
                value
            }
        })
        .collect();
    let bytes = encode_polynomial(&values, coefficient_bytes(profile, family)).unwrap();
    let mut record = b"SAV1".to_vec();
    record.extend([7; 64]);
    for body_index in profile.contribution_body_polynomials() {
        record.extend(if body_index == index {
            identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes).unwrap()
        } else {
            [0; 64]
        });
    }
    let inputs = RetainedSetupInputs::parse(profile, &record, [7; 64]).unwrap();
    let mut reader = inputs.read_polynomial(index).unwrap();
    let chunk = setup_aggregate::CHUNK_BYTES / coefficient_bytes(profile, family)
        * coefficient_bytes(profile, family);
    for (ordinal, part) in bytes.chunks(chunk).enumerate() {
        reader.push(ordinal * chunk, part).unwrap();
    }
    reader.finish().unwrap()
}

/// A true ballot of the profile: its statement and witness columns.
pub(crate) fn synthetic_ballot(profile: Profile) -> (PublicStatement, Vec<Vec<u16>>) {
    let scores: Vec<u8> = (0..profile.options())
        .map(|option| [1, 10, 4, 7][option % 4])
        .collect();
    let packing = PackingWitness::new(&scores).unwrap();
    let (_, _, fhe_key) = setup_input(profile);
    let fhe = EncryptionWitness::create(
        profile,
        retained_key(profile, fhe_key, 3),
        packing.message(),
    )
    .unwrap();
    let mut literal = vec![0; AUXILIARY_DEGREE];
    for (target, score) in literal.iter_mut().zip(&scores) {
        *target = i32::from(*score);
    }
    let auxiliary = EncryptionWitness::create_auxiliary(&literal).unwrap();
    let header = header(
        &[1; 64],
        &[7; 64],
        profile.participants() - 1,
        profile.options(),
        profile.options(),
    )
    .unwrap();
    let statement = PublicStatement::from_parts(profile, header, &fhe, &auxiliary).unwrap();
    let columns = crate::columns::from_parts(profile, &packing, &fhe, &auxiliary).unwrap();
    (statement, columns.to_vec())
}

fn affine_value(
    statement: &PublicStatement,
    columns: &[Vec<u16>],
    alpha: Element,
) -> (Element, Element) {
    let operator = statement.operator(alpha).unwrap();
    let actual = operator.columns(columns.len()).iter().zip(columns).fold(
        ZERO,
        |sum, (coefficients, column)| {
            coefficients
                .iter()
                .zip(column)
                .fold(sum, |sum, (coefficient, value)| {
                    field::add(sum, field::scale(*coefficient, u128::from(*value)))
                })
        },
    );
    (actual, operator.target)
}

#[test]
fn ballots_satisfy_the_affine_relation_at_the_smallest_and_widest_profiles() {
    for (participants, options) in [(3, 2), (16, 2), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let (statement, mut columns) = synthetic_ballot(profile);
        assert_eq!(columns.len(), ballot_relation(profile).columns());
        assert!(columns.iter().all(|column| column.len() == DEGREE));
        for alpha in [[13, 17, 19], [29, 31, 37]] {
            let (actual, target) = affine_value(&statement, &columns, alpha);
            assert_eq!(actual, target);
        }
        // A changed score, carry or auxiliary quotient breaks it.
        let layout = BallotColumns::new(profile);
        for (column, position) in [
            (layout.scores(), 0),
            (layout.fhe_carry(1, layout.fhe_limbs() - 2), 9),
            (layout.auxiliary_quotient(0), 16),
        ] {
            columns[column][position] ^= 1;
            let (actual, target) = affine_value(&statement, &columns, [13, 17, 19]);
            assert_ne!(actual, target);
            columns[column][position] ^= 1;
        }
    }
}

// The weighted operator places at every row of every column the
// coefficient the dense reference builds there, with the same target and
// lookup weight.
#[test]
fn weighted_operators_equal_the_dense_reference_at_every_row() {
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let (statement, _) = synthetic_ballot(profile);
        let columns = ballot_relation(profile).columns();
        for alpha in [
            [1, 0, 0],
            [13, 17, 19],
            [MODULUS - 2, MODULUS - 3, MODULUS - 5],
        ] {
            let weighted = statement.operator(alpha).unwrap();
            let dense = super::dense_operator::operator(&statement, alpha).unwrap();
            assert_eq!(weighted.columns(columns), dense.coefficients);
            assert_eq!(
                (weighted.target, weighted.lookup_weight),
                (dense.target, dense.lookup_weight)
            );
        }
    }
}

#[test]
fn statements_of_another_profile_or_position_are_refused() {
    let profile = Profile::new(3, 2).unwrap();
    let (statement, _) = synthetic_ballot(profile);
    let mut other = PublicStatement {
        profile: Profile::new(3, 3).unwrap(),
        header: statement.header.clone(),
        polynomials: statement.polynomials.clone(),
    };
    assert!(other.operator([13, 17, 19]).is_err());
    other.profile = profile;
    other.header[132..134].copy_from_slice(&3u16.to_le_bytes());
    assert!(other.operator([13, 17, 19]).is_err());
    other.header = statement.header.clone();
    other.polynomials.pop();
    assert!(other.operator([13, 17, 19]).is_err());
    // Ciphertext bytes whose top coefficient exceeds half the modulus
    // are not canonical.
    let mut changed = statement.polynomials.clone();
    let width = coefficient_bytes(profile, Family::Fhe);
    changed[2][width - 1] = 0xff;
    let changed = PublicStatement {
        profile,
        header: statement.header.clone(),
        polynomials: changed,
    };
    assert!(changed.operator([13, 17, 19]).is_err());
    assert!(
        statement
            .polynomials
            .iter()
            .enumerate()
            .all(|(index, bytes)| bytes.len() == polynomial_bytes(profile, index))
    );
}

// Verifiers stream each common polynomial's canonical records where the
// prover encodes its generated coefficients; both give the statement the
// same bytes, at the smallest and the largest ciphertext modulus.
#[test]
fn common_records_encode_the_generated_common_polynomials() {
    let smallest = Profile::all().next().unwrap();
    let largest = Profile::all().last().unwrap();
    assert_ne!(smallest.ciphertext_modulus(), largest.ciphertext_modulus());
    for profile in [smallest, largest] {
        let (family, common, _) = setup_input(profile);
        let values = setup_witness::contribution::common_polynomial(profile, common).unwrap();
        assert_eq!(
            setup_witness::contribution::common_records(profile, common).unwrap(),
            encode_polynomial(&values, coefficient_bytes(profile, family)).unwrap()
        );
    }
}
