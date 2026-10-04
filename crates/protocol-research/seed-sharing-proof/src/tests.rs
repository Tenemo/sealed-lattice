use super::*;
use crate::{
    layout::{Layout, STRIDE},
    statement::{Statement, encoded_bytes},
};
use word_proof::{
    field::{self, ZERO},
    oracles::Witness,
};

pub(crate) use crate::fixture::create as fixture;
use crate::fixture::{inputs, public_inputs};

#[test]
fn conservative_lifting_bounds_cover_every_accepted_seed_share() {
    let profile = profile();
    let threshold = profile.release_threshold();
    let eligible = threshold + (RECIPIENTS - 1) / 3;
    let translation = (1usize << (threshold - 1)) - 1;
    assert!(
        eligible * SEED_BITS * translation
            <= threshold * 2 * supported_profile::FHE_SECRET_SUPPORT * translation
    );
    let prime = BigInt::from(word_proof::field::MODULUS);
    let modulus = modulus();
    let radix = BigInt::from(1u8) << profile.share_limb_bits();
    let radius = BigInt::from(1u8) << (profile.sharing_coefficient_bits() - 1);
    let maximum_share = radius + 1;
    assert!(&maximum_share * 2 < prime);
    let honest_quotient =
        ((&modulus >> 1usize) * (SUPPORT + 1) + BigInt::from(SCALE) * maximum_share + 64)
            / &modulus;
    let quotient_bound = BigInt::from(1u8) << 15usize;
    assert!(honest_quotient < quotient_bound);
    for component in 0..2 {
        let carry_bits = if component == 0 {
            profile.share_carry_bits()
        } else {
            16
        };
        let private = if component == 0 {
            BigInt::from(SCALE) * ((&radix >> 1usize) + 1) + 64
        } else {
            BigInt::from(64)
        };
        let radix_less_one = &radix - 1;
        let honest_carry = ((BigInt::from(SUPPORT + 2) + &honest_quotient) * &radix_less_one
            + &private)
            / &radix_less_one
            + 1;
        let accepted_carry = BigInt::from(1u8) << (carry_bits - 1);
        assert!(honest_carry < accepted_carry);
        let residual = (BigInt::from(SUPPORT + 2) + &quotient_bound) * &radix_less_one
            + private
            + &accepted_carry * (&radix + 1);
        assert!(residual < prime);
        assert!(&prime / &radix >= accepted_carry);
    }
    assert!(2 * (2 * SUPPORT as i128 + 1) * 64 < SCALE);
}

#[test]
fn canonical_statement_binds_scope_and_rejects_noncanonical_coefficients() {
    let (statement, _) = fixture();
    let encoded = statement.encode().unwrap();
    assert_eq!(encoded.len(), encoded_bytes());
    assert_eq!(
        Statement::decode(&encoded, &statement.scope).unwrap(),
        statement
    );
    for field in 0..4 {
        let mut changed = statement.scope.clone();
        match field {
            0 => changed.poll[0] ^= 1,
            1 => changed.roster[0] ^= 1,
            2 => changed.author = 2,
            _ => changed.sealed_body[0] ^= 1,
        }
        assert!(Statement::decode(&encoded, &changed).is_err());
    }
    let coefficient = encoded.len() - (1 + 3 * RECIPIENTS) * DEGREE * 21;
    for sign in [1, 2] {
        let mut changed = encoded.clone();
        changed[coefficient] = sign;
        assert!(Statement::decode(&changed, &statement.scope).is_err());
    }
    let mut changed = encoded.clone();
    changed[coefficient + 1..coefficient + 21].fill(255);
    assert!(Statement::decode(&changed, &statement.scope).is_err());
    assert!(Statement::decode(&encoded[..encoded.len() - 1], &statement.scope).is_err());
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(Statement::decode(&changed, &statement.scope).is_err());
    let mut changed = statement.clone();
    changed.recipients.swap(0, 1);
    assert_ne!(changed.digest().unwrap(), statement.digest().unwrap());
}

#[test]
fn common_word_engine_checks_ranges_and_sparse_supports_of_the_bound_witness() {
    let (_, witness) = fixture();
    let layout = Layout::new(encoded_bytes());
    assert_eq!(witness.relation, layout.relation);
    assert_eq!(witness.columns[layout.seed][0], 1);
    assert_eq!(witness.columns[layout.seed][STRIDE], 0);
    for corruption in 0..3 {
        let mut columns = witness.columns.clone();
        match corruption {
            0 => columns[layout.seed][0] = 2,
            1 => {
                columns[layout.relation.words][0] = 1;
                columns[layout.relation.words + 1][0] = 1;
            }
            _ => {
                let positive = &mut columns[layout.relation.words];
                let row = positive.iter().position(|value| *value == 1).unwrap();
                positive[row] = 0;
            }
        }
        assert!(Witness::from_columns(&layout.relation, witness.statement, columns).is_err());
    }
    let (scope, common, keys) = public_inputs();
    let mut outside = inputs();
    outside.sharing[0] = 1i128 << (profile().sharing_coefficient_bits() - 1);
    assert!(witness::create(scope, common, keys, outside).is_err());
}

#[test]
fn honest_witness_satisfies_every_weighted_relation() {
    let (statement, witness) = fixture();
    for challenge in [[17, 29, 43], [911, 71, 5]] {
        let operator = operator::build(&statement, challenge).unwrap();
        let mut sum = ZERO;
        for term in &operator.terms {
            let word_proof::affine::PublicColumn::Values(values) = &term.public else {
                panic!("Unexpected fixture operator")
            };
            for &(column, weight) in &term.weights {
                for (row, &coefficient) in values.iter().enumerate() {
                    sum = field::add(
                        sum,
                        field::scale(
                            field::multiply(weight, coefficient),
                            u128::from(witness.columns[column][row * STRIDE]),
                        ),
                    );
                }
            }
        }
        assert_eq!(sum, operator.target);
    }
}
