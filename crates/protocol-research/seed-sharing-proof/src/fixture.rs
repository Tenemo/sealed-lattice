use crate::{
    DEGREE, RECIPIENTS, SUPPORT, center, modulus, profile,
    statement::{Scope, Statement},
    witness::{self, Inputs},
};
use num_bigint::BigInt;
use word_proof::oracles::Witness;

pub(crate) fn inputs() -> Inputs {
    let radius = 1i128 << (profile().sharing_coefficient_bits() - 1);
    Inputs {
        // The later-public seed does not derive the encryption inputs or
        // sharing coefficients. These fixed sequences are independent test
        // operands, not a protocol randomness generator.
        seed: vec![1, 0, 1, 1],
        sharing: (0..DEGREE)
            .map(|row| match row {
                0 => -radius,
                1 => radius - 1,
                _ => (row as i128 * 17 % 2048) * (radius / 1024) - radius,
            })
            .collect(),
        ephemeral: (0..RECIPIENTS)
            .map(|recipient| {
                (0..DEGREE)
                    .map(|row| {
                        if (row * 13 + recipient * 29) % DEGREE < SUPPORT / 2 {
                            1
                        } else {
                            -1
                        }
                    })
                    .collect()
            })
            .collect(),
        errors: (0..RECIPIENTS)
            .map(|recipient| {
                std::array::from_fn(|component| {
                    (0..DEGREE)
                        .map(|row| ((row + recipient * 19 + component * 37) % 128) as i128 - 64)
                        .collect()
                })
            })
            .collect(),
    }
}
pub(crate) fn public_inputs() -> (Scope, Vec<BigInt>, Vec<Vec<BigInt>>) {
    let modulus = modulus();
    let common: Vec<_> = (0..DEGREE)
        .map(|row| {
            if row == 0 {
                BigInt::from(0)
            } else {
                center((&modulus / 257) * (row * 53 + 19) + row * row)
            }
        })
        .collect();
    let keys = (0..RECIPIENTS)
        .map(|recipient| {
            let secret: Vec<_> = (0..DEGREE)
                .map(|row| {
                    if (row + recipient * 17) % DEGREE < SUPPORT / 2 {
                        1
                    } else {
                        -1
                    }
                })
                .collect();
            witness::product(&common, &secret)
                .into_iter()
                .enumerate()
                .map(|(row, value)| center(-value + ((row + recipient) % 128) as i128 - 64))
                .collect()
        })
        .collect();
    (
        Scope {
            poll: [2; 64],
            roster: [3; 64],
            author: 1,
            sealed_body: [5; 64],
        },
        common,
        keys,
    )
}
pub fn create() -> (Statement, Witness) {
    let (scope, common, keys) = public_inputs();
    witness::create(scope, common, keys, inputs()).unwrap()
}

/// A synthetic zero-source encryption relation, not a sample from the
/// production common-polynomial distribution. Its public key equations are
/// satisfied by the existing sparse recipient secrets and zero key error.
pub fn zero_source() -> (Statement, Witness) {
    let (scope, _, _) = public_inputs();
    let mut private = inputs();
    private.seed.fill(0);
    private.sharing.fill(0);
    for errors in &mut private.errors {
        for error in errors {
            error.fill(0);
        }
    }
    witness::create(
        scope,
        vec![BigInt::from(0); DEGREE],
        vec![vec![BigInt::from(0); DEGREE]; RECIPIENTS],
        private,
    )
    .unwrap()
}

/// Canonical statement whose quarter-modulus share is outside every bounded
/// plaintext/noise representative of the zero-source relation. The native
/// gate and independent dense test establish that impossibility separately.
pub fn impossible_share() -> (Statement, Witness) {
    let (mut statement, mut witness) = zero_source();
    statement.recipients[0].ciphertext[0][0] = modulus() / 4u8;
    witness.statement = statement.digest().unwrap();
    (statement, witness)
}
