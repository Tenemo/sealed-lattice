//! Fixed algebra operands. These helpers do not admit predecessor proofs or
//! manufacture verified holders; the native check must perform that work.
use crate::{
    DEGREE, Error, RECIPIENTS, SCALE, SELECTED, SUPPORT, center, maximum_share, profile,
    statement::{FixtureSelection, Statement},
    witness,
};
use num_bigint::Sign;
use seed_sharing_proof::{statement::Statement as SeedStatement, witness::Inputs};
use word_proof::oracles::Witness;

pub fn recipient_secret(recipient: usize) -> Vec<i8> {
    assert!(recipient < RECIPIENTS);
    (0..DEGREE)
        .map(|row| {
            if (row + recipient * 17) % DEGREE < SUPPORT / 2 {
                1
            } else {
                -1
            }
        })
        .collect()
}
pub fn second_source(original: &SeedStatement) -> (SeedStatement, Witness) {
    let radius = 1i128 << (profile().sharing_coefficient_bits() - 1);
    let mut scope = original.scope.clone();
    scope.author = 0;
    scope.sealed_body = [7; 64];
    let input = Inputs {
        seed: vec![0, 1, 0, 1],
        sharing: (0..DEGREE)
            .map(|row| match row % 5 {
                0 => -radius,
                1 => -radius + 1,
                2 => radius - 2,
                3 => radius - 1,
                _ => row as i128 * 23 - 1000,
            })
            .collect(),
        ephemeral: (0..RECIPIENTS)
            .map(|recipient| {
                (0..DEGREE)
                    .map(|row| {
                        if (row * 19 + recipient * 31 + 11) % DEGREE < SUPPORT / 2 {
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
                        .map(|row| {
                            if (row + recipient + component) % 2 == 0 {
                                -64
                            } else {
                                63
                            }
                        })
                        .collect()
                })
            })
            .collect(),
    };
    seed_sharing_proof::witness::create(
        scope,
        original.common.clone(),
        original
            .recipients
            .iter()
            .map(|recipient| recipient.public_key.clone())
            .collect(),
        input,
    )
    .unwrap()
}

pub fn selection(original: &SeedStatement, records: [[u8; 64]; SELECTED]) -> FixtureSelection {
    FixtureSelection {
        poll: original.scope.poll,
        roster: original.scope.roster,
        runtime: [9; 64],
        records,
    }
}
/// Test-only original-key decoding, never a participant or public decrypt API.
pub fn messages(sources: [&SeedStatement; SELECTED], recipient: usize) -> [Vec<i128>; SELECTED] {
    let secret = recipient_secret(recipient);
    sources.map(|source| {
        let encrypted = &source.recipients[recipient].ciphertext;
        witness::product(&encrypted[1], &secret)
            .into_iter()
            .zip(&encrypted[0])
            .map(|(linear, constant)| {
                let phase = center(linear + constant);
                let magnitude = (phase.magnitude() + num_bigint::BigUint::from(SCALE as u128 / 2))
                    / num_bigint::BigUint::from(SCALE as u128);
                let magnitude = i128::try_from(magnitude).unwrap();
                let value = if phase.sign() == Sign::Minus {
                    -magnitude
                } else {
                    magnitude
                };
                assert!((-maximum_share()..=maximum_share()).contains(&value));
                value
            })
            .collect()
    })
}
pub fn algebra(recipient: usize) -> (Statement, Witness, Vec<i8>) {
    let (first, _) = seed_sharing_proof::fixture::create();
    let (second, _) = second_source(&first);
    // Statement hashes label unverified algebra inputs only. They are not
    // identities returned by the verified-record constructor.
    let descriptor = selection(&first, [first.digest().unwrap(), second.digest().unwrap()]);
    let statement = Statement::from_sources(
        descriptor,
        recipient as u16,
        [&first, &second],
        messages([&first, &second], recipient),
    )
    .unwrap();
    let secret = recipient_secret(recipient);
    let witness = witness::create(&statement, &secret).unwrap();
    (statement, witness, secret)
}
/// A fresh canonical false statement on ordinary nonzero source ciphertexts.
/// Its proof requires the shared test-only adversarial-affine producer mode.
pub fn shifted_share(statement: &Statement) -> Result<Statement, Error> {
    let mut shifted = statement.clone();
    let value = shifted.packages[0]
        .message
        .iter_mut()
        .find(|value| **value > -maximum_share() && **value < maximum_share())
        .ok_or("No interior fixture share")?;
    *value += 1;
    shifted.encode()?;
    Ok(shifted)
}
