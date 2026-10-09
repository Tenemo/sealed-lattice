use super::*;
use crate::{
    CHUNK_LIMIT, HEADER_LENGTH, ReleaseInputs, derive_bound, statement::share_modulus, verifier,
    witness::tests::synthetic_release,
};
use num_bigint::BigInt;
use parallel_work::random::{self, Purpose};
use setup_witness::{contribution::common_share_polynomial, registration::RegistrationKey};
use sha3::{
    Digest, Sha3_512, Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::cell::RefCell;
use supported_profile::{DEGREE, Profile, RECIPIENT_SECRET_SUPPORT, SHARE_SCALE};

fn verify(profile: Profile, role: &[u8], statement: &PublicStatement, proof: &[u8]) -> bool {
    let Ok(mut verifier) = verifier(profile, role, statement.digest(), &proof[..HEADER_LENGTH])
    else {
        return false;
    };
    for part in std::iter::once(&statement.header).chain(&statement.polynomials) {
        for chunk in part.chunks(CHUNK_LIMIT) {
            if verifier.push_statement(chunk).is_err() {
                return false;
            }
        }
    }
    if verifier.finish_statement().is_err() {
        return false;
    }
    for chunk in proof[HEADER_LENGTH..].chunks(CHUNK_LIMIT) {
        if verifier.push_proof(chunk).is_err() {
            return false;
        }
    }
    verifier.finish()
}

#[test]
fn release_proofs_verify_only_for_their_role_and_true_partial() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"release-proof-test";
    let (prepared, _) = synthetic_release(profile);
    let (statement, proof) = prove(role, prepared);
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    assert!(bytes.len() <= release_relation(profile).maximum_proof_bytes());
    assert!(verify(profile, role, &statement, &bytes));
    assert!(!verify(profile, b"another-role", &statement, &bytes));
    // A proof of a partial decryption one less than the derived value
    // cannot meet the affine relation.
    let (mut prepared, _) = synthetic_release(profile);
    let width = supported_profile::relation::release_coefficient_bytes(profile);
    let coefficient = &mut prepared.statement.polynomials[5][..width];
    let mut magnitude = num_bigint::BigUint::from_bytes_le(&coefficient[1..]);
    let negative = coefficient[0] == 1;
    if negative {
        magnitude += 1u32;
    } else if magnitude == num_bigint::BigUint::from(0u32) {
        magnitude = num_bigint::BigUint::from(1u32);
        coefficient[0] = 1;
    } else {
        magnitude -= 1u32;
    }
    let encoded = magnitude.to_bytes_le();
    coefficient[1..].fill(0);
    coefficient[1..1 + encoded.len()].copy_from_slice(&encoded);
    let relation = release_relation(profile);
    let witness = Witness::from_columns(
        &relation,
        prepared.statement.digest(),
        std::mem::take(&mut *prepared.columns),
    )
    .unwrap();
    let statement = &prepared.statement;
    let proof = OneShotProof::create(
        role,
        witness,
        &statement.header,
        &statement.polynomials,
        |alpha| statement.operator(alpha).unwrap(),
        true,
    );
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    assert!(!verify(profile, role, &prepared.statement, &bytes));
}

// The statement and proof digest of the seed-one release below, recorded
// while the setup witness still prepared the release's inputs.
const REPLAYED_RELEASE: &str = "9cd4a46a493e88376e9a28a084330ff19a45d423ddf11094334ac8df02615e63\
                                69429f806e19a8106298d565b4d567cfe9235b06a83502acbbdd78be8b86e46c";

thread_local! {
    // The fixture's witness and proof streams, which serve the key's and
    // the release's draws in place of the host's randomness.
    static DRAWS: RefCell<Option<[Shake256Reader; 2]>> = const { RefCell::new(None) };
}

// A SHAKE256 stream of the label and the seed.
fn stream(label: &str, seed: u8) -> Shake256Reader {
    let mut hasher = Shake256::default();
    hasher.update(label.as_bytes());
    hasher.update(&[seed]);
    hasher.finalize_xof()
}

fn serve(purpose: Purpose, bytes: &mut [u8]) -> bool {
    let index = match purpose {
        Purpose::Witness => 0,
        Purpose::Proof => 1,
        Purpose::Ballot => return false,
    };
    DRAWS.with(|draws| draws.borrow_mut().as_mut().unwrap()[index].read(bytes));
    true
}

// An integer of at most the bound in magnitude.
fn small(stream: &mut Shake256Reader, bound: u32) -> BigInt {
    let mut bytes = [0; 4];
    stream.read(&mut bytes);
    BigInt::from(i64::from(u32::from_le_bytes(bytes) % (2 * bound + 1)) - i64::from(bound))
}

// The terms of a sparse polynomial, half of them one and the rest minus one.
fn sparse(stream: &mut Shake256Reader, support: usize) -> Vec<(usize, bool)> {
    let mut terms: Vec<(usize, bool)> = Vec::with_capacity(support);
    while terms.len() < support {
        let mut bytes = [0; 4];
        stream.read(&mut bytes);
        let position = u32::from_le_bytes(bytes) as usize % DEGREE;
        if terms.iter().all(|(other, _)| *other != position) {
            terms.push((position, terms.len() < support / 2));
        }
    }
    terms
}

// The negacyclic product of a polynomial with a sparse one.
fn product(values: &[BigInt], terms: &[(usize, bool)]) -> Vec<BigInt> {
    (0..DEGREE)
        .map(|position| {
            let mut sum = BigInt::from(0);
            for &(term, positive) in terms {
                let (index, wrapped) = if position >= term {
                    (position - term, false)
                } else {
                    (position + DEGREE - term, true)
                };
                if positive != wrapped {
                    sum += &values[index];
                } else {
                    sum -= &values[index];
                }
            }
            sum
        })
        .collect()
}

fn centered(value: BigInt, modulus: &BigInt) -> BigInt {
    let reduced = ((value % modulus) + modulus) % modulus;
    if reduced > modulus >> 1usize {
        reduced - modulus
    } else {
        reduced
    }
}

// The last position's release header and its public inputs: an encryption
// of small shares under the key with small errors, and a target.
fn release_inputs(
    key: &RegistrationKey,
    profile: Profile,
    seed: u8,
) -> ([u8; RELEASE_HEADER_BYTES], [Vec<BigInt>; 3]) {
    let mut inputs = stream("inputs", seed);
    let modulus = share_modulus();
    let common = common_share_polynomial();
    let ephemeral = sparse(&mut inputs, RECIPIENT_SECRET_SUPPORT);
    let linear = product(&common, &ephemeral)
        .into_iter()
        .map(|value| centered(value + small(&mut inputs, 8), &modulus))
        .collect();
    let constant = product(key.public_key(), &ephemeral)
        .into_iter()
        .map(|value| {
            let share = small(&mut inputs, 1 << 10);
            centered(
                value + small(&mut inputs, 8) + BigInt::from(SHARE_SCALE) * share,
                &modulus,
            )
        })
        .collect();
    let target = (0..DEGREE).map(|_| small(&mut inputs, 1 << 20)).collect();
    let mut header = [0; RELEASE_HEADER_BYTES];
    header[..4].copy_from_slice(RELEASE_HEADER_MAGIC);
    let position = (profile.participants() - 1) as u16;
    header[RELEASE_HEADER_BYTES - 2..].copy_from_slice(&position.to_le_bytes());
    (header, [constant, linear, target])
}

// The digest of the statement and proof of a release to a registration key
// generated from the seed's witness stream and proved from its proof stream,
// as the participant's release proves it with the key's lent secret.
fn replayed_release(seed: u8) -> String {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"registration-key-release-fixture";
    DRAWS.with(|draws| {
        *draws.borrow_mut() = Some([stream("witness", seed), stream("proof", seed)]);
    });
    random::install(serve);
    let key = RegistrationKey::new();
    let (header, [constant, linear, target]) = release_inputs(&key, profile, seed);
    let (statement, proof) = key
        .lend_secret(|secret| {
            let inputs = ReleaseInputs::new(
                profile,
                common_share_polynomial(),
                key.public_key().to_vec(),
                constant,
                linear,
                target,
                secret,
            )
            .unwrap();
            prove(role, derive_bound(inputs, header).unwrap())
        })
        .unwrap();
    random::release();
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    assert!(verify(profile, role, &statement, &bytes));
    Sha3_512::digest([statement.digest().as_slice(), &bytes].concat())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// Statistical zero knowledge allows one published proof for each mask
// draw. A release replayed from the seed that drew its key and its masks,
// as its retained seed replays it, repeats its statement and proof bytes,
// and another seed gives another release.
#[test]
fn a_replayed_seed_repeats_its_registration_key_release() {
    assert_eq!(replayed_release(1), REPLAYED_RELEASE);
    assert_ne!(replayed_release(2), REPLAYED_RELEASE);
}
