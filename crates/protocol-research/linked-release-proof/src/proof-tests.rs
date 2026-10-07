use super::*;
use crate::{CHUNK_LIMIT, HEADER_LENGTH, verifier, witness::tests::synthetic_release};
use supported_profile::Profile;

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
    let width = crate::statement::release_coefficient_bytes(profile);
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

// Statistical zero knowledge allows one published proof for each mask
// draw. A release replayed from the same draw, as its retained seed
// replays it, repeats its statement and proof bytes, and another draw
// gives another proof.
#[test]
fn a_replayed_mask_draw_repeats_its_release() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"release-proof-test";
    let release = |seed| {
        word_proof::random::REPLAYED.with(|replayed| replayed.set(Some(seed)));
        let (prepared, _) = synthetic_release(profile);
        let (statement, proof) = prove(role, prepared);
        let mut bytes = Vec::new();
        proof.write(&mut bytes);
        (statement, bytes)
    };
    let (statement, first) = release(1);
    assert!(verify(profile, role, &statement, &first));
    let (replayed, again) = release(1);
    assert_eq!(replayed.digest(), statement.digest());
    assert_eq!(again, first);
    assert_ne!(release(2).1, first);
}
