use super::*;
use crate::{
    CHUNK_LIMIT, HEADER_LENGTH,
    statement::{coefficient_bytes, tests::synthetic_ballot},
    verifier,
};
use parallel_work::random::{self, Purpose};
use std::cell::Cell;
use supported_profile::{Family, Profile, relation::ballot_relation};

thread_local! {
    // The state of the SplitMix64 stream that serves the proof's draws, as
    // an operation's retained seed serves them.
    static PROOF_STREAM: Cell<u64> = const { Cell::new(0) };
}

fn serve(purpose: Purpose, bytes: &mut [u8]) -> bool {
    if purpose != Purpose::Proof {
        return false;
    }
    PROOF_STREAM.with(|stream| {
        let mut state = stream.get();
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut word = state;
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            word ^= word >> 31;
            chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
        }
        stream.set(state);
    });
    true
}

fn verify(profile: Profile, role: &[u8], statement: &PublicStatement, proof: &[u8]) -> bool {
    let Ok(mut verifier) = verifier(profile, role, &proof[..HEADER_LENGTH]) else {
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
fn ballot_proofs_verify_only_for_their_role_profile_inputs_and_true_ciphertext() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"ballot-proof-test";
    let (statement, columns) = synthetic_ballot(profile);
    let relation = ballot_relation(profile);
    PROOF_STREAM.with(|stream| stream.set(3));
    random::install(serve);
    let witness = Witness::from_columns(&relation, statement.digest(), columns).unwrap();
    let proof = prove(role, &statement, witness, false);
    random::release();
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    drop(proof);
    assert!(bytes.len() <= relation.maximum_proof_bytes());
    assert!(verify(profile, role, &statement, &bytes));
    assert!(!verify(profile, b"another-role", &statement, &bytes));
    // The same bytes are a statement of another option count only by
    // header, which that profile's verifier refuses.
    assert!(!verify(
        Profile::new(3, 3).unwrap(),
        role,
        &statement,
        &bytes
    ));
    // The relation verifier states its setup's inputs itself, so a proof
    // made over other inputs is refused: here the fixed auxiliary public
    // key differs by its first coefficient, nonzero and negated.
    let width = coefficient_bytes(profile, Family::Auxiliary);
    let mut polynomials = statement.polynomials.clone();
    assert!(polynomials[5][1..width].iter().any(|byte| *byte != 0));
    polynomials[5][0] ^= 1;
    let substituted = PublicStatement {
        profile,
        header: statement.header.clone(),
        polynomials,
    };
    assert!(!verify(profile, role, &substituted, &bytes));
    // A proof for a ciphertext coefficient changed by one cannot meet
    // the affine relation. The coefficient is uniform, so its magnitude
    // stays nonzero and below half the modulus.
    let (mut statement, columns) = synthetic_ballot(profile);
    statement.polynomials[2][1] ^= 1;
    random::install(serve);
    let witness = Witness::from_columns(&relation, statement.digest(), columns).unwrap();
    let proof = prove(role, &statement, witness, true);
    random::release();
    let mut bytes = Vec::new();
    proof.write(&mut bytes);
    assert!(!verify(profile, role, &statement, &bytes));
}

// Every edit of an honest proof is refused: a commitment root, a fold root
// and the terminal value of its header, the first and last bytes of its
// openings and one between, one byte less and one byte more.
#[test]
fn edited_ballot_proofs_are_refused() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"ballot-proof-test";
    let (statement, columns) = synthetic_ballot(profile);
    let relation = ballot_relation(profile);
    PROOF_STREAM.with(|stream| stream.set(5));
    random::install(serve);
    let witness = Witness::from_columns(&relation, statement.digest(), columns).unwrap();
    let mut bytes = Vec::new();
    prove(role, &statement, witness, false).write(&mut bytes);
    random::release();
    assert!(verify(profile, role, &statement, &bytes));
    // The header holds the magic, the statement and context digests, three
    // roots, the mask sum, twenty message salts, the fold roots and the
    // terminal value.
    let first_root = 4 + 64 + 64;
    let first_fold_root = first_root + 3 * 64 + 48 + 20 * 128;
    for offset in [
        first_root,
        first_fold_root,
        HEADER_LENGTH - 48,
        HEADER_LENGTH,
        (HEADER_LENGTH + bytes.len()) / 2,
        bytes.len() - 1,
    ] {
        let mut edited = bytes.clone();
        edited[offset] ^= 1;
        assert!(!verify(profile, role, &statement, &edited), "{offset}");
    }
    assert!(!verify(
        profile,
        role,
        &statement,
        &bytes[..bytes.len() - 1]
    ));
    assert!(!verify(
        profile,
        role,
        &statement,
        &[&bytes[..], &[0]].concat()
    ));
}

// Statistical zero knowledge allows one published proof for each mask
// draw. A proof replayed from the same draw, as an operation's retained
// seed replays it, repeats its bytes, and another draw gives another
// proof.
#[test]
fn a_replayed_mask_draw_repeats_its_proof() {
    let profile = Profile::new(3, 2).unwrap();
    let role = b"ballot-proof-test";
    let (statement, columns) = synthetic_ballot(profile);
    let relation = ballot_relation(profile);
    let prove = |seed| {
        PROOF_STREAM.with(|stream| stream.set(seed));
        random::install(serve);
        let witness =
            Witness::from_columns(&relation, statement.digest(), columns.clone()).unwrap();
        let mut bytes = Vec::new();
        prove(role, &statement, witness, false).write(&mut bytes);
        random::release();
        bytes
    };
    let first = prove(1);
    assert!(verify(profile, role, &statement, &first));
    assert_eq!(prove(1), first);
    assert_ne!(prove(2), first);
}
