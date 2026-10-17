use super::*;
use std::sync::OnceLock;
use word_proof::{public_evaluation::EvaluationProver, public_oracle::PublicOracleBuilder};

const ROLE: &[u8] = b"aggregate-test";
const CONTRIBUTION: &[u8] = b"contribution-test";
const AGGREGATE: [u8; 64] = [31; 64];

struct Fixture {
    profile: Profile,
    roots: Vec<[u8; 64]>,
    proof: Vec<u8>,
    expected: Element,
}

fn column(index: usize) -> Vec<u128> {
    let mut values = vec![0; SYSTEMATIC];
    values[0] = index as u128 + 1;
    values[1] = MODULUS - (index as u128 + 3);
    values[SYSTEMATIC - 1] = 2 * index as u128 + 7;
    values
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let profile = Profile::new(3, 2).unwrap();
        let mut tree = PublicOracleBuilder::new(CONTRIBUTION, profile.committed_columns()).unwrap();
        for index in 0..profile.committed_columns() {
            tree.column(&column(index)).unwrap();
        }
        let mut roots = vec![[19; 64]; profile.setup_contributors()];
        roots[0] = tree.finish().unwrap().root();
        let mut prover =
            EvaluationProver::new(profile, ROLE, &AGGREGATE, &roots, 0, CONTRIBUTION).unwrap();
        assert!(prover.finish_columns().is_err());
        assert!(prover.finish_openings().is_err());
        assert!(prover.next_output(&mut Vec::new()).is_err());
        assert!(prover.column(&[0]).is_err());
        for index in 0..profile.committed_columns() {
            prover.column(&column(index)).unwrap();
        }
        assert!(prover.column(&column(0)).is_err());
        prover.finish_columns().unwrap();
        for index in 0..profile.committed_columns() {
            prover.opening_column(&column(index)).unwrap();
        }
        prover.finish_openings().unwrap();
        let mut proof = Vec::new();
        let mut output = Vec::new();
        while prover.next_output(&mut output).unwrap() {
            assert!(output.len() <= CHUNK_LIMIT);
            proof.extend_from_slice(&output);
        }
        assert!(output.is_empty());
        assert!(!prover.next_output(&mut output).unwrap());
        let (point, weights) = aggregate_challenges(profile, ROLE, &AGGREGATE, &roots).unwrap();
        // Direct monomial evaluation is independent of the prover's Horner
        // evaluation and synthetic division.
        let mut highest = [1, 0, 0];
        let mut factor = point;
        let mut exponent = SYSTEMATIC - 1;
        while exponent != 0 {
            if exponent & 1 != 0 {
                highest = multiply(highest, factor);
            }
            factor = multiply(factor, factor);
            exponent >>= 1;
        }
        let expected = weights
            .iter()
            .enumerate()
            .fold(ZERO, |sum, (index, weight)| {
                let value = add(
                    subtract([index as u128 + 1, 0, 0], scale(point, index as u128 + 3)),
                    scale(highest, 2 * index as u128 + 7),
                );
                add(sum, multiply(*weight, value))
            });
        Fixture {
            profile,
            roots,
            proof,
            expected,
        }
    })
}

fn verify(
    bytes: &[u8],
    role: &[u8],
    aggregate: &[u8; 64],
    roots: &[[u8; 64]],
    ordinal: usize,
    contribution: &[u8],
    chunk: usize,
) -> Option<Element> {
    let fixture = fixture();
    let header = bytes.get(..EVALUATION_HEADER_BYTES)?;
    let mut verifier = EvaluationVerifier::open(
        fixture.profile,
        role,
        aggregate,
        roots,
        ordinal,
        contribution,
        header,
    )
    .ok()?;
    for part in bytes[EVALUATION_HEADER_BYTES..].chunks(chunk) {
        verifier.push(part).ok()?;
    }
    verifier.finish()
}

#[test]
fn evaluation_proof_matches_an_independent_monomial_sum_across_stream_boundaries() {
    let fixture = fixture();
    for chunk in [47, 4096, CHUNK_LIMIT] {
        assert_eq!(
            verify(
                &fixture.proof,
                ROLE,
                &AGGREGATE,
                &fixture.roots,
                0,
                CONTRIBUTION,
                chunk
            ),
            Some(fixture.expected)
        );
    }
}

#[test]
fn evaluation_proof_binds_the_aggregate_roles_roots_and_selected_ordinal() {
    let fixture = fixture();
    let mut changed_roots = fixture.roots.clone();
    changed_roots[1][0] ^= 1;
    for (role, aggregate, roots, ordinal, contribution) in [
        (
            b"other-aggregate".as_slice(),
            AGGREGATE,
            fixture.roots.as_slice(),
            0,
            CONTRIBUTION,
        ),
        (ROLE, [32; 64], fixture.roots.as_slice(), 0, CONTRIBUTION),
        (ROLE, AGGREGATE, changed_roots.as_slice(), 0, CONTRIBUTION),
        (ROLE, AGGREGATE, fixture.roots.as_slice(), 1, CONTRIBUTION),
        (
            ROLE,
            AGGREGATE,
            fixture.roots.as_slice(),
            0,
            b"other-contribution".as_slice(),
        ),
    ] {
        assert!(
            verify(
                &fixture.proof,
                role,
                &aggregate,
                roots,
                ordinal,
                contribution,
                CHUNK_LIMIT
            )
            .is_none()
        );
    }
}

#[test]
fn evaluation_proof_refuses_changed_claims_openings_noncanonical_and_incomplete_bytes() {
    let fixture = fixture();
    for position in [
        0,
        48,
        EVALUATION_HEADER_BYTES - 48,
        EVALUATION_HEADER_BYTES,
        EVALUATION_HEADER_BYTES + 8,
        fixture.proof.len() - 1,
    ] {
        let mut changed = fixture.proof.clone();
        changed[position] ^= 1;
        assert!(
            verify(
                &changed,
                ROLE,
                &AGGREGATE,
                &fixture.roots,
                0,
                CONTRIBUTION,
                CHUNK_LIMIT
            )
            .is_none(),
            "byte {position}"
        );
    }
    for length in [
        0,
        EVALUATION_HEADER_BYTES - 1,
        EVALUATION_HEADER_BYTES,
        fixture.proof.len() - 1,
    ] {
        assert!(
            verify(
                &fixture.proof[..length],
                ROLE,
                &AGGREGATE,
                &fixture.roots,
                0,
                CONTRIBUTION,
                CHUNK_LIMIT
            )
            .is_none()
        );
    }
    let mut noncanonical = fixture.proof.clone();
    noncanonical[..16].copy_from_slice(&MODULUS.to_le_bytes());
    assert!(
        verify(
            &noncanonical,
            ROLE,
            &AGGREGATE,
            &fixture.roots,
            0,
            CONTRIBUTION,
            CHUNK_LIMIT
        )
        .is_none()
    );
    let mut trailing = fixture.proof.clone();
    trailing.push(0);
    assert!(
        verify(
            &trailing,
            ROLE,
            &AGGREGATE,
            &fixture.roots,
            0,
            CONTRIBUTION,
            CHUNK_LIMIT
        )
        .is_none()
    );
    let mut verifier = EvaluationVerifier::open(
        fixture.profile,
        ROLE,
        &AGGREGATE,
        &fixture.roots,
        0,
        CONTRIBUTION,
        &fixture.proof[..EVALUATION_HEADER_BYTES],
    )
    .unwrap();
    assert!(verifier.push(&vec![0; CHUNK_LIMIT + 1]).is_err());
    assert!(verifier.push(&[]).is_err());
    assert!(verifier.finish().is_none());
}
