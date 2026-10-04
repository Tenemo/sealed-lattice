use crate::{
    DEGREE, RECIPIENTS, SELECTED, fixture, maximum_share, predecessor,
    statement::{Statement, encoded_bytes},
    verification, witness,
};
use std::io::{self, Cursor, Read};
use word_verifier::{HEADER_LENGTH, Refusal};

#[test]
fn canonical_statement_binds_every_context_and_public_operand() {
    let (statement, _, _) = fixture::algebra(2);
    let encoded = statement.encode().unwrap();
    assert_eq!(encoded.len(), encoded_bytes());
    statement.matches(&encoded).unwrap();
    for index in [0, 4, 16, 52, 116, 180, 244, 308, 372, encoded.len() - 1] {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(statement.matches(&changed).is_err(), "changed byte {index}");
    }
    assert!(statement.matches(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(statement.matches(&trailing).is_err());
    for context in 0..6 {
        let mut other = statement.clone();
        match context {
            0 => other.selection.poll[0] ^= 1,
            1 => other.selection.roster[0] ^= 1,
            2 => other.selection.runtime[0] ^= 1,
            3 => other.selection.records.swap(0, 1),
            4 => other.recipient = 1,
            _ => other.packages.swap(0, 1),
        }
        assert_ne!(statement.digest().unwrap(), other.digest().unwrap());
        assert!(statement.matches(&other.encode().unwrap()).is_err());
    }
}

#[test]
fn canonical_ranges_refuse_aliases_and_malformed_shapes_before_witness_work() {
    let (statement, _, secret) = fixture::algebra(1);
    let radius = maximum_share();
    let proof_prime = crate::modulus() / crate::SCALE;
    for boundary in [-radius, radius] {
        let mut edge = statement.clone();
        edge.packages[0].message[0] = boundary;
        assert!(edge.encode().is_ok());
    }
    for invalid in [-radius - 1, radius + 1] {
        let mut edge = statement.clone();
        edge.packages[0].message[0] = invalid;
        assert!(edge.encode().is_err());
        assert!(witness::create(&edge, &secret).is_err());
    }
    // Adding the proof prime leaves D unchanged modulo Q. Public canonical
    // range, rather than the affine proof, must exclude that alias.
    let message = statement.packages[0].message[0];
    assert!(num_bigint::BigInt::from(message) + &proof_prime > num_bigint::BigInt::from(radius));
    assert_eq!(
        crate::center(
            &statement.packages[0].constant[0] - num_bigint::BigInt::from(crate::SCALE) * message
        ),
        crate::center(
            &statement.packages[0].constant[0]
                - num_bigint::BigInt::from(crate::SCALE)
                    * (num_bigint::BigInt::from(message) + proof_prime)
        )
    );
    let mut malformed = statement.clone();
    malformed.packages[0].message.pop();
    assert!(malformed.encode().is_err());
    malformed = statement.clone();
    malformed.common[0] = crate::modulus();
    assert!(witness::create(&malformed, &secret).is_err());
    malformed = statement.clone();
    malformed.selection.records[1] = malformed.selection.records[0];
    assert!(malformed.encode().is_err());
    malformed = statement;
    malformed.recipient = RECIPIENTS as u16;
    assert!(malformed.encode().is_err());
}

#[test]
fn source_assembly_rejects_changed_original_keys_and_selection_mismatches() {
    let (first, _) = seed_sharing_proof::fixture::create();
    let (second, _) = fixture::second_source(&first);
    let descriptor =
        fixture::selection(&first, [first.digest().unwrap(), second.digest().unwrap()]);
    let messages = fixture::messages([&first, &second], 2);
    Statement::from_sources(descriptor.clone(), 2, [&first, &second], messages.clone()).unwrap();
    for change in 0..5 {
        let mut changed = second.clone();
        match change {
            0 => changed.scope.poll[0] ^= 1,
            1 => changed.scope.roster[0] ^= 1,
            2 => changed.scope.author = first.scope.author,
            3 => changed.common[0] += 1,
            _ => changed.recipients[0].public_key[0] += 1,
        }
        assert!(
            Statement::from_sources(descriptor.clone(), 2, [&first, &changed], messages.clone())
                .is_err()
        );
    }
    let mut outside_pool = second;
    outside_pool.scope.author =
        (crate::profile().release_threshold() + crate::profile().corrupt()) as u16;
    assert!(Statement::from_sources(descriptor, 2, [&first, &outside_pool], messages).is_err());
    assert_eq!(SELECTED, crate::profile().release_threshold());
    assert_eq!(DEGREE, seed_sharing_proof::DEGREE);
}

struct FailedRead;
impl Read for FailedRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture read failure"))
    }
}
#[test]
fn predecessor_admission_distinguishes_refusal_from_io_failure() {
    use seed_sharing_proof::verification::VerificationError;
    let (source, _) = seed_sharing_proof::fixture::create();
    let bytes = source.encode().unwrap();
    assert!(matches!(
        predecessor::verify(&mut Cursor::new([]), &source, &bytes),
        Err(VerificationError::Refused(Refusal::Length))
    ));
    assert!(matches!(
        predecessor::verify(&mut FailedRead, &source, &bytes),
        Err(VerificationError::Read(_))
    ));
    assert!(matches!(
        predecessor::verify(&mut FailedRead, &source, &bytes[..bytes.len() - 1]),
        Err(VerificationError::Refused(Refusal::Length))
    ));
    let mut changed = bytes;
    changed[0] ^= 1;
    assert!(matches!(
        predecessor::verify(&mut Cursor::new(vec![0; HEADER_LENGTH]), &source, &changed),
        Err(VerificationError::Refused(_))
    ));
}

#[test]
fn opening_verifier_rejects_wrong_statement_before_proof_processing() {
    let (statement, _, _) = fixture::algebra(2);
    let mut bytes = statement.encode().unwrap();
    bytes[0] ^= 1;
    assert!(matches!(
        verification::Verifier::open(&statement, &bytes, crate::ROLE, &vec![0; HEADER_LENGTH]),
        Err(Refusal::Context)
    ));
    assert!(matches!(
        verification::verify(
            &mut FailedRead,
            &statement,
            &statement.encode().unwrap(),
            crate::ROLE
        ),
        Err(verification::VerificationError::Read(_))
    ));
}
