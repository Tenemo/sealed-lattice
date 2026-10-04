use opening_share_proof::{
    DEGREE, RECIPIENTS, ROLE, SELECTED, fixture, predecessor, proof,
    statement::Statement,
    verification::{self, VerificationError},
    witness,
};
use seed_sharing_proof::verification::VerificationError as SourceError;
use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Cursor, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use word_verifier::Refusal;

fn read(path: &Path) -> io::Result<BufReader<File>> {
    File::open(path).map(BufReader::new)
}
fn source_failure(error: SourceError) -> io::Error {
    io::Error::other(format!("Source verification failed: {error:?}"))
}
fn opening_failure(error: VerificationError) -> io::Error {
    io::Error::other(format!("Opening verification failed: {error:?}"))
}
fn bytes(directory: &Path, name: &str, encoded: &[u8]) -> io::Result<()> {
    File::create_new(directory.join(name))?.write_all(encoded)
}
fn generate(
    directory: &Path,
    name: &str,
    maximum: usize,
    write: impl FnOnce(&mut BufWriter<File>) -> io::Result<()>,
) -> io::Result<(PathBuf, u64)> {
    let path = directory.join(name);
    let started = Instant::now();
    let mut file = BufWriter::new(File::create_new(&path)?);
    write(&mut file)?;
    file.flush()?;
    let length = std::fs::metadata(&path)?.len();
    if length > maximum as u64 {
        return Err(io::Error::other("Proof exceeds its derived maximum"));
    }
    println!(
        "{{\"event\":\"proof-written\",\"case\":\"{name}\",\"milliseconds\":{},\"bytes\":{length}}}",
        started.elapsed().as_millis()
    );
    Ok((path, length))
}
fn reject(name: &str, result: Result<(), VerificationError>) {
    match result {
        Err(VerificationError::Refused(reason)) => println!(
            "{{\"event\":\"proof-refused\",\"case\":\"{name}\",\"reason\":\"{reason:?}\"}}"
        ),
        Err(VerificationError::Read(error)) => panic!("Fixture read failed for {name}: {error}"),
        Ok(()) => panic!("Hostile opening accepted: {name}"),
    }
}
fn reject_source(name: &str, result: Result<predecessor::VerifiedSeedSharingRecord, SourceError>) {
    match result {
        Err(SourceError::Refused(reason)) => println!(
            "{{\"event\":\"source-refused\",\"case\":\"{name}\",\"reason\":\"{reason:?}\"}}"
        ),
        Err(SourceError::Read(error)) => panic!("Fixture read failed for {name}: {error}"),
        Ok(_) => panic!("Hostile source admitted: {name}"),
    }
}
fn hex(value: [u8; 64]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let source_directory = PathBuf::from(
        arguments
            .next()
            .ok_or("Missing fresh seed artifact directory")?,
    );
    let output = PathBuf::from(
        arguments
            .next()
            .ok_or("Missing opening artifact directory")?,
    );
    if arguments.next().is_some() {
        return Err("Unexpected fixture arguments".into());
    }
    if !source_directory.is_dir()
        || !output.is_dir()
        || source_directory.canonicalize()? == output.canonicalize()?
    {
        return Err("Expected distinct existing artifact directories".into());
    }

    let (expected, _) = seed_sharing_proof::fixture::create();
    let expected_bytes = expected.encode()?;
    let honest_source = source_directory.join("proof-honest.bin");
    let source_length = std::fs::metadata(&honest_source)?.len();
    let first = predecessor::verify(&mut read(&honest_source)?, &expected, &expected_bytes)
        .map_err(source_failure)?;
    reject_source(
        "truncated-source",
        predecessor::verify(
            &mut read(&honest_source)?.take(source_length.saturating_sub(1)),
            &expected,
            &expected_bytes,
        ),
    );
    reject_source(
        "false-source-witness",
        predecessor::verify(
            &mut read(&source_directory.join("proof-false-seed.bin"))?,
            &expected,
            &expected_bytes,
        ),
    );
    reject_source(
        "substituted-source-statement",
        predecessor::verify(
            &mut read(&source_directory.join("proof-false-share.bin"))?,
            &expected,
            &expected_bytes,
        ),
    );

    drop(expected);
    drop(expected_bytes);
    let (second_statement, second_witness) = fixture::second_source(first.statement());
    let second_bytes = second_statement.encode()?;
    bytes(&output, "statement-second-source.bin", &second_bytes)?;
    let maximum = second_witness.relation.maximum_proof_bytes();
    let (second_path, second_length) =
        generate(&output, "proof-second-source.bin", maximum, |file| {
            seed_sharing_proof::proof::write(
                &second_statement,
                second_witness,
                0x52b4_89d6_1131_a075,
                false,
                file,
            )
        })?;
    let second = predecessor::verify(&mut read(&second_path)?, &second_statement, &second_bytes)
        .map_err(source_failure)?;
    drop(second_statement);
    drop(second_bytes);

    let recipient = 2;
    let descriptor = fixture::selection(first.statement(), [first.identity(), second.identity()]);
    let messages = fixture::messages([first.statement(), second.statement()], recipient);
    let statement = Statement::from_records(
        descriptor.clone(),
        recipient as u16,
        [&first, &second],
        messages.clone(),
    )?;
    let statement_bytes = statement.encode()?;
    bytes(&output, "statement-opening-honest.bin", &statement_bytes)?;
    let secret = fixture::recipient_secret(recipient);
    let witness = witness::create(&statement, &secret)?;
    let maximum = witness.relation.maximum_proof_bytes();
    let (honest_path, honest_length) =
        generate(&output, "proof-opening-honest.bin", maximum, |file| {
            proof::write(
                &statement,
                witness,
                opening_share_proof::prover::POSITIVE_PROOF_RANDOMNESS_SEED,
                false,
                file,
            )
        })?;
    verification::verify(&mut read(&honest_path)?, &statement, &statement_bytes, ROLE)
        .map_err(opening_failure)?;

    reject(
        "truncated-opening",
        verification::verify(
            &mut read(&honest_path)?.take(honest_length.saturating_sub(1)),
            &statement,
            &statement_bytes,
            ROLE,
        ),
    );
    reject(
        "trailing-opening",
        verification::verify(
            &mut read(&honest_path)?.chain(Cursor::new([0])),
            &statement,
            &statement_bytes,
            ROLE,
        ),
    );
    reject(
        "wrong-purpose",
        verification::verify(
            &mut read(&honest_path)?,
            &statement,
            &statement_bytes,
            b"bounded-outer-seed-sharing-fixture/v1",
        ),
    );

    let mut reversed = descriptor.clone();
    reversed.records.swap(0, 1);
    let reordered = Statement::from_records(
        reversed,
        recipient as u16,
        [&second, &first],
        [messages[1].clone(), messages[0].clone()],
    )?;
    reject(
        "wrong-selected-order",
        verification::verify(
            &mut read(&honest_path)?,
            &reordered,
            &reordered.encode()?,
            ROLE,
        ),
    );
    drop(reordered);
    let different_recipient =
        Statement::from_records(descriptor.clone(), 1, [&first, &second], messages.clone())?;
    reject(
        "wrong-recipient",
        verification::verify(
            &mut read(&honest_path)?,
            &different_recipient,
            &different_recipient.encode()?,
            ROLE,
        ),
    );
    drop(different_recipient);
    let mut other_runtime = descriptor;
    other_runtime.runtime[0] ^= 1;
    let other_runtime =
        Statement::from_records(other_runtime, recipient as u16, [&first, &second], messages)?;
    reject(
        "wrong-runtime",
        verification::verify(
            &mut read(&honest_path)?,
            &other_runtime,
            &other_runtime.encode()?,
            ROLE,
        ),
    );
    drop(other_runtime);

    let shifted = fixture::shifted_share(&statement)?;
    let shifted_bytes = shifted.encode()?;
    bytes(&output, "statement-opening-shifted.bin", &shifted_bytes)?;
    assert!(witness::create(&shifted, &secret).is_err());
    let mut false_witness = witness::create(&statement, &secret)?;
    false_witness.statement = shifted.digest()?;
    let (shifted_path, shifted_length) =
        generate(&output, "proof-opening-shifted.bin", maximum, |file| {
            // Strict honest production asserts an unsatisfied affine equation.
            // This existing test-only path emits the hostile prover's response.
            proof::write(&shifted, false_witness, 0x4be2_94d9_61c7_2350, true, file)
        })?;
    let result = verification::verify(&mut read(&shifted_path)?, &shifted, &shifted_bytes, ROLE);
    assert!(
        matches!(result, Err(VerificationError::Refused(Refusal::Relation))),
        "Shifted share did not reach relation refusal: {result:?}"
    );
    reject("fresh-shifted-share", result);
    let layout = opening_share_proof::layout::Layout::new(statement_bytes.len());
    println!(
        "{{\"kind\":\"bounded-opening-share-proof\",\"degree\":{DEGREE},\"participants\":{RECIPIENTS},\"selected\":{SELECTED},\"recipient\":{recipient},\"predecessors\":2,\"positive\":1,\"falseStatements\":1,\"hostileCases\":10,\"wordColumns\":{},\"booleanColumns\":{},\"lookupEntries\":{},\"affineRows\":{},\"proofDomain\":{},\"statementBytes\":{},\"sourceIdentities\":[\"{}\",\"{}\"],\"secondSourceProofBytes\":{second_length},\"proofBytes\":{honest_length},\"shiftedProofBytes\":{shifted_length}}}",
        layout.relation.words,
        layout.relation.booleans,
        layout.relation.lookups(),
        2 * (SELECTED + 1) * DEGREE + 2,
        word_proof::parameters::DOMAIN,
        statement_bytes.len(),
        hex(first.identity()),
        hex(second.identity())
    );
    Ok(())
}
