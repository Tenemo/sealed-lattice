use seed_sharing_proof::{
    DEGREE, RECIPIENTS, SEED_BITS, fixture,
    layout::Layout,
    proof::{self, VerificationError},
    statement::{Statement, encoded_bytes},
};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufReader, BufWriter, Cursor, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use word_proof::{oracles::Witness, parameters::DOMAIN};
use word_verifier::{HEADER_LENGTH, Refusal};

// Changes only the requested public proof bytes as the verifier streams
// them. It retains no whole proof and writes no modified artifact.
struct Patched<R> {
    source: R,
    offset: usize,
    patch_offset: usize,
    patch: Vec<u8>,
}
impl<R: Read> Read for Patched<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(output)?;
        for (index, byte) in output[..count].iter_mut().enumerate() {
            let position = self.offset + index;
            if let Some(relative) = position.checked_sub(self.patch_offset)
                && let Some(replacement) = self.patch.get(relative)
            {
                *byte = *replacement;
            }
        }
        self.offset += count;
        Ok(count)
    }
}
fn read(path: &Path) -> io::Result<BufReader<File>> {
    File::open(path).map(BufReader::new)
}
fn generate(
    directory: &Path,
    name: &str,
    statement: &Statement,
    witness: Witness,
    seed: u64,
    false_affine: bool,
) -> io::Result<(PathBuf, u64)> {
    let path = directory.join(format!("proof-{name}.bin"));
    let started = Instant::now();
    let maximum = witness.relation.maximum_proof_bytes() as u64;
    let file = File::create_new(&path)?;
    proof::write(
        statement,
        witness,
        seed,
        false_affine,
        &mut BufWriter::new(file),
    )?;
    let bytes = std::fs::metadata(&path)?.len();
    assert!(bytes <= maximum, "Proof exceeds the derived maximum");
    println!(
        "{{\"event\":\"proof-written\",\"case\":\"{name}\",\"milliseconds\":{},\"bytes\":{bytes}}}",
        started.elapsed().as_millis()
    );
    Ok((path, bytes))
}
fn reject(name: &str, result: Result<(), VerificationError>) {
    match result {
        Err(VerificationError::Refused(reason)) => println!(
            "{{\"event\":\"proof-refused\",\"case\":\"{name}\",\"reason\":\"{reason:?}\"}}"
        ),
        Err(VerificationError::Read(error)) => panic!("Fixture read failed for {name}: {error}"),
        Ok(()) => panic!("Hostile proof accepted: {name}"),
    }
}
fn reject_relation(name: &str, result: Result<(), VerificationError>) {
    assert!(
        matches!(result, Err(VerificationError::Refused(Refusal::Relation))),
        "Fresh negative did not reach relation rejection: {name}: {result:?}"
    );
    reject(name, result);
}
#[derive(Debug, PartialEq, Eq)]
struct GuardGates {
    start: PathBuf,
    finish: PathBuf,
}
fn arguments(
    values: impl IntoIterator<Item = OsString>,
) -> Result<(PathBuf, bool, Option<GuardGates>), &'static str> {
    let mut values = values.into_iter();
    let first = values.next().ok_or("Missing artifact directory")?;
    let verify_existing = first == "--verify-existing";
    let directory = if verify_existing {
        values.next().ok_or("Missing existing artifact directory")?
    } else {
        if first.to_string_lossy().starts_with("--") {
            return Err("Unknown fixture option");
        }
        first
    };
    let mut start = None;
    let mut finish = None;
    while let Some(option) = values.next() {
        if !verify_existing {
            return Err("Guard gates require existing verification");
        }
        let destination = match option.to_str() {
            Some("--guard-start") => &mut start,
            Some("--guard-finish") => &mut finish,
            _ => return Err("Unknown fixture option"),
        };
        if destination.is_some() {
            return Err("Duplicate guard gate");
        }
        let path = values.next().ok_or("Missing guard gate path")?;
        if path.is_empty() || path.to_string_lossy().starts_with("--") {
            return Err("Missing guard gate path");
        }
        *destination = Some(PathBuf::from(path));
    }
    let gates = match (start, finish) {
        (None, None) => None,
        (Some(start), Some(finish)) if start != finish => Some(GuardGates { start, finish }),
        (Some(_), Some(_)) => return Err("Guard gates must be distinct"),
        _ => return Err("Guard gates must be paired"),
    };
    Ok((PathBuf::from(directory), verify_existing, gates))
}

// The runner owns these fresh scratch paths and publishes an empty regular
// file only after taking its process-tree sample. This binary only reads
// them; gate coordination never retries or changes proof verification.
impl GuardGates {
    fn validate(self) -> io::Result<Self> {
        let resolve = |path: &Path| -> io::Result<PathBuf> {
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::other("Invalid guard gate filename"))?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let resolved = parent.canonicalize()?.join(name);
            match std::fs::symlink_metadata(&resolved) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(resolved),
                Err(error) => Err(error),
                Ok(_) => Err(io::Error::other("Guard gate already exists")),
            }
        };
        let start = resolve(&self.start)?;
        let finish = resolve(&self.finish)?;
        let same = start == finish
            || (cfg!(windows)
                && start
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&finish.to_string_lossy()));
        if same {
            return Err(io::Error::other("Guard gates must be distinct"));
        }
        Ok(Self { start, finish })
    }
}
fn wait_gate(path: &Path) -> io::Result<()> {
    let started = Instant::now();
    loop {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => return Ok(()),
            Ok(_) => return Err(io::Error::other("Guard gate must be an empty regular file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if started.elapsed() >= Duration::from_secs(60) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Guard gate timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn verify_existing(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let expected = fixture::create().0;
    let honest = directory.join("proof-honest.bin");
    let false_witness = directory.join("proof-false-seed.bin");
    let false_statement = directory.join("proof-false-share.bin");
    proof::verify(
        &mut read(&honest)?,
        &expected,
        &expected.encode()?,
        proof::ROLE,
    )
    .map_err(|error| format!("Existing honest proof rejected: {error:?}"))?;
    reject_relation(
        "existing-false-witness",
        proof::verify(
            &mut read(&false_witness)?,
            &expected,
            &expected.encode()?,
            proof::ROLE,
        ),
    );
    let expected = fixture::impossible_share().0;
    reject_relation(
        "existing-false-statement",
        proof::verify(
            &mut read(&false_statement)?,
            &expected,
            &expected.encode()?,
            proof::ROLE,
        ),
    );
    println!(
        "{{\"kind\":\"seed-sharing-existing-verification\",\"positive\":1,\"falseWitnesses\":1,\"falseStatements\":1,\"proofBytes\":[{},{},{}]}}",
        std::fs::metadata(honest)?.len(),
        std::fs::metadata(false_witness)?.len(),
        std::fs::metadata(false_statement)?.len()
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, existing, gates) = arguments(std::env::args_os().skip(1))?;
    if !directory.is_dir() {
        return Err("The artifact directory must exist".into());
    }
    let directory = directory.canonicalize()?;
    if existing {
        let gates = gates.map(GuardGates::validate).transpose()?;
        if let Some(gates) = &gates {
            println!("{{\"event\":\"native-verifier-ready\"}}");
            io::stdout().flush()?;
            wait_gate(&gates.start)?;
        }
        let started = Instant::now();
        verify_existing(&directory)?;
        let verification_milliseconds = started.elapsed().as_millis();
        if let Some(gates) = &gates {
            println!(
                "{{\"event\":\"native-verifier-completed\",\"verificationMilliseconds\":{verification_milliseconds}}}"
            );
            io::stdout().flush()?;
            wait_gate(&gates.finish)?;
        }
        return Ok(());
    }
    let (expected, witness) = fixture::create();
    let statement_bytes = expected.encode()?;
    let (honest, honest_bytes) = generate(
        &directory,
        "honest",
        &expected,
        witness,
        0x2165_5c07_319b_8481,
        false,
    )?;
    let started = Instant::now();
    proof::verify(
        &mut read(&honest)?,
        &expected,
        &statement_bytes,
        proof::ROLE,
    )
    .map_err(|error| format!("Honest proof rejected: {error:?}"))?;
    println!(
        "{{\"event\":\"proof-verified\",\"case\":\"honest\",\"milliseconds\":{}}}",
        started.elapsed().as_millis()
    );
    let mut hostile_cases = 0;
    for change in 0..5 {
        let mut other = expected.clone();
        let name = match change {
            0 => {
                other.scope.poll[0] ^= 1;
                "wrong-poll"
            }
            1 => {
                other.scope.roster[0] ^= 1;
                "wrong-roster"
            }
            2 => {
                other.scope.author = 2;
                "wrong-author"
            }
            3 => {
                other.scope.sealed_body[0] ^= 1;
                "wrong-sealed-body"
            }
            _ => {
                other.recipients.swap(0, 1);
                "wrong-recipient-order"
            }
        };
        reject(
            name,
            proof::verify(&mut read(&honest)?, &other, &other.encode()?, proof::ROLE),
        );
        hostile_cases += 1;
    }
    reject(
        "wrong-proof-role",
        proof::verify(
            &mut read(&honest)?,
            &expected,
            &statement_bytes,
            b"another-outer-role",
        ),
    );
    hostile_cases += 1;
    let mut changed = expected.clone();
    changed.recipients[0].ciphertext[0][7] += 1;
    reject(
        "changed-supplied-share",
        proof::verify(
            &mut read(&honest)?,
            &expected,
            &changed.encode()?,
            proof::ROLE,
        ),
    );
    hostile_cases += 1;
    let mut noncanonical = statement_bytes.clone();
    let first_coefficient = encoded_bytes() - (1 + 3 * RECIPIENTS) * DEGREE * 21;
    noncanonical[first_coefficient] = 1; // The common polynomial begins with zero.
    reject(
        "negative-zero-statement",
        proof::verify(&mut read(&honest)?, &expected, &noncanonical, proof::ROLE),
    );
    hostile_cases += 1;
    reject(
        "truncated-statement",
        proof::verify(
            &mut read(&honest)?,
            &expected,
            &statement_bytes[..statement_bytes.len() - 1],
            proof::ROLE,
        ),
    );
    hostile_cases += 1;
    for (name, length) in [
        ("truncated-proof-header", (HEADER_LENGTH - 1) as u64),
        ("truncated-proof-body", honest_bytes - 1),
    ] {
        reject(
            name,
            proof::verify(
                &mut read(&honest)?.take(length),
                &expected,
                &statement_bytes,
                proof::ROLE,
            ),
        );
        hostile_cases += 1;
    }
    let mut noncanonical = Patched {
        source: read(&honest)?,
        offset: 0,
        patch_offset: 4 + 5 * 64,
        patch: word_proof::field::MODULUS.to_le_bytes().to_vec(),
    };
    let result = proof::verify(&mut noncanonical, &expected, &statement_bytes, proof::ROLE);
    assert!(matches!(
        result,
        Err(VerificationError::Refused(Refusal::Encoding))
    ));
    reject("noncanonical-proof-field", result);
    hostile_cases += 1;
    let mut altered_root = Patched {
        source: read(&honest)?,
        offset: 0,
        patch_offset: 4 + 2 * 64,
        patch: vec![0; 64],
    };
    reject(
        "changed-proof-root",
        proof::verify(&mut altered_root, &expected, &statement_bytes, proof::ROLE),
    );
    hostile_cases += 1;
    reject(
        "trailing-proof-byte",
        proof::verify(
            &mut read(&honest)?.chain(Cursor::new([0])),
            &expected,
            &statement_bytes,
            proof::ROLE,
        ),
    );
    hostile_cases += 1;

    let (statement, mut witness) = fixture::create();
    let layout = Layout::new(encoded_bytes());
    witness.columns[layout.seed][0] ^= 1;
    let columns = std::mem::take(&mut witness.columns);
    let witness = Witness::from_columns(&layout.relation, statement.digest()?, columns)?;
    let (false_seed, false_seed_bytes) = generate(
        &directory,
        "false-seed",
        &statement,
        witness,
        0x02a3_1149_716d_c37b,
        true,
    )?;
    reject_relation(
        "fresh-false-witness",
        proof::verify(
            &mut read(&false_seed)?,
            &statement,
            &statement.encode()?,
            proof::ROLE,
        ),
    );
    let (statement, witness) = fixture::impossible_share();
    // With zero public sources the selected coefficient must equal
    // Delta*M + error modulo Q. The bounded degree-one sharing and binary
    // seed give |M| <= B+1, so this canonical quarter-modulus coefficient
    // cannot arise from any accepted witness, including another quotient.
    let modulus = seed_sharing_proof::modulus();
    let impossible = &modulus / 4u8;
    let radius = num_bigint::BigInt::from(1u8)
        << (seed_sharing_proof::profile().sharing_coefficient_bits() - 1);
    let bound = num_bigint::BigInt::from(seed_sharing_proof::SCALE) * (radius + 1u8) + 64u8;
    assert!(
        statement
            .common
            .iter()
            .all(|value| *value == num_bigint::BigInt::from(0u8))
    );
    assert!(statement.recipients.iter().all(|recipient| {
        recipient
            .public_key
            .iter()
            .all(|value| *value == num_bigint::BigInt::from(0u8))
    }));
    assert_eq!(statement.recipients[0].ciphertext[0][0], impossible);
    assert!(impossible > bound && &modulus - &impossible > bound);
    let (false_share, false_share_bytes) = generate(
        &directory,
        "false-share",
        &statement,
        witness,
        0x9e81_063d_b521_7437,
        true,
    )?;
    reject_relation(
        "fresh-false-statement",
        proof::verify(
            &mut read(&false_share)?,
            &statement,
            &statement.encode()?,
            proof::ROLE,
        ),
    );
    println!(
        "{{\"kind\":\"seed-sharing-proof-fragment\",\"positive\":1,\"falseWitnesses\":1,\"falseStatements\":1,\"hostileCases\":{hostile_cases},\"participants\":{RECIPIENTS},\"degree\":{DEGREE},\"seedBits\":{SEED_BITS},\"proofDomain\":{DOMAIN},\"wordColumns\":{},\"booleanColumns\":{},\"affineRows\":{},\"proofBytes\":[{honest_bytes},{false_seed_bytes},{false_share_bytes}]}}",
        layout.relation.words,
        layout.relation.booleans,
        4 * RECIPIENTS * DEGREE + 2 * RECIPIENTS
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(values: &[&str]) -> Result<(PathBuf, bool, Option<GuardGates>), &'static str> {
        arguments(values.iter().map(OsString::from))
    }
    #[test]
    fn fixture_modes_keep_generation_and_existing_verification_distinct() {
        assert_eq!(
            parse(&["artifacts"]).unwrap(),
            (PathBuf::from("artifacts"), false, None)
        );
        assert_eq!(
            parse(&["--verify-existing", "artifacts"]).unwrap(),
            (PathBuf::from("artifacts"), true, None)
        );
        for values in [
            &[][..],
            &["--verify-existing"],
            &["--unknown"],
            &["artifacts", "extra"],
            &["--verify-existing", "artifacts", "extra"],
        ] {
            assert!(parse(values).is_err());
        }
    }
    #[test]
    fn guard_gates_are_paired_distinct_and_only_enable_existing_verification() {
        for flags in [
            ["--guard-start", "start", "--guard-finish", "finish"],
            ["--guard-finish", "finish", "--guard-start", "start"],
        ] {
            let arguments = [vec!["--verify-existing", "artifacts"], flags.to_vec()].concat();
            assert_eq!(
                parse(&arguments).unwrap(),
                (
                    PathBuf::from("artifacts"),
                    true,
                    Some(GuardGates {
                        start: PathBuf::from("start"),
                        finish: PathBuf::from("finish")
                    })
                )
            );
        }
        for flags in [
            &["--guard-start"][..],
            &["--guard-finish"],
            &["--guard-start", "start"],
            &["--guard-finish", "finish"],
            &["--guard-start", "--guard-finish"],
            &["--guard-start", "start", "--guard-start", "again"],
            &["--guard-finish", "finish", "--guard-finish", "again"],
            &["--guard-start", "same", "--guard-finish", "same"],
            &[
                "--guard-start",
                "start",
                "--guard-finish",
                "finish",
                "extra",
            ],
        ] {
            let arguments = [vec!["--verify-existing", "artifacts"], flags.to_vec()].concat();
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
        assert!(
            parse(&[
                "artifacts",
                "--guard-start",
                "start",
                "--guard-finish",
                "finish"
            ])
            .is_err()
        );
    }
}
