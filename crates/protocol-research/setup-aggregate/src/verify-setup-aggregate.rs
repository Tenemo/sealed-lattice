use registration_credentials::{
    contribution_authentication::{CommitmentInventory, verify_confirmation},
    roster_authentication::verify_roster_proposal,
    roster_input::RosterInputVerifier,
};
use setup_aggregate::{
    CHUNK_BYTES, ModulusKind,
    verified::{Refusal, SetupAggregator},
};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

fn bounded(path: impl AsRef<Path>, limit: usize) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(io::Error::other("Oversized public control."));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("Growing public control."));
    }
    Ok(bytes)
}
fn packet(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if length > 1024 || bytes.len() != 4 + length + 3309 {
        return None;
    }
    Some((&bytes[4..4 + length], &bytes[4 + length..]))
}
fn verify(arguments: &[String], mode: &str) -> io::Result<bool> {
    if arguments.len() != 46 {
        return Err(io::Error::other(
            "Supply context, signed poll, proposal signature, confirmation batch, new output directory, ten registration directories, ten opening directories, ten body directories, and ten proof paths.",
        ));
    }
    let context = bounded(&arguments[0], 128)?;
    let definition = bounded(&arguments[1], 1 << 20)?;
    let definition_signature = bounded(&arguments[2], 3309)?;
    if context.len() != 128 || definition_signature.len() != 3309 {
        return Ok(false);
    }
    let mut control = context;
    control.extend(10u16.to_le_bytes());
    control.extend((definition.len() as u32).to_le_bytes());
    control.extend(definition);
    control.extend(definition_signature);
    let mut roster =
        RosterInputVerifier::new(&control).map_err(|_| io::Error::other("Public poll refused."))?;
    let mut buffer = vec![0; CHUNK_BYTES];
    for (position, directory) in arguments[6..16].iter().enumerate() {
        let directory = Path::new(directory);
        let header = bounded(directory.join("registration-header.bin"), 4096)?;
        let signature = bounded(directory.join("signature.bin"), 3309)?;
        let mut control = Vec::from((position as u16).to_le_bytes());
        control.extend((header.len() as u32).to_le_bytes());
        control.extend(header);
        control.extend(signature);
        if roster.begin_record(&control).is_err() {
            return Ok(false);
        }
        let mut key = fs::File::open(directory.join("polynomial-01.bin"))?;
        loop {
            let length = key.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            if roster.push_key(&buffer[..length]).is_err() {
                return Ok(false);
            }
        }
        if roster.finish_key().is_err() {
            return Ok(false);
        }
        let mut proof = fs::File::open(directory.join("proof.bin"))?;
        loop {
            let length = proof.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            if roster.push_proof(&buffer[..length]).is_err() {
                return Ok(false);
            }
        }
        if roster.finish_record().is_err() {
            return Ok(false);
        }
    }
    let Ok(proposal) = roster.finish() else {
        return Ok(false);
    };
    let Ok(proposal) = verify_roster_proposal(proposal, &bounded(&arguments[3], 3309)?) else {
        return Ok(false);
    };
    let proposal = Arc::new(proposal);
    let batch = bounded(&arguments[4], 1 << 20)?;
    if batch.get(..4) != Some(10u32.to_le_bytes().as_slice()) {
        return Ok(false);
    }
    let mut offset = 4;
    let mut confirmations = Vec::new();
    for _ in 0..10 {
        let Some(length) = batch
            .get(offset..offset + 4)
            .map(|value| u32::from_le_bytes(value.try_into().unwrap()) as usize)
        else {
            return Ok(false);
        };
        if length > 1024 {
            return Ok(false);
        }
        let Some(bytes) = batch.get(offset..offset + 4 + length + 3309) else {
            return Ok(false);
        };
        let Some((body, signature)) = packet(bytes) else {
            return Ok(false);
        };
        let Ok(confirmation) = verify_confirmation(&proposal, body, signature) else {
            return Ok(false);
        };
        confirmations.push(confirmation);
        offset += bytes.len();
    }
    if offset != batch.len() {
        return Ok(false);
    }
    let Ok(inventory) = CommitmentInventory::new(proposal, confirmations) else {
        return Ok(false);
    };
    let mut aggregator = SetupAggregator::new(Arc::new(inventory))
        .map_err(|_| io::Error::other("Inventory refused."))?;
    let output = PathBuf::from(&arguments[5]);
    fs::create_dir(&output)?;
    let indices: Vec<_> = (0..75)
        .filter(|index| ModulusKind::for_contribution_polynomial(*index).is_some())
        .collect();
    let mut previous_directory: Option<PathBuf> = None;
    for position in 0..10 {
        let opening_directory = Path::new(&arguments[16 + position]);
        let opening = bounded(opening_directory.join("opening.bin"), 4 + 1024 + 3309)?;
        let header = bounded(opening_directory.join("body-header.bin"), 12)?;
        let Some((body, signature)) = packet(&opening) else {
            return Ok(false);
        };
        let mut proof = fs::File::open(&arguments[36 + position])?;
        let mut lookahead = [0; 4004];
        if proof.read_exact(&mut lookahead).is_err() {
            return Ok(false);
        }
        if aggregator
            .begin(body, signature, &header, &lookahead)
            .is_err()
        {
            return Ok(false);
        }
        let directory = output.join(format!("after-participant-{position}"));
        fs::create_dir(&directory)?;
        for index in &indices {
            let kind = ModulusKind::for_contribution_polynomial(*index).unwrap();
            let width = kind.coefficient_bytes();
            let length = kind.degree() * width;
            let chunk = CHUNK_BYTES / width * width;
            let name = format!("polynomial-{index:02}.bin");
            let mut incoming = fs::File::open(Path::new(&arguments[26 + position]).join(&name))?;
            if incoming.metadata()?.len() != length as u64 {
                return Ok(false);
            }
            let mut previous = previous_directory
                .as_ref()
                .map(|directory| fs::File::open(directory.join(&name)))
                .transpose()?;
            if previous.as_ref().is_some_and(|file| {
                file.metadata()
                    .map_or(true, |metadata| metadata.len() != length as u64)
            }) {
                return Ok(false);
            }
            let mut destination = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(&name))?;
            let mut prior = vec![0; chunk];
            let mut offset = 0;
            while offset < length {
                let used = chunk.min(length - offset);
                incoming.read_exact(&mut buffer[..used])?;
                if let Some(previous) = previous.as_mut() {
                    previous.read_exact(&mut prior[..used])?;
                }
                if mode == "changed-previous" && position == 1 && *index == 1 && offset == 0 {
                    if prior[1..width].iter().all(|value| *value == 0) {
                        prior[1] = 1;
                    } else {
                        prior[0] ^= 1;
                    }
                }
                let result =
                    aggregator.polynomial(*index, offset, &buffer[..used], &mut prior[..used]);
                if let Err(error) = result {
                    if mode == "changed-previous"
                        && position == 1
                        && matches!(error, Refusal::PreviousAggregate)
                    {
                        assert_eq!(aggregator.accepted(), 1);
                        println!("Refused changed previous aggregate");
                        return Ok(true);
                    }
                    return Ok(false);
                }
                destination.write_all(&prior[..used])?;
                offset += used;
            }
            destination.flush()?;
        }
        let mut proof = fs::File::open(&arguments[36 + position])?;
        let mut offset = 0;
        loop {
            let length = proof.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            if mode == "changed-proof" && position == 1 && offset <= 4004 && offset + length > 4004
            {
                buffer[4004 - offset] ^= 1;
            }
            if aggregator.proof(offset, &buffer[..length]).is_err() {
                if mode == "changed-proof" && position == 1 {
                    assert_eq!(aggregator.accepted(), 1);
                    println!("Refused changed incoming proof");
                    return Ok(true);
                }
                return Ok(false);
            }
            offset += length;
        }
        if aggregator.finish_contribution().is_err() {
            return Ok(false);
        }
        assert_eq!(aggregator.accepted(), position + 1);
        previous_directory = Some(directory);
        if mode == "incomplete" {
            assert!(aggregator.finish().is_err());
            println!("Refused incomplete setup");
            return Ok(true);
        }
        println!("Verified and aggregated participant {position}");
    }
    if mode != "valid" {
        return Ok(false);
    }
    let verified = aggregator
        .finish()
        .map_err(|_| io::Error::other("Complete setup refused."))?;
    let mut report = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("aggregate-digests.txt"))?;
    for polynomial in verified.polynomials() {
        let mut reader = verified
            .read_polynomial(polynomial.index())
            .map_err(|_| io::Error::other("Aggregate reference refused."))?;
        let kind = ModulusKind::for_contribution_polynomial(polynomial.index()).unwrap();
        let chunk = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
        let mut cached = fs::File::open(
            previous_directory
                .as_ref()
                .unwrap()
                .join(format!("polynomial-{:02}.bin", polynomial.index())),
        )?;
        let mut offset = 0;
        while offset < polynomial.bytes() {
            let length = chunk.min(polynomial.bytes() - offset);
            cached.read_exact(&mut buffer[..length])?;
            reader
                .push(offset, &buffer[..length])
                .map_err(|_| io::Error::other("Retained aggregate bytes refused."))?;
            offset += length;
        }
        if cached.read(&mut buffer[..1])? != 0 {
            return Ok(false);
        }
        let loaded = reader
            .finish()
            .map_err(|_| io::Error::other("Retained aggregate identity refused."))?;
        assert_eq!(loaded.index(), polynomial.index());
        assert_eq!(loaded.inventory(), &verified.inventory().identity());
        assert_eq!(loaded.coefficients().len(), kind.degree());
        write!(report, "{} {} ", polynomial.index(), polynomial.bytes())?;
        for byte in polynomial.digest() {
            write!(report, "{byte:02x}")?;
        }
        writeln!(report)?;
    }
    report.flush()?;
    Ok(true)
}
fn main() -> io::Result<()> {
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = if arguments.len() == 47 {
        arguments.pop().unwrap()
    } else {
        "valid".to_owned()
    };
    if !["valid", "changed-previous", "changed-proof", "incomplete"].contains(&mode.as_str()) {
        return Err(io::Error::other("Unknown reader fixture."));
    }
    println!("{}", verify(&arguments, &mode)?);
    Ok(())
}
