use opened_contribution::OpenedContributionVerifier;
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, verify_confirmation},
    roster_authentication::verify_roster_proposal,
    roster_input::RosterInputVerifier,
};
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    sync::Arc,
};

fn bounded(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(io::Error::other("Public input exceeds its bound."));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("Public input grew beyond its bound."));
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
    if arguments.len() != 19 {
        return Err(io::Error::other(
            "Supply context, signed definition, proposal signature, confirmation batch, opening packet, body header, proof, polynomial directory, and ten registration directories.",
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
    let Ok(mut roster) = RosterInputVerifier::new(&control) else {
        return Ok(false);
    };
    let mut buffer = vec![0u8; 1 << 20];
    for (position, path) in arguments[9..].iter().enumerate() {
        let directory = PathBuf::from(path);
        let header = bounded(
            directory.join("registration-header.bin").to_str().unwrap(),
            4096,
        )?;
        let signature = bounded(directory.join("signature.bin").to_str().unwrap(), 3309)?;
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
    let signature = bounded(&arguments[3], 3309)?;
    let Ok(proposal) = verify_roster_proposal(proposal, &signature) else {
        return Ok(false);
    };
    let proposal = Arc::new(proposal);
    let batch = bounded(&arguments[4], 1 << 20)?;
    if batch.len() < 4 || u32::from_le_bytes(batch[..4].try_into().unwrap()) != 10 {
        return Ok(false);
    }
    let mut offset = 4usize;
    let mut confirmations = Vec::new();
    for _ in 0..10 {
        let Some(length) = batch
            .get(offset..offset + 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
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
    let opening = bounded(&arguments[5], 4 + 1024 + 3309)?;
    let header = bounded(&arguments[6], 12)?;
    let Some((opening_body, opening_signature)) = packet(&opening) else {
        return Ok(false);
    };
    let mut proof = fs::File::open(&arguments[7])?;
    let mut proof_header = [0u8; word_verifier::HEADER_LENGTH];
    if proof.read_exact(&mut proof_header).is_err() {
        return Ok(false);
    }
    // These reader mutations are adversarial fixtures, not verifier options.
    if mode == "changed-lookahead" {
        proof_header[132] ^= 1;
    }
    let Ok(mut verifier) = OpenedContributionVerifier::new(
        Arc::new(inventory),
        opening_body,
        opening_signature,
        &header,
        &proof_header,
    ) else {
        return Ok(false);
    };
    let directory = PathBuf::from(&arguments[8]);
    let polynomials = (0..6)
        .flat_map(|gadget| [1, 2, 4, 6].map(move |index| 7 * gadget + index))
        .chain((0..10).flat_map(|recipient| [44 + 3 * recipient, 45 + 3 * recipient]))
        .chain(std::iter::once(74));
    for index in polynomials {
        let mut file = fs::File::open(directory.join(format!("polynomial-{index:02}.bin")))?;
        let mut offset = 0;
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            if mode == "changed-polynomial" && index == 1 && offset == 0 {
                if length < 109 {
                    return Ok(false);
                }
                if buffer[1..109].iter().all(|byte| *byte == 0) {
                    buffer[1] = 1;
                } else {
                    buffer[0] ^= 1;
                }
            }
            if verifier
                .polynomial(index, offset, &buffer[..length])
                .is_err()
            {
                return Ok(false);
            }
            offset += length;
        }
    }
    let mut proof = fs::File::open(&arguments[7])?;
    let proof_length = proof.metadata()?.len() as usize;
    let mut offset = 0;
    loop {
        let length = proof.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        if mode == "changed-proof"
            && offset <= word_verifier::HEADER_LENGTH
            && offset + length > word_verifier::HEADER_LENGTH
        {
            buffer[word_verifier::HEADER_LENGTH - offset] ^= 1;
        }
        let used = if mode == "truncated-proof" && offset + length == proof_length {
            length - 1
        } else {
            length
        };
        if used > 0 && verifier.proof(offset, &buffer[..used]).is_err() {
            return Ok(false);
        }
        offset += length;
    }
    Ok(verifier.finish().is_ok())
}
fn main() -> io::Result<()> {
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = if arguments.len() == 20 {
        arguments.pop().unwrap()
    } else {
        "valid".to_string()
    };
    if ![
        "valid",
        "changed-polynomial",
        "changed-proof",
        "changed-lookahead",
        "truncated-proof",
    ]
    .contains(&mode.as_str())
    {
        return Err(io::Error::other("Unknown adversarial reader fixture."));
    }
    println!("{}", verify(&arguments, &mode)?);
    Ok(())
}
