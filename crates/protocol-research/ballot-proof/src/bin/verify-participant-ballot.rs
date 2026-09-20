#[path = "../native-setup.rs"]
mod native_setup;
use ballot_proof::{
    body::{BallotBodyClassification, SignedBallotVerifier},
    submission::authenticate_envelope,
};
use native_setup::{bounded, required, setup};
use registration_credentials::ballot_body;
use setup_aggregate::{CHUNK_BYTES, ModulusKind};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

fn main() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 47 {
        return Err(io::Error::other(
            "Supply the complete public setup and actual participant ballot directory.",
        ));
    }
    let (poll, setup) = setup(&arguments)?;
    let directory = Path::new(&arguments[46]);
    let envelope = bounded(directory.join("envelope.bin"), 206)?;
    let signature = bounded(directory.join("signature.bin"), 3309)?;
    let authentication = required(authenticate_envelope(&setup, &envelope, &signature))?;
    let position = authentication.envelope().position();
    let expected = *authentication.envelope().body_identity();
    for mode in [
        "valid",
        "signature",
        "context",
        "proof",
        "truncated",
        "trailing",
        "key",
        "valid",
    ] {
        let mut envelope = envelope.clone();
        let mut signature = signature.clone();
        if mode == "signature" {
            signature[0] ^= 1;
        }
        if mode == "context" {
            envelope[132] ^= 1;
        }
        let authentication = authenticate_envelope(&setup, &envelope, &signature);
        if mode == "signature" || mode == "context" {
            if authentication.is_ok() {
                return Err(io::Error::other(
                    "Changed envelope authentication accepted.",
                ));
            }
            println!("Refused participant ballot: {mode}");
            continue;
        }
        let mut file = fs::File::open(directory.join("body.bin"))?;
        let total = usize::try_from(file.metadata()?.len())
            .map_err(|_| io::Error::other("Body length overflow."))?;
        let mut header = vec![0; ballot_body::HEADER_BYTES];
        file.read_exact(&mut header)?;
        let mut verifier = required(SignedBallotVerifier::new(
            poll.clone(),
            setup.clone(),
            required(authentication)?,
            &header,
        ))?;
        if !verifier.requires_keys() {
            return Err(io::Error::other("Original body context refused."));
        }
        let mut refused = false;
        for index in [1, 74] {
            if refused {
                break;
            }
            required(verifier.begin_key(index))?;
            let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
            let length = kind.degree() * kind.coefficient_bytes();
            let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let mut key = fs::File::open(
                Path::new(&arguments[5])
                    .join("after-participant-9")
                    .join(format!("polynomial-{index:02}.bin")),
            )?;
            if key.metadata()?.len() != length as u64 {
                return Err(io::Error::other("Key length differs."));
            }
            let mut buffer = vec![0; capacity];
            let mut offset = 0;
            while offset < length {
                let used = capacity.min(length - offset);
                key.read_exact(&mut buffer[..used])?;
                if mode == "key" && index == 1 && offset == 0 {
                    buffer[1] ^= 1;
                }
                if verifier.push_key(&buffer[..used]).is_err() {
                    refused = true;
                    break;
                }
                offset += used;
            }
            if !refused && verifier.finish_key().is_err() {
                refused = true;
            }
        }
        let mut buffer = vec![0; 65521];
        let mut offset = header.len();
        let limit = total - usize::from(mode == "truncated");
        let changed = header.len() + ballot_body::CIPHERTEXT_BYTES + 4004;
        while !refused && offset < limit {
            let length = buffer.len().min(limit - offset);
            file.read_exact(&mut buffer[..length])?;
            if mode == "proof" && offset <= changed && changed < offset + length {
                buffer[changed - offset] ^= 1;
            }
            if verifier.push(&buffer[..length]).is_err() {
                refused = true;
                break;
            }
            offset += length;
        }
        if !refused && mode == "trailing" {
            if verifier.push(&[0]).is_ok() {
                return Err(io::Error::other("Extra body byte accepted."));
            }
            refused = true;
        }
        let result = verifier.finish();
        if mode == "valid" {
            let BallotBodyClassification::Valid(value) = required(result)? else {
                return Err(io::Error::other("Original body classified invalid."));
            };
            if refused
                || value.body().identity() != &expected
                || value.body().relation().position() != position
            {
                return Err(io::Error::other("Wrong verified ballot."));
            }
            println!("Verified original participant ballot {position}");
        } else {
            if result.is_ok() {
                return Err(io::Error::other(
                    "Corrupted delivery classified as an author's ballot.",
                ));
            }
            println!("Refused participant ballot: {mode}");
        }
    }
    Ok(())
}
