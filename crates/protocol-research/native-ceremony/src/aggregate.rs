use registration_credentials::{
    contribution_authentication::{CommitmentInventory, SignedOpening},
    poll::VerifiedPoll,
};
use setup_aggregate::{
    CHUNK_BYTES, ModulusKind, VerifiedAggregatePolynomial,
    verified::{SetupAggregator, VerifiedSetupAggregate},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub fn verify(
    inventory: Arc<CommitmentInventory>,
    directories: &[PathBuf],
    headers: &[Vec<u8>],
    openings: &[SignedOpening],
    output: &Path,
) -> VerifiedSetupAggregate {
    fs::create_dir(output).unwrap();
    let mut verifier = SetupAggregator::new(inventory).unwrap();
    for (position, directory) in directories.iter().enumerate() {
        let target = output.join(format!("after-participant-{position}"));
        fs::create_dir(&target).unwrap();
        let mut proof = File::open(directory.join("proof.bin")).unwrap();
        let mut proof_header = [0; 4004];
        proof.read_exact(&mut proof_header).unwrap();
        verifier
            .begin(
                openings[position].body(),
                openings[position].signature(),
                &headers[position],
                &proof_header,
            )
            .unwrap();
        for index in
            (0..75).filter(|index| ModulusKind::for_contribution_polynomial(*index).is_some())
        {
            let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
            let length = kind.degree() * kind.coefficient_bytes();
            let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let name = format!("polynomial-{index:02}.bin");
            let mut incoming = File::open(directory.join(&name)).unwrap();
            assert_eq!(incoming.metadata().unwrap().len(), length as u64);
            let mut previous = if position == 0 {
                None
            } else {
                Some(
                    File::open(
                        output
                            .join(format!("after-participant-{}", position - 1))
                            .join(&name),
                    )
                    .unwrap(),
                )
            };
            let mut destination =
                crate::public_output::PublicOutput::create(target.join(&name)).unwrap();
            let mut input = vec![0; capacity];
            let mut value = vec![0; capacity];
            let mut offset = 0;
            while offset < length {
                let count = capacity.min(length - offset);
                incoming.read_exact(&mut input[..count]).unwrap();
                if let Some(previous) = previous.as_mut() {
                    previous.read_exact(&mut value[..count]).unwrap();
                } else {
                    value[..count].fill(0);
                }
                verifier
                    .polynomial(index, offset, &input[..count], &mut value[..count])
                    .unwrap();
                destination.write_all(&value[..count]).unwrap();
                offset += count;
            }
            destination.finish().unwrap();
        }
        let mut proof = File::open(directory.join("proof.bin")).unwrap();
        let mut buffer = vec![0; 1 << 20];
        let mut offset = 0;
        loop {
            let count = proof.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            verifier.proof(offset, &buffer[..count]).unwrap();
            offset += count;
        }
        verifier.finish_contribution().unwrap();
        println!("Verified fresh contribution {position}");
    }
    verifier.finish().unwrap()
}
pub fn read_key(
    setup: &VerifiedSetupAggregate,
    index: usize,
    directory: &Path,
) -> VerifiedAggregatePolynomial {
    let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
    let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
    let total = kind.degree() * kind.coefficient_bytes();
    let mut reader = setup.read_polynomial(index).unwrap();
    let mut file = File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
    assert_eq!(file.metadata().unwrap().len(), total as u64);
    let mut buffer = vec![0; capacity];
    let mut offset = 0;
    while offset < total {
        let count = capacity.min(total - offset);
        file.read_exact(&mut buffer[..count]).unwrap();
        reader.push(offset, &buffer[..count]).unwrap();
        offset += count;
    }
    reader.finish().unwrap()
}
pub fn verify_ballot(
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    header: &[u8],
    path: &Path,
    keys: &Path,
) -> ballot_proof::body::VerifiedBallotBody {
    let mut verifier = ballot_proof::body::BallotBodyVerifier::new(poll, setup, 0, header).unwrap();
    for index in [1, 74] {
        verifier.begin_key(index).unwrap();
        let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
        let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
        let total = kind.degree() * kind.coefficient_bytes();
        let mut file = File::open(keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
        let mut buffer = vec![0; capacity];
        let mut offset = 0;
        while offset < total {
            let count = capacity.min(total - offset);
            file.read_exact(&mut buffer[..count]).unwrap();
            verifier.push_key(&buffer[..count]).unwrap();
            offset += count;
        }
        verifier.finish_key().unwrap();
    }
    let mut file = File::open(path).unwrap();
    let mut actual_header = vec![0; header.len()];
    file.read_exact(&mut actual_header).unwrap();
    assert_eq!(actual_header, header);
    let mut buffer = vec![0; 65521];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        verifier.push(&buffer[..count]).unwrap();
    }
    verifier.finish().unwrap()
}

pub fn classify_ballot(
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    envelope: &[u8],
    signature: &[u8],
    path: &Path,
    keys: &Path,
    mode: &str,
) -> Result<ballot_proof::body::BallotBodyClassification, ballot_proof::body::Error> {
    use ballot_proof::body::{Error, SignedBallotVerifier};
    let authentication =
        ballot_proof::submission::authenticate_envelope(&setup, envelope, signature)
            .map_err(|_| Error::Context)?;
    let mut file = File::open(path).unwrap();
    let mut header = [0; registration_credentials::ballot_body::HEADER_BYTES];
    file.read_exact(&mut header).unwrap();
    if mode == "header" {
        header[0] ^= 1;
    }
    let mut verifier = SignedBallotVerifier::new(poll, setup, authentication, &header)?;
    if verifier.requires_keys() {
        for index in [1, 74] {
            verifier.begin_key(index)?;
            let kind = ModulusKind::for_contribution_polynomial(index).unwrap();
            let capacity = CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let total = kind.degree() * kind.coefficient_bytes();
            let mut key = File::open(keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
            let mut buffer = vec![0; capacity];
            let mut offset = 0;
            while offset < total {
                let count = capacity.min(total - offset);
                key.read_exact(&mut buffer[..count]).unwrap();
                if mode == "key" && index == 1 && offset == 0 {
                    buffer[1] ^= 1;
                }
                verifier.push_key(&buffer[..count])?;
                offset += count;
            }
            if mode != "unfinished-keys" || index != 74 {
                verifier.finish_key()?;
            }
        }
    }
    let total = file.metadata().unwrap().len() as usize - usize::from(mode == "truncated");
    let mut offset = header.len();
    let mut buffer = vec![0; 65521];
    let changed = header.len() + registration_credentials::ballot_body::CIPHERTEXT_BYTES + 4004;
    while offset < total {
        let count = buffer.len().min(total - offset);
        file.read_exact(&mut buffer[..count]).unwrap();
        if mode == "proof" && offset <= changed && changed < offset + count {
            buffer[changed - offset] ^= 1;
        }
        verifier.push(&buffer[..count])?;
        offset += count;
    }
    if mode == "trailing" {
        verifier.push(&[0])?;
    }
    verifier.finish()
}
