use ballot_proof::statement::setup_inputs;
use registration_credentials::{
    contribution_authentication::{CommitmentInventory, SignedOpening},
    poll::VerifiedPoll,
};
use setup_aggregate::{
    CHUNK_BYTES, VerifiedAggregatePolynomial, contribution_family,
    verified::{SetupAggregator, VerifiedSetupAggregate},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use supported_profile::{Profile, relation::PROOF_HEADER_BYTES};

/// Bytes of a contribution polynomial and of the largest whole-coefficient
/// chunk.
pub fn polynomial_bytes(profile: Profile, index: usize) -> (usize, usize) {
    let family = contribution_family(profile, index).unwrap();
    let width = 1 + profile.family_magnitude_bytes(family);
    (
        profile.family_degree(family) * width,
        CHUNK_BYTES / width * width,
    )
}
/// The aggregate after the last contribution.
pub fn final_keys(output: &Path, profile: Profile) -> PathBuf {
    output.join(format!(
        "aggregates/after-participant-{}",
        profile.participants() - 1
    ))
}
/// The setup indices of the FHE and auxiliary encryption keys, in the
/// order a ballot statement takes them.
pub fn ballot_keys(profile: Profile) -> [usize; 2] {
    setup_inputs(profile).map(|(_, _, key)| key)
}

pub fn verify(
    inventory: Arc<CommitmentInventory>,
    directories: &[PathBuf],
    headers: &[Vec<u8>],
    openings: &[SignedOpening],
    output: &Path,
) -> VerifiedSetupAggregate {
    fs::create_dir(output).unwrap();
    let profile = inventory.proposal().proposal().profile();
    let mut verifier = SetupAggregator::new(inventory).unwrap();
    for (position, directory) in directories.iter().enumerate() {
        let target = output.join(format!("after-participant-{position}"));
        fs::create_dir(&target).unwrap();
        let mut proof = File::open(directory.join("proof.bin")).unwrap();
        let mut proof_header = [0; PROOF_HEADER_BYTES];
        proof.read_exact(&mut proof_header).unwrap();
        verifier
            .begin(
                openings[position].body(),
                openings[position].signature(),
                &headers[position],
                &proof_header,
            )
            .unwrap();
        for index in profile.contribution_body_polynomials() {
            let (length, capacity) = polynomial_bytes(profile, index);
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
    let (total, capacity) = polynomial_bytes(setup.profile(), index);
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
    let profile = setup.profile();
    let mut verifier = ballot_proof::body::BallotBodyVerifier::new(poll, setup, 0, header).unwrap();
    for index in ballot_keys(profile) {
        verifier.begin_key(index).unwrap();
        let (total, capacity) = polynomial_bytes(profile, index);
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
    let profile = setup.profile();
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
    let [fhe_key, last_key] = ballot_keys(profile);
    if verifier.requires_keys() {
        for index in [fhe_key, last_key] {
            verifier.begin_key(index)?;
            let (total, capacity) = polynomial_bytes(profile, index);
            let mut key = File::open(keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
            let mut buffer = vec![0; capacity];
            let mut offset = 0;
            while offset < total {
                let count = capacity.min(total - offset);
                key.read_exact(&mut buffer[..count]).unwrap();
                if mode == "key" && index == fhe_key && offset == 0 {
                    buffer[1] ^= 1;
                }
                verifier.push_key(&buffer[..count])?;
                offset += count;
            }
            if mode != "unfinished-keys" || index != last_key {
                verifier.finish_key()?;
            }
        }
    }
    let total = file.metadata().unwrap().len() as usize - usize::from(mode == "truncated");
    let mut offset = header.len();
    let mut buffer = vec![0; 65521];
    let changed = header.len()
        + registration_credentials::ballot_body::ciphertext_bytes(profile)
        + PROOF_HEADER_BYTES;
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
