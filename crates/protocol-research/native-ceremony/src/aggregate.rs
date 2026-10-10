use ballot_proof::statement::setup_input;
use protocol_foundations::{
    contribution_offer::AuthenticatedContributionOffer, poll::VerifiedPoll,
    setup_selection::AuthenticatedSelectionProposal,
};
use setup_aggregate::offer_verifier::{ContributionOfferVerifier, VerifiedContributionOffer};
use setup_aggregate::{
    CHUNK_BYTES, VerifiedAggregatePolynomial, contribution_family,
    verified::{SetupAggregator, VerifiedSelectionInputs, VerifiedSetupAggregate},
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
/// The aggregate after the last setup contributor's contribution.
pub fn final_keys(output: &Path, profile: Profile) -> PathBuf {
    output.join(format!(
        "aggregates/after-contributor-{}",
        profile.setup_contributors() - 1
    ))
}
/// The FHE key the ballot takes from the verified setup aggregate.
pub fn ballot_key(profile: Profile) -> usize {
    setup_input(profile).2
}

/// Both controls reach the registered-coordinate check before proof bytes.
pub fn verify_source_refusals(
    offers: &[Arc<AuthenticatedContributionOffer>],
    directories: &[PathBuf],
    headers: &[Vec<u8>],
) {
    let profile = offers[0].roster().proposal().profile();
    let index = profile.fhe_polynomial(0, 1);
    let mut proof_header = [0; PROOF_HEADER_BYTES];
    File::open(directories[0].join("proof.bin"))
        .unwrap()
        .read_exact(&mut proof_header)
        .unwrap();
    let (length, capacity) = polynomial_bytes(profile, index);
    for wrong_source in [false, true] {
        let mut header = headers[0].clone();
        if !wrong_source {
            header[12] ^= 1;
        }
        let mut verifier =
            ContributionOfferVerifier::new(offers[0].clone(), &header, &proof_header).unwrap();
        let mut incoming = File::open(
            directories[usize::from(wrong_source)].join(format!("polynomial-{index:02}.bin")),
        )
        .unwrap();
        let mut bytes = vec![0; capacity];
        for offset in (0..length).step_by(capacity) {
            let count = capacity.min(length - offset);
            incoming.read_exact(&mut bytes[..count]).unwrap();
            let result = verifier.polynomial(index, offset, &bytes[..count]);
            if offset + count == length {
                assert!(matches!(
                    result,
                    Err(setup_aggregate::offer_verifier::Refusal::Commitment)
                ));
            } else {
                result.unwrap();
            }
        }
        assert!(verifier.finish().is_err());
    }
    println!(
        "Refused a foreign registered coordinate and changed source opening before proof consumption"
    );
}

pub fn verify_offer(
    offer: Arc<AuthenticatedContributionOffer>,
    directory: &Path,
    header: &[u8],
) -> VerifiedContributionOffer {
    let profile = offer.roster().proposal().profile();
    let mut proof_header = [0; PROOF_HEADER_BYTES];
    File::open(directory.join("proof.bin"))
        .unwrap()
        .read_exact(&mut proof_header)
        .unwrap();
    let mut verifier = ContributionOfferVerifier::new(offer, header, &proof_header).unwrap();
    for index in profile.contribution_body_polynomials() {
        let (length, capacity) = polynomial_bytes(profile, index);
        let mut file = File::open(directory.join(format!("polynomial-{index:02}.bin"))).unwrap();
        assert_eq!(file.metadata().unwrap().len(), length as u64);
        let mut buffer = vec![0; capacity];
        for offset in (0..length).step_by(capacity) {
            let count = capacity.min(length - offset);
            file.read_exact(&mut buffer[..count]).unwrap();
            verifier
                .polynomial(index, offset, &buffer[..count])
                .unwrap();
        }
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
    verifier.finish().unwrap()
}

pub fn verify(
    selection: Arc<AuthenticatedSelectionProposal>,
    offers: Vec<Arc<VerifiedContributionOffer>>,
    directories: &[PathBuf],
    output: &Path,
) -> VerifiedSelectionInputs {
    fs::create_dir(output).unwrap();
    let profile = selection.roster().proposal().profile();
    let positions: Vec<_> = offers
        .iter()
        .map(|offer| offer.envelope().position())
        .collect();
    // A changed reread cannot mint selection inputs. Its mixed scratch is
    // discarded; the verified offer holders remain usable by a clean pass.
    {
        let mut verifier = SetupAggregator::new(selection.clone(), offers.clone()).unwrap();
        let directory = &directories[0];
        verifier.begin(positions[0]).unwrap();
        let first = profile.contribution_body_polynomials()[0];
        let (length, capacity) = polynomial_bytes(profile, first);
        let name = format!("polynomial-{first:02}.bin");
        let mut probe = File::open(directory.join(&name)).unwrap();
        let mut input = vec![0; capacity];
        let mut value = vec![0; capacity];
        let mut refused = false;
        for offset in (0..length).step_by(capacity) {
            let count = capacity.min(length - offset);
            probe.read_exact(&mut input[..count]).unwrap();
            if offset == 0 {
                input[1] ^= 1;
            }
            match verifier.polynomial(first, offset, &input[..count], &mut value[..count]) {
                Ok(()) => assert!(offset + count < length),
                Err(setup_aggregate::verified::Refusal::Body) => {
                    refused = true;
                    break;
                }
                Err(error) => panic!("Unexpected changed-offer refusal: {error:?}"),
            }
        }
        assert!(refused);
        assert_eq!(verifier.accepted(), 0);
        assert!(!verifier.complete());
        assert!(verifier.finish_contribution().is_err());
        assert!(verifier.finish().is_err());
    }
    let mut verifier = SetupAggregator::new(selection, offers).unwrap();
    for (ordinal, directory) in directories.iter().enumerate() {
        let target = output.join(format!("after-contributor-{ordinal}"));
        fs::create_dir(&target).unwrap();
        verifier.begin(positions[ordinal]).unwrap();
        for index in profile.contribution_body_polynomials() {
            let (length, capacity) = polynomial_bytes(profile, index);
            let name = format!("polynomial-{index:02}.bin");
            let mut incoming = File::open(directory.join(&name)).unwrap();
            assert_eq!(incoming.metadata().unwrap().len(), length as u64);
            let mut previous = (ordinal != 0).then(|| {
                File::open(
                    output
                        .join(format!("after-contributor-{}", ordinal - 1))
                        .join(&name),
                )
                .unwrap()
            });
            let mut destination =
                crate::public_output::PublicOutput::create(target.join(&name)).unwrap();
            let mut input = vec![0; capacity];
            let mut value = vec![0; capacity];
            for offset in (0..length).step_by(capacity) {
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
            }
            destination.finish().unwrap();
        }
        verifier.finish_contribution().unwrap();
        println!("Aggregated original selected author {}", positions[ordinal]);
    }
    verifier.finish().unwrap()
}

fn begin_streamed_offer(
    verifier: &mut SetupAggregator,
    offer: Arc<AuthenticatedContributionOffer>,
    directory: &Path,
    header: &[u8],
) {
    let mut proof_header = [0; PROOF_HEADER_BYTES];
    File::open(directory.join("proof.bin"))
        .unwrap()
        .read_exact(&mut proof_header)
        .unwrap();
    verifier
        .begin_verification(offer, header, &proof_header)
        .unwrap();
}

// Genuine public files supply both the incoming coefficients and the
// independently verified two-pass aggregate used for byte comparison.
fn check_streamed_polynomials(
    verifier: &mut SetupAggregator,
    profile: Profile,
    directory: &Path,
    aggregates: &Path,
    ordinal: usize,
    damage_previous: bool,
) -> Result<(), setup_aggregate::verified::Refusal> {
    for (polynomial_ordinal, index) in profile
        .contribution_body_polynomials()
        .into_iter()
        .enumerate()
    {
        let (length, capacity) = polynomial_bytes(profile, index);
        let name = format!("polynomial-{index:02}.bin");
        let mut incoming = File::open(directory.join(&name)).unwrap();
        let mut previous = (ordinal > 0).then(|| {
            File::open(
                aggregates
                    .join(format!("after-contributor-{}", ordinal - 1))
                    .join(&name),
            )
            .unwrap()
        });
        let mut expected = File::open(
            aggregates
                .join(format!("after-contributor-{ordinal}"))
                .join(&name),
        )
        .unwrap();
        let mut input = vec![0; capacity];
        let mut value = vec![0; capacity];
        let mut reference = vec![0; capacity];
        for offset in (0..length).step_by(capacity) {
            let count = capacity.min(length - offset);
            incoming.read_exact(&mut input[..count]).unwrap();
            match previous.as_mut() {
                Some(previous) => previous.read_exact(&mut value[..count]).unwrap(),
                None => value[..count].fill(0),
            }
            if damage_previous && polynomial_ordinal == 0 && offset == 0 {
                assert!(previous.is_some());
                let width = 1 + profile
                    .family_magnitude_bytes(contribution_family(profile, index).unwrap());
                let was_zero = value[..width].iter().all(|byte| *byte == 0);
                value[..width].fill(0);
                if was_zero {
                    value[1] = 1;
                }
            }
            verifier.polynomial(index, offset, &input[..count], &mut value[..count])?;
            expected.read_exact(&mut reference[..count]).unwrap();
            if !damage_previous {
                assert_eq!(&value[..count], &reference[..count]);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ProofDelivery {
    Complete,
    Truncated,
    Changed,
}

fn stream_offer_proof(
    verifier: &mut SetupAggregator,
    directory: &Path,
    delivery: ProofDelivery,
) -> Result<(), setup_aggregate::verified::Refusal> {
    let mut proof = File::open(directory.join("proof.bin")).unwrap();
    let total = usize::try_from(proof.metadata().unwrap().len()).unwrap();
    assert!(total > PROOF_HEADER_BYTES);
    let limit = total - usize::from(matches!(delivery, ProofDelivery::Truncated));
    let mut buffer = vec![0; 1 << 20];
    let mut offset = 0;
    while offset < limit {
        let count = buffer.len().min(limit - offset);
        proof.read_exact(&mut buffer[..count]).unwrap();
        if matches!(delivery, ProofDelivery::Changed) && offset + count == limit {
            buffer[count - 1] ^= 1;
        }
        verifier.proof(offset, &buffer[..count])?;
        offset += count;
    }
    Ok(())
}

/// Exercises the streaming owner on real proofs, including refusal after
/// provisional output and a clean rebuild retaining only positive offers.
pub fn verify_streamed_selection(
    selection: Arc<AuthenticatedSelectionProposal>,
    offers: &[Arc<AuthenticatedContributionOffer>],
    directories: &[PathBuf],
    headers: &[Vec<u8>],
    expected: &VerifiedSelectionInputs,
    aggregates: &Path,
) {
    let profile = selection.roster().proposal().profile();
    assert_eq!(offers.len(), profile.setup_contributors());
    assert_eq!(directories.len(), offers.len());
    assert_eq!(headers.len(), offers.len());
    for delivery in [ProofDelivery::Truncated, ProofDelivery::Changed] {
        let mut refused = SetupAggregator::new(selection.clone(), Vec::new()).unwrap();
        begin_streamed_offer(
            &mut refused,
            offers[0].clone(),
            &directories[0],
            &headers[0],
        );
        check_streamed_polynomials(&mut refused, profile, &directories[0], aggregates, 0, false)
            .unwrap();
        // Every provisional polynomial already exists when the proof fails.
        let delivered = stream_offer_proof(&mut refused, &directories[0], delivery);
        let completed = refused.finish_contribution();
        assert!(delivered.is_err() || completed.is_err());
        assert!(completed.is_err());
        assert_eq!(refused.accepted(), 0);
        assert!(!refused.complete());
        assert!(refused.finish().is_err());
    }

    let mut verifier = SetupAggregator::new(selection, Vec::new()).unwrap();
    begin_streamed_offer(
        &mut verifier,
        offers[0].clone(),
        &directories[0],
        &headers[0],
    );
    check_streamed_polynomials(
        &mut verifier,
        profile,
        &directories[0],
        aggregates,
        0,
        false,
    )
    .unwrap();
    stream_offer_proof(&mut verifier, &directories[0], ProofDelivery::Complete).unwrap();
    let first = verifier.finish_contribution().unwrap();
    assert_eq!(
        first.envelope().body_identity(),
        offers[0].envelope().body_identity()
    );
    assert_eq!(verifier.accepted(), 1);
    assert!(!verifier.complete());

    begin_streamed_offer(
        &mut verifier,
        offers[1].clone(),
        &directories[1],
        &headers[1],
    );
    assert!(matches!(
        check_streamed_polynomials(&mut verifier, profile, &directories[1], aggregates, 1, true),
        Err(setup_aggregate::verified::Refusal::PreviousAggregate)
    ));
    assert_eq!(verifier.accepted(), 1);
    assert!(!verifier.complete());
    assert!(verifier.finish_contribution().is_err());
    verifier.discard_progress();
    assert_eq!(verifier.accepted(), 0);
    assert!(!verifier.complete());

    for (ordinal, offer) in offers.iter().enumerate() {
        if ordinal == 0 {
            // The failed scratch pass did not erase its positive offer.
            verifier.begin(first.envelope().position()).unwrap();
        } else {
            begin_streamed_offer(
                &mut verifier,
                offer.clone(),
                &directories[ordinal],
                &headers[ordinal],
            );
        }
        check_streamed_polynomials(
            &mut verifier,
            profile,
            &directories[ordinal],
            aggregates,
            ordinal,
            false,
        )
        .unwrap();
        if ordinal != 0 {
            stream_offer_proof(
                &mut verifier,
                &directories[ordinal],
                ProofDelivery::Complete,
            )
            .unwrap();
        }
        let verified = verifier.finish_contribution().unwrap();
        assert_eq!(
            verified.envelope().body_identity(),
            offer.envelope().body_identity()
        );
        assert_eq!(verifier.accepted(), ordinal + 1);
    }
    let actual = verifier.finish().unwrap();
    assert_eq!(actual.identity(), expected.identity());
    assert_eq!(actual.polynomials().len(), expected.polynomials().len());
    for (actual, expected) in actual.polynomials().iter().zip(expected.polynomials()) {
        assert_eq!(
            (actual.index(), actual.bytes(), actual.digest()),
            (expected.index(), expected.bytes(), expected.digest())
        );
    }
    println!("Verified fused setup aggregation, late proof refusal and retained-offer rebuild");
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
    let index = ballot_key(profile);
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
    let mut header = [0; protocol_foundations::ballot_body::HEADER_BYTES];
    file.read_exact(&mut header).unwrap();
    if mode == "header" {
        header[0] ^= 1;
    }
    let mut verifier = SignedBallotVerifier::new(poll, setup, authentication, &header, None)?;
    let index = ballot_key(profile);
    if verifier.requires_key() {
        verifier.begin_key(index)?;
        let (total, capacity) = polynomial_bytes(profile, index);
        let mut key = File::open(keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
        let mut buffer = vec![0; capacity];
        let mut offset = 0;
        while offset < total {
            let count = capacity.min(total - offset);
            key.read_exact(&mut buffer[..count]).unwrap();
            if mode == "key" && offset == 0 {
                buffer[1] ^= 1;
            }
            verifier.push_key(&buffer[..count])?;
            offset += count;
        }
        if mode != "unfinished-key" {
            verifier.finish_key()?;
        }
    }
    let total = file.metadata().unwrap().len() as usize - usize::from(mode == "truncated");
    let mut offset = header.len();
    let mut buffer = vec![0; 65521];
    let changed = header.len()
        + protocol_foundations::ballot_body::ciphertext_bytes(profile)
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
