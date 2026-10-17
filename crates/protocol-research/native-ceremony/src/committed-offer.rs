//! A published aggregate checked against independent full-input aggregation.
use crate::{aggregate, public_output::PublicOutput};
use protocol_foundations::{
    Credential, poll::VerifiedPoll, setup_selection::AuthenticatedSelectionProposal,
};
use setup_aggregate::{
    CHUNK_BYTES,
    aggregate_publisher::AggregatePublisher,
    offer_verifier::VerifiedContributionOffer,
    published_aggregate::{AggregateManifest, PublishedAggregateVerifier, evaluation_role},
    verified::{StreamedOfferAggregator, VerifiedSelectionInputs},
};
use statement_stream::committed_polynomial::CommittedPolynomial;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use supported_profile::{
    Profile, relation::EVALUATION_HEADER_BYTES, source_linked::relation as setup_relation,
};
use word_proof::public_evaluation::EvaluationProver;
use word_proof::public_oracle::PublicOracleBuilder;
use word_verifier::public_evaluation::EvaluationVerifier;

fn polynomial_file(directory: &Path, index: usize) -> PathBuf {
    directory.join(format!("polynomial-{index:02}.bin"))
}

fn columns(profile: Profile, directory: &Path, mut consume: impl FnMut(&[u128])) {
    let mut buffer = vec![0; 1 << 20];
    for index in profile.committed_polynomials() {
        let mut polynomial = CommittedPolynomial::new(profile);
        let mut file = File::open(polynomial_file(directory, index)).unwrap();
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            polynomial.push(&buffer[..length]).unwrap();
        }
        for column in polynomial.finish().unwrap() {
            consume(&column);
        }
    }
}

fn evaluation(
    selection: &AuthenticatedSelectionProposal,
    offers: &[Arc<VerifiedContributionOffer>],
    directories: &[PathBuf],
    manifest: &AggregateManifest,
    ordinal: usize,
    output: &Path,
) {
    let profile = selection.roster().proposal().profile();
    let roots: Vec<_> = offers.iter().map(|offer| *offer.public_root()).collect();
    let role = evaluation_role(selection);
    let contribution_role = selection
        .roster()
        .proposal()
        .contribution_role(offers[ordinal].envelope().position())
        .unwrap();
    let mut prover = EvaluationProver::new(
        profile,
        &role,
        manifest.identity(),
        &roots,
        ordinal,
        &contribution_role,
    )
    .unwrap();
    let started = Instant::now();
    columns(profile, &directories[ordinal], |column| {
        prover.column(column).unwrap()
    });
    prover.finish_columns().unwrap();
    let commitment_and_folds_milliseconds = started.elapsed().as_millis();
    columns(profile, &directories[ordinal], |column| {
        prover.opening_column(column).unwrap()
    });
    prover.finish_openings().unwrap();
    let mut file = PublicOutput::create(output).unwrap();
    let mut bytes = Vec::new();
    while prover.next_output(&mut bytes).unwrap() {
        file.write_all(&bytes).unwrap();
    }
    file.finish().unwrap();
    drop(prover);
    let proof = fs::read(output).unwrap();
    println!(
        "Public evaluation {ordinal}: bytes={}, commitment_and_folds_ms={commitment_and_folds_milliseconds}, generation_ms={}",
        proof.len(),
        started.elapsed().as_millis()
    );
    let verifies = |bytes: &[u8], aggregate: &[u8; 64], ordinal| {
        let header = bytes.get(..EVALUATION_HEADER_BYTES)?;
        let Ok(mut verifier) = EvaluationVerifier::open(
            profile,
            &role,
            aggregate,
            &roots,
            ordinal,
            &contribution_role,
            header,
        ) else {
            return None;
        };
        for chunk in bytes[EVALUATION_HEADER_BYTES..].chunks(32_761) {
            if verifier.push(chunk).is_err() {
                return None;
            }
        }
        verifier.finish()
    };
    assert!(verifies(&proof, manifest.identity(), ordinal).is_some());
    let mut changed_identity = *manifest.identity();
    changed_identity[0] ^= 1;
    assert!(verifies(&proof, &changed_identity, ordinal).is_none());
    assert!(verifies(&proof, manifest.identity(), (ordinal + 1) % offers.len()).is_none());
    for offset in [
        0,
        48,
        EVALUATION_HEADER_BYTES - 1,
        EVALUATION_HEADER_BYTES,
        proof.len() - 1,
    ] {
        let mut changed = proof.clone();
        changed[offset] ^= 1;
        assert!(verifies(&changed, manifest.identity(), ordinal).is_none());
    }
    assert!(verifies(&proof[..proof.len() - 1], manifest.identity(), ordinal).is_none());
    let mut trailing = proof;
    trailing.push(0);
    assert!(verifies(&trailing, manifest.identity(), ordinal).is_none());
}

pub fn verify_selection(
    selection: Arc<AuthenticatedSelectionProposal>,
    offers: &[Arc<VerifiedContributionOffer>],
    directories: &[PathBuf],
    output: &Path,
    expected: &VerifiedSelectionInputs,
    credentials: [&Credential; 2],
    poll: &VerifiedPoll,
) -> VerifiedSelectionInputs {
    let profile = selection.roster().proposal().profile();
    let published = output.join("published-aggregate");
    fs::create_dir(&published).unwrap();
    // Measure exact public-root reconstruction separately from proof folding.
    let role = selection
        .roster()
        .proposal()
        .contribution_role(offers[0].envelope().position())
        .unwrap();
    let started = Instant::now();
    let mut builder = PublicOracleBuilder::new(&role, profile.committed_columns()).unwrap();
    columns(profile, &directories[0], |column| {
        builder.column(column).unwrap()
    });
    assert_eq!(builder.finish().unwrap().root(), *offers[0].public_root());
    println!(
        "Public root reencoding: milliseconds={}",
        started.elapsed().as_millis()
    );
    let mut publisher = AggregatePublisher::new(selection.roster().clone());
    let mut previous_directory: Option<PathBuf> = None;
    // Reverse discovery order while the signed selection remains sorted.
    for (accepted, ordinal) in (0..offers.len()).rev().enumerate() {
        publisher.begin(offers[ordinal].clone()).unwrap();
        let destination = if accepted + 1 == offers.len() {
            published.clone()
        } else {
            let path = output.join(format!("collected-prefix-{accepted}"));
            fs::create_dir(&path).unwrap();
            path
        };
        for index in profile.contribution_body_polynomials() {
            let (length, capacity) = aggregate::polynomial_bytes(profile, index);
            let mut source = File::open(polynomial_file(&directories[ordinal], index)).unwrap();
            let mut previous = previous_directory
                .as_ref()
                .map(|directory| File::open(polynomial_file(directory, index)).unwrap());
            let mut target = PublicOutput::create(polynomial_file(&destination, index)).unwrap();
            let mut incoming = vec![0; capacity];
            for offset in (0..length).step_by(capacity) {
                let count = capacity.min(length - offset);
                source.read_exact(&mut incoming[..count]).unwrap();
                let mut sum = vec![0; publisher.output_bytes(index, count).unwrap()];
                if let Some(previous) = &mut previous {
                    previous.read_exact(&mut sum).unwrap();
                }
                publisher
                    .polynomial(index, offset, &incoming[..count], &mut sum)
                    .unwrap();
                target.write_all(&sum).unwrap();
            }
            target.finish().unwrap();
        }
        publisher.finish_offer().unwrap();
        let retained = publisher.retain(credentials[0], poll).unwrap();
        for offset in [0, 2, retained.len() - 65, retained.len() - 1] {
            let mut changed = retained.clone();
            changed[offset] ^= 1;
            assert!(
                AggregatePublisher::restore(
                    credentials[0],
                    poll,
                    selection.roster().clone(),
                    &changed
                )
                .is_err()
            );
        }
        assert!(
            AggregatePublisher::restore(
                credentials[1],
                poll,
                selection.roster().clone(),
                &retained
            )
            .is_err()
        );
        assert!(
            AggregatePublisher::restore(
                credentials[0],
                poll,
                selection.roster().clone(),
                &retained[..retained.len() - 1]
            )
            .is_err()
        );
        publisher = AggregatePublisher::restore(
            credentials[0],
            poll,
            selection.roster().clone(),
            &retained,
        )
        .unwrap();
        assert_eq!(publisher.accepted(), accepted + 1);
        previous_directory = Some(destination);
    }
    let (manifest, _organizer_streamed) = publisher.finish(selection.clone()).unwrap();
    crate::write(published.join("manifest.bin"), &manifest.encode());
    // This reader receives no committed key polynomial.
    let mut reader = StreamedOfferAggregator::new(selection.clone(), Vec::new()).unwrap();
    let mut previous_directory: Option<PathBuf> = None;
    for (ordinal, offer) in offers.iter().enumerate() {
        let mut proof_header = vec![0; setup_relation(profile).proof_header_bytes()];
        File::open(directories[ordinal].join("proof.bin"))
            .unwrap()
            .read_exact(&mut proof_header)
            .unwrap();
        let header = fs::read(directories[ordinal].join("body-header.bin")).unwrap();
        reader
            .begin_verification(offer.authenticated().clone(), &header, &proof_header)
            .unwrap();
        aggregate::read_source(&directories[ordinal], |bytes| reader.source(bytes)).unwrap();
        let destination = output.join(format!("compact-prefix-{ordinal}"));
        fs::create_dir(&destination).unwrap();
        for index in profile.streamed_contribution_polynomials() {
            let (length, capacity) = aggregate::polynomial_bytes(profile, index);
            let mut source = File::open(polynomial_file(&directories[ordinal], index)).unwrap();
            let mut previous = previous_directory
                .as_ref()
                .map(|directory| File::open(polynomial_file(directory, index)).unwrap());
            let mut target = PublicOutput::create(polynomial_file(&destination, index)).unwrap();
            let mut incoming = vec![0; capacity];
            let mut sum = vec![0; capacity];
            for offset in (0..length).step_by(capacity) {
                let count = capacity.min(length - offset);
                source.read_exact(&mut incoming[..count]).unwrap();
                if let Some(previous) = &mut previous {
                    previous.read_exact(&mut sum[..count]).unwrap();
                }
                reader
                    .polynomial(index, offset, &incoming[..count], &mut sum[..count])
                    .unwrap();
                target.write_all(&sum[..count]).unwrap();
            }
            target.finish().unwrap();
        }
        let mut proof = File::open(directories[ordinal].join("proof.bin")).unwrap();
        let mut bytes = vec![0; CHUNK_BYTES];
        let mut offset = 0;
        loop {
            let count = proof.read(&mut bytes).unwrap();
            if count == 0 {
                break;
            }
            reader.proof(offset, &bytes[..count]).unwrap();
            offset += count;
        }
        reader.finish_contribution().unwrap();
        previous_directory = Some(destination);
    }
    let streamed = reader.finish().unwrap();
    let mut verifier =
        PublishedAggregateVerifier::new(streamed.clone(), &manifest.encode()).unwrap();
    for index in profile.committed_polynomials() {
        let mut source = File::open(polynomial_file(&published, index)).unwrap();
        let mut normalized =
            PublicOutput::create(output.join(format!("normalized-{index:02}.bin"))).unwrap();
        let mut bytes = vec![0; CHUNK_BYTES - 17];
        let mut offset = 0;
        loop {
            let count = source.read(&mut bytes).unwrap();
            if count == 0 {
                break;
            }
            let mut output = Vec::new();
            verifier
                .polynomial(index, offset, &bytes[..count], &mut output)
                .unwrap();
            normalized.write_all(&output).unwrap();
            offset += count;
        }
        normalized.finish().unwrap();
    }
    let retained = verifier.retain_data(credentials[0], poll).unwrap();
    let fresh = || PublishedAggregateVerifier::new(streamed.clone(), &manifest.encode()).unwrap();
    for offset in [0, 64, 112, retained.len() - 1] {
        let mut changed = retained.clone();
        changed[offset] ^= 1;
        assert!(
            fresh()
                .restore_data(credentials[0], poll, &changed)
                .is_err()
        );
    }
    assert!(
        fresh()
            .restore_data(credentials[1], poll, &retained)
            .is_err()
    );
    assert!(
        fresh()
            .restore_data(credentials[0], poll, &retained[..retained.len() - 1])
            .is_err()
    );
    let mut incomplete = fresh();
    incomplete
        .restore_data(credentials[0], poll, &retained)
        .unwrap();
    assert!(incomplete.finish().is_err());
    verifier = fresh();
    verifier
        .restore_data(credentials[0], poll, &retained)
        .unwrap();
    for ordinal in 0..offers.len() {
        let path = published.join(format!("evaluation-{ordinal:02}.bin"));
        evaluation(&selection, offers, directories, &manifest, ordinal, &path);
        let mut proof = File::open(path).unwrap();
        let mut header = vec![0; EVALUATION_HEADER_BYTES];
        proof.read_exact(&mut header).unwrap();
        // A bad candidate at this ordinal cannot poison the valid successor.
        verifier.begin_evaluation(ordinal, &header).unwrap();
        assert!(verifier.finish_evaluation().is_err());
        verifier.begin_evaluation(ordinal, &header).unwrap();
        assert!(verifier.proof(&[0xff; 8]).is_err());
        verifier.begin_evaluation(ordinal, &header).unwrap();
        let mut bytes = vec![0; 32_761];
        loop {
            let count = proof.read(&mut bytes).unwrap();
            if count == 0 {
                break;
            }
            verifier.proof(&bytes[..count]).unwrap();
        }
        verifier.finish_evaluation().unwrap();
    }
    let verified = verifier.finish().unwrap();
    assert_eq!(verified.identity(), expected.identity());
    assert_eq!(verified.polynomials(), expected.polynomials());
    // Rehashing an altered sum authenticates its transport, but cannot satisfy
    // the sum relation even with truthful proofs at its newly derived point.
    let forged = output.join("altered-aggregate");
    fs::create_dir(&forged).unwrap();
    let first = profile.committed_polynomials()[0];
    let mut altered = fs::read(polynomial_file(&published, first)).unwrap();
    altered[0] ^= 1;
    crate::write(polynomial_file(&forged, first), &altered);
    let digest =
        protocol_foundations::identity::identity("sealed-lattice/setup-limb-sum", &altered)
            .unwrap();
    let mut forged_manifest = manifest.encode();
    forged_manifest[1..65].copy_from_slice(&digest);
    let forged_manifest = AggregateManifest::decode(&selection, &forged_manifest).unwrap();
    let mut false_sum =
        PublishedAggregateVerifier::new(streamed, &forged_manifest.encode()).unwrap();
    for index in profile.committed_polynomials() {
        let directory = if index == first { &forged } else { &published };
        let mut file = File::open(polynomial_file(directory, index)).unwrap();
        let mut buffer = vec![0; CHUNK_BYTES];
        let mut offset = 0;
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            false_sum
                .polynomial(index, offset, &buffer[..length], &mut Vec::new())
                .unwrap();
            offset += length;
        }
    }
    for ordinal in 0..offers.len() {
        let path = forged.join(format!("evaluation-{ordinal:02}.bin"));
        evaluation(
            &selection,
            offers,
            directories,
            &forged_manifest,
            ordinal,
            &path,
        );
        let proof = fs::read(path).unwrap();
        false_sum
            .begin_evaluation(ordinal, &proof[..EVALUATION_HEADER_BYTES])
            .unwrap();
        for chunk in proof[EVALUATION_HEADER_BYTES..].chunks(32_761) {
            false_sum.proof(chunk).unwrap();
        }
        false_sum.finish_evaluation().unwrap();
    }
    assert!(false_sum.finish().is_err());
    println!(
        "Verified the published aggregate from compact offers and matched every independently summed polynomial"
    );
    verified
}
