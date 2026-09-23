use ballot_proof::publication::{SourceValue, VerifiedClosedSlots};
use evaluation_target::{
    certification::CertificateCollector,
    release::ReleaseContext,
    release_body::ReleaseBodyVerifier,
    target::{ClassifiedClosedInventory, Error, PublicInputs, WorkingStore},
    terminal::{ReleaseCollector, verify_no_result},
};
use linked_release_proof::parameters::MAXIMUM_PROOF_BYTES;
use registration_credentials::{
    contribution_authentication::SignedOpening, poll::VerifiedPoll, release_signing::body_header,
    roster::RetainedContributionContext,
};
use registration_enrollment::{Enrollment, finality_work::FinalityWork, release_work::ReleaseWork};
use rns_arithmetic_probe::ranking::{Ciphertext, DEGREE};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

fn packet(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from((body.len() as u32).to_le_bytes());
    bytes.extend(body);
    bytes.extend(signature);
    bytes
}
struct Inputs {
    aggregate: PathBuf,
    ballot: PathBuf,
}
impl PublicInputs for Inputs {
    fn aggregate(&mut self, index: usize) -> Result<Box<dyn Read + '_>, Error> {
        Ok(Box::new(
            File::open(self.aggregate.join(format!("polynomial-{index:02}.bin")))
                .map_err(|_| Error::PublicInput)?,
        ))
    }
    fn ballot(&mut self, author: usize) -> Result<Box<dyn Read + '_>, Error> {
        Ok(Box::new(
            File::open(crate::ballot_body_path(&self.ballot, author))
                .map_err(|_| Error::PublicInput)?,
        ))
    }
}
struct Spool {
    directory: PathBuf,
    indices: BTreeSet<usize>,
}
impl WorkingStore for Spool {
    fn put(&mut self, index: usize, value: &Ciphertext) -> Result<(), Error> {
        if !self.indices.insert(index) {
            return Err(Error::Storage);
        }
        let mut bytes = Vec::with_capacity(2 * DEGREE * 112);
        for polynomial in value {
            for coefficient in polynomial {
                for word in coefficient {
                    bytes.extend(word.to_le_bytes());
                }
            }
        }
        crate::write(self.directory.join(format!("{index}.bin")), &bytes);
        Ok(())
    }
    fn get(&mut self, index: usize) -> Result<Ciphertext, Error> {
        let bytes =
            fs::read(self.directory.join(format!("{index}.bin"))).map_err(|_| Error::Storage)?;
        if bytes.len() != 2 * DEGREE * 112 {
            return Err(Error::Storage);
        }
        Ok(std::array::from_fn(|part| {
            bytes[part * DEGREE * 112..(part + 1) * DEGREE * 112]
                .chunks_exact(112)
                .map(|coefficient| {
                    std::array::from_fn(|word| {
                        u64::from_le_bytes(coefficient[word * 8..word * 8 + 8].try_into().unwrap())
                    })
                })
                .collect()
        }))
    }
    fn remove(&mut self, index: usize) -> Result<(), Error> {
        if self.indices.remove(&index) {
            fs::remove_file(self.directory.join(format!("{index}.bin")))
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}
struct ProofBytes(Vec<u8>);
impl Write for ProofBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAXIMUM_PROOF_BYTES - self.0.len() {
            return Err(io::Error::other("Release proof exceeds its bound"));
        }
        self.0.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn run(
    output: &Path,
    scratch_root: &Path,
    poll: Arc<VerifiedPoll>,
    setup: Arc<VerifiedSetupAggregate>,
    closed: VerifiedClosedSlots,
    enrollments: &mut [Enrollment],
    openings: &[SignedOpening],
) {
    let started = Instant::now();
    let directory = output.join("completion");
    fs::create_dir(&directory).unwrap();
    let aggregate = output.join("aggregates/after-participant-9");
    let ballot = output.join("ballot");
    let mut classifications = Vec::new();
    let mut retained_sources = Vec::new();
    for (author, slot) in closed.slots().iter().enumerate() {
        match slot.source().value() {
            SourceValue::Empty { body, signature } => {
                classifications.push(None);
                let mut bytes = vec![0];
                bytes.extend(packet(body, signature));
                retained_sources.push(bytes);
            }
            SourceValue::Ballot(body) => {
                let authentication = body.authentication();
                let path = crate::ballot_body_path(&ballot, author);
                classifications.push(Some(
                    crate::aggregate::classify_ballot(
                        poll.clone(),
                        setup.clone(),
                        authentication.envelope().bytes(),
                        authentication.signature(),
                        &path,
                        &aggregate,
                        "valid",
                    )
                    .unwrap(),
                ));
                let mut bytes = vec![1];
                bytes.extend(authentication.envelope().bytes());
                bytes.extend(authentication.signature());
                retained_sources.push(bytes);
            }
        }
    }
    let invalid: Vec<_> = classifications
        .iter()
        .enumerate()
        .filter_map(|(author, value)| {
            matches!(
                value,
                Some(ballot_proof::body::BallotBodyClassification::Invalid(_))
            )
            .then_some(author)
        })
        .collect();
    let classified =
        ClassifiedClosedInventory::new(poll.clone(), setup.clone(), closed, classifications)
            .unwrap();
    let accepted: Vec<_> = classified.accepted_authors().collect();
    let scratch = scratch_root.join("completion-spills");
    fs::create_dir(&scratch).unwrap();
    let mut spool = Spool {
        directory: scratch,
        indices: BTreeSet::new(),
    };
    let target = Arc::new(
        classified
            .evaluate(
                &mut Inputs {
                    aggregate: aggregate.clone(),
                    ballot: ballot.clone(),
                },
                &mut spool,
            )
            .unwrap(),
    );
    assert!(spool.indices.is_empty());
    crate::write(directory.join("target.bin"), target.body());
    if let Some(bytes) = target.ciphertext() {
        crate::write(directory.join("ciphertext.bin"), bytes);
    }
    let owners: Vec<_> = enrollments
        .iter_mut()
        .enumerate()
        .map(|(position, enrollment)| {
            let retained = RetainedContributionContext::parse(
                poll.identity(),
                poll.runtime(),
                position,
                setup.inventory().proposal().proposal().body(),
            )
            .unwrap();
            Arc::new(
                enrollment
                    .credential
                    .retain_ballot_owner(
                        &poll,
                        &retained,
                        setup.inventory().identity(),
                        openings[position].body(),
                        openings[position].signature(),
                    )
                    .unwrap(),
            )
        })
        .collect();
    let mut collector = CertificateCollector::new(target.clone());
    assert_eq!(collector.threshold(), 7);
    assert!(collector.certificate().is_err());
    for position in 0..enrollments.len() {
        let body = fs::read(output.join(format!("publication/witness-{position}.bin"))).unwrap();
        let signature =
            fs::read(output.join(format!("publication/witness-{position}-signature.bin"))).unwrap();
        let witness = packet(&body, &signature);
        let owner = owners[position].clone();
        let work = FinalityWork::new(
            owner,
            target.clone(),
            &retained_sources[position],
            Some(&witness),
        )
        .unwrap();
        let mut wrong = work.body().to_vec();
        wrong[0] ^= 1;
        assert!(
            work.sign(
                &mut enrollments[position].credential,
                &wrong,
                *crate::random::<32>()
            )
            .is_err()
        );
        let vote = work
            .sign(
                &mut enrollments[position].credential,
                work.body(),
                *crate::random::<32>(),
            )
            .unwrap();
        assert!(
            work.sign(
                &mut enrollments[position].credential,
                work.body(),
                *crate::random::<32>()
            )
            .is_err()
        );
        let packet = vote.encode();
        let mut wrong = packet.clone();
        wrong[2] ^= 1;
        assert!(collector.insert(&wrong).is_err());
        assert!(collector.insert(&packet).unwrap());
        assert!(!collector.insert(&packet).unwrap());
        let mut wrong = packet.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(collector.insert(&wrong).is_err());
        if position + 1 < collector.threshold() {
            assert!(collector.certificate().is_err());
        }
        crate::write(
            directory.join(format!("target-vote-{position}.bin")),
            &packet,
        );
    }
    let certificate = Arc::new(collector.certificate().unwrap());
    assert_eq!(certificate.target().identity(), target.identity());
    println!("Verified complete original-credential target certificate");
    if target.ciphertext().is_none() {
        let terminal = verify_no_result(certificate).unwrap();
        assert_eq!(
            terminal.certificate().target().identity(),
            target.identity()
        );
        crate::write(
            directory.join("result.json"),
            format!(
                "{{\"kind\":\"no-result\",\"accepted\":{accepted:?},\"invalid\":{invalid:?},\"milliseconds\":{}}}\n",
                started.elapsed().as_secs_f64() * 1000.0
            )
            .as_bytes(),
        );
        println!("Verified certified no-result outcome");
        return;
    }
    assert!(verify_no_result(certificate.clone()).is_err());
    assert_eq!(
        accepted,
        crate::HONEST_BALLOTS.map(|(position, _)| position)
    );
    let mut shares = Vec::new();
    for position in 0..enrollments.len() {
        let context = Arc::new(
            ReleaseContext::new(
                certificate.clone(),
                position,
                crate::aggregate::read_key(&setup, 44 + 3 * position, &aggregate),
                crate::aggregate::read_key(&setup, 45 + 3 * position, &aggregate),
            )
            .unwrap(),
        );
        let operation = ReleaseWork::new(owners[position].clone(), context.clone()).unwrap();
        let enrollment = &mut enrollments[position];
        let (context, statement, proof) = operation
            .prove(&enrollment.key, &mut enrollment.credential)
            .unwrap();
        let mut bytes = ProofBytes(Vec::new());
        proof.write(&mut bytes);
        drop(proof);
        let header = body_header(context.header(), bytes.0.len()).unwrap();
        let partial = &statement.polynomials[5];
        let mut verifier = ReleaseBodyVerifier::new(context.clone(), &header).unwrap();
        for chunk in partial.chunks(1 << 20).chain(bytes.0.chunks(1 << 20)) {
            verifier.push(chunk).unwrap();
        }
        let verified = verifier.finish().unwrap();
        let envelope = verified.envelope();
        let path = directory.join(format!("release-{position}.bin"));
        let mut body = crate::public_output::PublicOutput::create(path).unwrap();
        body.write_all(&header).unwrap();
        body.write_all(partial).unwrap();
        body.write_all(&bytes.0).unwrap();
        body.finish().unwrap();
        let signature = enrollment
            .credential
            .sign_release(
                &owners[position],
                setup.inventory().proposal(),
                &envelope,
                *crate::random::<32>(),
            )
            .unwrap();
        assert!(
            enrollment
                .credential
                .sign_release(
                    &owners[position],
                    setup.inventory().proposal(),
                    &envelope,
                    *crate::random::<32>()
                )
                .is_err()
        );
        let mut packet = envelope.bytes().to_vec();
        packet.extend(signature);
        let mut wrong = packet.clone();
        wrong[132] ^= 1;
        assert!(context.authenticate(&wrong).is_err());
        let authentication = context.authenticate(&packet).unwrap();
        shares.push(Arc::new(verified.authenticate(authentication).unwrap()));
        crate::write(
            directory.join(format!("release-envelope-{position}.bin")),
            &packet,
        );
        let repeated = ReleaseWork::new(owners[position].clone(), context).unwrap();
        assert!(
            repeated
                .prove(&enrollment.key, &mut enrollment.credential)
                .is_err()
        );
        println!("Verified original-key release share {position}");
    }
    // A sorting oracle over the cast scores, with ties to the lower position.
    let mut totals = [0u32; 10];
    for (_, scores) in crate::HONEST_BALLOTS {
        for (total, score) in totals.iter_mut().zip(scores) {
            *total += u32::from(score);
        }
    }
    let mut order: Vec<usize> = (0..10).collect();
    order.sort_by_key(|option| (std::cmp::Reverse(totals[*option]), *option));
    let options = poll.manifest().options();
    let expected: Vec<_> = order
        .into_iter()
        .map(|option| options[option].option_identifier().to_owned())
        .collect();
    let mut subsets = 0;
    for a in 0..10 {
        for b in a + 1..10 {
            for c in b + 1..10 {
                for d in c + 1..10 {
                    let mut result = ReleaseCollector::new(certificate.clone()).unwrap();
                    assert!(result.result().is_err());
                    for index in [a, b, c, d] {
                        assert!(result.insert(shares[index].clone()).unwrap());
                        assert!(!result.insert(shares[index].clone()).unwrap());
                    }
                    assert_eq!(result.result().unwrap().identifiers(), expected);
                    subsets += 1;
                }
            }
        }
    }
    let mut departures = 0;
    for missing in 0u16..1 << 10 {
        if missing.count_ones() > 3 {
            continue;
        }
        let available: Vec<_> = (0..10)
            .filter(|position| missing & (1 << position) == 0 && ![1, 2, 3].contains(position))
            .collect();
        assert!(available.len() >= 4);
        let mut result = ReleaseCollector::new(certificate.clone()).unwrap();
        for position in available.into_iter().take(4) {
            result.insert(shares[position].clone()).unwrap();
        }
        assert_eq!(result.result().unwrap().identifiers(), expected);
        departures += 1;
    }
    crate::write(directory.join("result.json"),format!("{{\"kind\":\"result\",\"accepted\":{accepted:?},\"invalid\":{invalid:?},\"identifiers\":{expected:?},\"releaseSubsets\":{subsets},\"departureSets\":{departures},\"milliseconds\":{}}}\n",started.elapsed().as_secs_f64()*1000.0).as_bytes());
    println!(
        "Verified original ballot-to-result path, every release subset and bounded departure set"
    );
}
