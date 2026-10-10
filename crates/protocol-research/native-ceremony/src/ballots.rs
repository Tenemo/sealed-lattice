//! The honest ballots: the organizer's ballot with every refusal its private
//! and public paths owe, the corrupt authors' authenticated invalid ballots,
//! and every other voter's ballot.
use crate::{
    aggregate::{self, ballot_key, polynomial_bytes},
    close,
    enrollment::RetainedSigner,
    participants::OriginalEnrollments,
    public_output,
    scenario::Scenario,
    write,
};
use participant_module::{Enrollment, ballot::BallotOperation};
use protocol_foundations::{
    RETAINED_TAG_BYTES, SIGNATURE_BYTES,
    ballot_authentication::BallotEnvelope,
    poll::{SignedPoll, VerifiedPoll},
    roster::RetainedContributionContext,
    setup_selection::AuthenticatedSelectionCertificate,
};
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use supported_profile::{MAXIMUM_SCORE, Profile};

/// The public body file of each ballot source. The wrong-position source
/// reuses position zero's body.
pub(crate) fn ballot_body_path(directory: &Path, scenario: &Scenario, author: usize) -> PathBuf {
    directory.join(if author == 0 || Some(author) == scenario.wrong_position {
        "body.bin".to_owned()
    } else if Some(author) == scenario.invalid_proof {
        "invalid-proof-body.bin".to_owned()
    } else {
        format!("body-{author}.bin")
    })
}
/// Streams a final aggregate key into a consumer in whole-coefficient
/// chunks, with each chunk's offset.
fn stream_key(keys: &Path, profile: Profile, index: usize, mut consume: impl FnMut(usize, &[u8])) {
    let (total, chunk) = polynomial_bytes(profile, index);
    let values = fs::read(keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
    assert_eq!(values.len(), total);
    for (ordinal, bytes) in values.chunks(chunk).enumerate() {
        consume(ordinal * chunk, bytes);
    }
}
/// Public inputs shared by every honest participant's private ballot commands.
pub(crate) struct BallotInputs<'a> {
    pub(crate) poll: &'a Arc<VerifiedPoll>,
    pub(crate) setup: &'a Arc<VerifiedSetupAggregate>,
    pub(crate) definition: &'a SignedPoll,
    pub(crate) final_keys: &'a Path,
    pub(crate) directory: &'a Path,
    pub(crate) scenario: &'a Scenario,
}
impl BallotInputs<'_> {
    /// Casts one honest ballot through the enrollment-owned private commands,
    /// then accepts it through the public classification path.
    pub(crate) fn cast(
        &self,
        enrollment: &mut Enrollment,
        position: usize,
        scores: &[u8],
    ) -> close::Submission {
        let profile = self.scenario.profile();
        let proposal = RetainedContributionContext::parse(
            &enrollment.credential,
            &self.setup.roster().proposal().records()[position],
            self.poll,
            position,
            self.setup.roster().proposal().body(),
        )
        .unwrap();
        let retained_reference = participant_module::ballot::retained_setup_reference(
            &enrollment.credential,
            self.poll,
            self.setup,
        )
        .unwrap();
        let control = [
            self.poll.identity().as_slice(),
            self.poll.runtime().as_slice(),
            (self.definition.body.len() as u32).to_le_bytes().as_slice(),
            self.definition.body.as_slice(),
            self.definition.signature.as_slice(),
            self.setup.identity().as_slice(),
            retained_reference.as_slice(),
        ]
        .concat();
        let credential = &mut enrollment.credential;
        let mut work =
            participant_module::ballot::BallotWork::new(credential, &proposal, &control).unwrap();
        let index = ballot_key(profile);
        work.command(credential, BallotOperation::BeginKey, index, &[])
            .unwrap();
        stream_key(self.final_keys, profile, index, |offset, bytes| {
            work.command(credential, BallotOperation::PushKey, offset, bytes)
                .unwrap();
        });
        work.command(credential, BallotOperation::FinishKey, 0, &[])
            .unwrap();
        let ballot_time = close::now_milliseconds();
        work.command(
            credential,
            BallotOperation::Create,
            0,
            &[ballot_time.to_le_bytes().as_slice(), scores].concat(),
        )
        .unwrap();
        let envelope = BallotEnvelope::decode(
            profile,
            &work
                .command(credential, BallotOperation::Envelope, 0, &[])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(envelope.ballot_time(), ballot_time);
        let path = ballot_body_path(self.directory, self.scenario, position);
        let mut body = public_output::PublicOutput::create(&path).unwrap();
        for offset in (0..envelope.body_length()).step_by(1 << 20) {
            let length = ((1 << 20).min(envelope.body_length() - offset)) as u32;
            body.write_all(
                &work
                    .command(
                        credential,
                        BallotOperation::BodySlice,
                        offset,
                        &length.to_le_bytes(),
                    )
                    .unwrap(),
            )
            .unwrap();
        }
        body.finish().unwrap();
        work.command(credential, BallotOperation::Sign, 0, envelope.bytes())
            .unwrap();
        let signature: [u8; SIGNATURE_BYTES] = work
            .command(credential, BallotOperation::Signature, 0, &[])
            .unwrap()
            .try_into()
            .unwrap();
        assert!(matches!(
            aggregate::classify_ballot(
                self.poll.clone(),
                self.setup.clone(),
                envelope.bytes(),
                &signature,
                &path,
                self.final_keys,
                "valid",
            ),
            Ok(ballot_proof::body::BallotBodyClassification::Valid(_))
        ));
        write(
            self.directory.join(format!("envelope-{position}.bin")),
            envelope.bytes(),
        );
        write(
            self.directory.join(format!("signature-{position}.bin")),
            &signature,
        );
        close::Submission {
            envelope,
            signature,
            body: path,
        }
    }
}

/// Casts and checks the organizer's ballot, the corrupt authors' invalid
/// ballots and every other voter's ballot, and returns each position's
/// submission.
pub(crate) fn run(
    ballot_inputs: &BallotInputs,
    certificate: &AuthenticatedSelectionCertificate,
    enrollments: &mut OriginalEnrollments,
    organizer: &RetainedSigner,
) -> Vec<Option<close::Submission>> {
    let (poll, setup, packet, scenario) = (
        ballot_inputs.poll,
        ballot_inputs.setup,
        ballot_inputs.definition,
        ballot_inputs.scenario,
    );
    let (final_keys, ballot_directory) = (ballot_inputs.final_keys, ballot_inputs.directory);
    let profile = scenario.profile();
    let count = profile.participants();
    let fhe_key = ballot_key(profile);
    let retained_proposal = RetainedContributionContext::parse(
        &enrollments[0].credential,
        &setup.roster().proposal().records()[0],
        poll,
        0,
        setup.roster().proposal().body(),
    )
    .unwrap();
    let owner = close::owner_of(&enrollments[0].credential, poll, setup, 0);
    let retained_reference = participant_module::ballot::retained_setup_reference(
        &enrollments[0].credential,
        poll,
        setup,
    )
    .unwrap();
    let retained_record = &retained_reference[..retained_reference.len() - RETAINED_TAG_BYTES];
    let restore = |credential: &protocol_foundations::Credential, retained: &[u8]| {
        VerifiedSetupAggregate::restore(credential, poll, certificate, retained)
    };
    let restored = restore(&enrollments[0].credential, &retained_reference).unwrap();
    assert_eq!(restored.identity(), setup.identity());
    assert_eq!(restored.polynomials().len(), setup.polynomials().len());
    for (left, right) in restored.polynomials().iter().zip(setup.polynomials()) {
        assert_eq!(
            (left.index(), left.bytes(), left.digest()),
            (right.index(), right.bytes(), right.digest())
        );
    }
    let inputs =
        setup_aggregate::RetainedSetupInputs::parse(profile, retained_record, setup.identity())
            .unwrap();
    let private_context = ballot_encryption::context::BallotComputationContext::from_retained(
        poll.clone(),
        &owner,
        &inputs,
    )
    .unwrap();
    assert_eq!(
        ballot_proof::context::private_proof_role(&private_context).unwrap(),
        ballot_proof::context::proof_role(poll, setup, 0).unwrap()
    );
    let control_with_reference = |reference: &[u8]| {
        [
            poll.identity().as_slice(),
            poll.runtime().as_slice(),
            (packet.body.len() as u32).to_le_bytes().as_slice(),
            packet.body.as_slice(),
            packet.signature.as_slice(),
            setup.identity().as_slice(),
            reference,
        ]
        .concat()
    };
    let foreign_reference = participant_module::ballot::retained_setup_reference(
        &enrollments[1].credential,
        poll,
        setup,
    )
    .unwrap();
    let mut changed_digest = retained_reference.clone();
    changed_digest[4 + 64] ^= 1;
    for reference in [&foreign_reference[..], &changed_digest, retained_record] {
        assert!(
            participant_module::ballot::BallotWork::new(
                &enrollments[0].credential,
                &retained_proposal,
                &control_with_reference(reference)
            )
            .is_err()
        );
        assert!(restore(&enrollments[0].credential, reference).is_err());
    }
    assert!(restore(&enrollments[1].credential, &retained_reference).is_err());
    // Selected and nonselected original positions use the same certified,
    // credential-keyed setup reference; neither needs an own offer later.
    let outsider = count - 1;
    let outsider_proposal = RetainedContributionContext::parse(
        &enrollments[outsider].credential,
        &setup.roster().proposal().records()[outsider],
        poll,
        outsider,
        setup.roster().proposal().body(),
    )
    .unwrap();
    let outsider_reference = participant_module::ballot::retained_setup_reference(
        &enrollments[outsider].credential,
        poll,
        setup,
    )
    .unwrap();
    let outsider_owner = close::owner_of(&enrollments[outsider].credential, poll, setup, outsider);
    assert_eq!(outsider_owner.position(), outsider);
    assert_eq!(outsider_owner.setup_identity(), &setup.identity());
    assert_eq!(
        participant_module::ballot::BallotWork::new(
            &enrollments[outsider].credential,
            &outsider_proposal,
            &control_with_reference(&outsider_reference)
        )
        .unwrap()
        .into_owner()
        .position(),
        outsider
    );
    let ballot_control = control_with_reference(&retained_reference);
    let mut work = participant_module::ballot::BallotWork::new(
        &enrollments[0].credential,
        &retained_proposal,
        &ballot_control,
    )
    .unwrap();
    assert!(
        work.command(
            &mut enrollments[0].credential,
            BallotOperation::Envelope,
            0,
            &[]
        )
        .is_err()
    );
    // Only the FHE aggregate is a delivered ballot key.
    assert!(
        participant_module::ballot::BallotWork::new(
            &enrollments[0].credential,
            &retained_proposal,
            &ballot_control,
        )
        .unwrap()
        .command(
            &mut enrollments[0].credential,
            BallotOperation::BeginKey,
            profile.share_constant_polynomial(0),
            &[]
        )
        .is_err()
    );
    let index = fhe_key;
    let mut reader = inputs.read_polynomial(index).unwrap();
    stream_key(final_keys, profile, index, |offset, bytes| {
        reader.push(offset, bytes).unwrap();
    });
    let key = reader.finish().unwrap();
    assert_eq!(
        key.coefficients(),
        aggregate::read_key(setup, index, final_keys).coefficients()
    );
    work.command(
        &mut enrollments[0].credential,
        BallotOperation::BeginKey,
        index,
        &[],
    )
    .unwrap();
    stream_key(final_keys, profile, index, |offset, bytes| {
        work.command(
            &mut enrollments[0].credential,
            BallotOperation::PushKey,
            offset,
            bytes,
        )
        .unwrap();
    });
    work.command(
        &mut enrollments[0].credential,
        BallotOperation::FinishKey,
        0,
        &[],
    )
    .unwrap();
    // A repeated key poisons its private session, so isolate that hostile
    // delivery from the original session's later score checks.
    {
        let mut repeated = participant_module::ballot::BallotWork::new(
            &enrollments[0].credential,
            &retained_proposal,
            &ballot_control,
        )
        .unwrap();
        repeated
            .command(
                &mut enrollments[0].credential,
                BallotOperation::BeginKey,
                fhe_key,
                &[],
            )
            .unwrap();
        stream_key(final_keys, profile, fhe_key, |offset, bytes| {
            repeated
                .command(
                    &mut enrollments[0].credential,
                    BallotOperation::PushKey,
                    offset,
                    bytes,
                )
                .unwrap();
        });
        repeated
            .command(
                &mut enrollments[0].credential,
                BallotOperation::FinishKey,
                0,
                &[],
            )
            .unwrap();
        assert!(
            repeated
                .command(
                    &mut enrollments[0].credential,
                    BallotOperation::BeginKey,
                    fhe_key,
                    &[]
                )
                .is_err()
        );
        let timed_scores = [
            close::now_milliseconds().to_le_bytes().as_slice(),
            &scenario.scores(0),
        ]
        .concat();
        assert!(matches!(
            repeated.command(
                &mut enrollments[0].credential,
                BallotOperation::Create,
                0,
                &timed_scores
            ),
            Err(protocol_foundations::Error::Consumed)
        ));
    }
    // Refused inputs consume neither the ballot attempt nor the keys already
    // delivered to this session.
    let ballot_time = close::now_milliseconds();
    let timed = |scores: &[u8]| [ballot_time.to_le_bytes().as_slice(), scores].concat();
    let valid = scenario.scores(0);
    let options = valid.len();
    let mut refused = vec![
        Vec::new(),
        valid[..options - 1].to_vec(),
        valid.iter().copied().chain([1]).collect(),
    ];
    for (index, score) in [(0, 0), (options - 1, MAXIMUM_SCORE as u8 + 1)] {
        let mut scores = valid.clone();
        scores[index] = score;
        refused.push(scores);
    }
    let mut inputs: Vec<_> = refused.iter().map(|scores| timed(scores)).collect();
    // A score vector without its ballot time.
    inputs.push(valid[..options.min(7)].to_vec());
    for input in inputs {
        assert!(matches!(
            work.command(
                &mut enrollments[0].credential,
                BallotOperation::Create,
                0,
                &input
            ),
            Err(protocol_foundations::Error::Shape)
        ));
    }
    work.command(
        &mut enrollments[0].credential,
        BallotOperation::Create,
        0,
        &timed(&valid),
    )
    .unwrap();
    let encoded = work
        .command(
            &mut enrollments[0].credential,
            BallotOperation::Envelope,
            0,
            &[],
        )
        .unwrap();
    let computed_envelope = BallotEnvelope::decode(profile, &encoded).unwrap();
    let body_path = ballot_body_path(ballot_directory, scenario, 0);
    let mut body_file = public_output::PublicOutput::create(&body_path).unwrap();
    for offset in (0..computed_envelope.body_length()).step_by(1 << 20) {
        let length = ((1 << 20).min(computed_envelope.body_length() - offset)) as u32;
        body_file
            .write_all(
                &work
                    .command(
                        &mut enrollments[0].credential,
                        BallotOperation::BodySlice,
                        offset,
                        &length.to_le_bytes(),
                    )
                    .unwrap(),
            )
            .unwrap();
    }
    body_file.finish().unwrap();
    let mut body_input = File::open(&body_path).unwrap();
    let mut header = vec![0; protocol_foundations::ballot_body::HEADER_BYTES];
    body_input.read_exact(&mut header).unwrap();
    std::io::copy(
        &mut std::io::Read::by_ref(&mut body_input)
            .take(protocol_foundations::ballot_body::ciphertext_bytes(profile) as u64),
        &mut std::io::sink(),
    )
    .unwrap();
    let mut proof_file =
        public_output::PublicOutput::create(ballot_directory.join("proof.bin")).unwrap();
    std::io::copy(&mut body_input, &mut proof_file).unwrap();
    proof_file.finish().unwrap();
    let body =
        aggregate::verify_ballot(poll.clone(), setup.clone(), &header, &body_path, final_keys);
    let identity = *body.identity();
    let envelope = BallotEnvelope::new(
        profile,
        poll.identity(),
        setup.identity(),
        0,
        ballot_time,
        body.length(),
        *body.identity(),
    )
    .unwrap();
    assert_eq!(envelope.bytes(), computed_envelope.bytes());
    assert!(
        enrollments[1]
            .credential
            .sign_retained_ballot_envelope(&owner, &envelope)
            .is_err()
    );
    assert!(
        work.command(
            &mut enrollments[1].credential,
            BallotOperation::Sign,
            0,
            envelope.bytes()
        )
        .is_err()
    );
    work.command(
        &mut enrollments[0].credential,
        BallotOperation::Sign,
        0,
        envelope.bytes(),
    )
    .unwrap();
    let signature: [u8; SIGNATURE_BYTES] = work
        .command(
            &mut enrollments[0].credential,
            BallotOperation::Signature,
            0,
            &[],
        )
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        work.command(
            &mut enrollments[0].credential,
            BallotOperation::Sign,
            0,
            envelope.bytes()
        )
        .is_err()
    );
    let restore_credential = || organizer.restored(poll, setup.roster().proposal(), 0);
    let mut restored = restore_credential();
    for changed_body in [false, true] {
        let mut restored_credential = restore_credential();
        let mut restored_work = participant_module::ballot::BallotWork::new(
            &restored_credential,
            &retained_proposal,
            &ballot_control,
        )
        .unwrap();
        let index = fhe_key;
        restored_work
            .command(
                &mut restored_credential,
                BallotOperation::BeginKey,
                index,
                &[],
            )
            .unwrap();
        stream_key(final_keys, profile, index, |offset, bytes| {
            restored_work
                .command(
                    &mut restored_credential,
                    BallotOperation::PushKey,
                    offset,
                    bytes,
                )
                .unwrap();
        });
        restored_work
            .command(&mut restored_credential, BallotOperation::FinishKey, 0, &[])
            .unwrap();
        restored_work
            .command(
                &mut restored_credential,
                BallotOperation::BeginImport,
                0,
                envelope.bytes(),
            )
            .unwrap();
        let mut file = File::open(&body_path).unwrap();
        let mut buffer = vec![0; 1 << 20];
        let mut offset = 0;
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            if changed_body && offset == 0 {
                buffer[0] ^= 1;
            }
            restored_work
                .command(
                    &mut restored_credential,
                    BallotOperation::PushImport,
                    offset,
                    &buffer[..length],
                )
                .unwrap();
            offset += length;
        }
        let verified = restored_work.command(
            &mut restored_credential,
            BallotOperation::FinishImport,
            0,
            &[],
        );
        if changed_body {
            assert!(verified.is_err());
        } else {
            verified.unwrap();
        }
        // The restored credential signs no ballot: a changed body stops the
        // work, and the verified body's credential keeps its ballot purpose
        // locked.
        assert!(
            restored_work
                .command(
                    &mut restored_credential,
                    BallotOperation::Sign,
                    0,
                    envelope.bytes(),
                )
                .is_err()
        );
    }
    let restored_owner = close::owner_of(&restored, poll, setup, 0);
    let mut changed_envelope = *envelope.bytes();
    changed_envelope[150] ^= 1;
    let changed_envelope = BallotEnvelope::decode(profile, &changed_envelope).unwrap();
    // The restored credential signs nothing new until its authenticated root
    // unlocks a purpose that the root's records show unused.
    assert!(matches!(
        restored.sign_retained_ballot_envelope(&restored_owner, &changed_envelope),
        Err(protocol_foundations::Error::Consumed)
    ));
    // Restoring the completed ballot consumes the purpose even after an unlock.
    restored
        .unlock_unused_purposes(protocol_foundations::SigningPurpose::Ballot.mask())
        .unwrap();
    assert!(
        restored
            .restore_retained_ballot_signing(&restored_owner, &changed_envelope, &signature)
            .is_err()
    );
    restored
        .restore_retained_ballot_signing(&restored_owner, &envelope, &signature)
        .unwrap();
    assert!(
        restored
            .sign_retained_ballot_envelope(&restored_owner, &envelope)
            .is_err()
    );
    assert!(
        restored
            .sign_retained_ballot_envelope(&restored_owner, &changed_envelope)
            .is_err()
    );
    // The author's credential signs its ballot envelope only once.
    assert!(
        enrollments[0]
            .credential
            .sign_ballot_envelope(setup.roster(), &envelope)
            .is_err()
    );
    let authenticated =
        ballot_proof::submission::authenticate_envelope(setup, envelope.bytes(), &signature)
            .unwrap();
    let accepted = ballot_proof::submission::verify_submission(body, setup, authenticated).unwrap();
    assert_eq!(accepted.body().identity(), &identity);
    assert_eq!(accepted.body().relation().position(), 0);
    write(ballot_directory.join("body-identity.bin"), &identity);
    write(ballot_directory.join("envelope.bin"), envelope.bytes());
    write(ballot_directory.join("signature.bin"), &signature);
    write(
        ballot_directory.join("signing-public.bin"),
        enrollments[0].credential.signing_public(),
    );
    let mut changed = signature;
    changed[0] ^= 1;
    assert!(
        ballot_proof::submission::authenticate_envelope(setup, envelope.bytes(), &changed).is_err()
    );
    let body =
        aggregate::verify_ballot(poll.clone(), setup.clone(), &header, &body_path, final_keys);
    // Another participant's credential cannot sign the author's envelope.
    assert!(
        enrollments[1]
            .credential
            .sign_ballot_envelope(setup.roster(), &envelope)
            .is_err()
    );
    let mut submissions: Vec<Option<close::Submission>> = vec![None; enrollments.len()];
    submissions[0] = Some(close::Submission {
        envelope: envelope.clone(),
        signature,
        body: body_path.clone(),
    });
    use ballot_proof::body::BallotBodyClassification;
    // A corrupt author signs position zero's body under its own envelope
    // position; the statement names position zero, so the body is invalid.
    let mut invalid_sources = Vec::new();
    if let Some(author) = scenario.wrong_position {
        let wrong_position = BallotEnvelope::new(
            profile,
            *body.relation().poll(),
            setup.identity(),
            author,
            close::now_milliseconds(),
            body.length(),
            *body.identity(),
        )
        .unwrap();
        let wrong_position_signature = enrollments[author]
            .credential
            .sign_ballot_envelope(setup.roster(), &wrong_position)
            .unwrap();
        let authentication = ballot_proof::submission::authenticate_envelope(
            setup,
            wrong_position.bytes(),
            &wrong_position_signature,
        )
        .unwrap();
        write(
            ballot_directory.join("wrong-position-envelope.bin"),
            wrong_position.bytes(),
        );
        write(
            ballot_directory.join("wrong-position-signature.bin"),
            &wrong_position_signature,
        );
        assert!(ballot_proof::submission::verify_submission(body, setup, authentication).is_err());
        invalid_sources.push(close::Submission {
            envelope: wrong_position,
            signature: wrong_position_signature,
            body: body_path.clone(),
        });
    }
    // A corrupt author signs position zero's body with its own position in
    // the statement, so the statement and position agree and the proof
    // fails.
    if let Some(author) = scenario.invalid_proof {
        let invalid_proof_path = ballot_body_path(ballot_directory, scenario, author);
        let mut source = File::open(&body_path).unwrap();
        let mut modified_header = [0; protocol_foundations::ballot_body::HEADER_BYTES];
        source.read_exact(&mut modified_header).unwrap();
        // The statement position follows the body header's magic, proof
        // length, statement magic, poll and setup identity.
        let position = 12 + 4 + 64 + 64;
        modified_header[position..position + 2].copy_from_slice(&(author as u16).to_le_bytes());
        let mut destination = public_output::PublicOutput::create(&invalid_proof_path).unwrap();
        let mut hash =
            protocol_foundations::ballot_body::body_hasher(profile, envelope.body_length())
                .unwrap();
        destination.write_all(&modified_header).unwrap();
        hash.push(&modified_header).unwrap();
        let mut buffer = vec![0; 1 << 20];
        loop {
            let length = source.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            destination.write_all(&buffer[..length]).unwrap();
            hash.push(&buffer[..length]).unwrap();
        }
        destination.finish().unwrap();
        let invalid_proof_envelope = BallotEnvelope::new(
            profile,
            poll.identity(),
            setup.identity(),
            author,
            close::now_milliseconds(),
            envelope.body_length(),
            hash.finish().unwrap(),
        )
        .unwrap();
        let invalid_proof_signature = enrollments[author]
            .credential
            .sign_ballot_envelope(setup.roster(), &invalid_proof_envelope)
            .unwrap();
        write(
            ballot_directory.join("invalid-proof-envelope.bin"),
            invalid_proof_envelope.bytes(),
        );
        write(
            ballot_directory.join("invalid-proof-signature.bin"),
            &invalid_proof_signature,
        );
        invalid_sources.push(close::Submission {
            envelope: invalid_proof_envelope,
            signature: invalid_proof_signature,
            body: invalid_proof_path,
        });
    }
    for mode in [
        "valid",
        "header",
        "proof",
        "truncated",
        "trailing",
        "key",
        "unfinished-key",
        "valid",
    ] {
        let result = aggregate::classify_ballot(
            poll.clone(),
            setup.clone(),
            envelope.bytes(),
            &signature,
            &body_path,
            final_keys,
            mode,
        );
        if mode == "valid" {
            assert!(matches!(result, Ok(BallotBodyClassification::Valid(_))));
        } else {
            assert!(
                result.is_err(),
                "Corrupt delivery classified as an author's ballot: {mode}"
            );
        }
    }
    for source in invalid_sources {
        let author = source.envelope.position();
        match aggregate::classify_ballot(
            poll.clone(),
            setup.clone(),
            source.envelope.bytes(),
            &source.signature,
            &source.body,
            final_keys,
            "valid",
        )
        .unwrap()
        {
            BallotBodyClassification::Invalid(value) => {
                assert_eq!(value.envelope().position(), author)
            }
            BallotBodyClassification::Valid(_) => panic!("An authenticated invalid body verified"),
        }
        submissions[author] = Some(source);
    }
    println!("Authenticated invalid bodies and corrupted delivery distinguished");
    println!(
        "Original retained owner and private setup inputs verified without a public capability shortcut"
    );
    for &position in scenario.voters[1..].iter().chain(&scenario.omitted) {
        submissions[position] = Some(ballot_inputs.cast(
            &mut enrollments[position],
            position,
            &scenario.scores(position),
        ));
        println!("Cast and accepted honest ballot {position}");
    }
    submissions
}
