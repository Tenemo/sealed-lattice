mod aggregate;
mod close;
mod completion;
mod contribution;
#[path = "no-result-close.rs"]
mod no_result_close;
mod participants;
#[path = "public-output.rs"]
mod public_output;
mod scenario;
#[path = "selected-setup-completion.rs"]
mod selected_setup_completion;
mod selection;
use aggregate::{ballot_key, final_keys, polynomial_bytes};
use participant_module::{
    Enrollment, ballot::BallotOperation, data_kind, finality_work::OwnBallotInclusion,
};
use participants::OriginalEnrollments;
use protocol_foundations::{
    RETAINED_TAG_BYTES, SIGNATURE_BYTES,
    ballot_authentication::BallotEnvelope,
    foundation::{
        StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
    registration::RegistrationVerifier,
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::authenticate_roster_proposal,
};
use scenario::Scenario;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use supported_profile::{MAXIMUM_SCORE, Profile};
use zeroize::Zeroizing;

// Every participant of this ceremony creates honest ballots; a corrupt
// participant's build of the ballot proof never reaches it.
const _: () = assert!(!ballot_proof::private_ballot::FALSE_STATEMENT);

fn write(path: impl AsRef<Path>, bytes: &[u8]) {
    let mut output = public_output::PublicOutput::create(path).unwrap();
    output.write_all(bytes).unwrap();
    output.finish().unwrap();
}
/// The public body file of each ballot source. The wrong-position source
/// reuses position zero's body.
fn ballot_body_path(directory: &Path, scenario: &Scenario, author: usize) -> PathBuf {
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
struct BallotInputs<'a> {
    poll: &'a Arc<VerifiedPoll>,
    setup: &'a Arc<VerifiedSetupAggregate>,
    definition: &'a SignedPoll,
    final_keys: &'a Path,
    directory: &'a Path,
    scenario: &'a Scenario,
}
impl BallotInputs<'_> {
    /// Casts one honest ballot through the enrollment-owned private commands,
    /// then accepts it through the public classification path.
    fn cast(
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
struct EnrollmentOutput<'a> {
    files: Vec<public_output::PublicOutput>,
    controls: &'a mut [Vec<u8>; 2],
    offsets: [usize; 3],
}
impl<'a> EnrollmentOutput<'a> {
    fn new(directory: &Path, controls: &'a mut [Vec<u8>; 2]) -> Self {
        let files: Vec<_> = [
            "polynomial-01.bin",
            "registration-header.bin",
            "signature.bin",
        ]
        .iter()
        .map(|name| public_output::PublicOutput::create(directory.join(name)).unwrap())
        .collect();
        Self {
            files,
            controls,
            offsets: [0; 3],
        }
    }
    fn emit(&mut self, kind: u32, offset: usize, bytes: &[u8]) {
        let file = match kind {
            data_kind::PUBLIC_KEY => 0,
            data_kind::HEADER => 1,
            data_kind::SIGNATURE => 2,
            _ => return,
        };
        if file >= 1 {
            self.controls[file - 1].extend(bytes);
        }
        assert_eq!(offset, self.offsets[file]);
        self.files[file].write_all(bytes).unwrap();
        self.offsets[file] += bytes.len();
    }
    fn finish(self) {
        for file in self.files {
            file.finish().unwrap();
        }
    }
}
/// The position of an enrollment capsule's record in the order the
/// restoration reads the capsules: the recipient key's, the credential's and
/// the sources'.
fn capsule_index(kind: u32) -> Option<usize> {
    match kind {
        data_kind::RECIPIENT_CAPSULE => Some(0),
        data_kind::SIGNING_CAPSULE => Some(1),
        data_kind::SOURCE_CAPSULE => Some(2),
        _ => None,
    }
}
/// Arguments: the new output directory, the runtime identity file, the
/// scratch directory, the participant and option counts, and optionally
/// `empty` or `invalid-only` for a no-result case.
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(
        arguments.len() == 5
            || (arguments.len() == 6
                && matches!(
                    arguments[5].as_str(),
                    "empty" | "invalid-only" | "setup-departure" | "selection-fork"
                ))
    );
    let scratch = PathBuf::from(&arguments[2]);
    assert!(scratch.is_dir());
    let profile =
        Profile::new(arguments[3].parse().unwrap(), arguments[4].parse().unwrap()).unwrap();
    let scenario = if arguments
        .get(5)
        .is_some_and(|mode| mode == "setup-departure")
    {
        assert_eq!(profile, Profile::new(4, 2).unwrap());
        Scenario::setup_departure()
    } else if arguments
        .get(5)
        .is_some_and(|mode| mode == "selection-fork")
    {
        assert_eq!(profile, Profile::new(4, 2).unwrap());
        Scenario::selection_fork()
    } else {
        Scenario::new(profile)
    };
    let count = profile.participants();
    let output = PathBuf::from(&arguments[0]);
    fs::create_dir(&output).unwrap();
    let runtime_bytes = fs::read(&arguments[1]).unwrap();
    let runtime: [u8; 64] = runtime_bytes.try_into().unwrap();
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let manifest = Manifest::new(
        text("Verify the complete signed ballot path"),
        (0..profile.options() as u16)
            .map(|index| {
                OptionDefinition::new(
                    index,
                    format!("option-{index}"),
                    text(&format!("Option {index}")),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    // The result lists every option, and the roster fills the poll.
    let draft = PollDraft::new(manifest, profile.options() as u16, count as u16).unwrap();
    let directories = (0..count)
        .map(|index| {
            let directory = output.join(format!("participant-{index}"));
            fs::create_dir(&directory).unwrap();
            directory
        })
        .collect::<Vec<_>>();
    let mut controls: Vec<[Vec<u8>; 2]> = (0..count).map(|_| [Vec::new(), Vec::new()]).collect();
    let mut enrollment_capsules: Vec<[Zeroizing<Vec<u8>>; 3]> = (0..count)
        .map(|_| std::array::from_fn(|_| Zeroizing::new(Vec::new())))
        .collect();
    let mut signing_capsule = Vec::new();
    let mut organizer_output = EnrollmentOutput::new(&directories[0], &mut controls[0]);
    let (packet, organizer, organizer_keys) =
        Enrollment::create_organizer(draft, runtime, b"Organizer", |kind, offset, bytes| {
            organizer_output.emit(kind, offset, bytes);
            if let Some(capsule) = capsule_index(kind) {
                assert_eq!(offset, enrollment_capsules[0][capsule].len());
                enrollment_capsules[0][capsule].extend(bytes);
            }
            if kind == data_kind::SIGNING_CAPSULE {
                assert_eq!(offset, signing_capsule.len());
                signing_capsule.extend(bytes);
            }
        })
        .unwrap();
    organizer_output.finish();
    // The organizer's credential capsule key, which later steps reopen.
    let organizer_signing_key: Zeroizing<[u8; 32]> =
        Zeroizing::new(organizer_keys[32..64].try_into().unwrap());
    let mut enrollment_data_keys = vec![organizer_keys];
    let poll =
        Arc::new(verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap());
    write(output.join("poll-definition.bin"), &packet.body);
    write(output.join("poll-signature.bin"), &packet.signature);
    write(
        output.join("context.bin"),
        &[poll.identity().as_slice(), runtime.as_slice()].concat(),
    );
    let mut enrollments = vec![organizer];
    // The corrupt equivocator may fork its own signing state. These
    // encrypted key bytes and wrapping key remain in this process only.
    let mut corrupt_signing_capsule = Zeroizing::new(Vec::new());
    let mut corrupt_wrapping_key = Zeroizing::new([0u8; 32]);
    for (position, directory) in directories.iter().enumerate().skip(1) {
        let retained_corrupt_signer = Some(position) == scenario.equivocator
            || (scenario.departed.is_some() && scenario.corrupt(position));
        let mut record_output = EnrollmentOutput::new(directory, &mut controls[position]);
        let (enrollment, keys) = Enrollment::create_for_poll(
            &poll,
            format!("Participant {position}").as_bytes(),
            |kind, offset, bytes| {
                record_output.emit(kind, offset, bytes);
                if let Some(capsule) = capsule_index(kind) {
                    assert_eq!(offset, enrollment_capsules[position][capsule].len());
                    enrollment_capsules[position][capsule].extend(bytes);
                }
                if retained_corrupt_signer && kind == data_kind::SIGNING_CAPSULE {
                    assert_eq!(offset, corrupt_signing_capsule.len());
                    corrupt_signing_capsule.extend(bytes);
                }
            },
        )
        .unwrap();
        enrollments.push(enrollment);
        record_output.finish();
        if retained_corrupt_signer {
            corrupt_wrapping_key.copy_from_slice(&keys[32..64]);
        }
        enrollment_data_keys.push(keys);
    }
    let mut records = Vec::new();
    let mut buffer = vec![0; 1 << 20];
    for (position, directory) in directories.iter().enumerate() {
        let header = fs::read(directory.join("registration-header.bin")).unwrap();
        let signature = fs::read(directory.join("signature.bin")).unwrap();
        assert!(
            header == controls[position][0],
            "Header readback differs for {position}: stored {} bytes, emitted {} bytes",
            header.len(),
            controls[position][0].len()
        );
        assert!(
            signature == controls[position][1],
            "Signature readback differs for {position}: stored {} bytes, emitted {} bytes",
            signature.len(),
            controls[position][1].len()
        );
        let mut verifier = RegistrationVerifier::new(&poll, &header, &signature).unwrap();
        let mut file = File::open(directory.join("polynomial-01.bin")).unwrap();
        loop {
            let length = file.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            verifier.push_key(&buffer[..length]).unwrap();
        }
        verifier.finish_key().unwrap();
        let record = Arc::new(verifier.finish().unwrap());
        let capsules = &enrollment_capsules[position];
        let restore = |source_capsule: &[u8]| {
            Enrollment::restore(
                &poll,
                record.header(),
                record.public_key(),
                record.body_digest(),
                &enrollment_data_keys[position],
                [&capsules[0], &capsules[1], source_capsule],
            )
        };
        if position == 0 {
            assert!(restore(&[]).is_err());
            let mut changed = Zeroizing::new(capsules[2].to_vec());
            changed[0] ^= 1;
            assert!(restore(&changed).is_err());
            assert!(restore(&enrollment_capsules[1][2]).is_err());
        }
        let mut restored = restore(&capsules[2]).unwrap();
        assert_eq!(
            restored
                .contribution_header(profile, supported_profile::relation::PROOF_HEADER_BYTES)
                .unwrap(),
            enrollments[position]
                .contribution_header(profile, supported_profile::relation::PROOF_HEADER_BYTES)
                .unwrap(),
        );
        // The original completed enrollment has not acted on any roster yet.
        restored
            .credential
            .unlock_unused_purposes(2 * protocol_foundations::SigningPurpose::Release.mask() - 1)
            .unwrap();
        enrollments[position] = restored;
        records.push(record);
        println!("Verified fresh registration {position}");
    }
    drop(enrollment_capsules);
    drop(enrollment_data_keys);
    let proposal = RosterProposal::new(&poll, records).unwrap();
    assert_eq!(proposal.profile(), profile);
    let proposal_signature = enrollments[0]
        .credential
        .sign_roster_proposal(&proposal)
        .unwrap();
    write(output.join("proposal.bin"), proposal.body());
    write(output.join("proposal-signature.bin"), &proposal_signature);
    let roster = Arc::new(authenticate_roster_proposal(proposal, &proposal_signature).unwrap());
    println!("Verified original enrollment roster");
    let mut enrollments = OriginalEnrollments::new(enrollments);
    if let Some(position) = scenario.departed {
        // No future message or private operation can access this authority.
        enrollments.depart(position);
        assert_eq!(enrollments.positions(), [0, 2, 3]);
    }
    let selected_authors: Vec<_> = if scenario.departed.is_some() || scenario.selection_fork {
        vec![0, 2]
    } else {
        (0..profile.setup_contributors()).collect()
    };
    let alternate_endorser = if scenario.departed.is_some() || scenario.selection_fork {
        let position = if scenario.selection_fork { 0 } else { 2 };
        let record = &roster.proposal().records()[position];
        let key = if position == 0 {
            &*organizer_signing_key
        } else {
            &*corrupt_wrapping_key
        };
        let capsule = if position == 0 {
            &signing_capsule
        } else {
            &*corrupt_signing_capsule
        };
        let mut credential = protocol_foundations::Credential::open_complete(
            record.header().signing_public,
            record.body_digest(),
            key,
            capsule,
        )
        .unwrap();
        let retained = RetainedContributionContext::parse(
            &credential,
            record,
            &poll,
            position,
            roster.proposal().body(),
        )
        .unwrap();
        credential.confirm_roster(&retained).unwrap();
        credential
            .unlock_unused_purposes(
                protocol_foundations::SigningPurpose::SelectionEndorsement.mask()
                    | protocol_foundations::SigningPurpose::SelectionProposal.mask(),
            )
            .unwrap();
        Some((position, credential))
    } else {
        None
    };
    let prepared = selection::run(
        &output,
        &poll,
        roster,
        &mut enrollments,
        &selected_authors,
        alternate_endorser,
        scenario.selection_fork,
    );
    let setup = prepared.setup;
    let certificate = prepared.certificate;
    for (_, enrollment) in enrollments.iter_mut() {
        enrollment.retire_sources();
        enrollment.credential.retire_preparation();
        assert!(enrollment.sources_retired());
        assert!(enrollment.contribution_source(profile).is_err());
        assert!(
            enrollment
                .contribution_header(profile, supported_profile::relation::PROOF_HEADER_BYTES)
                .is_err()
        );
    }
    if scenario.departed.is_some() || scenario.selection_fork {
        selected_setup_completion::run(
            &output,
            &scratch,
            poll,
            setup,
            &packet,
            &mut enrollments,
            &scenario,
        );
        return;
    }
    if let Some(mode) = arguments.get(5) {
        let invalid_only = mode == "invalid-only";
        let barrier = no_result_close::run(
            &output,
            poll.clone(),
            setup.clone(),
            &mut enrollments,
            invalid_only,
            &scenario,
        );
        let statuses = (0..enrollments.len())
            .map(|position| {
                (
                    position,
                    if invalid_only && position == 0 {
                        OwnBallotInclusion::Included
                    } else {
                        OwnBallotInclusion::NotCast
                    },
                )
            })
            .collect();
        completion::run(
            &output,
            &scratch,
            barrier,
            &mut enrollments,
            completion::Finality {
                signers: (0..count).collect(),
                statuses,
                forks: Vec::new(),
            },
            &scenario,
        );
        return;
    }
    let final_keys = final_keys(&output, profile);
    let fhe_key = ballot_key(profile);
    let retained_proposal = RetainedContributionContext::parse(
        &enrollments[0].credential,
        &setup.roster().proposal().records()[0],
        &poll,
        0,
        setup.roster().proposal().body(),
    )
    .unwrap();
    let owner = close::owner_of(&enrollments[0].credential, &poll, &setup, 0);
    let retained_reference = participant_module::ballot::retained_setup_reference(
        &enrollments[0].credential,
        &poll,
        &setup,
    )
    .unwrap();
    let retained_record = &retained_reference[..retained_reference.len() - RETAINED_TAG_BYTES];
    let restore = |credential: &protocol_foundations::Credential, retained: &[u8]| {
        VerifiedSetupAggregate::restore(credential, &poll, &certificate, retained)
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
        ballot_proof::context::proof_role(&poll, &setup, 0).unwrap()
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
        &poll,
        &setup,
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
        &poll,
        outsider,
        setup.roster().proposal().body(),
    )
    .unwrap();
    let outsider_reference = participant_module::ballot::retained_setup_reference(
        &enrollments[outsider].credential,
        &poll,
        &setup,
    )
    .unwrap();
    let outsider_owner =
        close::owner_of(&enrollments[outsider].credential, &poll, &setup, outsider);
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
    stream_key(&final_keys, profile, index, |offset, bytes| {
        reader.push(offset, bytes).unwrap();
    });
    let key = reader.finish().unwrap();
    assert_eq!(
        key.coefficients(),
        aggregate::read_key(&setup, index, &final_keys).coefficients()
    );
    work.command(
        &mut enrollments[0].credential,
        BallotOperation::BeginKey,
        index,
        &[],
    )
    .unwrap();
    stream_key(&final_keys, profile, index, |offset, bytes| {
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
        stream_key(&final_keys, profile, fhe_key, |offset, bytes| {
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
    let ballot_directory = output.join("ballot");
    fs::create_dir(&ballot_directory).unwrap();
    let body_path = ballot_body_path(&ballot_directory, &scenario, 0);
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
    let body = aggregate::verify_ballot(
        poll.clone(),
        setup.clone(),
        &header,
        &body_path,
        &final_keys,
    );
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
    let original = setup.roster().proposal().records()[0].as_ref();
    let restore_credential = || {
        let mut credential = protocol_foundations::Credential::open_complete(
            original.header().signing_public,
            original.body_digest(),
            &organizer_signing_key,
            &signing_capsule,
        )
        .unwrap();
        credential.confirm_roster(&retained_proposal).unwrap();
        credential.retire_preparation();
        credential
    };
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
        stream_key(&final_keys, profile, index, |offset, bytes| {
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
    let restored_owner = close::owner_of(&restored, &poll, &setup, 0);
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
        ballot_proof::submission::authenticate_envelope(&setup, envelope.bytes(), &signature)
            .unwrap();
    let accepted =
        ballot_proof::submission::verify_submission(body, &setup, authenticated).unwrap();
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
        ballot_proof::submission::authenticate_envelope(&setup, envelope.bytes(), &changed)
            .is_err()
    );
    let body = aggregate::verify_ballot(
        poll.clone(),
        setup.clone(),
        &header,
        &body_path,
        &final_keys,
    );
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
            &setup,
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
        assert!(ballot_proof::submission::verify_submission(body, &setup, authentication).is_err());
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
        let invalid_proof_path = ballot_body_path(&ballot_directory, &scenario, author);
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
            &final_keys,
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
            &final_keys,
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
    let ballot_inputs = BallotInputs {
        poll: &poll,
        setup: &setup,
        definition: &packet,
        final_keys: &final_keys,
        directory: &ballot_directory,
        scenario: &scenario,
    };
    for &position in scenario.voters[1..].iter().chain(&scenario.omitted) {
        submissions[position] = Some(ballot_inputs.cast(
            &mut enrollments[position],
            position,
            &scenario.scores(position),
        ));
        println!("Cast and accepted honest ballot {position}");
    }
    let equivocator = scenario.equivocator.map(|position| {
        let record = &setup.roster().proposal().records()[position];
        let restore = || {
            let mut credential = protocol_foundations::Credential::open_complete(
                record.header().signing_public,
                record.body_digest(),
                &corrupt_wrapping_key,
                &corrupt_signing_capsule,
            )
            .unwrap();
            let retained = RetainedContributionContext::parse(
                &credential,
                record,
                &poll,
                position,
                setup.roster().proposal().body(),
            )
            .unwrap();
            credential.confirm_roster(&retained).unwrap();
            credential.retire_preparation();
            credential
        };
        // A corrupt participant's own root may unlock any purpose on its
        // forks.
        close::Equivocator {
            forks: std::array::from_fn(|_| {
                let mut fork = restore();
                fork.unlock_unused_purposes(protocol_foundations::SigningPurpose::Ballot.mask())
                    .unwrap();
                fork
            }),
            restored: restore(),
        }
    });
    let restored = close::Restored {
        equivocator,
        organizer: restore_credential(),
    };
    let (barrier, late_fork) = close::run(
        &output,
        poll,
        setup,
        &mut enrollments,
        &submissions,
        restored,
        &scenario,
    );
    // Every corrupt participant withholds its target signature, so the
    // certificate needs every honest participant, including the omitted
    // voter.
    let statuses = (0..count)
        .map(|position| {
            let status = if scenario.usable().contains(&position) {
                OwnBallotInclusion::Included
            } else if Some(position) == scenario.omitted {
                OwnBallotInclusion::Omitted
            } else {
                OwnBallotInclusion::NotCast
            };
            (position, status)
        })
        .collect();
    completion::run(
        &output,
        &scratch,
        barrier,
        &mut enrollments,
        completion::Finality {
            signers: scenario.honest(),
            statuses,
            forks: late_fork
                .map(|fork| {
                    (
                        scenario.equivocator.unwrap(),
                        fork,
                        OwnBallotInclusion::Late,
                    )
                })
                .into_iter()
                .collect(),
        },
        &scenario,
    );
    println!(
        "Fresh original setup, linked proof, signed ballot and quorum close evidence verified"
    );
}
