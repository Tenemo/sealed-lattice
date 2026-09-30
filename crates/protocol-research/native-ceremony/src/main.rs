mod aggregate;
mod close;
mod completion;
mod contribution;
#[path = "no-result-close.rs"]
mod no_result_close;
#[path = "public-output.rs"]
mod public_output;
mod scenario;
use aggregate::{ballot_keys, final_keys, polynomial_bytes};
use registration_credentials::{
    RETAINED_TAG_BYTES,
    ballot_authentication::BallotEnvelope,
    contribution_authentication::{CommitmentInventory, SignedOpening, verify_confirmation},
    foundation::{
        StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
    registration::RegistrationVerifier,
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::verify_roster_proposal,
};
use registration_enrollment::{Enrollment, finality_work::OwnBallotStatus};
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
fn random<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(&mut *bytes).unwrap();
    bytes
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
        opening: Option<&SignedOpening>,
        position: usize,
        scores: &[u8],
    ) -> close::Submission {
        let profile = self.scenario.profile();
        let proposal = RetainedContributionContext::parse(
            self.poll.identity(),
            self.poll.runtime(),
            profile.options(),
            position,
            self.setup.inventory().proposal().proposal().body(),
        )
        .unwrap();
        // Only a setup contributor names its own opening.
        let opening_packet = opening.map_or_else(Vec::new, |opening| {
            [
                (opening.body().len() as u32).to_le_bytes().as_slice(),
                opening.body(),
                opening.signature(),
            ]
            .concat()
        });
        let retained_reference = registration_enrollment::ballot::retained_setup_reference(
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
            self.setup.inventory().identity().as_slice(),
            (opening_packet.len() as u32).to_le_bytes().as_slice(),
            opening_packet.as_slice(),
            retained_reference.as_slice(),
        ]
        .concat();
        let credential = &mut enrollment.credential;
        let mut work =
            registration_enrollment::ballot::BallotWork::new(credential, &proposal, &control)
                .unwrap();
        for index in ballot_keys(profile) {
            work.command(credential, 1, index, &[]).unwrap();
            stream_key(self.final_keys, profile, index, |offset, bytes| {
                work.command(credential, 2, offset, bytes).unwrap();
            });
            work.command(credential, 3, 0, &[]).unwrap();
        }
        let ballot_time = close::now_milliseconds();
        work.command(
            credential,
            4,
            0,
            &[ballot_time.to_le_bytes().as_slice(), scores].concat(),
        )
        .unwrap();
        let envelope =
            BallotEnvelope::decode(profile, &work.command(credential, 10, 0, &[]).unwrap())
                .unwrap();
        assert_eq!(envelope.ballot_time(), ballot_time);
        let path = ballot_body_path(self.directory, self.scenario, position);
        let mut body = public_output::PublicOutput::create(&path).unwrap();
        for offset in (0..envelope.body_length()).step_by(1 << 20) {
            let length = ((1 << 20).min(envelope.body_length() - offset)) as u32;
            body.write_all(
                &work
                    .command(credential, 11, offset, &length.to_le_bytes())
                    .unwrap(),
            )
            .unwrap();
        }
        body.finish().unwrap();
        let coins = random::<32>();
        let signing = [envelope.bytes().as_slice(), coins.as_slice()].concat();
        work.command(credential, 8, 0, &signing).unwrap();
        let signature: [u8; 3309] = work
            .command(credential, 12, 0, &[])
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
    offsets: [usize; 4],
}
impl<'a> EnrollmentOutput<'a> {
    fn new(directory: &Path, controls: &'a mut [Vec<u8>; 2]) -> Self {
        let files: Vec<_> = [
            "polynomial-01.bin",
            "proof.bin",
            "registration-header.bin",
            "signature.bin",
        ]
        .iter()
        .map(|name| public_output::PublicOutput::create(directory.join(name)).unwrap())
        .collect();
        Self {
            files,
            controls,
            offsets: [0; 4],
        }
    }
    fn emit(&mut self, kind: u32, offset: usize, bytes: &[u8]) {
        if kind < 4 {
            let kind = kind as usize;
            if kind >= 2 {
                self.controls[kind - 2].extend(bytes);
            }
            assert_eq!(offset, self.offsets[kind]);
            self.files[kind].write_all(bytes).unwrap();
            self.offsets[kind] += bytes.len();
        }
    }
    fn finish(self) {
        for file in self.files {
            file.finish().unwrap();
        }
    }
}
/// Arguments: the new output directory, the runtime identity file, the
/// scratch directory, the participant and option counts, and optionally
/// `empty` or `invalid-only` for a no-result case.
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(
        arguments.len() == 5
            || (arguments.len() == 6 && matches!(arguments[5].as_str(), "empty" | "invalid-only"))
    );
    let scratch = PathBuf::from(&arguments[2]);
    assert!(scratch.is_dir());
    let profile =
        Profile::new(arguments[3].parse().unwrap(), arguments[4].parse().unwrap()).unwrap();
    let scenario = Scenario::new(profile);
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
    let data_keys = random::<64>();
    let mut signing_capsule = Vec::new();
    let mut creator_output = EnrollmentOutput::new(&directories[0], &mut controls[0]);
    let (packet, creator) = Enrollment::create_creator(
        draft,
        runtime,
        b"Creator",
        data_keys[..32].try_into().unwrap(),
        data_keys[32..].try_into().unwrap(),
        |kind, offset, bytes| {
            creator_output.emit(kind, offset, bytes);
            if kind == 5 {
                assert_eq!(offset, signing_capsule.len());
                signing_capsule.extend(bytes);
            }
        },
    )
    .unwrap();
    creator_output.finish();
    let poll =
        Arc::new(verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap());
    write(output.join("poll-definition.bin"), &packet.body);
    write(output.join("poll-signature.bin"), &packet.signature);
    write(
        output.join("context.bin"),
        &[poll.identity().as_slice(), runtime.as_slice()].concat(),
    );
    let mut enrollments = vec![creator];
    // The corrupt equivocator may fork its own signing state. These
    // encrypted key bytes and wrapping key remain in this process only.
    let mut corrupt_signing_capsule = Zeroizing::new(Vec::new());
    let mut corrupt_wrapping_key = Zeroizing::new([0u8; 32]);
    for (position, directory) in directories.iter().enumerate().skip(1) {
        let keys = random::<64>();
        let equivocator = Some(position) == scenario.equivocator;
        let mut record_output = EnrollmentOutput::new(directory, &mut controls[position]);
        enrollments.push(
            Enrollment::create_for_poll(
                &poll,
                format!("Participant {position}").as_bytes(),
                keys[..32].try_into().unwrap(),
                keys[32..].try_into().unwrap(),
                |kind, offset, bytes| {
                    record_output.emit(kind, offset, bytes);
                    if equivocator && kind == 5 {
                        assert_eq!(offset, corrupt_signing_capsule.len());
                        corrupt_signing_capsule.extend(bytes);
                    }
                },
            )
            .unwrap(),
        );
        record_output.finish();
        if equivocator {
            corrupt_wrapping_key.copy_from_slice(&keys[32..]);
        }
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
        let mut verifier = RegistrationVerifier::new(&poll, &header, &signature).unwrap_or_else(|error| {
            let decoded=registration_credentials::foundation::RegistrationHeader::decode_prefix(&header);
            let decoded_status=decoded.as_ref().map(|(_,used)|*used);
            let body_status=registration_credentials::BodyHasher::from_header(&header,poll.identity(),poll.runtime()).map(|(_,used)|used);
            panic!("Registration prefix {position}: {error:?}, header={}, signature={}, decoded={decoded_status:?}, body={body_status:?}",header.len(),signature.len());
        });
        for (name, key) in [("polynomial-01.bin", true), ("proof.bin", false)] {
            let mut file = File::open(directory.join(name)).unwrap();
            loop {
                let length = file.read(&mut buffer).unwrap();
                if length == 0 {
                    break;
                }
                if key {
                    verifier.push_key(&buffer[..length]).unwrap();
                } else {
                    verifier.push_proof(&buffer[..length]).unwrap();
                }
            }
            if key {
                verifier.finish_key().unwrap();
            }
        }
        records.push(Arc::new(verifier.finish().unwrap()));
        println!("Verified fresh registration {position}");
    }
    let proposal = RosterProposal::new(&poll, records).unwrap();
    assert_eq!(proposal.profile(), profile);
    let proposal_signature = enrollments[0]
        .credential
        .sign_roster_proposal(&proposal, *random::<32>())
        .unwrap();
    write(output.join("proposal.bin"), proposal.body());
    write(output.join("proposal-signature.bin"), &proposal_signature);
    let roster = Arc::new(verify_roster_proposal(proposal, &proposal_signature).unwrap());
    println!("Verified original enrollment roster");
    // Every participant confirms the roster once. Only the setup
    // contributors commit and open; any other position's contribution is
    // refused before commitment work, and its confirmation names its own
    // registration body instead.
    let contributors = profile.setup_contributors();
    let mut confirmations = Vec::new();
    for (position, enrollment) in enrollments.iter_mut().enumerate().skip(contributors) {
        assert!(matches!(
            enrollment
                .credential
                .validate_confirmation_position(&roster, position),
            Err(registration_credentials::Error::Context)
        ));
        assert!(roster.proposal().contribution_role(position).is_err());
        let signed = enrollment
            .credential
            .sign_roster_confirmation(&roster, position, *random::<32>())
            .unwrap();
        let directory = output.join(format!("contribution-{position}"));
        fs::create_dir_all(&directory).unwrap();
        write(directory.join("confirmation.bin"), signed.body());
        write(
            directory.join("confirmation-signature.bin"),
            signed.signature(),
        );
        confirmations
            .push(verify_confirmation(&roster, signed.body(), signed.signature()).unwrap());
    }
    let mut contribution_directories = Vec::new();
    let mut body_headers = Vec::new();
    for (position, enrollment) in enrollments.iter_mut().enumerate().take(contributors) {
        let directory = output.join(format!("contribution-{position}"));
        let (commitment, header) =
            contribution::generate(&roster, position, &directory, &random::<64>());
        let signed = enrollment
            .credential
            .sign_confirmation(&roster, commitment, *random::<32>())
            .unwrap();
        write(directory.join("confirmation.bin"), signed.body());
        write(
            directory.join("confirmation-signature.bin"),
            signed.signature(),
        );
        write(directory.join("body-header.bin"), &header);
        confirmations
            .push(verify_confirmation(&roster, signed.body(), signed.signature()).unwrap());
        contribution_directories.push(directory);
        body_headers.push(header);
        println!("Generated and confirmed contribution {position}");
    }
    let inventory = Arc::new(CommitmentInventory::new(roster, confirmations).unwrap());
    write(output.join("inventory.bin"), inventory.body());
    write(output.join("inventory-identity.bin"), &inventory.identity());
    let mut openings = Vec::new();
    for (position, enrollment) in enrollments.iter_mut().enumerate().take(contributors) {
        let opening = enrollment
            .credential
            .sign_opening(&inventory, *random::<32>())
            .unwrap();
        write(
            contribution_directories[position].join("opening.bin"),
            opening.body(),
        );
        write(
            contribution_directories[position].join("opening-signature.bin"),
            opening.signature(),
        );
        openings.push(opening);
    }
    let setup = Arc::new(aggregate::verify(
        inventory.clone(),
        &contribution_directories,
        &body_headers,
        &openings,
        &output.join("aggregates"),
    ));
    if let Some(mode) = arguments.get(5) {
        let invalid_only = mode == "invalid-only";
        let barrier = no_result_close::run(
            &output,
            poll.clone(),
            setup.clone(),
            &mut enrollments,
            &openings,
            invalid_only,
            &scenario,
        );
        let statuses = (0..enrollments.len())
            .map(|position| {
                (
                    position,
                    if invalid_only && position == 0 {
                        OwnBallotStatus::Included
                    } else {
                        OwnBallotStatus::NotCast
                    },
                )
            })
            .collect();
        completion::run(
            &output,
            &scratch,
            barrier,
            &mut enrollments,
            &openings,
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
    let [fhe_key, auxiliary_key] = ballot_keys(profile);
    let retained_proposal = RetainedContributionContext::parse(
        poll.identity(),
        poll.runtime(),
        profile.options(),
        0,
        inventory.proposal().proposal().body(),
    )
    .unwrap();
    let owner = enrollments[0]
        .credential
        .retain_ballot_owner(
            &poll,
            &retained_proposal,
            inventory.identity(),
            openings[0].body(),
            openings[0].signature(),
        )
        .unwrap();
    // A retained proposal read with another option count names another
    // profile, which the original poll refuses.
    let other_options = if profile.options() < 20 {
        profile.options() + 1
    } else {
        profile.options() - 1
    };
    let other_profile = RetainedContributionContext::parse(
        poll.identity(),
        poll.runtime(),
        other_options,
        0,
        inventory.proposal().proposal().body(),
    )
    .unwrap();
    assert!(
        enrollments[0]
            .credential
            .retain_ballot_owner(
                &poll,
                &other_profile,
                inventory.identity(),
                openings[0].body(),
                openings[0].signature()
            )
            .is_err()
    );
    assert!(
        enrollments[1]
            .credential
            .retain_ballot_owner(
                &poll,
                &retained_proposal,
                inventory.identity(),
                openings[0].body(),
                openings[0].signature()
            )
            .is_err()
    );
    let mut changed_signature = *openings[0].signature();
    changed_signature[0] ^= 1;
    assert!(
        enrollments[0]
            .credential
            .retain_ballot_owner(
                &poll,
                &retained_proposal,
                inventory.identity(),
                openings[0].body(),
                &changed_signature
            )
            .is_err()
    );
    assert!(
        enrollments[0]
            .credential
            .retain_ballot_owner(
                &poll,
                &retained_proposal,
                [0; 64],
                openings[0].body(),
                openings[0].signature()
            )
            .is_err()
    );
    assert!(
        enrollments[0]
            .credential
            .retain_ballot_owner(
                &poll,
                &retained_proposal,
                inventory.identity(),
                openings[1].body(),
                openings[1].signature()
            )
            .is_err()
    );
    let retained_reference = registration_enrollment::ballot::retained_setup_reference(
        &enrollments[0].credential,
        &poll,
        &setup,
    )
    .unwrap();
    let retained_record = &retained_reference[..retained_reference.len() - RETAINED_TAG_BYTES];
    // The setup verifier's result comes back for the same inventory from the
    // reference the participant's credential keyed, as a later visit restores
    // it instead of verifying every opening again.
    let restore = |credential: &registration_credentials::Credential, retained: &[u8]| {
        setup_aggregate::verified::SetupAggregator::new(setup.inventory().clone())
            .unwrap()
            .restore(credential, &poll, retained)
    };
    let restored = restore(&enrollments[0].credential, &retained_reference).unwrap();
    assert_eq!(
        restored.inventory().identity(),
        setup.inventory().identity()
    );
    assert_eq!(restored.polynomials().len(), setup.polynomials().len());
    for (left, right) in restored.polynomials().iter().zip(setup.polynomials()) {
        assert_eq!(
            (left.index(), left.bytes(), left.digest()),
            (right.index(), right.bytes(), right.digest())
        );
    }
    let inputs =
        setup_aggregate::RetainedSetupInputs::parse(profile, retained_record, inventory.identity())
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
    let opening_packet = [
        (openings[0].body().len() as u32).to_le_bytes().as_slice(),
        openings[0].body(),
        openings[0].signature(),
    ]
    .concat();
    let control_with_reference = |reference: &[u8]| {
        [
            poll.identity().as_slice(),
            poll.runtime().as_slice(),
            (packet.body.len() as u32).to_le_bytes().as_slice(),
            packet.body.as_slice(),
            packet.signature.as_slice(),
            inventory.identity().as_slice(),
            (opening_packet.len() as u32).to_le_bytes().as_slice(),
            opening_packet.as_slice(),
            reference,
        ]
        .concat()
    };
    // A reference keyed to another credential, a changed digest under the
    // original tag, and an untagged record are all refused before any work.
    let foreign_reference = registration_enrollment::ballot::retained_setup_reference(
        &enrollments[1].credential,
        &poll,
        &setup,
    )
    .unwrap();
    let mut changed_digest = retained_reference.clone();
    changed_digest[4 + 64] ^= 1;
    for reference in [&foreign_reference[..], &changed_digest, retained_record] {
        assert!(
            registration_enrollment::ballot::BallotWork::new(
                &enrollments[0].credential,
                &retained_proposal,
                &control_with_reference(reference),
            )
            .is_err()
        );
        assert!(restore(&enrollments[0].credential, reference).is_err());
    }
    // Another participant's credential restores nothing from this one's
    // reference.
    assert!(restore(&enrollments[1].credential, &retained_reference).is_err());
    // The last position contributes nothing. Its owner comes only from the
    // setup reference its own credential keyed, never from an opening, and a
    // contributor's never from its reference alone.
    let outsider = count - 1;
    let outsider_proposal = RetainedContributionContext::parse(
        poll.identity(),
        poll.runtime(),
        profile.options(),
        outsider,
        inventory.proposal().proposal().body(),
    )
    .unwrap();
    let outsider_reference = registration_enrollment::ballot::retained_setup_reference(
        &enrollments[outsider].credential,
        &poll,
        &setup,
    )
    .unwrap();
    let (outsider_record, outsider_tag) =
        outsider_reference.split_at(outsider_reference.len() - RETAINED_TAG_BYTES);
    let outsider_owner = enrollments[outsider]
        .credential
        .retain_setup_ballot_owner(
            &poll,
            &outsider_proposal,
            inventory.identity(),
            outsider_record,
            outsider_tag,
        )
        .unwrap();
    assert_eq!(outsider_owner.position(), outsider);
    assert_eq!(outsider_owner.inventory(), &inventory.identity());
    let organizer_tag = &retained_reference[retained_record.len()..];
    for (record, tag, inventory) in [
        (retained_record, organizer_tag, inventory.identity()),
        (outsider_record, outsider_tag, [0; 64]),
    ] {
        assert!(
            enrollments[outsider]
                .credential
                .retain_setup_ballot_owner(&poll, &outsider_proposal, inventory, record, tag)
                .is_err()
        );
    }
    assert!(
        enrollments[outsider]
            .credential
            .retain_ballot_owner(
                &poll,
                &outsider_proposal,
                inventory.identity(),
                openings[0].body(),
                openings[0].signature()
            )
            .is_err()
    );
    assert!(
        enrollments[0]
            .credential
            .retain_setup_ballot_owner(
                &poll,
                &retained_proposal,
                inventory.identity(),
                retained_record,
                organizer_tag
            )
            .is_err()
    );
    // A ballot names an opening exactly when its author contributed.
    let control_of = |opening: &[u8], reference: &[u8]| {
        [
            poll.identity().as_slice(),
            poll.runtime().as_slice(),
            (packet.body.len() as u32).to_le_bytes().as_slice(),
            packet.body.as_slice(),
            packet.signature.as_slice(),
            inventory.identity().as_slice(),
            (opening.len() as u32).to_le_bytes().as_slice(),
            opening,
            reference,
        ]
        .concat()
    };
    for (position, context, control) in [
        (
            outsider,
            &outsider_proposal,
            control_of(&opening_packet, &outsider_reference),
        ),
        (0, &retained_proposal, control_of(&[], &retained_reference)),
    ] {
        assert!(
            registration_enrollment::ballot::BallotWork::new(
                &enrollments[position].credential,
                context,
                &control,
            )
            .is_err()
        );
    }
    assert_eq!(
        registration_enrollment::ballot::BallotWork::new(
            &enrollments[outsider].credential,
            &outsider_proposal,
            &control_of(&[], &outsider_reference),
        )
        .unwrap()
        .into_owner()
        .position(),
        outsider
    );
    let ballot_control = control_with_reference(&retained_reference);
    let mut work = registration_enrollment::ballot::BallotWork::new(
        &enrollments[0].credential,
        &retained_proposal,
        &ballot_control,
    )
    .unwrap();
    assert!(
        work.command(&mut enrollments[0].credential, 10, 0, &[])
            .is_err()
    );
    // Keys are delivered only in the statement's order.
    assert!(
        registration_enrollment::ballot::BallotWork::new(
            &enrollments[0].credential,
            &retained_proposal,
            &ballot_control,
        )
        .unwrap()
        .command(&mut enrollments[0].credential, 1, auxiliary_key, &[])
        .is_err()
    );
    for index in [fhe_key, auxiliary_key] {
        let mut reader = inputs.read_polynomial(index).unwrap();
        stream_key(&final_keys, profile, index, |offset, bytes| {
            reader.push(offset, bytes).unwrap();
        });
        let key = reader.finish().unwrap();
        assert_eq!(
            key.coefficients(),
            aggregate::read_key(&setup, index, &final_keys).coefficients()
        );
        work.command(&mut enrollments[0].credential, 1, index, &[])
            .unwrap();
        stream_key(&final_keys, profile, index, |offset, bytes| {
            work.command(&mut enrollments[0].credential, 2, offset, bytes)
                .unwrap();
        });
        work.command(&mut enrollments[0].credential, 3, 0, &[])
            .unwrap();
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
            work.command(&mut enrollments[0].credential, 4, 0, &input),
            Err(registration_credentials::Error::Shape)
        ));
    }
    work.command(&mut enrollments[0].credential, 4, 0, &timed(&valid))
        .unwrap();
    let encoded = work
        .command(&mut enrollments[0].credential, 10, 0, &[])
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
                        11,
                        offset,
                        &length.to_le_bytes(),
                    )
                    .unwrap(),
            )
            .unwrap();
    }
    body_file.finish().unwrap();
    let mut body_input = File::open(&body_path).unwrap();
    let mut header = vec![0; registration_credentials::ballot_body::HEADER_BYTES];
    body_input.read_exact(&mut header).unwrap();
    std::io::copy(
        &mut std::io::Read::by_ref(&mut body_input)
            .take(registration_credentials::ballot_body::ciphertext_bytes(profile) as u64),
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
        inventory.identity(),
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
            .sign_retained_ballot_envelope(&owner, &envelope, *random::<32>())
            .is_err()
    );
    let coins = random::<32>();
    let signing = [envelope.bytes().as_slice(), coins.as_slice()].concat();
    assert!(
        work.command(&mut enrollments[1].credential, 8, 0, &signing)
            .is_err()
    );
    work.command(&mut enrollments[0].credential, 8, 0, &signing)
        .unwrap();
    let signature: [u8; 3309] = work
        .command(&mut enrollments[0].credential, 12, 0, &[])
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        work.command(&mut enrollments[0].credential, 8, 0, &signing)
            .is_err()
    );
    let original = inventory.proposal().proposal().records()[0].as_ref();
    let restore_credential = || {
        registration_credentials::Credential::open_complete(
            original.header().signing_public,
            original.header().mailbox_public,
            original.body_digest(),
            data_keys[32..].try_into().unwrap(),
            &signing_capsule,
        )
        .unwrap()
    };
    let mut restored = restore_credential();
    for changed_body in [false, true] {
        let mut restored_credential = restore_credential();
        let mut restored_work = registration_enrollment::ballot::BallotWork::new(
            &restored_credential,
            &retained_proposal,
            &ballot_control,
        )
        .unwrap();
        for index in [fhe_key, auxiliary_key] {
            restored_work
                .command(&mut restored_credential, 1, index, &[])
                .unwrap();
            stream_key(&final_keys, profile, index, |offset, bytes| {
                restored_work
                    .command(&mut restored_credential, 2, offset, bytes)
                    .unwrap();
            });
            restored_work
                .command(&mut restored_credential, 3, 0, &[])
                .unwrap();
        }
        restored_work
            .command(&mut restored_credential, 5, 0, envelope.bytes())
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
                .command(&mut restored_credential, 6, offset, &buffer[..length])
                .unwrap();
            offset += length;
        }
        let verified = restored_work.command(&mut restored_credential, 7, 0, &[]);
        if changed_body {
            assert!(verified.is_err());
            assert!(
                restored_work
                    .command(&mut restored_credential, 8, 0, &signing)
                    .is_err()
            );
        } else {
            verified.unwrap();
            let packet = [envelope.bytes().as_slice(), signature.as_slice()].concat();
            restored_work
                .command(&mut restored_credential, 9, 0, &packet)
                .unwrap();
            assert_eq!(
                restored_work
                    .command(&mut restored_credential, 12, 0, &[])
                    .unwrap(),
                signature
            );
            assert!(
                restored_work
                    .command(&mut restored_credential, 8, 0, &signing)
                    .is_err()
            );
        }
    }
    let restored_owner = restored
        .retain_ballot_owner(
            &poll,
            &retained_proposal,
            inventory.identity(),
            openings[0].body(),
            openings[0].signature(),
        )
        .unwrap();
    let mut changed_envelope = *envelope.bytes();
    changed_envelope[150] ^= 1;
    let changed_envelope = BallotEnvelope::decode(profile, &changed_envelope).unwrap();
    // The restored credential signs nothing new until its authenticated root
    // unlocks a purpose that the root's records show unused.
    assert!(matches!(
        restored.sign_retained_ballot_envelope(&restored_owner, &changed_envelope, *random::<32>()),
        Err(registration_credentials::Error::Consumed)
    ));
    // Restoring the completed ballot consumes the purpose even after an unlock.
    restored
        .unlock_unused_purposes(registration_credentials::SigningPurpose::Ballot.mask())
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
            .sign_retained_ballot_envelope(&restored_owner, &envelope, *random::<32>())
            .is_err()
    );
    assert!(
        restored
            .sign_retained_ballot_envelope(&restored_owner, &changed_envelope, *random::<32>())
            .is_err()
    );
    assert!(
        ballot_proof::submission::sign_body(
            &mut enrollments[0].credential,
            &body,
            &setup,
            ballot_time,
            *random::<32>()
        )
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
    assert!(
        ballot_proof::submission::sign_body(
            &mut enrollments[1].credential,
            &body,
            &setup,
            ballot_time,
            *random::<32>()
        )
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
            setup.inventory().identity(),
            author,
            close::now_milliseconds(),
            body.length(),
            *body.identity(),
        )
        .unwrap();
        let wrong_position_signature = enrollments[author]
            .credential
            .sign_ballot_envelope(
                setup.inventory().proposal(),
                &wrong_position,
                *random::<32>(),
            )
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
        let mut modified_header = [0; registration_credentials::ballot_body::HEADER_BYTES];
        source.read_exact(&mut modified_header).unwrap();
        // The statement position follows the body header's magic, proof
        // length, statement magic, poll and inventory.
        let position = 12 + 4 + 64 + 64;
        modified_header[position..position + 2].copy_from_slice(&(author as u16).to_le_bytes());
        let mut destination = public_output::PublicOutput::create(&invalid_proof_path).unwrap();
        let mut hash = registration_credentials::ballot_body::BallotBodyHasher::for_body_length(
            profile,
            envelope.body_length(),
        )
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
            setup.inventory().identity(),
            author,
            close::now_milliseconds(),
            envelope.body_length(),
            hash.finish().unwrap(),
        )
        .unwrap();
        let invalid_proof_signature = enrollments[author]
            .credential
            .sign_ballot_envelope(
                setup.inventory().proposal(),
                &invalid_proof_envelope,
                *random::<32>(),
            )
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
        "unfinished-keys",
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
            openings.get(position),
            position,
            &scenario.scores(position),
        ));
        println!("Cast and accepted honest ballot {position}");
    }
    let equivocator = scenario.equivocator.map(|position| {
        let record = &setup.inventory().proposal().proposal().records()[position];
        let restore = || {
            registration_credentials::Credential::open_complete(
                record.header().signing_public,
                record.header().mailbox_public,
                record.body_digest(),
                &corrupt_wrapping_key,
                &corrupt_signing_capsule,
            )
            .unwrap()
        };
        // A corrupt participant's own root may unlock any purpose on its
        // forks.
        close::Equivocator {
            forks: std::array::from_fn(|_| {
                let mut fork = restore();
                fork.unlock_unused_purposes(
                    registration_credentials::SigningPurpose::Ballot.mask(),
                )
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
        close::Participants {
            enrollments: &mut enrollments,
            openings: &openings,
        },
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
                OwnBallotStatus::Included
            } else if Some(position) == scenario.omitted {
                OwnBallotStatus::Omitted
            } else {
                OwnBallotStatus::NotCast
            };
            (position, status)
        })
        .collect();
    completion::run(
        &output,
        &scratch,
        barrier,
        &mut enrollments,
        &openings,
        completion::Finality {
            signers: scenario.honest(),
            statuses,
            forks: late_fork
                .map(|fork| (scenario.equivocator.unwrap(), fork, OwnBallotStatus::Late))
                .into_iter()
                .collect(),
        },
        &scenario,
    );
    println!(
        "Fresh original setup, linked proof, signed ballot and quorum close evidence verified"
    );
}
