mod aggregate;
mod completion;
mod contribution;
#[path = "no-result-publication.rs"]
mod no_result_publication;
#[path = "public-output.rs"]
mod public_output;
mod publication;
use registration_credentials::{
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
use registration_enrollment::Enrollment;
use setup_aggregate::verified::VerifiedSetupAggregate;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

/// Honest ballots in the result case, enough for the minimum turnout of five
/// with ten participants. Positions one to three form the fixed corrupt set;
/// one and two submit authenticated invalid ballots.
const HONEST_BALLOTS: [(usize, [u8; 10]); 5] = [
    (0, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    (4, [3, 9, 9, 1, 7, 2, 10, 5, 4, 6]),
    (5, [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
    (6, [5, 5, 5, 5, 5, 5, 10, 5, 5, 5]),
    (7, [2, 8, 8, 1, 9, 3, 10, 4, 6, 7]),
];

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
/// The public body file of each ballot source. The wrong-position source of
/// position one reuses position zero's body.
fn ballot_body_path(directory: &Path, author: usize) -> PathBuf {
    directory.join(match author {
        0 | 1 => "body.bin".to_owned(),
        2 => "invalid-proof-body.bin".to_owned(),
        _ => format!("body-{author}.bin"),
    })
}
/// Public inputs shared by every honest participant's private ballot commands.
struct BallotInputs<'a> {
    poll: &'a Arc<VerifiedPoll>,
    setup: &'a Arc<VerifiedSetupAggregate>,
    definition: &'a SignedPoll,
    retained_record: &'a [u8],
    final_keys: &'a Path,
    directory: &'a Path,
}
impl BallotInputs<'_> {
    /// Casts one honest ballot through the enrollment-owned private commands,
    /// then accepts it through the public classification path.
    fn cast(
        &self,
        enrollment: &mut Enrollment,
        opening: &SignedOpening,
        position: usize,
        scores: &[u8],
    ) -> (BallotEnvelope, [u8; 3309], PathBuf) {
        let proposal = RetainedContributionContext::parse(
            self.poll.identity(),
            self.poll.runtime(),
            position,
            self.setup.inventory().proposal().proposal().body(),
        )
        .unwrap();
        let opening_packet = [
            (opening.body().len() as u32).to_le_bytes().as_slice(),
            opening.body(),
            opening.signature(),
        ]
        .concat();
        let control = [
            self.poll.identity().as_slice(),
            self.poll.runtime().as_slice(),
            (self.definition.body.len() as u32).to_le_bytes().as_slice(),
            self.definition.body.as_slice(),
            self.definition.signature.as_slice(),
            self.setup.inventory().identity().as_slice(),
            (opening_packet.len() as u32).to_le_bytes().as_slice(),
            opening_packet.as_slice(),
            self.retained_record,
        ]
        .concat();
        let credential = &mut enrollment.credential;
        let mut work =
            registration_enrollment::ballot::BallotWork::new(credential, &proposal, &control)
                .unwrap();
        for index in [1, 74] {
            let kind = setup_aggregate::ModulusKind::for_contribution_polynomial(index).unwrap();
            let chunk =
                setup_aggregate::CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let values =
                fs::read(self.final_keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
            work.command(credential, 1, index, &[]).unwrap();
            for (ordinal, bytes) in values.chunks(chunk).enumerate() {
                work.command(credential, 2, ordinal * chunk, bytes).unwrap();
            }
            work.command(credential, 3, 0, &[]).unwrap();
        }
        work.command(credential, 4, 0, scores).unwrap();
        let envelope =
            BallotEnvelope::decode(&work.command(credential, 10, 0, &[]).unwrap()).unwrap();
        let path = ballot_body_path(self.directory, position);
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
        (envelope, signature, path)
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
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(
        arguments.len() == 3
            || (arguments.len() == 4 && matches!(arguments[3].as_str(), "empty" | "invalid-only"))
    );
    let scratch = PathBuf::from(&arguments[2]);
    assert!(scratch.is_dir());
    let output = PathBuf::from(&arguments[0]);
    fs::create_dir(&output).unwrap();
    let runtime_bytes = fs::read(&arguments[1]).unwrap();
    let runtime: [u8; 64] = runtime_bytes.try_into().unwrap();
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let manifest = Manifest::new(
        text("Verify the complete signed ballot path"),
        (0..10)
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
    let draft = PollDraft::new(manifest, 10).unwrap();
    let directories = (0..10)
        .map(|index| {
            let directory = output.join(format!("participant-{index}"));
            fs::create_dir(&directory).unwrap();
            directory
        })
        .collect::<Vec<_>>();
    let mut controls: Vec<[Vec<u8>; 2]> = (0..10).map(|_| [Vec::new(), Vec::new()]).collect();
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
    // An explicitly corrupt fixture participant may fork its own signing state.
    // These encrypted key bytes and wrapping key remain in this process only.
    let mut corrupt_signing_capsule = Zeroizing::new(Vec::new());
    let mut corrupt_wrapping_key = Zeroizing::new([0u8; 32]);
    for (position, directory) in directories.iter().enumerate().skip(1) {
        let keys = random::<64>();
        let mut record_output = EnrollmentOutput::new(directory, &mut controls[position]);
        enrollments.push(
            Enrollment::create_for_poll(
                &poll,
                format!("Participant {position}").as_bytes(),
                keys[..32].try_into().unwrap(),
                keys[32..].try_into().unwrap(),
                |kind, offset, bytes| {
                    record_output.emit(kind, offset, bytes);
                    if position == 3 && kind == 5 {
                        assert_eq!(offset, corrupt_signing_capsule.len());
                        corrupt_signing_capsule.extend(bytes);
                    }
                },
            )
            .unwrap(),
        );
        record_output.finish();
        if position == 3 {
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
    let proposal_signature = enrollments[0]
        .credential
        .sign_roster_proposal(&proposal, *random::<32>())
        .unwrap();
    write(output.join("proposal.bin"), proposal.body());
    write(output.join("proposal-signature.bin"), &proposal_signature);
    let roster = Arc::new(verify_roster_proposal(proposal, &proposal_signature).unwrap());
    println!("Verified original enrollment roster");
    let mut confirmations = Vec::new();
    let mut contribution_directories = Vec::new();
    let mut body_headers = Vec::new();
    for (position, enrollment) in enrollments.iter_mut().enumerate() {
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
    for (position, enrollment) in enrollments.iter_mut().enumerate() {
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
    if let Some(mode) = arguments.get(3) {
        let closed = no_result_publication::run(
            &output,
            poll.clone(),
            setup.clone(),
            &mut enrollments,
            &openings,
            mode == "invalid-only",
        );
        completion::run(
            &output,
            &scratch,
            poll,
            setup,
            closed,
            &mut enrollments,
            &openings,
        );
        return;
    }
    let final_keys = output.join("aggregates/after-participant-9");
    let retained_proposal = registration_credentials::roster::RetainedContributionContext::parse(
        poll.identity(),
        poll.runtime(),
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
    let mut retained_record = Vec::from(b"SAV1".as_slice());
    retained_record.extend(inventory.identity());
    for polynomial in setup.polynomials() {
        retained_record.extend(polynomial.digest());
    }
    let inputs =
        setup_aggregate::RetainedSetupInputs::parse(&retained_record, inventory.identity())
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
    let ballot_control = [
        poll.identity().as_slice(),
        poll.runtime().as_slice(),
        (packet.body.len() as u32).to_le_bytes().as_slice(),
        packet.body.as_slice(),
        packet.signature.as_slice(),
        inventory.identity().as_slice(),
        (opening_packet.len() as u32).to_le_bytes().as_slice(),
        opening_packet.as_slice(),
        retained_record.as_slice(),
    ]
    .concat();
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
    for index in [1, 74] {
        let mut reader = inputs.read_polynomial(index).unwrap();
        let values = fs::read(final_keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
        let kind = setup_aggregate::ModulusKind::for_contribution_polynomial(index).unwrap();
        let chunk =
            setup_aggregate::CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
        for (ordinal, bytes) in values.chunks(chunk).enumerate() {
            reader.push(ordinal * chunk, bytes).unwrap();
        }
        let key = reader.finish().unwrap();
        assert_eq!(
            key.coefficients(),
            aggregate::read_key(&setup, index, &final_keys).coefficients()
        );
        work.command(&mut enrollments[0].credential, 1, index, &[])
            .unwrap();
        for (ordinal, bytes) in values.chunks(chunk).enumerate() {
            work.command(&mut enrollments[0].credential, 2, ordinal * chunk, bytes)
                .unwrap();
        }
        work.command(&mut enrollments[0].credential, 3, 0, &[])
            .unwrap();
    }
    work.command(&mut enrollments[0].credential, 4, 0, &HONEST_BALLOTS[0].1)
        .unwrap();
    let encoded = work
        .command(&mut enrollments[0].credential, 10, 0, &[])
        .unwrap();
    let computed_envelope =
        registration_credentials::ballot_authentication::BallotEnvelope::decode(&encoded).unwrap();
    let ballot_directory = output.join("ballot");
    fs::create_dir(&ballot_directory).unwrap();
    let body_path = ballot_body_path(&ballot_directory, 0);
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
            .take(registration_credentials::ballot_body::CIPHERTEXT_BYTES as u64),
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
    let envelope = registration_credentials::ballot_authentication::BallotEnvelope::new(
        poll.identity(),
        inventory.identity(),
        0,
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
        for index in [1, 74] {
            restored_work
                .command(&mut restored_credential, 1, index, &[])
                .unwrap();
            let kind = setup_aggregate::ModulusKind::for_contribution_polynomial(index).unwrap();
            let chunk =
                setup_aggregate::CHUNK_BYTES / kind.coefficient_bytes() * kind.coefficient_bytes();
            let bytes = fs::read(final_keys.join(format!("polynomial-{index:02}.bin"))).unwrap();
            for (ordinal, bytes) in bytes.chunks(chunk).enumerate() {
                restored_work
                    .command(&mut restored_credential, 2, ordinal * chunk, bytes)
                    .unwrap();
            }
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
    changed_envelope[142] ^= 1;
    let changed_envelope =
        registration_credentials::ballot_authentication::BallotEnvelope::decode(&changed_envelope)
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
            *random::<32>()
        )
        .is_err()
    );
    let wrong_position = registration_credentials::ballot_authentication::BallotEnvelope::new(
        *body.relation().poll(),
        setup.inventory().identity(),
        1,
        body.length(),
        *body.identity(),
    )
    .unwrap();
    let wrong_position_signature = enrollments[1]
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
    let invalid_proof_path = ballot_body_path(&ballot_directory, 2);
    let mut source = File::open(&body_path).unwrap();
    let mut modified_header = [0; registration_credentials::ballot_body::HEADER_BYTES];
    source.read_exact(&mut modified_header).unwrap();
    modified_header[144..146].copy_from_slice(&2u16.to_le_bytes());
    let mut destination = public_output::PublicOutput::create(&invalid_proof_path).unwrap();
    let mut hash = registration_credentials::ballot_body::BallotBodyHasher::for_body_length(
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
    let invalid_proof_envelope =
        registration_credentials::ballot_authentication::BallotEnvelope::new(
            poll.identity(),
            setup.inventory().identity(),
            2,
            envelope.body_length(),
            hash.finish().unwrap(),
        )
        .unwrap();
    let invalid_proof_signature = enrollments[2]
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
    use ballot_proof::body::BallotBodyClassification;
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
    for (packet, signature, path, position) in [
        (&wrong_position, &wrong_position_signature, &body_path, 1),
        (
            &invalid_proof_envelope,
            &invalid_proof_signature,
            &invalid_proof_path,
            2,
        ),
    ] {
        match aggregate::classify_ballot(
            poll.clone(),
            setup.clone(),
            packet.bytes(),
            signature,
            path,
            &final_keys,
            "valid",
        )
        .unwrap()
        {
            BallotBodyClassification::Invalid(value) => {
                assert_eq!(value.envelope().position(), position)
            }
            BallotBodyClassification::Valid(_) => panic!("An authenticated invalid body verified"),
        }
    }
    println!("Authenticated invalid bodies and corrupted delivery distinguished");
    println!(
        "Original retained owner and private setup inputs verified without a public capability shortcut"
    );
    let ballot_inputs = BallotInputs {
        poll: &poll,
        setup: &setup,
        definition: &packet,
        retained_record: &retained_record,
        final_keys: &final_keys,
        directory: &ballot_directory,
    };
    let additional: Vec<_> = HONEST_BALLOTS[1..]
        .iter()
        .map(|(position, scores)| {
            let ballot = ballot_inputs.cast(
                &mut enrollments[*position],
                &openings[*position],
                *position,
                scores,
            );
            println!("Cast and accepted honest ballot {position}");
            (*position, ballot)
        })
        .collect();
    let corrupt_record = &setup.inventory().proposal().proposal().records()[3];
    let restore_corrupt = || {
        registration_credentials::Credential::open_complete(
            corrupt_record.header().signing_public,
            corrupt_record.header().mailbox_public,
            corrupt_record.body_digest(),
            &corrupt_wrapping_key,
            &corrupt_signing_capsule,
        )
        .unwrap()
    };
    let corrupt_credentials = [restore_corrupt(), restore_corrupt()];
    let mut ballots = vec![None; enrollments.len()];
    ballots[0] = Some((&envelope, &signature, body_path.as_path()));
    ballots[1] = Some((
        &wrong_position,
        &wrong_position_signature,
        body_path.as_path(),
    ));
    ballots[2] = Some((
        &invalid_proof_envelope,
        &invalid_proof_signature,
        invalid_proof_path.as_path(),
    ));
    for (position, (envelope, signature, path)) in &additional {
        ballots[*position] = Some((envelope, signature, path.as_path()));
    }
    let closed = publication::run(
        &output,
        poll.clone(),
        setup.clone(),
        &mut enrollments,
        &openings,
        corrupt_credentials,
        &ballots,
    );
    completion::run(
        &output,
        &scratch,
        poll,
        setup,
        closed,
        &mut enrollments,
        &openings,
    );
    println!(
        "Fresh original setup, linked proof, signed ballot and slot publication evidence verified"
    );
}
