//! The original enrollment: the organizer's poll and every participant's
//! registration, each verified as a roster reads it and restored from its
//! capsules.
use crate::{public_output, scenario::Scenario, write};
use participant_module::{Enrollment, data_kind};
use protocol_foundations::{
    Credential,
    foundation::{
        StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
    registration::{RegistrationVerifier, VerifiedRegistration},
    roster::{RetainedContributionContext, RosterProposal},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    sync::Arc,
};
use zeroize::Zeroizing;

struct EnrollmentOutput<'a> {
    files: Vec<public_output::PublicOutput>,
    controls: &'a mut [Vec<u8>; 2],
    offsets: [usize; 4],
}
impl<'a> EnrollmentOutput<'a> {
    fn new(directory: &Path, controls: &'a mut [Vec<u8>; 2]) -> Self {
        let files: Vec<_> = [
            "polynomial-01.bin",
            "registration-header.bin",
            "signature.bin",
            "source-ciphertexts.bin",
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
        let file = match kind {
            data_kind::PUBLIC_KEY => 0,
            data_kind::HEADER => 1,
            data_kind::SIGNATURE => 2,
            data_kind::SOURCE_CIPHERTEXTS => 3,
            _ => return,
        };
        if (1..=2).contains(&file) {
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

/// A credential capsule this process keeps beside its wrapping key, so that
/// a later step can reopen the credential as a restored or forked signer.
pub(crate) struct RetainedSigner {
    key: Zeroizing<[u8; 32]>,
    capsule: Zeroizing<Vec<u8>>,
}
impl RetainedSigner {
    /// The credential of the roster's record at the position, reopened and
    /// confirmed on that roster.
    pub(crate) fn open(
        &self,
        poll: &VerifiedPoll,
        roster: &RosterProposal,
        position: usize,
    ) -> Credential {
        let record = &roster.records()[position];
        let mut credential = Credential::open_complete(
            record.header().signing_public,
            record.body_digest(),
            &self.key,
            &self.capsule,
        )
        .unwrap();
        let retained =
            RetainedContributionContext::parse(&credential, record, poll, position, roster.body())
                .unwrap();
        credential.confirm_roster(&retained).unwrap();
        credential
    }
    /// The credential as a restored participant holds it, with its
    /// preparation retired.
    pub(crate) fn restored(
        &self,
        poll: &VerifiedPoll,
        roster: &RosterProposal,
        position: usize,
    ) -> Credential {
        let mut credential = self.open(poll, roster, position);
        credential.retire_preparation();
        credential
    }
}

pub(crate) struct Enrolled {
    pub(crate) packet: SignedPoll,
    pub(crate) poll: Arc<VerifiedPoll>,
    pub(crate) enrollments: Vec<Enrollment>,
    pub(crate) records: Vec<Arc<VerifiedRegistration>>,
    pub(crate) organizer: RetainedSigner,
    // The corrupt signer that may fork its own signing state.
    pub(crate) corrupt: Option<RetainedSigner>,
}

/// Enrolls every participant of the scenario's profile under the runtime.
pub(crate) fn run(output: &Path, runtime: [u8; 64], scenario: &Scenario) -> Enrolled {
    let profile = scenario.profile();
    let count = profile.participants();
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
    let mut signing_capsule = Zeroizing::new(Vec::new());
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
    let organizer_signing_key = Zeroizing::new(organizer_keys[32..64].try_into().unwrap());
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
    let mut corrupt_retained = false;
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
            corrupt_retained = true;
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
        let mut sources = File::open(directory.join("source-ciphertexts.bin")).unwrap();
        loop {
            let length = sources.read(&mut buffer).unwrap();
            if length == 0 {
                break;
            }
            verifier.push_sources(&buffer[..length]).unwrap();
        }
        let record = Arc::new(verifier.finish().unwrap());
        let capsules = &enrollment_capsules[position];
        let restore = |source_capsule: &[u8]| {
            Enrollment::restore(
                &poll,
                &record,
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
                .contribution_coordinate_hash(&poll, profile)
                .unwrap(),
            enrollments[position]
                .contribution_coordinate_hash(&poll, profile)
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
    Enrolled {
        packet,
        poll,
        enrollments,
        records,
        organizer: RetainedSigner {
            key: organizer_signing_key,
            capsule: signing_capsule,
        },
        corrupt: corrupt_retained.then(|| RetainedSigner {
            key: corrupt_wrapping_key,
            capsule: corrupt_signing_capsule,
        }),
    }
}
