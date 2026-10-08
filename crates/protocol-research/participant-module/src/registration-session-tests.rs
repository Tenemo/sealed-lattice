//! Registration sessions against the registration verifier on a real
//! registration: the same verified record however the bytes are divided or
//! interleaved, and the verifier's own refusal of changed bytes.
use crate::registration_fixture::{Record, registration};
use contribution_prover::contribution_session::ContributionSession;
use parallel_work::sealing;
use protocol_foundations::{
    Credential, Error,
    foundation::{
        CanonicalItem, CanonicalTuple, participant_identity::derive_participant_identity,
    },
    poll::VerifiedPoll,
    registration::{RegistrationVerifier, VerifiedRegistration, session::RegistrationSession},
    roster::RetainedContributionContext,
};
use supported_profile::Profile;

const CHUNK: usize = 1 << 20;

fn direct(poll: &VerifiedPoll, record: &Record) -> Result<VerifiedRegistration, Error> {
    let mut verifier = RegistrationVerifier::new(poll, &record.header, &record.signature)?;
    for part in record.key.chunks(CHUNK) {
        verifier.push_key(part)?;
    }
    verifier.finish_key()?;
    verifier.finish()
}

// A session of the record, streamed in parts of the division.
fn streamed(
    poll: &VerifiedPoll,
    record: &Record,
    division: usize,
) -> Result<VerifiedRegistration, Error> {
    let mut session = RegistrationSession::open(poll, 0, &record.header, &record.signature)?;
    for part in record.key.chunks(division) {
        session.push_key(part)?;
    }
    session.finish_key()?;
    session.finish()?.wait()
}

fn same(left: &VerifiedRegistration, right: &VerifiedRegistration) -> bool {
    left.body_digest() == right.body_digest()
        && left.public_key() == right.public_key()
        && left.header().encode().unwrap() == right.header().encode().unwrap()
}

#[test]
fn sessions_verify_and_refuse_a_registration_as_its_verifier_does() {
    let (_, poll, record, enrollment) = registration();
    let expected = direct(&poll, &record).unwrap();
    checkpoint_import_preserves_the_verified_original_owner(
        &poll,
        &expected,
        &enrollment.credential,
    );
    for division in [CHUNK, 65_543, 4_099] {
        assert!(same(
            &streamed(&poll, &record, division).unwrap(),
            &expected
        ));
    }
    // Two sessions whose steps interleave keep their own states.
    let mut sessions = [0, 1].map(|shard| {
        RegistrationSession::open(&poll, shard, &record.header, &record.signature).unwrap()
    });
    for part in record.key.chunks(CHUNK) {
        for session in &mut sessions {
            session.push_key(part).unwrap();
        }
    }
    for session in &mut sessions {
        session.finish_key().unwrap();
    }
    for session in sessions {
        assert!(same(&session.finish().unwrap().wait().unwrap(), &expected));
    }
    // A changed header, key or signature and a short key are
    // refused with the verifier's refusal.
    let changed = |change: fn(&mut Record)| {
        let mut record = record.clone();
        change(&mut record);
        record
    };
    for record in [
        changed(|record| {
            record.header.push(0);
        }),
        changed(|record| {
            record.key.pop();
        }),
        changed(|record| record.key[5] ^= 1),
        changed(|record| record.signature[0] ^= 1),
    ] {
        let refusal = |result: Result<VerifiedRegistration, Error>| {
            format!("{:?}", result.err().expect("A refusal"))
        };
        assert_eq!(
            refusal(streamed(&poll, &record, 65_543)),
            refusal(direct(&poll, &record))
        );
    }
}

// This reuses the test's one genuinely generated and verified registration.
// The other proposal entries and the partial checkpoint are framing fixtures:
// they establish neither a publicly verified roster nor a resumed proof.
fn checkpoint_import_preserves_the_verified_original_owner(
    poll: &VerifiedPoll,
    original: &VerifiedRegistration,
    credential: &Credential,
) {
    let profile = Profile::new(3, poll.manifest().option_count()).unwrap();
    let mut bodies = (profile.participants() as u32).to_le_bytes().to_vec();
    bodies.extend(original.body_digest());
    bodies.extend([7; 64]);
    bodies.extend([8; 64]);
    let proposal = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/roster-proposal/v2").unwrap(),
            CanonicalItem::hash512(poll.identity()),
            CanonicalItem::variable_bytes(bodies).unwrap(),
        ],
    )
    .encode()
    .unwrap();
    let context =
        RetainedContributionContext::parse(credential, original, poll, 0, &proposal).unwrap();
    let prefix = [poll.identity(), *context.identity()].concat();
    let role = |credential: &Credential, position: u16, purpose: &str| {
        CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii(purpose).unwrap(),
                CanonicalItem::nonempty_ascii(
                    &derive_participant_identity(credential.signing_public())
                        .unwrap()
                        .to_lowercase_hex(),
                )
                .unwrap(),
                CanonicalItem::hash512(poll.identity()),
                CanonicalItem::hash512(*context.identity()),
                CanonicalItem::unsigned16(position),
            ],
        )
        .encode()
        .unwrap()
    };
    let expected_role = role(credential, 0, "sealed-lattice/setup-contribution/v3");
    assert_eq!(
        context.checkpoint_role(&prefix, 0, profile).unwrap(),
        expected_role
    );
    let header = |role: &[u8], input_hashes: usize| {
        let mut bytes = b"FPC4".to_vec();
        bytes.extend([profile.participants() as u8, profile.options() as u8]);
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((role.len() as u16).to_le_bytes());
        bytes.extend(role);
        bytes.extend([0; 128]);
        bytes.extend(profile.setup_statement_header());
        bytes.extend((input_hashes as u16).to_le_bytes());
        for _ in 0..input_hashes {
            bytes.extend(original.header().recipient_key_hash);
        }
        bytes
    };
    let request = |role: &[u8], count| [prefix.as_slice(), &header(role, count)].concat();
    let valid = request(&expected_role, profile.participants());
    let other_owner = Credential::from_seed([91; 32]);
    for wrong_role in [
        role(&other_owner, 0, "sealed-lattice/setup-contribution/v3"),
        role(credential, 1, "sealed-lattice/setup-contribution/v3"),
    ] {
        let bytes = request(&wrong_role, profile.participants());
        // The checkpoint decoder accepts this partial header, isolating the
        // owning import helper's role check as the reason for refusal.
        assert!(word_proof::bridge::first_checkpoint::Import::begin(&bytes[128..]).is_ok());
        assert!(contribution_prover::import_checkpoint(&context, 0, &bytes).is_err());
    }
    for position in [1, 2, usize::MAX] {
        assert!(contribution_prover::import_checkpoint(&context, position, &valid).is_err());
    }
    let missing_keys = request(&expected_role, 0);
    assert!(word_proof::bridge::first_checkpoint::Import::begin(&missing_keys[128..]).is_ok());
    assert!(contribution_prover::import_checkpoint(&context, 0, &missing_keys).is_err());
    for offset in [0, 64] {
        let mut changed = valid.clone();
        changed[offset] ^= 1;
        assert!(contribution_prover::import_checkpoint(&context, 0, &changed).is_err());
    }
    let imported = contribution_prover::import_checkpoint(&context, 0, &valid).unwrap();
    assert_eq!(imported.role(), expected_role);
    assert!(!imported.complete());
    assert!(imported.finish().is_err());
    contribution_session_imports_the_checkpoint(&context, &valid, original.public_key(), profile);
}

// The prover session's import of the same checkpoint: it takes each
// recipient key only when the key hashes to the checkpoint's input hash,
// cannot finish before every record opened, and stops when a record does
// not open, when a proof command fails or when it retires.
fn contribution_session_imports_the_checkpoint(
    context: &RetainedContributionContext,
    request: &[u8],
    key: &[u8],
    profile: Profile,
) {
    let session =
        || ContributionSession::new(|_, _, _| unreachable!("An import emits no public chunk."));
    let write = |session: &mut ContributionSession, bytes: &[u8]| {
        session.input()[..bytes.len()].copy_from_slice(bytes);
    };
    let mut importing = session();
    write(&mut importing, request);
    importing
        .checkpoint_command(4, 0, request.len(), context)
        .unwrap();
    assert_eq!(
        importing.checkpoint_records(),
        contribution_prover::checkpoint_layout(profile).1.len()
    );
    // A second import is refused without stopping the first.
    write(&mut importing, request);
    assert!(
        importing
            .checkpoint_command(4, 0, request.len(), context)
            .is_err()
    );
    // A short key, a changed key and a position beyond the roster.
    let mut changed = key.to_vec();
    changed[0] ^= 1;
    for (position, bytes) in [
        (0, &key[1..]),
        (0, changed.as_slice()),
        (profile.participants(), key),
    ] {
        write(&mut importing, bytes);
        assert!(importing.checkpoint_key(position, bytes.len()).is_err());
    }
    // Each position takes its key once.
    for position in 0..profile.participants() {
        write(&mut importing, key);
        importing.checkpoint_key(position, key.len()).unwrap();
        write(&mut importing, key);
        assert!(importing.checkpoint_key(position, key.len()).is_err());
    }
    // No record opened yet, so the import cannot finish and stays open.
    assert!(importing.checkpoint_command(6, 0, 0, context).is_err());
    assert_ne!(importing.checkpoint_records(), 0);
    // A record that does not open under its key stops the session.
    let unopened = [0; sealing::KEY_BYTES + sealing::TAG_BYTES];
    write(&mut importing, &unopened);
    assert!(
        importing
            .checkpoint_command(5, 0, unopened.len(), context)
            .is_err()
    );
    assert_eq!(importing.checkpoint_records(), 0);
    write(&mut importing, request);
    assert!(
        importing
            .checkpoint_command(4, 0, request.len(), context)
            .is_err()
    );
    // A failed proof command stops a session before any import.
    let mut failed = session();
    write(&mut failed, request);
    assert!(failed.command(2, 0, 0).is_err());
    assert!(
        failed
            .checkpoint_command(4, 0, request.len(), context)
            .is_err()
    );
    // The retirement drops the import and stops the session.
    let mut retired = session();
    write(&mut retired, request);
    retired
        .checkpoint_command(4, 0, request.len(), context)
        .unwrap();
    retired.retire();
    assert_eq!(retired.checkpoint_records(), 0);
    assert!(
        retired
            .checkpoint_command(4, 0, request.len(), context)
            .is_err()
    );
}
