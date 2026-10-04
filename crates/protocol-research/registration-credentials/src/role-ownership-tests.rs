//! Original-owner role controls at the authenticated local-custody boundary.
//! These synthetic retained records exercise the real keyed restore operation;
//! they do not establish public registration-proof acceptance.
use crate::{
    BodyHasher, Credential, Error,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        RegistrationHeader, StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
        derive_participant_identity, normalize_username,
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
    registration::{KEY_BYTES, RegistrationVerifier, VerifiedRegistration},
    roster::{RetainedContributionContext, RosterProposal},
    roster_input::RosterInputVerifier,
};
use parallel_work::ProtocolHash;
use registration_proof::CHUNK_LIMIT;
use std::sync::Arc;
use supported_profile::{Profile, relation::PROOF_HEADER_BYTES};

struct CustodyFixture {
    packet: SignedPoll,
    poll: VerifiedPoll,
    credentials: Vec<Credential>,
    proposal: RosterProposal,
}

// Every holder below comes from the production restore operation: the key
// must match its header and the retained metadata must authenticate under the
// original credential. No test constructor creates a verified capability.
fn retained_registration(
    poll: &VerifiedPoll,
    credential: &mut Credential,
    body: u8,
) -> VerifiedRegistration {
    let mut key = vec![0; KEY_BYTES];
    key[1] = body;
    let header = RegistrationHeader {
        username: normalize_username(format!("Participant {body}").as_bytes()).unwrap(),
        poll: poll.identity(),
        runtime: poll.runtime(),
        signing_public: *credential.signing_public(),
        recipient_key_hash: ProtocolHash::digest(&key),
        proof_length: PROOF_HEADER_BYTES + 1,
        fhe_key_commitments: vec![[7; 64]; crate::source_binding::fhe_key_families(poll).len()],
    }
    .encode()
    .unwrap();
    let proof = vec![body; PROOF_HEADER_BYTES + 1];
    let (mut hasher, consumed) =
        BodyHasher::from_header(&header, poll.identity(), poll.runtime()).unwrap();
    assert_eq!(consumed, header.len());
    hasher.absorb(&proof).unwrap();
    let digest = hasher.finish().unwrap();
    let body_digest = digest.bytes();
    let signature = credential.sign_registration(digest, [body; 32]).unwrap();
    let digests = [ProtocolHash::digest(&proof), body_digest].concat();
    let tagged = [
        (header.len() as u32).to_le_bytes().as_slice(),
        &header,
        &digests,
    ]
    .concat();
    let tag = credential.retained_tag(b"sealed-lattice/retained-registration/v1", poll, &tagged);
    let retained = [digests.as_slice(), &tag].concat();
    let mut verifier = RegistrationVerifier::new(poll, &header, &signature).unwrap();
    for chunk in key.chunks(CHUNK_LIMIT) {
        verifier.push_key(chunk).unwrap();
    }
    verifier.finish_key().unwrap();
    verifier.restore(credential, poll, &retained).unwrap()
}

fn custody_fixture(runtime: [u8; 64], nonce: u8) -> CustodyFixture {
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..2)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                text(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2, 3).unwrap();
    let mut credentials: Vec<_> = (1..=3)
        .map(|seed| Credential::from_seed([seed; 32]))
        .collect();
    let packet = credentials[0]
        .create_poll(draft, runtime, [nonce; 32], [8; 32])
        .unwrap();
    let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
    let records = credentials
        .iter_mut()
        .enumerate()
        .map(|(position, credential)| {
            Arc::new(retained_registration(&poll, credential, position as u8 + 1))
        })
        .collect();
    let proposal = RosterProposal::new(&poll, records).unwrap();
    CustodyFixture {
        packet,
        poll,
        credentials,
        proposal,
    }
}

fn retained_context(fixture: &CustodyFixture, position: usize) -> RetainedContributionContext {
    RetainedContributionContext::parse(
        &fixture.credentials[position],
        &fixture.proposal.records()[position],
        &fixture.poll,
        position,
        fixture.proposal.body(),
    )
    .unwrap()
}

fn checkpoint_prefix(fixture: &CustodyFixture) -> Vec<u8> {
    [
        fixture.poll.identity(),
        fixture.poll.runtime(),
        fixture.proposal.identity(),
    ]
    .concat()
}

fn restore_roster(fixture: &CustodyFixture) -> RosterProposal {
    let owner = &fixture.credentials[1];
    let retained = owner
        .retain_roster(&fixture.poll, &fixture.proposal)
        .unwrap();
    let begin = [
        fixture.poll.identity().as_slice(),
        &fixture.poll.runtime(),
        &(fixture.proposal.records().len() as u16).to_le_bytes(),
        &(fixture.packet.body.len() as u32).to_le_bytes(),
        &fixture.packet.body,
        &fixture.packet.signature,
    ]
    .concat();
    let mut verifier = RosterInputVerifier::retained(&begin, owner, &retained).unwrap();
    for (position, record) in fixture.proposal.records().iter().enumerate() {
        let header = record.header().encode().unwrap();
        let input = [
            (position as u16).to_le_bytes().as_slice(),
            &(header.len() as u32).to_le_bytes(),
            &header,
        ]
        .concat();
        verifier.begin_record(&input).unwrap();
        for chunk in record.public_key().chunks(65_537) {
            verifier.push_key(position, chunk).unwrap();
        }
        verifier.finish_key(position).unwrap();
        verifier.finish_record(position).unwrap();
    }
    verifier.finish().unwrap()
}

#[test]
fn contribution_roles_retain_the_original_owner_across_roster_and_context_restoration() {
    let fixture = custody_fixture([4; 64], 5);
    let restored = restore_roster(&fixture);
    for position in 0..fixture.proposal.profile().setup_contributors() {
        let role = fixture.proposal.contribution_role(position).unwrap();
        let tuple = CanonicalTuple::decode(&role, &CanonicalDecodeLimits::default()).unwrap();
        let participant =
            derive_participant_identity(fixture.credentials[position].signing_public())
                .unwrap()
                .to_lowercase_hex();
        assert_eq!(tuple.schema_identifier, 1);
        assert_eq!(tuple.schema_version, 1);
        assert_eq!(tuple.items.len(), 6);
        assert_eq!(tuple.items[0].item_type(), CanonicalItemType::Ascii);
        assert_eq!(
            tuple.items[0].variable_value_bytes().unwrap(),
            b"sealed-lattice/setup-contribution/v2"
        );
        assert_eq!(tuple.items[1].item_type(), CanonicalItemType::Ascii);
        assert_eq!(
            tuple.items[1].variable_value_bytes().unwrap(),
            participant.as_bytes()
        );
        for (item, expected) in tuple.items[2..5].iter().zip([
            fixture.poll.identity(),
            fixture.poll.runtime(),
            fixture.proposal.identity(),
        ]) {
            assert_eq!(item.item_type(), CanonicalItemType::Hash512);
            assert_eq!(item.canonical_bytes(), expected);
        }
        assert_eq!(tuple.items[5].item_type(), CanonicalItemType::Unsigned16);
        assert_eq!(
            tuple.items[5].canonical_bytes(),
            (position as u16).to_le_bytes()
        );
        assert_eq!(restored.contribution_role(position).unwrap(), role);
        let context = retained_context(&fixture, position);
        assert_eq!(context.role(), role);
        assert_eq!(
            context.fhe_key_commitment(),
            fixture.proposal.fhe_key_commitment(position).unwrap()
        );
        assert_eq!(
            context
                .checkpoint_role(
                    &checkpoint_prefix(&fixture),
                    position,
                    fixture.proposal.profile()
                )
                .unwrap(),
            role,
        );
    }
}

#[test]
fn retained_context_refuses_other_original_owners_and_positions_before_signing() {
    let mut fixture = custody_fixture([4; 64], 5);
    let original = &fixture.proposal.records()[0];
    for (credential, record, position) in [
        (&fixture.credentials[1], original, 0),
        (&fixture.credentials[1], &fixture.proposal.records()[1], 0),
        (&fixture.credentials[0], original, 1),
    ] {
        assert!(matches!(
            RetainedContributionContext::parse(
                credential,
                record,
                &fixture.poll,
                position,
                fixture.proposal.body()
            ),
            Err(Error::Context)
        ));
    }
    // The same signing key without the original completed enrollment, or
    // after completing another body, must not impersonate that original.
    let mut same_key = Credential::from_seed([1; 32]);
    assert!(matches!(
        RetainedContributionContext::parse(
            &same_key,
            original,
            &fixture.poll,
            0,
            fixture.proposal.body()
        ),
        Err(Error::Context)
    ));
    let other_body = retained_registration(&fixture.poll, &mut same_key, 19);
    assert_ne!(other_body.body_digest(), original.body_digest());
    for record in [original.as_ref(), &other_body] {
        assert!(matches!(
            RetainedContributionContext::parse(
                &same_key,
                record,
                &fixture.poll,
                0,
                fixture.proposal.body()
            ),
            Err(Error::Context)
        ));
    }
    for position in [fixture.proposal.records().len(), usize::MAX] {
        assert!(
            RetainedContributionContext::parse(
                &fixture.credentials[0],
                original,
                &fixture.poll,
                position,
                fixture.proposal.body()
            )
            .is_err()
        );
    }
    let context = retained_context(&fixture, 0);
    assert_eq!(context.identity(), fixture.proposal.identity_bytes());
    let signature = fixture.credentials[0]
        .sign_roster_proposal(&fixture.proposal, [13; 32])
        .unwrap();
    assert!(matches!(
        fixture.credentials[0].sign_roster_proposal(&fixture.proposal, [14; 32]),
        Err(Error::Consumed)
    ));
    crate::roster_authentication::verify_roster_proposal(fixture.proposal, &signature).unwrap();
}

#[test]
fn retained_context_requires_the_original_poll_and_runtime() {
    let fixture = custody_fixture([4; 64], 5);
    // Keep the original owner, body entry, and other routing fields intact,
    // so each routing comparison must reject independently.
    for field in [1, 2] {
        let mut proposal =
            CanonicalTuple::decode(fixture.proposal.body(), &CanonicalDecodeLimits::default())
                .unwrap();
        proposal.items[field] = CanonicalItem::hash512([99; 64]);
        assert!(matches!(
            RetainedContributionContext::parse(
                &fixture.credentials[1],
                &fixture.proposal.records()[1],
                &fixture.poll,
                1,
                &proposal.encode().unwrap(),
            ),
            Err(Error::Context)
        ));
    }
    for (runtime, nonce) in [([4; 64], 6), ([9; 64], 5)] {
        let foreign = custody_fixture(runtime, nonce);
        assert_ne!(fixture.poll.identity(), foreign.poll.identity());
        retained_context(&foreign, 1);
        assert!(matches!(
            RetainedContributionContext::parse(
                &foreign.credentials[1],
                &foreign.proposal.records()[1],
                &foreign.poll,
                1,
                fixture.proposal.body(),
            ),
            Err(Error::Context)
        ));
        assert!(matches!(
            RetainedContributionContext::parse(
                &fixture.credentials[1],
                &fixture.proposal.records()[1],
                &fixture.poll,
                1,
                foreign.proposal.body(),
            ),
            Err(Error::Context)
        ));
    }
}

#[test]
fn retained_noncontributors_keep_roster_context_without_checkpoint_authority() {
    let mut fixture = custody_fixture([4; 64], 5);
    let position = fixture.proposal.profile().setup_contributors();
    let context = retained_context(&fixture, position);
    assert_eq!(context.position(), position);
    assert_eq!(context.profile(), fixture.proposal.profile());
    assert!(matches!(
        fixture.proposal.contribution_role(position),
        Err(Error::Context)
    ));
    assert!(matches!(
        context.checkpoint_role(&checkpoint_prefix(&fixture), position, context.profile()),
        Err(Error::Context)
    ));
    let expected = fixture.credentials[position]
        .retained_roster_confirmation_body(&context)
        .unwrap();
    let confirmation = fixture.credentials[position]
        .sign_retained_roster_confirmation(&context, [11; 32])
        .unwrap();
    assert_eq!(confirmation.body(), expected);
    let signature = fixture.credentials[0]
        .sign_roster_proposal(&fixture.proposal, [12; 32])
        .unwrap();
    let roster =
        crate::roster_authentication::verify_roster_proposal(fixture.proposal, &signature).unwrap();
    let verified = crate::contribution_authentication::verify_confirmation(
        &roster,
        confirmation.body(),
        confirmation.signature(),
    )
    .unwrap();
    assert_eq!(verified.position(), position);
    assert_eq!(verified.commitment(), None);
    assert!(matches!(
        fixture.credentials[position].sign_retained_roster_confirmation(&context, [13; 32]),
        Err(Error::Consumed)
    ));
}

#[test]
fn checkpoint_roles_refuse_changed_routing_position_and_profile() {
    let fixture = custody_fixture([4; 64], 5);
    let context = retained_context(&fixture, 1);
    let prefix = checkpoint_prefix(&fixture);
    for position in [0, 2, usize::MAX] {
        assert!(
            context
                .checkpoint_role(&prefix, position, context.profile())
                .is_err()
        );
    }
    for profile in [Profile::new(4, 2).unwrap(), Profile::new(3, 3).unwrap()] {
        assert!(context.checkpoint_role(&prefix, 1, profile).is_err());
    }
    for offset in [0, 63, 64, 127, 128, 191] {
        let mut changed = prefix.clone();
        changed[offset] ^= 1;
        assert!(
            context
                .checkpoint_role(&changed, 1, context.profile())
                .is_err()
        );
    }
    for changed in [&prefix[..191], &[prefix.as_slice(), &[0]].concat()] {
        assert!(
            context
                .checkpoint_role(changed, 1, context.profile())
                .is_err()
        );
    }
    assert_eq!(
        context
            .checkpoint_role(&prefix, 1, context.profile())
            .unwrap(),
        context.role()
    );
}
