//! Original-owner role controls at the authenticated local-custody boundary.
//! Signed canonical recipient keys pass the real registration verifier before
//! these controls exercise original credential authority.
use crate::registration::CHUNK_LIMIT;
use crate::{
    BodyDigest, Credential, Error, SIGNATURE_BYTES,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        RegistrationHeader, StabilizedDisplayText, derive_participant_identity,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
    registration::{KEY_BYTES, RegistrationVerifier, VerifiedRegistration},
    roster::{RetainedContributionContext, RosterProposal},
    roster_input::RosterInputVerifier,
};
use parallel_work::ProtocolHash;
use std::sync::Arc;
use supported_profile::Profile;

struct CustodyFixture {
    packet: SignedPoll,
    poll: VerifiedPoll,
    credentials: Vec<Credential>,
    signatures: Vec<[u8; SIGNATURE_BYTES]>,
    proposal: RosterProposal,
}

// Every holder below comes from the production registration verifier, with
// the signature it verified: the key must match its header and the signature
// must verify under the original credential. No test constructor creates a
// verified capability.
fn signed_registration(
    poll: &VerifiedPoll,
    credential: &mut Credential,
    body: u8,
) -> (VerifiedRegistration, [u8; SIGNATURE_BYTES]) {
    let mut key = vec![0; KEY_BYTES];
    key[1] = body;
    let header = RegistrationHeader {
        username: normalize_username(format!("Participant {body}").as_bytes()).unwrap(),
        poll: poll.identity(),
        signing_public: *credential.signing_public(),
        recipient_key_hash: ProtocolHash::digest(&key),

        fhe_key_commitments: vec![[7; 64]; crate::source_binding::fhe_key_families(poll).len()],
    }
    .encode()
    .unwrap();
    let digest = BodyDigest::from_header(&header, poll.identity()).unwrap();
    let signature = credential.sign_registration(digest).unwrap();
    let mut verifier = RegistrationVerifier::new(poll, &header, &signature).unwrap();
    for chunk in key.chunks(CHUNK_LIMIT) {
        verifier.push_key(chunk).unwrap();
    }
    verifier.finish_key().unwrap();
    (verifier.finish().unwrap(), signature)
}

fn custody_fixture(runtime: [u8; 64], nonce: u8) -> CustodyFixture {
    custody_fixture_with_size(runtime, nonce, 3)
}
fn custody_fixture_with_size(runtime: [u8; 64], nonce: u8, participants: usize) -> CustodyFixture {
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
    let draft = PollDraft::new(
        Manifest::new(text("Question"), options).unwrap(),
        2,
        participants as u16,
    )
    .unwrap();
    let mut credentials: Vec<_> = (1..=participants as u8)
        .map(|seed| Credential::from_seed([seed; 32]))
        .collect();
    let packet = credentials[0]
        .create_poll(draft, runtime, [nonce; 32])
        .unwrap();
    let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
    let (records, signatures): (Vec<_>, Vec<_>) = credentials
        .iter_mut()
        .enumerate()
        .map(|(position, credential)| {
            let (record, signature) = signed_registration(&poll, credential, position as u8 + 1);
            (Arc::new(record), signature)
        })
        .unzip();
    let proposal = RosterProposal::new(&poll, records).unwrap();
    CustodyFixture {
        packet,
        poll,
        credentials,
        signatures,
        proposal,
    }
}

#[test]
fn clear_preparation_purposes_share_one_original_confirmed_roster() {
    use crate::{
        contribution_body::body_lengths,
        contribution_offer::{OfferEnvelope, authenticate_offer},
        setup_selection::{SelectionProposal, authenticate_endorsement, authenticate_selection},
    };
    let mut fixture = custody_fixture_with_size([4; 64], 5, 4);
    let contexts: Vec<_> = (0..4)
        .map(|position| retained_context(&fixture, position))
        .collect();
    let mut foreign_records = fixture.proposal.records().to_vec();
    foreign_records.swap(1, 2);
    let foreign = RosterProposal::new(&fixture.poll, foreign_records).unwrap();
    let foreign_context = RetainedContributionContext::parse(
        &fixture.credentials[1],
        &foreign.records()[2],
        &fixture.poll,
        2,
        foreign.body(),
    )
    .unwrap();
    let signature = fixture.credentials[0]
        .sign_roster_proposal(&fixture.proposal)
        .unwrap();
    let roster = Arc::new(
        crate::roster_authentication::authenticate_roster_proposal(fixture.proposal, &signature)
            .unwrap(),
    );
    // A corrupt organizer can authenticate another roster; that does not
    // let an honest member split its preparation purposes between them.
    let mut equivocator = Credential::from_seed([1; 32]);
    equivocator.completed_body = Some(foreign.records()[0].body_digest());
    let signature = equivocator.sign_roster_proposal(&foreign).unwrap();
    let foreign =
        crate::roster_authentication::authenticate_roster_proposal(foreign, &signature).unwrap();
    let profile = roster.proposal().profile();
    let envelope = OfferEnvelope::new(
        roster.proposal(),
        1,
        *body_lengths(profile).start(),
        [13; 64],
    )
    .unwrap();
    assert!(
        fixture.credentials[1]
            .sign_offer(&contexts[1], &envelope)
            .is_err()
    );
    fixture.credentials[1].confirm_roster(&contexts[1]).unwrap();
    fixture.credentials[1].confirm_roster(&contexts[1]).unwrap();
    assert!(
        fixture.credentials[1]
            .confirm_roster(&foreign_context)
            .is_err()
    );
    let foreign_envelope = OfferEnvelope::new(
        foreign.proposal(),
        2,
        *body_lengths(profile).start(),
        [13; 64],
    )
    .unwrap();
    assert!(
        fixture.credentials[1]
            .sign_offer(&foreign_context, &foreign_envelope)
            .is_err()
    );
    let signature = fixture.credentials[1]
        .sign_offer(&contexts[1], &envelope)
        .unwrap();
    authenticate_offer(roster.clone(), envelope.bytes(), &signature).unwrap();
    assert!(
        fixture.credentials[1]
            .sign_offer(&contexts[1], &envelope)
            .is_err()
    );
    let selection =
        SelectionProposal::new(roster.proposal(), &[(0, [17; 64]), (2, [18; 64])]).unwrap();
    let other_selection =
        SelectionProposal::new(foreign.proposal(), &[(0, [17; 64]), (2, [18; 64])]).unwrap();
    assert!(
        fixture.credentials[1]
            .endorse_selection(&foreign, &other_selection, 2)
            .is_err()
    );
    let endorsement = fixture.credentials[1]
        .endorse_selection(&roster, &selection, 1)
        .unwrap();
    authenticate_endorsement(&roster, &selection, &endorsement).unwrap();
    assert!(
        fixture.credentials[1]
            .endorse_selection(&roster, &selection, 1)
            .is_err()
    );
    fixture.credentials[0].confirm_roster(&contexts[0]).unwrap();
    let signature = fixture.credentials[0]
        .sign_selection_proposal(&roster, &selection)
        .unwrap();
    authenticate_selection(roster.clone(), selection.body(), &signature).unwrap();
    assert!(
        fixture.credentials[0]
            .sign_selection_proposal(&roster, &selection)
            .is_err()
    );
    fixture.credentials[2].confirm_roster(&contexts[2]).unwrap();
    fixture.credentials[2].retire_preparation();
    fixture.credentials[2].confirm_roster(&contexts[2]).unwrap();
    fixture.credentials[2]
        .unlock_unused_purposes(
            crate::SigningPurpose::Offer.mask()
                | crate::SigningPurpose::SelectionEndorsement.mask(),
        )
        .unwrap();
    assert!(
        fixture.credentials[2]
            .validate_offer_context(&contexts[2])
            .is_err()
    );
    assert!(
        fixture.credentials[2]
            .endorse_selection(&roster, &selection, 2)
            .is_err()
    );
}

#[test]
fn a_losing_endorsement_never_blocks_authenticating_the_winning_certificate() {
    use crate::setup_selection::{
        SelectionProposal, authenticate_certificate, authenticate_endorsement,
        authenticate_selection, encode_certificate,
    };
    let mut fixture = custody_fixture_with_size([4; 64], 5, 4);
    let contexts: Vec<_> = (0..4)
        .map(|position| retained_context(&fixture, position))
        .collect();
    for (position, context) in contexts.iter().enumerate() {
        fixture.credentials[position]
            .confirm_roster(context)
            .unwrap();
    }
    let signature = fixture.credentials[0]
        .sign_roster_proposal(&fixture.proposal)
        .unwrap();
    let roster = Arc::new(
        crate::roster_authentication::authenticate_roster_proposal(fixture.proposal, &signature)
            .unwrap(),
    );
    let winning =
        SelectionProposal::new(roster.proposal(), &[(0, [13; 64]), (2, [14; 64])]).unwrap();
    let losing =
        SelectionProposal::new(roster.proposal(), &[(0, [13; 64]), (1, [15; 64])]).unwrap();
    let packet = fixture.credentials[3]
        .endorse_selection(&roster, &losing, 3)
        .unwrap();
    let old = authenticate_endorsement(&roster, &losing, &packet).unwrap();
    fixture.credentials[3]
        .restore_selection_endorsement(&roster, &old)
        .unwrap();
    assert!(
        fixture.credentials[3]
            .endorse_selection(&roster, &winning, 3)
            .is_err()
    );
    let signature = fixture.credentials[0]
        .sign_selection_proposal(&roster, &winning)
        .unwrap();
    let proposal = authenticate_selection(roster.clone(), winning.body(), &signature).unwrap();
    let endorsements: Vec<_> = fixture
        .credentials
        .iter_mut()
        .take(3)
        .enumerate()
        .map(|(position, credential)| {
            authenticate_endorsement(
                &roster,
                &winning,
                &credential
                    .endorse_selection(&roster, &winning, position)
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let certificate = encode_certificate(&proposal, &endorsements).unwrap();
    assert_eq!(
        authenticate_certificate(roster, &certificate)
            .unwrap()
            .identity(),
        winning.identity()
    );
    assert_eq!(
        fixture.credentials[3].selection_endorsed,
        Some(losing.identity())
    );
}

#[test]
fn selection_certificates_bind_complete_canonical_choices_but_not_quorum_carriers() {
    use crate::setup_selection::{
        self, SelectionProposal, authenticate_certificate, authenticate_endorsement,
        authenticate_selection, encode_certificate,
    };
    let mut fixture = custody_fixture_with_size([4; 64], 5, 4);
    let contexts: Vec<_> = (0..4)
        .map(|position| retained_context(&fixture, position))
        .collect();
    for (position, context) in contexts.iter().enumerate() {
        fixture.credentials[position]
            .confirm_roster(context)
            .unwrap();
    }
    let signature = fixture.credentials[0]
        .sign_roster_proposal(&fixture.proposal)
        .unwrap();
    let roster = Arc::new(
        crate::roster_authentication::authenticate_roster_proposal(fixture.proposal, &signature)
            .unwrap(),
    );
    let entries = [(0, [13; 64]), (2, [14; 64])];
    for malformed in [
        vec![entries[0]],
        vec![entries[0], entries[0]],
        vec![entries[1], entries[0]],
        vec![(0, [13; 64]), (3, [14; 64])],
    ] {
        assert!(SelectionProposal::new(roster.proposal(), &malformed).is_err());
    }
    let selection = SelectionProposal::new(roster.proposal(), &entries).unwrap();
    assert_eq!(
        selection.body().len(),
        setup_selection::selection_body_bytes(roster.proposal().profile())
    );
    let signature = fixture.credentials[0]
        .sign_selection_proposal(&roster, &selection)
        .unwrap();
    let proposal = authenticate_selection(roster.clone(), selection.body(), &signature).unwrap();
    let endorsements: Vec<_> = fixture
        .credentials
        .iter_mut()
        .enumerate()
        .map(|(position, credential)| {
            let packet = credential
                .endorse_selection(&roster, &selection, position)
                .unwrap();
            assert_eq!(packet.len(), setup_selection::ENDORSEMENT_BYTES);
            authenticate_endorsement(&roster, &selection, &packet).unwrap()
        })
        .collect();
    let first = encode_certificate(&proposal, &endorsements[..3]).unwrap();
    let second = encode_certificate(
        &proposal,
        &[
            endorsements[0].clone(),
            endorsements[2].clone(),
            endorsements[3].clone(),
        ],
    )
    .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        authenticate_certificate(roster.clone(), &first)
            .unwrap()
            .identity(),
        authenticate_certificate(roster.clone(), &second)
            .unwrap()
            .identity()
    );
    assert_eq!(
        first.len(),
        setup_selection::certificate_bytes(roster.proposal().profile(), selection.body().len())
            .unwrap()
    );
    assert!(encode_certificate(&proposal, &endorsements[..2]).is_err());
    assert!(
        encode_certificate(
            &proposal,
            &[
                endorsements[0].clone(),
                endorsements[0].clone(),
                endorsements[2].clone()
            ]
        )
        .is_err()
    );
    for changed in [
        first[..first.len() - 1].to_vec(),
        [first.as_slice(), &[0]].concat(),
        {
            let mut changed = first.clone();
            let end = changed.len();
            changed[end - 1] ^= 1;
            changed
        },
    ] {
        assert!(authenticate_certificate(roster.clone(), &changed).is_err());
    }
    let mut packet = endorsements[1].packet();
    packet[2] ^= 1;
    assert!(authenticate_endorsement(&roster, &selection, &packet).is_err());
    let mut encoded =
        CanonicalTuple::decode(selection.body(), &CanonicalDecodeLimits::default()).unwrap();
    encoded.items[1] = CanonicalItem::hash512([99; 64]);
    assert!(SelectionProposal::decode(roster.proposal(), &encoded.encode().unwrap()).is_err());
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
    [fixture.poll.identity(), fixture.proposal.identity()].concat()
}

// A later visit's roster, which the roster verifier verifies again from the
// published records under the body identities the proposal lists.
fn verify_roster(fixture: &CustodyFixture) -> RosterProposal {
    let begin = [
        fixture.poll.identity().as_slice(),
        &fixture.poll.runtime(),
        &(fixture.proposal.records().len() as u16).to_le_bytes(),
        &(fixture.packet.body.len() as u32).to_le_bytes(),
        &fixture.packet.body,
        &fixture.packet.signature,
    ]
    .concat();
    let mut verifier = RosterInputVerifier::new(&begin).unwrap();
    for (position, record) in fixture.proposal.records().iter().enumerate() {
        let header = record.header().encode().unwrap();
        let input = [
            (position as u16).to_le_bytes().as_slice(),
            &record.body_digest(),
            &(header.len() as u32).to_le_bytes(),
            &header,
            &fixture.signatures[position],
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
fn contribution_roles_retain_the_original_owner_across_roster_verification_and_context_restoration()
{
    let fixture = custody_fixture([4; 64], 5);
    let verified = verify_roster(&fixture);
    for position in 0..fixture.proposal.profile().setup_eligible_contributors() {
        let role = fixture.proposal.contribution_role(position).unwrap();
        let tuple = CanonicalTuple::decode(&role, &CanonicalDecodeLimits::default()).unwrap();
        let participant =
            derive_participant_identity(fixture.credentials[position].signing_public())
                .unwrap()
                .to_lowercase_hex();
        assert_eq!(tuple.schema_identifier, 1);
        assert_eq!(tuple.schema_version, 1);
        assert_eq!(tuple.items.len(), 5);
        assert_eq!(tuple.items[0].item_type(), CanonicalItemType::Ascii);
        assert_eq!(
            tuple.items[0].variable_value_bytes().unwrap(),
            b"sealed-lattice/setup-contribution/v3"
        );
        assert_eq!(tuple.items[1].item_type(), CanonicalItemType::Ascii);
        assert_eq!(
            tuple.items[1].variable_value_bytes().unwrap(),
            participant.as_bytes()
        );
        for (item, expected) in tuple.items[2..4]
            .iter()
            .zip([fixture.poll.identity(), fixture.proposal.identity()])
        {
            assert_eq!(item.item_type(), CanonicalItemType::Hash512);
            assert_eq!(item.canonical_bytes(), expected);
        }
        assert_eq!(tuple.items[4].item_type(), CanonicalItemType::Unsigned16);
        assert_eq!(
            tuple.items[4].canonical_bytes(),
            (position as u16).to_le_bytes()
        );
        assert_eq!(verified.contribution_role(position).unwrap(), role);
        let context = retained_context(&fixture, position);
        assert_eq!(
            context
                .checkpoint_role(&checkpoint_prefix(&fixture), position, context.profile())
                .unwrap(),
            role
        );
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
    let (other_body, _) = signed_registration(&fixture.poll, &mut same_key, 19);
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
        .sign_roster_proposal(&fixture.proposal)
        .unwrap();
    assert!(matches!(
        fixture.credentials[0].sign_roster_proposal(&fixture.proposal),
        Err(Error::Consumed)
    ));
    crate::roster_authentication::authenticate_roster_proposal(fixture.proposal, &signature)
        .unwrap();
}

#[test]
fn retained_context_requires_the_original_poll() {
    let fixture = custody_fixture([4; 64], 5);
    // Keep the original owner and body entries intact, so the poll
    // comparison must reject on its own.
    let mut proposal =
        CanonicalTuple::decode(fixture.proposal.body(), &CanonicalDecodeLimits::default()).unwrap();
    proposal.items[1] = CanonicalItem::hash512([99; 64]);
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
    // Another poll, of another nonce or of another runtime, refuses both
    // ways.
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
fn retained_noneligible_members_keep_roster_context_without_offer_authority() {
    let mut fixture = custody_fixture([4; 64], 5);
    let position = fixture.proposal.profile().setup_eligible_contributors();
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
    fixture.credentials[position]
        .confirm_roster(&context)
        .unwrap();
    fixture.credentials[position]
        .confirm_roster(&context)
        .unwrap();
    assert!(matches!(
        fixture.credentials[position].validate_offer_context(&context),
        Err(Error::Context)
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
    for offset in [0, 63, 64, 127] {
        let mut changed = prefix.clone();
        changed[offset] ^= 1;
        assert!(
            context
                .checkpoint_role(&changed, 1, context.profile())
                .is_err()
        );
    }
    for changed in [&prefix[..127], &[prefix.as_slice(), &[0]].concat()] {
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
        fixture.proposal.contribution_role(1).unwrap()
    );
}
