use parallel_work::ProtocolHash;
use protocol_foundations::{
    BodyDigest, Credential, Refusal, SIGNATURE_BYTES,
    foundation::{
        RegistrationHeader, StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        participant_identity::derive_participant_identity,
    },
    poll::{PollDraft, SignedPoll, VerifiedPoll, verify_poll},
    registration::{
        CHUNK_LIMIT, KEY_BYTES, RegistrationVerifier, VerifiedRegistration,
        session::RegistrationSession,
    },
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::authenticate_roster_proposal,
    roster_input::{RecordStep, RosterInputVerifier},
    source_binding::{fhe_key_families, source_verifier},
};
use setup_witness::encrypted_source::{EncryptedSource, ciphertext_bytes};
use std::sync::Arc;
use supported_profile::{DEGREE, Profile};

fn label(value: &str) -> StabilizedDisplayText {
    StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap()
}
fn create_poll_fixture(
    maximum: u16,
    options: u16,
    seed: u8,
) -> (Credential, SignedPoll, VerifiedPoll) {
    let mut creator = Credential::from_seed([seed; 64]);
    let options = (0..options)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                label(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(
        Manifest::new(label("Source registration"), options).unwrap(),
        1,
        maximum,
    )
    .unwrap();
    let packet = creator.create_poll(draft, [4; 64], [5; 32]).unwrap();
    let verified = verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap();
    (creator, packet, verified)
}

// Independent public framing also signs malformed bodies in negative cases.
// A failed digest or stale signature cannot substitute for canonical checks.
fn binding(profile: Profile, poll: [u8; 64], key: &[u8; 64], bytes: &[u8]) -> [u8; 64] {
    let owner = derive_participant_identity(key).unwrap();
    let mut hash = ProtocolHash::new();
    hash.update(b"sealed-lattice/registered-source/v1");
    hash.update(poll);
    hash.update(owner.as_bytes());
    hash.update((DEGREE as u32).to_le_bytes());
    let modulus = profile.ciphertext_modulus().to_bytes();
    hash.update((modulus.len() as u16).to_le_bytes());
    hash.update(modulus);
    hash.update((profile.fhe_common_sample_bits() as u32).to_le_bytes());
    hash.update(((2 * DEGREE * 6) as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize()
}
struct Fixture {
    header: Vec<u8>,
    signature: [u8; SIGNATURE_BYTES],
    key: Vec<u8>,
    sources: Vec<Vec<u8>>,
    identity: [u8; 64],
}
fn signed_fixture(
    poll: &VerifiedPoll,
    credential: &mut Credential,
    sources: Vec<Vec<u8>>,
    name: &str,
) -> Fixture {
    signed_fixture_with_key(poll, credential, sources, name, vec![0; KEY_BYTES])
}
fn signed_fixture_with_key(
    poll: &VerifiedPoll,
    credential: &mut Credential,
    sources: Vec<Vec<u8>>,
    name: &str,
    key: Vec<u8>,
) -> Fixture {
    let families = fhe_key_families(poll);
    assert_eq!(families.len(), sources.len());
    let header = RegistrationHeader {
        username: label(name),
        poll: poll.identity(),
        signing_public: *credential.signing_public(),
        recipient_key_hash: ProtocolHash::digest(&key),
        source_bindings: families
            .iter()
            .zip(&sources)
            .map(|(profile, body)| {
                binding(*profile, poll.identity(), credential.signing_public(), body)
            })
            .collect(),
    }
    .encode()
    .unwrap();
    let body = BodyDigest::from_header(&header, poll.identity()).unwrap();
    let identity = body.bytes();
    let signature = credential.sign_registration(body).unwrap();
    Fixture {
        header,
        signature,
        key,
        sources,
        identity,
    }
}
fn bodies(poll: &VerifiedPoll, marker: u8) -> Vec<Vec<u8>> {
    fhe_key_families(poll)
        .iter()
        .enumerate()
        .map(|(family, _)| {
            let mut bytes = vec![0; ciphertext_bytes()];
            bytes[1] = marker + family as u8;
            bytes
        })
        .collect()
}

fn verify(
    poll: &VerifiedPoll,
    fixture: &Fixture,
    sources: &[u8],
    chunk: usize,
) -> Result<VerifiedRegistration, Refusal> {
    let mut verifier = RegistrationVerifier::new(poll, &fixture.header, &fixture.signature)?;
    for part in fixture.key.chunks(chunk) {
        verifier.push_key(part)?;
    }
    verifier.finish_key()?;
    for part in sources.chunks(chunk) {
        verifier.push_sources(part)?;
    }
    verifier.finish()
}

#[test]
fn registration_requires_every_complete_canonical_signed_source_body() {
    let (mut creator, _, poll) = create_poll_fixture(20, 20, 7);
    let fixture = signed_fixture(&poll, &mut creator, bodies(&poll, 1), "Creator");
    assert!(fixture.sources.len() > 1);
    let bytes = fixture.sources.concat();
    for chunk in [65_537, CHUNK_LIMIT] {
        let record = verify(&poll, &fixture, &bytes, chunk).unwrap();
        assert_eq!(record.body_digest(), fixture.identity);
        assert_eq!(record.header().source_bindings.len(), fixture.sources.len());
    }
    assert!(verify(&poll, &fixture, &[], 65_537).is_err());
    assert!(verify(&poll, &fixture, &bytes[..bytes.len() - 1], 65_537).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify(&poll, &fixture, &trailing, CHUNK_LIMIT).is_err());
    let mut swapped = fixture.sources.clone();
    swapped.swap(0, 1);
    assert!(verify(&poll, &fixture, &swapped.concat(), 65_537).is_err());
    let mut changed = bytes.clone();
    changed[1] ^= 1;
    assert!(verify(&poll, &fixture, &changed, CHUNK_LIMIT).is_err());
    let mut signature = fixture.signature;
    signature[SIGNATURE_BYTES - 1] ^= 1;
    let bad = Fixture {
        signature,
        header: fixture.header.clone(),
        key: fixture.key.clone(),
        sources: fixture.sources.clone(),
        identity: fixture.identity,
    };
    assert!(verify(&poll, &bad, &bytes, CHUNK_LIMIT).is_err());
    let mut oversized =
        RegistrationVerifier::new(&poll, &fixture.header, &fixture.signature).unwrap();
    for part in fixture.key.chunks(CHUNK_LIMIT) {
        oversized.push_key(part).unwrap();
    }
    oversized.finish_key().unwrap();
    assert!(oversized.push_sources(&vec![0; CHUNK_LIMIT + 1]).is_err());
    assert!(oversized.push_sources(&bytes[..6]).is_err());
    assert!(oversized.finish().is_err());
    let mut old_header = fixture.header.clone();
    let offset = old_header
        .windows(b"registration-header/v7".len())
        .position(|part| part == b"registration-header/v7")
        .unwrap();
    old_header[offset + b"registration-header/v".len()] = b'6';
    assert!(RegistrationVerifier::new(&poll, &old_header, &fixture.signature).is_err());
    for (index, record) in [
        [2, 1, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0],
        [0, 255, 255, 255, 255, 255],
    ]
    .iter()
    .enumerate()
    {
        let mut sources = bodies(&poll, 1);
        sources[0][..6].copy_from_slice(record);
        let mut corrupt = Credential::from_seed([30 + index as u8; 64]);
        let signed = signed_fixture(&poll, &mut corrupt, sources, "Malformed source");
        assert!(verify(&poll, &signed, &signed.sources.concat(), 65_537).is_err());
    }
    println!(
        "Source registration: complete bodies accepted; missing, truncated, trailing, reordered, changed, unsigned and noncanonical bodies refused"
    );
}

#[test]
fn helper_sessions_and_roster_verification_consume_the_same_source_inventory() {
    let (mut creator, packet, poll) = create_poll_fixture(3, 2, 11);
    let first = signed_fixture(&poll, &mut creator, bodies(&poll, 1), "Creator");
    let mut second_credential = Credential::from_seed([12; 64]);
    let second = signed_fixture(&poll, &mut second_credential, bodies(&poll, 2), "Second");
    let mut third_credential = Credential::from_seed([13; 64]);
    let third = signed_fixture(&poll, &mut third_credential, bodies(&poll, 3), "Third");
    let mut session = RegistrationSession::open(&poll, 0, &first.header, &first.signature).unwrap();
    for chunk in first.key.chunks(CHUNK_LIMIT) {
        session.push_key(chunk).unwrap();
    }
    session.finish_key().unwrap();
    assert!(session.finish().is_err());
    let input = [
        packet.identity.as_slice(),
        &[4; 64],
        &3u16.to_le_bytes(),
        &(packet.body.len() as u32).to_le_bytes(),
        &packet.body,
        &packet.signature,
    ]
    .concat();
    let mut verifier = RosterInputVerifier::new(&input).unwrap();
    for (position, fixture) in [&first, &second, &third].into_iter().enumerate() {
        let begin = [
            (position as u16).to_le_bytes().as_slice(),
            &fixture.identity,
            &(fixture.header.len() as u32).to_le_bytes(),
            &fixture.header,
            &fixture.signature,
        ]
        .concat();
        verifier
            .record_step(RecordStep::Begin, position, &begin)
            .unwrap();
        for part in fixture.key.chunks(65_537) {
            verifier
                .record_step(RecordStep::Key, position, part)
                .unwrap();
        }
        verifier
            .record_step(RecordStep::KeyFinish, position, &[])
            .unwrap();
        assert!(verifier.finish().is_err());
        for source in &fixture.sources {
            for part in source.chunks(65_537) {
                verifier
                    .record_step(RecordStep::Sources, position, part)
                    .unwrap();
            }
        }
        verifier
            .record_step(RecordStep::Finish, position, &[])
            .unwrap();
        assert!(verifier.discard_record(position).is_err());
    }
    let proposal = verifier.finish().unwrap();
    assert_eq!(proposal.records().len(), 3);
    assert_eq!(proposal.records()[0].body_digest(), first.identity);
    let signature = creator.sign_roster_proposal(&proposal).unwrap();
    let authenticated = authenticate_roster_proposal(proposal, &signature).unwrap();
    assert_eq!(authenticated.proposal().organizer_position(), 0);
    println!("Source registration: owning helper verdicts gate the complete authenticated roster");
}

#[test]
fn an_original_encrypted_source_is_bound_to_the_authenticated_owner_and_confirmation() {
    let (mut creator, _, poll) = create_poll_fixture(3, 2, 21);
    let profile = Profile::new(3, 2).unwrap();
    let owner = derive_participant_identity(creator.signing_public()).unwrap();
    let create = || {
        EncryptedSource::from_seed(profile, &poll.identity(), owner.as_bytes(), [41; 64]).unwrap()
    };
    let package = create();
    let public = package.public().polynomials.clone();
    let source_bytes = package.public().ciphertext_records().unwrap().concat();
    let first = signed_fixture(&poll, &mut creator, vec![source_bytes.clone()], "Creator");
    let first_verified = Arc::new(verify(&poll, &first, &source_bytes, 65_537).unwrap());
    let mut second = Credential::from_seed([22; 64]);
    let second = signed_fixture(&poll, &mut second, bodies(&poll, 2), "Second");
    let mut third = Credential::from_seed([23; 64]);
    let third = signed_fixture(&poll, &mut third, bodies(&poll, 3), "Third");
    let records = vec![
        first_verified.clone(),
        Arc::new(verify(&poll, &second, &second.sources.concat(), CHUNK_LIMIT).unwrap()),
        Arc::new(verify(&poll, &third, &third.sources.concat(), CHUNK_LIMIT).unwrap()),
    ];
    let proposal = RosterProposal::new(&poll, records).unwrap();
    let signature = creator.sign_roster_proposal(&proposal).unwrap();
    let authenticated = authenticate_roster_proposal(proposal, &signature).unwrap();
    assert!(
        creator
            .source_contribution(&authenticated, 0, package)
            .is_err()
    );
    let context = RetainedContributionContext::parse(
        &creator,
        &first_verified,
        &poll,
        0,
        authenticated.proposal().body(),
    )
    .unwrap();
    creator.confirm_roster(&context).unwrap();
    creator.confirm_roster(&context).unwrap();
    let mut reopened = source_verifier(&poll, &first_verified, profile).unwrap();
    for part in source_bytes.chunks(65_537) {
        reopened.push(part).unwrap();
    }
    assert_eq!(
        reopened
            .finish()
            .unwrap()
            .into_public(profile)
            .unwrap()
            .polynomials,
        public
    );
    let contribution = creator
        .source_contribution(&authenticated, 0, create())
        .unwrap();
    assert_eq!(contribution.profile(), profile);
    let other_source =
        EncryptedSource::from_seed(profile, &poll.identity(), owner.as_bytes(), [42; 64]).unwrap();
    assert!(
        creator
            .source_contribution(&authenticated, 0, other_source)
            .is_err()
    );
    assert!(
        creator
            .source_contribution(&authenticated, 1, create())
            .is_err()
    );
    assert!(source_verifier(&poll, &first_verified, Profile::new(4, 2).unwrap()).is_err());
    println!(
        "Source registration: original package and reopening match; absent confirmation, changed source and wrong owner/family refused"
    );
}

#[test]
fn retained_source_seeds_replay_under_the_completed_original_registration() {
    use protocol_foundations::source_seeds::{SourceSeeds, capsule_bytes};
    let (mut creator, _, poll) = create_poll_fixture(3, 2, 51);
    let profile = Profile::new(3, 2).unwrap();
    let mut staged = Vec::new();
    let mut maximum_chunk = 0;
    let mut sources = SourceSeeds::create(&poll, &mut creator, |offset, bytes| {
        assert_eq!(offset, staged.len());
        assert!(bytes.len() <= CHUNK_LIMIT);
        maximum_chunk = maximum_chunk.max(bytes.len());
        staged.extend_from_slice(bytes);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        staged.len(),
        fhe_key_families(&poll).len() * ciphertext_bytes()
    );
    assert!(SourceSeeds::create(&poll, &mut creator, |_, _| Ok(())).is_err());
    let original = signed_fixture(
        &poll,
        &mut creator,
        staged
            .chunks_exact(ciphertext_bytes())
            .map(|bytes| bytes.to_vec())
            .collect(),
        "Creator",
    );
    let registration = verify(&poll, &original, &staged, 65_537).unwrap();
    assert_eq!(sources.bindings(), registration.header().source_bindings);
    assert_eq!(
        sources
            .package(&poll, profile)
            .unwrap()
            .public()
            .ciphertext_records()
            .unwrap()
            .concat(),
        staged
    );
    let sealed = sources.seal(&creator, registration.header()).unwrap();
    assert_eq!(sealed.bytes.len(), capsule_bytes(&poll));
    assert!(sources.seal(&creator, registration.header()).is_err());
    let signing = creator.seal_complete().unwrap();
    let mut restored = Credential::open_complete(
        *creator.signing_public(),
        registration.body_digest(),
        &signing.key,
        &signing.bytes,
    )
    .unwrap();
    assert!(SourceSeeds::create(&poll, &mut restored, |_, _| Ok(())).is_err());
    let mut reopened =
        SourceSeeds::open(&poll, &restored, &registration, &sealed.key, &sealed.bytes).unwrap();
    let (_, _, other_poll) = create_poll_fixture(3, 2, 54);
    assert!(reopened.package(&other_poll, profile).is_err());
    assert!(
        reopened
            .package(&poll, Profile::new(4, 2).unwrap())
            .is_err()
    );
    assert_eq!(
        reopened
            .package(&poll, profile)
            .unwrap()
            .public()
            .ciphertext_records()
            .unwrap()
            .concat(),
        staged
    );
    assert!(reopened.seal(&restored, registration.header()).is_err());
    assert!(SourceSeeds::open(&poll, &restored, &registration, &sealed.key, &[]).is_err());
    let mut changed = sealed.bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(SourceSeeds::open(&poll, &restored, &registration, &sealed.key, &changed).is_err());
    let mut wrong_key = *sealed.key;
    wrong_key[0] ^= 1;
    assert!(SourceSeeds::open(&poll, &restored, &registration, &wrong_key, &sealed.bytes).is_err());
    let unrelated = Credential::from_seed([52; 64]);
    assert!(
        SourceSeeds::open(&poll, &unrelated, &registration, &sealed.key, &sealed.bytes).is_err()
    );
    // An internally authenticated but different seed is still insufficient:
    // reconstruction must reproduce the source bound by the signed record.
    let mut plaintext = b"ESC1".to_vec();
    plaintext.extend([0; 64]);
    let mut associated = b"sealed-lattice/encrypted-source-custody/v1".to_vec();
    associated.extend(registration.body_digest());
    let different = parallel_work::sealing::seal(&plaintext, &associated);
    let mismatch = SourceSeeds::open(
        &poll,
        &restored,
        &registration,
        &different.key,
        &different.bytes,
    )
    .unwrap();
    assert!(mismatch.package(&poll, profile).is_err());
    let mut failed_owner = Credential::from_seed([53; 64]);
    assert!(SourceSeeds::create(&poll, &mut failed_owner, |_, _| Err(Refusal::Crypto)).is_err());
    assert!(SourceSeeds::create(&poll, &mut failed_owner, |_, _| Ok(())).is_err());
    println!(
        "Source custody: original seed replay accepted; missing, changed, wrong-owner and replacement state refused; maximum staged source chunk {maximum_chunk}"
    );
}

#[test]
fn largest_roster_reopens_every_family_of_its_original_generated_source() {
    use protocol_foundations::source_seeds::SourceSeeds;
    let (creator, _, poll) = create_poll_fixture(20, 20, 61);
    let families = fhe_key_families(&poll).len();
    let source_total = 20 * families * ciphertext_bytes();
    let corpus_bound = source_total + 20 * (KEY_BYTES + 4096 + SIGNATURE_BYTES + 64) + 1_048_576;
    assert!(
        corpus_bound < 1 << 29,
        "Derive the bounded corpus before creating it."
    );
    let mut credentials = vec![creator];
    credentials.extend((1..20).map(|index| Credential::from_seed([61 + index; 64])));
    let mut records = Vec::new();
    let mut original_inventory = Vec::new();
    for (index, credential) in credentials.iter_mut().enumerate() {
        // Generate one owner's complete family bank. Other records need
        // canonical signed ciphertext inventories, not private witnesses,
        // to exercise the largest roster's public admission boundary.
        let mut staged = Vec::new();
        let generated = if index == 0 {
            Some(
                SourceSeeds::create(&poll, credential, |offset, bytes| {
                    assert_eq!(offset, staged.len());
                    assert!(bytes.len() <= CHUNK_LIMIT);
                    staged.extend_from_slice(bytes);
                    Ok(())
                })
                .unwrap(),
            )
        } else {
            staged = bodies(&poll, index as u8).concat();
            None
        };
        let recipient = setup_witness::registration::RecipientKey::new();
        let fixture = signed_fixture_with_key(
            &poll,
            credential,
            staged
                .chunks_exact(ciphertext_bytes())
                .map(|bytes| bytes.to_vec())
                .collect(),
            &format!("Participant {index}"),
            recipient.public_key_bytes(),
        );
        let registration = verify(&poll, &fixture, &staged, 65_537).unwrap();
        if let Some(source) = generated {
            assert_eq!(source.bindings(), registration.header().source_bindings);
            original_inventory = staged;
        }
        records.push(Arc::new(registration));
    }
    assert_eq!(original_inventory.len(), families * ciphertext_bytes());
    let mut nonzero_ranges = 0;
    for count in 3..=20 {
        let proposal = RosterProposal::new(&poll, records[..count].to_vec()).unwrap();
        let range = proposal.source_ciphertext_range();
        nonzero_ranges += usize::from(range.start != 0);
        let mut reopened = source_verifier(&poll, &records[0], proposal.profile()).unwrap();
        for bytes in original_inventory[range].chunks(65_537) {
            reopened.push(bytes).unwrap();
        }
        reopened.finish().unwrap();
    }
    assert!(nonzero_ranges > 0);
    let proposal = RosterProposal::new(&poll, records).unwrap();
    assert_eq!(proposal.profile(), Profile::new(20, 20).unwrap());
    let signature = credentials[0].sign_roster_proposal(&proposal).unwrap();
    authenticate_roster_proposal(proposal, &signature).unwrap();
}
