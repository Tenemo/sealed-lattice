use super::*;
use crate::{
    CHUNK_BYTES,
    aggregate_publisher::AggregatePublisher,
    published_aggregate::{PublishedAggregateVerifier, evaluation_role},
    verified::build_selection,
};
use num_bigint::BigInt;
use protocol_foundations::{
    BodyDigest,
    contribution_body::body_lengths,
    foundation::{
        RegistrationHeader, StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    identity::identity,
    poll::{PollDraft, verify_poll},
    registration::{KEY_BYTES, RegistrationVerifier},
    roster::{RetainedContributionContext, RosterProposal},
    roster_authentication::authenticate_roster_proposal,
    setup_selection::{AuthenticatedSelectionProposal, authenticate_selection},
};
use statement_stream::coefficient;
use std::collections::BTreeMap;
use supported_profile::relation::EVALUATION_HEADER_BYTES;
use word_proof::public_evaluation::EvaluationProver;

struct Fixture {
    poll: VerifiedPoll,
    credential: Credential,
    roster: Arc<AuthenticatedRosterProposal>,
    selection: Arc<AuthenticatedSelectionProposal>,
    offers: Vec<Arc<VerifiedContributionOffer>>,
}

fn source(profile: Profile, index: usize, position: usize) -> Vec<u8> {
    let width = 1 + profile.family_magnitude_bytes(profile.setup_family(index).unwrap());
    let mut bytes = vec![0; profile.setup_polynomial_bytes(index).unwrap()];
    for (coefficient, value) in [
        BigInt::from(position + index + 1),
        -BigInt::from(2 * position + index + 3),
        (BigInt::from(1) << 96usize) + BigInt::from(position + 5),
    ]
    .iter()
    .enumerate()
    {
        coefficient::encode(
            value,
            &mut bytes[coefficient * width..(coefficient + 1) * width],
        );
    }
    bytes
}

fn columns(profile: Profile, index: usize, position: usize) -> Vec<Vec<u128>> {
    let mut polynomial = CommittedPolynomial::new(profile);
    for bytes in source(profile, index, position).chunks(CHUNK_BYTES) {
        polynomial.push(bytes).unwrap();
    }
    polynomial.finish().unwrap()
}

fn fixture() -> Fixture {
    let profile = Profile::new(3, 2).unwrap();
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
    let mut credentials: Vec<_> = (1..=3)
        .map(|seed| Credential::from_seed([seed; 64]))
        .collect();
    let packet = credentials[0]
        .create_poll(
            PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2, 3).unwrap(),
            [21; 64],
            [22; 32],
        )
        .unwrap();
    let poll = verify_poll(packet.identity, [21; 64], &packet.body, &packet.signature).unwrap();
    let public_source = setup_witness::encrypted_source::PublicSource {
        polynomials: vec![
            vec![0; supported_profile::DEGREE];
            supported_profile::source_linked::SOURCE_POLYNOMIALS
        ],
    };
    let source_body = public_source.ciphertext_records().unwrap().concat();
    let mut records = Vec::new();
    for (position, credential) in credentials.iter_mut().enumerate() {
        let mut key = vec![0; KEY_BYTES];
        key[1] = position as u8 + 1;
        let header = RegistrationHeader {
            username: normalize_username(format!("Participant {position}").as_bytes()).unwrap(),
            poll: poll.identity(),
            signing_public: *credential.signing_public(),
            recipient_key_hash: parallel_work::ProtocolHash::digest(&key),
            source_bindings: protocol_foundations::source_binding::fhe_key_families(&poll)
                .iter().map(|family| public_source.binding(
                    *family, &poll.identity(),
                    protocol_foundations::foundation::participant_identity::derive_participant_identity(credential.signing_public()).unwrap().as_bytes(),
                ).unwrap()).collect(),
        }
        .encode()
        .unwrap();
        let signature = credential
            .sign_registration(BodyDigest::from_header(&header, poll.identity()).unwrap())
            .unwrap();
        let mut verifier = RegistrationVerifier::new(&poll, &header, &signature).unwrap();
        for part in key.chunks(CHUNK_BYTES) {
            verifier.push_key(part).unwrap();
        }
        verifier.finish_key().unwrap();
        for _ in protocol_foundations::source_binding::fhe_key_families(&poll) {
            for chunk in source_body.chunks(CHUNK_BYTES) {
                verifier.push_sources(chunk).unwrap();
            }
        }
        records.push(Arc::new(verifier.finish().unwrap()));
    }
    let proposal = RosterProposal::new(&poll, records).unwrap();
    let signature = credentials[0].sign_roster_proposal(&proposal).unwrap();
    let roster = Arc::new(authenticate_roster_proposal(proposal, &signature).unwrap());
    let mut offers = Vec::new();
    for (position, credential) in credentials.iter_mut().enumerate() {
        let context = RetainedContributionContext::parse(
            credential,
            &roster.proposal().records()[position],
            &poll,
            position,
            roster.proposal().body(),
        )
        .unwrap();
        credential.confirm_roster(&context).unwrap();
        if position >= profile.setup_contributors() {
            continue;
        }
        let envelope = OfferEnvelope::new(
            roster.proposal(),
            position,
            *body_lengths(profile).start(),
            [position as u8 + 30; 64],
        )
        .unwrap();
        let signature = credential.sign_offer(&context, &envelope).unwrap();
        let offer =
            Arc::new(authenticate_offer(roster.clone(), envelope.bytes(), &signature).unwrap());
        let role = roster.proposal().contribution_role(position).unwrap();
        let mut builder = PublicOracleBuilder::new(&role, profile.committed_columns()).unwrap();
        for index in profile.committed_polynomials() {
            for column in columns(profile, index, position) {
                builder.column(&column).unwrap();
            }
        }
        // The preceding contribution relation is isolated here. These
        // test-local predecessor results never enter an exported constructor;
        // the publisher and aggregate verifier still process all actual bytes.
        offers.push(Arc::new(VerifiedContributionOffer {
            offer,
            public_root: builder.finish().unwrap().root(),
            polynomials: profile
                .contribution_body_polynomials()
                .into_iter()
                .map(|index| {
                    let bytes = source(profile, index, position);
                    OfferPolynomial {
                        index,
                        bytes: bytes.len(),
                        digest: identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes).unwrap(),
                    }
                })
                .collect(),
        }));
    }
    let proposal = build_selection(&roster, &offers).unwrap();
    let signature = credentials[0]
        .sign_selection_proposal(&roster, &proposal)
        .unwrap();
    let selection =
        Arc::new(authenticate_selection(roster.clone(), proposal.body(), &signature).unwrap());
    Fixture {
        poll,
        credential: credentials.remove(0),
        roster,
        selection,
        offers,
    }
}

fn collect(
    publisher: &mut AggregatePublisher,
    offer: Arc<VerifiedContributionOffer>,
    sums: &mut BTreeMap<usize, Vec<u8>>,
) {
    let profile = offer.roster().proposal().profile();
    let position = offer.envelope().position();
    publisher.begin(offer).unwrap();
    for index in profile.contribution_body_polynomials() {
        let bytes = source(profile, index, position);
        let width = 1 + profile.family_magnitude_bytes(profile.setup_family(index).unwrap());
        let chunk = CHUNK_BYTES / width * width;
        let mut output = Vec::new();
        for (ordinal, bytes) in bytes.chunks(chunk).enumerate() {
            let length = publisher.output_bytes(index, bytes.len()).unwrap();
            let mut part = sums.get(&index).map_or_else(
                || vec![0; length],
                |sum| sum[output.len()..output.len() + length].to_vec(),
            );
            publisher
                .polynomial(index, ordinal * chunk, bytes, &mut part)
                .unwrap();
            output.extend(part);
        }
        sums.insert(index, output);
    }
    publisher.finish_offer().unwrap();
}

fn stream_sums(
    verifier: &mut PublishedAggregateVerifier,
    sums: &BTreeMap<usize, Vec<u8>>,
    profile: Profile,
) -> BTreeMap<usize, Vec<u8>> {
    let mut normalized = BTreeMap::new();
    for index in profile.committed_polynomials() {
        let mut value = Vec::new();
        let mut output = Vec::new();
        // Deliberately split a signed limb as well as a coefficient.
        let chunk = CHUNK_BYTES - 3;
        for (ordinal, bytes) in sums[&index].chunks(chunk).enumerate() {
            verifier
                .polynomial(index, ordinal * chunk, bytes, &mut output)
                .unwrap();
            value.extend_from_slice(&output);
        }
        normalized.insert(index, value);
    }
    normalized
}

fn proof(fixture: &Fixture, aggregate: &[u8; 64], ordinal: usize) -> Vec<u8> {
    let profile = fixture.roster.proposal().profile();
    let roots: Vec<_> = fixture
        .offers
        .iter()
        .map(|offer| *offer.public_root())
        .collect();
    let role = fixture
        .roster
        .proposal()
        .contribution_role(ordinal)
        .unwrap();
    let mut prover = EvaluationProver::new(
        profile,
        &evaluation_role(&fixture.selection),
        aggregate,
        &roots,
        ordinal,
        &role,
    )
    .unwrap();
    for index in profile.committed_polynomials() {
        for column in columns(profile, index, ordinal) {
            prover.column(&column).unwrap();
        }
    }
    prover.finish_columns().unwrap();
    for index in profile.committed_polynomials() {
        for column in columns(profile, index, ordinal) {
            prover.opening_column(&column).unwrap();
        }
    }
    prover.finish_openings().unwrap();
    let mut proof = Vec::new();
    let mut output = Vec::new();
    while prover.next_output(&mut output).unwrap() {
        proof.extend_from_slice(&output);
    }
    proof
}

#[test]
fn published_aggregate_checks_resumed_sums_every_evaluation_and_normalized_bytes() {
    let fixture = fixture();
    let profile = fixture.roster.proposal().profile();
    let mut publisher = AggregatePublisher::new(fixture.roster.clone());
    assert!(
        publisher
            .retain(&fixture.credential, &fixture.poll)
            .is_err()
    );
    let mut sums = BTreeMap::new();
    // Discovery order differs from the signed selected order.
    for offer in fixture.offers.iter().rev() {
        collect(&mut publisher, offer.clone(), &mut sums);
        let retained = publisher
            .retain(&fixture.credential, &fixture.poll)
            .unwrap();
        let mut changed = retained.clone();
        changed[2] ^= 1;
        assert!(
            AggregatePublisher::restore(
                &fixture.credential,
                &fixture.poll,
                fixture.roster.clone(),
                &changed
            )
            .is_err()
        );
        publisher = AggregatePublisher::restore(
            &fixture.credential,
            &fixture.poll,
            fixture.roster.clone(),
            &retained,
        )
        .unwrap();
    }
    assert_eq!(publisher.accepted(), profile.setup_contributors());
    assert!(publisher.begin(fixture.offers[0].clone()).is_err());
    let (manifest, streamed) = publisher.finish(fixture.selection.clone()).unwrap();
    let open = || PublishedAggregateVerifier::new(streamed.clone(), &manifest.encode()).unwrap();
    assert!(open().finish().is_err());
    let mut verifier = open();
    assert!(
        verifier
            .retain_data(&fixture.credential, &fixture.poll)
            .is_err()
    );
    assert!(
        verifier
            .begin_evaluation(0, &vec![0; EVALUATION_HEADER_BYTES])
            .is_err()
    );
    let normalized = stream_sums(&mut verifier, &sums, profile);
    let retained = verifier
        .retain_data(&fixture.credential, &fixture.poll)
        .unwrap();
    let mut restored = open();
    let mut changed = retained.clone();
    changed[64] ^= 1;
    assert!(
        restored
            .restore_data(&fixture.credential, &fixture.poll, &changed)
            .is_err()
    );
    assert!(
        restored
            .restore_data(&Credential::from_seed([99; 64]), &fixture.poll, &retained)
            .is_err()
    );
    restored
        .restore_data(&fixture.credential, &fixture.poll, &retained)
        .unwrap();
    for ordinal in 0..fixture.offers.len() {
        let proof = proof(&fixture, manifest.identity(), ordinal);
        assert!(
            restored
                .begin_evaluation(ordinal + 1, &proof[..EVALUATION_HEADER_BYTES])
                .is_err()
        );
        // A bad proof must not advance or poison the same ordinal.
        restored
            .begin_evaluation(ordinal, &proof[..EVALUATION_HEADER_BYTES])
            .unwrap();
        assert!(restored.finish_evaluation().is_err());
        restored
            .begin_evaluation(ordinal, &proof[..EVALUATION_HEADER_BYTES])
            .unwrap();
        let mut damaged = proof[EVALUATION_HEADER_BYTES..].to_vec();
        damaged[8] ^= 1;
        assert!(
            damaged
                .chunks(CHUNK_BYTES)
                .try_for_each(|part| restored.proof(part))
                .is_err()
        );
        assert!(restored.finish_evaluation().is_err());
        restored
            .begin_evaluation(ordinal, &proof[..EVALUATION_HEADER_BYTES])
            .unwrap();
        for part in proof[EVALUATION_HEADER_BYTES..].chunks(CHUNK_BYTES) {
            restored.proof(part).unwrap();
        }
        restored.finish_evaluation().unwrap();
    }
    let verified = restored.finish().unwrap();
    verifier.check_cache(&verified).unwrap();
    for polynomial in verified.polynomials() {
        let actual = normalized
            .get(&polynomial.index())
            .unwrap_or(&sums[&polynomial.index()]);
        let mut expected = vec![0; profile.setup_polynomial_bytes(polynomial.index()).unwrap()];
        let width =
            1 + profile.family_magnitude_bytes(profile.setup_family(polynomial.index()).unwrap());
        for (coefficient, record) in expected.chunks_exact_mut(width).take(3).enumerate() {
            let value: BigInt = (0..profile.setup_contributors())
                .map(|position| {
                    let source = source(profile, polynomial.index(), position);
                    let record = &source[coefficient * width..(coefficient + 1) * width];
                    let value = BigInt::from_bytes_le(num_bigint::Sign::Plus, &record[1..]);
                    if record[0] == 1 { -value } else { value }
                })
                .sum();
            coefficient::encode(&value, record);
        }
        assert_eq!(actual, &expected);
        assert_eq!(
            polynomial.digest(),
            &identity(PUBLIC_POLYNOMIAL_DOMAIN, &expected).unwrap()
        );
    }
    for (index, offset, bytes) in [
        (profile.committed_polynomials()[0], 1, vec![0]),
        (
            profile.committed_polynomials()[0],
            0,
            vec![0; CHUNK_BYTES + 1],
        ),
        (profile.streamed_contribution_polynomials()[0], 0, vec![0]),
    ] {
        let mut refused = open();
        let mut output = vec![1];
        assert!(
            refused
                .polynomial(index, offset, &bytes, &mut output)
                .is_err()
        );
        assert!(output.is_empty());
        assert!(refused.finish().is_err());
    }
    let mut wrong_digest = open();
    let index = profile.committed_polynomials()[0];
    let mut changed = sums[&index].clone();
    changed[0] ^= 1;
    let mut output = Vec::new();
    assert!(
        changed
            .chunks(CHUNK_BYTES)
            .enumerate()
            .try_for_each(|(ordinal, bytes)| wrong_digest.polynomial(
                index,
                ordinal * CHUNK_BYTES,
                bytes,
                &mut output
            ))
            .is_err()
    );
    assert!(wrong_digest.finish().is_err());
    let mut wrong_manifest = manifest.encode();
    wrong_manifest[0] = 0;
    assert!(PublishedAggregateVerifier::new(streamed, &wrong_manifest).is_err());
}

#[test]
fn aggregate_publisher_refuses_missing_duplicate_replayed_and_changed_sources() {
    let fixture = fixture();
    let profile = fixture.roster.proposal().profile();
    let mut publisher = AggregatePublisher::new(fixture.roster.clone());
    let mut sums = BTreeMap::new();
    collect(&mut publisher, fixture.offers[0].clone(), &mut sums);
    assert!(publisher.begin(fixture.offers[0].clone()).is_err());
    let retained = publisher
        .retain(&fixture.credential, &fixture.poll)
        .unwrap();
    assert!(publisher.finish(fixture.selection.clone()).is_err());
    let index = profile.contribution_body_polynomials()[0];
    let source = source(profile, index, 1);
    let width = 1 + profile.family_magnitude_bytes(profile.setup_family(index).unwrap());
    for changed_previous in [false, true] {
        let mut publisher = AggregatePublisher::restore(
            &fixture.credential,
            &fixture.poll,
            fixture.roster.clone(),
            &retained,
        )
        .unwrap();
        publisher.begin(fixture.offers[1].clone()).unwrap();
        let mut incoming = source.clone();
        let mut previous = sums[&index].clone();
        if changed_previous {
            previous[1] ^= 1;
        } else {
            incoming[1] ^= 1;
        }
        let chunk = CHUNK_BYTES / width * width;
        assert!(
            incoming
                .chunks(chunk)
                .enumerate()
                .try_for_each(|(ordinal, bytes)| publisher.polynomial(
                    index,
                    ordinal * chunk,
                    bytes,
                    &mut previous[ordinal * chunk..ordinal * chunk + bytes.len()]
                ))
                .is_err()
        );
        assert!(publisher.finish_offer().is_err());
        assert!(
            publisher
                .retain(&fixture.credential, &fixture.poll)
                .is_err()
        );
    }
    let mut publisher = AggregatePublisher::restore(
        &fixture.credential,
        &fixture.poll,
        fixture.roster,
        &retained,
    )
    .unwrap();
    publisher.begin(fixture.offers[1].clone()).unwrap();
    assert!(
        publisher
            .polynomial(index, width, &source[..width], &mut vec![0; width])
            .is_err()
    );
    assert!(publisher.finish_offer().is_err());
}
