use super::super::schemas::SchemaResult;
use super::super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, DistributionPurpose, FOUNDATION_PROFILE,
    Hash512, ParticipantIdentity, RefusalReason, hash_foundation_tuple_512 as hash512,
};
use super::stream::sample_modulo_from_byte_source;
use super::*;
use zeroize::Zeroizing;

fn hash(fill: u8) -> Hash512 {
    Hash512::from_bytes([fill; Hash512::BYTE_LENGTH])
}

fn fixed_lowercase_hex<const BYTE_LENGTH: usize>(value: &str) -> [u8; BYTE_LENGTH] {
    assert_eq!(value.len(), BYTE_LENGTH * 2);
    let mut output = [0u8; BYTE_LENGTH];
    for (byte_index, hexadecimal_pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let decode_digit = |digit: u8| match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => panic!("test vector must use lowercase hexadecimal"),
        };
        output[byte_index] =
            (decode_digit(hexadecimal_pair[0]) << 4) | decode_digit(hexadecimal_pair[1]);
    }
    output
}

fn participant_identity() -> ParticipantIdentity {
    ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH])
}

fn derivation_input() -> ActionRandomnessDerivationInput {
    ActionRandomnessDerivationInput::new(hash(0x11), hash(0x22), hash(0x33), participant_identity())
}

fn action_randomness() -> ActionPrivateRandomness {
    ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
        [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
    ))
    .derive(derivation_input())
    .expect("fixed action randomness derives")
}

fn witness_bound_persistent_attempt_identifier(
    action_randomness: &ActionPrivateRandomness,
    input: &PersistentProofCoinInput,
    canonical_witness: &[u8],
) -> PrivateRandomnessAttemptIdentifier {
    let mut binding = action_randomness
        .begin_persistent_proof_witness_coin_binding(input)
        .expect("persistent witness binding starts");
    binding
        .absorb_canonical_bytes(b"sealed-lattice/test/canonical-semantic-witness/v1")
        .expect("test witness domain is absorbed");
    binding
        .absorb_canonical_bytes(canonical_witness)
        .expect("test witness is absorbed");
    binding.finish().expect("persistent attempt derives")
}

fn persistent_slot() -> ProofApplicationSlot {
    ProofApplicationSlot::new(
        hash(0x11),
        hash(0x22),
        hash(0x33),
        0x1211,
        Some(2),
        None,
        None,
    )
    .expect("persistent application slot")
}

fn ordinary_slot() -> ProofApplicationSlot {
    ProofApplicationSlot::new(
        hash(0x11),
        hash(0x22),
        hash(0x33),
        ORDINARY_BALLOT_PROOF_FAMILY,
        Some(2),
        None,
        Some(19),
    )
    .expect("ordinary application slot")
}

#[test]
fn canonical_private_randomness_inputs_round_trip() {
    let limits = CanonicalDecodeLimits::default();
    let derivation = derivation_input();
    assert_eq!(
        ActionRandomnessDerivationInput::decode(
            &derivation.encode().expect("derivation input encodes"),
            &limits,
        )
        .expect("derivation input decodes"),
        derivation,
    );

    let persistent = PersistentProofCoinInput::new(persistent_slot(), hash(0x66))
        .expect("persistent proof coin input");
    assert_eq!(
        PersistentProofCoinInput::decode(
            &persistent.encode().expect("persistent input encodes"),
            &limits,
        )
        .expect("persistent input decodes"),
        persistent,
    );

    let ordinary = OrdinaryProofCoinInput::new(ordinary_slot(), hash(0x77), [0x88; 32])
        .expect("ordinary proof coin input");
    assert_eq!(
        OrdinaryProofCoinInput::decode(
            &ordinary.encode().expect("ordinary input encodes"),
            &limits,
        )
        .expect("ordinary input decodes"),
        ordinary,
    );

    let action_randomness = action_randomness();
    let domain = PrivateRandomnessDomain::setup_source(4).expect("block domain");
    let block_input = PrivateRandomBlockInput::new(
        derivation,
        domain,
        hash(0x99),
        action_randomness.setup_attempt_identifier(),
        u64::MAX,
    )
    .expect("block input");
    assert_eq!(
        PrivateRandomBlockInput::decode(
            &block_input.encode().expect("block input encodes"),
            &limits,
        )
        .expect("block input decodes"),
        block_input,
    );

    let mut unsupported_version_tuple = CanonicalTuple::decode(
        &derivation.encode().expect("derivation input encodes"),
        &limits,
    )
    .expect("derivation tuple decodes");
    unsupported_version_tuple.items[0] = CanonicalItem::unsigned16(2);
    let error = ActionRandomnessDerivationInput::decode(
        &unsupported_version_tuple
            .encode()
            .expect("mutated tuple encodes"),
        &limits,
    )
    .expect_err("unsupported protocol version refuses");
    assert_eq!(
        error.refusal_reason,
        RefusalReason::UnsupportedVersionOrSuite
    );
}

#[test]
fn structured_commitment_opening_context_is_canonical_and_binds_every_coordinate() {
    let limits = CanonicalDecodeLimits::default();
    let baseline = SetupStructuredCommitmentOpeningContext::new(hash(0x91), 1, 11, 1)
        .expect("assigned structured-commitment opening context");
    let encoded = baseline.encode().expect("opening context encodes");
    assert_eq!(
        SetupStructuredCommitmentOpeningContext::decode(&encoded, &limits)
            .expect("opening context decodes"),
        baseline,
    );
    assert_eq!(baseline.source_setup_intent_object_hash(), hash(0x91));
    assert_eq!(baseline.commitment_data_prime_index(), 1);
    assert_eq!(baseline.distribution_purpose(), 11);
    assert_eq!(baseline.component_ordinal(), 1);

    let baseline_hash = baseline.hash().expect("opening context hashes");
    for changed in [
        SetupStructuredCommitmentOpeningContext::new(hash(0x92), 1, 11, 1),
        SetupStructuredCommitmentOpeningContext::new(hash(0x91), 2, 11, 1),
        SetupStructuredCommitmentOpeningContext::new(hash(0x91), 1, 12, 0),
        SetupStructuredCommitmentOpeningContext::new(hash(0x91), 1, 11, 0),
    ] {
        assert_ne!(
            changed
                .expect("changed opening context remains assigned")
                .hash()
                .expect("changed opening context hashes"),
            baseline_hash,
        );
    }

    for (purpose, component_ordinal) in [(10, 0), (13, 0), (11, 2), (12, 1)] {
        assert_eq!(
            SetupStructuredCommitmentOpeningContext::new(
                hash(0x91),
                1,
                purpose,
                component_ordinal,
            )
            .expect_err("unassigned purpose or component refuses")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength,
        );
    }
}

#[test]
fn key_hierarchy_is_deterministic_and_bound_to_every_action_input() {
    let first = action_randomness();
    let second = action_randomness();
    assert_eq!(
        first.action_randomness_commitment(),
        second.action_randomness_commitment()
    );
    assert_eq!(
        first.setup_attempt_identifier(),
        second.setup_attempt_identifier()
    );

    for changed_input in [
        ActionRandomnessDerivationInput::new(
            hash(0x10),
            hash(0x22),
            hash(0x33),
            participant_identity(),
        ),
        ActionRandomnessDerivationInput::new(
            hash(0x11),
            hash(0x20),
            hash(0x33),
            participant_identity(),
        ),
        ActionRandomnessDerivationInput::new(
            hash(0x11),
            hash(0x22),
            hash(0x30),
            participant_identity(),
        ),
        ActionRandomnessDerivationInput::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            ParticipantIdentity::from_bytes([0x45; ParticipantIdentity::BYTE_LENGTH]),
        ),
    ] {
        let changed = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(changed_input)
        .expect("changed input derives");
        assert_ne!(
            first.action_randomness_commitment(),
            changed.action_randomness_commitment()
        );
        assert_ne!(
            first.setup_attempt_identifier(),
            changed.setup_attempt_identifier()
        );
    }

    let changed_root = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
        [0x5b; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
    ))
    .derive(derivation_input())
    .expect("changed root derives");
    assert_ne!(
        first.action_randomness_commitment(),
        changed_root.action_randomness_commitment()
    );
}

#[test]
fn setup_action_randomness_authorization_binds_commitment_roster_and_action_scope() {
    let randomness = action_randomness();
    let roster_hash = hash(0x55);
    let expected = hash512(
        SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN,
        &[
            CanonicalItem::hash512(hash(0x11).into_bytes()),
            CanonicalItem::hash512(hash(0x22).into_bytes()),
            CanonicalItem::hash512(hash(0x33).into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::participant_identity(participant_identity().into_bytes()),
            CanonicalItem::hash512(randomness.action_randomness_commitment().into_bytes()),
        ],
    )
    .expect("authorization tuple hashes");
    assert_eq!(
        randomness
            .setup_action_randomness_authorization(roster_hash)
            .expect("authorization derives"),
        expected,
    );
    assert_ne!(
        randomness
            .setup_action_randomness_authorization(hash(0x56))
            .expect("changed roster authorization derives"),
        expected,
    );

    let changed_root = ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
        [0x5b; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
    ))
    .derive(derivation_input())
    .expect("changed root derives");
    assert_ne!(
        changed_root
            .setup_action_randomness_authorization(roster_hash)
            .expect("changed commitment authorization derives"),
        expected,
    );
}

#[test]
fn key_hierarchy_and_first_stream_block_match_independent_kmac_vector() {
    let action_randomness = action_randomness();
    assert_eq!(
        action_randomness
            .action_randomness_commitment()
            .into_bytes(),
        fixed_lowercase_hex(concat!(
            "358a1f0d923ca0ee03d6a5ddd4dd1bcd49c1c0d71e66e3e82e575097aba76d5f",
            "ce106820325f0459528e341511ebacfb872a42d6ae7e2e1ed5ab12b3b079d12e",
        ))
    );
    let setup_attempt = action_randomness.setup_attempt_identifier();
    assert_eq!(
        *setup_attempt.as_bytes(),
        fixed_lowercase_hex("d04f89c8ec54e88bd6d9dddfe1cff886dc8f51bc6d486f719915c2f0e686d85f")
    );

    let mut stream = action_randomness
        .begin_stream(
            PrivateRandomnessDomain::setup_source(2).expect("assigned setup-source domain"),
            hash(0xa1),
            setup_attempt,
        )
        .expect("stream starts");
    let mut first_block = [0u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH];
    stream
        .fill_bytes(&mut first_block)
        .expect("first block derives");
    assert_eq!(
        first_block,
        fixed_lowercase_hex(concat!(
            "279d21339244bcf46f55e87b5b364187170959fe8314b76cf65f4587ef79603a",
            "8536eba7788ab52c3d4648805519feec7f147da13c574d9189cfc75558fd662a",
        ))
    );
    assert_eq!(stream.cursor().next_counter(), 1);
    assert_eq!(
        stream.cursor().next_unread_bit_offset_in_buffered_block(),
        None
    );
}

#[test]
fn attempt_identifiers_bind_attempt_kind_statement_witness_and_nonce() {
    let action_randomness = action_randomness();
    let persistent =
        PersistentProofCoinInput::new(persistent_slot(), hash(0x66)).expect("persistent input");
    let changed_statement = PersistentProofCoinInput::new(persistent_slot(), hash(0x67))
        .expect("changed persistent input");
    assert_ne!(
        witness_bound_persistent_attempt_identifier(
            &action_randomness,
            &persistent,
            b"first canonical witness",
        ),
        witness_bound_persistent_attempt_identifier(
            &action_randomness,
            &changed_statement,
            b"first canonical witness",
        ),
    );
    assert_ne!(
        witness_bound_persistent_attempt_identifier(
            &action_randomness,
            &persistent,
            b"first canonical witness",
        ),
        witness_bound_persistent_attempt_identifier(
            &action_randomness,
            &persistent,
            b"second canonical witness",
        ),
    );

    let ordinary = OrdinaryProofCoinInput::new(ordinary_slot(), hash(0x66), [0x70; 32])
        .expect("ordinary input");
    let retried = OrdinaryProofCoinInput::new(ordinary_slot(), hash(0x66), [0x71; 32])
        .expect("ordinary retry input");
    assert_ne!(
        action_randomness
            .ordinary_proof_attempt_identifier(&ordinary)
            .expect("ordinary attempt"),
        action_randomness
            .ordinary_proof_attempt_identifier(&retried)
            .expect("ordinary retry attempt"),
    );

    let target_slot = ProofApplicationSlot::new(
        hash(0x11),
        hash(0x22),
        hash(0x33),
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        Some(2),
        None,
        None,
    )
    .expect("target application slot");
    let target_attempt = action_randomness
        .target_release_attempt_identifier(target_slot)
        .expect("target attempt");
    let changed_target_slot = ProofApplicationSlot::new(
        hash(0x11),
        hash(0x22),
        hash(0x33),
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        Some(3),
        None,
        None,
    )
    .expect("changed target application slot");
    assert_ne!(
        target_attempt,
        action_randomness
            .target_release_attempt_identifier(changed_target_slot)
            .expect("changed target attempt")
    );
    assert!(
        action_randomness
            .begin_stream(
                PrivateRandomnessDomain::target_flooding(1).expect("target domain"),
                hash(0x81),
                target_attempt,
            )
            .is_ok()
    );

    let persistent_attempt = witness_bound_persistent_attempt_identifier(
        &action_randomness,
        &persistent,
        b"first canonical witness",
    );
    let mismatch = action_randomness
        .begin_stream(
            PrivateRandomnessDomain::setup_source(1).expect("setup domain"),
            hash(0x82),
            persistent_attempt,
        )
        .expect_err("proof attempt cannot select a setup stream");
    assert_eq!(mismatch.refusal_reason, RefusalReason::WrongContext);

    let ballot_attempt = action_randomness.ballot_encryption_attempt_identifier(Zeroizing::new(
        [0x91; PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    ));
    assert!(
        action_randomness
            .begin_stream(
                PrivateRandomnessDomain::ballot_encryption_distribution(8).expect("ballot domain"),
                hash(0x83),
                ballot_attempt,
            )
            .is_ok()
    );
    assert_eq!(
        action_randomness
            .begin_stream(
                PrivateRandomnessDomain::setup_suite_distribution(1)
                    .expect("setup distribution domain"),
                hash(0x83),
                ballot_attempt,
            )
            .expect_err("ballot attempt cannot select a setup distribution stream")
            .refusal_reason,
        RefusalReason::WrongContext,
    );
}

#[test]
fn stream_resume_preserves_exact_byte_and_bit_suffixes() {
    let action_randomness = action_randomness();
    let domain = PrivateRandomnessDomain::setup_source(2).expect("assigned domain");
    let context = hash(0xa1);
    let attempt = action_randomness.setup_attempt_identifier();

    let mut uninterrupted = action_randomness
        .begin_stream(domain, context, attempt)
        .expect("stream starts");
    let mut prefix = [0u8; 61];
    uninterrupted
        .fill_bytes(&mut prefix)
        .expect("prefix samples");
    let byte_cursor = uninterrupted.cursor();
    let mut expected_suffix = [0u8; 79];
    uninterrupted
        .fill_bytes(&mut expected_suffix)
        .expect("suffix samples");

    let mut resumed = action_randomness
        .resume_stream(domain, context, attempt, byte_cursor)
        .expect("byte cursor resumes");
    let mut resumed_suffix = [0u8; 79];
    resumed
        .fill_bytes(&mut resumed_suffix)
        .expect("resumed suffix samples");
    assert_eq!(resumed_suffix, expected_suffix);
    assert_eq!(resumed.cursor(), uninterrupted.cursor());

    let mut bit_stream = action_randomness
        .begin_stream(domain, context, attempt)
        .expect("bit stream starts");
    for _ in 0..509 {
        bit_stream.sample_bit().expect("prefix bit samples");
    }
    let bit_cursor = bit_stream.cursor();
    let expected_bits = (0..70)
        .map(|_| bit_stream.sample_bit().expect("suffix bit samples"))
        .collect::<Vec<_>>();
    let mut resumed_bits = action_randomness
        .resume_stream(domain, context, attempt, bit_cursor)
        .expect("bit cursor resumes");
    let actual_bits = (0..70)
        .map(|_| resumed_bits.sample_bit().expect("resumed bit samples"))
        .collect::<Vec<_>>();
    assert_eq!(actual_bits, expected_bits);
    assert_eq!(resumed_bits.cursor(), bit_stream.cursor());
}

#[test]
fn cursor_binding_misalignment_and_counter_exhaustion_refuse_without_consuming() {
    let action_randomness = action_randomness();
    let domain = PrivateRandomnessDomain::setup_source(1).expect("assigned domain");
    let context = hash(0xa2);
    let attempt = action_randomness.setup_attempt_identifier();
    let mut stream = action_randomness
        .begin_stream(domain, context, attempt)
        .expect("stream starts");
    stream.sample_bit().expect("one bit samples");
    let misaligned_cursor = stream.cursor();
    let mut output = [0u8; 1];
    let error = stream
        .fill_bytes(&mut output)
        .expect_err("byte sampling from a partial byte refuses");
    assert_eq!(error.refusal_reason, RefusalReason::ConsumedState);
    assert_eq!(stream.cursor(), misaligned_cursor);

    let wrong_context_error = action_randomness
        .resume_stream(domain, hash(0xa3), attempt, misaligned_cursor)
        .expect_err("wrong context refuses");
    assert_eq!(
        wrong_context_error.refusal_reason,
        RefusalReason::WrongContext
    );

    let exhausted_cursor = PrivateRandomCursor::new(
        domain.family(),
        domain.purpose(),
        context,
        *attempt.as_bytes(),
        u64::MAX,
        None,
    )
    .expect("boundary cursor is structurally valid");
    let mut exhausted_stream = action_randomness
        .resume_stream(domain, context, attempt, exhausted_cursor)
        .expect("boundary cursor resumes before another block is requested");
    let error = exhausted_stream
        .sample_bit()
        .expect_err("counter overflow refuses");
    assert_eq!(error.refusal_reason, RefusalReason::ConsumedState);
    assert_eq!(exhausted_stream.cursor(), exhausted_cursor);
}

#[test]
fn sampling_is_bounded_and_stays_in_exact_output_domains() {
    let action_randomness = action_randomness();
    let domain = PrivateRandomnessDomain::setup_source(2).expect("assigned domain");
    let attempt = action_randomness.setup_attempt_identifier();
    let mut modular_stream = action_randomness
        .begin_stream(domain, hash(0xb1), attempt)
        .expect("stream starts");

    for modulus in [2, 3, 5, 251, 256, 257, 65_537, u32::MAX as u64, u64::MAX] {
        for _ in 0..257 {
            let sample = modular_stream
                .sample_modulo(modulus, 64)
                .expect("fixed ceiling is ample for deterministic test stream");
            assert!(sample < modulus);
        }
    }

    let mut ternary_stream = action_randomness
        .begin_stream(domain, hash(0xb2), attempt)
        .expect("ternary stream starts");
    let mut binomial_stream = action_randomness
        .begin_stream(domain, hash(0xb3), attempt)
        .expect("binomial stream starts");
    for _ in 0..257 {
        assert!(matches!(
            ternary_stream
                .sample_centered_ternary(64)
                .expect("ternary sample succeeds"),
            -1..=1
        ));
        let centered_binomial = binomial_stream
            .sample_centered_binomial(7)
            .expect("centered-binomial sample succeeds");
        assert!((-7..=7).contains(&centered_binomial));
    }
    assert_eq!(
        modular_stream
            .sample_modulo(1, 64)
            .expect_err("unit modulus refuses")
            .refusal_reason,
        RefusalReason::WrongTypeOrLength,
    );
    assert_eq!(
        modular_stream
            .sample_modulo(3, 0)
            .expect_err("zero draw ceiling refuses")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile,
    );
}

#[test]
fn rejection_sampling_uses_exact_little_endian_candidates_and_hard_ceiling() {
    fn sample_from_bytes(
        source: &[u8],
        modulus: u64,
        maximum_draws: u32,
    ) -> (SchemaResult<u64>, usize) {
        let mut source_offset = 0usize;
        let result = sample_modulo_from_byte_source(modulus, maximum_draws, |candidate_bytes| {
            let source_end = source_offset + candidate_bytes.len();
            if source_end > source.len() {
                return Err(schema_error(
                    RefusalReason::MissingPrerequisite,
                    "test byte source is exhausted",
                ));
            }
            candidate_bytes.copy_from_slice(&source[source_offset..source_end]);
            source_offset = source_end;
            Ok(())
        });
        (result, source_offset)
    }

    let (sample, consumed) = sample_from_bytes(&[255, 254], 5, 2);
    assert_eq!(sample.expect("second one-byte candidate is accepted"), 4);
    assert_eq!(consumed, 2);

    let (exhausted, consumed) = sample_from_bytes(&[255, 0], 5, 1);
    assert_eq!(
        exhausted
            .expect_err("one rejected candidate exhausts a one-draw ceiling")
            .refusal_reason,
        RefusalReason::OutsideSupportedProfile,
    );
    assert_eq!(consumed, 1);

    let (sample, consumed) = sample_from_bytes(&[0xff, 0xff, 0x02, 0x01], 257, 2);
    assert_eq!(
        sample.expect("little-endian 65535 rejects and 258 accepts"),
        1
    );
    assert_eq!(consumed, 4);

    let mut maximum_width_candidates = [0xff; 16];
    maximum_width_candidates[8] = 0xfe;
    let (sample, consumed) = sample_from_bytes(&maximum_width_candidates, u64::MAX, 2);
    assert_eq!(
        sample.expect("maximum-width second candidate accepts"),
        u64::MAX - 1
    );
    assert_eq!(consumed, 16);
}

#[test]
fn proof_application_slots_enforce_closed_coordinate_shapes() {
    for (family, roster, schedule, producer) in [
        (0x1211, Some(0), None, None),
        (0x1214, Some(9), Some(0), None),
        (0x1213, None, None, None),
        (0x1215, None, Some(u32::MAX), None),
        (0x1218, None, None, None),
        (ORDINARY_BALLOT_PROOF_FAMILY, Some(1), None, Some(0)),
    ] {
        assert!(
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                family,
                roster,
                schedule,
                producer,
            )
            .is_ok()
        );
    }

    for (family, roster, schedule, producer) in [
        (0x1211, None, None, None),
        (0x1214, Some(0), None, None),
        (0x1213, Some(0), None, None),
        (0x1215, None, None, None),
        (0x1218, Some(0), None, None),
        (ORDINARY_BALLOT_PROOF_FAMILY, Some(0), None, None),
        (0xffff, None, None, None),
    ] {
        assert!(
            ProofApplicationSlot::new(
                hash(1),
                hash(2),
                hash(3),
                family,
                roster,
                schedule,
                producer,
            )
            .is_err()
        );
    }
    assert!(
        ProofApplicationSlot::new(
            hash(1),
            hash(2),
            hash(3),
            0x1211,
            Some(FOUNDATION_PROFILE.participant_count),
            None,
            None,
        )
        .is_err()
    );
}

#[test]
fn every_public_witness_family_has_only_private_construction_hiding_coins() {
    let action_randomness = action_randomness();
    let mut construction_attempt_identifiers = std::collections::BTreeSet::new();
    for (public_family, schedule_position) in [
        (
            ProofFamilyIdentifiers::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
        ),
        (
            ProofFamilyIdentifiers::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
        ),
        (
            ProofFamilyIdentifiers::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
        ),
    ] {
        let application_slot = ProofApplicationSlot::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            public_family,
            None,
            schedule_position,
            None,
        )
        .expect("the public-only family has one canonical slot shape");

        assert!(PrivateRandomnessDomain::reset_safe_proof(public_family, 4).is_ok());
        for forbidden_purpose in [1, 2, 3, PRIVATE_PROOF_SALT_PURPOSE] {
            assert!(
                PrivateRandomnessDomain::reset_safe_proof(public_family, forbidden_purpose)
                    .is_err()
            );
        }
        let input = PersistentProofCoinInput::new(application_slot, hash(4))
            .expect("the public-witness construction-hiding input is canonical");
        let construction_attempt_identifier = action_randomness
            .persistent_proof_preparation_identifier(&input)
            .expect("the private construction-hiding attempt derives");
        assert!(
            construction_attempt_identifiers.insert(*construction_attempt_identifier.as_bytes()),
            "each public-witness family must have a distinct construction-hiding attempt",
        );
        assert!(
            action_randomness
                .begin_persistent_proof_witness_coin_binding(&input)
                .is_err(),
            "a public relation must not acquire a private-witness binding",
        );
        let changed_statement_input = PersistentProofCoinInput::new(application_slot, hash(5))
            .expect("a changed public statement remains canonical");
        assert_ne!(
            construction_attempt_identifier,
            action_randomness
                .persistent_proof_preparation_identifier(&changed_statement_input)
                .expect("the changed construction-hiding attempt derives"),
        );
        assert_eq!(
            proof_attempt_identifier_derivation_count(public_family),
            Some(1)
        );
    }
    assert_eq!(
        PUBLIC_ONLY_PROOF_FAMILIES,
        ProofFamilyIdentifiers::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS,
    );

    for invalid_purpose in [0, 8, 9, 10, 13, u16::MAX] {
        assert!(PrivateRandomnessDomain::setup_suite_distribution(invalid_purpose).is_err());
    }
    assert!(PrivateRandomnessDomain::setup_mailbox(4).is_err());
    assert!(PrivateRandomnessDomain::setup_source(3).is_err());
    assert!(PrivateRandomnessDomain::target_flooding(0).is_err());
    assert!(PrivateRandomnessDomain::target_flooding(3).is_err());
    assert!(PrivateRandomnessDomain::reset_safe_proof(0x1211, 0x4000).is_err());
    assert!(PrivateRandomnessDomain::ordinary_proof(0x4000).is_err());
}

#[test]
fn ballot_encryption_distribution_accepts_exactly_purposes_eight_through_ten() {
    let assigned_purposes = [
        DistributionPurpose::BallotEncryptionEphemeralSecret.canonical_code(),
        DistributionPurpose::BallotEncryptionErrorZero.canonical_code(),
        DistributionPurpose::BallotEncryptionErrorOne.canonical_code(),
    ];
    for purpose in u16::MIN..=u16::MAX {
        assert_eq!(
            PrivateRandomnessDomain::ballot_encryption_distribution(purpose).is_ok(),
            assigned_purposes.contains(&purpose),
            "unexpected ballot-encryption purpose assignment for {purpose}",
        );
    }
}
