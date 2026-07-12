use super::super::LINCHECK_REPETITIONS;
use super::super::SAME_SECRET_BRIDGE_PROOF_FAMILY;
use super::super::relation::{
    SameSecretBridgeStatement, SameSecretLinkageStatement, SuccinctSetupProofFamilyShape,
    TrusteeEvaluationKeyWitness,
};
use super::*;
use crate::bgv::setup::commitment::compute_setup_commitment_for_tests;
use crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn same_secret_bridge_source_commitments_must_be_complete_and_canonically_ordered() {
    let (mut missing_limb, _witness) = same_secret_bridge_instance();
    missing_limb
        .same_secret_linkage
        .as_mut()
        .expect("source linkage")
        .commitments
        .pop();
    assert!(
        missing_limb.validate_shape().is_err(),
        "a bridge must include every source data-basis limb"
    );

    let (mut duplicate_limb, _witness) = same_secret_bridge_instance();
    let linkage = duplicate_limb
        .same_secret_linkage
        .as_mut()
        .expect("source linkage");
    linkage.commitments[1] = linkage.commitments[0].clone();
    assert!(
        duplicate_limb.validate_shape().is_err(),
        "a duplicated source limb must not satisfy canonical coverage"
    );

    let (mut reordered_limbs, _witness) = same_secret_bridge_instance();
    reordered_limbs
        .same_secret_linkage
        .as_mut()
        .expect("source linkage")
        .commitments
        .swap(0, 1);
    assert!(
        reordered_limbs.validate_shape().is_err(),
        "source limbs must remain in canonical data-basis order"
    );
}

#[test]
fn same_secret_bridge_physical_columns_are_disjoint_and_in_range() {
    let (statement, _witness) = same_secret_bridge_instance();
    let layout = LimbColumnLayout::new(&statement, 0).expect("bridge layout");
    let mut physical_positions = Vec::new();

    for half in 0..super::super::TRACE_SPLIT {
        physical_positions.push(layout.physical_secret(half));
        physical_positions.push(layout.physical_negative_indicator(half));
    }
    for target_index in 0..layout.same_secret_bridge_target_count() {
        let encoding_column_count = (0..layout.same_secret_bridge_message_encoding_columns())
            .filter(|encoding_column| {
                layout
                    .same_secret_bridge_message_position_for_encoding_column(*encoding_column)
                    .is_some_and(|(mapped_target_index, _)| mapped_target_index == target_index)
            })
            .count();
        for encoding_column in 0..encoding_column_count {
            for half in 0..super::super::TRACE_SPLIT {
                physical_positions.push(layout.physical_same_secret_bridge_message(
                    target_index,
                    encoding_column,
                    half,
                ));
            }
        }
    }
    for randomness_position in 0..layout.linkage_randomness_columns {
        for half in 0..super::super::TRACE_SPLIT {
            physical_positions.push(layout.physical_linkage_randomness(randomness_position, half));
        }
    }
    for mask_column in 0..layout.mask_column_count {
        for half in 0..super::super::TRACE_SPLIT {
            physical_positions.push(layout.physical_mask(mask_column, half));
        }
    }

    assert_eq!(
        physical_positions.len(),
        layout.phase_one_physical_count(),
        "the bridge layout audit must cover every phase-one physical column"
    );
    assert!(
        physical_positions
            .iter()
            .all(|position| *position < layout.phase_one_physical_count()),
        "every physical column must stay inside the phase-one commitment"
    );
    assert_eq!(
        physical_positions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        physical_positions.len(),
        "secret, indicator, target, source-randomness, and mask columns must be pairwise disjoint"
    );
}

#[test]
fn same_secret_bridge_row_kernel_rejects_nonternary_source_randomness() {
    let (statement, _witness) = same_secret_bridge_instance();
    let layout = LimbColumnLayout::new(&statement, 0).expect("bridge layout");
    let tower = super::super::extension_field::ChallengeExtensionTower::for_modulus(DATA_PRIMES[0])
        .expect("challenge extension tower");
    let domain = super::super::relation::BaseColumnDomain { tower };
    let mut column_values = vec![0_u64; layout.phase_one_physical_count()];
    let material_values = vec![0_u64; layout.vss_committed_material_physical_count()];
    let beta = vec![
        super::super::extension_field::ChallengeExtensionTower::one();
        layout.row_check_constraint_count()
    ];
    assert_eq!(
        super::super::relation::batched_row_check_value(
            &domain,
            &column_values,
            &material_values,
            &beta,
            &layout,
        ),
        super::super::extension_field::ChallengeExtensionTower::zero(),
        "the all-zero bridge row must satisfy every local constraint"
    );

    column_values[layout.physical_linkage_randomness(0, 0)] = 2;
    assert_ne!(
        super::super::relation::batched_row_check_value(
            &domain,
            &column_values,
            &material_values,
            &beta,
            &layout,
        ),
        super::super::extension_field::ChallengeExtensionTower::zero(),
        "the row kernel itself must reject nonternary source randomness"
    );
}

#[test]
fn same_secret_bridge_and_source_linkage_use_independent_alpha_domains() {
    let (statement, _witness) = same_secret_bridge_instance();
    let layout = LimbColumnLayout::new(&statement, 0).expect("bridge layout");
    let modulus = DATA_PRIMES[0];
    let mut transcript =
        super::super::fiat_shamir_transcript::FiatShamirTranscript::new("bridge-alpha-test");
    let challenges = super::super::prover::draw_limb_challenges(&mut transcript, &layout, modulus);
    assert_eq!(
        challenges.same_secret_bridge_alpha.len(),
        layout.same_secret_bridge_relation_count(),
        "target bridge alpha count must match every target and decoder relation"
    );
    assert_eq!(
        challenges.linkage_alpha.len(),
        layout.linkage_relation_count(),
        "source-linkage alpha count must match every canonical source row"
    );

    let comparison_count = challenges
        .same_secret_bridge_alpha
        .len()
        .min(challenges.linkage_alpha.len());
    assert_ne!(
        &challenges.same_secret_bridge_alpha[..comparison_count],
        &challenges.linkage_alpha[..comparison_count],
        "source and target relations must not reuse one alpha stream"
    );

    let mut target_domain_transcript =
        super::super::fiat_shamir_transcript::FiatShamirTranscript::new("alpha-domain-test");
    let target_domain = target_domain_transcript.challenge_extension_elements(
        "same-secret-bridge-alpha",
        modulus,
        comparison_count,
    );
    let mut source_domain_transcript =
        super::super::fiat_shamir_transcript::FiatShamirTranscript::new("alpha-domain-test");
    let source_domain = source_domain_transcript.challenge_extension_elements(
        "same-secret-source-linkage-alpha",
        modulus,
        comparison_count,
    );
    assert_ne!(
        target_domain, source_domain,
        "the Fiat-Shamir labels must domain-separate source and target alpha challenges"
    );
}

#[test]
fn same_secret_bridge_proof_round_trips_and_rejects_tampering() {
    let (statement, witness) = same_secret_bridge_instance();
    assert_eq!(
        statement
            .same_secret_bridge
            .as_ref()
            .expect("bridge statement")
            .bridge_rns_primes
            .len(),
        7,
        "bridge fixture should exercise a nontrivial Q_share prefix"
    );
    let layout = LimbColumnLayout::new(&statement, 0).expect("bridge layout");
    let bridge_digit_count = layout.same_secret_bridge_target_count()
        * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
    assert_eq!(
        layout.same_secret_bridge_decoder_digit_count(),
        bridge_digit_count,
        "bridge target-message digits must carry verifier-side decoder rows"
    );
    assert!(
        layout.same_secret_bridge_message_encoding_columns() > bridge_digit_count,
        "bridge target messages must carry digit and trit columns"
    );
    assert_eq!(
        layout.consistency_vector_count(),
        2 + bridge_digit_count + layout.linkage_randomness_columns,
        "bridge consistency claims must bind the secret, indicator, target digits, and randomness"
    );
    assert_eq!(
        layout.same_secret_bridge_relation_count(),
        layout.same_secret_bridge_target_count() * LINCHECK_REPETITIONS
            + layout.same_secret_bridge_decoder_digit_count() * LINCHECK_REPETITIONS,
        "bridge relation challenges must include the bridge lincheck and decoder rows"
    );
    assert_eq!(
        layout.linkage_relation_count(),
        DATA_PRIMES.len() * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS,
        "bridge source-linkage challenges must cover every source commitment row"
    );
    let last_target_index = layout.same_secret_bridge_target_count() - 1;
    let last_target_encoding_column = layout.same_secret_bridge_message_encoding_columns() - 1;
    let (last_target_for_encoding_column, last_local_encoding_column) = layout
        .same_secret_bridge_message_position_for_encoding_column(last_target_encoding_column)
        .expect("last bridge message encoding column");
    assert_eq!(last_target_for_encoding_column, last_target_index);
    assert!(
        layout.physical_linkage_randomness(0, 0)
            > layout.physical_same_secret_bridge_message(
                last_target_for_encoding_column,
                last_local_encoding_column,
                super::super::TRACE_SPLIT - 1,
            ),
        "source randomness columns must follow every target message column without overlap"
    );
    assert_eq!(
        layout.same_secret_bridge_logical_columns(),
        2 + layout.same_secret_bridge_message_encoding_columns()
            + layout.linkage_randomness_columns,
    );
    assert!(
        layout.same_secret_bridge_message_trit_count(0, 0) > 0,
        "bridge target messages must carry trit decoder columns"
    );
    let later_commitment_limb_layout =
        LimbColumnLayout::new(&statement, 1).expect("bridge second limb layout");
    assert_eq!(
        later_commitment_limb_layout.same_secret_bridge_relation_count(),
        layout.same_secret_bridge_relation_count(),
        "bridge commitment limbs should use the same decoder-backed relation"
    );
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");

    verify_evaluation_key_share(&statement, &proof).expect("verify same-secret bridge");

    let (invalid_secret_statement, mut invalid_secret_witness) = same_secret_bridge_instance();
    invalid_secret_witness.secret_coefficients[0] = 1;
    invalid_secret_witness.negative_indicator_coefficients[0] = 0;
    assert!(
        prove_evaluation_key_share(
            &invalid_secret_statement,
            &invalid_secret_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a secret that no longer opens the target constants"
    );

    let (non_binary_statement, mut non_binary_witness) = same_secret_bridge_instance();
    non_binary_witness.negative_indicator_coefficients[1] = 2;
    assert!(
        prove_evaluation_key_share(
            &non_binary_statement,
            &non_binary_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "proving must reject a non-binary negative indicator"
    );

    let (non_ternary_opening_statement, mut non_ternary_opening_witness) =
        same_secret_bridge_instance();
    non_ternary_opening_witness.opening_randomness_by_limb[0][0][0] = 2;
    assert!(
        prove_evaluation_key_share(
            &non_ternary_opening_statement,
            &non_ternary_opening_witness,
            PROOF_RANDOMNESS_SEED,
        )
        .is_err(),
        "proving must reject non-ternary source-commitment opening randomness"
    );

    let (mut tampered_statement, _unused_witness) = same_secret_bridge_instance();
    tampered_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_constant_commitments[0]
        .material_roots_by_commitment_field[0][0] ^= 0x01;

    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with the published target constant material root must reject"
    );

    let (mut tampered_source_statement, _unused_witness) = same_secret_bridge_instance();
    let source_row = &mut tampered_source_statement
        .same_secret_linkage
        .as_mut()
        .expect("source linkage")
        .commitments[0]
        .limbs[0]
        .rows[0];
    source_row[0] = (source_row[0] + 1) % DATA_PRIMES[0];
    assert!(
        verify_evaluation_key_share(&tampered_source_statement, &proof).is_err(),
        "tampering with a canonical source commitment body must reject"
    );

    let (mut unexpected_context_statement, _unused_witness) = same_secret_bridge_instance();
    unexpected_context_statement
        .context
        .binding_roots
        .push(("unexpectedBridgeBinding".to_string(), repeated_hash("ab")));
    assert!(
        unexpected_context_statement.validate_shape().is_err(),
        "the standalone bridge context must carry exactly zero binding roots"
    );

    let (mut changed_setup_statement, _unused_witness) = same_secret_bridge_instance();
    changed_setup_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .setup_parameters_hash = repeated_hash("c1");
    changed_setup_statement
        .validate_shape()
        .expect("a different well-formed setup hash remains structurally valid");
    assert!(
        verify_evaluation_key_share(&changed_setup_statement, &proof).is_err(),
        "the same-secret bridge proof must bind setupParametersHash"
    );
}

#[test]
fn public_key_share_proof_round_trips_with_same_secret_bridge() {
    let (statement, witness) =
        generate_development_public_key_share_instance("c0ffee01", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let (statement, witness) =
        attach_same_secret_bridge_to_key_statement(statement, witness, DATA_PRIMES.len());

    assert_eq!(
        statement.family_shape().expect("statement shape"),
        SuccinctSetupProofFamilyShape::PublicKeyShare
    );
    assert!(
        statement.same_secret_linkage.is_none(),
        "public-key share must use the same-secret bridge"
    );
    assert!(
        statement.same_secret_bridge.is_some(),
        "public-key share must carry bridge material"
    );
    assert_eq!(statement.limb_count(), DATA_PRIMES.len());

    let setup_field_layout =
        LimbColumnLayout::new(&statement, 0).expect("public-key setup-field layout");
    assert!(setup_field_layout.same_secret_bridge_material_active());
    let bridge_digit_count = DATA_PRIMES.len() * VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
    assert_eq!(
        setup_field_layout.consistency_vector_count(),
        1 + statement.keys[0].digit_count()
            + 1
            + bridge_digit_count
            + setup_field_layout.linkage_randomness_columns,
        "setup commitment fields must claim key errors and bridge witnesses together"
    );
    assert_eq!(
        setup_field_layout.same_secret_bridge_relation_count(),
        DATA_PRIMES.len() * LINCHECK_REPETITIONS
            + setup_field_layout.same_secret_bridge_decoder_digit_count() * LINCHECK_REPETITIONS,
    );

    let key_only_limb_index = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
    assert!(
        key_only_limb_index < DATA_PRIMES.len(),
        "the public-key share fixture should exercise key-only limbs after setup commitment fields"
    );
    let key_only_layout =
        LimbColumnLayout::new(&statement, key_only_limb_index).expect("public-key key-only layout");
    assert!(!key_only_layout.same_secret_bridge_material_active());
    assert_eq!(key_only_layout.linkage_randomness_columns, 0);
    assert_eq!(
        key_only_layout.consistency_vector_count(),
        1 + statement.keys[0].digit_count(),
        "later public-key limbs should carry only the key relation claims"
    );

    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify public-key share");

    let mut tampered_statement = statement;
    tampered_statement
        .same_secret_bridge
        .as_mut()
        .expect("bridge statement")
        .target_constant_commitments[0]
        .material_roots_by_commitment_field[0][0] ^= 0x01;
    assert!(
        verify_evaluation_key_share(&tampered_statement, &proof).is_err(),
        "tampering with bridge material must reject the public-key share proof"
    );
}

pub(super) fn same_secret_bridge_instance() -> (
    TrusteeEvaluationKeyStatement,
    super::super::relation::TrusteeEvaluationKeyWitness,
) {
    let ring_degree = SMALL_RING_DEGREE;
    let public_matrix_seed_hash = repeated_hash("cd");
    let setup_parameters_hash = repeated_hash("bc");
    let bridge_rns_limb_count = 7_usize;
    let bridge_rns_primes = DATA_PRIMES[..bridge_rns_limb_count].to_vec();
    let secret_coefficients = (0..ring_degree)
        .map(|coefficient_index| match coefficient_index % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect::<Vec<_>>();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();

    let target_constant_material = bridge_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, target_rns_prime)| {
            let message_coefficients = bridge_message_coefficients(
                &secret_coefficients,
                &negative_indicator_coefficients,
                *target_rns_prime,
            );
            test_committed_material_commitment(
                "coefficient",
                json!({
                    "testPurpose": "same-secret-bridge-proof",
                    "targetRnsLimbIndex": target_rns_limb_index,
                }),
                target_rns_limb_index,
                *target_rns_prime,
                ring_degree,
                &message_coefficients,
                *target_rns_prime,
            )
        })
        .collect::<Vec<_>>();
    let target_constant_commitments = target_constant_material
        .iter()
        .map(|material| material.commitment.clone())
        .collect::<Vec<_>>();
    let opening_randomness_by_limb = source_opening_randomness_by_limb(ring_degree);
    let source_constant_commitments = DATA_PRIMES
        .iter()
        .enumerate()
        .map(|(source_rns_limb_index, source_rns_prime)| {
            let source_message_coefficients = bridge_message_coefficients(
                &secret_coefficients,
                &negative_indicator_coefficients,
                *source_rns_prime,
            )
            .into_iter()
            .map(u128::from)
            .collect::<Vec<_>>();
            let randomness = opening_randomness_by_limb[source_rns_limb_index]
                .iter()
                .map(|column| column.iter().copied().map(i128::from).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            compute_setup_commitment_for_tests(
                &public_matrix_seed_hash,
                source_rns_limb_index,
                *source_rns_prime,
                0,
                &source_message_coefficients,
                &randomness,
                ring_degree,
            )
            .expect("source constant commitment")
        })
        .collect::<Vec<_>>();

    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: SAME_SECRET_BRIDGE_PROOF_FAMILY.to_string(),
            ceremony_id: "bridge-proof-test".to_string(),
            manifest_hash: repeated_hash("11"),
            roster_hash: repeated_hash("22"),
            trustee_identity: "trustee-0".to_string(),
            trustee_roster_position: 0,
            setup_epoch: "setup-epoch-1".to_string(),
            binding_roots: Vec::new(),
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: Some(SameSecretLinkageStatement {
            public_matrix_seed_hash: public_matrix_seed_hash.clone(),
            commitments: source_constant_commitments,
        }),
        private_vss_share: None,
        vss_share_linkage: None,
        same_secret_bridge: Some(SameSecretBridgeStatement {
            public_matrix_seed_hash,
            source_trustee_identity: "trustee-0".to_string(),
            source_trustee_roster_position: 0,
            setup_parameters_hash,
            bridge_rns_primes,
            target_constant_commitment_roots: (0..bridge_rns_limb_count)
                .map(|target_rns_limb_index| {
                    repeated_hash(&format!("{:02x}", 0xd0 + target_rns_limb_index))
                })
                .collect(),
            target_constant_commitments,
        }),
        target_decryption_share: None,
    };
    statement
        .validate_shape()
        .expect("same-secret bridge statement");

    let witness = super::super::relation::TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key: Vec::new(),
        negative_indicator_coefficients,
        opening_randomness_by_limb,
        private_vss_coefficient_messages_by_shamir_index: Vec::new(),
        private_vss_opening_randomness_by_shamir_index: Vec::new(),
        private_vss_carry_witnesses: Vec::new(),
        vss_public_coefficient_messages_by_shamir_index: Vec::new(),
        vss_public_recipient_share_messages: Vec::new(),
        vss_public_coefficient_opening_randomness_by_shamir_index: Vec::new(),
        vss_public_recipient_share_opening_randomness: Vec::new(),
        vss_public_carry_witnesses: Vec::new(),
        vss_public_recipient_share_messages_by_item: Vec::new(),
        vss_public_recipient_share_opening_randomness_by_item: Vec::new(),
        vss_public_carry_witnesses_by_item: Vec::new(),
        target_decryption_message_vectors: Vec::new(),
        target_decryption_opening_randomness_by_commitment: Vec::new(),
        vss_committed_material_seeds_by_bound_message: target_constant_material
            .iter()
            .map(|material| material.material_seed_hex.clone())
            .collect(),
        vss_committed_material_context_hashes_by_bound_message: target_constant_material
            .iter()
            .map(|material| material.context_hash.clone())
            .collect(),
    };

    (statement, witness)
}

fn source_opening_randomness_by_limb(ring_degree: usize) -> Vec<Vec<Vec<i64>>> {
    DATA_PRIMES
        .iter()
        .enumerate()
        .map(|(source_rns_limb_index, _)| {
            (0..crate::bgv::setup::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column| {
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            match (source_rns_limb_index + randomness_column + coefficient_index)
                                % 3
                            {
                                0 => -1,
                                1 => 0,
                                _ => 1,
                            }
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn attach_same_secret_bridge_to_key_statement(
    mut statement: TrusteeEvaluationKeyStatement,
    mut witness: TrusteeEvaluationKeyWitness,
    bridge_rns_limb_count: usize,
) -> (TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness) {
    assert!((1..=DATA_PRIMES.len()).contains(&bridge_rns_limb_count));
    let public_matrix_seed_hash = statement
        .same_secret_linkage
        .as_ref()
        .map(|linkage| linkage.public_matrix_seed_hash.clone())
        .unwrap_or_else(|| repeated_hash("cd"));
    let setup_parameters_hash = repeated_hash("bc");
    let bridge_rns_primes = DATA_PRIMES[..bridge_rns_limb_count].to_vec();
    let target_constant_material = bridge_rns_primes
        .iter()
        .enumerate()
        .map(|(target_rns_limb_index, target_rns_prime)| {
            let message_coefficients = bridge_message_coefficients(
                &witness.secret_coefficients,
                &witness.negative_indicator_coefficients,
                *target_rns_prime,
            );
            test_committed_material_commitment(
                "coefficient",
                json!({
                    "testPurpose": "same-secret-bridge-key-attach",
                    "targetRnsLimbIndex": target_rns_limb_index,
                }),
                target_rns_limb_index,
                *target_rns_prime,
                statement.ring_degree,
                &message_coefficients,
                *target_rns_prime,
            )
        })
        .collect::<Vec<_>>();
    let target_constant_commitments = target_constant_material
        .iter()
        .map(|material| material.commitment.clone())
        .collect::<Vec<_>>();

    statement.same_secret_linkage = None;
    statement.same_secret_bridge = Some(SameSecretBridgeStatement {
        public_matrix_seed_hash,
        source_trustee_identity: statement.context.trustee_identity.clone(),
        source_trustee_roster_position: statement.context.trustee_roster_position,
        setup_parameters_hash,
        bridge_rns_primes,
        target_constant_commitment_roots: (0..bridge_rns_limb_count)
            .map(|target_rns_limb_index| {
                repeated_hash(&format!("{:02x}", 0xe0 + target_rns_limb_index))
            })
            .collect(),
        target_constant_commitments,
    });
    witness.opening_randomness_by_limb = Vec::new();
    witness.vss_committed_material_seeds_by_bound_message = target_constant_material
        .iter()
        .map(|material| material.material_seed_hex.clone())
        .collect();
    witness.vss_committed_material_context_hashes_by_bound_message = target_constant_material
        .iter()
        .map(|material| material.context_hash.clone())
        .collect();
    statement.validate_shape().expect("key statement shape");

    (statement, witness)
}

fn bridge_message_coefficients(
    secret_coefficients: &[i64],
    negative_indicator_coefficients: &[i64],
    target_rns_prime: u64,
) -> Vec<u64> {
    secret_coefficients
        .iter()
        .zip(negative_indicator_coefficients.iter())
        .map(|(secret_coefficient, negative_indicator)| {
            let lifted = i128::from(*secret_coefficient)
                + i128::from(*negative_indicator) * i128::from(target_rns_prime);
            u64::try_from(lifted).expect("bridge message is canonical")
        })
        .collect()
}
