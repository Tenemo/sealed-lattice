use super::super::semantic_execution::{
    SemanticFactorOneMoveDescriptor, SemanticVerifierMoveOwner, SemanticVerifierMoveStatement,
};
use super::super::semantic_outer::{
    SemanticCrossEpochDisclosures, SemanticProductionOuterCommitments,
    SemanticProductionOuterLayout,
};
use super::super::semantic_whir::{
    SemanticWhirBaseFreshMessage, SemanticWhirBasePreCombinationWitness, SemanticWhirBasePrefix,
    SemanticWhirBaseQueryChallenges, SemanticWhirBaseStatement, SemanticWhirCodeSwitchPrefix,
    SemanticWhirCodeSwitchStatement, SemanticWhirMaskedSumcheckPrefix,
    SemanticWhirMaskedSumcheckStatement, SemanticWhirOpeningBatchingPrefix,
    semantic_whir_base_input_pair, semantic_whir_code_switch_kstate,
    semantic_whir_code_switch_output_pair, semantic_whir_masked_sumcheck_kstate,
    semantic_whir_masked_sumcheck_output_pair, semantic_whir_opening_output_pair,
};
use super::*;
use crate::bgv::proof_suite::ProofBaseFieldElement;
use crate::bgv::proof_suite::compact_cfw::{
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_MATRIX_COUNT,
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwMatrixRole, PreparedCompactCfwProver,
    compact_challenge_from_production,
};
use p3_field::PrimeCharacteristicRing;

fn field(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(value).expect("small canonical field element"),
    )
}

fn lookup_challenge() -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
        .expect("the extension indeterminate is canonical")
        .add(field(7))
}

fn committed_code_relation(
    message_length: u64,
    hiding_randomness_length: u64,
    block_length: u64,
    interleaving_width: u64,
) -> CommittedCodeRelation {
    CommittedCodeRelation {
        message_length,
        hiding_randomness_length,
        block_length,
        interleaving_width,
    }
}

fn code_fixture(
    relation: &CommittedCodeRelation,
    message_columns: Vec<Vec<ProofChallengeExtensionElement>>,
    first_randomness_value: u64,
) -> (SemanticCommittedCodeInstance, SemanticCommittedCodeWitness) {
    let interleaving_width = usize::try_from(relation.interleaving_width).unwrap();
    let hiding_randomness_length = usize::try_from(relation.hiding_randomness_length).unwrap();
    assert_eq!(message_columns.len(), interleaving_width);
    let hiding_randomness_columns = (0..interleaving_width)
        .map(|column_ordinal| {
            (0..hiding_randomness_length)
                .map(|coefficient_ordinal| {
                    field(
                        first_randomness_value
                            + u64::try_from(column_ordinal * 17 + coefficient_ordinal).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let witness = SemanticCommittedCodeWitness {
        message_columns,
        hiding_randomness_columns,
    };
    let received_rows = encode_canonical_interleaved_reed_solomon(
        semantic_code_geometry(relation).unwrap(),
        &witness.coefficient_columns(relation).unwrap(),
    )
    .unwrap();
    (SemanticCommittedCodeInstance { received_rows }, witness)
}

fn claim_for_witness(
    witness: &SemanticGeneralizedRelationWitness,
) -> SemanticGeneralizedLinearClaim {
    let source_message = witness.source.flattened_messages();
    let mask_messages = witness
        .masks
        .iter()
        .map(SemanticCommittedCodeWitness::flattened_messages)
        .collect::<Vec<_>>();
    let source_covector = vec![field(2); source_message.len()];
    let mask_covectors = mask_messages
        .iter()
        .map(|message| vec![field(3); message.len()])
        .collect::<Vec<_>>();
    let mut claim = SemanticGeneralizedLinearClaim {
        source_covector,
        mask_covectors,
        target: ProofChallengeExtensionElement::ZERO,
    };
    claim.target = evaluate_linear_claim(&claim, witness);
    claim
}

fn evaluate_linear_claim(
    claim: &SemanticGeneralizedLinearClaim,
    witness: &SemanticGeneralizedRelationWitness,
) -> ProofChallengeExtensionElement {
    let source_message = witness.source.flattened_messages();
    let mask_messages = witness
        .masks
        .iter()
        .map(SemanticCommittedCodeWitness::flattened_messages)
        .collect::<Vec<_>>();
    claim
        .source_covector
        .iter()
        .zip(&source_message)
        .map(|(coefficient, value)| coefficient.multiply(*value))
        .chain(
            claim
                .mask_covectors
                .iter()
                .zip(&mask_messages)
                .flat_map(|(covector, message)| {
                    covector
                        .iter()
                        .zip(message)
                        .map(|(coefficient, value)| coefficient.multiply(*value))
                }),
        )
        .fold(ProofChallengeExtensionElement::ZERO, |sum, value| {
            sum.add(value)
        })
}

fn combine_committed_witnesses(
    fresh: &SemanticCommittedCodeWitness,
    input: &SemanticCommittedCodeWitness,
    challenge: ProofChallengeExtensionElement,
) -> SemanticCommittedCodeWitness {
    let combine_columns =
        |fresh_columns: &[Vec<ProofChallengeExtensionElement>],
         input_columns: &[Vec<ProofChallengeExtensionElement>]| {
            fresh_columns
                .iter()
                .zip(input_columns)
                .map(|(fresh, input)| {
                    fresh
                        .iter()
                        .zip(input)
                        .map(|(&fresh, &input)| fresh.add(challenge.multiply(input)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
    SemanticCommittedCodeWitness {
        message_columns: combine_columns(&fresh.message_columns, &input.message_columns),
        hiding_randomness_columns: combine_columns(
            &fresh.hiding_randomness_columns,
            &input.hiding_randomness_columns,
        ),
    }
}

fn combine_generalized_witnesses(
    fresh: &SemanticGeneralizedRelationWitness,
    input: &SemanticGeneralizedRelationWitness,
    challenge: ProofChallengeExtensionElement,
) -> SemanticGeneralizedRelationWitness {
    SemanticGeneralizedRelationWitness {
        source: combine_committed_witnesses(&fresh.source, &input.source, challenge),
        masks: fresh
            .masks
            .iter()
            .zip(&input.masks)
            .map(|(fresh, input)| combine_committed_witnesses(fresh, input, challenge))
            .collect(),
    }
}

struct BaseFixture {
    statement: SemanticWhirBaseStatement,
    fresh_message: SemanticWhirBaseFreshMessage,
    input_witness: SemanticGeneralizedRelationWitness,
    fresh_witness: SemanticGeneralizedRelationWitness,
    blinded_witness: SemanticGeneralizedRelationWitness,
    combination_challenge: ProofChallengeExtensionElement,
}

fn base_fixture(
    statement: SemanticWhirBaseStatement,
    input_witness: SemanticGeneralizedRelationWitness,
) -> BaseFixture {
    let (_, input_instance) = semantic_whir_base_input_pair(&statement);
    let fresh_witness = input_witness.clone();
    let claim = input_instance
        .carried_reduction_claims
        .first()
        .expect("the base statement has one carried claim");
    let masked_claim = evaluate_linear_claim(claim, &fresh_witness);
    let fresh_message = SemanticWhirBaseFreshMessage {
        source: input_instance.source.clone(),
        masks: input_instance.masks.clone(),
        masked_claim,
    };
    let combination_challenge = field(97);
    let blinded_witness =
        combine_generalized_witnesses(&fresh_witness, &input_witness, combination_challenge);
    BaseFixture {
        statement,
        fresh_message,
        input_witness,
        fresh_witness,
        blinded_witness,
        combination_challenge,
    }
}

fn fresh_base_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        fresh_message: Some(fixture.fresh_message.clone()),
        combination_challenge: None,
        revealed_witness: None,
        query_challenges: None,
    }
}

fn combination_base_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        combination_challenge: Some(fixture.combination_challenge),
        ..fresh_base_prefix(fixture)
    }
}

fn revealed_base_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        revealed_witness: Some(fixture.blinded_witness.clone()),
        ..combination_base_prefix(fixture)
    }
}

fn full_base_prefix(fixture: &BaseFixture) -> SemanticWhirBasePrefix {
    SemanticWhirBasePrefix {
        query_challenges: Some(SemanticWhirBaseQueryChallenges {
            source_positions: vec![0, 4],
            mask_group_positions: vec![vec![1, 5]; fixture.fresh_message.masks.len()],
        }),
        ..revealed_base_prefix(fixture)
    }
}

struct EpochFixture {
    history: SemanticWhirEpochHistory,
    base: BaseFixture,
    first_masked_combination_witness: SemanticGeneralizedRelationWitness,
    verifier_moves: Vec<EpochVerifierMoveFixture>,
}

#[derive(Clone)]
enum EpochVerifierMoveOwner {
    MaskedSumcheckCombination {
        batch_ordinal: u8,
    },
    Folding {
        batch_ordinal: u8,
        round_ordinal: u8,
    },
    CodeSwitch {
        round_ordinal: u8,
    },
    BaseCombination,
}

impl EpochVerifierMoveOwner {
    fn with_epoch(&self, epoch: TranscriptEpoch) -> SemanticVerifierMoveOwner {
        match *self {
            Self::MaskedSumcheckCombination { batch_ordinal } => {
                SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
                    epoch,
                    batch_ordinal,
                }
            }
            Self::Folding {
                batch_ordinal,
                round_ordinal,
            } => SemanticVerifierMoveOwner::WhirFolding {
                epoch,
                batch_ordinal,
                round_ordinal,
            },
            Self::CodeSwitch { round_ordinal } => SemanticVerifierMoveOwner::WhirCodeSwitch {
                epoch,
                round_ordinal,
            },
            Self::BaseCombination => SemanticVerifierMoveOwner::WhirBaseCombination { epoch },
        }
    }
}

#[derive(Clone)]
enum EpochVerifierMoveStatement {
    MaskedSumcheck(SemanticWhirMaskedSumcheckStatement),
    CodeSwitch(SemanticWhirCodeSwitchStatement),
    Base(SemanticWhirBaseStatement),
}

impl EpochVerifierMoveStatement {
    fn as_semantic_statement(
        &self,
    ) -> SemanticVerifierMoveStatement<'_, '_, SixtyFourElementR1csMatrices> {
        match self {
            Self::MaskedSumcheck(statement) => {
                SemanticVerifierMoveStatement::WhirMaskedSumcheck(statement)
            }
            Self::CodeSwitch(statement) => SemanticVerifierMoveStatement::WhirCodeSwitch(statement),
            Self::Base(statement) => SemanticVerifierMoveStatement::WhirBase(statement),
        }
    }
}

#[derive(Clone)]
struct EpochVerifierMoveFixture {
    owner: EpochVerifierMoveOwner,
    statement: EpochVerifierMoveStatement,
    history: SemanticWhirEpochHistory,
    preceding_prefix: SemanticVerifierMovePrefix,
    extended_prefix: SemanticVerifierMovePrefix,
    predecessor_witness: SemanticConstructionWhirWitness,
    post_challenge_witness: SemanticConstructionWhirWitness,
}

fn zero_message_columns(
    relation: &CommittedCodeRelation,
) -> Vec<Vec<ProofChallengeExtensionElement>> {
    vec![
        vec![
            ProofChallengeExtensionElement::ZERO;
            usize::try_from(relation.message_length).unwrap()
        ];
        usize::try_from(relation.interleaving_width).unwrap()
    ]
}

fn fold_source_at_zero(
    source: &SemanticCommittedCodeWitness,
    round_count: usize,
) -> SemanticCommittedCodeWitness {
    let mut folded = source.clone();
    for _ in 0..round_count {
        let half_width = folded.message_columns.len() / 2;
        assert!(half_width > 0);
        folded.message_columns.truncate(half_width);
        folded.hiding_randomness_columns.truncate(half_width);
    }
    folded
}

fn epoch_fixture(
    opening: &SemanticWhirOpeningBatchingStatement,
    input_witness: SemanticGeneralizedRelationWitness,
) -> EpochFixture {
    let opening_prefix = SemanticWhirOpeningBatchingPrefix {
        batching_challenge: Some(ProofChallengeExtensionElement::ZERO),
    };
    let (mut relation, mut instance) =
        semantic_whir_opening_output_pair(opening, &opening_prefix).unwrap();
    let mut witness = input_witness;
    let mut completed_components = Vec::new();
    let mut first_masked_combination_witness = None;
    let mut verifier_moves = Vec::new();

    for batch_ordinal in 0..=u8::try_from(WHIR_ROUND_COUNT).unwrap() {
        let history_before_masked_sumcheck = SemanticWhirEpochHistory {
            opening_prefix,
            completed_components: completed_components.clone(),
        };
        let source_width = usize::try_from(relation.source_code.interleaving_width).unwrap();
        assert!(source_width >= 2 && source_width.is_power_of_two());
        let folding_factor = source_width.ilog2() as usize;
        let sumcheck_mask_relation = CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirSumcheck { batch_ordinal },
            code: committed_code_relation(4, 1, 16, u64::try_from(folding_factor).unwrap()),
        };
        let (sumcheck_mask_instance, sumcheck_mask_witness) = code_fixture(
            &sumcheck_mask_relation.code,
            zero_message_columns(&sumcheck_mask_relation.code),
            10_000 + u64::from(batch_ordinal) * 101,
        );
        let statement = SemanticWhirMaskedSumcheckStatement::new(
            relation,
            instance,
            sumcheck_mask_relation,
            sumcheck_mask_instance,
        )
        .unwrap();
        let completed_prefix = SemanticWhirMaskedSumcheckPrefix {
            mask_hypercube_sum: ProofChallengeExtensionElement::ZERO,
            combining_challenge: Some(ProofChallengeExtensionElement::ZERO),
            round_wires: vec![
                vec![
                    ProofChallengeExtensionElement::ZERO;
                    statement.wire_coefficient_count()
                ];
                folding_factor
            ],
            round_challenges: vec![ProofChallengeExtensionElement::ZERO; folding_factor],
        };
        let input_witness = witness.clone();
        let combination_witness = SemanticGeneralizedRelationWitness {
            source: input_witness.source.clone(),
            masks: witness
                .masks
                .iter()
                .cloned()
                .chain(core::iter::once(sumcheck_mask_witness))
                .collect(),
        };
        first_masked_combination_witness.get_or_insert_with(|| combination_witness.clone());
        let combination_prefix = SemanticWhirMaskedSumcheckPrefix {
            mask_hypercube_sum: completed_prefix.mask_hypercube_sum,
            combining_challenge: completed_prefix.combining_challenge,
            round_wires: Vec::new(),
            round_challenges: Vec::new(),
        };
        let mut preceding_combination_prefix = combination_prefix.clone();
        preceding_combination_prefix.combining_challenge = None;
        verifier_moves.push(EpochVerifierMoveFixture {
            owner: EpochVerifierMoveOwner::MaskedSumcheckCombination { batch_ordinal },
            statement: EpochVerifierMoveStatement::MaskedSumcheck(statement.clone()),
            history: history_before_masked_sumcheck.clone(),
            preceding_prefix: SemanticVerifierMovePrefix::WhirMaskedSumcheck(
                preceding_combination_prefix,
            ),
            extended_prefix: SemanticVerifierMovePrefix::WhirMaskedSumcheck(
                combination_prefix.clone(),
            ),
            predecessor_witness: SemanticConstructionWhirWitness::Generalized(input_witness),
            post_challenge_witness: SemanticConstructionWhirWitness::Generalized(
                combination_witness.clone(),
            ),
        });

        let mut incremental_prefix = combination_prefix;
        let mut folding_witness = combination_witness;
        for round_ordinal in 0..folding_factor {
            incremental_prefix
                .round_wires
                .push(completed_prefix.round_wires[round_ordinal].clone());
            let preceding_prefix = incremental_prefix.clone();
            incremental_prefix
                .round_challenges
                .push(completed_prefix.round_challenges[round_ordinal]);
            let post_challenge_witness = SemanticGeneralizedRelationWitness {
                source: fold_source_at_zero(&folding_witness.source, 1),
                masks: folding_witness.masks.clone(),
            };
            verifier_moves.push(EpochVerifierMoveFixture {
                owner: EpochVerifierMoveOwner::Folding {
                    batch_ordinal,
                    round_ordinal: u8::try_from(round_ordinal).unwrap(),
                },
                statement: EpochVerifierMoveStatement::MaskedSumcheck(statement.clone()),
                history: history_before_masked_sumcheck.clone(),
                preceding_prefix: SemanticVerifierMovePrefix::WhirMaskedSumcheck(preceding_prefix),
                extended_prefix: SemanticVerifierMovePrefix::WhirMaskedSumcheck(
                    incremental_prefix.clone(),
                ),
                predecessor_witness: SemanticConstructionWhirWitness::Generalized(folding_witness),
                post_challenge_witness: SemanticConstructionWhirWitness::Generalized(
                    post_challenge_witness.clone(),
                ),
            });
            folding_witness = post_challenge_witness;
        }
        assert_eq!(incremental_prefix, completed_prefix);
        witness = folding_witness;
        assert!(
            semantic_whir_masked_sumcheck_kstate(&statement, Some(&completed_prefix), &witness,)
                .unwrap()
        );
        (relation, instance) =
            semantic_whir_masked_sumcheck_output_pair(&statement, &completed_prefix).unwrap();
        completed_components.push(SemanticWhirCompletedComponent::MaskedSumcheck {
            statement,
            prefix: completed_prefix,
        });

        if usize::from(batch_ordinal) == WHIR_ROUND_COUNT {
            break;
        }

        let history_before_code_switch = SemanticWhirEpochHistory {
            opening_prefix,
            completed_components: completed_components.clone(),
        };
        let logical_message = witness.source.flattened_messages();
        assert_eq!(logical_message.len() % 2, 0);
        let output_source_relation =
            committed_code_relation(u64::try_from(logical_message.len() / 2).unwrap(), 2, 64, 2);
        let output_messages = logical_message
            .chunks_exact(logical_message.len() / 2)
            .map(<[ProofChallengeExtensionElement]>::to_vec)
            .collect::<Vec<_>>();
        let (output_source_instance, output_source_witness) = code_fixture(
            &output_source_relation,
            output_messages,
            20_000 + u64::from(batch_ordinal) * 101,
        );
        let switch_mask_relation = CommittedMaskCodeRelation {
            role: MaskGroupRole::WhirCodeSwitch {
                round_ordinal: batch_ordinal,
            },
            code: committed_code_relation(relation.source_code.hiding_randomness_length, 1, 8, 1),
        };
        let (switch_mask_instance, switch_mask_witness) = code_fixture(
            &switch_mask_relation.code,
            vec![witness.source.hiding_randomness_columns.concat()],
            30_000 + u64::from(batch_ordinal) * 101,
        );
        let statement = SemanticWhirCodeSwitchStatement::new(
            relation,
            instance,
            output_source_relation,
            output_source_instance,
            switch_mask_relation,
            switch_mask_instance,
            2,
        )
        .unwrap();
        let prefix = SemanticWhirCodeSwitchPrefix {
            query_positions: Some(vec![0, 1]),
            combination_challenge: Some(ProofChallengeExtensionElement::ZERO),
        };
        let input_witness = witness.clone();
        let output_witness = SemanticGeneralizedRelationWitness {
            source: output_source_witness,
            masks: witness
                .masks
                .iter()
                .cloned()
                .chain(core::iter::once(switch_mask_witness))
                .collect(),
        };
        let preceding_prefix = SemanticWhirCodeSwitchPrefix {
            query_positions: None,
            combination_challenge: None,
        };
        verifier_moves.push(EpochVerifierMoveFixture {
            owner: EpochVerifierMoveOwner::CodeSwitch {
                round_ordinal: batch_ordinal,
            },
            statement: EpochVerifierMoveStatement::CodeSwitch(statement.clone()),
            history: history_before_code_switch,
            preceding_prefix: SemanticVerifierMovePrefix::WhirCodeSwitch(preceding_prefix),
            extended_prefix: SemanticVerifierMovePrefix::WhirCodeSwitch(prefix.clone()),
            predecessor_witness: SemanticConstructionWhirWitness::Generalized(input_witness),
            post_challenge_witness: SemanticConstructionWhirWitness::Generalized(
                output_witness.clone(),
            ),
        });
        witness = output_witness;
        assert!(semantic_whir_code_switch_kstate(&statement, Some(&prefix), &witness).unwrap());
        (relation, instance) = semantic_whir_code_switch_output_pair(&statement, &prefix).unwrap();
        completed_components.push(SemanticWhirCompletedComponent::CodeSwitch { statement, prefix });
    }

    let statement = SemanticWhirBaseStatement::new(relation, instance, 2, 2).unwrap();
    assert!(
        super::super::semantic_whir::semantic_whir_base_kstate(
            &statement,
            None,
            &SemanticWhirBaseKnowledgeWitness::Input(witness.clone()),
        )
        .unwrap()
    );
    let history = SemanticWhirEpochHistory {
        opening_prefix,
        completed_components,
    };
    let base = base_fixture(statement, witness);
    verifier_moves.push(EpochVerifierMoveFixture {
        owner: EpochVerifierMoveOwner::BaseCombination,
        statement: EpochVerifierMoveStatement::Base(base.statement.clone()),
        history: history.clone(),
        preceding_prefix: SemanticVerifierMovePrefix::WhirBase(fresh_base_prefix(&base)),
        extended_prefix: SemanticVerifierMovePrefix::WhirBase(combination_base_prefix(&base)),
        predecessor_witness: SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::PreCombination(
                SemanticWhirBasePreCombinationWitness {
                    input: base.input_witness.clone(),
                    fresh: base.fresh_witness.clone(),
                },
            ),
        ),
        post_challenge_witness: SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::Blinded(base.blinded_witness.clone()),
        ),
    });
    EpochFixture {
        history,
        base,
        first_masked_combination_witness: first_masked_combination_witness.unwrap(),
        verifier_moves,
    }
}

struct SixtyFourElementR1csMatrices;

impl CompactCfwR1csMatrices for SixtyFourElementR1csMatrices {
    fn witness_length(&self) -> usize {
        64
    }

    fn evaluate_assignment_rows(
        &self,
        matrix_role: CompactCfwMatrixRole,
        public_input: &[CompactChallengeField],
        witness: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
        if public_input.len() != 64 || witness.len() != 64 {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        Ok(match matrix_role {
            CompactCfwMatrixRole::LeftMultiplicand | CompactCfwMatrixRole::Product => witness
                .iter()
                .copied()
                .chain([CompactChallengeField::ZERO; 64])
                .collect(),
            CompactCfwMatrixRole::RightMultiplicand => {
                vec![CompactChallengeField::ONE; witness.len() * 2]
            }
        })
    }

    fn public_contribution_at_row_point(
        &self,
        matrix_role: CompactCfwMatrixRole,
        row_point: &[CompactChallengeField],
        public_input: &[CompactChallengeField],
    ) -> Result<CompactChallengeField, CompactCfwError> {
        if row_point.len() != 7 || public_input.len() != 64 {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        Ok(match matrix_role {
            CompactCfwMatrixRole::RightMultiplicand => CompactChallengeField::ONE,
            CompactCfwMatrixRole::LeftMultiplicand | CompactCfwMatrixRole::Product => {
                CompactChallengeField::ZERO
            }
        })
    }

    fn accumulate_weighted_witness_covector_at_row_point(
        &self,
        row_point: &[CompactChallengeField],
        matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        destination: &mut [CompactChallengeField],
    ) -> Result<(), CompactCfwError> {
        if row_point.len() != 7 || destination.len() != 64 {
            return Err(CompactCfwError::InvalidMatrixSource);
        }
        for (witness_ordinal, destination) in destination.iter_mut().enumerate() {
            let row_weight = row_point.iter().enumerate().fold(
                CompactChallengeField::ONE,
                |weight, (coordinate_ordinal, coordinate)| {
                    if (witness_ordinal >> coordinate_ordinal) & 1 == 0 {
                        weight * (CompactChallengeField::ONE - *coordinate)
                    } else {
                        weight * *coordinate
                    }
                },
            );
            *destination += row_weight
                * (matrix_role_weights[CompactCfwMatrixRole::LeftMultiplicand.ordinal()]
                    + matrix_role_weights[CompactCfwMatrixRole::Product.ordinal()]);
        }
        Ok(())
    }
}

struct ConstructionFixture {
    outer_statement: SemanticProductionOuterStatement,
    cfw_statement: SemanticCfwStatement<'static, SixtyFourElementR1csMatrices>,
    pre_opening: SemanticWhirOpeningBatchingStatement,
    main_opening: SemanticWhirOpeningBatchingStatement,
    outer_witness: SemanticProductionOuterWitness,
    cfw_witness: SemanticCfwExtractedWitness,
    commitments: SemanticProductionOuterCommitments,
    lookup_challenge: ProofChallengeExtensionElement,
    completed_outer: SemanticProductionOuterPrefix,
    cfw_final_prover_prefix: SemanticCfwTranscriptPrefix,
    cfw_joint_prefix: SemanticCfwTranscriptPrefix,
    pre_witness: SemanticGeneralizedRelationWitness,
    main_witness: SemanticGeneralizedRelationWitness,
}

fn construction_fixture() -> ConstructionFixture {
    let pre_source_relation = committed_code_relation(8, 1, 64, 4);
    let main_source_relation = committed_code_relation(16, 1, 64, 4);
    let cross_mask_relation = CommittedMaskCodeRelation {
        role: MaskGroupRole::CrossEpochOpening,
        code: committed_code_relation(1, 1, 8, 2),
    };
    let layout = SemanticProductionOuterLayout::new(0, 1, 1, 1, 3, 1, 32, 64, 1)
        .expect("reduced production outer layout derives");
    let outer_statement = SemanticProductionOuterStatement::new(
        layout,
        pre_source_relation.clone(),
        main_source_relation.clone(),
        cross_mask_relation.clone(),
    )
    .expect("reduced production outer statement derives");
    let lookup_challenge = lookup_challenge();
    let inverse = lookup_challenge
        .inverse()
        .expect("the lookup denominator is nonzero");
    let mut pre_message = vec![ProofChallengeExtensionElement::ZERO; 32];
    pre_message[1] = field(1);
    let mut main_message = vec![ProofChallengeExtensionElement::ZERO; 64];
    main_message[..2].copy_from_slice(&pre_message[..2]);
    main_message[3] = inverse;
    let (pre_instance, pre_source) = code_fixture(
        &pre_source_relation,
        pre_message.chunks_exact(8).map(<[_]>::to_vec).collect(),
        101,
    );
    let (main_instance, main_source) = code_fixture(
        &main_source_relation,
        main_message.chunks_exact(16).map(<[_]>::to_vec).collect(),
        151,
    );
    let (cross_instance, cross_masks) = code_fixture(
        &cross_mask_relation.code,
        vec![vec![field(11)], vec![field(13)]],
        201,
    );
    let commitments = SemanticProductionOuterCommitments {
        pre_challenge_source: pre_instance.clone(),
        main_source: main_instance.clone(),
        shared_masks: cross_instance.clone(),
    };
    let outer_witness = SemanticProductionOuterWitness {
        pre_challenge_source: pre_source.clone(),
        main_source: main_source.clone(),
        shared_masks: cross_masks.clone(),
    };

    let geometry = CompactCfwGeometry::derive(64).unwrap();
    let inner_relation = committed_code_relation(
        u64::try_from(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH).unwrap(),
        1,
        8,
        u64::try_from(geometry.inner_mask_count()).unwrap(),
    );
    let outer_relation = committed_code_relation(
        u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH).unwrap(),
        1,
        16,
        u64::try_from(geometry.outer_mask_count()).unwrap(),
    );
    let inner_messages = (0..geometry.inner_mask_count())
        .map(|mask_ordinal| {
            let first = field(31 + u64::try_from(mask_ordinal).unwrap() * 3);
            let second = field(37 + u64::try_from(mask_ordinal).unwrap() * 3);
            vec![
                ProofChallengeExtensionElement::ZERO,
                first,
                second,
                first.add(second).negate(),
            ]
        })
        .collect::<Vec<_>>();
    let outer_messages = (0..geometry.outer_mask_count())
        .map(|mask_ordinal| {
            (0..COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                .map(|coefficient_ordinal| {
                    field(71 + u64::try_from(mask_ordinal * 11 + coefficient_ordinal).unwrap())
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let (inner_instance, inner_masks) = code_fixture(&inner_relation, inner_messages, 251);
    let (outer_instance, outer_masks) = code_fixture(&outer_relation, outer_messages, 301);
    let point = vec![ProofChallengeExtensionElement::ZERO; 5];
    let pre_evaluation = ProofChallengeExtensionElement::ZERO;
    let main_evaluation = ProofChallengeExtensionElement::ZERO;
    let cross_values = cross_masks.flattened_messages();
    let cross_epoch_handoff = SemanticCfwCrossEpochHandoff {
        mask_code_relation: cross_mask_relation.clone(),
        committed_instance: cross_instance.clone(),
        point: point
            .iter()
            .copied()
            .map(compact_challenge_from_production)
            .collect(),
        copied_main_source_element_count: 2,
        masked_pre_challenge_evaluation: compact_challenge_from_production(
            pre_evaluation.add(cross_values[0]),
        ),
        masked_main_evaluation: compact_challenge_from_production(
            main_evaluation.add(cross_values[1]),
        ),
        mask_difference: compact_challenge_from_production(
            cross_values[0].subtract(cross_values[1]),
        ),
    };
    let code_relations = Box::leak(Box::new(SemanticCfwCodeRelations {
        source: main_source_relation,
        inner_masks: inner_relation,
        outer_masks: outer_relation,
    }));
    let committed_instances = Box::leak(Box::new(SemanticCfwCommittedInstances {
        source: main_instance,
        inner_masks: inner_instance,
        outer_masks: outer_instance,
    }));
    let cross_epoch_handoff = Box::leak(Box::new(cross_epoch_handoff));
    let matrices = Box::leak(Box::new(SixtyFourElementR1csMatrices));
    let public_input = Box::leak(Box::new([CompactChallengeField::ZERO; 64]));
    let expected_cfw_witness = semantic_cfw_witness_from_code_witnesses(
        geometry,
        main_source.clone(),
        inner_masks,
        outer_masks,
        cross_masks.clone(),
    )
    .expect("the reduced committed witnesses define the CFW witness");
    let prepared = PreparedCompactCfwProver::prepare(
        matrices,
        public_input,
        &expected_cfw_witness.r1cs_witness,
        expected_cfw_witness.mask_material.clone(),
    )
    .expect("the reduced CFW witness prepares");
    let auxiliary_target = prepared.auxiliary_target();
    let constraint_challenge = compact_challenge_from_production(field(19));
    let equality_point = (0..geometry.sumcheck_round_count())
        .map(|coordinate_ordinal| {
            compact_challenge_from_production(field(
                23 + u64::try_from(coordinate_ordinal).unwrap() * 6,
            ))
        })
        .collect::<Vec<_>>();
    let relation_plan_hash = [0x91; 64];
    let canonical_public_input_binding = [0xa1; 64];
    let initial_verifier_prefix = CompactCfwInitialVerifierPrefix::for_focused_semantic_test(
        relation_plan_hash,
        canonical_public_input_binding,
        auxiliary_target,
        constraint_challenge,
        equality_point.clone(),
    );
    let cfw_statement = SemanticCfwStatement::new(
        SemanticCfwInitialStatementBinding::new(
            relation_plan_hash,
            canonical_public_input_binding,
            &initial_verifier_prefix,
        ),
        matrices,
        public_input,
        code_relations,
        committed_instances,
        cross_epoch_handoff,
    )
    .expect("reduced CFW statement derives");
    let cfw_witness = semantic_cfw_errbr(&cfw_statement, cross_masks.clone())
        .expect("the reduced CFW commitments decode")
        .witness;
    assert_eq!(cfw_witness, expected_cfw_witness);
    let mut prover = prepared
        .begin(constraint_challenge, equality_point.clone())
        .expect("the reduced CFW sumcheck begins");
    let mut round_polynomials = Vec::new();
    let mut round_challenges = Vec::new();
    for round_ordinal in 0..geometry.sumcheck_round_count() {
        let polynomial = prover
            .next_round_polynomial()
            .expect("the next reduced CFW round polynomial exists");
        let challenge = compact_challenge_from_production(field(
            37 + u64::try_from(round_ordinal).unwrap() * 6,
        ));
        round_polynomials.push(polynomial);
        round_challenges.push(challenge);
        prover
            .bind_round_challenge(challenge)
            .expect("the reduced CFW round binds");
    }
    let finish = prover.finish().expect("the reduced CFW sumcheck finishes");
    let final_message = SemanticCfwFinalMessage {
        outer_evaluations: finish.outer_evaluations().to_vec(),
        final_values: finish.final_values(),
    };
    let cfw_final_prover_prefix = SemanticCfwTranscriptPrefix {
        auxiliary_target,
        constraint_combining_challenge: Some(constraint_challenge),
        equality_point,
        round_polynomials,
        round_challenges,
        final_message: Some(final_message),
        joint_constraint_challenge: None,
    };
    let cfw_joint_prefix = SemanticCfwTranscriptPrefix {
        joint_constraint_challenge: Some(compact_challenge_from_production(field(47))),
        ..cfw_final_prover_prefix.clone()
    };
    let (main_relation, main_instance) =
        semantic_cfw_output_relation_and_instance(&cfw_statement, &cfw_joint_prefix)
            .expect("the reduced CFW output pair derives");
    let main_witness = main_input_witness_from_cfw(&cfw_witness);
    let main_opening = SemanticWhirOpeningBatchingStatement::new(main_relation, main_instance)
        .expect("the main opening consumes the exact CFW output pair");
    let pre_witness = SemanticGeneralizedRelationWitness {
        source: pre_source,
        masks: vec![cross_masks],
    };
    let pre_relation = GeneralizedCommittedRelation {
        source_code: pre_source_relation,
        mask_codes: vec![cross_mask_relation],
        source_message_element_count: 32,
        source_hiding_element_count: 4,
        mask_message_element_count: 2,
        covector_extension_element_count: 35,
        opening_evaluation_claim_count: 1,
        carried_reduction_claim_count: 0,
        claim_count: 1,
    };
    let pre_instance = SemanticGeneralizedRelationInstance {
        source: pre_instance,
        masks: vec![cross_instance],
        opening_claims: vec![claim_for_witness(&pre_witness)],
        carried_reduction_claims: Vec::new(),
    };
    let pre_opening = SemanticWhirOpeningBatchingStatement::new(pre_relation, pre_instance)
        .expect("the pre-challenge opening statement derives");
    let disclosures = SemanticCrossEpochDisclosures {
        masked_pre_challenge_evaluation: pre_evaluation.add(cross_values[0]),
        masked_main_evaluation: main_evaluation.add(cross_values[1]),
        mask_difference: cross_values[0].subtract(cross_values[1]),
    };
    let completed_outer = SemanticProductionOuterPrefix::CrossEpochDisclosuresSent {
        commitments: commitments.clone(),
        lookup_challenge,
        point,
        disclosures,
    };
    ConstructionFixture {
        outer_statement,
        cfw_statement,
        pre_opening,
        main_opening,
        outer_witness,
        cfw_witness,
        commitments,
        lookup_challenge,
        completed_outer,
        cfw_final_prover_prefix,
        cfw_joint_prefix,
        pre_witness,
        main_witness,
    }
}

fn completed_cfw_handoff(construction: &ConstructionFixture) -> SemanticCompletedCfwHandoff {
    SemanticCompletedCfwHandoff {
        completed_outer: construction.completed_outer.clone(),
        cfw_and_pre_challenge_opening: SemanticCfwAndPreWhirOpeningPrefix {
            cfw: construction.cfw_joint_prefix.clone(),
            pre_challenge_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: Some(ProofChallengeExtensionElement::ZERO),
            },
        },
    }
}

fn completed_pre_challenge_handoff(
    construction: &ConstructionFixture,
    pre_challenge_epoch: &EpochFixture,
) -> SemanticCompletedPreChallengeWhirHandoff {
    SemanticCompletedPreChallengeWhirHandoff {
        completed_cfw: completed_cfw_handoff(construction),
        pre_challenge_history: pre_challenge_epoch.history.clone(),
        pre_challenge_base: pre_challenge_epoch.base.statement.clone(),
        pre_final_and_main_opening: SemanticPreWhirFinalAndMainOpeningPrefix {
            pre_challenge_base: full_base_prefix(&pre_challenge_epoch.base),
            main_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: Some(ProofChallengeExtensionElement::ZERO),
            },
        },
    }
}

fn epoch_construction_prefix(
    construction: &ConstructionFixture,
    epoch: TranscriptEpoch,
    completed_pre_challenge: Option<&SemanticCompletedPreChallengeWhirHandoff>,
    history: &SemanticWhirEpochHistory,
    active: SemanticVerifierMovePrefix,
) -> SemanticConstructionPrefix {
    match epoch {
        TranscriptEpoch::PreChallenge => SemanticConstructionPrefix::PreChallengeWhir {
            completed_cfw: completed_cfw_handoff(construction),
            history: history.clone(),
            active,
        },
        TranscriptEpoch::Main => SemanticConstructionPrefix::MainWhir {
            completed_pre_challenge: Box::new(
                completed_pre_challenge
                    .expect("the main epoch has a completed pre-challenge handoff")
                    .clone(),
            ),
            history: history.clone(),
            active,
        },
    }
}

fn epoch_construction_witness(
    construction: &ConstructionFixture,
    epoch: TranscriptEpoch,
    local: SemanticConstructionWhirWitness,
) -> SemanticConstructionWitness {
    match epoch {
        TranscriptEpoch::PreChallenge => SemanticConstructionWitness::PreChallengeAndMainInput {
            pre_challenge: local,
            main: construction.main_witness.clone(),
        },
        TranscriptEpoch::Main => SemanticConstructionWitness::MainWhir(local),
    }
}

fn mutate_epoch_knowledge_witness(witness: &mut SemanticConstructionWhirWitness) {
    let generalized = match witness {
        SemanticConstructionWhirWitness::Generalized(generalized) => generalized,
        SemanticConstructionWhirWitness::Base(SemanticWhirBaseKnowledgeWitness::Input(input)) => {
            input
        }
        SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::PreCombination(pre_combination),
        ) => &mut pre_combination.input,
        SemanticConstructionWhirWitness::Base(SemanticWhirBaseKnowledgeWitness::Blinded(
            blinded,
        )) => blinded,
        SemanticConstructionWhirWitness::Base(SemanticWhirBaseKnowledgeWitness::Terminal) => {
            panic!("a terminal witness has no prover-message successor")
        }
    };
    generalized.source.message_columns[0][0] =
        generalized.source.message_columns[0][0].add(field(1));
}

fn mutate_initial_construction_witness(witness: &mut SemanticConstructionWitness) {
    let SemanticConstructionWitness::OuterAndCfw { outer, .. } = witness else {
        panic!("the initial construction witness must retain the production outer witness")
    };
    outer.pre_challenge_source.message_columns[0][0] =
        outer.pre_challenge_source.message_columns[0][0].add(field(1));
}

#[allow(clippy::too_many_arguments)]
fn assert_prover_boundary_preserves_false_state(
    context: &SemanticConstructionContext<'_, '_, SixtyFourElementR1csMatrices>,
    boundary_name: &str,
    before_descriptor: &SemanticFactorOneMoveDescriptor,
    before_statement: &SemanticVerifierMoveStatement<'_, '_, SixtyFourElementR1csMatrices>,
    before_prefix: &SemanticConstructionPrefix,
    after_descriptor: &SemanticFactorOneMoveDescriptor,
    after_statement: &SemanticVerifierMoveStatement<'_, '_, SixtyFourElementR1csMatrices>,
    after_prefix: &SemanticConstructionPrefix,
    witness: &SemanticConstructionWitness,
    hostile_witness: &SemanticConstructionWitness,
) {
    check_semantic_construction_prover_move(
        context,
        (before_descriptor, before_statement, before_prefix),
        (after_descriptor, after_statement, after_prefix),
        witness,
    )
    .unwrap_or_else(|error| {
        panic!("the canonical prover transition at {boundary_name} failed: {error:?}")
    });
    check_semantic_construction_prover_move(
        context,
        (before_descriptor, before_statement, before_prefix),
        (after_descriptor, after_statement, after_prefix),
        hostile_witness,
    )
    .unwrap_or_else(|error| {
        panic!("the hostile-state implication at {boundary_name} failed: {error:?}")
    });
    assert!(
        semantic_construction_kstate(
            context,
            before_descriptor,
            before_statement,
            before_prefix,
            witness,
        )
        .unwrap(),
        "the knowledge state before {boundary_name} must hold",
    );
    assert!(
        semantic_construction_kstate(
            context,
            after_descriptor,
            after_statement,
            after_prefix,
            witness,
        )
        .unwrap(),
        "the same witness after {boundary_name} must hold",
    );
    assert!(
        !semantic_construction_kstate(
            context,
            before_descriptor,
            before_statement,
            before_prefix,
            hostile_witness,
        )
        .unwrap(),
        "the hostile knowledge state before {boundary_name} must be false",
    );
    assert!(
        !semantic_construction_kstate(
            context,
            after_descriptor,
            after_statement,
            after_prefix,
            hostile_witness,
        )
        .unwrap(),
        "the prover message at {boundary_name} must not repair the hostile state",
    );
}

fn assert_epoch_verifier_move_extracts_exact_predecessor(
    context: &SemanticConstructionContext<'_, '_, SixtyFourElementR1csMatrices>,
    construction: &ConstructionFixture,
    epoch: TranscriptEpoch,
    completed_pre_challenge: Option<&SemanticCompletedPreChallengeWhirHandoff>,
    verifier_move: &EpochVerifierMoveFixture,
) {
    let descriptor =
        SemanticFactorOneMoveDescriptor::for_focused_test(verifier_move.owner.with_epoch(epoch));
    let statement = verifier_move.statement.as_semantic_statement();
    let preceding_prefix = epoch_construction_prefix(
        construction,
        epoch,
        completed_pre_challenge,
        &verifier_move.history,
        verifier_move.preceding_prefix.clone(),
    );
    let extended_prefix = epoch_construction_prefix(
        construction,
        epoch,
        completed_pre_challenge,
        &verifier_move.history,
        verifier_move.extended_prefix.clone(),
    );
    let predecessor_witness = epoch_construction_witness(
        construction,
        epoch,
        verifier_move.predecessor_witness.clone(),
    );
    let post_challenge_witness = epoch_construction_witness(
        construction,
        epoch,
        verifier_move.post_challenge_witness.clone(),
    );

    assert!(
        semantic_construction_kstate(
            context,
            &descriptor,
            &statement,
            &preceding_prefix,
            &predecessor_witness,
        )
        .unwrap(),
        "the preceding knowledge state must hold for {:?}",
        descriptor.owner(),
    );
    assert!(
        semantic_construction_kstate(
            context,
            &descriptor,
            &statement,
            &extended_prefix,
            &post_challenge_witness,
        )
        .unwrap(),
        "the post-challenge knowledge state must hold for {:?}",
        descriptor.owner(),
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&descriptor, &extended_prefix).unwrap(),
        preceding_prefix,
        "the preceding transcript projection must be exact for {:?}",
        descriptor.owner(),
    );
    assert_eq!(
        semantic_construction_errbr(
            context,
            &descriptor,
            &statement,
            &extended_prefix,
            &post_challenge_witness,
        )
        .unwrap()
        .witness,
        Some(predecessor_witness),
        "ERRBR must reconstruct the exact adjacent witness for {:?}",
        descriptor.owner(),
    );
    assert_eq!(
        semantic_construction_bad_transition(
            context,
            &descriptor,
            &statement,
            &extended_prefix,
            &post_challenge_witness,
        )
        .unwrap(),
        None,
        "the honest adjacent transition must not produce a bad event for {:?}",
        descriptor.owner(),
    );
}

#[test]
fn construction_kstate_and_errbr_bind_empty_outer_cfw_and_atomic_handoff() {
    let fixture = construction_fixture();
    let context = SemanticConstructionContext::new(
        &fixture.outer_statement,
        &fixture.cfw_statement,
        &fixture.pre_opening,
        &fixture.main_opening,
    )
    .expect("the exact construction context binds");
    let initial = SemanticConstructionWitness::OuterAndCfw {
        outer: fixture.outer_witness.clone(),
        cfw: fixture.cfw_witness.clone(),
    };
    assert!(semantic_construction_empty_kstate(&context, &initial).unwrap());

    let lookup_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::LookupChallenge,
    );
    let lookup_statement = SemanticVerifierMoveStatement::ProductionOuter(&fixture.outer_statement);
    let lookup_preceding = SemanticConstructionPrefix::Outer(
        SemanticProductionOuterPrefix::PreChallengeSourceCommitted {
            pre_challenge_source: fixture.commitments.pre_challenge_source.clone(),
        },
    );
    let lookup_extended =
        SemanticConstructionPrefix::Outer(SemanticProductionOuterPrefix::LookupChallengeSampled {
            pre_challenge_source: fixture.commitments.pre_challenge_source.clone(),
            lookup_challenge: fixture.lookup_challenge,
        });
    assert!(
        semantic_construction_kstate(
            &context,
            &lookup_descriptor,
            &lookup_statement,
            &lookup_preceding,
            &initial,
        )
        .unwrap()
    );
    assert!(
        semantic_construction_kstate(
            &context,
            &lookup_descriptor,
            &lookup_statement,
            &lookup_extended,
            &initial,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&lookup_descriptor, &lookup_extended).unwrap(),
        lookup_preceding
    );
    assert_eq!(
        semantic_construction_errbr(
            &context,
            &lookup_descriptor,
            &lookup_statement,
            &lookup_extended,
            &initial,
        )
        .unwrap()
        .witness,
        Some(initial.clone())
    );

    let cfw_initial_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CfwInitialRandomness,
    );
    let cfw_statement = SemanticVerifierMoveStatement::Cfw(&fixture.cfw_statement);
    let cfw_initial_preceding = SemanticConstructionPrefix::Cfw {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwTranscriptPrefix {
            auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
            constraint_combining_challenge: None,
            equality_point: Vec::new(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        },
    };
    let cfw_initial_extended = SemanticConstructionPrefix::Cfw {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwTranscriptPrefix {
            auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
            constraint_combining_challenge: fixture
                .cfw_final_prover_prefix
                .constraint_combining_challenge,
            equality_point: fixture.cfw_final_prover_prefix.equality_point.clone(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        },
    };
    assert!(
        semantic_construction_kstate(
            &context,
            &cfw_initial_descriptor,
            &cfw_statement,
            &cfw_initial_preceding,
            &initial,
        )
        .unwrap()
    );
    assert!(
        semantic_construction_kstate(
            &context,
            &cfw_initial_descriptor,
            &cfw_statement,
            &cfw_initial_extended,
            &initial,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&cfw_initial_descriptor, &cfw_initial_extended,)
            .unwrap(),
        cfw_initial_preceding
    );
    assert_eq!(
        semantic_construction_errbr(
            &context,
            &cfw_initial_descriptor,
            &cfw_statement,
            &cfw_initial_extended,
            &initial,
        )
        .unwrap()
        .witness,
        Some(initial.clone())
    );
    assert_eq!(
        semantic_construction_bad_transition(
            &context,
            &cfw_initial_descriptor,
            &cfw_statement,
            &cfw_initial_extended,
            &initial,
        )
        .unwrap(),
        None
    );

    let combined_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
    );
    let combined_statement = SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
        cfw: &fixture.cfw_statement,
        pre_challenge_opening: &fixture.pre_opening,
    };
    let combined_preceding = SemanticConstructionPrefix::CfwAndPreWhirOpening {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwAndPreWhirOpeningPrefix {
            cfw: fixture.cfw_final_prover_prefix.clone(),
            pre_challenge_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: None,
            },
        },
    };
    let combined_extended = SemanticConstructionPrefix::CfwAndPreWhirOpening {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwAndPreWhirOpeningPrefix {
            cfw: fixture.cfw_joint_prefix.clone(),
            pre_challenge_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: Some(ProofChallengeExtensionElement::ZERO),
            },
        },
    };
    let post_handoff = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Generalized(fixture.pre_witness.clone()),
        main: fixture.main_witness.clone(),
    };
    assert!(
        semantic_construction_kstate(
            &context,
            &combined_descriptor,
            &combined_statement,
            &combined_preceding,
            &post_handoff,
        )
        .unwrap()
    );
    assert!(
        semantic_construction_kstate(
            &context,
            &combined_descriptor,
            &combined_statement,
            &combined_extended,
            &post_handoff,
        )
        .unwrap()
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&combined_descriptor, &combined_extended).unwrap(),
        combined_preceding
    );
    assert_eq!(
        semantic_construction_errbr(
            &context,
            &combined_descriptor,
            &combined_statement,
            &combined_extended,
            &post_handoff,
        )
        .unwrap()
        .witness,
        Some(initial.clone())
    );
    assert_eq!(
        semantic_construction_bad_transition(
            &context,
            &combined_descriptor,
            &combined_statement,
            &combined_extended,
            &post_handoff,
        )
        .unwrap(),
        None
    );

    let mut substituted_handoff = post_handoff;
    let SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Generalized(pre_challenge),
        ..
    } = &mut substituted_handoff
    else {
        unreachable!("the test constructed the generalized handoff variant")
    };
    pre_challenge.masks[0].message_columns[0][0] =
        pre_challenge.masks[0].message_columns[0][0].add(field(1));
    assert!(
        !semantic_construction_kstate(
            &context,
            &combined_descriptor,
            &combined_statement,
            &combined_extended,
            &substituted_handoff,
        )
        .unwrap()
    );
}

#[test]
fn construction_extracts_every_reduced_outer_and_cfw_witness_transition() {
    let fixture = construction_fixture();
    let context = SemanticConstructionContext::new(
        &fixture.outer_statement,
        &fixture.cfw_statement,
        &fixture.pre_opening,
        &fixture.main_opening,
    )
    .unwrap();
    let witness = SemanticConstructionWitness::OuterAndCfw {
        outer: fixture.outer_witness.clone(),
        cfw: fixture.cfw_witness.clone(),
    };

    let point = match &fixture.completed_outer {
        SemanticProductionOuterPrefix::CrossEpochDisclosuresSent { point, .. } => point.clone(),
        _ => panic!("the construction fixture must finish the production outer relation"),
    };
    let outer_statement = SemanticVerifierMoveStatement::ProductionOuter(&fixture.outer_statement);
    let outer_transitions = [
        (
            SemanticVerifierMoveOwner::LookupChallenge,
            SemanticProductionOuterPrefix::PreChallengeSourceCommitted {
                pre_challenge_source: fixture.commitments.pre_challenge_source.clone(),
            },
            SemanticProductionOuterPrefix::LookupChallengeSampled {
                pre_challenge_source: fixture.commitments.pre_challenge_source.clone(),
                lookup_challenge: fixture.lookup_challenge,
            },
        ),
        (
            SemanticVerifierMoveOwner::CrossEpochPoint,
            SemanticProductionOuterPrefix::PostLookupCommitments {
                commitments: fixture.commitments.clone(),
                lookup_challenge: fixture.lookup_challenge,
            },
            SemanticProductionOuterPrefix::CrossEpochPointSampled {
                commitments: fixture.commitments.clone(),
                lookup_challenge: fixture.lookup_challenge,
                point,
            },
        ),
    ];
    for (owner, preceding, extended) in outer_transitions {
        let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(owner);
        let preceding = SemanticConstructionPrefix::Outer(preceding);
        let extended = SemanticConstructionPrefix::Outer(extended);
        let preceding_state = semantic_construction_kstate(
            &context,
            &descriptor,
            &outer_statement,
            &preceding,
            &witness,
        )
        .unwrap();
        assert!(preceding_state, "the canonical preceding state must hold");
        assert!(
            semantic_construction_kstate(
                &context,
                &descriptor,
                &outer_statement,
                &extended,
                &witness,
            )
            .unwrap()
        );
        assert_eq!(
            semantic_construction_preceding_prefix(&descriptor, &extended).unwrap(),
            preceding
        );
        assert_eq!(
            semantic_construction_errbr(
                &context,
                &descriptor,
                &outer_statement,
                &extended,
                &witness,
            )
            .unwrap()
            .witness,
            Some(witness.clone())
        );
        assert_eq!(
            semantic_construction_bad_transition(
                &context,
                &descriptor,
                &outer_statement,
                &extended,
                &witness,
            )
            .unwrap(),
            None,
        );
    }

    let cfw_statement = SemanticVerifierMoveStatement::Cfw(&fixture.cfw_statement);
    let initial_preceding = SemanticCfwTranscriptPrefix {
        auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
        constraint_combining_challenge: None,
        equality_point: Vec::new(),
        round_polynomials: Vec::new(),
        round_challenges: Vec::new(),
        final_message: None,
        joint_constraint_challenge: None,
    };
    let initial_extended = SemanticCfwTranscriptPrefix {
        constraint_combining_challenge: fixture
            .cfw_final_prover_prefix
            .constraint_combining_challenge,
        equality_point: fixture.cfw_final_prover_prefix.equality_point.clone(),
        ..initial_preceding.clone()
    };
    let mut cfw_transitions = vec![(
        SemanticVerifierMoveOwner::CfwInitialRandomness,
        initial_preceding,
        initial_extended,
    )];
    for round_ordinal in 0..fixture.cfw_final_prover_prefix.round_polynomials.len() {
        let preceding = SemanticCfwTranscriptPrefix {
            auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
            constraint_combining_challenge: fixture
                .cfw_final_prover_prefix
                .constraint_combining_challenge,
            equality_point: fixture.cfw_final_prover_prefix.equality_point.clone(),
            round_polynomials: fixture.cfw_final_prover_prefix.round_polynomials[..=round_ordinal]
                .to_vec(),
            round_challenges: fixture.cfw_final_prover_prefix.round_challenges[..round_ordinal]
                .to_vec(),
            final_message: None,
            joint_constraint_challenge: None,
        };
        let mut extended = preceding.clone();
        extended
            .round_challenges
            .push(fixture.cfw_final_prover_prefix.round_challenges[round_ordinal]);
        cfw_transitions.push((
            SemanticVerifierMoveOwner::CfwSumcheckRound {
                round_ordinal: u32::try_from(round_ordinal).unwrap(),
            },
            preceding,
            extended,
        ));
    }
    for (owner, preceding, extended) in cfw_transitions {
        let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(owner);
        let preceding = SemanticConstructionPrefix::Cfw {
            completed_outer: fixture.completed_outer.clone(),
            active: preceding,
        };
        let extended = SemanticConstructionPrefix::Cfw {
            completed_outer: fixture.completed_outer.clone(),
            active: extended,
        };
        assert!(
            semantic_construction_kstate(
                &context,
                &descriptor,
                &cfw_statement,
                &preceding,
                &witness,
            )
            .unwrap(),
            "the preceding CFW state must hold for {:?}",
            descriptor.owner(),
        );
        assert!(
            semantic_construction_kstate(
                &context,
                &descriptor,
                &cfw_statement,
                &extended,
                &witness,
            )
            .unwrap(),
            "the extended CFW state must hold for {:?}",
            descriptor.owner(),
        );
        assert_eq!(
            semantic_construction_preceding_prefix(&descriptor, &extended).unwrap(),
            preceding
        );
        assert_eq!(
            semantic_construction_errbr(
                &context,
                &descriptor,
                &cfw_statement,
                &extended,
                &witness,
            )
            .unwrap()
            .witness,
            Some(witness.clone()),
            "ERRBR must reconstruct the exact CFW witness for {:?}",
            descriptor.owner(),
        );
        assert_eq!(
            semantic_construction_bad_transition(
                &context,
                &descriptor,
                &cfw_statement,
                &extended,
                &witness,
            )
            .unwrap(),
            None
        );
    }
}

#[test]
fn construction_outer_and_cfw_prover_messages_cannot_repair_a_false_state() {
    let fixture = construction_fixture();
    let context = SemanticConstructionContext::new(
        &fixture.outer_statement,
        &fixture.cfw_statement,
        &fixture.pre_opening,
        &fixture.main_opening,
    )
    .unwrap();
    let witness = SemanticConstructionWitness::OuterAndCfw {
        outer: fixture.outer_witness.clone(),
        cfw: fixture.cfw_witness.clone(),
    };
    let mut hostile_witness = witness.clone();
    mutate_initial_construction_witness(&mut hostile_witness);

    let lookup_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::LookupChallenge,
    );
    let outer_statement = SemanticVerifierMoveStatement::ProductionOuter(&fixture.outer_statement);
    let lookup_preceding = SemanticConstructionPrefix::Outer(
        SemanticProductionOuterPrefix::PreChallengeSourceCommitted {
            pre_challenge_source: fixture.commitments.pre_challenge_source.clone(),
        },
    );
    assert!(semantic_construction_empty_kstate(&context, &witness).unwrap());
    assert!(
        semantic_construction_kstate(
            &context,
            &lookup_descriptor,
            &outer_statement,
            &lookup_preceding,
            &witness,
        )
        .unwrap()
    );
    assert!(!semantic_construction_empty_kstate(&context, &hostile_witness).unwrap());
    check_semantic_construction_initial_prover_move(
        &context,
        &lookup_descriptor,
        &outer_statement,
        &lookup_preceding,
        &witness,
    )
    .expect("the first canonical prover message preserves the input relation");
    check_semantic_construction_initial_prover_move(
        &context,
        &lookup_descriptor,
        &outer_statement,
        &lookup_preceding,
        &hostile_witness,
    )
    .expect("the first prover message cannot repair the hostile input witness");
    assert!(
        !semantic_construction_kstate(
            &context,
            &lookup_descriptor,
            &outer_statement,
            &lookup_preceding,
            &hostile_witness,
        )
        .unwrap()
    );

    let lookup_extended =
        SemanticConstructionPrefix::Outer(SemanticProductionOuterPrefix::LookupChallengeSampled {
            pre_challenge_source: fixture.commitments.pre_challenge_source.clone(),
            lookup_challenge: fixture.lookup_challenge,
        });
    let cross_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CrossEpochPoint,
    );
    let cross_preceding =
        SemanticConstructionPrefix::Outer(SemanticProductionOuterPrefix::PostLookupCommitments {
            commitments: fixture.commitments.clone(),
            lookup_challenge: fixture.lookup_challenge,
        });
    assert_prover_boundary_preserves_false_state(
        &context,
        "the post-lookup commitments",
        &lookup_descriptor,
        &outer_statement,
        &lookup_extended,
        &cross_descriptor,
        &outer_statement,
        &cross_preceding,
        &witness,
        &hostile_witness,
    );
    let substituted_cross_preceding =
        SemanticConstructionPrefix::Outer(SemanticProductionOuterPrefix::PostLookupCommitments {
            commitments: fixture.commitments.clone(),
            lookup_challenge: fixture.lookup_challenge.add(field(1)),
        });
    assert_eq!(
        check_semantic_construction_prover_move(
            &context,
            (&lookup_descriptor, &outer_statement, &lookup_extended),
            (
                &cross_descriptor,
                &outer_statement,
                &substituted_cross_preceding,
            ),
            &witness,
        ),
        Err(SemanticConstructionError::InvalidProverChronology)
    );
    assert!(
        !semantic_construction_kstate(
            &context,
            &lookup_descriptor,
            &outer_statement,
            &lookup_extended,
            &hostile_witness,
        )
        .unwrap()
    );
    assert!(
        !semantic_construction_kstate(
            &context,
            &cross_descriptor,
            &outer_statement,
            &cross_preceding,
            &hostile_witness,
        )
        .unwrap()
    );

    let point = match &fixture.completed_outer {
        SemanticProductionOuterPrefix::CrossEpochDisclosuresSent { point, .. } => point.clone(),
        _ => panic!("the construction fixture must finish the production outer relation"),
    };
    let cross_extended =
        SemanticConstructionPrefix::Outer(SemanticProductionOuterPrefix::CrossEpochPointSampled {
            commitments: fixture.commitments.clone(),
            lookup_challenge: fixture.lookup_challenge,
            point,
        });
    let cfw_statement = SemanticVerifierMoveStatement::Cfw(&fixture.cfw_statement);
    let cfw_initial_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CfwInitialRandomness,
    );
    let cfw_initial_preceding = SemanticConstructionPrefix::Cfw {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwTranscriptPrefix {
            auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
            constraint_combining_challenge: None,
            equality_point: Vec::new(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        },
    };
    assert_prover_boundary_preserves_false_state(
        &context,
        "the production-outer-to-CFW response",
        &cross_descriptor,
        &outer_statement,
        &cross_extended,
        &cfw_initial_descriptor,
        &cfw_statement,
        &cfw_initial_preceding,
        &witness,
        &hostile_witness,
    );

    let cfw_initial_extended = SemanticConstructionPrefix::Cfw {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwTranscriptPrefix {
            auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
            constraint_combining_challenge: fixture
                .cfw_final_prover_prefix
                .constraint_combining_challenge,
            equality_point: fixture.cfw_final_prover_prefix.equality_point.clone(),
            round_polynomials: Vec::new(),
            round_challenges: Vec::new(),
            final_message: None,
            joint_constraint_challenge: None,
        },
    };
    let mut previous_descriptor = cfw_initial_descriptor;
    let mut previous_extended = cfw_initial_extended;
    for round_ordinal in 0..fixture.cfw_final_prover_prefix.round_polynomials.len() {
        let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
            SemanticVerifierMoveOwner::CfwSumcheckRound {
                round_ordinal: u32::try_from(round_ordinal).unwrap(),
            },
        );
        let preceding = SemanticConstructionPrefix::Cfw {
            completed_outer: fixture.completed_outer.clone(),
            active: SemanticCfwTranscriptPrefix {
                auxiliary_target: fixture.cfw_final_prover_prefix.auxiliary_target,
                constraint_combining_challenge: fixture
                    .cfw_final_prover_prefix
                    .constraint_combining_challenge,
                equality_point: fixture.cfw_final_prover_prefix.equality_point.clone(),
                round_polynomials: fixture.cfw_final_prover_prefix.round_polynomials
                    [..=round_ordinal]
                    .to_vec(),
                round_challenges: fixture.cfw_final_prover_prefix.round_challenges[..round_ordinal]
                    .to_vec(),
                final_message: None,
                joint_constraint_challenge: None,
            },
        };
        assert_prover_boundary_preserves_false_state(
            &context,
            "a CFW round-polynomial message",
            &previous_descriptor,
            &cfw_statement,
            &previous_extended,
            &descriptor,
            &cfw_statement,
            &preceding,
            &witness,
            &hostile_witness,
        );
        let mut active = match preceding {
            SemanticConstructionPrefix::Cfw { active, .. } => active,
            _ => unreachable!("the preceding prefix was constructed as CFW"),
        };
        active
            .round_challenges
            .push(fixture.cfw_final_prover_prefix.round_challenges[round_ordinal]);
        previous_extended = SemanticConstructionPrefix::Cfw {
            completed_outer: fixture.completed_outer.clone(),
            active,
        };
        previous_descriptor = descriptor;
    }

    let joint_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
    );
    let joint_statement = SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
        cfw: &fixture.cfw_statement,
        pre_challenge_opening: &fixture.pre_opening,
    };
    let joint_preceding = SemanticConstructionPrefix::CfwAndPreWhirOpening {
        completed_outer: fixture.completed_outer.clone(),
        active: SemanticCfwAndPreWhirOpeningPrefix {
            cfw: fixture.cfw_final_prover_prefix.clone(),
            pre_challenge_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: None,
            },
        },
    };
    assert_prover_boundary_preserves_false_state(
        &context,
        "the CFW final message and pre-challenge opening commitment",
        &previous_descriptor,
        &cfw_statement,
        &previous_extended,
        &joint_descriptor,
        &joint_statement,
        &joint_preceding,
        &witness,
        &hostile_witness,
    );
}

#[test]
fn construction_full_transcript_state_is_the_main_whir_terminal_relation() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .expect("the exact construction context binds");
    let pre_challenge_epoch =
        epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let completed_pre_challenge =
        completed_pre_challenge_handoff(&construction, &pre_challenge_epoch);
    let epoch = epoch_fixture(
        &construction.main_opening,
        construction.main_witness.clone(),
    );
    let base = &epoch.base;
    let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::MainWhirFinalQueries,
    );
    let statement = SemanticVerifierMoveStatement::WhirBase(&base.statement);
    let preceding = SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(completed_pre_challenge.clone()),
        history: epoch.history.clone(),
        active: SemanticVerifierMovePrefix::WhirBase(revealed_base_prefix(base)),
    };
    let full = SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(completed_pre_challenge.clone()),
        history: epoch.history.clone(),
        active: SemanticVerifierMovePrefix::WhirBase(full_base_prefix(base)),
    };
    let preceding_witness =
        SemanticConstructionWitness::MainWhir(SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::Blinded(base.blinded_witness.clone()),
        ));
    let terminal = SemanticConstructionWitness::Terminal;

    assert!(
        semantic_construction_kstate(
            &context,
            &descriptor,
            &statement,
            &preceding,
            &preceding_witness,
        )
        .unwrap()
    );
    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &full, &terminal,).unwrap()
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&descriptor, &full).unwrap(),
        preceding
    );
    let extraction =
        semantic_construction_errbr(&context, &descriptor, &statement, &full, &terminal)
            .expect("the terminal construction extractor executes");
    assert_eq!(extraction.witness, Some(preceding_witness));
    assert!(extraction.field_operation_count > 0);
    assert_eq!(
        semantic_construction_bad_transition(&context, &descriptor, &statement, &full, &terminal,)
            .unwrap(),
        None
    );

    let mut changed_full = full_base_prefix(base);
    changed_full
        .query_challenges
        .as_mut()
        .unwrap()
        .source_positions[0] = 4;
    let changed_full = SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(completed_pre_challenge),
        history: epoch.history,
        active: SemanticVerifierMovePrefix::WhirBase(changed_full),
    };
    assert_eq!(
        semantic_construction_kstate(&context, &descriptor, &statement, &changed_full, &terminal,),
        Err(SemanticConstructionError::Execution(
            SemanticExecutionError::Whir(SemanticWhirError::MalformedPrefix)
        ))
    );
}

#[test]
fn construction_atomic_epoch_handoff_extracts_both_predecessor_witnesses() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .expect("the exact construction context binds");
    let epoch = epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let base = &epoch.base;
    let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
    );
    let statement = SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
        pre_challenge_base: &base.statement,
        main_opening: &construction.main_opening,
    };
    let preceding = SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
        completed_cfw: completed_cfw_handoff(&construction),
        history: epoch.history.clone(),
        active: SemanticPreWhirFinalAndMainOpeningPrefix {
            pre_challenge_base: revealed_base_prefix(base),
            main_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: None,
            },
        },
    };
    let extended = SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
        completed_cfw: completed_cfw_handoff(&construction),
        history: epoch.history,
        active: SemanticPreWhirFinalAndMainOpeningPrefix {
            pre_challenge_base: full_base_prefix(base),
            main_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: Some(ProofChallengeExtensionElement::ZERO),
            },
        },
    };
    let predecessor = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::Blinded(base.blinded_witness.clone()),
        ),
        main: construction.main_witness.clone(),
    };
    let post = SemanticConstructionWitness::MainWhir(SemanticConstructionWhirWitness::Generalized(
        construction.main_witness.clone(),
    ));

    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &preceding, &predecessor,)
            .unwrap()
    );
    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &extended, &post,).unwrap()
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&descriptor, &extended).unwrap(),
        preceding
    );
    let extraction =
        semantic_construction_errbr(&context, &descriptor, &statement, &extended, &post)
            .expect("both atomic backward extractors execute");
    assert_eq!(extraction.witness, Some(predecessor));
    assert!(extraction.field_operation_count > 0);
    assert_eq!(
        semantic_construction_bad_transition(&context, &descriptor, &statement, &extended, &post,)
            .unwrap(),
        None
    );
}

#[test]
fn construction_pre_challenge_extractor_retains_the_exact_main_input() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .expect("the exact construction context binds");
    let epoch = epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let base = &epoch.base;
    let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::WhirBaseCombination {
            epoch: TranscriptEpoch::PreChallenge,
        },
    );
    let statement = SemanticVerifierMoveStatement::WhirBase(&base.statement);
    let preceding = SemanticConstructionPrefix::PreChallengeWhir {
        completed_cfw: completed_cfw_handoff(&construction),
        history: epoch.history.clone(),
        active: SemanticVerifierMovePrefix::WhirBase(fresh_base_prefix(base)),
    };
    let extended = SemanticConstructionPrefix::PreChallengeWhir {
        completed_cfw: completed_cfw_handoff(&construction),
        history: epoch.history,
        active: SemanticVerifierMovePrefix::WhirBase(combination_base_prefix(base)),
    };
    let predecessor = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::PreCombination(
                SemanticWhirBasePreCombinationWitness {
                    input: base.input_witness.clone(),
                    fresh: base.fresh_witness.clone(),
                },
            ),
        ),
        main: construction.main_witness.clone(),
    };
    let post = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Base(
            SemanticWhirBaseKnowledgeWitness::Blinded(base.blinded_witness.clone()),
        ),
        main: construction.main_witness.clone(),
    };

    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &preceding, &predecessor,)
            .unwrap()
    );
    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &extended, &post,).unwrap()
    );
    let extraction =
        semantic_construction_errbr(&context, &descriptor, &statement, &extended, &post)
            .expect("the pre-challenge base extractor executes");
    assert_eq!(extraction.witness, Some(predecessor));
    assert!(extraction.field_operation_count > 0);
    assert_eq!(
        semantic_construction_bad_transition(&context, &descriptor, &statement, &extended, &post,)
            .unwrap(),
        None
    );
}

#[test]
fn construction_first_whir_move_replays_the_opening_output_and_extracts_its_witness() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .unwrap();
    let epoch = epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let (first_statement, mut extended_local) = match &epoch.history.completed_components[0] {
        SemanticWhirCompletedComponent::MaskedSumcheck { statement, prefix } => {
            (statement.clone(), prefix.clone())
        }
        SemanticWhirCompletedComponent::CodeSwitch { .. } => {
            panic!("the first WHIR component must be masked sumcheck")
        }
    };
    extended_local.round_wires.clear();
    extended_local.round_challenges.clear();
    let mut preceding_local = extended_local.clone();
    preceding_local.combining_challenge = None;
    let history = SemanticWhirEpochHistory {
        opening_prefix: epoch.history.opening_prefix,
        completed_components: Vec::new(),
    };
    let preceding = SemanticConstructionPrefix::PreChallengeWhir {
        completed_cfw: completed_cfw_handoff(&construction),
        history: history.clone(),
        active: SemanticVerifierMovePrefix::WhirMaskedSumcheck(preceding_local),
    };
    let extended = SemanticConstructionPrefix::PreChallengeWhir {
        completed_cfw: completed_cfw_handoff(&construction),
        history,
        active: SemanticVerifierMovePrefix::WhirMaskedSumcheck(extended_local),
    };
    let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
            epoch: TranscriptEpoch::PreChallenge,
            batch_ordinal: 0,
        },
    );
    let statement = SemanticVerifierMoveStatement::WhirMaskedSumcheck(&first_statement);
    let predecessor = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Generalized(
            construction.pre_witness.clone(),
        ),
        main: construction.main_witness.clone(),
    };
    let post = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Generalized(
            epoch.first_masked_combination_witness,
        ),
        main: construction.main_witness,
    };

    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &preceding, &predecessor)
            .unwrap()
    );
    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &extended, &post).unwrap()
    );
    assert_eq!(
        semantic_construction_preceding_prefix(&descriptor, &extended).unwrap(),
        preceding
    );
    assert_eq!(
        semantic_construction_errbr(&context, &descriptor, &statement, &extended, &post)
            .unwrap()
            .witness,
        Some(predecessor)
    );
}

#[test]
fn construction_extracts_every_adjacent_whir_witness_transition_in_both_epochs() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .unwrap();
    let pre_challenge_epoch =
        epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    for verifier_move in &pre_challenge_epoch.verifier_moves {
        assert_epoch_verifier_move_extracts_exact_predecessor(
            &context,
            &construction,
            TranscriptEpoch::PreChallenge,
            None,
            verifier_move,
        );
    }

    let completed_pre_challenge =
        completed_pre_challenge_handoff(&construction, &pre_challenge_epoch);
    let main_epoch = epoch_fixture(
        &construction.main_opening,
        construction.main_witness.clone(),
    );
    for verifier_move in &main_epoch.verifier_moves {
        assert_epoch_verifier_move_extracts_exact_predecessor(
            &context,
            &construction,
            TranscriptEpoch::Main,
            Some(&completed_pre_challenge),
            verifier_move,
        );
    }
}

#[test]
fn construction_whir_prover_messages_cannot_repair_a_false_knowledge_state() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .unwrap();
    let pre_challenge_epoch =
        epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let completed_pre_challenge =
        completed_pre_challenge_handoff(&construction, &pre_challenge_epoch);
    let main_epoch = epoch_fixture(
        &construction.main_opening,
        construction.main_witness.clone(),
    );

    for (epoch, epoch_fixture, completed_pre_challenge) in [
        (TranscriptEpoch::PreChallenge, &pre_challenge_epoch, None),
        (
            TranscriptEpoch::Main,
            &main_epoch,
            Some(&completed_pre_challenge),
        ),
    ] {
        for adjacent_moves in epoch_fixture.verifier_moves.windows(2) {
            let [before_move, after_move] = adjacent_moves else {
                unreachable!("a two-element window has exactly two moves")
            };
            let before_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
                before_move.owner.with_epoch(epoch),
            );
            let after_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
                after_move.owner.with_epoch(epoch),
            );
            let before_statement = before_move.statement.as_semantic_statement();
            let after_statement = after_move.statement.as_semantic_statement();
            let before_prefix = epoch_construction_prefix(
                &construction,
                epoch,
                completed_pre_challenge,
                &before_move.history,
                before_move.extended_prefix.clone(),
            );
            let after_prefix = epoch_construction_prefix(
                &construction,
                epoch,
                completed_pre_challenge,
                &after_move.history,
                after_move.preceding_prefix.clone(),
            );
            let common_witness = epoch_construction_witness(
                &construction,
                epoch,
                after_move.predecessor_witness.clone(),
            );
            assert!(
                semantic_construction_kstate(
                    &context,
                    &before_descriptor,
                    &before_statement,
                    &before_prefix,
                    &common_witness,
                )
                .unwrap(),
                "the state before the prover message must hold between {:?} and {:?}",
                before_descriptor.owner(),
                after_descriptor.owner(),
            );
            assert!(
                semantic_construction_kstate(
                    &context,
                    &after_descriptor,
                    &after_statement,
                    &after_prefix,
                    &common_witness,
                )
                .unwrap(),
                "the same witness must hold after the prover message between {:?} and {:?}",
                before_descriptor.owner(),
                after_descriptor.owner(),
            );

            let mut hostile_local_witness = after_move.predecessor_witness.clone();
            mutate_epoch_knowledge_witness(&mut hostile_local_witness);
            let hostile_witness =
                epoch_construction_witness(&construction, epoch, hostile_local_witness);
            check_semantic_construction_prover_move(
                &context,
                (&before_descriptor, &before_statement, &before_prefix),
                (&after_descriptor, &after_statement, &after_prefix),
                &common_witness,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "the canonical prover move between {:?} and {:?} failed: {error:?}",
                    before_descriptor.owner(),
                    after_descriptor.owner(),
                )
            });
            check_semantic_construction_prover_move(
                &context,
                (&before_descriptor, &before_statement, &before_prefix),
                (&after_descriptor, &after_statement, &after_prefix),
                &hostile_witness,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "the hostile prover-move implication between {:?} and {:?} failed: {error:?}",
                    before_descriptor.owner(),
                    after_descriptor.owner(),
                )
            });
            assert!(
                !semantic_construction_kstate(
                    &context,
                    &before_descriptor,
                    &before_statement,
                    &before_prefix,
                    &hostile_witness,
                )
                .unwrap(),
                "the hostile state before the prover message must be false between {:?} and {:?}",
                before_descriptor.owner(),
                after_descriptor.owner(),
            );
            assert!(
                !semantic_construction_kstate(
                    &context,
                    &after_descriptor,
                    &after_statement,
                    &after_prefix,
                    &hostile_witness,
                )
                .unwrap(),
                "the prover message must not repair the hostile state between {:?} and {:?}",
                before_descriptor.owner(),
                after_descriptor.owner(),
            );
        }
    }
}

#[test]
fn construction_epoch_boundary_prover_messages_preserve_the_knowledge_state() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .unwrap();
    let pre_challenge_epoch =
        epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let completed_pre_challenge =
        completed_pre_challenge_handoff(&construction, &pre_challenge_epoch);
    let main_epoch = epoch_fixture(
        &construction.main_opening,
        construction.main_witness.clone(),
    );

    let first_pre_challenge_move = &pre_challenge_epoch.verifier_moves[0];
    let pre_challenge_before_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::CfwJointAndPreWhirOpening,
    );
    let pre_challenge_before_statement = SemanticVerifierMoveStatement::CfwAndPreWhirOpening {
        cfw: &construction.cfw_statement,
        pre_challenge_opening: &construction.pre_opening,
    };
    let pre_challenge_before_prefix = SemanticConstructionPrefix::CfwAndPreWhirOpening {
        completed_outer: construction.completed_outer.clone(),
        active: completed_cfw_handoff(&construction).cfw_and_pre_challenge_opening,
    };
    let pre_challenge_after_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        first_pre_challenge_move
            .owner
            .with_epoch(TranscriptEpoch::PreChallenge),
    );
    let pre_challenge_after_statement = first_pre_challenge_move.statement.as_semantic_statement();
    let pre_challenge_after_prefix = epoch_construction_prefix(
        &construction,
        TranscriptEpoch::PreChallenge,
        None,
        &first_pre_challenge_move.history,
        first_pre_challenge_move.preceding_prefix.clone(),
    );
    let pre_challenge_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::PreChallenge,
        first_pre_challenge_move.predecessor_witness.clone(),
    );
    let mut hostile_pre_challenge_local = first_pre_challenge_move.predecessor_witness.clone();
    mutate_epoch_knowledge_witness(&mut hostile_pre_challenge_local);
    let hostile_pre_challenge_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::PreChallenge,
        hostile_pre_challenge_local,
    );
    assert_prover_boundary_preserves_false_state(
        &context,
        "the first pre-challenge WHIR message",
        &pre_challenge_before_descriptor,
        &pre_challenge_before_statement,
        &pre_challenge_before_prefix,
        &pre_challenge_after_descriptor,
        &pre_challenge_after_statement,
        &pre_challenge_after_prefix,
        &pre_challenge_witness,
        &hostile_pre_challenge_witness,
    );

    let first_main_move = &main_epoch.verifier_moves[0];
    let main_before_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
    );
    let main_before_statement = SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
        pre_challenge_base: &pre_challenge_epoch.base.statement,
        main_opening: &construction.main_opening,
    };
    let main_before_prefix = SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
        completed_cfw: completed_cfw_handoff(&construction),
        history: pre_challenge_epoch.history.clone(),
        active: completed_pre_challenge.pre_final_and_main_opening.clone(),
    };
    let main_after_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        first_main_move.owner.with_epoch(TranscriptEpoch::Main),
    );
    let main_after_statement = first_main_move.statement.as_semantic_statement();
    let main_after_prefix = epoch_construction_prefix(
        &construction,
        TranscriptEpoch::Main,
        Some(&completed_pre_challenge),
        &first_main_move.history,
        first_main_move.preceding_prefix.clone(),
    );
    let main_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::Main,
        first_main_move.predecessor_witness.clone(),
    );
    let mut hostile_main_local = first_main_move.predecessor_witness.clone();
    mutate_epoch_knowledge_witness(&mut hostile_main_local);
    let hostile_main_witness =
        epoch_construction_witness(&construction, TranscriptEpoch::Main, hostile_main_local);
    assert_prover_boundary_preserves_false_state(
        &context,
        "the first main-WHIR message",
        &main_before_descriptor,
        &main_before_statement,
        &main_before_prefix,
        &main_after_descriptor,
        &main_after_statement,
        &main_after_prefix,
        &main_witness,
        &hostile_main_witness,
    );

    let final_pre_challenge_move = pre_challenge_epoch
        .verifier_moves
        .last()
        .expect("the pre-challenge epoch has a base-combination move");
    let final_pre_before_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        final_pre_challenge_move
            .owner
            .with_epoch(TranscriptEpoch::PreChallenge),
    );
    let final_pre_before_statement = final_pre_challenge_move.statement.as_semantic_statement();
    let final_pre_before_prefix = epoch_construction_prefix(
        &construction,
        TranscriptEpoch::PreChallenge,
        None,
        &final_pre_challenge_move.history,
        final_pre_challenge_move.extended_prefix.clone(),
    );
    let final_pre_after_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::PreWhirFinalAndMainWhirOpening,
    );
    let final_pre_after_statement = SemanticVerifierMoveStatement::PreWhirFinalAndMainWhirOpening {
        pre_challenge_base: &pre_challenge_epoch.base.statement,
        main_opening: &construction.main_opening,
    };
    let final_pre_after_prefix = SemanticConstructionPrefix::PreWhirFinalAndMainOpening {
        completed_cfw: completed_cfw_handoff(&construction),
        history: pre_challenge_epoch.history.clone(),
        active: SemanticPreWhirFinalAndMainOpeningPrefix {
            pre_challenge_base: revealed_base_prefix(&pre_challenge_epoch.base),
            main_opening: SemanticWhirOpeningBatchingPrefix {
                batching_challenge: None,
            },
        },
    };
    let final_pre_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::PreChallenge,
        final_pre_challenge_move.post_challenge_witness.clone(),
    );
    let mut hostile_final_pre_local = final_pre_challenge_move.post_challenge_witness.clone();
    mutate_epoch_knowledge_witness(&mut hostile_final_pre_local);
    let hostile_final_pre_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::PreChallenge,
        hostile_final_pre_local,
    );
    assert_prover_boundary_preserves_false_state(
        &context,
        "the pre-challenge terminal reveal",
        &final_pre_before_descriptor,
        &final_pre_before_statement,
        &final_pre_before_prefix,
        &final_pre_after_descriptor,
        &final_pre_after_statement,
        &final_pre_after_prefix,
        &final_pre_witness,
        &hostile_final_pre_witness,
    );

    let final_main_move = main_epoch
        .verifier_moves
        .last()
        .expect("the main epoch has a base-combination move");
    let final_main_before_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        final_main_move.owner.with_epoch(TranscriptEpoch::Main),
    );
    let final_main_before_statement = final_main_move.statement.as_semantic_statement();
    let final_main_before_prefix = epoch_construction_prefix(
        &construction,
        TranscriptEpoch::Main,
        Some(&completed_pre_challenge),
        &final_main_move.history,
        final_main_move.extended_prefix.clone(),
    );
    let final_main_after_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::MainWhirFinalQueries,
    );
    let final_main_after_statement =
        SemanticVerifierMoveStatement::WhirBase(&main_epoch.base.statement);
    let final_main_after_prefix = epoch_construction_prefix(
        &construction,
        TranscriptEpoch::Main,
        Some(&completed_pre_challenge),
        &main_epoch.history,
        SemanticVerifierMovePrefix::WhirBase(revealed_base_prefix(&main_epoch.base)),
    );
    let final_main_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::Main,
        final_main_move.post_challenge_witness.clone(),
    );
    let mut hostile_final_main_local = final_main_move.post_challenge_witness.clone();
    mutate_epoch_knowledge_witness(&mut hostile_final_main_local);
    let hostile_final_main_witness = epoch_construction_witness(
        &construction,
        TranscriptEpoch::Main,
        hostile_final_main_local,
    );
    assert_prover_boundary_preserves_false_state(
        &context,
        "the main-WHIR terminal reveal",
        &final_main_before_descriptor,
        &final_main_before_statement,
        &final_main_before_prefix,
        &final_main_after_descriptor,
        &final_main_after_statement,
        &final_main_after_prefix,
        &final_main_witness,
        &hostile_final_main_witness,
    );
}

#[test]
fn completed_rejecting_verifier_prefixes_remain_outside_the_knowledge_state() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .unwrap();
    let pre_challenge_epoch =
        epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let (first_pre_statement, mut first_pre_prefix) =
        match &pre_challenge_epoch.history.completed_components[0] {
            SemanticWhirCompletedComponent::MaskedSumcheck { statement, prefix } => {
                (statement.clone(), prefix.clone())
            }
            SemanticWhirCompletedComponent::CodeSwitch { .. } => {
                panic!("the first WHIR component must be masked sumcheck")
            }
        };
    first_pre_prefix.combining_challenge = None;
    first_pre_prefix.round_wires.clear();
    first_pre_prefix.round_challenges.clear();

    let mut rejected_cfw_handoff = completed_cfw_handoff(&construction);
    rejected_cfw_handoff
        .cfw_and_pre_challenge_opening
        .cfw
        .round_polynomials[0][0] += CompactChallengeField::ONE;
    let first_pre_prefix = SemanticConstructionPrefix::PreChallengeWhir {
        completed_cfw: rejected_cfw_handoff,
        history: SemanticWhirEpochHistory {
            opening_prefix: pre_challenge_epoch.history.opening_prefix,
            completed_components: Vec::new(),
        },
        active: SemanticVerifierMovePrefix::WhirMaskedSumcheck(first_pre_prefix),
    };
    let first_pre_witness = SemanticConstructionWitness::PreChallengeAndMainInput {
        pre_challenge: SemanticConstructionWhirWitness::Generalized(
            construction.pre_witness.clone(),
        ),
        main: construction.main_witness.clone(),
    };
    let first_pre_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::WhirMaskedSumcheckCombination {
            epoch: TranscriptEpoch::PreChallenge,
            batch_ordinal: 0,
        },
    );
    assert!(
        !semantic_construction_kstate(
            &context,
            &first_pre_descriptor,
            &SemanticVerifierMoveStatement::WhirMaskedSumcheck(&first_pre_statement),
            &first_pre_prefix,
            &first_pre_witness,
        )
        .unwrap()
    );

    let mut rejected_pre_challenge =
        completed_pre_challenge_handoff(&construction, &pre_challenge_epoch);
    let revealed_pre_challenge = rejected_pre_challenge
        .pre_final_and_main_opening
        .pre_challenge_base
        .revealed_witness
        .as_mut()
        .expect("the completed pre-challenge transcript reveals its final witness");
    revealed_pre_challenge.source.message_columns[0][0] =
        revealed_pre_challenge.source.message_columns[0][0].add(field(1));

    let main_epoch = epoch_fixture(
        &construction.main_opening,
        construction.main_witness.clone(),
    );
    let full_prefix = SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(rejected_pre_challenge),
        history: main_epoch.history.clone(),
        active: SemanticVerifierMovePrefix::WhirBase(full_base_prefix(&main_epoch.base)),
    };
    let final_descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::MainWhirFinalQueries,
    );
    assert!(
        !semantic_construction_kstate(
            &context,
            &final_descriptor,
            &SemanticVerifierMoveStatement::WhirBase(&main_epoch.base.statement),
            &full_prefix,
            &SemanticConstructionWitness::Terminal,
        )
        .unwrap()
    );
}

#[test]
fn construction_kstate_refuses_hostile_history_while_errbr_uses_only_the_active_move() {
    let construction = construction_fixture();
    let context = SemanticConstructionContext::new(
        &construction.outer_statement,
        &construction.cfw_statement,
        &construction.pre_opening,
        &construction.main_opening,
    )
    .unwrap();
    let pre_challenge_epoch =
        epoch_fixture(&construction.pre_opening, construction.pre_witness.clone());
    let completed_pre_challenge =
        completed_pre_challenge_handoff(&construction, &pre_challenge_epoch);
    let epoch = epoch_fixture(
        &construction.main_opening,
        construction.main_witness.clone(),
    );
    let descriptor = SemanticFactorOneMoveDescriptor::for_focused_test(
        SemanticVerifierMoveOwner::MainWhirFinalQueries,
    );
    let statement = SemanticVerifierMoveStatement::WhirBase(&epoch.base.statement);
    let terminal = SemanticConstructionWitness::Terminal;
    let prefix_for_history = |history| SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(completed_pre_challenge.clone()),
        history,
        active: SemanticVerifierMovePrefix::WhirBase(full_base_prefix(&epoch.base)),
    };
    let valid_prefix = prefix_for_history(epoch.history.clone());
    assert!(
        semantic_construction_kstate(&context, &descriptor, &statement, &valid_prefix, &terminal,)
            .unwrap()
    );
    let valid_extraction =
        semantic_construction_errbr(&context, &descriptor, &statement, &valid_prefix, &terminal)
            .unwrap();

    let mut reordered = epoch.history.clone();
    reordered.completed_components.swap(0, 1);
    let reordered_prefix = prefix_for_history(reordered);
    assert_eq!(
        semantic_construction_kstate(
            &context,
            &descriptor,
            &statement,
            &reordered_prefix,
            &terminal,
        ),
        Err(SemanticConstructionError::InvalidWhirChronology)
    );
    assert_eq!(
        semantic_construction_errbr(
            &context,
            &descriptor,
            &statement,
            &reordered_prefix,
            &terminal,
        )
        .unwrap(),
        valid_extraction,
        "ERRBR must not replay completed history or invoke KState indirectly",
    );

    let mut truncated = epoch.history.clone();
    truncated.completed_components.pop();
    assert_eq!(
        semantic_construction_kstate(
            &context,
            &descriptor,
            &statement,
            &prefix_for_history(truncated),
            &terminal,
        ),
        Err(SemanticConstructionError::InvalidWhirChronology)
    );

    let mut substituted_opening = epoch.history.clone();
    substituted_opening.opening_prefix.batching_challenge = Some(field(1));
    assert_eq!(
        semantic_construction_kstate(
            &context,
            &descriptor,
            &statement,
            &prefix_for_history(substituted_opening),
            &terminal,
        ),
        Err(SemanticConstructionError::InvalidConstructionChronology)
    );

    let mut substituted_cfw_handoff = completed_pre_challenge.clone();
    substituted_cfw_handoff
        .completed_cfw
        .cfw_and_pre_challenge_opening
        .pre_challenge_opening
        .batching_challenge = Some(field(1));
    let substituted_cfw_prefix = SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(substituted_cfw_handoff),
        history: epoch.history.clone(),
        active: SemanticVerifierMovePrefix::WhirBase(full_base_prefix(&epoch.base)),
    };
    assert_eq!(
        semantic_construction_kstate(
            &context,
            &descriptor,
            &statement,
            &substituted_cfw_prefix,
            &terminal,
        ),
        Err(SemanticConstructionError::InvalidConstructionChronology)
    );

    let mut substituted_main_handoff = completed_pre_challenge;
    substituted_main_handoff
        .pre_final_and_main_opening
        .main_opening
        .batching_challenge = Some(field(1));
    let substituted_main_prefix = SemanticConstructionPrefix::MainWhir {
        completed_pre_challenge: Box::new(substituted_main_handoff),
        history: epoch.history.clone(),
        active: SemanticVerifierMovePrefix::WhirBase(full_base_prefix(&epoch.base)),
    };
    assert_eq!(
        semantic_construction_kstate(
            &context,
            &descriptor,
            &statement,
            &substituted_main_prefix,
            &terminal,
        ),
        Err(SemanticConstructionError::InvalidConstructionChronology)
    );
}
