//! Deterministic committed-material trees for the VSS commitment family.
//!
//! One tree per commitment field commits a VSS message's canonical digit
//! columns as masked `TRACE_SPLIT` half-columns over the `DOMAIN_BLOWUP` coset.
//! Salted phase-pair Merkle leaves bind the extension values; leaf salts and
//! `Z_H`-multiple column masks hide unopened values.
//!
//! Mask and salt streams derive from the holder's private material seed and the
//! commitment-context hash, so later phases regenerate byte-identical trees.
//!
//! A persistent tree is opened by at most three proof flows, each exposing at
//! most `2 * LOW_DEGREE_QUERY_COUNT` evaluations plus the DEEP points: 1017
//! evaluations total. At the full trace, the mask cap covers that total; at
//! every trace it remains at most the trace size. These columns enter only
//! linear rows, preserving the committed degree bound
//! `COMMITMENT_BOUND_FACTOR * trace`.

use super::super::evaluation_domain::EvaluationDomainPlan;
use super::super::merkle_commitment::MerkleDigest;
use super::super::relation::{TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness};
use super::super::{TRACE_SPLIT, invalid_succinct_setup_proof};
use super::claim_masking::masked_half_coefficients_with_mask_degree;
use super::salted_tree::{SaltedTree, commit_salted_extension_row_pairs};
use crate::bgv::evaluator::prg::DeterministicSampler;
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;
use crate::bgv::setup::vss_commitment::vss_public_canonical_message_digit_columns;
use crate::encoding::CanonicalResult;

const VSS_COMMITTED_MATERIAL_COLUMN_MASK_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/column-mask";
const VSS_COMMITTED_MATERIAL_LEAF_SALT_DOMAIN: &str =
    "sealed-lattice/setup/vss-committed-material/leaf-salt";

// Covers three 339-evaluation opening sets plus two additional sets. The
// trace-size minimum below preserves the committed degree bound.
pub(crate) const VSS_COMMITTED_MATERIAL_COLUMN_MASK_DEGREE_CAP: usize = 2048;

pub(crate) fn vss_committed_material_column_mask_degree(trace_size: usize) -> usize {
    VSS_COMMITTED_MATERIAL_COLUMN_MASK_DEGREE_CAP.min(trace_size)
}

pub(crate) struct VssCommittedMaterialTreeInput<'a> {
    // Canonical digit columns of the committed message, digit-major, each of
    // ring-degree length. Digit values are small integers below every
    // commitment-field modulus, so one integer column serves every field.
    pub(crate) message_digit_columns: &'a [Vec<u64>],
    pub(crate) ring_degree: usize,
    // The holder's private deterministic seed for the mask and salt streams.
    pub(crate) material_seed_hex: &'a str,
    // The commitment-context hash, mixed into the mask and salt derivations so
    // trees for different roles or ceremony contexts never share masks.
    pub(crate) commitment_context_hash: &'a str,
}

// One commitment field's regenerated committed-material trees: the masked
// coefficient forms (for out-of-domain evaluation), the extension codeword
// columns (digit-major, half-minor physical order), and the salted phase-pair
// tree. The share-linkage prover reuses these to answer the shared query
// positions; the verifier only ever sees the root and the openings.
pub(super) struct VssCommittedMaterialFieldTrees {
    pub(super) masked_coefficients: Vec<Vec<u64>>,
    pub(super) extension_columns: Vec<Vec<u64>>,
    pub(super) salted: SaltedTree,
}

// Build the per-commitment-field committed-material trees for one VSS message.
// Deterministic: identical inputs regenerate byte-identical trees and roots,
// which is what makes the commitment stable across ceremony phases.
pub(super) fn vss_committed_material_trees_by_commitment_field(
    input: &VssCommittedMaterialTreeInput<'_>,
) -> CanonicalResult<Vec<VssCommittedMaterialFieldTrees>> {
    if input.message_digit_columns.is_empty() {
        return Err(invalid_succinct_setup_proof(
            "VSS committed material requires at least one digit column",
        ));
    }
    if !input.ring_degree.is_power_of_two() || input.ring_degree < TRACE_SPLIT {
        return Err(invalid_succinct_setup_proof(
            "VSS committed material ring degree must be a power of two covering the trace split",
        ));
    }
    for column in input.message_digit_columns {
        if column.len() != input.ring_degree {
            return Err(invalid_succinct_setup_proof(
                "VSS committed material digit column length must match the ring degree",
            ));
        }
    }
    let trace_size = input.ring_degree / TRACE_SPLIT;
    let mask_degree = vss_committed_material_column_mask_degree(trace_size);

    let mut trees_by_field = Vec::with_capacity(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
    for (commitment_field_position, commitment_modulus_index) in
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.iter().enumerate()
    {
        let modulus = DATA_PRIMES[*commitment_modulus_index];
        // Rejects out-of-range trace sizes (below the minimum or beyond the
        // two-adicity headroom) with the shared domain-plan refusal.
        let plan = EvaluationDomainPlan::new(modulus, trace_size)?;
        let mut masked_coefficients_by_column =
            Vec::with_capacity(input.message_digit_columns.len() * TRACE_SPLIT);
        let mut extension_columns =
            Vec::with_capacity(input.message_digit_columns.len() * TRACE_SPLIT);
        for (digit_index, digit_column) in input.message_digit_columns.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                let physical_column_index = digit_index * TRACE_SPLIT + half;
                let half_values = &digit_column[half * trace_size..(half + 1) * trace_size];
                let mut mask_sampler = DeterministicSampler::new(
                    VSS_COMMITTED_MATERIAL_COLUMN_MASK_DOMAIN,
                    &[
                        input.material_seed_hex.as_bytes(),
                        input.commitment_context_hash.as_bytes(),
                        &(commitment_field_position as u64).to_le_bytes(),
                        &(physical_column_index as u64).to_le_bytes(),
                    ],
                );
                let coefficients = masked_half_coefficients_with_mask_degree(
                    &plan,
                    half_values,
                    mask_degree,
                    &mut mask_sampler,
                );
                extension_columns.push(plan.extension_evaluations_from_coefficients(&coefficients));
                masked_coefficients_by_column.push(coefficients);
            }
        }
        let mut salt_sampler = DeterministicSampler::new(
            VSS_COMMITTED_MATERIAL_LEAF_SALT_DOMAIN,
            &[
                input.material_seed_hex.as_bytes(),
                input.commitment_context_hash.as_bytes(),
                &(commitment_field_position as u64).to_le_bytes(),
            ],
        );
        let salted = commit_salted_extension_row_pairs(
            &extension_columns,
            plan.extension_size,
            &mut salt_sampler,
        )?;
        trees_by_field.push(VssCommittedMaterialFieldTrees {
            masked_coefficients: masked_coefficients_by_column,
            extension_columns,
            salted,
        });
    }

    Ok(trees_by_field)
}

pub(crate) fn vss_committed_material_roots_by_commitment_field(
    input: &VssCommittedMaterialTreeInput<'_>,
) -> CanonicalResult<Vec<MerkleDigest>> {
    Ok(vss_committed_material_trees_by_commitment_field(input)?
        .iter()
        .map(|field_trees| field_trees.salted.tree.root())
        .collect())
}

// The regenerated committed-material trees for every bound message of a
// material-binding statement: `trees_by_bound_message[m][c]` is bound message
// m's tree over commitment field c. Regenerated once per statement and shared
// by every commitment-field limb proof.
pub(super) struct BoundCommittedMaterial {
    pub(super) trees_by_bound_message: Vec<Vec<VssCommittedMaterialFieldTrees>>,
}

impl BoundCommittedMaterial {
    pub(super) fn is_empty(&self) -> bool {
        self.trees_by_bound_message.is_empty()
    }
}

// The canonical message coefficients behind every bound commitment, in the
// statement's bound-commitment order, assembled from the witness the same way
// the witness columns are built (so the binding rows hold exactly when the
// commitment matches the proven witness).
fn bound_message_coefficients(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let to_unsigned = |coefficients: &[i64], label: &str| -> CanonicalResult<Vec<u64>> {
        coefficients
            .iter()
            .map(|coefficient| {
                u64::try_from(*coefficient).map_err(|_| {
                    invalid_succinct_setup_proof(format!(
                        "{label} must be a canonical non-negative residue"
                    ))
                })
            })
            .collect()
    };

    if let Some(share_linkage) = &statement.vss_share_linkage {
        let slot_count = share_linkage.unique_coefficient_witness_slot_count();
        if witness
            .vss_public_coefficient_messages_by_shamir_index
            .len()
            != slot_count
        {
            return Err(invalid_succinct_setup_proof(
                "VSS coefficient witness count does not match the bound commitments",
            ));
        }
        let mut messages = Vec::with_capacity(slot_count + share_linkage.item_count());
        for coefficient_messages in &witness.vss_public_coefficient_messages_by_shamir_index {
            messages.push(to_unsigned(
                coefficient_messages,
                "VSS coefficient message coefficient",
            )?);
        }
        let recipient_messages_by_item: Vec<&[i64]> = witness
            .vss_public_recipient_share_messages_by_item
            .iter()
            .map(Vec::as_slice)
            .collect();
        if recipient_messages_by_item.len() != share_linkage.item_count() {
            return Err(invalid_succinct_setup_proof(
                "VSS recipient share witness count does not match the bound commitments",
            ));
        }
        for recipient_messages in recipient_messages_by_item {
            messages.push(to_unsigned(
                recipient_messages,
                "VSS recipient share message coefficient",
            )?);
        }

        return Ok(messages);
    }
    if let Some(bridge) = &statement.same_secret_bridge {
        let mut messages = Vec::with_capacity(bridge.bridge_rns_primes.len());
        for target_rns_prime in &bridge.bridge_rns_primes {
            let target_message_coefficients = witness
                .secret_coefficients
                .iter()
                .zip(witness.negative_indicator_coefficients.iter())
                .map(|(secret_coefficient, negative_indicator)| {
                    let target_message = i128::from(*secret_coefficient)
                        + i128::from(*target_rns_prime) * i128::from(*negative_indicator);
                    u64::try_from(target_message).map_err(|_| {
                        invalid_succinct_setup_proof(
                            "same-secret bridge target message coefficient is negative",
                        )
                    })
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            messages.push(target_message_coefficients);
        }

        return Ok(messages);
    }
    if statement.target_decryption_share.is_some() {
        return witness
            .target_decryption_message_vectors
            .iter()
            .map(|message_vector| {
                to_unsigned(message_vector, "target-decryption message coefficient")
            })
            .collect();
    }

    Ok(Vec::new())
}

// Regenerate every bound committed-material tree from the witness seeds and
// refuse fail-closed if any regenerated root differs from the statement's
// roots. A proof never commits fresh trees: the openings must be of the
// published commitments, or the statement is not provable.
pub(super) fn regenerate_bound_committed_material(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<BoundCommittedMaterial> {
    let bound_commitments = statement.vss_committed_material_bound_commitments();
    if bound_commitments.is_empty() {
        return Ok(BoundCommittedMaterial {
            trees_by_bound_message: Vec::new(),
        });
    }
    if witness.vss_committed_material_seeds_by_bound_message.len() != bound_commitments.len()
        || witness
            .vss_committed_material_context_hashes_by_bound_message
            .len()
            != bound_commitments.len()
    {
        return Err(invalid_succinct_setup_proof(
            "committed-material witness must carry one seed and one context hash per bound commitment",
        ));
    }
    let messages = bound_message_coefficients(statement, witness)?;
    if messages.len() != bound_commitments.len() {
        return Err(invalid_succinct_setup_proof(
            "committed-material witness messages do not cover every bound commitment",
        ));
    }

    let mut trees_by_bound_message = Vec::with_capacity(bound_commitments.len());
    for (bound_message_index, (bound_commitment, message_coefficients)) in
        bound_commitments.iter().zip(messages.iter()).enumerate()
    {
        let message_digit_columns = vss_public_canonical_message_digit_columns(
            message_coefficients,
            statement.ring_degree,
        )?;
        let field_trees =
            vss_committed_material_trees_by_commitment_field(&VssCommittedMaterialTreeInput {
                message_digit_columns: &message_digit_columns,
                ring_degree: statement.ring_degree,
                material_seed_hex: &witness.vss_committed_material_seeds_by_bound_message
                    [bound_message_index],
                commitment_context_hash: &witness
                    .vss_committed_material_context_hashes_by_bound_message[bound_message_index],
            })?;
        for (commitment_field_position, field_tree) in field_trees.iter().enumerate() {
            let expected_root = bound_commitment
                .material_roots_by_commitment_field
                .get(commitment_field_position)
                .ok_or_else(|| {
                    invalid_succinct_setup_proof(
                        "bound commitment does not carry one material root per commitment field",
                    )
                })?;
            if field_tree.salted.tree.root() != *expected_root {
                return Err(invalid_succinct_setup_proof(
                    "regenerated committed-material root does not match the statement's commitment",
                ));
            }
        }
        trees_by_bound_message.push(field_trees);
    }

    Ok(BoundCommittedMaterial {
        trees_by_bound_message,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::merkle_commitment::{
        consistent_sorted_leaves, phase_pair_leaf_hash, sorted_unique_indices, verify_merkle_batch,
    };
    use super::*;
    use crate::bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast, pow_mod};
    use crate::bgv::setup::vss_commitment::vss_public_canonical_message_digit_columns;

    const TEST_RING_DEGREE: usize = 128;

    fn test_digit_columns() -> Vec<Vec<u64>> {
        let message: Vec<u64> = (0..TEST_RING_DEGREE)
            .map(|coefficient_index| {
                let mixed = (coefficient_index as u128 + 7)
                    * (coefficient_index as u128 + 13)
                    * 2_654_435_761_u128;
                (mixed % u128::from(DATA_PRIMES[0])) as u64
            })
            .collect();
        vss_public_canonical_message_digit_columns(&message, TEST_RING_DEGREE)
            .expect("canonical digit columns")
    }

    fn test_seed_hex() -> String {
        "42".repeat(64)
    }

    fn test_context_hash() -> String {
        "9c".repeat(64)
    }

    fn evaluate_coefficients(coefficients: &[u64], point: u64, modulus: u64) -> u64 {
        let mut accumulated = 0_u64;
        for coefficient in coefficients.iter().rev() {
            accumulated = add_mod_fast(
                mul_mod_fast(accumulated, point, modulus),
                *coefficient,
                modulus,
            );
        }

        accumulated
    }

    // The cross-phase opening property the share-linkage, aggregate-opening,
    // bridge, and target-decryption proofs rely on: a later phase regenerates
    // the trees byte-identically from the persisted seed, opens arbitrary pair
    // positions, and every opening authenticates against the original root
    // through the same batched Merkle path the limb verifier runs.
    #[test]
    fn committed_material_trees_open_and_reverify_across_regeneration() {
        let digit_columns = test_digit_columns();
        let seed = test_seed_hex();
        let context_hash = test_context_hash();
        let input = VssCommittedMaterialTreeInput {
            message_digit_columns: &digit_columns,
            ring_degree: TEST_RING_DEGREE,
            material_seed_hex: &seed,
            commitment_context_hash: &context_hash,
        };
        let trees_by_field =
            vss_committed_material_trees_by_commitment_field(&input).expect("trees");
        let regenerated_by_field =
            vss_committed_material_trees_by_commitment_field(&input).expect("regenerated trees");

        for (field_position, (field_trees, regenerated)) in trees_by_field
            .iter()
            .zip(regenerated_by_field.iter())
            .enumerate()
        {
            let field_modulus = DATA_PRIMES[SETUP_COMMITMENT_MODULUS_LIMB_INDICES[field_position]];
            let pair_count = field_trees.extension_columns[0].len() / 2;
            let depth = pair_count.trailing_zeros() as usize;
            let root = field_trees.salted.tree.root();

            // A later phase reproduces the exact tree from the persisted seed.
            assert_eq!(
                root,
                regenerated.salted.tree.root(),
                "regeneration must reproduce the committed root"
            );
            assert_eq!(
                field_trees.extension_columns, regenerated.extension_columns,
                "regeneration must reproduce the committed codewords"
            );

            let pair_indices =
                sorted_unique_indices([0_usize, 1, 5, pair_count / 2, pair_count - 1]);
            let batched_opening = field_trees.salted.tree.open_batch(&pair_indices);
            // Reconstruct the opened pair rows exactly as a verifier receives
            // them: one row per half across every physical column, hashed with
            // the pair salt.
            let opened_leaves = pair_indices
                .iter()
                .map(|&pair_index| {
                    let first_row: Vec<u64> = field_trees
                        .extension_columns
                        .iter()
                        .map(|column| column[pair_index])
                        .collect();
                    let second_row: Vec<u64> = field_trees
                        .extension_columns
                        .iter()
                        .map(|column| column[pair_index + pair_count])
                        .collect();
                    assert_eq!(
                        field_trees.salted.pair_salt(pair_index),
                        regenerated.salted.pair_salt(pair_index),
                        "regeneration must reproduce the pair salts"
                    );
                    (
                        pair_index,
                        phase_pair_leaf_hash(
                            pair_index,
                            field_trees.salted.pair_salt(pair_index),
                            &first_row,
                            &second_row,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let sorted_leaves =
                consistent_sorted_leaves(opened_leaves.clone()).expect("consistent leaves");
            assert!(
                verify_merkle_batch(&root, depth, &sorted_leaves, &batched_opening),
                "an honest batched opening must verify against the committed root"
            );

            // A tampered opened value is rejected.
            let mut tampered_leaves = opened_leaves;
            let (tampered_pair, _) = tampered_leaves[2];
            let mut tampered_first_row: Vec<u64> = field_trees
                .extension_columns
                .iter()
                .map(|column| column[tampered_pair])
                .collect();
            tampered_first_row[0] = add_mod_fast(tampered_first_row[0], 1, field_modulus);
            let tampered_second_row: Vec<u64> = field_trees
                .extension_columns
                .iter()
                .map(|column| column[tampered_pair + pair_count])
                .collect();
            tampered_leaves[2] = (
                tampered_pair,
                phase_pair_leaf_hash(
                    tampered_pair,
                    field_trees.salted.pair_salt(tampered_pair),
                    &tampered_first_row,
                    &tampered_second_row,
                ),
            );
            let tampered_sorted =
                consistent_sorted_leaves(tampered_leaves).expect("consistent leaves");
            assert!(
                !verify_merkle_batch(&root, depth, &tampered_sorted, &batched_opening),
                "a tampered opened row must be rejected"
            );
        }

        // A different field's root never authenticates this field's openings.
        let first_field = &trees_by_field[0];
        let other_root = trees_by_field[1].salted.tree.root();
        let pair_count = first_field.extension_columns[0].len() / 2;
        let depth = pair_count.trailing_zeros() as usize;
        let pair_indices = sorted_unique_indices([3_usize, 8]);
        let batched_opening = first_field.salted.tree.open_batch(&pair_indices);
        let opened_leaves = pair_indices
            .iter()
            .map(|&pair_index| {
                let first_row: Vec<u64> = first_field
                    .extension_columns
                    .iter()
                    .map(|column| column[pair_index])
                    .collect();
                let second_row: Vec<u64> = first_field
                    .extension_columns
                    .iter()
                    .map(|column| column[pair_index + pair_count])
                    .collect();
                (
                    pair_index,
                    phase_pair_leaf_hash(
                        pair_index,
                        first_field.salted.pair_salt(pair_index),
                        &first_row,
                        &second_row,
                    ),
                )
            })
            .collect::<Vec<_>>();
        let sorted_leaves = consistent_sorted_leaves(opened_leaves).expect("consistent leaves");
        assert!(
            !verify_merkle_batch(&other_root, depth, &sorted_leaves, &batched_opening),
            "another field's root must not authenticate these openings"
        );
    }

    // The two algebraic properties the binding row and the batched FRI rely
    // on: every committed codeword interpolates to a polynomial under the
    // committed degree bound, and the mask leaves the on-trace digit values
    // unchanged.
    #[test]
    fn committed_material_columns_keep_trace_values_and_degree_bound() {
        let digit_columns = test_digit_columns();
        let seed = test_seed_hex();
        let context_hash = test_context_hash();
        let trees_by_field =
            vss_committed_material_trees_by_commitment_field(&VssCommittedMaterialTreeInput {
                message_digit_columns: &digit_columns,
                ring_degree: TEST_RING_DEGREE,
                material_seed_hex: &seed,
                commitment_context_hash: &context_hash,
            })
            .expect("trees");
        let trace_size = TEST_RING_DEGREE / TRACE_SPLIT;
        let mask_degree = vss_committed_material_column_mask_degree(trace_size);

        for (field_position, field_trees) in trees_by_field.iter().enumerate() {
            let field_modulus = DATA_PRIMES[SETUP_COMMITMENT_MODULUS_LIMB_INDICES[field_position]];
            let plan =
                EvaluationDomainPlan::new(field_modulus, trace_size).expect("field domain plan");
            for (physical_column_index, extension_column) in
                field_trees.extension_columns.iter().enumerate()
            {
                let digit_index = physical_column_index / TRACE_SPLIT;
                let half = physical_column_index % TRACE_SPLIT;
                let coefficients = plan
                    .coefficients_from_extension_evaluations(extension_column)
                    .expect("coefficient recovery");
                // Degree bound: the masked column stays strictly below
                // COMMITMENT_BOUND_FACTOR * trace, so FRI accepts it.
                for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
                    if coefficient_index >= trace_size + mask_degree {
                        assert_eq!(
                            *coefficient, 0,
                            "masked column degree must stay under the committed bound"
                        );
                    }
                }
                // Trace values: the Z_H mask vanishes on H, so evaluating the
                // committed polynomial at trace points returns the canonical
                // digit values the binding row equates.
                for trace_position in [0_usize, 1, trace_size - 1] {
                    let trace_point =
                        pow_mod(plan.trace_root, trace_position as u64, field_modulus)
                            .expect("trace point");
                    assert_eq!(
                        evaluate_coefficients(&coefficients, trace_point, field_modulus),
                        digit_columns[digit_index][half * trace_size + trace_position],
                        "on-trace evaluations must equal the canonical digit values"
                    );
                }
            }
        }
    }
}
