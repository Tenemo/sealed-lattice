//! Creation-side aggregate binding for the committed key-switch material,
//! cross-bound to each atom proof's material commitment.
//!
//! This is the setup-creation counterpart of `material_aggregate_verify`'s
//! acceptance-path wrapper. For one published runtime key group it regenerates
//! each trustee's atom material commitment - the exact masked material columns and
//! the material-commit salt seed the atom proof used - through the single-source
//! `key_proof::regenerate_material_commitment_inputs` helper, solves the
//! per-coefficient wrap multiples against the published runtime key, and opens
//! every trustee's batched linear evaluation under one shared Fiat-Shamir
//! challenge. The outputs are exactly what the package record and the transported
//! opening set carry: the per-trustee material roots, the per-coefficient wrap
//! multiples, and the encoded opening bytes.
//!
//! Per-atom material-root binding: because the columns and the salt come from the same helper
//! the atom prover publishes its `material_root` through, the recomputed opening
//! column root equals that atom proof's `KeyFriProof.material_root` byte-for-byte.
//! The published `trusteeMaterialRoots` are therefore the atom-verified material
//! roots, and the verifier enforces this equality
//! (`evaluation_key_material_transport::aggregate_binding`), so the aggregate can
//! only bind runtime key to material that passed the atom relation. A malicious
//! aggregator cannot substitute material that has valid delta-openings but fails
//! the atom relation.
//!
//! The columns are the trace interpolation of each trustee's recombined material
//! masked by a deterministic `Z_H` multiple (a multiple of `x^ring_degree - 1`,
//! which vanishes on the trace subgroup `H`). The mask changes the committed
//! coefficients but not the on-`H` material values, so the aggregate identity the
//! verifier checks reconstructs the same integer coefficient sum
//! `S = sum_trustee recombined_B` and the same wraps. The recombined material is
//! derived from the public transported component material, so masking here is for
//! commitment uniformity, not for hiding a secret.
//!
//! Trust boundary: this only produces the binding; the verifier
//! (`material_aggregate_verify::verify_material_aggregate_group_binding` plus the
//! material-root equality check) is the sole authority that accepts or refuses.

use super::super::proof_field::ProofFieldParameters;
use super::key_proof::{
    LinkageLayout, key_switch_linkage_layout, regenerate_material_commitment_inputs,
};
use super::material_aggregate_opening::encode_linear_evaluation_opening_proof;
use super::material_aggregate_verify::prove_material_aggregate;
use super::merkle::MerkleDigest;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

fn invalid_creation(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// One key group's creation-side aggregate binding: the per-trustee material
// roots, the per-coefficient wrap multiples `[digit][coeff]`, and the encoded
// batched linear-evaluation opening bytes per trustee. Ordered by trustee roster
// position, matching the order the verifier gathers them.
pub(super) struct KeyGroupAggregateBinding {
    pub(super) material_roots: Vec<MerkleDigest>,
    pub(super) wrap_multiples: Vec<Vec<i64>>,
    pub(super) opening_bytes: Vec<Vec<u8>>,
}

// Prove the material aggregate binding for one published runtime key group,
// cross-bound to each atom proof's material commitment.
//
// `recombined_material_by_trustee[trustee][digit]` is trustee `trustee`'s
// recombined component material `B_col` for the group's digits (centered CRT
// proof-field vectors of length `ring_degree`, one per digit) - the same
// `public.digits[digit].recombined_component_b` that trustee's atom proof commits.
// `atom_initial_salt_seeds[trustee]` is that trustee's atom proof INITIAL salt
// seed for this key group (`key_salt_seed(statement_hash, proof_index)`), so the
// regenerated material commitment reproduces the atom proof's `material_root`.
// `mask_degree` is the atom proof's mask degree (`schedule_mask_degree`).
// `runtime_key_by_digit[digit][group-limb][coeff]` is the published runtime key
// residues already restricted to this group's limbs. `parameters` and `group`
// come from the caller's sixteen-limb-group proof field and the group's
// `DATA_PRIMES` slice, matching the verifier wrapper.
//
// Returns the per-trustee material roots (the atom-verified material roots), the
// solved wrap multiples, and the encoded openings. Fail-closed: any shape
// mismatch, an unsolvable wrap, or a column-root disagreement inside
// `prove_material_aggregate` returns `Err`.
#[allow(clippy::too_many_arguments)]
pub(super) fn prove_key_group_aggregate_binding<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    group: &super::super::limb_group_statement::LimbGroupContext<LIMB_COUNT>,
    ring_degree: usize,
    roster_size: usize,
    mask_degree: usize,
    recombined_material_by_trustee: &[Vec<Vec<[u64; LIMB_COUNT]>>],
    atom_initial_salt_seeds: &[u64],
    runtime_key_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<KeyGroupAggregateBinding> {
    if roster_size == 0
        || recombined_material_by_trustee.len() != roster_size
        || atom_initial_salt_seeds.len() != roster_size
    {
        return Err(invalid_creation(
            "aggregate binding requires one recombined material set and one atom salt seed per trustee",
        ));
    }
    let digit_count = runtime_key_by_digit.len();
    if digit_count == 0 {
        return Err(invalid_creation(
            "aggregate binding runtime key must have at least one digit",
        ));
    }
    for material in recombined_material_by_trustee {
        if material.len() != digit_count {
            return Err(invalid_creation(
                "each trustee must contribute one recombined material column per digit",
            ));
        }
        for column in material {
            if column.len() != ring_degree {
                return Err(invalid_creation(
                    "recombined material column length must match the ring degree",
                ));
            }
        }
    }

    // The atom proof's linkage layout for this ring degree; key-bearing statements
    // always carry the linkage block, so `base_column_count` in the helper matches
    // the atom prover's `plan.base_column_count()`.
    let linkage_layout: LinkageLayout = key_switch_linkage_layout(ring_degree)?;

    // Regenerate each trustee's atom material commitment: the exact masked columns
    // and the material-commit salt seed the atom proof used, and the material root
    // that equals its `KeyFriProof.material_root`. Both feed the aggregate opening,
    // so the opening binds the atom-verified material.
    let mut material_columns_by_trustee = Vec::with_capacity(roster_size);
    let mut material_roots = Vec::with_capacity(roster_size);
    let mut material_commit_salt_seeds = Vec::with_capacity(roster_size);
    for (trustee_index, material) in recombined_material_by_trustee.iter().enumerate() {
        let (columns, material_commit_salt_seed, material_root) =
            regenerate_material_commitment_inputs(
                parameters,
                ring_degree,
                mask_degree,
                material,
                Some(&linkage_layout),
                atom_initial_salt_seeds[trustee_index],
            )?;
        material_columns_by_trustee.push(columns);
        material_commit_salt_seeds.push(material_commit_salt_seed);
        material_roots.push(material_root);
    }

    let (recomputed_roots, wrap_multiples, openings) = prove_material_aggregate(
        parameters,
        group,
        ring_degree,
        roster_size,
        &material_columns_by_trustee,
        &material_roots,
        &material_commit_salt_seeds,
        runtime_key_by_digit,
        super::schedule::SCHEDULE_QUERY_COUNT,
    )?;
    // `prove_material_aggregate` asserts the recomputed roots equal the supplied
    // ones; this restates that invariant so a future drift in the salt discipline
    // fails here rather than silently publishing mismatched roots.
    if recomputed_roots != material_roots {
        return Err(invalid_creation(
            "aggregate binding material roots diverged from the regenerated atom commitments",
        ));
    }

    let opening_bytes = openings
        .iter()
        .map(encode_linear_evaluation_opening_proof)
        .collect::<CanonicalResult<Vec<Vec<u8>>>>()?;

    Ok(KeyGroupAggregateBinding {
        material_roots,
        wrap_multiples,
        opening_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::super::material_aggregate_verify::{
        AggregateBindingGroupInputs, verify_material_aggregate_group_binding,
    };
    use super::*;
    use crate::bgv::parameters::DATA_PRIMES;

    const RING_DEGREE: usize = 64;
    const ROSTER_SIZE: usize = 4;
    const GROUP_LIMB_COUNT: usize = 2;
    const SALT_SEED: u64 = 0x5ea1_edc0_de00;
    // The atom proof mask degree for this ring: `schedule_mask_degree(64) = 16`.
    const MASK_DEGREE: usize = RING_DEGREE / 4;

    // A deterministic per-trustee atom initial salt seed, standing in for
    // `key_salt_seed(statement_hash, proof_index)`. The value itself is not checked
    // by the verifier (the Fiat-Shamir delta is re-derived from the transported
    // roots, runtime key, and wraps); it only has to be reproducible so the
    // regenerated material commitment and its opening agree.
    fn atom_initial_salt_seed(trustee: usize) -> u64 {
        SALT_SEED
            .wrapping_add(0xA707_0000)
            .wrapping_mul(trustee as u64 + 1)
    }

    // A deterministic small non-negative material value in `[0, 1000)`, so the
    // per-limb residue of the trustee sum stays well inside each level prime and
    // the wrap search exercises the full path without overflowing the field.
    fn small_material_value(trustee: usize, digit: usize, coefficient: usize) -> u64 {
        let mut state = 0x1234_5678_u64
            .wrapping_add(trustee as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add((digit as u64) << 20)
            .wrapping_add(coefficient as u64);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state % 1000
    }

    // Build an honest instance: per-trustee small integer material, its recombined
    // proof-field form (small values recombine to themselves here), and the
    // runtime key as the per-limb residue of the integer material sum.
    #[allow(clippy::type_complexity)]
    fn honest_instance(
        parameters: &ProofFieldParameters<13>,
    ) -> (Vec<Vec<Vec<[u64; 13]>>>, Vec<Vec<Vec<u64>>>) {
        let mut material_integers =
            vec![vec![vec![0_u64; RING_DEGREE]; GROUP_LIMB_COUNT]; ROSTER_SIZE];
        for (trustee, digits) in material_integers.iter_mut().enumerate() {
            for (digit, coefficients) in digits.iter_mut().enumerate() {
                for (coefficient, slot) in coefficients.iter_mut().enumerate() {
                    *slot = small_material_value(trustee, digit, coefficient);
                }
            }
        }

        // Recombined material per trustee per digit: the small values map to
        // proof-field elements directly (they are far below each level prime).
        let recombined_material_by_trustee: Vec<Vec<Vec<[u64; 13]>>> = material_integers
            .iter()
            .map(|digits| {
                digits
                    .iter()
                    .map(|values| {
                        values
                            .iter()
                            .map(|value| parameters.unsigned_word_to_element(*value))
                            .collect()
                    })
                    .collect()
            })
            .collect();

        // Runtime key: the per-limb residue of the integer material sum.
        let runtime_key_by_digit: Vec<Vec<Vec<u64>>> = (0..GROUP_LIMB_COUNT)
            .map(|digit| {
                (0..GROUP_LIMB_COUNT)
                    .map(|limb| {
                        let prime = DATA_PRIMES[limb];
                        (0..RING_DEGREE)
                            .map(|coefficient| {
                                let sum: u128 = material_integers
                                    .iter()
                                    .map(|digits| u128::from(digits[digit][coefficient]))
                                    .sum();
                                (sum % u128::from(prime)) as u64
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        (recombined_material_by_trustee, runtime_key_by_digit)
    }

    #[test]
    fn creation_side_aggregate_binding_verifies_and_rejects_forgeries() {
        let parameters = sixteen_limb_group_field_parameters();
        let group_primes = &DATA_PRIMES[..GROUP_LIMB_COUNT];
        let group = super::super::super::limb_group_statement::LimbGroupContext::new(
            &parameters,
            group_primes,
        )
        .expect("group builds");
        let (recombined_material_by_trustee, runtime_key_by_digit) = honest_instance(&parameters);
        let atom_initial_salt_seeds: Vec<u64> =
            (0..ROSTER_SIZE).map(atom_initial_salt_seed).collect();

        let binding = prove_key_group_aggregate_binding(
            &parameters,
            &group,
            RING_DEGREE,
            ROSTER_SIZE,
            MASK_DEGREE,
            &recombined_material_by_trustee,
            &atom_initial_salt_seeds,
            &runtime_key_by_digit,
        )
        .expect("creation-side aggregate binding proves");

        // Per-atom material-root binding: each published material root must equal the material
        // root the shared `regenerate_material_commitment_inputs` helper produces
        // for that trustee's atom commitment - the exact value the atom proof would
        // publish as `KeyFriProof.material_root`.
        let linkage_layout = key_switch_linkage_layout(RING_DEGREE).expect("linkage layout");
        for (trustee, material) in recombined_material_by_trustee.iter().enumerate() {
            let (_columns, _salt, expected_root) = regenerate_material_commitment_inputs(
                &parameters,
                RING_DEGREE,
                MASK_DEGREE,
                material,
                Some(&linkage_layout),
                atom_initial_salt_seeds[trustee],
            )
            .expect("regenerate atom material commitment");
            assert_eq!(
                binding.material_roots[trustee], expected_root,
                "each published material root must equal the regenerated atom material root"
            );
        }

        assert_eq!(
            binding.material_roots.len(),
            ROSTER_SIZE,
            "one material root per trustee"
        );
        assert_eq!(
            binding.opening_bytes.len(),
            ROSTER_SIZE,
            "one opening per trustee"
        );
        assert_eq!(
            binding.wrap_multiples.len(),
            GROUP_LIMB_COUNT,
            "one wrap row per digit"
        );

        // The verifier wrapper accepts the honestly produced binding against the
        // same runtime key.
        let inputs = AggregateBindingGroupInputs {
            group_start_limb: 0,
            group_limb_count: GROUP_LIMB_COUNT,
            ring_degree: RING_DEGREE,
            roster_size: ROSTER_SIZE,
            query_count: super::super::schedule::SCHEDULE_QUERY_COUNT,
            material_roots: &binding.material_roots,
            runtime_key_by_digit: &runtime_key_by_digit,
            wrap_multiples: &binding.wrap_multiples,
            opening_bytes: &binding.opening_bytes,
        };
        assert!(
            verify_material_aggregate_group_binding(&inputs).is_ok(),
            "the honestly produced aggregate binding must verify"
        );

        // A forged runtime-key residue must be rejected by the verifier wrapper.
        let mut forged_runtime_key = runtime_key_by_digit.clone();
        forged_runtime_key[1][0][5] = (forged_runtime_key[1][0][5] + 1) % DATA_PRIMES[0];
        let forged_inputs = AggregateBindingGroupInputs {
            runtime_key_by_digit: &forged_runtime_key,
            ..inputs
        };
        assert!(
            verify_material_aggregate_group_binding(&forged_inputs).is_err(),
            "a forged runtime-key residue must be refused"
        );

        // A tampered wrap multiple must be rejected: the delta transcript diverges
        // and the identity fails.
        let mut forged_wraps = binding.wrap_multiples.clone();
        forged_wraps[0][3] += 1;
        let forged_wrap_inputs = AggregateBindingGroupInputs {
            wrap_multiples: &forged_wraps,
            ..inputs
        };
        assert!(
            verify_material_aggregate_group_binding(&forged_wrap_inputs).is_err(),
            "a tampered wrap multiple must be refused"
        );
    }
}
