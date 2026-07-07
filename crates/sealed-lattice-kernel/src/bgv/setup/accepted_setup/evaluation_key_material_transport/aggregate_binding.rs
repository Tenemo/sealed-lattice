//! Verifier-side wiring of the committed-material aggregate binding (S1) into
//! the accepted-setup evaluation-key verification.
//!
//! The runtime relinearization and Galois keys are still DERIVED and returned by
//! `public_key_reconstruction`, which sums each trustee's raw `component_b`
//! per RNS limb. This module ADDS the aggregate binding the verified-download
//! reduction introduces: it binds the published runtime key to the trustee-
//! committed material through the atom proofs' material roots plus a batched
//! linear-evaluation opening per trustee, with public per-coefficient wrap
//! multiples, checked by the family backend's `verify_material_aggregate`.
//!
//! A follow-up will RETIRE the raw-material summing as the aggregate binding once
//! the setup-creation side emits the openings; until then both run - the runtime
//! key stays a derivation checked by this identity rather than the aggregate's
//! only binding. This file does NOT implement that creation-side aggregator; it
//! only defines what the verifier consumes and runs the check fail-closed.
//!
//! S2 cross-binding: the aggregate opening on its own only proves it opens
//! whatever material root the package publishes. To tie that material to the
//! ATOM-VERIFIED material, this module also surfaces each trustee's atom proof
//! `KeyFriProof.material_root` (decoded from the verified schedule container) and
//! REFUSES unless every package `trusteeMaterialRoots` entry equals the atom
//! proof's own root for the same (trustee, key group). Without this, a malicious
//! aggregator could publish a self-committed root over material that has valid
//! delta-openings but fails the atom relation.
//!
//! Per key group (one atom proof: a key and a consecutive `DATA_PRIMES` slice, so
//! keys wider than the sixteen-limb group split into consecutive groups) the
//! verifier gathers, from the newly defined package and request fields:
//!
//! - the per-trustee committed material roots (each from that trustee's atom
//!   proof `materialRoot`, surfaced in the package aggregate-binding record, and
//!   cross-checked against the atom proof's own `material_root`),
//! - the per-trustee batched linear-evaluation opening bytes (transported in the
//!   request, decoded through the family backend's opening codec),
//! - the per-coefficient wrap multiples `[digit][coeff]`, range-checked
//!   `|w| <= ceil(roster_size / 2)`,
//! - the published runtime key residues, recomputed here by the same per-limb
//!   trustee sum `public_key_reconstruction` reads, sliced to the group's limbs.

use super::super::same_secret_bridge_verification::verified_same_secret_bridge_material_from_package;
use super::material_transport::evaluation_key_material_verification_failure;
use super::public_key_reconstruction::accepted_key_switch_runtime_residues_by_digit;
use super::*;

use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::limb_group_key_switch_atom::family_backend::material_aggregate_verify::{
    AGGREGATE_MATERIAL_ROOT_BYTES, AggregateBindingGroupInputs, material_root_from_hex,
    verify_material_aggregate_group_binding,
};

// The sixteen-limb group capacity: a key at level L has L + 1 digits and L + 1
// RNS limbs; keys wider than this split into consecutive limb groups, one atom
// proof per group, matching the schedule prover's `LIMB_GROUP_CAPACITY`. The
// aggregate binding runs per group, so this bounds each group's limb count.
const AGGREGATE_BINDING_LIMB_GROUP_CAPACITY: usize = 16;

// The FRI query count the schedule prover and its atom proofs use, so the
// transported openings the verifier checks share the same soundness parameter.
// Recomputed here (not read from the package) so a package cannot weaken it.
const AGGREGATE_BINDING_QUERY_COUNT: usize = 80;

// Object types for the newly defined aggregate-binding package record and the
// transported opening set. Self-describing and canonical, like the other
// evaluation-key transport objects.
const AGGREGATE_BINDING_SET_OBJECT_TYPE: &str = "EvaluationKeyAggregateBindingSet";
const AGGREGATE_BINDING_KEY_GROUP_OBJECT_TYPE: &str = "EvaluationKeyAggregateBindingKeyGroup";
const AGGREGATE_BINDING_OPENING_SET_OBJECT_TYPE: &str =
    "SetupTransportedEvaluationKeyAggregateBindingOpeningSet";

// The maximum wrap-multiple magnitude the identity accepts for a roster of the
// given size: each centered mod-Q_L summand is in (-Q_L/2, Q_L/2], so the sum of
// `roster_size` of them wraps by at most `ceil(roster_size / 2)`. Range-checked
// here before the field enters the identity, mirroring the family backend's own
// bound, so a malformed field is refused before any proof work.
fn maximum_aggregate_wrap_multiple_magnitude(roster_size: u64) -> i64 {
    roster_size.div_ceil(2) as i64
}

// Validate that a supplied material root is the canonical lowercase-hex encoding
// of an atom-proof Merkle digest. Unlike the 128-character (64-byte) canonical
// object hashes the rest of the setup package carries, the atom material root is
// a fixed-width Merkle digest (`AGGREGATE_MATERIAL_ROOT_BYTES` bytes), so it is
// exactly `2 * AGGREGATE_MATERIAL_ROOT_BYTES` lowercase hex characters. This is
// the width `material_root_from_hex` decodes, so the two agree and a well-formed
// creation-side material root is accepted rather than refused as a wrong-length
// protocol hash. Fail-closed on any wrong length or non-lowercase-hex byte.
fn validate_material_root_hex(material_root: &str, field_name: &str) -> CanonicalResult<()> {
    let expected_hex_length = AGGREGATE_MATERIAL_ROOT_BYTES * 2;
    let is_canonical_digest = material_root.len() == expected_hex_length
        && material_root
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !is_canonical_digest {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{field_name} must be a {expected_hex_length}-character lowercase hexadecimal Merkle digest"
            ),
        ));
    }
    Ok(())
}

// Whether the evaluation-key set declares the aggregate-binding record. The
// binding is only checked when the package publishes it; a package without it is
// still gated by `public_key_reconstruction`, which remains present.
pub(super) fn evaluation_key_set_has_aggregate_binding(evaluation_keys: &Value) -> bool {
    evaluation_keys.get("aggregateBinding").is_some()
}

// Verify the committed-material aggregate binding for every scheduled key group.
// Returns a fail-closed refusal on any malformed field, missing opening, out-of-
// range wrap, or broken aggregate identity, and `Ok(None)` when every key group's
// published runtime key matches its committed-material aggregate. The result is
// the structural pass or refuse only - there is no self-attested status field.
pub(super) fn verify_accepted_key_switch_aggregate_binding(
    setup_package: &Value,
    evaluation_keys: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let roster = super::super::accepted_roster_from_package(setup_package);
    let aggregate_binding = evaluation_keys
        .get("aggregateBinding")
        .expect("aggregate binding presence was checked before verification");
    if aggregate_binding.get("objectType").and_then(Value::as_str)
        != Some(AGGREGATE_BINDING_SET_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyAggregateBindingTypeMismatch",
            "evaluationKeys.aggregateBinding.objectType must be an aggregate-binding set",
            "setupPackage.evaluationKeys.aggregateBinding",
        )?));
    }
    let opening_bytes_by_material_root =
        match transported_aggregate_binding_openings_by_material_root(request) {
            Ok(openings) => openings,
            Err(error) => {
                return Ok(Some(evaluation_key_material_verification_failure(
                    error,
                    "transportedEvaluationKeyAggregateBindingOpenings",
                )?));
            }
        };

    // Surface each trustee's atom-proof material commitment roots (S2 cross-
    // binding): the aggregate binds runtime key to the trustee-committed material
    // only if every package `trusteeMaterialRoots` entry equals the ATOM proof's
    // own `KeyFriProof.material_root` for the same (trustee, key group). Building
    // this once here reconstructs each trustee's statement and decodes the verified
    // schedule container. The same-secret bridge is rebuilt from the package the
    // same way the trustee-proof phase does.
    let verified_same_secret_bridge = match setup_package.get("sameSecretBridgeStatementSet") {
        Some(_) => {
            match verified_same_secret_bridge_material_from_package(setup_package, request) {
                Ok(material) => Some(material),
                Err(error) => {
                    return Ok(Some(evaluation_key_material_verification_failure(
                        error,
                        "setupPackage.sameSecretBridgeStatementSet",
                    )?));
                }
            }
        }
        None => None,
    };
    let atom_material_roots_by_trustee = match super::super::evaluation_key_proof_checks::accepted_setup_atom_material_roots_by_trustee(
        setup_package,
        request,
        verified_same_secret_bridge.as_ref(),
    ) {
        Ok(roots) => roots,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "setupPackage.trusteeEvaluationKeyProofs",
            )?));
        }
    };

    let key_groups = match array_value(aggregate_binding, "keyGroups") {
        Ok(key_groups) => key_groups,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups",
            )?));
        }
    };

    // Recompute the per-level and per-Galois-key published runtime-key residues
    // once from the same trustee sum `public_key_reconstruction` reads, so a
    // key group binds against the identical residues the runtime key derives
    // from. Reads are keyed by (level) for relinearization round two and by
    // (rotation, level) for Galois.
    for key_group in key_groups {
        if let Some(response) = verify_one_key_group(
            setup_package,
            request,
            &roster,
            key_group,
            &opening_bytes_by_material_root,
            &atom_material_roots_by_trustee,
        )? {
            return Ok(Some(response));
        }
    }

    Ok(None)
}

// The transported opening bytes keyed by their material root. Each opening is
// content-addressed by the material root it opens, matching the per-trustee atom
// proof material root in the package aggregate-binding record. Absent set is an
// empty map; the per-group lookup refuses a missing root, so an incomplete set
// fails closed.
fn transported_aggregate_binding_openings_by_material_root(
    request: &Value,
) -> CanonicalResult<BTreeMap<String, Vec<u8>>> {
    let mut openings = BTreeMap::new();
    let Some(opening_set) = request.get("transportedEvaluationKeyAggregateBindingOpenings") else {
        return Ok(openings);
    };
    if opening_set.get("objectType").and_then(Value::as_str)
        != Some(AGGREGATE_BINDING_OPENING_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyAggregateBindingOpenings must be an aggregate-binding opening set",
        ));
    }
    for opening in array_value(opening_set, "openings")? {
        let material_root = value_string(opening, "materialRoot")?;
        validate_material_root_hex(
            material_root,
            "transportedEvaluationKeyAggregateBindingOpenings.openings.materialRoot",
        )?;
        let opening_bytes = decode_hex(value_string(opening, "openingBytesHex")?)?;
        if openings
            .insert(material_root.to_string(), opening_bytes)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyAggregateBindingOpenings must not repeat a material root",
            ));
        }
    }

    Ok(openings)
}

// Parsed identity of one key-group aggregate-binding record. `rotation` is
// `None` for relinearization round two and `Some(rotation)` for Galois keys.
struct AggregateBindingKeyGroup {
    rotation: Option<u64>,
    level: u64,
    group_start_limb: usize,
    group_limb_count: usize,
    ring_degree: usize,
}

// Verify one key-group aggregate-binding record: parse and range-check its
// fields, recompute the published runtime-key residues sliced to the group's
// limbs, gather the per-trustee material roots and transported openings, and run
// the family backend's aggregate binding. Fail-closed on any mismatch.
#[allow(clippy::type_complexity)]
fn verify_one_key_group(
    setup_package: &Value,
    request: &Value,
    roster: &super::super::AcceptedRosterParameters,
    key_group: &Value,
    opening_bytes_by_material_root: &BTreeMap<String, Vec<u8>>,
    atom_material_roots_by_trustee: &[Vec<
        crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::KeyGroupMaterialRoot,
    >],
) -> CanonicalResult<Option<Value>> {
    let parsed = match parse_key_group_record(key_group) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups",
            )?));
        }
    };

    // The full per-digit, per-limb published runtime-key residues for this key,
    // recomputed from the trustee sum, then sliced to this group's limbs.
    let runtime_key_full_by_digit = match accepted_key_switch_runtime_residues_by_digit(
        setup_package,
        request,
        parsed.rotation,
        parsed.level,
    ) {
        Ok(residues) => residues,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "transportedPublicEvaluationKeyMaterial.componentMaterials",
            )?));
        }
    };
    let group_runtime_key_by_digit = match slice_runtime_key_to_group(
        &runtime_key_full_by_digit,
        parsed.group_start_limb,
        parsed.group_limb_count,
    ) {
        Ok(sliced) => sliced,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups",
            )?));
        }
    };

    let wrap_multiples = match parse_wrap_multiples(key_group, roster.participant_count) {
        Ok(wrap_multiples) => wrap_multiples,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups.wrapMultiples",
            )?));
        }
    };

    let (material_roots, opening_bytes) = match gather_trustee_roots_and_openings(
        key_group,
        roster.participant_count,
        opening_bytes_by_material_root,
    ) {
        Ok(gathered) => gathered,
        Err(error) => {
            return Ok(Some(evaluation_key_material_verification_failure(
                error,
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups.trusteeMaterialRoots",
            )?));
        }
    };

    // S2 cross-binding: each package material root must equal the ATOM proof's own
    // `KeyFriProof.material_root` for the same (trustee, key group). Without this,
    // the opening only proves it opens whatever root the package published, which a
    // malicious aggregator could set to a self-committed root over material that
    // fails the atom relation. Enforcing equality with the relation-verified atom
    // root ties the aggregate's opened material to the atom-verified material.
    if let Some(response) = cross_check_material_roots_against_atom_proofs(
        &parsed,
        &material_roots,
        atom_material_roots_by_trustee,
    )? {
        return Ok(Some(response));
    }

    let roster_size = usize::try_from(roster.participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "roster size does not fit usize for the aggregate binding",
        )
    })?;
    let inputs = AggregateBindingGroupInputs {
        group_start_limb: parsed.group_start_limb,
        group_limb_count: parsed.group_limb_count,
        ring_degree: parsed.ring_degree,
        roster_size,
        query_count: AGGREGATE_BINDING_QUERY_COUNT,
        material_roots: &material_roots,
        runtime_key_by_digit: &group_runtime_key_by_digit,
        wrap_multiples: &wrap_multiples,
        opening_bytes: &opening_bytes,
    };
    if let Err(error) = verify_material_aggregate_group_binding(&inputs) {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyAggregateBindingMismatch",
            error.message,
            "setupPackage.evaluationKeys.aggregateBinding.keyGroups",
        )?));
    }

    Ok(None)
}

// Cross-check every package `trusteeMaterialRoots` entry (in roster order)
// against the atom proof's own `KeyFriProof.material_root` for the same key group.
// `material_roots[i]` is trustee `i`'s package-declared material root as raw
// digest bytes; `atom_material_roots_by_trustee[i]` holds trustee `i`'s atom-proof
// key-group roots. A missing atom root for the key group, or any inequality, is a
// fail-closed refusal (the aggregate would otherwise bind runtime key to material
// the atom relation never verified).
fn cross_check_material_roots_against_atom_proofs(
    parsed: &AggregateBindingKeyGroup,
    material_roots: &[[u8; AGGREGATE_MATERIAL_ROOT_BYTES]],
    atom_material_roots_by_trustee: &[Vec<
        crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::KeyGroupMaterialRoot,
    >],
) -> CanonicalResult<Option<Value>> {
    if atom_material_roots_by_trustee.len() != material_roots.len() {
        return Ok(Some(evaluation_key_material_refusal(
            "evaluationKeyAggregateBindingAtomRootCountMismatch",
            "aggregate-binding material roots must have one atom-proof root set per trustee",
            "setupPackage.evaluationKeys.aggregateBinding.keyGroups.trusteeMaterialRoots",
        )?));
    }
    for (trustee_index, package_material_root) in material_roots.iter().enumerate() {
        let atom_root = atom_material_roots_by_trustee[trustee_index]
            .iter()
            .find(|root| {
                root.rotation == parsed.rotation
                    && root.level == parsed.level
                    && root.group_start_limb == parsed.group_start_limb
                    && root.group_limb_count == parsed.group_limb_count
            });
        let Some(atom_root) = atom_root else {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeyAggregateBindingAtomRootMissing",
                "aggregate-binding key group has no atom proof material root for a trustee",
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups.trusteeMaterialRoots",
            )?));
        };
        if atom_root.material_root != *package_material_root {
            return Ok(Some(evaluation_key_material_refusal(
                "evaluationKeyAggregateBindingAtomRootMismatch",
                "aggregate-binding trusteeMaterialRoots entry does not equal the atom proof material root",
                "setupPackage.evaluationKeys.aggregateBinding.keyGroups.trusteeMaterialRoots",
            )?));
        }
    }

    Ok(None)
}

// Parse and range-check a key-group record's identity fields: object type,
// optional rotation, level, group span (a consecutive slice inside the level's
// limbs and inside the sixteen-limb group capacity), and full-ring degree.
fn parse_key_group_record(key_group: &Value) -> CanonicalResult<AggregateBindingKeyGroup> {
    if key_group.get("objectType").and_then(Value::as_str)
        != Some(AGGREGATE_BINDING_KEY_GROUP_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate-binding key group objectType must match the accepted parameters",
        ));
    }
    let level = value_u64(key_group, "level")?;
    let level_usize = usize::try_from(level).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group level does not fit usize",
        )
    })?;
    let digit_count = level_usize.checked_add(1).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group digit count overflowed",
        )
    })?;
    if digit_count > DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group level is outside the data prime basis",
        ));
    }
    let rotation = match key_group.get("rotation") {
        Some(_) => Some(value_u64(key_group, "rotation")?),
        None => None,
    };
    let group_start_limb =
        usize::try_from(value_u64(key_group, "groupStartLimb")?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregate-binding key group start limb does not fit usize",
            )
        })?;
    let group_limb_count =
        usize::try_from(value_u64(key_group, "groupLimbCount")?).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregate-binding key group limb count does not fit usize",
            )
        })?;
    if group_limb_count == 0 || group_limb_count > AGGREGATE_BINDING_LIMB_GROUP_CAPACITY {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group limb count must be within the limb group capacity",
        ));
    }
    let group_end_limb = group_start_limb
        .checked_add(group_limb_count)
        .filter(|end| *end <= digit_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregate-binding key group span must lie inside the key's limbs",
            )
        })?;
    // The group span must be one of the schedule's consecutive groups: it starts
    // on a limb-group boundary and covers a full group except possibly the last.
    if group_start_limb % AGGREGATE_BINDING_LIMB_GROUP_CAPACITY != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group must start on a limb-group boundary",
        ));
    }
    let expected_group_limb_count =
        AGGREGATE_BINDING_LIMB_GROUP_CAPACITY.min(digit_count - group_start_limb);
    if group_limb_count != expected_group_limb_count
        || group_end_limb - group_start_limb != group_limb_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group span must match the scheduled limb group",
        ));
    }
    let ring_degree = usize::try_from(value_u64(key_group, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group ring degree does not fit usize",
        )
    })?;
    if ring_degree != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate-binding key group requires full-ring component vectors",
        ));
    }

    Ok(AggregateBindingKeyGroup {
        rotation,
        level,
        group_start_limb,
        group_limb_count,
        ring_degree,
    })
}

// Slice the full `[digit][limb][coeff]` runtime-key residues to a group's
// consecutive limbs, preserving every digit. Refuses a group span that exceeds
// the available limbs.
fn slice_runtime_key_to_group(
    runtime_key_full_by_digit: &[Vec<Vec<u64>>],
    group_start_limb: usize,
    group_limb_count: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let group_end_limb = group_start_limb + group_limb_count;
    let mut sliced = Vec::with_capacity(runtime_key_full_by_digit.len());
    for limbs in runtime_key_full_by_digit {
        if limbs.len() < group_end_limb {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "runtime key digit does not cover the aggregate-binding group limbs",
            ));
        }
        sliced.push(limbs[group_start_limb..group_end_limb].to_vec());
    }

    Ok(sliced)
}

// Parse and range-check the `[digit][coeff]` wrap multiples. Every magnitude must
// be within `ceil(roster_size / 2)`, the maximum the identity accepts, and every
// coefficient row must be the full ring degree.
fn parse_wrap_multiples(key_group: &Value, roster_size: u64) -> CanonicalResult<Vec<Vec<i64>>> {
    let maximum_magnitude = maximum_aggregate_wrap_multiple_magnitude(roster_size);
    let digit_rows = array_value(key_group, "wrapMultiples")?;
    let mut wrap_multiples = Vec::with_capacity(digit_rows.len());
    for digit_row in digit_rows {
        let coefficient_values = digit_row.as_array().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "aggregate-binding wrap multiples must be an array per digit",
            )
        })?;
        if coefficient_values.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregate-binding wrap-multiple digit row must cover the full ring degree",
            ));
        }
        let mut wrap_row = Vec::with_capacity(coefficient_values.len());
        for wrap_value in coefficient_values {
            let wrap = wrap_value.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "aggregate-binding wrap multiple must be a signed integer",
                )
            })?;
            if wrap.abs() > maximum_magnitude {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate-binding wrap multiple exceeds the roster-bounded magnitude",
                ));
            }
            wrap_row.push(wrap);
        }
        wrap_multiples.push(wrap_row);
    }

    Ok(wrap_multiples)
}

// Gather the per-trustee material roots (in roster order) and the transported
// opening bytes each root addresses. Refuses a missing trustee, a repeated
// trustee, a wrong count, or an opening whose material root is not transported.
#[allow(clippy::type_complexity)]
fn gather_trustee_roots_and_openings(
    key_group: &Value,
    participant_count: u64,
    opening_bytes_by_material_root: &BTreeMap<String, Vec<u8>>,
) -> CanonicalResult<(Vec<[u8; AGGREGATE_MATERIAL_ROOT_BYTES]>, Vec<Vec<u8>>)> {
    let entries = array_value(key_group, "trusteeMaterialRoots")?;
    if entries.len() != participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate-binding key group requires one material root per trustee",
        ));
    }
    let mut roots_by_trustee: BTreeMap<u64, String> = BTreeMap::new();
    for entry in entries {
        let trustee_roster_position = value_u64(entry, "trusteeRosterPosition")?;
        let material_root = value_string(entry, "materialRoot")?;
        validate_material_root_hex(
            material_root,
            "setupPackage.evaluationKeys.aggregateBinding.keyGroups.trusteeMaterialRoots.materialRoot",
        )?;
        if roots_by_trustee
            .insert(trustee_roster_position, material_root.to_string())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "aggregate-binding key group must not repeat a trustee material root",
            ));
        }
    }

    let mut material_roots = Vec::with_capacity(participant_count as usize);
    let mut opening_bytes = Vec::with_capacity(participant_count as usize);
    for trustee_roster_position in 0..participant_count {
        let material_root = roots_by_trustee
            .get(&trustee_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate-binding key group is missing a trustee material root",
                )
            })?;
        let opening = opening_bytes_by_material_root
            .get(material_root)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "aggregate-binding key group material root has no transported opening",
                )
            })?;
        material_roots.push(material_root_from_hex(material_root)?);
        opening_bytes.push(opening.clone());
    }

    Ok((material_roots, opening_bytes))
}
