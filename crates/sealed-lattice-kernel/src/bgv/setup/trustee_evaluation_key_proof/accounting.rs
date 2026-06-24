use serde_json::{Value, json};

use super::extension_field::CHALLENGE_EXTENSION_DEGREE;
use super::*;
use crate::bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE};
use crate::hashing::derive_protocol_hash;

// Repo-owned accounting for the trustee-batched succinct evaluation-key
// argument. Every row states what is implemented and measured against the
// fixed parameters in this module, and every theorem row carries its closure
// argument inline. The soundness model is classical round-by-round, every
// post-commitment challenge is drawn from the degree-four challenge extension
// of the limb field, and the explicitly conjectured input (the per-query FRI
// proximity-gap bound at rate one half) is named with its insufficient proven
// fallback at the current query count.
//
// CHANGE (2026, Option B): the named conjecture was re-based onto CS25 "Our
// Conjecture 3" (mutual correlated agreement up to the q-ary list-decoding
// capacity for prime fields). The earlier accounting counted one bit per query,
// the up-to-capacity proximity-gap radius 1 - rho of BCI+23 Conjecture 8.4,
// which Crites-Stewart (CS25) and BCHKS26 DISPROVED in 2025. The repaired
// entropy-capacity radius costs about 1/log2(q) of distance over the base limb
// field, lowering per-query soundness from one bit to about 0.938 bit, so the
// fixed 168-query count now records about 140 effective bits after the union
// allowance rather than 144. The proven BCIKS20 Johnson fallback is unchanged.
//
// This conjecture is an admissible soundness foundation under the
// project's proximity-gap policy: a repaired below-capacity conjecture may carry
// post-quantum soundness, the disproved up-to-capacity one may not.
// The residual is a disclosed small-medium research risk, not a soundness gap: CS25
// Our Conjecture 3 is a recent (2025) conjecture and could be weakened by future
// work, though it is the best-pedigreed standing one (its authors disproved the
// prior conjecture). The proven BCIKS20 Johnson fallback at a larger query count
// removes that research risk entirely.
//
// The QROM row now carries the computed CMS19 reduction loss (state-restoration
// framework): the achieved quantum soundness is the Grover square-root of the
// classical round-by-round soundness, about seventy bits after the instance
// union, recorded with the present-time-threat scope and kept below the
// conventional 128-bit-quantum bar. The smudging row is a bounded-leakage
// statement rather than a 128-bit zero-knowledge claim.
// The accounting hash is bound into the generate and verify command responses,
// and package integration binds it into the setup proof accounting certificate.
#[derive(Clone, Copy, Debug)]
pub(super) struct SuccinctProofSoundnessReport {
    pub(super) trace_size: usize,
    pub(super) extension_size: usize,
    pub(super) commitment_bound: usize,
    pub(super) sumcheck_residual_degree_bound: usize,
    pub(super) opened_masked_evaluations_per_column: usize,
    pub(super) base_field_bits: i64,
    pub(super) challenge_field_bits: i64,
    pub(super) fold_round_bits: i64,
    pub(super) out_of_domain_round_bits: i64,
    pub(super) lincheck_round_bits: i64,
    pub(super) consistency_round_bits: i64,
    pub(super) query_round_bits: i64,
    pub(super) proven_fallback_query_bits: i64,
    pub(super) proven_fallback_effective_soundness_bits: i64,
    pub(super) proven_fallback_query_count_for_128_bits: i64,
    pub(super) union_budget_bits: i64,
    pub(super) weakest_round_bits: i64,
    pub(super) effective_soundness_bits: i64,
    pub(super) achieved_quantum_soundness_bits: i64,
    pub(super) achieved_quantum_soundness_after_union_bits: i64,
    pub(super) quantum_collision_resistance_bits: i64,
}

pub(super) fn succinct_proof_soundness_report(
    trace_size: usize,
) -> CanonicalResult<SuccinctProofSoundnessReport> {
    if trace_size == 0 || !trace_size.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "succinct proof soundness policy requires a power-of-two trace size",
        ));
    }
    let extension_size = trace_size
        .checked_mul(DOMAIN_BLOWUP)
        .ok_or_else(|| invalid_succinct_setup_proof("soundness extension size overflowed"))?;
    let commitment_bound = COMMITMENT_BOUND_FACTOR
        .checked_mul(trace_size)
        .ok_or_else(|| invalid_succinct_setup_proof("soundness commitment bound overflowed"))?;
    let opened_masked_evaluations_per_column =
        2 * LOW_DEGREE_QUERY_COUNT + DEEP_EVALUATION_POINT_COUNT;
    let smallest_limb_prime = *DATA_PRIMES
        .iter()
        .min()
        .expect("the data basis is non-empty");
    let base_field_bits = i64::from(smallest_limb_prime.ilog2());
    let challenge_field_bits = base_field_bits * CHALLENGE_EXTENSION_DEGREE as i64;
    let union_budget_bits = 16_i64;
    let fold_round_bits = challenge_field_bits - i64::from(extension_size.ilog2());
    let out_of_domain_round_bits =
        challenge_field_bits - (i64::from((3 * commitment_bound).ilog2()) + 1);
    let lincheck_round_bits =
        (challenge_field_bits - i64::from(trace_size.ilog2())) * LINCHECK_REPETITIONS as i64;
    let consistency_round_bits =
        CONSISTENCY_COEFFICIENT_BITS as i64 * CONSISTENCY_REPETITIONS as i64;
    let entropy_capacity_query_soundness_permille = 930_i64;
    let query_round_bits =
        LOW_DEGREE_QUERY_COUNT as i64 * entropy_capacity_query_soundness_permille / 1000;
    let proven_fallback_query_bits = LOW_DEGREE_QUERY_COUNT as i64 / 2;
    let proven_fallback_effective_soundness_bits = proven_fallback_query_bits - union_budget_bits;
    let proven_fallback_query_count_for_128_bits =
        2 * (MINIMUM_CONJECTURED_CLASSICAL_SOUNDNESS_AFTER_UNION_BITS + union_budget_bits);
    let weakest_round_bits = [
        fold_round_bits,
        out_of_domain_round_bits,
        lincheck_round_bits,
        consistency_round_bits,
        query_round_bits,
    ]
    .into_iter()
    .min()
    .expect("round list is non-empty");
    let effective_soundness_bits = weakest_round_bits - union_budget_bits;
    let achieved_quantum_soundness_bits = weakest_round_bits / 2;
    let achieved_quantum_soundness_after_union_bits = effective_soundness_bits / 2;
    let digest_bits = 512_i64;
    let quantum_collision_resistance_bits = digest_bits / 3;

    Ok(SuccinctProofSoundnessReport {
        trace_size,
        extension_size,
        commitment_bound,
        sumcheck_residual_degree_bound: trace_size,
        opened_masked_evaluations_per_column,
        base_field_bits,
        challenge_field_bits,
        fold_round_bits,
        out_of_domain_round_bits,
        lincheck_round_bits,
        consistency_round_bits,
        query_round_bits,
        proven_fallback_query_bits,
        proven_fallback_effective_soundness_bits,
        proven_fallback_query_count_for_128_bits,
        union_budget_bits,
        weakest_round_bits,
        effective_soundness_bits,
        achieved_quantum_soundness_bits,
        achieved_quantum_soundness_after_union_bits,
        quantum_collision_resistance_bits,
    })
}

pub(super) fn enforce_current_succinct_proof_soundness_policy(
    trace_size: usize,
) -> CanonicalResult<()> {
    let report = succinct_proof_soundness_report(trace_size)?;
    if report.effective_soundness_bits < MINIMUM_CONJECTURED_CLASSICAL_SOUNDNESS_AFTER_UNION_BITS {
        return Err(invalid_succinct_setup_proof(format!(
            "succinct proof conjectured classical soundness after union is {} bits, below the required {} bits",
            report.effective_soundness_bits,
            MINIMUM_CONJECTURED_CLASSICAL_SOUNDNESS_AFTER_UNION_BITS
        )));
    }

    Ok(())
}

pub(crate) fn succinct_evaluation_key_proof_accounting_value() -> CanonicalResult<Value> {
    let trace_size = POLYNOMIAL_DEGREE / TRACE_SPLIT;
    let soundness_report = succinct_proof_soundness_report(trace_size)?;
    let extension_size = soundness_report.extension_size;
    let commitment_bound = soundness_report.commitment_bound;
    let mask_degree = column_mask_degree(trace_size);
    let opened_evaluations_per_column = soundness_report.opened_masked_evaluations_per_column;
    // Clear consistency sums are bounded by max witness magnitude (two for
    // centered-binomial errors) times the ring degree times the coefficient
    // bound; the smudging mask spans CLAIM_MASK_DIGIT_COUNT binary digits.
    let consistency_coefficient_bound = (1_u64 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    // Witness magnitude two is the centered-binomial error bound, exact for the
    // three magnitude-two families (trustee-evaluation-key,
    // same-secret-linkage-anchor, public-key-share). The recipient-private VSS
    // family masks full-range message residues instead and overrides this clear
    // bound and the derived smudging row with a family-aware bound in
    // succinct_private_vss_share_accounting_value.
    let clear_claim_bound =
        2_u128 * POLYNOMIAL_DEGREE as u128 * u128::from(consistency_coefficient_bound);
    // Ceiling of the clear bound's bit length, again the conservative side.
    let clear_claim_bound_bits = i64::from(clear_claim_bound.ilog2()) + 1;
    // Union budget over the first profile: limb fields, schedule keys,
    // trustees, and accepted ceremony objects. Stated as a power-of-two
    // allowance the per-round bounds are discounted by.
    // Query-phase soundness under CS25 "Our Conjecture 3" (mutual correlated
    // agreement up to the q-ary list-decoding capacity for prime fields). The
    // older accounting counted one bit per query, the disproved BCI+23
    // Conjecture 8.4 up-to-capacity radius 1 - rho. CS25 repairs the radius to
    // the entropy capacity, lowering it by 1/log2(q) + 1/n over a prime base
    // field. Our batched DEEP-FRI commits columns over the base limb field
    // (q ~ 2^base_field_bits), so a far word survives one query with
    // probability rho + 1/base_field_bits ~ 0.522 rather than rho = 1/2, and
    // per-query soundness is -log2(0.522) ~ 0.938 bit, not one bit. We floor
    // that to 930/1000 bit per query, a conservative understatement, to stay in
    // integer arithmetic; at 168 queries this records 156 bits, 140 after the
    // union allowance, still clearing 128.
    let query_round_bits = soundness_report.query_round_bits;
    // The proven, unconditional fallback is the BCIKS20 Johnson radius
    // (square root of the rate, half a bit per query); it is independent of the
    // conjecture, so it is computed from the raw query count, not from the
    // re-based query-round bits above.
    let proven_fallback_query_bits = soundness_report.proven_fallback_query_bits;
    let proven_fallback_effective_soundness_bits =
        soundness_report.proven_fallback_effective_soundness_bits;
    let proven_fallback_query_count_for_128_bits =
        soundness_report.proven_fallback_query_count_for_128_bits;
    let challenge_field_bits = soundness_report.challenge_field_bits;
    let fold_round_bits = soundness_report.fold_round_bits;
    let out_of_domain_round_bits = soundness_report.out_of_domain_round_bits;
    let lincheck_round_bits = soundness_report.lincheck_round_bits;
    let consistency_round_bits = soundness_report.consistency_round_bits;
    let union_budget_bits = soundness_report.union_budget_bits;
    let weakest_round_bits = soundness_report.weakest_round_bits;
    let effective_soundness_bits = soundness_report.effective_soundness_bits;
    // Computed CMS19 QROM accounting. The t^2 * eps soundness term breaks at
    // t about eps^(-1/2), so the achieved quantum soundness is the Grover
    // square-root (half in bits) of the classical round-by-round soundness; it
    // is derived from the same classical variables so the two can never drift.
    // The t^3 / 2^lambda hash term is BHT quantum collision search on the
    // SHAKE256 512-bit digest, about a third of the digest in bits.
    let achieved_quantum_soundness_bits = soundness_report.achieved_quantum_soundness_bits;
    let achieved_quantum_soundness_after_union_bits =
        soundness_report.achieved_quantum_soundness_after_union_bits;
    let digest_bits = 512_i64;
    let quantum_collision_resistance_bits = soundness_report.quantum_collision_resistance_bits;

    Ok(json!({
        "objectType": "SuccinctEvaluationKeyProofAccounting",
        "objectVersion": 3,
        "proofFamily": "trustee-evaluation-key",
        "argumentShape": {
            "model": "per-limb-field univariate polynomial IOP with batched low-degree commitment",
            "limbFields": "one instance per active data prime, no lifted-integer carries",
            "traceSplit": TRACE_SPLIT,
            "traceSize": soundness_report.trace_size,
            "domainBlowup": DOMAIN_BLOWUP,
            "extensionSize": extension_size,
            "commitmentDegreeBound": commitment_bound,
            "rate": "commitment bound over extension size, one half",
            "sumcheckResidualDegreeBound": soundness_report.sumcheck_residual_degree_bound,
            "sumcheckResidualRate": "residual degree bound over the same extension size, one quarter",
            "ringDegree": POLYNOMIAL_DEGREE,
            "challengeExtensionDegree": CHALLENGE_EXTENSION_DEGREE,
            "baseFieldBitsFloor": soundness_report.base_field_bits,
            "challengeFieldBitsApproximate": challenge_field_bits,
            "challengeDomain": "every post-commitment challenge (key batching, lincheck, batching alphas, beta, out-of-domain points, batching lambda, fold challenges) is drawn from the degree-four extension tower of the limb field; committed columns and query openings stay in the base field",
        },
        "lowDegreeSoundness": {
            "queryCount": LOW_DEGREE_QUERY_COUNT,
            "foldedFinalCoefficientCount": LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
            "mainBatchedDegreeBound": commitment_bound,
            "sumcheckResidualDegreeBound": soundness_report.sumcheck_residual_degree_bound,
            "sumcheckResidualProof": "a second low-degree proof over the same quotient tree proves the sumcheck residual column has degree below the trace size; the deterministic zero DEEP anchor binds its constant term",
            "conjecturedQueryBoundLog2": -query_round_bits,
            "provenBoundReference": "Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, Proximity gaps for Reed-Solomon codes (BCIKS20)",
            "provenFallbackQueryBoundLog2": -proven_fallback_query_bits,
            "provenFallbackEffectiveSoundnessBitsAfterUnion": proven_fallback_effective_soundness_bits,
            "provenFallbackQueryCountFor128BitsAfterUnion": proven_fallback_query_count_for_128_bits,
            "foldRoundSoundnessLog2": -fold_round_bits,
            "foldChallengeDomain": "each fold challenge is one degree-four extension element, so a fold round's round-by-round error is the extension domain size over the challenge field size",
            "grinding": "none-applied: every round bound already clears the target with margin",
            "unionBudgetLog2": union_budget_bits,
            "effectiveSoundnessBitsAfterUnion": effective_soundness_bits,
        },
        "identitySoundness": {
            "randomOutOfDomainPointCount": DEEP_POINT_COUNT,
            "deterministicResidualAnchorPointCount": SUMCHECK_RESIDUAL_ANCHOR_POINT_COUNT,
            "totalDeepEvaluationPointCount": DEEP_EVALUATION_POINT_COUNT,
            "compositionDegreeBound": "three times the masked column degree bound",
            "outOfDomainPointDomain": "random points are degree-four challenge-extension points rejection-sampled outside the base trace subgroup and coset; the deterministic residual anchor is zero, outside the trace subgroup and extension coset",
            "schwartzZippelPerPointLog2": -out_of_domain_round_bits,
            "linkedThroughBatchedQuotients": true,
            "sumcheckResidualZeroAnchor": "the residual column's claimed evaluation at zero must be zero and is bound through the main DEEP-batched low-degree proof",
        },
        "linearRelationSoundness": {
            "lincheckRepetitions": LINCHECK_REPETITIONS,
            "perRepetitionBoundModel": "trace size over challenge field size per repetition, repetitions drawn in one round",
            "lincheckRoundSoundnessLog2": -lincheck_round_bits,
            "digitAndKeyBatching": "per-key gamma powers and per-relation alpha weights, all in the challenge extension",
        },
        "crossLimbConsistency": {
            "coefficientBits": CONSISTENCY_COEFFICIENT_BITS,
            "repetitions": CONSISTENCY_REPETITIONS,
            "preUnionCollisionBoundLog2": -consistency_round_bits,
            "integerBinding": {
                "clearClaimBound": clear_claim_bound.to_string(),
                "maskBound": (1_u128 << CLAIM_MASK_DIGIT_COUNT).to_string(),
                "twoPrimeWindowRule": "the product of the two smallest data primes exceeds twice the mask-plus-clear claim bound, so the lifted integer is unique and a claim present in fewer than two limb fields is refused",
            },
        },
        "zeroKnowledge": {
            "columnMaskDegree": mask_degree,
            "openedEvaluationsPerColumn": opened_evaluations_per_column,
            "openedMaskedEvaluationsPerColumn": opened_evaluations_per_column,
            "extraPhaseTwoResidualOpeningsPerColumn": 2 * LOW_DEGREE_QUERY_COUNT,
            "saltedCommitmentLeaves": true,
            "phaseTwoColumnsDeterministicFromMaskedMaterial": true,
            "simulatorMarginEvaluations": mask_degree as i64 - opened_evaluations_per_column as i64,
            "smudgingBudget": {
                "perClaimStatisticalDistanceLog2": clear_claim_bound_bits - CLAIM_MASK_DIGIT_COUNT as i64,
                "claimBudgetLog2Approximate": 17,
                "totalLeakageLog2Approximate": clear_claim_bound_bits - CLAIM_MASK_DIGIT_COUNT as i64 + 17,
            },
        },
        "fiatShamir": {
            "transform": "multi-round Fiat-Shamir over the shared transcript hash",
            "soundnessModel": "classical round-by-round: every interactive round's error is bounded above, and the non-interactive bound is the adversary's query budget times the weakest round error (BCS16-style compilation); the stated security level counts one hash query per grinding attempt on the weakest round",
            "transcriptOrder": [
                "statement hash",
                "per-limb witness tree roots",
                "consistency challenge vectors",
                "per-limb fork: per-key gamma, lincheck challenges, lincheck alpha, linkage alpha, consistency alpha, beta",
                "per-limb quotient tree root and masked consistency claims",
                "out-of-domain points and evaluations",
                "batch lambda and low-degree fold transcript",
            ],
            "domainSeparation": "labelled absorb and challenge domains with per-limb forks",
            "weakestRoundSoundnessLog2": -weakest_round_bits,
            "effectiveSoundnessBitsAfterUnion": effective_soundness_bits,
            "digestBits": digest_bits,
            "quantumCollisionResistanceBitsApproximate": quantum_collision_resistance_bits,
            "achievedQuantumSoundnessBitsApproximate": achieved_quantum_soundness_bits,
            "achievedQuantumSoundnessAfterInstanceUnionBitsApproximate": achieved_quantum_soundness_after_union_bits,
            "qromReferences": [
                "CMS19, Chiesa, Manohar, Spooner, Succinct arguments in the quantum random-oracle model (governing reduction)",
                "BCS16, Ben-Sasson, Chiesa, Spooner, Interactive oracle proofs (the BCS transform)",
                "GMW25, A simplified round-by-round soundness proof of FRI (the round-by-round soundness CMS19 consumes)",
                "DFM20, The measure-and-reprogram technique 2.0: multi-round Fiat-Shamir and more (lineage, wrong granularity at this round count)",
                "DFMS19, Security of the Fiat-Shamir transformation in the quantum random-oracle model (lineage)",
                "DFMS22, Efficient NIZKs and signatures from commit-and-open protocols in the QROM (lineage)",
            ],
        },
        "sameSecretLinkage": {
            "mechanism": "BDLOP constant commitments opened natively over the commitment-modulus fields, bound to the shared secret by the joint cross-limb consistency",
            "commitmentFieldsAreDataPrimes": true,
            "arithmeticSourceRelations": [
                "round-one source equals the committed trustee secret",
                "round-two source equals the trustee secret times the public round-one aggregate",
                "Galois source equals the automorphism image of the committed trustee secret",
            ],
            "soundnessInheritance": "the opening relations are rows of the same batched lincheck and row checks, so their soundness is the linear-relation and consistency rows above",
        },
    }))
}

pub(crate) fn succinct_evaluation_key_proof_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctEvaluationKeyProofAccountingHash",
        &succinct_evaluation_key_proof_accounting_value()?,
    )
}

// One migrated family's accounting: the closed evaluation-key accounting with
// the object type, proof family, family relation rows, and per-family mobile
// measurement row overridden. The argument machinery, parameters, and theorem
// rows stay the shared closed accounting; only the family-specific rows change.
fn migrated_family_accounting(
    object_type: &str,
    proof_family: &str,
    family_relation_rows: Value,
    wasm_browser_measurement: Value,
) -> CanonicalResult<Value> {
    // Note: this carries the base smudgingBudget and integer-binding blocks
    // (perClaimStatisticalDistanceLog2 about -68, clear claim bound about 2^24)
    // into every migrated family. That figure is exact for the magnitude-two
    // centered-binomial families; the recipient-private VSS family overrides
    // both blocks with a family-aware full-range-message bound in
    // succinct_private_vss_share_accounting_value.
    let mut accounting = succinct_evaluation_key_proof_accounting_value()?;
    let accounting_fields = accounting
        .as_object_mut()
        .expect("succinct accounting is an object");
    accounting_fields.insert(
        "objectType".to_string(),
        Value::String(object_type.to_string()),
    );
    accounting_fields.insert(
        "proofFamily".to_string(),
        Value::String(proof_family.to_string()),
    );
    accounting_fields.insert("familyRelationRows".to_string(), family_relation_rows);
    accounting_fields.insert(
        "wasmBrowserMeasurement".to_string(),
        wasm_browser_measurement,
    );

    Ok(accounting)
}

// A measurement row whose desktop browser lane has not yet recorded its
// numbers; the family does not close until the lane runs and the row flips to
// the recorded shape.
fn pending_desktop_browser_measurement() -> Value {
    json!({
        "status": "wasm-browser-measurement-pending",
        "requiredRows": [
            "maximum per-trustee prove time",
            "full setup-package verify time",
            "peak WASM memory",
            "persistent storage footprint",
            "largest copied buffer",
            "resume behavior across interruption",
        ],
    })
}

// A measurement row recorded on a desktop browser lane with every
// supported-phone row left open. The canonical object never carries
// machine-specific numbers, so the recorded lane is described by what it
// measures, not by one machine's results.
fn recorded_desktop_browser_measurement(family_label: &str) -> Value {
    json!({
        "status": "desktop-browser-wasm-measurement-recorded-supported-phone-rows-open",
        "recordedLane": format!("manual desktop Chromium vitest lane over the published WASM kernel artifact: one first-profile {family_label} prove and verify per run, logging per-trustee prove time, verify time, proof byte length, peak WASM linear memory, largest copied buffer, persistent storage footprint, and resume behavior"),
        "recordedRows": [
            "per-trustee prove time in desktop browser WASM",
            "proof verify time in desktop browser WASM",
            "proof byte length",
            "peak WASM linear memory after prove and verify",
            "largest copied buffer at the WASM boundary",
            "persistent storage footprint",
            "resume behavior across interruption",
        ],
        "openRows": [
            "maximum per-trustee prove time on a supported phone",
            "full setup-package verify time on a supported phone",
            "peak WASM memory on a supported phone",
            "persistent storage footprint on a supported phone",
            "largest copied buffer on a supported phone",
            "resume behavior across interruption on a supported phone",
        ],
        "evidenceBoundary": "desktop Chromium development evidence only; the recorded lane does not certify supported-phone behavior, and the supported-phone rows stay open",
    })
}

// Accounting for the keyless same-secret linkage anchor family.
pub(crate) fn succinct_same_secret_linkage_anchor_accounting_value() -> CanonicalResult<Value> {
    migrated_family_accounting(
        "SuccinctSameSecretLinkageAnchorAccounting",
        super::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        json!({
            "statementShape": "keyless statement over the commitment fields: no key relations, the linkage opening rows, ternary secret support, binary negative-indicator support, ternary opening-randomness support, and the masked cross-limb consistency claims",
            "anchorRole": "one anchor proof per trustee; every other setup proof family carries the anchor root in its hashed context and keeps its own commitment-opening rows against the same commitment values",
            "linkageSoundness": "congruence modulo the commitment modulus product (three commitment fields) plus ternary support makes every family witness secret equal to the anchored secret as integers",
        }),
        recorded_desktop_browser_measurement("keyless anchor"),
    )
}

pub(crate) fn succinct_same_secret_linkage_anchor_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctSameSecretLinkageAnchorAccountingHash",
        &succinct_same_secret_linkage_anchor_accounting_value()?,
    )
}

// Accounting for the public-key share family: one share-correctness relation
// per Q_share limb plus the single constant-commitment opening that links the
// share secret to the anchor.
pub(crate) fn succinct_public_key_share_accounting_value() -> CanonicalResult<Value> {
    migrated_family_accounting(
        "SuccinctPublicKeyShareAccounting",
        super::PUBLIC_KEY_SHARE_PROOF_FAMILY,
        json!({
            "statementShape": "one share-correctness relation b_l + a_l (*) s - p * e = 0 over every Q_share limb with no diagonal source, ternary secret support, centered-binomial error support, the masked cross-limb consistency claims for the shared secret and error, and one constant-commitment opening (limb zero) with the linkage opening rows",
            "commonReferenceBinding": "the public sample a_l is the accepted common reference polynomial recomputed per limb from the accepted public matrix seed under the accepted-bgv-public-a label, never transported, so the relation cannot be proven against an arbitrary reference polynomial",
            "singleCommitmentLinkageRationale": "the same-secret anchor has already verified that every accepted Q_share constant commitment opens to one ternary trustee secret; the public-key share proof therefore opens the selected limb-zero constant commitment, carries the accepted anchor statement and proof roots in its statement context, and proves ternary support for the public-key witness secret",
            "anchorReference": "the limb-zero constant-commitment opening makes the public-key share secret congruent to the anchored secret modulo the commitment modulus product, which with ternary support makes them equal as integers; this is intentionally narrower than the same-secret anchor, which opens every Q_share constant commitment",
        }),
        pending_desktop_browser_measurement(),
    )
}

pub(crate) fn succinct_public_key_share_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctPublicKeyShareAccountingHash",
        &succinct_public_key_share_accounting_value()?,
    )
}

// Accounting for the recipient-private VSS share family: hidden Shamir
// coefficient openings plus the lifted recipient-share relation with hidden
// carry columns over the setup commitment fields.
pub(crate) fn succinct_private_vss_share_accounting_value() -> CanonicalResult<Value> {
    // Family-aware leakage accounting. The migrated base blocks are computed for
    // magnitude-two centered-binomial witnesses (clear claim bound about 2^24,
    // per-claim statistical distance about 2^-68). The recipient-private VSS
    // family masks only the carry and the ternary opening-randomness columns: its
    // message (Shamir coefficient) columns carry no consistency claim because the
    // per-field opening rows plus the opening-randomness consistency already pin
    // them across the commitment fields (see consistency_vector_count in
    // relation.rs), so masking them would add leakage with no soundness gain. Its
    // clear claim bound is therefore carry-driven (about 2^34) and its real
    // per-claim leakage about 2^-58 (about 2^-41 across the first profile's ~2^17
    // claims) -- still the leakage-dominating family of the four, but only mildly,
    // not by the ~46 bits the message-masking variant cost. The smudging and
    // integer-binding rows are recomputed from that carry bound below, sourced
    // from the same helper masked_claim_bounds uses, so the disclosed figures stay
    // honest and cannot diverge from the relation bound.
    let mut accounting = migrated_family_accounting(
        "SuccinctPrivateVssShareAccounting",
        super::PRIVATE_VSS_SHARE_PROOF_FAMILY,
        json!({
            "statementShape": "recipient-private statement over the setup commitment fields: one hidden message column per Shamir coefficient, one hidden carry column, ternary opening-randomness columns for every coefficient commitment, masked cross-field consistency claims, coefficient commitment opening rows, and one lifted share-evaluation row",
            "commitmentOpeningRows": "for every hidden Shamir coefficient polynomial F_k and every setup commitment row, the proof checks the published BDLOP commitment row against F_k and its ternary opening randomness over each commitment field",
            "liftedShareRelation": "for recipient trustee point alpha_j, the proof checks sum_k alpha_j^k F_k - q_l * carry = share_j over the commitment fields; the term q_l * carry is not dropped except in fields where q_l is the field modulus, and the other commitment fields bind the integer carry",
            "privacyBoundary": "coefficient messages, opening randomness, and carry vectors stay witness-private; the envelope publishes only share values, commitment roots, statement and proof hashes, proof bytes or chunk roots, and verification status",
            "integerBinding": "full-size message residues use the shared masked-claim two-prime lift with a statement-specific bound based on the source limb modulus; carry columns use the explicit first-profile carry bound",
        }),
        pending_desktop_browser_measurement(),
    )?;
    let accounting_fields = accounting
        .as_object_mut()
        .expect("succinct accounting is an object");
    if let Some(argument_shape) = accounting_fields
        .get_mut("argumentShape")
        .and_then(Value::as_object_mut)
    {
        argument_shape.insert(
            "limbFields".to_string(),
            Value::String(
                "one instance per setup commitment field; the lifted carry relation is checked over the commitment-field CRT window"
                    .to_string(),
            ),
        );
    }

    // Recompute the disclosed clear claim bound from the witnesses that actually
    // carry a masked consistency claim. The message (Shamir coefficient) columns
    // do not carry one: their cross-field consistency is argued globally (carry
    // consistency + the public range-checked share pin the evaluation per
    // recipient, and >= t honest recipients pin the polynomial; see
    // consistency_vector_count in relation/column_layout.rs), not by the per-field
    // opening rows. So the published masked claims range only over the carry and
    // the ternary opening-randomness columns. The lifted carry bound dominates
    // the magnitude-one randomness, so the clear bound is the worst-case carry
    // bound times the ring degree times the per-coefficient bound, mirroring the
    // private-VSS branch of masked_claim_bounds. Worst case over the first
    // profile: the recipient trustee point is largest at the last roster position
    // (participant count ten minus one) and the Shamir coefficient count is the
    // decryption threshold (four). Sourcing the carry bound from the same helper
    // masked_claim_bounds uses keeps the relation bound and the disclosed figure
    // from diverging. This yields a clear bound about 2^34, so per-claim leakage
    // about 2^-58.
    const FIRST_PROFILE_LARGEST_RECIPIENT_ROSTER_POSITION: u64 = 9;
    const FIRST_PROFILE_SHAMIR_COEFFICIENT_COUNT: usize = 4;
    let worst_case_carry_bound =
        u128::try_from(super::relation::private_vss_share_lifted_carry_bound(
            FIRST_PROFILE_LARGEST_RECIPIENT_ROSTER_POSITION,
            FIRST_PROFILE_SHAMIR_COEFFICIENT_COUNT,
        )?)
        .expect("the lifted carry bound is positive");
    let consistency_coefficient_bound = u128::from((1_u64 << CONSISTENCY_COEFFICIENT_BITS) - 1);
    let private_vss_clear_claim_bound =
        worst_case_carry_bound * POLYNOMIAL_DEGREE as u128 * consistency_coefficient_bound;
    let private_vss_clear_claim_bound_bits = i64::from(private_vss_clear_claim_bound.ilog2()) + 1;
    let per_claim_leakage_log2 = private_vss_clear_claim_bound_bits - CLAIM_MASK_DIGIT_COUNT as i64;
    // Union budget: the masked claims a c_priv-bounded adversary actually
    // observes in the first profile. A corrupted recipient receives, from each of
    // the n sources, one envelope of DATA_PRIMES.len() limb proofs, each
    // publishing (4 Shamir coefficients * 5 opening-randomness columns + 1 carry)
    // * 20 repetitions = 420 masked claims (mirrors consistency_vector_count for
    // this family). With c_priv corrupted recipients the adversary view is
    // c_priv * n * DATA_PRIMES.len() * 420 ~ 2^17.7 claims, whose ceil-log gives a
    // conservative 18-bit budget, so the total statistical distance over the
    // adversary's view is about 2^-40. The earlier flat 2^17 budget under-counted
    // the bounded adversary's view (~2^17.7).
    const FIRST_PROFILE_CORRUPTED_RECIPIENTS: u128 = 3;
    const FIRST_PROFILE_ROSTER_SIZE: u128 = 10;
    const FIRST_PROFILE_PRIVATE_VSS_CLAIMS_PER_LIMB_PROOF: u128 =
        (FIRST_PROFILE_SHAMIR_COEFFICIENT_COUNT as u128 * 5 + 1) * CONSISTENCY_REPETITIONS as u128;
    let adversary_view_claim_count = FIRST_PROFILE_CORRUPTED_RECIPIENTS
        * FIRST_PROFILE_ROSTER_SIZE
        * DATA_PRIMES.len() as u128
        * FIRST_PROFILE_PRIVATE_VSS_CLAIMS_PER_LIMB_PROOF;
    let claim_budget_log2 = i64::from(adversary_view_claim_count.ilog2()) + 1;
    let total_leakage_log2 = per_claim_leakage_log2 + claim_budget_log2;

    if let Some(zero_knowledge) = accounting_fields
        .get_mut("zeroKnowledge")
        .and_then(Value::as_object_mut)
    {
        zero_knowledge.insert(
            "smudgingBudget".to_string(),
            json!({
                "perClaimStatisticalDistanceLog2": per_claim_leakage_log2,
                "clearClaimBoundBits": private_vss_clear_claim_bound_bits,
                "maskDigitCount": CLAIM_MASK_DIGIT_COUNT,
                "claimBudgetLog2Approximate": claim_budget_log2,
                "totalLeakageLog2Approximate": total_leakage_log2,
            }),
        );
    }

    if let Some(integer_binding) = accounting_fields
        .get_mut("crossLimbConsistency")
        .and_then(Value::as_object_mut)
        .and_then(|cross_limb| cross_limb.get_mut("integerBinding"))
        .and_then(Value::as_object_mut)
    {
        integer_binding.insert(
            "clearClaimBound".to_string(),
            Value::String(private_vss_clear_claim_bound.to_string()),
        );
        integer_binding.insert(
            "twoPrimeWindowRule".to_string(),
            Value::String(
                "the product of the two smallest data primes (about two to the ninety-four) exceeds twice the mask-plus-clear claim bound (about two to the ninety-three, dominated by the ninety-two-bit mask now that the clear bound is the carry-driven about two to the thirty-four rather than the full-range message bound) by only about one bit, so the centered two-prime lift is unique but with a thin margin set by the mask; widening the mask would not fit this window and would require a wider lift"
                    .to_string(),
            ),
        );
    }

    Ok(accounting)
}

pub(crate) fn succinct_private_vss_share_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctPrivateVssShareAccountingHash",
        &succinct_private_vss_share_accounting_value()?,
    )
}
