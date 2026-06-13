use serde_json::{Value, json};

use super::extension_field::CHALLENGE_EXTENSION_DEGREE;
use super::*;
use crate::bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE};
use crate::hashing::derive_protocol_hash;

// Repo-owned accounting for the trustee-batched succinct evaluation-key
// argument. Every row states what is implemented and measured against the
// fixed parameters in this module, and every theorem row carries its closure
// argument inline: the soundness model is round-by-round, every
// post-commitment challenge is drawn from the degree-four challenge extension
// of the limb field, and the one explicitly conjectured input (the per-query
// FRI bound at rate one half) is named as a conjecture with its proven
// fallback. The accounting hash is bound into the generate and verify command
// responses, and package integration binds it into the setup proof accounting
// certificate.
pub(crate) fn succinct_evaluation_key_proof_accounting_value() -> CanonicalResult<Value> {
    let trace_size = POLYNOMIAL_DEGREE / TRACE_SPLIT;
    let extension_size = trace_size * DOMAIN_BLOWUP;
    let commitment_bound = COMMITMENT_BOUND_FACTOR * trace_size;
    let mask_degree = column_mask_degree(trace_size);
    let opened_evaluations_per_column = 2 * LOW_DEGREE_QUERY_COUNT + DEEP_POINT_COUNT;
    let smallest_limb_prime = *DATA_PRIMES
        .iter()
        .min()
        .expect("the data basis is non-empty");
    // Conservative floor of the field sizes: bits(p) - 1, so every stated
    // bound understates rather than overstates the challenge space.
    let base_field_bits = i64::from(smallest_limb_prime.ilog2());
    let challenge_field_bits = base_field_bits * CHALLENGE_EXTENSION_DEGREE as i64;
    // Clear consistency sums are bounded by max witness magnitude (two for
    // centered-binomial errors) times the ring degree times the coefficient
    // bound; the smudging mask spans CLAIM_MASK_DIGIT_COUNT binary digits.
    let consistency_coefficient_bound = (1_u64 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    let clear_claim_bound =
        2_u128 * POLYNOMIAL_DEGREE as u128 * u128::from(consistency_coefficient_bound);
    // Ceiling of the clear bound's bit length, again the conservative side.
    let clear_claim_bound_bits = i64::from(clear_claim_bound.ilog2()) + 1;
    // Union budget over the first profile: limb fields, schedule keys,
    // trustees, and accepted ceremony objects. Stated as a power-of-two
    // allowance the per-round bounds are discounted by.
    let union_budget_bits = 16_i64;
    // Per-round round-by-round errors, in -log2, each rounded against us.
    let fold_round_bits = challenge_field_bits - i64::from(extension_size.ilog2());
    let out_of_domain_round_bits =
        challenge_field_bits - (i64::from((3 * commitment_bound).ilog2()) + 1);
    let lincheck_round_bits =
        (challenge_field_bits - i64::from(trace_size.ilog2())) * LINCHECK_REPETITIONS as i64;
    let consistency_round_bits =
        CONSISTENCY_COEFFICIENT_BITS as i64 * CONSISTENCY_REPETITIONS as i64;
    let query_round_bits = LOW_DEGREE_QUERY_COUNT as i64;
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

    Ok(json!({
        "objectType": "SuccinctEvaluationKeyProofAccounting",
        "objectVersion": 2,
        "proofFamily": "trustee-evaluation-key",
        "argumentShape": {
            "model": "per-limb-field univariate polynomial IOP with batched low-degree commitment",
            "limbFields": "one instance per active data prime, no lifted-integer carries",
            "traceSplit": TRACE_SPLIT,
            "traceSize": trace_size,
            "domainBlowup": DOMAIN_BLOWUP,
            "extensionSize": extension_size,
            "commitmentDegreeBound": commitment_bound,
            "rate": "commitment bound over extension size, one half",
            "ringDegree": POLYNOMIAL_DEGREE,
            "challengeExtensionDegree": CHALLENGE_EXTENSION_DEGREE,
            "challengeFieldBitsApproximate": challenge_field_bits,
            "challengeDomain": "every post-commitment challenge (key batching, lincheck, batching alphas, beta, out-of-domain points, batching lambda, fold challenges) is drawn from the degree-four extension tower of the limb field; committed columns and query openings stay in the base field",
        },
        "lowDegreeSoundness": {
            "queryCount": LOW_DEGREE_QUERY_COUNT,
            "foldedFinalCoefficientCount": LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
            "perQueryBoundModel": "explicitly conjectured one-half per query at rate one half",
            "conjecturedQueryBoundLog2": -(LOW_DEGREE_QUERY_COUNT as i64),
            "conjectureStatement": "the accepted bound is the standard rate-per-query FRI conjecture; the proven proximity-gap bound (Johnson radius, square root of the rate per query) gives half the bits per query and is the documented fallback at double the query count",
            "provenBoundReference": "Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, Proximity gaps for Reed-Solomon codes (BCIKS20)",
            "foldRoundSoundnessLog2": -fold_round_bits,
            "foldChallengeDomain": "each fold challenge is one degree-four extension element, so a fold round's round-by-round error is the extension domain size over the challenge field size",
            "grinding": "none-applied: every round bound already clears the target with margin",
            "unionBudgetLog2": union_budget_bits,
            "effectiveSoundnessBitsAfterUnion": effective_soundness_bits,
            "acceptanceBar": "explicitly conjectured bound with grinding allowance and union bounds over limbs, keys, trustees, and ceremony objects, at least 128-bit effective soundness after every loss",
            "accepted": true,
        },
        "identitySoundness": {
            "outOfDomainPointCount": DEEP_POINT_COUNT,
            "compositionDegreeBound": "three times the masked column degree bound",
            "outOfDomainPointDomain": "degree-four challenge extension, rejection-sampled outside the base trace subgroup and coset",
            "schwartzZippelPerPointLog2": -out_of_domain_round_bits,
            "linkedThroughBatchedQuotients": true,
            "accepted": true,
        },
        "linearRelationSoundness": {
            "lincheckRepetitions": LINCHECK_REPETITIONS,
            "perRepetitionBoundModel": "trace size over challenge field size per repetition, repetitions drawn in one round",
            "lincheckRoundSoundnessLog2": -lincheck_round_bits,
            "digitAndKeyBatching": "per-key gamma powers and per-relation alpha weights, all in the challenge extension",
            "accepted": true,
        },
        "crossLimbConsistency": {
            "coefficientBits": CONSISTENCY_COEFFICIENT_BITS,
            "repetitions": CONSISTENCY_REPETITIONS,
            "preUnionCollisionBoundLog2": -consistency_round_bits,
            "consistencyLemma": "every limb publishes the residue of one shared claim integer per (witness vector, repetition); the verifier lifts the integer from two limb fields (the two-prime window exceeds twice the claim bound, so the centered lift is unique) and checks every other limb residue against it, so distinct row-checked small witnesses across limbs must collide on all bounded random combinations, which happens with probability at most two to the negative coefficient bits per repetition, fixed before the challenge vectors by the committed witness trees",
            "integerBinding": {
                "clearClaimBound": clear_claim_bound.to_string(),
                "maskBound": (1_u128 << CLAIM_MASK_DIGIT_COUNT).to_string(),
                "twoPrimeWindowRule": "the product of the two smallest data primes exceeds twice the mask-plus-clear claim bound, so the lifted integer is unique and a claim present in fewer than two limb fields is refused",
            },
            "accepted": true,
        },
        "zeroKnowledge": {
            "columnMaskDegree": mask_degree,
            "openedEvaluationsPerColumn": opened_evaluations_per_column,
            "maskCoversOpenings": mask_degree >= opened_evaluations_per_column,
            "saltedCommitmentLeaves": true,
            "phaseTwoColumnsDeterministicFromMaskedMaterial": true,
            "simulatorArgument": "every opened leaf row, out-of-domain evaluation, and low-degree-proof message is simulatable from the public statement and the published claims: the vanishing-polynomial column masks exceed the opened-evaluation budget, so opened off-trace evaluations of each committed column are uniform and independent of the witness; leaf salts give statistical hiding for unopened rows; the quotient and fold layers are deterministic functions of the masked material and the public challenges",
            "simulatorMarginEvaluations": mask_degree as i64 - opened_evaluations_per_column as i64,
            "smudgingBudget": {
                "perClaimStatisticalDistanceLog2": clear_claim_bound_bits - CLAIM_MASK_DIGIT_COUNT as i64,
                "leakageStatement": "each published claim integer is a clear bounded combination plus a uniform mask of CLAIM_MASK_DIGIT_COUNT bits, so the per-claim statistical distance from a witness-independent distribution is at most the clear bound over the mask bound, about two to the minus sixty-eight; across every claim, trustee, and ceremony object of the first profile (about two to the seventeen claims) the total leakage stays below two to the minus fifty, and the bound says nothing about quantities outside the published claims",
                "claimBudgetLog2Approximate": 17,
                "totalLeakageLog2Approximate": clear_claim_bound_bits - CLAIM_MASK_DIGIT_COUNT as i64 + 17,
                "accepted": true,
            },
        },
        "fiatShamir": {
            "transform": "multi-round Fiat-Shamir over the shared transcript hash",
            "soundnessModel": "round-by-round: every interactive round's error is bounded above, and the non-interactive bound is the adversary's query budget times the weakest round error (BCS16-style compilation); the stated security level counts one hash query per grinding attempt on the weakest round",
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
            "qromAccounting": "quantum random-oracle reductions for multi-round Fiat-Shamir are referenced, not re-proven here: the measure-and-reprogram bound of DFM20 with the DFMS19 sigma-protocol predecessor and the DFMS22 commit-and-open treatment; the certified level is stated in the classical round-by-round model, and the QROM reduction loss is an explicit open caveat carried by this row's references rather than a silent assumption",
            "qromReferences": [
                "DFM20, The measure-and-reprogram technique 2.0: multi-round Fiat-Shamir and more",
                "DFMS19, Security of the Fiat-Shamir transformation in the quantum random-oracle model",
                "DFMS22, Efficient NIZKs and signatures from commit-and-open protocols in the QROM",
            ],
            "accepted": true,
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
            "accepted": true,
        },
        "claimBoundary": "accounting closed for the succinct trustee evaluation-key argument: every theorem row above is accepted under one explicitly named conjecture (the rate-per-query FRI bound) and classical round-by-round Fiat-Shamir accounting with referenced QROM reductions; rows outside this argument (ceremony transport, roster binding, target decryption) keep their own gates",
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
    accounting_fields.insert("wasmBrowserMeasurement".to_string(), wasm_browser_measurement);

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
            "anchorReference": "the statement carries the same-secret anchor statement and proof roots in its hashed context, and the single constant-commitment opening makes the share secret congruent to the anchored secret modulo the commitment modulus product, which with ternary support makes them equal as integers",
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
