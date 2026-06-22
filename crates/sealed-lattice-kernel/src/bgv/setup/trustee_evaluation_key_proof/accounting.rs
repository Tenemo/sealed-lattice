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
// This conjecture is an admissible, claim-bearing soundness foundation under the
// project's proximity-gap policy: a repaired below-capacity conjecture may carry
// claim-bearing post-quantum soundness, the disproved up-to-capacity one may not.
// The residual is a disclosed small-medium research risk, not a claim gap: CS25
// Our Conjecture 3 is a recent (2025) conjecture and could be weakened by future
// work, though it is the best-pedigreed standing one (its authors disproved the
// prior conjecture). The proven BCIKS20 Johnson fallback at a larger query count
// removes that research risk entirely.
//
// QROM rows now carry the computed reduction loss via CMS19 (state-restoration
// BCS-in-QROM, round-independent O(t^2 * eps + t^3 / 2^lambda)): the Grover
// square-root halves the classical round-by-round soundness, giving about 70-bit
// quantum soundness across the instance union (about 78-bit single statement),
// with the 512-bit SHAKE256 digest contributing about 170-bit (not the
// bottleneck). This is below the conventional 128-bit quantum bar and is not
// upgraded to qromAccepted; it is recorded as the stated achieved level, scoped
// by the present-time threat (a forgery needs a quantum computer of that power
// running DURING the ceremony, with no harvest-now-decrypt-later exposure). The
// smudging row is still a bounded-leakage statement rather than a 128-bit
// zero-knowledge claim. The accounting hash is bound into the generate and
// verify command responses, and package integration binds it into the setup
// proof accounting certificate.
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
    // centered-binomial errors in this family) times the ring degree times the
    // coefficient bound; the smudging mask spans CLAIM_MASK_DIGIT_COUNT binary
    // digits.
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
    let entropy_capacity_query_soundness_permille = 930_i64;
    let query_round_bits =
        LOW_DEGREE_QUERY_COUNT as i64 * entropy_capacity_query_soundness_permille / 1000;
    // The proven, unconditional fallback is the BCIKS20 Johnson radius
    // (square root of the rate, half a bit per query); it is independent of the
    // conjecture, so it is computed from the raw query count, not from the
    // re-based query-round bits above.
    let proven_fallback_query_bits = LOW_DEGREE_QUERY_COUNT as i64 / 2;
    let proven_fallback_effective_soundness_bits = proven_fallback_query_bits - union_budget_bits;
    let proven_fallback_query_count_for_128_bits = 2 * (128 + union_budget_bits);
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
    // Quantum (QROM) soundness via CMS19 (state-restoration BCS-in-QROM): the
    // BCS transform of this public-coin round-by-round-sound IOP has QROM
    // soundness error O(t^2 * eps + t^3 / 2^lambda), independent of the round
    // count, for an adversary making t quantum random-oracle queries with IOP
    // round-by-round soundness eps and digest size lambda. The Grover
    // square-root halves the classical round-by-round soundness (the t^2 * eps
    // term), and the hash term is the BHT quantum-collision bound on the digest.
    // The digest is SHAKE256 with a 64-byte output (hashing::hash512), used for
    // every Merkle leaf, Merkle node, and Fiat-Shamir challenge.
    let digest_bits = 512_i64;
    let quantum_soundness_bits = weakest_round_bits / 2;
    let quantum_soundness_after_union_bits = effective_soundness_bits / 2;
    let quantum_collision_resistance_bits = digest_bits / 3;

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
            "perQueryBoundModel": "claim-bearing under the named CS25 mutual-correlated-agreement FRI conjecture up to the q-ary list-decoding (entropy) capacity for prime fields, the admissible repair of the disproved up-to-capacity conjecture, about 0.938 bit per query at rate one half over the base limb field, floored to 0.930 bit",
            "conjecturedQueryBoundLog2": -query_round_bits,
            "conjectureStatement": "re-based in 2026 onto CS25 'Our Conjecture 3': the proximity-gap radius this batched DEEP-FRI relies on is the q-ary list-decoding (entropy) capacity (mutual correlated agreement for prime fields), strictly below the 1 - rho radius of BCI+23 Conjecture 8.4 that Crites-Stewart (CS25) and BCHKS26 disproved in 2025; over the base limb field the entropy-capacity radius costs about one over log2(q) of distance, so per-query soundness is about 0.938 bit and 168 queries record about 156 bits before the union allowance; this repaired below-capacity conjecture is an admissible, claim-bearing soundness foundation under the project's proximity-gap policy, with a disclosed small-medium research risk that it is a recent (2025) conjecture; the proven proximity-gap fallback (BCIKS20 Johnson radius, square root of the rate, half a bit per query) is unconditional, removes that research risk, but needs double the query count to clear 128 bits",
            "namedConjectureReference": "Crites, Stewart, On Reed-Solomon proximity gaps conjectures (CS25), Our Conjecture 3 (mutual correlated agreement up to the q-ary list-decoding capacity for prime fields); repairs the disproved BCI+23 Conjecture 8.4 up-to-capacity proximity gap",
            "provenBoundReference": "Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, Proximity gaps for Reed-Solomon codes (BCIKS20)",
            "provenFallbackQueryBoundLog2": -proven_fallback_query_bits,
            "provenFallbackEffectiveSoundnessBitsAfterUnion": proven_fallback_effective_soundness_bits,
            "provenFallbackQueryCountFor128BitsAfterUnion": proven_fallback_query_count_for_128_bits,
            "foldRoundSoundnessLog2": -fold_round_bits,
            "foldChallengeDomain": "each fold challenge is one degree-four extension element, so a fold round's round-by-round error is the extension domain size over the challenge field size",
            "grinding": "none-applied: every round bound already clears the target with margin",
            "unionBudgetLog2": union_budget_bits,
            "effectiveSoundnessBitsAfterUnion": effective_soundness_bits,
            "acceptanceBar": "the named CS25 entropy-capacity FRI row clears 128 bits after the fixed union allowance (about 140 bits); the proven BCIKS20 Johnson fallback does not clear 128 bits at the current query count and would require the recorded larger query count or a redesigned low-degree check",
            "acceptedUnderNamedFriConjecture": true,
            "acceptedUnderProvenFallback": false,
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
            "zeroKnowledgeClaimStatus": "bounded-statistical-leakage-scope-recorded-not-128-bit-zero-knowledge",
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
                "acceptedForBoundedLeakagePrototype": true,
                "acceptedFor128BitZeroKnowledge": false,
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
            "qromModel": "the quantum random-oracle reduction loss is computed via CMS19 (Chiesa-Manohar-Spooner, Succinct arguments in the quantum random-oracle model): the BCS transform of a public-coin round-by-round-sound IOP, which this argument is, has QROM soundness error O(t^2 * eps + t^3 / 2^lambda) against an adversary making t quantum random-oracle queries, where eps is the IOP round-by-round soundness error and lambda is the digest size; the bound is independent of the round count, which is why it applies to this roughly seventeen-round FRI argument where the measure-and-reprogram bound (DFM20) carries a round-dependent (2t+1)^(2*rounds) loss that is vacuous at this round count",
            "qromSoundnessTermModel": "t^2 * eps: the Grover square-root halves the classical round-by-round soundness, so quantum soundness in bits is about half the weakest classical round",
            "qromHashTermModel": "t^3 / 2^lambda: the BHT quantum-collision bound on the digest, about lambda/3 bits",
            "digestBits": digest_bits,
            "digestFunction": "SHAKE256 with a 64-byte output (hashing::hash512), used for every Merkle leaf, Merkle node, and Fiat-Shamir challenge",
            "quantumCollisionResistanceBitsApproximate": quantum_collision_resistance_bits,
            "classicalCollisionResistanceBitsApproximate": digest_bits / 2,
            "achievedQuantumSoundnessBitsApproximate": quantum_soundness_bits,
            "achievedQuantumSoundnessAfterInstanceUnionBitsApproximate": quantum_soundness_after_union_bits,
            "achievedQuantumSoundnessCalculation": "the weakest classical round-by-round soundness (the FRI query round, about 156 bits, conjectural under CS25) is halved by the Grover square-root to about 78 bits single-statement; halving the union-effective 140 bits gives about 70 bits across the first profile's instance union; the digest contributes about 170 bits (512 over 3, BHT quantum collision) and is not the bottleneck, so the achieved post-quantum soundness is set by the soundness term, not the hash",
            "presentTimeThreatScope": "this bound concerns a cheating prover only, and soundness is a present-time property: a setup-proof forgery must be produced during the live ceremony, so exploiting it requires an adversary to operate a fault-tolerant quantum computer capable of roughly two to the seventy random-oracle queries DURING the ceremony itself. There is no harvest-now-decrypt-later exposure, unlike confidentiality: the BGV/RLWE, ML-KEM-768, and ML-DSA-65 confidentiality and authentication layers are the harvest-now surfaces and are post-quantum now. An adversary that does not possess such a quantum computer running at ceremony time cannot exploit this soundness bound, regardless of later quantum progress.",
            "pathTo128BitQuantumSoundness": "128-bit quantum soundness needs eps <= 2^-256, i.e. 256-bit classical round-by-round soundness on every round (CMS19 proves the t^2 * eps term tight, so the Grover halving is unavoidable); that forces a degree-six challenge extension (about 2^276, since the fold and out-of-domain rounds are single-challenge draws capped by the current 2^184 field), about 276 FRI queries with the column mask doubled, and about 32 consistency repetitions, roughly doubling the proof. This is not chosen; the achieved level above is stated instead.",
            "qromReferences": [
                "CMS19, Succinct arguments in the quantum random-oracle model (the applicable round-independent BCS-in-QROM bound)",
                "BCS16, Interactive oracle proofs (the underlying IOP-to-non-interactive-argument compilation)",
                "DFM20, The measure-and-reprogram technique 2.0: multi-round Fiat-Shamir and more (round-dependent, not the applicable bound at this round count)",
                "DFMS19, Security of the Fiat-Shamir transformation in the quantum random-oracle model",
                "DFMS22, Efficient NIZKs and signatures from commit-and-open protocols in the QROM",
            ],
            "classicalRoundByRoundAccepted": true,
            "qromReductionLossComputed": true,
            "meetsConventional128BitQuantumBar": false,
            "qromAccepted": false,
            "qromReductionLossStatus": "computed-cms19-state-restoration-achieved-level-recorded",
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
        "claimBoundary": "accounting closed for classical succinct-family soundness under the explicitly named CS25 mutual-correlated-agreement FRI conjecture up to the q-ary list-decoding (entropy) capacity, the admissible claim-bearing repair of the disproved up-to-capacity proximity gap, carrying a disclosed small-medium research risk; the proven BCIKS20 Johnson fallback is the unconditional alternative, CMS19 QROM achieved-level metadata is recorded but not accepted as QROM strength, the full 128-bit zero-knowledge upgrade is not accepted, and the smudging statement is scoped to its recorded bounded leakage; rows outside this argument (ceremony transport, roster binding, target decryption) keep their own gates",
    }))
}

pub(crate) fn succinct_evaluation_key_proof_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctEvaluationKeyProofAccountingHash",
        &succinct_evaluation_key_proof_accounting_value()?,
    )
}

const FIRST_PROFILE_ROSTER_SIZE: u64 = 10;
const FIRST_PROFILE_DECRYPTION_THRESHOLD: usize = 4;
const FIRST_PROFILE_CLAIM_BUDGET_LOG2_APPROXIMATE: i64 = 17;

fn clear_consistency_claim_bound_for_witness_bound(witness_bound: u128) -> u128 {
    let consistency_coefficient_bound = (1_u128 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    witness_bound
        .checked_mul(POLYNOMIAL_DEGREE as u128)
        .and_then(|bound| bound.checked_mul(consistency_coefficient_bound))
        .expect("first-profile consistency claim bound fits in u128")
}

fn bit_length(value: u128) -> i64 {
    i64::from(value.ilog2()) + 1
}

fn first_profile_private_vss_carry_bound() -> u128 {
    let mut power = 1_u128;
    let mut bound = 0_u128;
    for _ in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD {
        bound = bound
            .checked_add(power)
            .expect("first-profile private VSS carry bound fits in u128");
        power = power
            .checked_mul(u128::from(FIRST_PROFILE_ROSTER_SIZE))
            .expect("first-profile private VSS carry bound fits in u128");
    }

    bound
}

fn first_profile_private_vss_smudging_budget() -> Value {
    let largest_source_message_modulus = u128::from(
        *DATA_PRIMES
            .iter()
            .max()
            .expect("the data basis is non-empty"),
    );
    let source_message_bound = largest_source_message_modulus
        .checked_sub(1)
        .expect("data prime is positive");
    let carry_bound = first_profile_private_vss_carry_bound();
    let witness_bound = source_message_bound.max(carry_bound).max(1);
    let clear_claim_bound = clear_consistency_claim_bound_for_witness_bound(witness_bound);
    let clear_claim_bound_bits = bit_length(clear_claim_bound);
    let per_claim_statistical_distance_log2 =
        clear_claim_bound_bits - CLAIM_MASK_DIGIT_COUNT as i64;
    let total_leakage_log2_approximate =
        per_claim_statistical_distance_log2 + FIRST_PROFILE_CLAIM_BUDGET_LOG2_APPROXIMATE;

    json!({
        "perClaimStatisticalDistanceLog2": per_claim_statistical_distance_log2,
        "leakageStatement": "private VSS published claim integers include full-size source-limb message residues, so the family-specific clear bound is about two to the seventy and the ninety-two-bit mask gives about two to the minus twenty-two per claim; across the first profile claim budget this is about two to the minus five, a disclosed bounded-leakage row only and not a 128-bit zero-knowledge statement",
        "familyClearClaimBoundModel": "private VSS masked claims use max(source_message_modulus - 1, lifted carry bound) times ring degree times the eight-bit consistency coefficient bound; first-profile carry uses recipient point ten and four Shamir coefficients, giving 1 + 10 + 100 + 1000",
        "largestSourceMessageModulus": largest_source_message_modulus.to_string(),
        "sourceMessageBound": source_message_bound.to_string(),
        "carryBound": carry_bound.to_string(),
        "witnessBound": witness_bound.to_string(),
        "clearClaimBound": clear_claim_bound.to_string(),
        "clearClaimBoundBits": clear_claim_bound_bits,
        "claimBudgetLog2Approximate": FIRST_PROFILE_CLAIM_BUDGET_LOG2_APPROXIMATE,
        "totalLeakageLog2Approximate": total_leakage_log2_approximate,
        "acceptedForBoundedLeakagePrototype": true,
        "acceptedFor128BitZeroKnowledge": false,
    })
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
    // Families with wider consistency witnesses must replace the inherited
    // smudging budget after this shared accounting object is built.
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
    if let Some(smudging_budget) = accounting_fields
        .get_mut("zeroKnowledge")
        .and_then(|zero_knowledge| zero_knowledge.get_mut("smudgingBudget"))
    {
        *smudging_budget = first_profile_private_vss_smudging_budget();
    }

    Ok(accounting)
}

pub(crate) fn succinct_private_vss_share_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctPrivateVssShareAccountingHash",
        &succinct_private_vss_share_accounting_value()?,
    )
}
