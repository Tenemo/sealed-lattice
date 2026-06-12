use serde_json::{Value, json};

use super::*;
use crate::bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE};
use crate::hashing::derive_protocol_hash;

// Repo-owned accounting for the trustee-batched succinct evaluation-key
// argument. Every row states what is implemented and measured against the
// fixed parameters in this module, and every open theorem item carries an
// explicit not-accepted status: this object never upgrades a documented
// budget into an accepted claim. The accounting hash is bound into the
// generate and verify command responses, and package integration binds it
// into the setup proof accounting certificate.
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
    // Clear consistency sums are bounded by max witness magnitude (two for
    // centered-binomial errors) times the ring degree times the coefficient
    // bound; the smudging mask spans CLAIM_MASK_DIGIT_COUNT binary digits.
    let consistency_coefficient_bound = (1_u64 << CONSISTENCY_COEFFICIENT_BITS) - 1;
    let clear_claim_bound =
        2_u128 * POLYNOMIAL_DEGREE as u128 * u128::from(consistency_coefficient_bound);

    Ok(json!({
        "objectType": "SuccinctEvaluationKeyProofAccounting",
        "objectVersion": 1,
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
        },
        "lowDegreeSoundness": {
            "queryCount": LOW_DEGREE_QUERY_COUNT,
            "foldedFinalCoefficientCount": LOW_DEGREE_FINAL_COEFFICIENT_COUNT,
            "perQueryBoundModel": "conjectured one-half per query at rate one half",
            "conjecturedQueryBoundLog2": -(LOW_DEGREE_QUERY_COUNT as i64),
            "provenBoundStatus": "proven-bound-and-proximity-gap-accounting-not-accepted",
            "grinding": "none-applied",
            "acceptanceBar": "proven or explicitly conjectured bound with grinding allowance and union bounds over limbs, keys, trustees, and ceremony objects, at least 128-bit effective soundness after every loss",
            "accepted": false,
        },
        "identitySoundness": {
            "outOfDomainPointCount": DEEP_POINT_COUNT,
            "compositionDegreeBound": "three times the masked column degree bound",
            "schwartzZippelPerPointLog2Approximate": -30,
            "linkedThroughBatchedQuotients": true,
            "accepted": false,
        },
        "linearRelationSoundness": {
            "lincheckRepetitions": LINCHECK_REPETITIONS,
            "perRepetitionBoundModel": "trace size over field size per repetition",
            "digitAndKeyBatching": "per-key gamma powers and per-relation alpha weights",
            "accepted": false,
        },
        "crossLimbConsistency": {
            "coefficientBits": CONSISTENCY_COEFFICIENT_BITS,
            "repetitions": CONSISTENCY_REPETITIONS,
            "preUnionCollisionBoundLog2":
                -(CONSISTENCY_COEFFICIENT_BITS as i64 * CONSISTENCY_REPETITIONS as i64),
            "jointBindingWithMaskColumns": "a forged witness or mask difference fixed before the challenge vectors collides with probability at most two to the negative coefficient bits per repetition",
            "centeredWindowArgument": {
                "clearClaimBound": clear_claim_bound.to_string(),
                "maskBound": (1_u128 << CLAIM_MASK_DIGIT_COUNT).to_string(),
                "smallestLimbPrime": smallest_limb_prime,
                "rule": "mask bound plus clear bound stays below half the smallest limb prime, so centered representatives are field-independent integers",
            },
            "writtenLemmaStatus": "consistency-lemma-not-yet-certified",
            "accepted": false,
        },
        "zeroKnowledge": {
            "columnMaskDegree": mask_degree,
            "openedEvaluationsPerColumn": opened_evaluations_per_column,
            "maskCoversOpenings": mask_degree >= opened_evaluations_per_column,
            "saltedCommitmentLeaves": true,
            "phaseTwoColumnsDeterministicFromMaskedMaterial": true,
            "simulatorArgumentStatus": "simulator-argument-not-yet-certified",
            "smudgingBudget": {
                "perClaimStatisticalDistanceLog2Approximate": -21,
                "structuralCap": "the smudging mask is capped by the centered no-wrap window below half the smallest limb prime, so a conventional negligible per-claim distance is unreachable inside the per-limb-field architecture",
                "acceptanceBar": "a certified total statistical or information-theoretic leakage bound across all claims, trustees, and ceremonies, or the single-proof-ring fallback",
                "accepted": false,
            },
        },
        "fiatShamir": {
            "transform": "multi-round Fiat-Shamir over the shared transcript hash",
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
            "qromAccountingStatus": "multi-round measure-and-reprogram accounting not yet certified",
            "accepted": false,
        },
        "sameSecretLinkage": {
            "mechanism": "BDLOP constant commitments opened natively over the commitment-modulus fields, bound to the shared secret by the joint cross-limb consistency",
            "commitmentFieldsAreDataPrimes": true,
            "arithmeticSourceRelations": [
                "round-one source equals the committed trustee secret",
                "round-two source equals the trustee secret times the public round-one aggregate",
                "Galois source equals the automorphism image of the committed trustee secret",
            ],
            "accepted": false,
        },
        "claimBoundary": "ClaimClosureMissing: development accounting for the succinct trustee evaluation-key argument; no row is an accepted certificate until the setup proof accounting certificate binds the closed theorem items",
    }))
}

pub(crate) fn succinct_evaluation_key_proof_accounting_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SuccinctEvaluationKeyProofAccountingHash",
        &succinct_evaluation_key_proof_accounting_value()?,
    )
}
