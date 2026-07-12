use super::*;

pub(in super::super) fn setup_parameters_hash() -> CanonicalResult<String> {
    setup_parameters_hash_for_roster(&foundation_roster_parameters())
}

pub(in super::super) fn setup_parameters_hash_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&setup_parameters_value(roster)?)
}

// The single canonical identity for the roster-parameterized collective BGV
// setup parameter set, in the style of the BGV parms_id: one object that unions
// the roster quorums, the inlined sub-configuration values (carry-aware VSS
// relation, commitment, setup-proof, transport, evaluator key schedule), the
// inlined Q_share primes and public VSS commitment material sizing, and the BGV
// parameters hash. Each part is a deterministic function of the roster and fixed
// parameters, so this hash is the setup-parameter identity checked by verifiers.
pub(super) fn setup_parameters_value(roster: &AcceptedRosterParameters) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupParameters",
        "adversaryModel": "active-static",
        "livenessModel": "secure-with-abort",
        "participantCount": roster.participant_count,
        "qSetupComplete": roster.setup_completion_quorum,
        "qBallotRelease": roster.ballot_release_quorum,
        "qFinal": roster.finality_quorum,
        "qDec": roster.decryption_threshold,
        "qShare": q_share_value(),
        "bgvParametersHash": bgv_parameters_hash()?,
        "carryAwareVssShareRelation": carry_aware_vss_share_relation_value(),
        "commitment": setup_commitment_parameters_value()?,
        "setupProof": setup_proof_parameters_value()?,
        "setupTransport": setup_transport_parameters_value_for_roster(roster)?,
        "evaluatorKeySchedule": evaluator_key_schedule_value_for_roster(roster)?,
        "boundedDomainEvaluator": bounded_domain_evaluator_value_for_roster(roster)?,
    }))
}

// The bounded-domain evaluator profile binding: the score-difference domain the
// comparison polynomial is interpolated over is a deterministic function of the
// roster (score span times ballot count, ballots being full-roster), so binding
// it here makes the evaluator comparison domain part of the setup-parameter
// identity instead of an unbound runtime argument.
pub(super) fn bounded_domain_evaluator_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    let score_span =
        crate::bgv::direct_ballots::MAXIMUM_SCORE - crate::bgv::direct_ballots::MINIMUM_SCORE;
    let score_difference_bound = score_span
        .checked_mul(roster.participant_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "score-difference bound does not fit u64",
            )
        })?;
    Ok(json!({
        "objectType": "BoundedDomainEvaluatorParameters",
        "scoreDifferenceBound": score_difference_bound,
        "directComparisonOutputLevel": crate::bgv::evaluator::top_k::DIRECT_COMPARISON_OUTPUT_LEVEL,
        "tiePolicy": crate::bgv::evaluator::top_k::TIE_POLICY,
    }))
}

pub(super) fn setup_transport_parameters_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupTransport",
        "largeObjectEncoding": "binary",
        "chunking": "required",
        "storageQuotaBytes": SETUP_TRANSPORT_STORAGE_QUOTA_BYTES,
        "largestSingleBufferBytes": SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES,
        "copyCountLimit": SETUP_TRANSPORT_COPY_COUNT_LIMIT,
        "streamVerificationOrder": SETUP_TRANSPORT_STREAM_ORDER,
        "resumePolicy": SETUP_TRANSPORT_RESUME_POLICY,
        "lazyLoadingPolicy": SETUP_TRANSPORT_LAZY_LOADING_POLICY,
        "requiredTransportedObjects": [
            {
                "objectName": SETUP_TRANSPORTED_VSS_MATERIAL_NAME,
                "objectRole": SETUP_TRANSPORTED_VSS_MATERIAL_ROLE,
                // The transport minimum is the full-ring full-material size,
                // independent of any development-reduced-ring package; this keeps
                // the transport hash a pure function of the roster.
                "minimumByteLength": setup_transport_vss_material_byte_length_for_roster(
                    roster,
                    POLYNOMIAL_DEGREE as u64,
                )?,
            }
        ],
    }))
}

pub(super) fn evaluator_key_schedule_value_for_roster(
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<Value> {
    let required_galois_key_schedule = expected_required_galois_key_schedule()?;
    let required_galois_set_hash =
        expected_required_galois_set_hash(&required_galois_key_schedule)?;

    Ok(json!({
        "objectType": "EvaluatorKeySchedule",
        "evaluatorScheme": EVALUATOR_REPLAY_SCHEME_LABEL,
        "packingScheme": EVALUATOR_PACKING_SCHEME_LABEL,
        "participantCount": roster.participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "relinearizationLevelSchedule": expected_relinearization_level_schedule(),
        "requiredGaloisKeySchedule": required_galois_key_schedule,
        "requiredGaloisSetHash": required_galois_set_hash,
    }))
}

// One relinearization key per round at the selected evaluator working level:
// lower levels reuse the same key through CRT-idempotent truncation, so the
// schedule carries no per-level entries.
pub(super) fn expected_relinearization_level_schedule() -> Value {
    Value::Array(vec![json!({
        "level": SELECTED_EVALUATOR_WORKING_LEVEL,
        "proofFamily": "relinearization-key-share",
        "keyShareRounds": ["round-one", "round-two"],
    })])
}

pub(super) fn expected_required_galois_key_schedule() -> CanonicalResult<Value> {
    let mut entries_by_rotation_and_level = BTreeMap::new();
    for rotation in direct_score_packing_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, SELECTED_EVALUATOR_WORKING_LEVEL),
            "direct-score-packing-generator-basis",
        );
    }
    for rotation in packed_rank_forward_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level
            .entry((rotation, SELECTED_EVALUATOR_WORKING_LEVEL))
            .or_insert("generator-ordered-packed-rank-forward-basis");
    }
    for rotation in packed_rank_return_basis_galois_elements(MAXIMUM_OPTION_COUNT)? {
        entries_by_rotation_and_level.insert(
            (rotation, SELECTED_EVALUATOR_WORKING_LEVEL),
            "generator-ordered-packed-rank-return-basis",
        );
    }

    Ok(Value::Array(
        entries_by_rotation_and_level
            .into_iter()
            .map(|((rotation, level), purpose)| {
                json!({
                    "rotation": rotation,
                    "level": level,
                    "purpose": purpose,
                    "proofFamily": "galois-key-share",
                })
            })
            .collect(),
    ))
}

pub(super) fn expected_required_galois_set_hash(
    required_galois_key_schedule: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&required_galois_set_value(
        required_galois_key_schedule.clone(),
    ))
}

pub(super) fn required_galois_set_value(required_galois_key_schedule: Value) -> Value {
    json!({
        "objectType": REQUIRED_GALOIS_SET_OBJECT_TYPE,
        "evaluatorScheme": EVALUATOR_REPLAY_SCHEME_LABEL,
        "packingScheme": EVALUATOR_PACKING_SCHEME_LABEL,
        "rnsLimbCount": DATA_PRIMES.len(),
        "entries": required_galois_key_schedule,
    })
}

pub(super) fn setup_proof_parameters_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "SetupProof",
        "relationModel": {
            "applicationRing": "Z_q[X]/(X^N+1)",
            "applicationRingDegree": POLYNOMIAL_DEGREE,
            "ringDegreeMapping": "full BGV polynomials are mapped into proof-ring polynomial vectors by the fixed isoring split",
            "rnsLimbCount": DATA_PRIMES.len(),
            "statementEncoding": "canonical-json-roots-plus-binary-proof-chunks",
            "relationForm": "A*witness = target + q_l*carry over lifted integers with explicit no-wrap bounds",
            "limbHandling": "relations are checked per accepted Q_share limb and bind one shared trustee secret where required"
        },
        "witnessBounds": {
            "trusteeSecret": {
                "distribution": "coefficientwise-centered-ternary",
                "infinityNormBound": 1,
                "rnsBinding": "one short trustee secret is reduced into every accepted Q_share limb"
            },
            "vssOpeningCarry": {
                "domain": "non-negative-bounded-integer",
                "boundSource": "carry-aware-vss-share-opening-relation"
            },
            "noWrapCarry": {
                "domain": "bounded-lifted-integer"
            }
        },
        "proofFamilies": setup_proof_family_descriptions()?,
        "proofSerialization": {
            "encoding": SETUP_PROOF_SERIALIZATION,
            "proofBytesDomain": SETUP_PROOF_BYTES_DOMAIN,
            "succinctProofByteLayout": {
                "encoding": "sealed-lattice-succinct-setup-proof-bytes"
            },
            "chunking": "required-for-large-proof-material",
            "canonicalJsonRole": "root-bound metadata only"
        }
    }))
}

pub(super) fn setup_proof_family_descriptions() -> CanonicalResult<Vec<Value>> {
    let family_descriptions = ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES
        .iter()
        .map(|proof_family| {
            let (statement, witness, no_wrap_rule) = match *proof_family {
                "public-key-share" => (
                    "public-key share relation proves b_l + a_l*s - p*e = 0 over every accepted Q_share limb",
                    "one ternary trustee secret, one centered-binomial error vector, and the selected limb-zero commitment opening randomness",
                    "the selected limb-zero opening links the share secret to the verified same-secret bridge; ternary support makes the congruent secrets equal",
                ),
                "vss-opening-carry" => (
                    "private VSS share opens the homomorphic coefficient-commitment combination with explicit q_l carry",
                    "private share, coefficient openings, and bounded non-negative carry",
                    "unreduced lifted share relation must hold below the commitment modulus product",
                ),
                "trustee-evaluation-key" => (
                    "trustee evaluation-key relation proves every scheduled relinearization and Galois share against the committed trustee secret",
                    "one trustee secret, schedule-bound key-switch source witnesses, component openings, carry witnesses, and same-secret linkage openings",
                    "round-one, round-two, and Galois source relations are enforced against the frozen evaluator schedule and recomputed public aggregates",
                ),
                _ => unreachable!("ACCEPTED_SETUP_SUCCINCT_PROOF_FAMILIES is fixed in this module"),
            };
            Ok(json!({
                "proofFamily": proof_family,
                "statement": statement,
                "witness": witness,
                "noWrapRule": no_wrap_rule,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(family_descriptions)
}
