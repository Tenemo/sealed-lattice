use crate::bgv::setup::trustee_evaluation_key_proof::merkle_commitment::MERKLE_DIGEST_BYTES;

#[test]
fn proof_accounting_closes_every_theorem_row_with_margin() {
    let accounting = super::accounting::succinct_evaluation_key_proof_accounting_value()
        .expect("accounting value");
    let accounting_hash = super::accounting::succinct_evaluation_key_proof_accounting_hash()
        .expect("accounting hash");
    assert_eq!(accounting_hash.len(), 128);
    // These bounds are essential: 128-bit effective soundness depends on the
    // -160 pre-union margin and a named, unproven FRI conjecture, and
    // zero-knowledge is bounded-leakage only -- do not relax them to make the
    // accounting pass. The recomputed numeric soundness and leakage bounds, not
    // self-attested verdict flags, are what these rows must carry.
    assert_eq!(
        accounting["crossLimbConsistency"]["preUnionCollisionBoundLog2"],
        serde_json::json!(-160)
    );
    // The vanishing-polynomial column mask must strictly exceed the opened
    // evaluation budget, so the simulator margin is positive.
    assert!(
        accounting["zeroKnowledge"]["simulatorMarginEvaluations"]
            .as_i64()
            .expect("simulator margin")
            > 0
    );
    assert!(
        accounting["fiatShamir"]["effectiveSoundnessBitsAfterUnion"]
            .as_i64()
            .expect("effective soundness")
            >= 128
    );
    let merkle_digest_bits = i64::try_from(8 * MERKLE_DIGEST_BYTES).expect("digest bits");
    assert_eq!(
        accounting["fiatShamir"]["digestBits"],
        serde_json::json!(merkle_digest_bits)
    );
    assert_eq!(
        accounting["fiatShamir"]["quantumCollisionResistanceBitsApproximate"],
        serde_json::json!(merkle_digest_bits / 3)
    );
    let achieved_quantum_soundness_bits =
        accounting["fiatShamir"]["achievedQuantumSoundnessBitsApproximate"]
            .as_i64()
            .expect("achieved quantum soundness");
    assert!(
        merkle_digest_bits / 3 >= achieved_quantum_soundness_bits,
        "Merkle digest width must keep the CMS19 hash term above the current QROM soundness bottleneck"
    );
    let report = super::accounting::succinct_proof_soundness_report(
        crate::bgv::profile::POLYNOMIAL_DEGREE / 2,
    )
    .expect("typed soundness report");
    assert_eq!(
        report.effective_soundness_bits,
        accounting["fiatShamir"]["effectiveSoundnessBitsAfterUnion"]
            .as_i64()
            .expect("JSON effective soundness")
    );
    super::accounting::enforce_current_succinct_proof_soundness_policy(
        crate::bgv::profile::POLYNOMIAL_DEGREE / 2,
    )
    .expect("conjectured classical policy floor");
    assert_eq!(
        accounting["identitySoundness"]["totalDeepEvaluationPointCount"],
        serde_json::json!(3)
    );
    assert_eq!(
        accounting["lowDegreeSoundness"]["sumcheckResidualDegreeBound"],
        accounting["argumentShape"]["traceSize"]
    );
    assert!(
        accounting["zeroKnowledge"]["smudgingBudget"]["totalLeakageLog2Approximate"]
            .as_i64()
            .expect("total leakage")
            <= -50
    );
    assert_eq!(
        accounting["argumentShape"]["traceSize"],
        serde_json::json!(crate::bgv::profile::POLYNOMIAL_DEGREE / 2)
    );
    let anchor_accounting =
        super::accounting::succinct_same_secret_linkage_anchor_accounting_value()
            .expect("same-secret anchor accounting value");
    assert!(
        anchor_accounting["wasmBrowserMeasurement"]["recordedLane"].is_string(),
        "recorded measurement rows still name the lane they measured"
    );
    assert!(
        anchor_accounting["wasmBrowserMeasurement"]["openRows"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "recorded desktop evidence must keep the supported-phone rows open"
    );
}

#[test]
fn private_vss_share_accounting_discloses_family_aware_leakage() {
    // The recipient-private VSS family masks only its carry and ternary
    // opening-randomness columns; its message columns carry no consistency claim
    // and are pinned cross-field globally (carry consistency + the public
    // range-checked share pin the evaluation per recipient, and >= t honest
    // recipients pin the polynomial; see consistency_vector_count), not locally by
    // the opening rows. So its disclosed smudging leakage must be the carry-driven
    // family-aware figure (clear bound about 2^34, per-claim about 2^-57, and the
    // total about 2^-39 over the ~2^17.7 masked claims a c_priv-bounded adversary
    // observes), not the magnitude-two centered-binomial figure inherited from the
    // base accounting, and not the message-driven 2^-22 of the pre-Option-A
    // variant. This guards against the override silently reverting to either.
    let private_vss = super::accounting::succinct_private_vss_share_accounting_value()
        .expect("private VSS accounting value");
    let eval_key = super::accounting::succinct_evaluation_key_proof_accounting_value()
        .expect("eval-key accounting value");

    let private_vss_smudging = &private_vss["zeroKnowledge"]["smudgingBudget"];
    assert_eq!(
        private_vss_smudging["clearClaimBoundBits"],
        serde_json::json!(34)
    );
    assert_eq!(
        private_vss_smudging["perClaimStatisticalDistanceLog2"],
        serde_json::json!(-57)
    );
    // Honest per-adversary-view union: c_priv (3) corrupted recipients * n (10)
    // sources * 17 limb proofs * 420 masked claims ~ 2^17.7, ceil-log = 18, so the
    // total is -57 + 18 = -39 (the earlier flat 2^17 budget under-counted).
    assert_eq!(
        private_vss_smudging["claimBudgetLog2Approximate"],
        serde_json::json!(18)
    );
    assert_eq!(
        private_vss_smudging["totalLeakageLog2Approximate"],
        serde_json::json!(-39)
    );

    // The override must actually differ from the inherited magnitude-two row:
    // the eval-key family stays about 2^-67 per claim, the private-VSS family is
    // exactly 10 bits weaker (carry-driven 2^-57), still the leakage-dominating
    // family but only mildly, not the 46 bits the message-masking variant cost.
    let eval_key_per_claim =
        eval_key["zeroKnowledge"]["smudgingBudget"]["perClaimStatisticalDistanceLog2"]
            .as_i64()
            .expect("eval-key per-claim leakage");
    let private_vss_per_claim = private_vss_smudging["perClaimStatisticalDistanceLog2"]
        .as_i64()
        .expect("private VSS per-claim leakage");
    assert_eq!(eval_key_per_claim, -67);
    assert_eq!(private_vss_per_claim - eval_key_per_claim, 10);

    // The integer-binding clear bound is corrected away from the
    // inherited magnitude-two value (2 * N * (2^8 - 1) = 16711680) to the
    // carry-driven family bound, so the disclosed window margin is honest; the
    // eval-key family keeps the magnitude-two value.
    assert_ne!(
        private_vss["crossLimbConsistency"]["integerBinding"]["clearClaimBound"],
        serde_json::json!("16711680")
    );
    assert_eq!(
        eval_key["crossLimbConsistency"]["integerBinding"]["clearClaimBound"],
        serde_json::json!("16711680")
    );
}

#[test]
fn target_decryption_share_accounting_discloses_lifted_aggregate_leakage() {
    let target_accounting = super::accounting::succinct_target_decryption_share_accounting_value()
        .expect("target-decryption accounting value");
    let target_accounting_hash =
        super::accounting::succinct_target_decryption_share_accounting_hash()
            .expect("target-decryption accounting hash");
    let eval_key = super::accounting::succinct_evaluation_key_proof_accounting_value()
        .expect("eval-key accounting value");

    assert_eq!(target_accounting_hash.len(), 128);
    assert_eq!(
        target_accounting["objectType"],
        serde_json::json!("SuccinctTargetDecryptionShareAccounting")
    );
    assert_eq!(
        target_accounting["proofFamily"],
        serde_json::json!("target-decryption-share")
    );
    assert!(
        target_accounting["familyRelationRows"]["aggregateOpeningRows"]
            .as_str()
            .is_some_and(|text| text.contains("lifted compact-opening coefficients")),
        "target accounting must describe the lifted aggregate-message range"
    );
    let coverage = target_accounting["familyRelationRows"]["coverage"]
        .as_str()
        .expect("target coverage row");
    assert!(
        coverage.contains("one lower-level proof for one target share"),
        "target accounting must describe proof-material share coverage"
    );
    assert!(
        coverage.contains("target-result release remains fail-closed"),
        "target accounting must keep result release outside the current proof-material claim"
    );
    assert!(
        !coverage.contains("recombination verifies"),
        "target accounting must not claim a recombination verifier while target-result release is fail-closed"
    );

    let target_smudging = &target_accounting["zeroKnowledge"]["smudgingBudget"];
    assert_eq!(
        target_smudging["clearClaimBoundBits"],
        serde_json::json!(50)
    );
    assert_eq!(
        target_smudging["maskDigitCount"],
        serde_json::json!(super::TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT)
    );
    assert_eq!(
        target_smudging["perClaimStatisticalDistanceLog2"],
        serde_json::json!(-175)
    );
    assert_eq!(
        target_smudging["aggregateMessageMaskDigitCount"],
        serde_json::json!(super::TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT)
    );
    assert_eq!(
        target_smudging["aggregateMessageClaimsPerTargetShare"],
        serde_json::json!(1_400)
    );
    assert_eq!(
        target_smudging["aggregateMessageClaimBudgetLog2Approximate"],
        serde_json::json!(14)
    );
    assert_eq!(
        target_smudging["aggregateMessageTotalLeakageLog2Approximate"],
        serde_json::json!(-161)
    );
    assert_eq!(
        target_smudging["smudgingMessageClearClaimBoundBits"],
        serde_json::json!(28)
    );
    assert_eq!(
        target_smudging["smudgingMessageMaskDigitCount"],
        serde_json::json!(super::TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT)
    );
    assert_eq!(
        target_smudging["smudgingMessageClaimsPerTargetShare"],
        serde_json::json!(13_440)
    );
    assert_eq!(
        target_smudging["smudgingMessageClaimBudgetLog2Approximate"],
        serde_json::json!(17)
    );
    assert_eq!(
        target_smudging["smudgingMessageTotalLeakageLog2Approximate"],
        serde_json::json!(-135)
    );
    assert_eq!(
        target_smudging["randomnessClearClaimBoundBits"],
        serde_json::json!(23)
    );
    assert_eq!(
        target_smudging["randomnessMaskDigitCount"],
        serde_json::json!(super::TARGET_DECRYPTION_RANDOMNESS_CLAIM_MASK_DIGIT_COUNT)
    );
    assert_eq!(
        target_smudging["randomnessClaimsPerTargetShare"],
        serde_json::json!(14_560)
    );
    assert_eq!(
        target_smudging["randomnessClaimBudgetLog2Approximate"],
        serde_json::json!(17)
    );
    assert_eq!(
        target_smudging["randomnessTotalLeakageLog2Approximate"],
        serde_json::json!(-140)
    );
    assert_eq!(
        target_smudging["claimsPerTargetShare"],
        serde_json::json!(29_400)
    );
    assert_eq!(
        target_smudging["firstProfileTargetShareCount"],
        serde_json::json!(7)
    );
    assert_eq!(
        target_smudging["claimBudgetLog2Approximate"],
        serde_json::json!(18)
    );
    assert_eq!(
        target_smudging["totalLeakageLog2Approximate"],
        serde_json::json!(-133)
    );

    assert_ne!(
        target_accounting["crossLimbConsistency"]["integerBinding"]["clearClaimBound"],
        eval_key["crossLimbConsistency"]["integerBinding"]["clearClaimBound"],
        "target accounting must not inherit the centered-binomial clear bound"
    );
    assert!(
        target_accounting["crossLimbConsistency"]["integerBinding"]["crtWindowRule"]
            .as_str()
            .is_some_and(|text| text.contains(
                "smudging-message digit and ternary opening-randomness consistency claims use a 114-digit base-3 mask and four proof fields"
            )),
        "target accounting must disclose the split CRT lift"
    );
}

#[test]
fn public_key_share_accounting_carries_family_rows() {
    let accounting = super::accounting::succinct_public_key_share_accounting_value()
        .expect("public-key share accounting");
    assert_eq!(accounting["proofFamily"], "public-key-share");
    assert_eq!(accounting["objectType"], "SuccinctPublicKeyShareAccounting");
    assert!(
        accounting["familyRelationRows"]["commonReferenceBinding"].is_string(),
        "the family rows must record the common reference binding"
    );
    assert!(
        accounting["familyRelationRows"]["singleCommitmentLinkageRationale"]
            .as_str()
            .is_some_and(|text| text.contains("limb-zero")),
        "the public-key share accounting must document why the one-commitment linkage opens limb zero"
    );
    assert!(
        accounting["familyRelationRows"]["anchorReference"]
            .as_str()
            .is_some_and(|text| text.contains("opens every Q_share constant commitment")),
        "the public-key share accounting must distinguish its narrower linkage from the same-secret anchor"
    );
    assert!(
        accounting["wasmBrowserMeasurement"]["requiredLane"].is_string(),
        "required measurement rows still name the lane that must run"
    );
}
