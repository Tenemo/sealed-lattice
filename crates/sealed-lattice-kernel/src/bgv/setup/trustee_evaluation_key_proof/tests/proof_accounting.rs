#[test]
fn proof_accounting_closes_every_theorem_row_with_margin() {
    let accounting = super::accounting::succinct_evaluation_key_proof_accounting_value()
        .expect("accounting value");
    let accounting_hash = super::accounting::succinct_evaluation_key_proof_accounting_hash()
        .expect("accounting hash");
    assert_eq!(accounting_hash.len(), 128);
    for accepted_row in [
        &accounting["lowDegreeSoundness"]["accepted"],
        &accounting["identitySoundness"]["accepted"],
        &accounting["linearRelationSoundness"]["accepted"],
        &accounting["crossLimbConsistency"]["accepted"],
        &accounting["zeroKnowledge"]["smudgingBudget"]["acceptedForBoundedLeakagePrototype"],
        &accounting["fiatShamir"]["classicalRoundByRoundAccepted"],
        &accounting["sameSecretLinkage"]["accepted"],
    ] {
        assert_eq!(accepted_row, &serde_json::json!(true));
    }
    // These bounds are load-bearing: 128-bit effective soundness depends on the
    // -160 pre-union margin and a named, unproven FRI conjecture, and
    // zero-knowledge is bounded-leakage only -- do not relax them to make the
    // accounting pass.
    assert_eq!(
        accounting["lowDegreeSoundness"]["acceptedUnderNamedFriConjecture"],
        serde_json::json!(true)
    );
    assert_eq!(
        accounting["lowDegreeSoundness"]["acceptedUnderProvenFallback"],
        serde_json::json!(false)
    );
    assert_eq!(
        accounting["fiatShamir"]["qromAccepted"],
        serde_json::json!(false)
    );
    assert_eq!(
        accounting["zeroKnowledge"]["smudgingBudget"]["acceptedFor128BitZeroKnowledge"],
        serde_json::json!(false)
    );
    // Implemented facts the rows must reflect exactly, and the effective
    // soundness target the closure rests on.
    assert_eq!(
        accounting["crossLimbConsistency"]["preUnionCollisionBoundLog2"],
        serde_json::json!(-160)
    );
    assert_eq!(
        accounting["zeroKnowledge"]["maskCoversOpenings"],
        serde_json::json!(true)
    );
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
}

#[test]
fn private_vss_share_accounting_discloses_family_aware_leakage() {
    // The recipient-private VSS family masks only its carry and ternary
    // opening-randomness columns; its message columns are pinned cross-field by
    // the opening rows plus randomness consistency and carry no consistency claim.
    // So its disclosed smudging leakage must be the carry-driven family-aware
    // figure (clear bound about 2^34, per-claim about 2^-58, total about 2^-41),
    // not the magnitude-two centered-binomial figure inherited from the base
    // accounting, and not the message-driven 2^-22 of the pre-Option-A variant.
    // This guards against the override silently reverting to either.
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
        serde_json::json!(-58)
    );
    assert_eq!(
        private_vss_smudging["totalLeakageLog2Approximate"],
        serde_json::json!(-41)
    );
    assert_eq!(
        private_vss_smudging["leakageDominatingFamily"],
        serde_json::json!(true)
    );
    // Bounded-leakage prototype scope is retained and honestly paired with the
    // explicit not-128-bit-zero-knowledge flag, matching the other families; the
    // honesty is in the disclosed numbers, not in flipping the gate.
    assert_eq!(
        private_vss_smudging["acceptedForBoundedLeakagePrototype"],
        serde_json::json!(true)
    );
    assert_eq!(
        private_vss_smudging["acceptedFor128BitZeroKnowledge"],
        serde_json::json!(false)
    );

    // The override must actually differ from the inherited magnitude-two row:
    // the eval-key family stays about 2^-68 per claim, the private-VSS family is
    // exactly 10 bits weaker (carry-driven 2^-58), still the leakage-dominating
    // family but only mildly, not the 46 bits the message-masking variant cost.
    let eval_key_per_claim =
        eval_key["zeroKnowledge"]["smudgingBudget"]["perClaimStatisticalDistanceLog2"]
            .as_i64()
            .expect("eval-key per-claim leakage");
    let private_vss_per_claim = private_vss_smudging["perClaimStatisticalDistanceLog2"]
        .as_i64()
        .expect("private VSS per-claim leakage");
    assert_eq!(eval_key_per_claim, -68);
    assert_eq!(private_vss_per_claim - eval_key_per_claim, 10);

    // The two-prime integer-binding clear bound is corrected away from the
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
fn public_key_share_accounting_carries_family_rows() {
    let accounting = super::accounting::succinct_public_key_share_accounting_value()
        .expect("public-key share accounting");
    assert_eq!(accounting["proofFamily"], "public-key-share");
    assert_eq!(accounting["objectType"], "SuccinctPublicKeyShareAccounting");
    // The shared theorem rows stay accepted only in the scoped classical model.
    assert_eq!(accounting["lowDegreeSoundness"]["accepted"], true);
    assert_eq!(
        accounting["lowDegreeSoundness"]["acceptedUnderNamedFriConjecture"],
        true
    );
    assert_eq!(
        accounting["fiatShamir"]["classicalRoundByRoundAccepted"],
        true
    );
    assert_eq!(accounting["fiatShamir"]["qromAccepted"], false);
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
}
