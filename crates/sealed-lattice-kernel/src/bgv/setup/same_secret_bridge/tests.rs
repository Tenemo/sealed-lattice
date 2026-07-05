    use serde_json::{Value, json};

    use super::{
        SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        same_secret_anchor_proof_material_root, setup_proof_material_transport_hashes,
        value_without_root_field, verify_vss_same_secret_bridge_proof_material_set_request,
        verify_vss_same_secret_bridge_statement_set_request,
    };
    use crate::{
        bgv::parameters::DATA_PRIMES, encoding::CanonicalResult,
        hashing::derive_canonical_object_hash,
    };

    #[test]
    fn same_secret_bridge_statement_set_verifies_bound_roots() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let verification = verify_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyVssSameSecretBridgeStatementSet",
            "statementSet": statement_set,
            "sameSecretConsistency": same_secret_consistency,
            "sameSecretProofs": same_secret_proofs,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyVssSameSecretBridgeStatementSet"
        );
        assert_eq!(
            verification["sameSecretBridgeStatementSetRoot"],
            statement_set["sameSecretBridgeStatementSetRoot"]
        );
        assert_eq!(verification["participantCount"], json!(2_u64));
        assert_eq!(verification["targetRnsLimbCount"], json!(2_u64));
        assert_eq!(
            verification["vssPublicCommitmentEncoding"],
            "sealed-lattice-vss-public-commitment-binary-v1"
        );

        let (mut wrong_target_basis_statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        wrong_target_basis_statement_set["targetBasisHash"] = json!("7".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": wrong_target_basis_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "same-secret bridge statement sets must bind the canonical target basis hash"
        );

        let (mut tampered_statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        tampered_statement_set["statementRecords"][1]["targetConstantCoefficientCommitmentRoots"]
            [0]["coefficientCommitmentRoot"] = json!("c".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": tampered_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "tampered same-secret bridge target constant root must reject"
        );

        let (mut unsupported_convention_statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        unsupported_convention_statement_set["signedRepresentativeConvention"] =
            json!("unsupported bridge signed representative convention");
        unsupported_convention_statement_set["sameSecretBridgeStatementSetRoot"] = json!(
            derive_canonical_object_hash(&unsupported_convention_statement_set,)?
        );
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": unsupported_convention_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "unsupported signed-representative convention must reject"
        );

        Ok(())
    }

    #[test]
    fn same_secret_bridge_evidence_sets_bind_same_secret_roots() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let verification = verify_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyVssSameSecretBridgeStatementSet",
            "statementSet": statement_set.clone(),
            "sameSecretConsistency": same_secret_consistency.clone(),
            "sameSecretProofs": same_secret_proofs.clone(),
        }))?;
        assert_eq!(verification["ok"], json!(true));

        let mut forged_statement_set = statement_set;
        forged_statement_set["statementRecords"][0]["sameSecretProofRoot"] = json!("0".repeat(128));
        rebind_bridge_statement_root(&mut forged_statement_set["statementRecords"][0])?;
        rebind_bridge_statement_set_root(&mut forged_statement_set)?;
        let missing_evidence_error = verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": forged_statement_set.clone(),
        }))
        .expect_err("same-secret bridge statement verification must require evidence");
        assert!(
            missing_evidence_error
                .to_string()
                .contains("requires both sameSecretConsistency and sameSecretProofs"),
            "missing same-secret bridge evidence should report the required evidence sets: {missing_evidence_error}"
        );
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": forged_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "evidence-backed verification must reject a bridge proof root that is absent from the proof set"
        );

        Ok(())
    }

    #[test]
    fn same_secret_bridge_checks_transported_same_secret_proof_material() -> CanonicalResult<()> {
        let (mut statement_set, same_secret_consistency, mut same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let transported_same_secret_proof_material =
            move_same_secret_proof_bytes_to_transport(&mut same_secret_proofs)?;
        rebind_bridge_statement_set_to_same_secret_proofs(&mut statement_set, &same_secret_proofs)?;

        let verification = verify_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyVssSameSecretBridgeStatementSet",
            "statementSet": statement_set.clone(),
            "sameSecretConsistency": same_secret_consistency.clone(),
            "sameSecretProofs": same_secret_proofs.clone(),
            "transportedSameSecretProofMaterial": transported_same_secret_proof_material.clone(),
        }))?;
        assert_eq!(verification["ok"], json!(true));

        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
            }))
            .is_err(),
            "transported same-secret proof records must require transported proof material"
        );

        let mut tampered_material = transported_same_secret_proof_material;
        tampered_material["proofMaterials"][0]["chunks"][0]["bytesBase64"] = json!("/w==");
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
                "transportedSameSecretProofMaterial": tampered_material,
            }))
            .is_err(),
            "transported same-secret proof material must bind supplied chunks"
        );

        Ok(())
    }

    #[test]
    fn same_secret_bridge_proof_material_set_rejects_unbound_material() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let proof_material_set =
            same_secret_bridge_proof_material_set(&statement_set, ["aa", "bb"])?;

        assert!(
            verify_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
                "proofMaterialSet": proof_material_set.clone(),
            }))
            .is_err(),
            "proof material must reject proof bytes that do not verify against reconstructed statements"
        );

        let mut tampered_proof_material_set = proof_material_set.clone();
        tampered_proof_material_set["proofRecords"][0]["proofBytesHash"] = json!("0".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
                "proofMaterialSet": tampered_proof_material_set,
            }))
            .is_err(),
            "proof material must reject a proofBytesHash that no longer matches proofBytesBase64"
        );

        let mut wrong_statement_root_material_set = proof_material_set;
        wrong_statement_root_material_set["proofRecords"][1]["sameSecretBridgeStatementRoot"] =
            json!("0".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
                "proofMaterialSet": wrong_statement_root_material_set,
            }))
            .is_err(),
            "proof material must bind each proof record to its bridge statement root"
        );

        Ok(())
    }

    fn same_secret_bridge_proof_material_set(
        statement_set: &Value,
        proof_bytes_hex_values: [&str; 2],
    ) -> CanonicalResult<Value> {
        let statement_records = statement_set["statementRecords"]
            .as_array()
            .expect("bridge statement records");
        let proof_records = statement_records
            .iter()
            .zip(proof_bytes_hex_values)
            .map(
                |(statement_record, proof_bytes_hex)| {
                    let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
                    let proof_record_without_root = json!({
                        "objectType": "VssSameSecretBridgeProofRecord",
                        "objectVersion": 1,
                        "proofFamily": super::SAME_SECRET_BRIDGE_PROOF_FAMILY,
                        "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
                        "proofBytesHash": crate::hashing::hash512_hex(
                            super::SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
                            &[&proof_bytes],
                        ),
                        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
                    });
                    let mut proof_record = proof_record_without_root;
                    proof_record["proofRecordRoot"] = json!(derive_canonical_object_hash(&proof_record,
                    )?);
                    Ok(proof_record)
                },
            )
            .collect::<CanonicalResult<Vec<_>>>()?;
        let proof_material_set_without_root = json!({
            "objectType": "VssSameSecretBridgeProofMaterialSet",
            "objectVersion": 1,
            "proofFamily": super::SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "ceremonyId": statement_set["ceremonyId"],
            "manifestHash": statement_set["manifestHash"],
            "rosterHash": statement_set["rosterHash"],
            "setupParametersHash": statement_set["setupParametersHash"],
            "setupEpoch": statement_set["setupEpoch"],
            "targetBasisHash": statement_set["targetBasisHash"],
            "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
            "ringDegree": statement_set["ringDegree"],
            "participantCount": statement_set["participantCount"],
            "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
            "thresholdDegree": statement_set["thresholdDegree"],
            "coefficientCommitmentRoot": statement_set["coefficientCommitmentRoot"],
            "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
            "sameSecretBridgeStatementSetRoot": statement_set["sameSecretBridgeStatementSetRoot"],
            "proofRecords": proof_records,
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] =
            json!(derive_canonical_object_hash(&proof_material_set,)?);

        Ok(proof_material_set)
    }

    fn same_secret_bridge_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let target_basis_hash = crate::bgv::evaluator::top_k::canonical_target_basis_hash()?;
        let target_constant_records = (0..2_usize)
            .map(|rns_limb_index| {
                let rns_prime = DATA_PRIMES[rns_limb_index];
                let commitment_body = same_secret_bridge_target_commitment_body(
                    trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                )?;
                let coefficient_commitment_root = derive_canonical_object_hash(&commitment_body)?;
                Ok((
                    json!({
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": rns_prime,
                        "shamirCoefficientIndex": 0,
                        "coefficientCommitmentRoot": coefficient_commitment_root,
                    }),
                    json!({
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": rns_prime,
                        "shamirCoefficientIndex": 0,
                        "commitment": commitment_body,
                    }),
                ))
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let target_constant_coefficient_commitment_roots = target_constant_records
            .iter()
            .map(|(root, _commitment)| root.clone())
            .collect::<Vec<_>>();
        let target_constant_coefficient_commitments = target_constant_records
            .iter()
            .map(|(_root, commitment)| commitment.clone())
            .collect::<Vec<_>>();
        let statement_without_root = json!({
            "objectType": "VssSameSecretBridgeStatement",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": "8".repeat(128),
            "ringDegree": 8,
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretStatementRoot": if trustee_roster_position == 0 {
                "a".repeat(128)
            } else {
                "b".repeat(128)
            },
            "sameSecretProofRoot": if trustee_roster_position == 0 {
                "c".repeat(128)
            } else {
                "d".repeat(128)
            },
            "trusteeSecretCommitmentRoot": if trustee_roster_position == 0 {
                "e".repeat(128)
            } else {
                "f".repeat(128)
            },
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "dataBasisRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "vssPublicCommitmentEncoding": "sealed-lattice-vss-public-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "targetConstantCoefficientCommitmentRoots": target_constant_coefficient_commitment_roots,
            "targetConstantCoefficientCommitments": target_constant_coefficient_commitments,
            "relation": "target-basis constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof",
        });
        let mut statement = statement_without_root;
        statement["sameSecretBridgeStatementRoot"] =
            json!(derive_canonical_object_hash(&statement,)?);

        Ok(statement)
    }

    fn same_secret_bridge_target_commitment_body(
        trustee_roster_position: usize,
        rns_limb_index: usize,
        rns_prime: u64,
    ) -> CanonicalResult<Value> {
        let coordinate_count =
            crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT;
        let commitment_limbs = (0..3_usize)
            .map(|commitment_modulus_index| {
                let modulus = DATA_PRIMES[commitment_modulus_index];
                let coordinates = (0..coordinate_count)
                    .map(|coordinate_index| {
                        ((trustee_roster_position as u64 + 1) * 17
                            + (rns_limb_index as u64 + 1) * 19
                            + (commitment_modulus_index as u64 + 1) * 23
                            + coordinate_index as u64)
                            % modulus
                    })
                    .collect::<Vec<_>>();
                json!({
                    "commitmentModulusIndex": commitment_modulus_index,
                    "modulus": modulus,
                    "coordinates": coordinates,
                })
            })
            .collect::<Vec<_>>();

        Ok(json!({
            "objectType": "VssPublicCommitment",
            "objectVersion": 1,
            "commitmentRole": "coefficient",
            "commitmentContextHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "ringDegree": 8,
            "outputCoordinateCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
            "randomnessColumnCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
            "commitmentLimbs": commitment_limbs,
        }))
    }

    fn same_secret_bridge_statement_set_with_evidence() -> CanonicalResult<(Value, Value, Value)> {
        let target_basis_hash = crate::bgv::evaluator::top_k::canonical_target_basis_hash()?;
        let same_secret_consistency = same_secret_consistency_statement_set()?;
        let same_secret_proofs = same_secret_proof_set(&same_secret_consistency)?;
        let mut statement_records = Vec::new();
        for trustee_roster_position in 0..2_usize {
            statement_records.push(same_secret_bridge_statement_record_from_evidence(
                trustee_roster_position,
                &same_secret_consistency["statementRecords"][trustee_roster_position],
                &same_secret_proofs["proofRecords"][trustee_roster_position],
            )?);
        }
        let statement_set_without_root = json!({
            "objectType": "VssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": "8".repeat(128),
            "ringDegree": 8,
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 4,
            "coefficientCommitmentRoot": "9".repeat(128),
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": same_secret_proofs["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "vssPublicCommitmentEncoding": "sealed-lattice-vss-public-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "statementRecords": statement_records,
        });
        let mut statement_set = statement_set_without_root;
        statement_set["sameSecretBridgeStatementSetRoot"] =
            json!(derive_canonical_object_hash(&statement_set,)?);

        Ok((statement_set, same_secret_consistency, same_secret_proofs))
    }

    fn same_secret_consistency_statement_set() -> CanonicalResult<Value> {
        let statement_records = (0..2_usize)
            .map(same_secret_consistency_statement_record)
            .collect::<CanonicalResult<Vec<_>>>()?;
        let trustee_secret_commitment_roots = statement_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, statement_record)| {
                json!({
                    "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
                    "trusteeRosterPosition": trustee_roster_position,
                    "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
                })
            })
            .collect::<Vec<_>>();
        let statement_set_without_root = json!({
            "objectType": "SameSecretConsistencyStatementSet",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 2,
            "rnsLimbCount": 2,
            "thresholdDegree": 4,
            "vssCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "trusteeSecretCommitmentRoots": trustee_secret_commitment_roots,
            "statementRecords": statement_records,
        });
        let mut statement_set = statement_set_without_root;
        statement_set["sameSecretConsistencyRoot"] =
            json!(derive_canonical_object_hash(&statement_set,)?);

        Ok(statement_set)
    }

    fn same_secret_consistency_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let statement_without_root = json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": if trustee_roster_position == 0 {
                "a".repeat(128)
            } else {
                "b".repeat(128)
            },
            "constantCoefficientCommitmentRoots": [],
            "trusteeSecretCommitmentRoot": if trustee_roster_position == 0 {
                "e".repeat(128)
            } else {
                "f".repeat(128)
            },
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share"
            ],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        let mut statement = statement_without_root;
        statement["sameSecretStatementRoot"] = json!(derive_canonical_object_hash(&statement,)?);

        Ok(statement)
    }

    fn same_secret_proof_set(same_secret_consistency: &Value) -> CanonicalResult<Value> {
        let proof_records = (0..2_usize)
            .map(|trustee_roster_position| {
                same_secret_proof_record(
                    trustee_roster_position,
                    &same_secret_consistency["statementRecords"][trustee_roster_position],
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let same_secret_proof_roots = proof_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, proof_record)| {
                json!({
                    "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
                    "trusteeRosterPosition": trustee_roster_position,
                    "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                })
            })
            .collect::<Vec<_>>();
        let proof_set_without_root = json!({
            "objectType": "SameSecretProofSet",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "proofAccountingHash": "d".repeat(128),
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 2,
            "rnsLimbCount": 2,
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "vssCoefficientCommitmentMaterialRoot": "e".repeat(128),
            "sameSecretProofRoots": same_secret_proof_roots,
            "proofRecords": proof_records,
        });
        let mut proof_set = proof_set_without_root;
        proof_set["sameSecretProofSetRoot"] = json!(derive_canonical_object_hash(&proof_set,)?);

        Ok(proof_set)
    }

    fn same_secret_proof_record(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
    ) -> CanonicalResult<Value> {
        let proof_record_without_root = json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "ringDegree": 8,
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": same_secret_statement["sameSecretProofFamilyBindingRoot"],
            "statementHash": if trustee_roster_position == 0 {
                "1".repeat(128)
            } else {
                "2".repeat(128)
            },
            "proofSizeBytes": 1,
            "proofBytesHash": crate::hashing::hash512_hex(
                super::SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN,
                &[&[0_u8]],
            ),
            "proofBytesHex": "00",
        });
        let mut proof_record = proof_record_without_root;
        proof_record["sameSecretProofRoot"] = json!(derive_canonical_object_hash(&proof_record,)?);

        Ok(proof_record)
    }

    fn same_secret_bridge_statement_record_from_evidence(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
        same_secret_proof: &Value,
    ) -> CanonicalResult<Value> {
        let mut statement = same_secret_bridge_statement_record(trustee_roster_position)?;
        statement["sameSecretStatementRoot"] =
            same_secret_statement["sameSecretStatementRoot"].clone();
        statement["sameSecretProofRoot"] = same_secret_proof["sameSecretProofRoot"].clone();
        statement["trusteeSecretCommitmentRoot"] =
            same_secret_statement["trusteeSecretCommitmentRoot"].clone();
        statement["sameSecretProofFamilyBindingRoot"] =
            same_secret_statement["sameSecretProofFamilyBindingRoot"].clone();
        rebind_bridge_statement_root(&mut statement)?;

        Ok(statement)
    }

    fn rebind_bridge_statement_root(statement: &mut Value) -> CanonicalResult<()> {
        statement["sameSecretBridgeStatementRoot"] =
            json!(derive_canonical_object_hash(&value_without_root_field(
                statement,
                "sameSecretBridgeStatementRoot",
                "same-secret bridge statement",
            )?,)?);

        Ok(())
    }

    fn rebind_bridge_statement_set_root(statement_set: &mut Value) -> CanonicalResult<()> {
        statement_set["sameSecretBridgeStatementSetRoot"] =
            json!(derive_canonical_object_hash(&value_without_root_field(
                statement_set,
                "sameSecretBridgeStatementSetRoot",
                "same-secret bridge statement set",
            )?,)?);

        Ok(())
    }

    fn move_same_secret_proof_bytes_to_transport(
        same_secret_proofs: &mut Value,
    ) -> CanonicalResult<Value> {
        let proof_records = same_secret_proofs["proofRecords"]
            .as_array_mut()
            .expect("same-secret proof records");
        let mut transported_proof_materials = Vec::new();
        for proof_record in proof_records.iter_mut() {
            let proof_bytes = crate::transcript_core::decode_hex(
                proof_record["proofBytesHex"]
                    .as_str()
                    .expect("embedded same-secret proof bytes"),
            )?;
            let chunks = vec![proof_bytes.clone()];
            let transport_hashes = setup_proof_material_transport_hashes(
                "same-secret-linkage-anchor",
                &chunks,
                SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            )?;
            proof_record
                .as_object_mut()
                .expect("same-secret proof record object")
                .remove("proofBytesHex");
            proof_record["proofBytesEncoding"] = json!(SETUP_PROOF_MATERIAL_ENCODING);
            proof_record["proofChunkSizeBytes"] = json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
            proof_record["proofChunkCount"] = json!(transport_hashes.chunk_hashes.len());
            proof_record["proofTotalByteLength"] = json!(transport_hashes.total_byte_length);
            proof_record["proofFullObjectHash"] = json!(transport_hashes.full_object_hash.clone());
            proof_record["proofChunkRoot"] = json!(transport_hashes.chunk_root.clone());
            proof_record["proofChunkHashes"] = json!(transport_hashes.chunk_hashes.clone());
            proof_record["proofMaterialRoot"] = json!(same_secret_anchor_proof_material_root(
                proof_record,
                &transport_hashes
            )?);
            proof_record["sameSecretProofRoot"] =
                json!(derive_canonical_object_hash(&value_without_root_field(
                    proof_record,
                    "sameSecretProofRoot",
                    "same-secret proof",
                )?,)?);

            transported_proof_materials.push(json!({
                "objectType": "SetupTransportedSameSecretProofMaterial",
                "objectVersion": 1,
                "proofFamily": "same-secret-linkage-anchor",
                "proofMaterialRoot": proof_record["proofMaterialRoot"],
                "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
                "chunkCount": transport_hashes.chunk_hashes.len(),
                "totalByteLength": transport_hashes.total_byte_length,
                "fullObjectHash": transport_hashes.full_object_hash,
                "chunkHashes": transport_hashes.chunk_hashes,
                "chunkRoot": transport_hashes.chunk_root,
                "chunks": [{
                    "chunkIndex": 0,
                    "bytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
                }],
            }));
        }

        let same_secret_proof_roots = proof_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, proof_record)| {
                json!({
                    "trusteeIdentity": proof_record["trusteeIdentity"],
                    "trusteeRosterPosition": trustee_roster_position,
                    "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                })
            })
            .collect::<Vec<_>>();
        same_secret_proofs["sameSecretProofRoots"] = json!(same_secret_proof_roots);
        same_secret_proofs["sameSecretProofSetRoot"] =
            json!(derive_canonical_object_hash(&value_without_root_field(
                same_secret_proofs,
                "sameSecretProofSetRoot",
                "same-secret proof set",
            )?,)?);

        Ok(json!({
            "objectType": "SetupTransportedSameSecretProofMaterialSet",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "proofMaterials": transported_proof_materials,
        }))
    }

    fn rebind_bridge_statement_set_to_same_secret_proofs(
        statement_set: &mut Value,
        same_secret_proofs: &Value,
    ) -> CanonicalResult<()> {
        let statement_records = statement_set["statementRecords"]
            .as_array_mut()
            .expect("same-secret bridge statement records");
        let proof_records = same_secret_proofs["proofRecords"]
            .as_array()
            .expect("same-secret proof records");
        for (statement_index, statement_record) in statement_records.iter_mut().enumerate() {
            statement_record["sameSecretProofRoot"] =
                proof_records[statement_index]["sameSecretProofRoot"].clone();
            rebind_bridge_statement_root(statement_record)?;
        }
        statement_set["sameSecretProofSetRoot"] =
            same_secret_proofs["sameSecretProofSetRoot"].clone();
        rebind_bridge_statement_set_root(statement_set)
    }
