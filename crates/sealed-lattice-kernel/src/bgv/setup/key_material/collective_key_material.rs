use super::*;
use crate::bgv::coefficient_codec::{
    coefficient_vector_from_le_hex, coefficient_vector_hash512, coefficient_vector_le_hex,
};

const PUBLIC_KEY_COEFFICIENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/public-key-coefficient-vector-v1";

pub(in crate::bgv::setup) fn collective_public_key(
    input: &PassiveSetupInput,
    profile_hash: &str,
    backend_profile_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
) -> CanonicalResult<Value> {
    let participant_descriptors = input
        .participants
        .iter()
        .map(|participant| {
            json!({
                "trusteeIdentity": participant.trustee_identity,
                "rosterPosition": participant.roster_position,
                "recoveryEpoch": participant.recovery_epoch,
                "deviceEpoch": participant.device_epoch,
            })
        })
        .collect::<Vec<_>>();
    let participant_identities = input
        .participants
        .iter()
        .map(|participant| participant.trustee_identity.clone())
        .collect::<Vec<_>>();
    let coefficient_material = collective_public_key_coefficient_material(
        &input.setup_seed_hash,
        &input.private_setup_seed_hash,
        public_common_random_polynomial_root,
        public_key_share_roots,
        participant_descriptors,
        &participant_identities,
    )?;
    let collective_public_key_coefficient_root =
        collective_public_key_coefficient_root(&coefficient_material)?;
    let record_without_roots = json!({
        "objectType": "BgvCollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "ceremonyId": input.ceremony_id,
        "manifestHash": input.manifest_hash,
        "rosterHash": input.roster_hash,
        "profileHash": profile_hash,
        "backendProfileHash": backend_profile_hash,
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "aggregationRule": "coefficient-wise-public-key-share-sum-with-shared-crp",
        "publicKeyComponentModel": DECRYPTABLE_PUBLIC_KEY_COMPONENT_MODEL,
        "publicKeyCoefficientMaterialBinding": "public-coefficients-bound-in-setup-package-with-private-share-derivation-unexported",
        "participantCount": public_key_share_roots.len(),
    });
    let collective_public_key_root =
        derive_protocol_hash("CollectivePublicKeyRoot", &record_without_roots)?;
    let bgv_public_key_root = derive_protocol_hash(
        "BGVPublicKeyRoot",
        &json!({
            "collectivePublicKeyRoot": collective_public_key_root,
            "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
            "profileHash": profile_hash,
            "backendProfileHash": backend_profile_hash,
            "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        }),
    )?;

    Ok(json!({
        "record": record_without_roots,
        "coefficientMaterial": coefficient_material,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "collectivePublicKeyRoot": collective_public_key_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
    }))
}

pub(in crate::bgv::setup) fn collective_public_key_coefficients_by_modulus_from_setup_package(
    setup_package: &Value,
) -> CanonicalResult<Vec<CollectivePublicKeyCoefficients>> {
    let coefficient_tables = array_at_path(
        setup_package,
        &[
            "collectivePublicKey",
            "coefficientMaterial",
            "coefficientTables",
        ],
    )?;
    if coefficient_tables.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key coefficient table count does not match the selected data basis",
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        coefficient_tables
            .par_iter()
            .enumerate()
            .map(|(modulus_index, table)| {
                collective_public_key_coefficients_from_table(modulus_index, table)
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        coefficient_tables
            .iter()
            .enumerate()
            .map(|(modulus_index, table)| {
                collective_public_key_coefficients_from_table(modulus_index, table)
            })
            .collect()
    }
}

pub(in crate::bgv::setup) fn collective_public_key_coefficients_from_table(
    modulus_index: usize,
    table: &Value,
) -> CanonicalResult<CollectivePublicKeyCoefficients> {
    let modulus = unsigned_at_path(table, &["modulus"])?;
    if modulus != DATA_PRIMES[modulus_index] {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key coefficient table modulus does not match the selected data basis",
        ));
    }
    let component_zero_coefficients =
        read_public_key_coefficient_vector(table, "componentZeroCoefficients")?;
    let component_one_coefficients =
        read_public_key_coefficient_vector(table, "componentOneCoefficients")?;
    compare_hash_at_path(
        table,
        &["componentZeroCoefficientHash512"],
        &coefficient_vector_hash512(
            &component_zero_coefficients,
            PUBLIC_KEY_COEFFICIENT_VECTOR_HASH_DOMAIN,
        ),
        "collective public key component-zero coefficient hash",
    )?;
    compare_hash_at_path(
        table,
        &["componentOneCoefficientHash512"],
        &coefficient_vector_hash512(
            &component_one_coefficients,
            PUBLIC_KEY_COEFFICIENT_VECTOR_HASH_DOMAIN,
        ),
        "collective public key component-one coefficient hash",
    )?;

    Ok(CollectivePublicKeyCoefficients {
        component_zero_coefficients,
        component_one_coefficients,
    })
}

pub(in crate::bgv::setup) fn collective_public_key_coefficient_root(
    coefficient_material: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash("BGVPublicKeyRoot", coefficient_material)
}

pub(in crate::bgv::setup) fn collective_public_key_coefficient_material(
    setup_seed_hash: &str,
    private_setup_seed_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
    participant_descriptors: Vec<Value>,
    participant_identities: &[String],
) -> CanonicalResult<Value> {
    let (collective_secret_coefficients, collective_error_coefficients) =
        collective_signed_secret_and_error_coefficients(
            private_setup_seed_hash,
            participant_identities,
        );
    #[cfg(not(target_arch = "wasm32"))]
    let coefficient_tables = DATA_PRIMES
        .par_iter()
        .copied()
        .map(|modulus| {
            collective_public_key_coefficient_table(
                setup_seed_hash,
                &collective_secret_coefficients,
                &collective_error_coefficients,
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let coefficient_tables = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            collective_public_key_coefficient_table(
                setup_seed_hash,
                &collective_secret_coefficients,
                &collective_error_coefficients,
                modulus,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(not(target_arch = "wasm32"))]
    let modulus_summaries = coefficient_tables
        .par_iter()
        .map(|table| {
            collective_public_key_coefficient_derivation_summary(
                setup_seed_hash,
                public_common_random_polynomial_root,
                public_key_share_roots,
                participant_identities,
                table,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let modulus_summaries = coefficient_tables
        .iter()
        .map(|table| {
            collective_public_key_coefficient_derivation_summary(
                setup_seed_hash,
                public_common_random_polynomial_root,
                public_key_share_roots,
                participant_identities,
                table,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": "BgvCollectivePublicKeyCoefficientMaterial",
        "objectVersion": 1,
        "setupProfileId": PASSIVE_SETUP_PROFILE_ID,
        "basisId": BgvBasisKind::Data.basis_id(),
        "level": DATA_PRIMES.len() - 1,
        "coefficientCount": POLYNOMIAL_DEGREE,
        "componentModel": DECRYPTABLE_PUBLIC_KEY_COMPONENT_MODEL,
        "componentDerivation": "public-coefficients-generated-from-private-setup-witness-and-bound-in-setup-package",
        "fullCoefficientExpansionOwner": "passive setup package public key material",
        "publicCommonRandomPolynomialRoot": public_common_random_polynomial_root,
        "publicKeyShareRoots": public_key_share_roots,
        "participantCount": participant_identities.len(),
        "participants": participant_descriptors,
        "modulusSummaries": modulus_summaries,
        "coefficientTables": coefficient_tables,
    }))
}

pub(in crate::bgv::setup) fn collective_public_key_coefficient_table(
    setup_seed_hash: &str,
    collective_secret_coefficients: &[i64],
    collective_error_coefficients: &[i64],
    modulus: u64,
) -> CanonicalResult<Value> {
    let coefficients = collective_public_key_coefficients_from_signed(
        setup_seed_hash,
        collective_secret_coefficients,
        collective_error_coefficients,
        modulus,
    )?;

    Ok(json!({
        "modulus": modulus,
        "componentZeroCoefficientHash512": coefficient_vector_hash512(
            &coefficients.component_zero_coefficients,
            PUBLIC_KEY_COEFFICIENT_VECTOR_HASH_DOMAIN,
        ),
        "componentOneCoefficientHash512": coefficient_vector_hash512(
            &coefficients.component_one_coefficients,
            PUBLIC_KEY_COEFFICIENT_VECTOR_HASH_DOMAIN,
        ),
        "componentZeroCoefficientsLeHex": coefficient_vector_le_hex(&coefficients.component_zero_coefficients),
        "componentOneCoefficientsLeHex": coefficient_vector_le_hex(&coefficients.component_one_coefficients),
        "coefficientByteLength": POLYNOMIAL_DEGREE * 8,
    }))
}

pub(in crate::bgv::setup) fn collective_public_key_coefficient_derivation_summary(
    setup_seed_hash: &str,
    public_common_random_polynomial_root: &str,
    public_key_share_roots: &[String],
    participant_identities: &[String],
    coefficient_table: &Value,
) -> CanonicalResult<Value> {
    let modulus = unsigned_at_path(coefficient_table, &["modulus"])?;
    let modulus_bytes = modulus.to_le_bytes();
    let participant_count_bytes = (participant_identities.len() as u64).to_le_bytes();
    let public_key_share_root_count_bytes = (public_key_share_roots.len() as u64).to_le_bytes();
    let component_zero_derivation_hash = hash512_hex(
        "sealed-lattice-bgv-rns/collective-public-key-coefficient-derivation-v1",
        &[
            b"component-zero",
            setup_seed_hash.as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
            &modulus_bytes,
            &participant_count_bytes,
            &public_key_share_root_count_bytes,
        ],
    );
    let component_one_derivation_hash = hash512_hex(
        "sealed-lattice-bgv-rns/collective-public-key-coefficient-derivation-v1",
        &[
            b"component-one",
            setup_seed_hash.as_bytes(),
            public_common_random_polynomial_root.as_bytes(),
            &modulus_bytes,
            &participant_count_bytes,
            &public_key_share_root_count_bytes,
        ],
    );
    let sampled_component_one_coefficients =
        sample_public_residues(setup_seed_hash, "public-common-random-polynomial", modulus);
    let sampled_component_zero_derivation_residues = sample_public_residues(
        setup_seed_hash,
        "collective-public-key-component-zero-derivation-diagnostic",
        modulus,
    );

    Ok(json!({
        "modulus": modulus,
        "componentZeroCoefficientDerivationHash512": component_zero_derivation_hash,
        "componentOneCoefficientDerivationHash512": component_one_derivation_hash,
        "sampledComponentZeroDerivationResidues": sampled_component_zero_derivation_residues,
        "sampledComponentOneCoefficients": sampled_component_one_coefficients,
        "componentZeroCoefficientHash512": string_at_path(
            coefficient_table,
            &["componentZeroCoefficientHash512"],
        )?,
        "componentOneCoefficientHash512": string_at_path(
            coefficient_table,
            &["componentOneCoefficientHash512"],
        )?,
    }))
}

pub(super) fn read_public_key_coefficient_vector(
    table: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<u64>> {
    let hex_field_name = match field_name {
        "componentZeroCoefficients" => "componentZeroCoefficientsLeHex",
        "componentOneCoefficients" => "componentOneCoefficientsLeHex",
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "unknown collective public key coefficient vector field",
            ));
        }
    };
    coefficient_vector_from_le_hex(
        string_at_path(table, &[hex_field_name])?,
        POLYNOMIAL_DEGREE,
        "collective public key coefficient vector width does not match the selected BGV profile",
    )
}

pub(in crate::bgv::setup) fn collective_signed_secret_and_error_coefficients(
    private_setup_seed_hash: &str,
    participant_identities: &[String],
) -> (Vec<i64>, Vec<i64>) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let coefficient_pairs = (0..POLYNOMIAL_DEGREE)
            .into_par_iter()
            .map(|coefficient_index| {
                collective_signed_secret_and_error_coefficient_pair(
                    private_setup_seed_hash,
                    participant_identities,
                    coefficient_index,
                )
            })
            .collect::<Vec<_>>();

        coefficient_pairs.into_iter().unzip()
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut collective_secret_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
        let mut collective_error_coefficients = vec![0_i64; POLYNOMIAL_DEGREE];
        for participant_identity in participant_identities {
            for coefficient_index in 0..POLYNOMIAL_DEGREE {
                collective_secret_coefficients[coefficient_index] +=
                    bounded_collective_secret_share_coefficient(
                        private_setup_seed_hash,
                        participant_identities,
                        participant_identity,
                        coefficient_index,
                    )
                    .expect("participant identity is drawn from the owner schedule");
                collective_error_coefficients[coefficient_index] +=
                    bounded_collective_error_share_coefficient(
                        private_setup_seed_hash,
                        participant_identities,
                        participant_identity,
                        coefficient_index,
                    )
                    .expect("participant identity is drawn from the owner schedule");
            }
        }

        (
            collective_secret_coefficients,
            collective_error_coefficients,
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn collective_signed_secret_and_error_coefficient_pair(
    private_setup_seed_hash: &str,
    participant_identities: &[String],
    coefficient_index: usize,
) -> (i64, i64) {
    let mut collective_secret_coefficient = 0_i64;
    let mut collective_error_coefficient = 0_i64;
    for participant_identity in participant_identities {
        collective_secret_coefficient += bounded_collective_secret_share_coefficient(
            private_setup_seed_hash,
            participant_identities,
            participant_identity,
            coefficient_index,
        )
        .expect("participant identity is drawn from the owner schedule");
        collective_error_coefficient += bounded_collective_error_share_coefficient(
            private_setup_seed_hash,
            participant_identities,
            participant_identity,
            coefficient_index,
        )
        .expect("participant identity is drawn from the owner schedule");
    }

    (collective_secret_coefficient, collective_error_coefficient)
}

pub(in crate::bgv::setup) fn collective_public_key_coefficients_from_signed(
    setup_seed_hash: &str,
    collective_secret_coefficients: &[i64],
    collective_error_coefficients: &[i64],
    modulus: u64,
) -> CanonicalResult<CollectivePublicKeyCoefficients> {
    if collective_secret_coefficients.len() != POLYNOMIAL_DEGREE
        || collective_error_coefficients.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "collective public key signed coefficient width is invalid",
        ));
    }
    let collective_secret_residues = collective_secret_coefficients
        .iter()
        .map(|coefficient| signed_to_modulus_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let collective_scaled_error_residues = collective_error_coefficients
        .iter()
        .map(|coefficient| signed_to_plaintext_scaled_residue(*coefficient, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let component_one_coefficients =
        dense_public_residues(setup_seed_hash, "public-common-random-polynomial", modulus);
    let public_sample_secret_product = negacyclic_product_mod(
        &component_one_coefficients,
        &collective_secret_residues,
        modulus,
    )?;
    let component_zero_coefficients = collective_scaled_error_residues
        .iter()
        .zip(public_sample_secret_product.iter())
        .map(|(scaled_error_residue, product_residue)| {
            sub_mod(*scaled_error_residue, *product_residue, modulus)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(CollectivePublicKeyCoefficients {
        component_zero_coefficients,
        component_one_coefficients,
    })
}
