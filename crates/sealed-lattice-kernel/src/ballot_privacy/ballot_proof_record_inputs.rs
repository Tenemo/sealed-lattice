use super::*;

pub struct BallotProofRecordGenerationInput<'a> {
    pub statement: Option<&'a Value>,
    pub linear_statement: Option<&'a Value>,
    pub parameter_set: Option<&'a Value>,
    pub proof_encoding: Option<&'a Value>,
    pub public_randomness_hex: Option<&'a str>,
    pub component_bundle_statement: Option<&'a Value>,
    pub component_proof_inputs: Option<&'a Value>,
    pub secret_state: Option<&'a Value>,
    pub prover_randomness_hex: Option<&'a str>,
    pub component_prover_randomness_hexes: Option<&'a Value>,
    pub component_secret_states: Option<&'a Value>,
}

pub(crate) struct RequiredBallotProofRecordGenerationInput<'a> {
    pub(crate) statement: &'a Value,
    pub(crate) linear_statement: &'a Value,
    pub(crate) parameter_set: &'a Value,
    pub(crate) proof_encoding: &'a Value,
    pub(crate) public_randomness_hex: &'a str,
    pub(crate) component_bundle_statement: &'a Value,
    pub(crate) component_proof_inputs: &'a Value,
    pub(crate) secret_state: &'a Value,
    pub(crate) prover_randomness_hex: &'a str,
    pub(crate) component_prover_randomness_hexes: &'a Value,
    pub(crate) component_secret_states: Option<&'a Value>,
}

impl<'a> RequiredBallotProofRecordGenerationInput<'a> {
    pub(crate) fn parse(
        input: BallotProofRecordGenerationInput<'a>,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            statement: input.statement.ok_or_else(|| {
                invalid_preflight("statement is required for ballot proof record generation")
            })?,
            linear_statement: input.linear_statement.ok_or_else(|| {
                invalid_preflight(
                    "linearStatement is required for ballot proof record generation",
                )
            })?,
            parameter_set: input.parameter_set.ok_or_else(|| {
                invalid_preflight("parameterSet is required for ballot proof record generation")
            })?,
            proof_encoding: input.proof_encoding.ok_or_else(|| {
                invalid_preflight("proofEncoding is required for ballot proof record generation")
            })?,
            public_randomness_hex: input.public_randomness_hex.ok_or_else(|| {
                invalid_preflight(
                    "publicRandomnessHex is required for ballot proof record generation",
                )
            })?,
            component_bundle_statement: input.component_bundle_statement.ok_or_else(|| {
                invalid_preflight(
                    "componentBundleStatement is required for ballot proof record generation",
                )
            })?,
            component_proof_inputs: input.component_proof_inputs.ok_or_else(|| {
                invalid_preflight(
                    "componentProofInputs is required for ballot proof record generation",
                )
            })?,
            secret_state: input.secret_state.ok_or_else(|| {
                invalid_preflight("secretState is required for ballot proof record generation")
            })?,
            prover_randomness_hex: input.prover_randomness_hex.ok_or_else(|| {
                invalid_preflight(
                    "proverRandomnessHex is required for ballot proof record generation",
                )
            })?,
            component_prover_randomness_hexes: input
                .component_prover_randomness_hexes
                .ok_or_else(|| {
                    invalid_preflight(
                        "componentProverRandomnessHexes is required for ballot proof record generation",
                    )
                })?,
            component_secret_states: input.component_secret_states,
        })
    }

    pub(crate) fn validate_full_projection_coverage(&self) -> crate::encoding::CanonicalResult<()> {
        if string_field(self.linear_statement, "projectionCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        {
            return Err(invalid_preflight(
                "ballot proof record generation requires a full encoded-score linear statement",
            ));
        }
        if string_field(self.component_bundle_statement, "bundleCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        {
            return Err(invalid_preflight(
                "ballot proof record generation requires a full component bundle statement",
            ));
        }

        Ok(())
    }

    pub(crate) fn component_inputs_by_id(
        &self,
    ) -> crate::encoding::CanonicalResult<BTreeMap<&'a str, &'a Value>> {
        let component_inputs_array = self.component_proof_inputs.as_array().ok_or_else(|| {
            invalid_preflight("componentProofInputs must be an array for ballot proof generation")
        })?;
        if component_inputs_array.len() != REQUIRED_BALLOT_PROOF_COMPONENT_IDS.len() {
            return Err(invalid_preflight(
                "componentProofInputs must contain exactly the required ballot proof components",
            ));
        }

        let mut component_inputs_by_id = BTreeMap::new();
        for component_input in component_inputs_array {
            let component_id = string_field(component_input, "componentId")
                .ok_or_else(|| invalid_preflight("component proof input is missing componentId"))?;
            if object_map(component_input)
                .is_some_and(|object| object.contains_key("proofBytesHex"))
            {
                return Err(invalid_preflight(
                    "component proof inputs for generation must not pre-supply proofBytesHex",
                ));
            }
            if component_inputs_by_id
                .insert(component_id, component_input)
                .is_some()
            {
                return Err(invalid_preflight(
                    "component proof inputs contain a duplicate component",
                ));
            }
        }

        Ok(component_inputs_by_id)
    }
}
