use super::*;

pub(super) fn vanishing_polynomial<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    trace_size: usize,
) -> Vec<[u64; LIMB_COUNT]> {
    let mut vanishing = vec![parameters.zero(); trace_size + 1];
    vanishing[0] = parameters.negate(&parameters.one());
    vanishing[trace_size] = parameters.one();
    vanishing
}

pub(super) fn masked_coefficients<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    coefficients: &[[u64; LIMB_COUNT]],
    trace_size: usize,
    mask_degree: usize,
    private_randomness: &mut PrivateProofRandomness,
) -> Vec<[u64; LIMB_COUNT]> {
    if mask_degree == 0 {
        return coefficients.to_vec();
    }
    let mut mask = Vec::with_capacity(mask_degree + 1);
    for _ in 0..=mask_degree {
        mask.push(private_randomness.next_field_element(parameters));
    }
    let mask_multiple = polynomial::multiply_via_ntt(
        parameters,
        &mask,
        &vanishing_polynomial(parameters, trace_size),
    );
    polynomial::add(parameters, coefficients, &mask_multiple)
}

// A deterministic regeneration plan for every committed column. The streamed
// prover never holds all column coefficient vectors or codewords at once: each
// column is a pure function of the witness, the logUp challenge, and a
// per-column private-randomness snapshot, so commit, sumcheck/support, combination,
// and opening passes each rebuild exactly the columns they are consuming, and a
// regenerated column is bit-identical every time. Constructing the plan (and
// later setting the logUp challenge) advances the caller's stream by exactly the
// mask draws reserved for each column.
pub(super) struct KeyColumnPlan<'a, const LIMB_COUNT: usize> {
    ring_degree: usize,
    mask_degree: usize,
    secret: &'a [i64],
    digits: &'a [DigitWitness],
    // The recombined component material `B_j` per digit, committed as one masked
    // material column per digit and folded into the sumcheck's left-hand side.
    // Borrowed per-digit slices, never a full clone, so the streamed prover keeps
    // its bounded footprint. The prover normally binds the public material here;
    // a test override can substitute a mismatched column to exercise the
    // relation binding in isolation.
    component_b: Vec<&'a [[u64; LIMB_COUNT]]>,
    multiplicity_values: Vec<Vec<[u64; LIMB_COUNT]>>,
    base_mask_randomness: Vec<PrivateProofRandomness>,
    material_mask_randomness: Vec<PrivateProofRandomness>,
    lookup_challenge: Option<[u64; LIMB_COUNT]>,
    aux_mask_randomness: Vec<PrivateProofRandomness>,
    linkage: Option<LinkagePlanData>,
}

// The linkage plan data: the derived witness value columns and the layout,
// retained raw (small vectors, never coset codewords).
pub(super) struct LinkagePlanData {
    pub(super) layout: linkage::LinkageLayout,
    pub(super) values: linkage::LinkageWitnessValues,
}

impl<'a, const LIMB_COUNT: usize> KeyColumnPlan<'a, LIMB_COUNT> {
    pub(super) fn new(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        ring_degree: usize,
        mask_degree: usize,
        secret: &'a [i64],
        digits: &'a [DigitWitness],
        component_b: Vec<&'a [[u64; LIMB_COUNT]]>,
        linkage_inputs: Option<(&linkage::LinkageStatement<'_>, &linkage::LinkageWitness<'_>)>,
        private_randomness: &mut PrivateProofRandomness,
    ) -> CanonicalResult<Self> {
        if secret.len() != ring_degree {
            return Err(invalid_key("secret length does not match ring degree"));
        }
        if component_b.len() != digits.len() {
            return Err(invalid_key(
                "component material count does not match digit count",
            ));
        }
        for digit in digits {
            if digit.error.len() != ring_degree || digit.carry.len() != ring_degree {
                return Err(invalid_key(
                    "digit witness length does not match ring degree",
                ));
            }
        }
        for material in &component_b {
            if material.len() != ring_degree {
                return Err(invalid_key(
                    "component material length does not match ring degree",
                ));
            }
        }
        let linkage_data = match linkage_inputs {
            None => None,
            Some((statement, witness)) => {
                let layout = linkage::linkage_layout(ring_degree)?;
                let values = linkage::build_linkage_witness_values(
                    statement,
                    witness,
                    secret,
                    ring_degree,
                    &layout,
                )?;
                Some(LinkagePlanData { layout, values })
            }
        };
        let multiplicity_values = carry_multiplicity_values(parameters, ring_degree, digits);
        let steps = if mask_degree == 0 { 0 } else { mask_degree + 1 };
        let base_count = base_column_count(
            ring_degree,
            digits.len(),
            linkage_data.as_ref().map(|data| &data.layout),
        );
        let mut base_mask_randomness = Vec::with_capacity(base_count);
        for _ in 0..base_count {
            base_mask_randomness.push(private_randomness.clone());
            private_randomness.discard_field_elements(steps);
        }
        // The material columns' mask seeds are drawn right after the base seeds,
        // one per digit, so the deterministic salt/mask stream advances in a
        // fixed order that the commit, sumcheck, combination, and opening passes
        // all reproduce.
        let material_count = material_column_count(digits.len());
        let mut material_mask_randomness = Vec::with_capacity(material_count);
        for _ in 0..material_count {
            material_mask_randomness.push(private_randomness.clone());
            private_randomness.discard_field_elements(steps);
        }
        Ok(Self {
            ring_degree,
            mask_degree,
            secret,
            digits,
            component_b,
            multiplicity_values,
            base_mask_randomness,
            material_mask_randomness,
            lookup_challenge: None,
            aux_mask_randomness: Vec::new(),
            linkage: linkage_data,
        })
    }

    pub(super) fn linkage_layout(&self) -> Option<&linkage::LinkageLayout> {
        self.linkage.as_ref().map(|data| &data.layout)
    }

    pub(super) fn base_column_count(&self) -> usize {
        base_column_count(self.ring_degree, self.digits.len(), self.linkage_layout())
    }

    pub(super) fn aux_column_count(&self) -> usize {
        aux_column_count(self.ring_degree, self.digits.len(), self.linkage_layout())
    }

    pub(super) fn populate_linkage_reduced_witness(
        &mut self,
        public_forms: &linkage::LinkagePublicForms,
    ) -> CanonicalResult<()> {
        let data = self
            .linkage
            .as_mut()
            .ok_or_else(|| invalid_key("a BDLOP linkage reduction requires a linkage block"))?;
        linkage::populate_linkage_reduced_witness(
            &mut data.values,
            public_forms,
            self.secret,
            self.ring_degree,
            &data.layout,
        )
    }

    // Record the logUp challenge and snapshot each auxiliary column's private
    // mask stream.
    pub(super) fn set_lookup_challenge(
        &mut self,
        challenge: [u64; LIMB_COUNT],
        private_randomness: &mut PrivateProofRandomness,
    ) {
        let steps = if self.mask_degree == 0 {
            0
        } else {
            self.mask_degree + 1
        };
        let aux_count = self.aux_column_count();
        self.aux_mask_randomness = Vec::with_capacity(aux_count);
        for _ in 0..aux_count {
            self.aux_mask_randomness.push(private_randomness.clone());
            private_randomness.discard_field_elements(steps);
        }
        self.lookup_challenge = Some(challenge);
    }

    // The unmasked value column for base column `column` (shared secret block,
    // per-digit witness blocks, then the carry-range multiplicity columns; the
    // multiplicity of each table value counts the shifted carries equal to it,
    // and an out-of-range carry is simply not counted, which makes the logUp
    // balance fail - the sound outcome, exercised by a tamper test).
    fn base_value_column(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        column: usize,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let digit_count = self.digits.len();
        let multiplicity_start = base_multiplicity_start(digit_count);
        if column == COLUMN_SECRET {
            return self
                .secret
                .iter()
                .map(|v| parameters.signed_word_to_element(*v))
                .collect();
        }
        if column == COLUMN_SECRET_SQUARE {
            return self
                .secret
                .iter()
                .map(|v| parameters.signed_word_to_element(v * v))
                .collect();
        }
        if column < multiplicity_start {
            let digit_index = (column - SHARED_COLUMN_COUNT) / DIGIT_BLOCK_SIZE;
            let offset_in_block = (column - SHARED_COLUMN_COUNT) % DIGIT_BLOCK_SIZE;
            let digit = &self.digits[digit_index];
            return match offset_in_block {
                DIGIT_ERROR => digit
                    .error
                    .iter()
                    .map(|v| parameters.signed_word_to_element(*v))
                    .collect(),
                DIGIT_CARRY => digit
                    .carry
                    .iter()
                    .map(|v| parameters.signed_word_to_element(*v))
                    .collect(),
                DIGIT_ERROR_SQUARE => digit
                    .error
                    .iter()
                    .map(|v| parameters.signed_word_to_element(v * v))
                    .collect(),
                DIGIT_ERROR_SUPPORT => digit
                    .error
                    .iter()
                    .map(|v| {
                        let square = v * v;
                        parameters.signed_word_to_element((square - 1) * (square - 4))
                    })
                    .collect(),
                _ => unreachable!("digit block offset out of range"),
            };
        }
        let linkage_start = base_linkage_start(self.ring_degree, digit_count);
        if column < linkage_start {
            return self.multiplicity_values[column - multiplicity_start].clone();
        }
        let data = self
            .linkage
            .as_ref()
            .expect("linkage base columns only exist with a linkage block");
        linkage::linkage_base_value_column(
            parameters,
            &data.layout,
            &data.values,
            column - linkage_start,
        )
    }

    // The masked coefficient vector for base column `column`, bit-identical on
    // every regeneration (the mask seed is the per-column snapshot).
    pub(super) fn base_column_coefficients(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
        column: usize,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let values = self.base_value_column(parameters, column);
        let coefficients = trace_domain.interpolate(&values);
        let mut private_randomness = self.base_mask_randomness[column].clone();
        masked_coefficients(
            parameters,
            &coefficients,
            self.ring_degree,
            self.mask_degree,
            &mut private_randomness,
        )
    }

    // The masked coefficient vector for material column `digit`: the recombined
    // component material `B_digit` interpolated over the trace domain, then
    // masked exactly like a base column (per-column mask-seed snapshot), so it is
    // bit-identical on every regeneration and its opening is bounded-leakage.
    pub(super) fn material_column_coefficients(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
        digit: usize,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let coefficients = trace_domain.interpolate(self.component_b[digit]);
        let mut private_randomness = self.material_mask_randomness[digit].clone();
        masked_coefficients(
            parameters,
            &coefficients,
            self.ring_degree,
            self.mask_degree,
            &mut private_randomness,
        )
    }

    // The unmasked logUp fraction value column for aux column `column`: one
    // lookup fraction column per digit `f_d[x] = 1/(mu - (c_d(x) + shift))`,
    // then one table fraction column per chunk `f_T_k[x] = m_k(x)/(mu - T_k(x))`.
    fn aux_value_column(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        column: usize,
    ) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
        let challenge = self
            .lookup_challenge
            .as_ref()
            .ok_or_else(|| invalid_key("aux columns requested before the logUp challenge"))?;
        let digit_count = self.digits.len();
        if column < digit_count {
            let shift = carry_range_lookup::carry_shift(self.ring_degree);
            let shifted_values: Vec<[u64; LIMB_COUNT]> = self.digits[column]
                .carry
                .iter()
                .map(|carry| parameters.signed_word_to_element(carry + shift))
                .collect();
            return carry_range_lookup::lookup_fraction_column(
                parameters,
                challenge,
                &shifted_values,
            )
            .ok_or_else(|| invalid_key("logUp challenge collided with a shifted carry"));
        }
        let linkage_start = aux_linkage_start(self.ring_degree, digit_count);
        if column < linkage_start {
            let table_index = column - digit_count;
            let table_values =
                carry_range_lookup::table_values(parameters, self.ring_degree, table_index);
            return carry_range_lookup::table_fraction_column(
                parameters,
                challenge,
                &table_values,
                &self.multiplicity_values[table_index],
            )
            .ok_or_else(|| invalid_key("logUp challenge collided with a table value"));
        }
        let data = self
            .linkage
            .as_ref()
            .expect("linkage aux columns only exist with a linkage block");
        let linkage_offset = column - linkage_start;
        linkage::linkage_aux_value_column(parameters, &data.layout, &data.values, linkage_offset)
    }

    pub(super) fn aux_column_coefficients(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        trace_domain: &CyclicDomain<'_, LIMB_COUNT>,
        column: usize,
    ) -> CanonicalResult<Vec<[u64; LIMB_COUNT]>> {
        let values = self.aux_value_column(parameters, column)?;
        let coefficients = trace_domain.interpolate(&values);
        let mut private_randomness = self.aux_mask_randomness[column].clone();
        Ok(masked_coefficients(
            parameters,
            &coefficients,
            self.ring_degree,
            self.mask_degree,
            &mut private_randomness,
        ))
    }

    // The logUp terminals over the on-domain fraction values (masking is a
    // `Z_H`-multiple so it does not change on-domain sums): the lookup-side
    // total (the per-digit carry fractions) and one total per table chunk.
    pub(super) fn lookup_terminals(
        &self,
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) -> CanonicalResult<([u64; LIMB_COUNT], Vec<[u64; LIMB_COUNT]>)> {
        let digit_count = self.digits.len();
        let mut lookup_terminal = parameters.zero();
        for digit in 0..digit_count {
            let column = self.aux_value_column(parameters, aux_lookup_column(digit))?;
            lookup_terminal = parameters.add(
                &lookup_terminal,
                &carry_range_lookup::column_sum(parameters, &column),
            );
        }
        let table_count = carry_range_lookup::table_count(self.ring_degree);
        let mut table_terminals = Vec::with_capacity(table_count);
        for table_index in 0..table_count {
            let column = self.aux_value_column(
                parameters,
                aux_table_fraction_column(digit_count, table_index),
            )?;
            table_terminals.push(carry_range_lookup::column_sum(parameters, &column));
        }
        Ok((lookup_terminal, table_terminals))
    }
}

// The shared-lookup multiplicity value columns (one per table chunk), counting
// how many shifted digit-atom carries equal each table value. Out-of-range
// values are not counted, which makes the logUp balance fail. Deterministic
// from the witness, so every pass derives the same columns.
pub(super) fn carry_multiplicity_values<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    ring_degree: usize,
    digits: &[DigitWitness],
) -> Vec<Vec<[u64; LIMB_COUNT]>> {
    let shift = carry_range_lookup::carry_shift(ring_degree);
    let max_shifted = carry_range_lookup::max_shifted_value(ring_degree);
    let mut shifted_in_range = Vec::with_capacity(digits.len() * ring_degree);
    for digit in digits {
        for &carry in &digit.carry {
            let shifted = carry + shift;
            if shifted >= 0 && (shifted as usize) <= max_shifted {
                shifted_in_range.push(shifted as usize);
            }
        }
    }
    carry_range_lookup::multiplicities(parameters, &shifted_in_range, ring_degree)
}
