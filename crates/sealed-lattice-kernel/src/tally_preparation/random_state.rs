use core::fmt;

use zeroize::Zeroize;

use crate::tally_circuit::CompiledTallyCircuit;

use super::{
    BinaryFieldElement256, TallyPreparationError, TallyPreparationGeometry,
    TallyPreparationRandomTapeSource,
    geometry::{LABEL_KEY_BYTE_LENGTH, SECRET_LEAF_SALT_BYTE_LENGTH},
    output_sharing::DegreeThreeMaskPolynomial,
};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WireLabelKey([u8; LABEL_KEY_BYTE_LENGTH as usize]);

impl WireLabelKey {
    pub(crate) const fn canonical_bytes(&self) -> &[u8; LABEL_KEY_BYTE_LENGTH as usize] {
        &self.0
    }
}

impl fmt::Debug for WireLabelKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireLabelKey([redacted])")
    }
}

impl Zeroize for WireLabelKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretLeafSalt([u8; SECRET_LEAF_SALT_BYTE_LENGTH as usize]);

impl SecretLeafSalt {
    pub(crate) const fn canonical_bytes(&self) -> &[u8; SECRET_LEAF_SALT_BYTE_LENGTH as usize] {
        &self.0
    }
}

impl fmt::Debug for SecretLeafSalt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretLeafSalt([redacted])")
    }
}

impl Zeroize for SecretLeafSalt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct TallyPreparationRandomState {
    wire_masks: Vec<u8>,
    label_keys: Vec<WireLabelKey>,
    score_input_mask_polynomials: Vec<DegreeThreeMaskPolynomial>,
    result_mask_polynomials: Vec<DegreeThreeMaskPolynomial>,
    secret_leaf_salts: Vec<SecretLeafSalt>,
}

impl TallyPreparationRandomState {
    pub(crate) fn wire_masks(&self) -> &[u8] {
        &self.wire_masks
    }

    pub(crate) fn label_keys(&self) -> &[WireLabelKey] {
        &self.label_keys
    }

    pub(crate) fn score_input_mask_polynomials(&self) -> &[DegreeThreeMaskPolynomial] {
        &self.score_input_mask_polynomials
    }

    pub(crate) fn result_mask_polynomials(&self) -> &[DegreeThreeMaskPolynomial] {
        &self.result_mask_polynomials
    }

    pub(crate) fn secret_leaf_salts(&self) -> &[SecretLeafSalt] {
        &self.secret_leaf_salts
    }

    pub(crate) fn label_key(
        &self,
        geometry: TallyPreparationGeometry,
        wire_position: usize,
        external_bit: bool,
        component_owner_position: usize,
    ) -> Option<&WireLabelKey> {
        let participant_count = usize::try_from(geometry.participant_count).ok()?;
        let wire_count = usize::try_from(geometry.wire_count).ok()?;
        if wire_position >= wire_count || component_owner_position >= participant_count {
            return None;
        }
        let label_position = wire_position
            .checked_mul(2)?
            .checked_add(usize::from(external_bit))?;
        let key_position = label_position
            .checked_mul(participant_count)?
            .checked_add(component_owner_position)?;
        self.label_keys.get(key_position)
    }
}

impl fmt::Debug for TallyPreparationRandomState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TallyPreparationRandomState")
            .field("wire_mask_count", &self.wire_masks.len())
            .field("label_key_count", &self.label_keys.len())
            .field(
                "score_input_mask_polynomial_count",
                &self.score_input_mask_polynomials.len(),
            )
            .field(
                "result_mask_polynomial_count",
                &self.result_mask_polynomials.len(),
            )
            .field("secret_leaf_salt_count", &self.secret_leaf_salts.len())
            .finish()
    }
}

impl Drop for TallyPreparationRandomState {
    fn drop(&mut self) {
        self.wire_masks.zeroize();
        self.label_keys.zeroize();
        for polynomial in &mut self.score_input_mask_polynomials {
            polynomial.zeroize();
        }
        for polynomial in &mut self.result_mask_polynomials {
            polynomial.zeroize();
        }
        self.secret_leaf_salts.zeroize();
    }
}

pub(crate) fn parse_tally_preparation_random_state(
    circuit: &CompiledTallyCircuit,
    source: &mut impl TallyPreparationRandomTapeSource,
) -> Result<TallyPreparationRandomState, TallyPreparationError> {
    let geometry = TallyPreparationGeometry::derive(circuit)?;
    let expected_byte_length = geometry.direct_joint_random_tape_byte_length_usize()?;
    if source.total_byte_length() != expected_byte_length {
        return Err(TallyPreparationError::RandomSourceByteLengthMismatch {
            expected: expected_byte_length,
            actual: source.total_byte_length(),
        });
    }

    let wire_count = usize_from_u64(geometry.wire_count)?;
    let mut packed_wire_masks = vec![0_u8; usize_from_u64(geometry.packed_wire_mask_byte_length,)?];
    source.fill_exact(&mut packed_wire_masks)?;
    let wire_masks = (0..wire_count)
        .map(|wire_position| (packed_wire_masks[wire_position / 8] >> (wire_position % 8)) & 1_u8)
        .collect::<Vec<_>>();
    packed_wire_masks.zeroize();

    let label_key_count = usize_from_u64(geometry.label_key_count)?;
    let mut label_keys = Vec::new();
    label_keys
        .try_reserve_exact(label_key_count)
        .map_err(|_| TallyPreparationError::ArithmeticOverflow)?;
    for _label_key_position in 0..label_key_count {
        let mut key = [0_u8; LABEL_KEY_BYTE_LENGTH as usize];
        source.fill_exact(&mut key)?;
        label_keys.push(WireLabelKey(key));
    }

    let participant_count = usize::from(circuit.profile().participant_count());
    let score_input_wire_count = usize_from_u64(geometry.score_input_wire_count)?;
    let mut score_input_mask_polynomials = Vec::new();
    score_input_mask_polynomials
        .try_reserve_exact(score_input_wire_count)
        .map_err(|_| TallyPreparationError::ArithmeticOverflow)?;
    for score_input_position in 0..score_input_wire_count {
        let wire_position = participant_count
            .checked_add(score_input_position)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        score_input_mask_polynomials.push(read_mask_polynomial(wire_masks[wire_position], source)?);
    }

    let result_output_wire_count = usize_from_u64(geometry.result_output_wire_count)?;
    let mut result_mask_polynomials = Vec::new();
    result_mask_polynomials
        .try_reserve_exact(result_output_wire_count)
        .map_err(|_| TallyPreparationError::ArithmeticOverflow)?;
    for result_wire in circuit.ordered_option_position_wires().iter().flatten() {
        let wire_position =
            usize::try_from(*result_wire).map_err(|_| TallyPreparationError::IntegerConversion)?;
        let mask =
            *wire_masks
                .get(wire_position)
                .ok_or(TallyPreparationError::WireIndexOutOfRange {
                    wire_index: *result_wire,
                    wire_count,
                })?;
        result_mask_polynomials.push(read_mask_polynomial(mask, source)?);
    }
    if result_mask_polynomials.len() != result_output_wire_count {
        return Err(TallyPreparationError::GeometryMismatch);
    }

    let secret_leaf_salt_count = usize_from_u64(geometry.secret_leaf_salt_count)?;
    let mut secret_leaf_salts = Vec::new();
    secret_leaf_salts
        .try_reserve_exact(secret_leaf_salt_count)
        .map_err(|_| TallyPreparationError::ArithmeticOverflow)?;
    for _salt_position in 0..secret_leaf_salt_count {
        let mut salt = [0_u8; SECRET_LEAF_SALT_BYTE_LENGTH as usize];
        source.fill_exact(&mut salt)?;
        secret_leaf_salts.push(SecretLeafSalt(salt));
    }
    source.ensure_finished()?;

    Ok(TallyPreparationRandomState {
        wire_masks,
        label_keys,
        score_input_mask_polynomials,
        result_mask_polynomials,
        secret_leaf_salts,
    })
}

fn read_mask_polynomial(
    mask: u8,
    source: &mut impl TallyPreparationRandomTapeSource,
) -> Result<DegreeThreeMaskPolynomial, TallyPreparationError> {
    if mask > 1 {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let mut random_coefficients = [BinaryFieldElement256::ZERO; 3];
    for coefficient in &mut random_coefficients {
        let mut bytes = [0_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
        source.fill_exact(&mut bytes)?;
        *coefficient = BinaryFieldElement256::from_canonical_bytes(&bytes)?;
        bytes.zeroize();
    }
    Ok(DegreeThreeMaskPolynomial::new(
        BinaryFieldElement256::from_low_polynomial_u16(u16::from(mask)),
        random_coefficients,
    ))
}

fn usize_from_u64(value: u64) -> Result<usize, TallyPreparationError> {
    usize::try_from(value).map_err(|_| TallyPreparationError::IntegerConversion)
}
