use core::fmt;

use zeroize::Zeroize;

use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::{MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT},
};

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::{
        DegreeThreeMaskPolynomial, DegreeThreeMaskShare, canonical_evaluation_point,
        reconstruct_degree_three_mask,
    },
};

pub(crate) const LABEL_BODY_BIT_LENGTH: usize = 640;
pub(crate) const LABEL_BODY_BYTE_LENGTH: usize = LABEL_BODY_BIT_LENGTH / 8;
pub(crate) const LABEL_BODY_FIELD_LIMB_COUNT: usize = 3;
pub(crate) const LABEL_SHARE_VALUE_BYTE_LENGTH: usize =
    LABEL_BODY_FIELD_LIMB_COUNT * BinaryFieldElement256::CANONICAL_BYTE_LENGTH;
pub(crate) const WIRE_LABEL_BIT_LENGTH: usize = LABEL_BODY_BIT_LENGTH + 1;
pub(crate) const WIRE_LABEL_CANONICAL_BYTE_LENGTH: usize = LABEL_BODY_BYTE_LENGTH + 1;

const FINAL_LABEL_FIELD_LIMB_USED_BYTE_LENGTH: usize =
    LABEL_BODY_BYTE_LENGTH - (2 * BinaryFieldElement256::CANONICAL_BYTE_LENGTH);
pub(super) const DEGREE_THREE_LABEL_SHARE_ARTIFACT_MAGIC: &[u8] =
    b"sealed-lattice/degree-three-label-share";
pub(super) const DEGREE_THREE_LABEL_SHARE_ARTIFACT_VERSION: u64 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LabelBody([u8; LABEL_BODY_BYTE_LENGTH]);

impl LabelBody {
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let canonical_bytes: [u8; LABEL_BODY_BYTE_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| TallyPreparationError::LabelBodyByteLength {
                    expected: LABEL_BODY_BYTE_LENGTH,
                    actual: bytes.len(),
                })?;
        Ok(Self(canonical_bytes))
    }

    pub(crate) const fn canonical_bytes(&self) -> &[u8; LABEL_BODY_BYTE_LENGTH] {
        &self.0
    }

    fn field_limbs(self) -> [BinaryFieldElement256; LABEL_BODY_FIELD_LIMB_COUNT] {
        core::array::from_fn(|limb_position| {
            let start = limb_position * BinaryFieldElement256::CANONICAL_BYTE_LENGTH;
            let end =
                (start + BinaryFieldElement256::CANONICAL_BYTE_LENGTH).min(LABEL_BODY_BYTE_LENGTH);
            let mut limb_bytes = [0_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
            limb_bytes[..end - start].copy_from_slice(&self.0[start..end]);
            BinaryFieldElement256::from_canonical_bytes(&limb_bytes)
                .expect("a fixed-width field limb must decode")
        })
    }

    fn from_field_limbs(
        field_limbs: [BinaryFieldElement256; LABEL_BODY_FIELD_LIMB_COUNT],
    ) -> Result<Self, TallyPreparationError> {
        let final_limb_bytes = field_limbs[2].canonical_bytes();
        if final_limb_bytes[FINAL_LABEL_FIELD_LIMB_USED_BYTE_LENGTH..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(TallyPreparationError::LabelBodyPaddingNonzero);
        }

        let mut body_bytes = [0_u8; LABEL_BODY_BYTE_LENGTH];
        for (limb_position, field_limb) in field_limbs.iter().copied().enumerate() {
            let start = limb_position * BinaryFieldElement256::CANONICAL_BYTE_LENGTH;
            let end =
                (start + BinaryFieldElement256::CANONICAL_BYTE_LENGTH).min(LABEL_BODY_BYTE_LENGTH);
            body_bytes[start..end].copy_from_slice(&field_limb.canonical_bytes()[..end - start]);
        }
        Ok(Self(body_bytes))
    }
}

impl fmt::Debug for LabelBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LabelBody([redacted])")
    }
}

impl Zeroize for LabelBody {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireLabel {
    body: LabelBody,
    point_bit: bool,
}

impl WireLabel {
    pub(crate) const fn new(body: LabelBody, point_bit: bool) -> Self {
        Self { body, point_bit }
    }

    pub(crate) const fn body(self) -> LabelBody {
        self.body
    }

    pub(crate) fn canonical_bytes(self) -> [u8; WIRE_LABEL_CANONICAL_BYTE_LENGTH] {
        let mut bytes = [0_u8; WIRE_LABEL_CANONICAL_BYTE_LENGTH];
        bytes[..LABEL_BODY_BYTE_LENGTH].copy_from_slice(self.body.canonical_bytes());
        bytes[LABEL_BODY_BYTE_LENGTH] = u8::from(self.point_bit);
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        if bytes.len() != WIRE_LABEL_CANONICAL_BYTE_LENGTH {
            return Err(TallyPreparationError::WireLabelByteLength {
                expected: WIRE_LABEL_CANONICAL_BYTE_LENGTH,
                actual: bytes.len(),
            });
        }
        let point_bit = match bytes[LABEL_BODY_BYTE_LENGTH] {
            0 => false,
            1 => true,
            value => return Err(TallyPreparationError::NonCanonicalPointBit { value }),
        };
        Ok(Self {
            body: LabelBody::from_canonical_bytes(&bytes[..LABEL_BODY_BYTE_LENGTH])?,
            point_bit,
        })
    }
}

impl fmt::Debug for WireLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireLabel")
            .field("body", &self.body)
            .field("point_bit", &self.point_bit)
            .finish()
    }
}

impl Zeroize for WireLabel {
    fn zeroize(&mut self) {
        self.body.zeroize();
        self.point_bit = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DegreeThreeLabelPolynomial {
    limb_polynomials: [DegreeThreeMaskPolynomial; LABEL_BODY_FIELD_LIMB_COUNT],
}

impl DegreeThreeLabelPolynomial {
    pub(crate) fn new(
        label_body: LabelBody,
        random_coefficients: [[BinaryFieldElement256; 3]; LABEL_BODY_FIELD_LIMB_COUNT],
    ) -> Self {
        let field_limbs = label_body.field_limbs();
        Self {
            limb_polynomials: core::array::from_fn(|limb_position| {
                DegreeThreeMaskPolynomial::new(
                    field_limbs[limb_position],
                    random_coefficients[limb_position],
                )
            }),
        }
    }

    pub(crate) fn share(
        self,
        participant_count: u16,
        roster_position: u16,
    ) -> Result<DegreeThreeLabelShare, TallyPreparationError> {
        let evaluation_point = canonical_evaluation_point(participant_count, roster_position)?;
        DegreeThreeLabelShare::new(
            participant_count,
            roster_position,
            evaluation_point,
            self.limb_polynomials
                .map(|polynomial| polynomial.evaluate(evaluation_point)),
        )
    }

    pub(crate) fn shares(
        self,
        participant_count: u16,
    ) -> Result<Vec<DegreeThreeLabelShare>, TallyPreparationError> {
        (0..participant_count)
            .map(|roster_position| self.share(participant_count, roster_position))
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DegreeThreeLabelShare {
    participant_count: u16,
    roster_position: u16,
    evaluation_point: BinaryFieldElement256,
    values: [BinaryFieldElement256; LABEL_BODY_FIELD_LIMB_COUNT],
}

impl DegreeThreeLabelShare {
    pub(crate) fn new(
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement256,
        values: [BinaryFieldElement256; LABEL_BODY_FIELD_LIMB_COUNT],
    ) -> Result<Self, TallyPreparationError> {
        let expected_evaluation_point =
            canonical_evaluation_point(participant_count, roster_position)?;
        if evaluation_point.is_zero() {
            return Err(TallyPreparationError::ZeroEvaluationPoint);
        }
        if evaluation_point != expected_evaluation_point {
            return Err(TallyPreparationError::EvaluationPointMismatch { roster_position });
        }
        Ok(Self {
            participant_count,
            roster_position,
            evaluation_point,
            values,
        })
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn roster_position(self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn evaluation_point(self) -> BinaryFieldElement256 {
        self.evaluation_point
    }

    pub(crate) const fn values(self) -> [BinaryFieldElement256; LABEL_BODY_FIELD_LIMB_COUNT] {
        self.values
    }

    pub(crate) fn canonical_value_bytes(self) -> [u8; LABEL_SHARE_VALUE_BYTE_LENGTH] {
        let mut bytes = [0_u8; LABEL_SHARE_VALUE_BYTE_LENGTH];
        for (limb_position, value) in self.values.iter().copied().enumerate() {
            let start = limb_position * BinaryFieldElement256::CANONICAL_BYTE_LENGTH;
            bytes[start..start + BinaryFieldElement256::CANONICAL_BYTE_LENGTH]
                .copy_from_slice(&value.canonical_bytes());
        }
        bytes
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            DEGREE_THREE_LABEL_SHARE_ARTIFACT_MAGIC.len()
                + LABEL_SHARE_VALUE_BYTE_LENGTH
                + BinaryFieldElement256::CANONICAL_BYTE_LENGTH
                + 16,
        );
        append_bytes(&mut bytes, DEGREE_THREE_LABEL_SHARE_ARTIFACT_MAGIC);
        append_varuint(&mut bytes, DEGREE_THREE_LABEL_SHARE_ARTIFACT_VERSION);
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.roster_position));
        append_bytes(&mut bytes, &self.evaluation_point.canonical_bytes());
        for value in self.values {
            append_bytes(&mut bytes, &value.canonical_bytes());
        }
        bytes
    }
}

impl fmt::Debug for DegreeThreeLabelShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DegreeThreeLabelShare")
            .field("participant_count", &self.participant_count)
            .field("roster_position", &self.roster_position)
            .field("evaluation_point", &self.evaluation_point)
            .field("values", &"[redacted]")
            .finish()
    }
}

pub(crate) fn decode_canonical_degree_three_label_share(
    bytes: &[u8],
) -> Result<DegreeThreeLabelShare, TallyPreparationError> {
    let mut reader = CanonicalReader::new(bytes);
    if reader.read_bytes()?.as_slice() != DEGREE_THREE_LABEL_SHARE_ARTIFACT_MAGIC {
        return Err(TallyPreparationError::LabelShareArtifactMagicMismatch);
    }
    let version = reader.read_varuint()?;
    if version != DEGREE_THREE_LABEL_SHARE_ARTIFACT_VERSION {
        return Err(TallyPreparationError::UnsupportedLabelShareArtifactVersion { version });
    }
    let participant_count = read_u16(&mut reader)?;
    let roster_position = read_u16(&mut reader)?;
    let evaluation_point = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
    let mut values = [BinaryFieldElement256::ZERO; LABEL_BODY_FIELD_LIMB_COUNT];
    for value in &mut values {
        *value = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
    }
    if !reader.is_finished() {
        return Err(TallyPreparationError::TrailingLabelShareArtifactBytes);
    }
    DegreeThreeLabelShare::new(participant_count, roster_position, evaluation_point, values)
}

pub(crate) fn reconstruct_degree_three_label_body(
    expected_participant_count: u16,
    shares: &[DegreeThreeLabelShare],
) -> Result<LabelBody, TallyPreparationError> {
    let mut reconstructed_limbs = [BinaryFieldElement256::ZERO; LABEL_BODY_FIELD_LIMB_COUNT];
    for limb_position in 0..LABEL_BODY_FIELD_LIMB_COUNT {
        let limb_shares = shares
            .iter()
            .map(|share| {
                DegreeThreeMaskShare::new(
                    share.participant_count,
                    share.roster_position,
                    share.evaluation_point,
                    share.values[limb_position],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        reconstructed_limbs[limb_position] =
            reconstruct_degree_three_mask(expected_participant_count, &limb_shares)?;
    }
    LabelBody::from_field_limbs(reconstructed_limbs)
}

pub(crate) fn garbling_output_byte_length(
    participant_count: u16,
) -> Result<usize, TallyPreparationError> {
    validate_garbling_participant_count(participant_count)?;
    usize::from(participant_count)
        .checked_mul(WIRE_LABEL_BIT_LENGTH)
        .and_then(|bit_length| bit_length.checked_add(7))
        .map(|rounded_bit_length| rounded_bit_length / 8)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

pub(crate) fn encode_garbling_output_components(
    participant_count: u16,
    components: &[WireLabel],
) -> Result<Vec<u8>, TallyPreparationError> {
    validate_garbling_participant_count(participant_count)?;
    let expected_component_count = usize::from(participant_count);
    if components.len() != expected_component_count {
        return Err(
            TallyPreparationError::GarblingOutputComponentCountMismatch {
                expected: expected_component_count,
                actual: components.len(),
            },
        );
    }
    let mut output = vec![0_u8; garbling_output_byte_length(participant_count)?];
    for (component_position, component) in components.iter().copied().enumerate() {
        let component_start_bit = component_position
            .checked_mul(WIRE_LABEL_BIT_LENGTH)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        for body_bit_position in 0..LABEL_BODY_BIT_LENGTH {
            let body_bit = (component.body.canonical_bytes()[body_bit_position / 8]
                >> (body_bit_position % 8))
                & 1;
            set_packed_bit(
                &mut output,
                component_start_bit + body_bit_position,
                body_bit == 1,
            );
        }
        set_packed_bit(
            &mut output,
            component_start_bit + LABEL_BODY_BIT_LENGTH,
            component.point_bit,
        );
    }
    Ok(output)
}

pub(crate) fn decode_garbling_output_components(
    participant_count: u16,
    bytes: &[u8],
) -> Result<Vec<WireLabel>, TallyPreparationError> {
    let expected_byte_length = garbling_output_byte_length(participant_count)?;
    if bytes.len() != expected_byte_length {
        return Err(TallyPreparationError::GarblingOutputByteLength {
            expected: expected_byte_length,
            actual: bytes.len(),
        });
    }
    let bit_length = usize::from(participant_count)
        .checked_mul(WIRE_LABEL_BIT_LENGTH)
        .ok_or(TallyPreparationError::ArithmeticOverflow)?;
    let used_final_byte_bit_count = bit_length % 8;
    if used_final_byte_bit_count != 0 {
        let used_bit_mask = (1_u8 << used_final_byte_bit_count) - 1;
        if bytes.last().copied().unwrap_or_default() & !used_bit_mask != 0 {
            return Err(TallyPreparationError::GarblingOutputPaddingNonzero);
        }
    }

    let mut components = Vec::with_capacity(usize::from(participant_count));
    for component_position in 0..usize::from(participant_count) {
        let component_start_bit = component_position
            .checked_mul(WIRE_LABEL_BIT_LENGTH)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        let mut body_bytes = [0_u8; LABEL_BODY_BYTE_LENGTH];
        for body_bit_position in 0..LABEL_BODY_BIT_LENGTH {
            if read_packed_bit(bytes, component_start_bit + body_bit_position) {
                body_bytes[body_bit_position / 8] |= 1_u8 << (body_bit_position % 8);
            }
        }
        components.push(WireLabel::new(
            LabelBody::from_canonical_bytes(&body_bytes)?,
            read_packed_bit(bytes, component_start_bit + LABEL_BODY_BIT_LENGTH),
        ));
    }
    Ok(components)
}

fn set_packed_bit(bytes: &mut [u8], bit_position: usize, value: bool) {
    if value {
        bytes[bit_position / 8] |= 1_u8 << (bit_position % 8);
    }
}

fn read_packed_bit(bytes: &[u8], bit_position: usize) -> bool {
    (bytes[bit_position / 8] >> (bit_position % 8)) & 1 == 1
}

fn validate_garbling_participant_count(
    participant_count: u16,
) -> Result<(), TallyPreparationError> {
    if !(MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT)
        .contains(&participant_count)
    {
        return Err(TallyPreparationError::ParticipantCountOutOfRange { participant_count });
    }
    Ok(())
}

fn read_u16(reader: &mut CanonicalReader<'_>) -> Result<u16, TallyPreparationError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| TallyPreparationError::IntegerConversion)
}
