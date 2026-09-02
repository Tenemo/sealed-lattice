use core::fmt;
use std::collections::BTreeSet;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::Zeroize;

use crate::foundation::{CanonicalItem, Hash512, Roster, hash_foundation_tuple_512};

use super::finality::{
    COMPLETION_PROFILE_PARTICIPANT_COUNT, FinalityTargetKind, VerifiedFinalityCapability,
};
use super::preparation_parent::{ActionSignatureCarrier, ActionSignaturePurpose};
use super::roster::{require_roster_identity, signing_verification_key};

pub const LABEL_BYTE_LENGTH: usize = 48;
pub const MODULE_VALUE_BYTE_LENGTH: usize = 48;
pub const AFFINE_ENTROPY_BYTE_LENGTH: usize = 14 * MODULE_VALUE_BYTE_LENGTH;
pub const AFFINE_MATERIAL_BYTE_LENGTH: usize = Hash512::BYTE_LENGTH
    + 2 * MODULE_VALUE_BYTE_LENGTH
    + COMPLETION_PROFILE_PARTICIPANT_COUNT as usize * 2 * MODULE_VALUE_BYTE_LENGTH;
pub const TOKEN_BYTE_LENGTH: usize = LABEL_BYTE_LENGTH + 1;

const FIELD_BIT_WIDTH: usize = 4;
const MAXIMUM_GATE_BATCH_COUNT: usize = 32;
const MAXIMUM_INPUT_WIRE_COUNT: usize = 64;
const MAXIMUM_OUTPUT_WIRE_COUNT: usize = 64;
const LOCAL_MULTIPLICATION_GATE_COUNT: usize = 35;
const LOCAL_MULTIPLICATION_ROW_COUNT: usize = LOCAL_MULTIPLICATION_GATE_COUNT * 4;
const JOINT_ROW_COUNT_PER_GARBLER: usize = COMPLETION_PROFILE_PARTICIPANT_COUNT as usize * 16;
const CONTINUATION_AUTHENTICATOR_BYTE_LENGTH: usize = LABEL_BYTE_LENGTH;
const CONTINUATION_ROW_BYTE_LENGTH: usize =
    TOKEN_BYTE_LENGTH + CONTINUATION_AUTHENTICATOR_BYTE_LENGTH;
const GATE_PAYLOAD_BYTE_LENGTH: usize = LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH
    + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH
    + 1
    + JOINT_ROW_COUNT_PER_GARBLER * MODULE_VALUE_BYTE_LENGTH
    + 2 * CONTINUATION_ROW_BYTE_LENGTH
    + (FIELD_BIT_WIDTH - 1) * TOKEN_BYTE_LENGTH;
const TERMINAL_PAYLOAD_BYTE_LENGTH: usize =
    FIELD_BIT_WIDTH * 4 * TOKEN_BYTE_LENGTH + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH + 1;
const TOKEN_PAIR_ENTROPY_BYTE_LENGTH: usize = 2 * LABEL_BYTE_LENGTH + 1;

const PLAN_MAGIC: [u8; 4] = *b"SLJP";
const PLAN_VERSION: u16 = 1;
const BODY_MAGIC: [u8; 4] = *b"SLJB";
const BODY_VERSION: u16 = 2;
const PLAN_IDENTITY_DOMAIN: &str = "sealed-lattice/joint-continuation/plan/v1";
const BODY_IDENTITY_DOMAIN: &str = "sealed-lattice/joint-continuation/body/v1";
const BATCH_IDENTITY_DOMAIN: &str = "sealed-lattice/joint-continuation/batch/v1";
const AFFINE_COMMITMENT_DOMAIN: &str = "sealed-lattice/joint-continuation/affine-entropy/v1";
const LOCAL_ROW_DOMAIN: &[u8] = b"sealed-lattice/joint-continuation/local-row/v2";
const JOINT_ROW_DOMAIN: &[u8] = b"sealed-lattice/joint-continuation/joint-row/v2";
const CONTINUATION_ROW_DOMAIN: &[u8] = b"sealed-lattice/joint-continuation/continuation-row/v2";

type Label = [u8; LABEL_BYTE_LENGTH];
type ModuleValue = [u8; MODULE_VALUE_BYTE_LENGTH];
type FieldPairs = [TokenPair; FIELD_BIT_WIDTH];
type FieldTokens = [Token; FIELD_BIT_WIDTH];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JointContinuationError {
    ArithmeticOverflow,
    ContinuationAuthenticationFailed,
    DuplicateCommitment,
    DuplicateParticipant,
    InvalidAffineMaterial,
    InvalidBody,
    InvalidCodeword,
    InvalidContext,
    InvalidLabelEntropy,
    InvalidPlan,
    InvalidSignature,
    WrongParticipantCount,
    WrongParticipantPosition,
    WrongTargetKind,
}

impl fmt::Display for JointContinuationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArithmeticOverflow => "joint continuation arithmetic overflow",
            Self::ContinuationAuthenticationFailed => "joint continuation authentication failed",
            Self::DuplicateCommitment => "joint continuation reuses an entropy commitment",
            Self::DuplicateParticipant => {
                "joint continuation contains a duplicate participant position"
            }
            Self::InvalidAffineMaterial => "joint continuation affine material is invalid",
            Self::InvalidBody => "joint continuation body is invalid",
            Self::InvalidCodeword => "joint continuation codeword is invalid",
            Self::InvalidContext => "joint continuation context is invalid",
            Self::InvalidLabelEntropy => "joint continuation label entropy is invalid",
            Self::InvalidPlan => "joint continuation plan is invalid",
            Self::InvalidSignature => "joint continuation signature is invalid",
            Self::WrongParticipantCount => {
                "joint continuation requires the ten-participant completion roster"
            }
            Self::WrongParticipantPosition => "joint continuation participant position is invalid",
            Self::WrongTargetKind => "joint continuation requires a finalized computation target",
        })
    }
}

impl std::error::Error for JointContinuationError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Gf16(u8);

impl Gf16 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const fn new(value: u8) -> Self {
        Self(value & 0x0f)
    }

    const fn as_u8(self) -> u8 {
        self.0
    }

    const fn add(self, right: Self) -> Self {
        Self(self.0 ^ right.0)
    }

    fn multiply(self, right: Self) -> Self {
        let mut left_value = self.0;
        let mut right_value = right.0;
        let mut product = 0_u8;
        for _ in 0..FIELD_BIT_WIDTH {
            product ^= (0_u8.wrapping_sub(right_value & 1)) & left_value;
            let high_bit = left_value >> 3;
            left_value = (left_value << 1) & 0x0f;
            left_value ^= (0_u8.wrapping_sub(high_bit)) & 0x03;
            right_value >>= 1;
        }
        Self::new(product)
    }

    fn power(self, mut exponent: u8) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.multiply(base);
            }
            base = base.multiply(base);
            exponent >>= 1;
        }
        result
    }

    fn inverse(self) -> Option<Self> {
        (self != Self::ZERO).then(|| self.power(14))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JointContinuationGate {
    pub left_wire: u16,
    pub right_wire: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointContinuationPlan {
    input_wire_count: u16,
    gates: Vec<JointContinuationGate>,
    output_wires: Vec<u16>,
}

impl JointContinuationPlan {
    pub fn new(
        input_wire_count: u16,
        gates: Vec<JointContinuationGate>,
        output_wires: Vec<u16>,
    ) -> Result<Self, JointContinuationError> {
        if input_wire_count == 0
            || usize::from(input_wire_count) > MAXIMUM_INPUT_WIRE_COUNT
            || gates.is_empty()
            || gates.len() > MAXIMUM_GATE_BATCH_COUNT
            || output_wires.is_empty()
            || output_wires.len() > MAXIMUM_OUTPUT_WIRE_COUNT
        {
            return Err(JointContinuationError::InvalidPlan);
        }
        for (gate_index, gate) in gates.iter().enumerate() {
            let available_wire_count = usize::from(input_wire_count)
                .checked_add(gate_index)
                .ok_or(JointContinuationError::ArithmeticOverflow)?;
            if usize::from(gate.left_wire) >= available_wire_count
                || usize::from(gate.right_wire) >= available_wire_count
            {
                return Err(JointContinuationError::InvalidPlan);
            }
        }
        let wire_count = usize::from(input_wire_count)
            .checked_add(gates.len())
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let mut seen_outputs = BTreeSet::new();
        for output_wire in &output_wires {
            if usize::from(*output_wire) >= wire_count || !seen_outputs.insert(*output_wire) {
                return Err(JointContinuationError::InvalidPlan);
            }
        }
        Ok(Self {
            input_wire_count,
            gates,
            output_wires,
        })
    }

    pub fn wire_count(&self) -> Result<usize, JointContinuationError> {
        usize::from(self.input_wire_count)
            .checked_add(self.gates.len())
            .ok_or(JointContinuationError::ArithmeticOverflow)
    }

    pub fn encode(&self) -> Result<Vec<u8>, JointContinuationError> {
        let mut bytes = Vec::with_capacity(
            4 + 2 + 2 + 2 + self.gates.len() * 4 + 2 + self.output_wires.len() * 2,
        );
        bytes.extend_from_slice(&PLAN_MAGIC);
        bytes.extend_from_slice(&PLAN_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.input_wire_count.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.gates.len())
                .map_err(|_| JointContinuationError::InvalidPlan)?
                .to_le_bytes(),
        );
        for gate in &self.gates {
            bytes.extend_from_slice(&gate.left_wire.to_le_bytes());
            bytes.extend_from_slice(&gate.right_wire.to_le_bytes());
        }
        bytes.extend_from_slice(
            &u16::try_from(self.output_wires.len())
                .map_err(|_| JointContinuationError::InvalidPlan)?
                .to_le_bytes(),
        );
        for output_wire in &self.output_wires {
            bytes.extend_from_slice(&output_wire.to_le_bytes());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, JointContinuationError> {
        let mut reader = ByteReader::new(bytes);
        if reader.read_array::<4>()? != PLAN_MAGIC || reader.read_u16()? != PLAN_VERSION {
            return Err(JointContinuationError::InvalidPlan);
        }
        let input_wire_count = reader.read_u16()?;
        let gate_count = usize::from(reader.read_u16()?);
        if gate_count == 0 || gate_count > MAXIMUM_GATE_BATCH_COUNT {
            return Err(JointContinuationError::InvalidPlan);
        }
        let mut gates = Vec::with_capacity(gate_count);
        for _ in 0..gate_count {
            gates.push(JointContinuationGate {
                left_wire: reader.read_u16()?,
                right_wire: reader.read_u16()?,
            });
        }
        let output_count = usize::from(reader.read_u16()?);
        if output_count == 0 || output_count > MAXIMUM_OUTPUT_WIRE_COUNT {
            return Err(JointContinuationError::InvalidPlan);
        }
        let mut output_wires = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            output_wires.push(reader.read_u16()?);
        }
        reader.finish()?;
        let plan = Self::new(input_wire_count, gates, output_wires)?;
        if plan.encode()?.as_slice() != bytes {
            return Err(JointContinuationError::InvalidPlan);
        }
        Ok(plan)
    }

    pub fn identity(&self) -> Result<Hash512, JointContinuationError> {
        hash_bytes(PLAN_IDENTITY_DOMAIN, &self.encode()?)
    }

    pub fn label_entropy_byte_length(&self) -> Result<usize, JointContinuationError> {
        let pair_count = usize::from(self.input_wire_count)
            .checked_mul(FIELD_BIT_WIDTH)
            .and_then(|count| {
                self.gates
                    .len()
                    .checked_mul(43)
                    .and_then(|gate_pairs| count.checked_add(gate_pairs))
            })
            .and_then(|count| {
                self.output_wires
                    .len()
                    .checked_mul(8)
                    .and_then(|terminal_pairs| count.checked_add(terminal_pairs))
            })
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        pair_count
            .checked_mul(TOKEN_PAIR_ENTROPY_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)
    }

    pub fn participant_body_byte_length(&self) -> Result<usize, JointContinuationError> {
        let header_length = 4usize
            .checked_add(2)
            .and_then(|length| length.checked_add(2 * Hash512::BYTE_LENGTH))
            .and_then(|length| length.checked_add(2 + 2))
            .and_then(|length| {
                self.gates
                    .len()
                    .checked_mul(Hash512::BYTE_LENGTH)
                    .and_then(|commitments| length.checked_add(commitments))
            })
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        header_length
            .checked_add(
                usize::from(self.input_wire_count)
                    .checked_mul(FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH)
                    .ok_or(JointContinuationError::ArithmeticOverflow)?,
            )
            .and_then(|length| {
                self.gates
                    .len()
                    .checked_mul(GATE_PAYLOAD_BYTE_LENGTH)
                    .and_then(|payload| length.checked_add(payload))
            })
            .and_then(|length| {
                self.output_wires
                    .len()
                    .checked_mul(TERMINAL_PAYLOAD_BYTE_LENGTH)
                    .and_then(|payload| length.checked_add(payload))
            })
            .ok_or(JointContinuationError::ArithmeticOverflow)
    }
}

fn reviewed_reduced_plan() -> Result<JointContinuationPlan, JointContinuationError> {
    JointContinuationPlan::new(
        4,
        vec![
            JointContinuationGate {
                left_wire: 0,
                right_wire: 1,
            },
            JointContinuationGate {
                left_wire: 2,
                right_wire: 3,
            },
            JointContinuationGate {
                left_wire: 4,
                right_wire: 2,
            },
            JointContinuationGate {
                left_wire: 4,
                right_wire: 3,
            },
            JointContinuationGate {
                left_wire: 6,
                right_wire: 7,
            },
            JointContinuationGate {
                left_wire: 5,
                right_wire: 0,
            },
            JointContinuationGate {
                left_wire: 8,
                right_wire: 9,
            },
        ],
        vec![4, 7, 10],
    )
}

fn validate_reviewed_reduced_plan(
    plan: &JointContinuationPlan,
) -> Result<(), JointContinuationError> {
    if plan == &reviewed_reduced_plan()? {
        Ok(())
    } else {
        Err(JointContinuationError::InvalidPlan)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffineEvaluation {
    pub affine_a: ModuleValue,
    pub affine_b: ModuleValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedAffineMaterial {
    pub commitment: Hash512,
    pub constants: [ModuleValue; 2],
    pub evaluations: [AffineEvaluation; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
}

pub fn derive_affine_material(
    entropy: &[u8],
) -> Result<DerivedAffineMaterial, JointContinuationError> {
    if entropy.len() != AFFINE_ENTROPY_BYTE_LENGTH {
        return Err(JointContinuationError::InvalidAffineMaterial);
    }
    let mut offset = 0usize;
    let affine_a_coefficients: [ModuleValue; 10] = core::array::from_fn(|_| {
        let value = entropy[offset..offset + MODULE_VALUE_BYTE_LENGTH]
            .try_into()
            .expect("validated affine entropy has complete coefficient blocks");
        offset += MODULE_VALUE_BYTE_LENGTH;
        value
    });
    let affine_b_coefficients: [ModuleValue; 4] = core::array::from_fn(|_| {
        let value = entropy[offset..offset + MODULE_VALUE_BYTE_LENGTH]
            .try_into()
            .expect("validated affine entropy has complete coefficient blocks");
        offset += MODULE_VALUE_BYTE_LENGTH;
        value
    });
    if affine_b_coefficients[0].iter().all(|byte| *byte == 0) {
        return Err(JointContinuationError::InvalidAffineMaterial);
    }
    let evaluations = core::array::from_fn(|position| {
        let point = Gf16::new((position + 1) as u8);
        AffineEvaluation {
            affine_a: evaluate_module_polynomial(&affine_a_coefficients, point),
            affine_b: evaluate_module_polynomial(&affine_b_coefficients, point),
        }
    });
    Ok(DerivedAffineMaterial {
        commitment: hash_bytes(AFFINE_COMMITMENT_DOMAIN, entropy)?,
        constants: [affine_a_coefficients[0], affine_b_coefficients[0]],
        evaluations,
    })
}

pub struct ParticipantGenerationInput<'a> {
    pub participant_position: u16,
    pub initial_wire_values: &'a [u8],
    pub gate_mask_shares: &'a [u8],
    pub terminal_mask_shares: &'a [u8],
    pub label_entropy: &'a [u8],
    pub own_affine_entropy: &'a [u8],
    pub affine_commitments: &'a [u8],
    pub affine_evaluations: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedParticipantBody {
    pub body: Vec<u8>,
    pub body_identity: Hash512,
    pub affine_commitments: Vec<Hash512>,
}

pub fn generate_participant_body(
    capability: &VerifiedFinalityCapability,
    plan: &JointContinuationPlan,
    input: ParticipantGenerationInput<'_>,
) -> Result<GeneratedParticipantBody, JointContinuationError> {
    validate_capability(capability)?;
    validate_reviewed_reduced_plan(plan)?;
    let context = EvaluationContext {
        target_identity: capability.target_identity,
        plan_identity: plan.identity()?,
    };
    generate_participant_body_for_context(&context, plan, input)
}

fn generate_participant_body_for_context(
    context: &EvaluationContext,
    plan: &JointContinuationPlan,
    input: ParticipantGenerationInput<'_>,
) -> Result<GeneratedParticipantBody, JointContinuationError> {
    if context.plan_identity != plan.identity()? {
        return Err(JointContinuationError::InvalidContext);
    }
    validate_position(input.participant_position)?;
    let gate_count = plan.gates.len();
    if input.initial_wire_values.len() != usize::from(plan.input_wire_count)
        || input.initial_wire_values.iter().any(|value| *value > 0x0f)
        || input.gate_mask_shares.len() != gate_count * 2
        || input.gate_mask_shares.iter().any(|value| *value > 0x0f)
        || input.terminal_mask_shares.len() != plan.output_wires.len()
        || input.terminal_mask_shares.iter().any(|value| *value > 0x0f)
        || input.label_entropy.len() != plan.label_entropy_byte_length()?
        || input.own_affine_entropy.len() != gate_count * AFFINE_ENTROPY_BYTE_LENGTH
        || input.affine_commitments.len()
            != gate_count * usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) * Hash512::BYTE_LENGTH
        || input.affine_evaluations.len()
            != gate_count
                * usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
                * 2
                * MODULE_VALUE_BYTE_LENGTH
    {
        return Err(JointContinuationError::InvalidBody);
    }

    let all_affine_commitments = decode_hashes(input.affine_commitments)?;
    ensure_unique_commitments(&all_affine_commitments)?;
    let all_affine_evaluations = decode_affine_evaluations(input.affine_evaluations)?;
    let participant_index = usize::from(input.participant_position);
    let mut own_affine_material = Vec::with_capacity(gate_count);
    for gate_index in 0..gate_count {
        let entropy_start = gate_index * AFFINE_ENTROPY_BYTE_LENGTH;
        let derived = derive_affine_material(
            &input.own_affine_entropy[entropy_start..entropy_start + AFFINE_ENTROPY_BYTE_LENGTH],
        )?;
        let inventory_index =
            gate_index * usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) + participant_index;
        if all_affine_commitments.get(inventory_index) != Some(&derived.commitment)
            || all_affine_evaluations.get(inventory_index)
                != Some(&derived.evaluations[participant_index])
        {
            return Err(JointContinuationError::InvalidAffineMaterial);
        }
        own_affine_material.push(derived);
    }

    let mut entropy = LabelEntropyCursor::new(input.label_entropy);
    let mut body = Vec::with_capacity(plan.participant_body_byte_length()?);
    body.extend_from_slice(&BODY_MAGIC);
    body.extend_from_slice(&BODY_VERSION.to_le_bytes());
    body.extend_from_slice(context.target_identity.as_bytes());
    body.extend_from_slice(context.plan_identity.as_bytes());
    body.extend_from_slice(&COMPLETION_PROFILE_PARTICIPANT_COUNT.to_le_bytes());
    body.extend_from_slice(&input.participant_position.to_le_bytes());
    for material in &own_affine_material {
        body.extend_from_slice(material.commitment.as_bytes());
    }

    let wire_count = plan.wire_count()?;
    let mut wire_pairs = vec![None; wire_count];
    for (wire_index, value) in input.initial_wire_values.iter().copied().enumerate() {
        let pairs = entropy.read_field_pairs()?;
        for (basis, pair) in pairs.iter().enumerate() {
            write_token(&mut body, pair.tokens[usize::from((value >> basis) & 1)]);
        }
        wire_pairs[wire_index] = Some(pairs);
    }

    for (gate_index, gate) in plan.gates.iter().enumerate() {
        let left = wire_pairs
            .get(usize::from(gate.left_wire))
            .and_then(|pairs| *pairs)
            .ok_or(JointContinuationError::InvalidPlan)?;
        let right = wire_pairs
            .get(usize::from(gate.right_wire))
            .and_then(|pairs| *pairs)
            .ok_or(JointContinuationError::InvalidPlan)?;
        let low_mask_share = Gf16::new(input.gate_mask_shares[2 * gate_index]);
        let high_mask_share = Gf16::new(input.gate_mask_shares[2 * gate_index + 1]);
        let evaluation_start = gate_index * usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
        let commitment_start = evaluation_start;
        let output_pairs = generate_gate_payload(
            &mut body,
            context,
            input.participant_position,
            gate_index as u32,
            left,
            right,
            low_mask_share,
            high_mask_share,
            &all_affine_commitments[commitment_start
                ..commitment_start + usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)],
            &all_affine_evaluations[evaluation_start
                ..evaluation_start + usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)],
            &own_affine_material[gate_index],
            &mut entropy,
        )?;
        let output_wire = usize::from(plan.input_wire_count)
            .checked_add(gate_index)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        wire_pairs[output_wire] = Some(output_pairs);
    }

    for (output_index, output_wire) in plan.output_wires.iter().copied().enumerate() {
        let input_pairs = wire_pairs
            .get(usize::from(output_wire))
            .and_then(|pairs| *pairs)
            .ok_or(JointContinuationError::InvalidPlan)?;
        generate_terminal_payload(
            &mut body,
            context,
            input.participant_position,
            output_index as u32,
            input_pairs,
            Gf16::new(input.terminal_mask_shares[output_index]),
            &mut entropy,
        )?;
    }
    entropy.finish()?;
    if body.len() != plan.participant_body_byte_length()? {
        body.zeroize();
        return Err(JointContinuationError::InvalidBody);
    }
    let body_identity = hash_bytes(BODY_IDENTITY_DOMAIN, &body)?;
    Ok(GeneratedParticipantBody {
        body,
        body_identity,
        affine_commitments: own_affine_material
            .iter()
            .map(|material| material.commitment)
            .collect(),
    })
}

pub fn encode_activation_signature(
    participant_position: u16,
    body_identity: Hash512,
    signature: &[u8],
) -> Result<Vec<u8>, JointContinuationError> {
    ActionSignatureCarrier::new(
        COMPLETION_PROFILE_PARTICIPANT_COUNT,
        participant_position,
        ActionSignaturePurpose::Activation,
        body_identity,
        signature,
    )
    .map_err(|_| JointContinuationError::InvalidSignature)?
    .encode()
    .map_err(|_| JointContinuationError::InvalidSignature)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedJointContinuationBatch {
    pub batch_identity: Hash512,
    pub terminal_bits: Vec<bool>,
}

pub fn evaluate_signed_batch(
    capability: &VerifiedFinalityCapability,
    roster: &Roster,
    plan: &JointContinuationPlan,
    bodies: &[Vec<u8>],
    signatures: &[Vec<u8>],
) -> Result<EvaluatedJointContinuationBatch, JointContinuationError> {
    validate_capability(capability)?;
    validate_reviewed_reduced_plan(plan)?;
    if bodies.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || signatures.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
    {
        return Err(JointContinuationError::InvalidContext);
    }
    require_roster_identity(roster, capability.target.context().roster_identity)
        .map_err(|_| JointContinuationError::InvalidContext)?;
    let context = EvaluationContext {
        target_identity: capability.target_identity,
        plan_identity: plan.identity()?,
    };
    let mut body_identities = Vec::with_capacity(bodies.len());
    for position in 0..usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        let body_identity = hash_bytes(
            BODY_IDENTITY_DOMAIN,
            bodies
                .get(position)
                .ok_or(JointContinuationError::InvalidBody)?,
        )?;
        let carrier = ActionSignatureCarrier::decode(
            COMPLETION_PROFILE_PARTICIPANT_COUNT,
            signatures
                .get(position)
                .ok_or(JointContinuationError::InvalidSignature)?,
        )
        .map_err(|_| JointContinuationError::InvalidSignature)?;
        let verification_key = signing_verification_key(roster, position as u16)
            .map_err(|_| JointContinuationError::WrongParticipantPosition)?;
        carrier
            .verify(
                position as u16,
                ActionSignaturePurpose::Activation,
                body_identity,
                verification_key,
            )
            .map_err(|_| JointContinuationError::InvalidSignature)?;
        body_identities.push(body_identity);
    }
    evaluate_bodies(&context, plan, bodies, &body_identities)
}

fn evaluate_bodies(
    context: &EvaluationContext,
    plan: &JointContinuationPlan,
    bodies: &[Vec<u8>],
    body_identities: &[Hash512],
) -> Result<EvaluatedJointContinuationBatch, JointContinuationError> {
    if bodies.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || body_identities.len() != bodies.len()
    {
        return Err(JointContinuationError::WrongParticipantCount);
    }
    let mut parsed = Vec::with_capacity(bodies.len());
    let mut seen_positions = BTreeSet::new();
    let mut commitments = BTreeSet::new();
    for (expected_position, body) in bodies.iter().enumerate() {
        let parsed_body = ParsedBody::new(body, context, plan)?;
        if parsed_body.participant_position != expected_position as u16
            || !seen_positions.insert(parsed_body.participant_position)
        {
            return Err(JointContinuationError::DuplicateParticipant);
        }
        for commitment in &parsed_body.affine_commitments {
            if !commitments.insert(*commitment.as_bytes()) {
                return Err(JointContinuationError::DuplicateCommitment);
            }
        }
        parsed.push(parsed_body);
    }

    let wire_count = plan.wire_count()?;
    let mut active_tokens = vec![vec![None; wire_count]; bodies.len()];
    for (position, parsed_body) in parsed.iter().enumerate() {
        let initial = parsed_body.initial_tokens(plan)?;
        for (wire_index, tokens) in initial.into_iter().enumerate() {
            active_tokens[position][wire_index] = Some(tokens);
        }
    }

    for (gate_index, gate) in plan.gates.iter().enumerate() {
        let mut evaluated_gates = Vec::with_capacity(parsed.len());
        let mut masked_values = Vec::with_capacity(parsed.len());
        for (position, parsed_body) in parsed.iter().enumerate() {
            let left = active_tokens[position]
                .get(usize::from(gate.left_wire))
                .and_then(|tokens| *tokens)
                .ok_or(JointContinuationError::InvalidBody)?;
            let right = active_tokens[position]
                .get(usize::from(gate.right_wire))
                .and_then(|tokens| *tokens)
                .ok_or(JointContinuationError::InvalidBody)?;
            let evaluated =
                evaluate_gate_payload(parsed_body, context, plan, gate_index, left, right)?;
            masked_values.push(evaluated.masked_value);
            evaluated_gates.push(evaluated);
        }
        let selector = verify_masked_product_codeword(&masked_values)?;
        if selector.as_u8() > 1 {
            return Err(JointContinuationError::InvalidCodeword);
        }
        let mut refreshed = Vec::with_capacity(parsed.len());
        for receiver_position in 0..usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
            let receiver_commitment = parsed[receiver_position]
                .affine_commitments
                .get(gate_index)
                .copied()
                .ok_or(JointContinuationError::InvalidBody)?;
            let mut aggregate_evaluations = Vec::with_capacity(parsed.len());
            for (garbler_position, evaluated) in evaluated_gates.iter().enumerate() {
                let selected_row =
                    evaluated.joint_row(receiver_position, evaluated.masked_value)?;
                let mask = joint_row_mask(
                    context,
                    receiver_commitment,
                    garbler_position as u16,
                    receiver_position as u16,
                    gate_index as u32,
                    evaluated.masked_value,
                    &evaluated.masked_tokens,
                );
                let mut aggregate = selected_row;
                module_xor(&mut aggregate, &mask);
                aggregate_evaluations.push(aggregate);
            }
            let mut selected_key = interpolate_module_at_zero(&aggregate_evaluations)?;
            let receiver_gate = &evaluated_gates[receiver_position];
            let mut plaintext = receiver_gate.continuation_rows[usize::from(selector.as_u8())];
            let mask = continuation_row_mask(
                context,
                receiver_commitment,
                receiver_position as u16,
                gate_index as u32,
                selector.as_u8(),
                &selected_key,
            );
            xor_bytes(&mut plaintext, &mask);
            if plaintext[TOKEN_BYTE_LENGTH..].iter().any(|byte| *byte != 0) {
                plaintext.zeroize();
                selected_key.zeroize();
                return Err(JointContinuationError::ContinuationAuthenticationFailed);
            }
            let low_token = Token::decode(&plaintext[..TOKEN_BYTE_LENGTH])?;
            refreshed.push([
                low_token,
                receiver_gate.direct_output_tokens[0],
                receiver_gate.direct_output_tokens[1],
                receiver_gate.direct_output_tokens[2],
            ]);
            plaintext.zeroize();
            selected_key.zeroize();
        }
        let output_wire = usize::from(plan.input_wire_count)
            .checked_add(gate_index)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        for (position, tokens) in refreshed.into_iter().enumerate() {
            active_tokens[position][output_wire] = Some(tokens);
        }
    }

    let mut terminal_bits = Vec::with_capacity(plan.output_wires.len());
    for (output_index, output_wire) in plan.output_wires.iter().copied().enumerate() {
        let mut terminal_values = Vec::with_capacity(parsed.len());
        for (position, parsed_body) in parsed.iter().enumerate() {
            let input = active_tokens[position]
                .get(usize::from(output_wire))
                .and_then(|tokens| *tokens)
                .ok_or(JointContinuationError::InvalidBody)?;
            terminal_values.push(evaluate_terminal_payload(
                parsed_body,
                context,
                plan,
                output_index,
                input,
            )?);
        }
        let terminal = verify_terminal_codeword(&terminal_values)?;
        if terminal.as_u8() > 1 {
            return Err(JointContinuationError::InvalidCodeword);
        }
        terminal_bits.push(terminal == Gf16::ONE);
    }

    let identity_bytes = body_identities
        .iter()
        .flat_map(|identity| identity.as_bytes().iter().copied())
        .collect::<Vec<_>>();
    let batch_identity = hash_foundation_tuple_512(
        BATCH_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(context.target_identity.into_bytes()),
            CanonicalItem::hash512(context.plan_identity.into_bytes()),
            CanonicalItem::fixed_bytes(identity_bytes)
                .map_err(|_| JointContinuationError::InvalidBody)?,
        ],
    )
    .map_err(|_| JointContinuationError::InvalidBody)?;
    Ok(EvaluatedJointContinuationBatch {
        batch_identity,
        terminal_bits,
    })
}

#[derive(Clone, Copy)]
struct EvaluationContext {
    target_identity: Hash512,
    plan_identity: Hash512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Token {
    label: Label,
    color: u8,
}

impl Token {
    fn decode(bytes: &[u8]) -> Result<Self, JointContinuationError> {
        if bytes.len() != TOKEN_BYTE_LENGTH || bytes[LABEL_BYTE_LENGTH] > 1 {
            return Err(JointContinuationError::InvalidBody);
        }
        Ok(Self {
            label: bytes[..LABEL_BYTE_LENGTH]
                .try_into()
                .map_err(|_| JointContinuationError::InvalidBody)?,
            color: bytes[LABEL_BYTE_LENGTH],
        })
    }

    fn encode(self) -> [u8; TOKEN_BYTE_LENGTH] {
        let mut bytes = [0_u8; TOKEN_BYTE_LENGTH];
        bytes[..LABEL_BYTE_LENGTH].copy_from_slice(&self.label);
        bytes[LABEL_BYTE_LENGTH] = self.color;
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TokenPair {
    tokens: [Token; 2],
}

struct LabelEntropyCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    seen_labels: BTreeSet<Label>,
}

impl<'a> LabelEntropyCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            seen_labels: BTreeSet::new(),
        }
    }

    fn read_pair(&mut self) -> Result<TokenPair, JointContinuationError> {
        let end = self
            .offset
            .checked_add(TOKEN_PAIR_ENTROPY_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        if end > self.bytes.len() {
            return Err(JointContinuationError::InvalidLabelEntropy);
        }
        let first: Label = self.bytes[self.offset..self.offset + LABEL_BYTE_LENGTH]
            .try_into()
            .map_err(|_| JointContinuationError::InvalidLabelEntropy)?;
        let second: Label = self.bytes
            [self.offset + LABEL_BYTE_LENGTH..self.offset + 2 * LABEL_BYTE_LENGTH]
            .try_into()
            .map_err(|_| JointContinuationError::InvalidLabelEntropy)?;
        let first_color = self.bytes[self.offset + 2 * LABEL_BYTE_LENGTH];
        self.offset = end;
        if first_color > 1
            || first == second
            || !self.seen_labels.insert(first)
            || !self.seen_labels.insert(second)
        {
            return Err(JointContinuationError::InvalidLabelEntropy);
        }
        Ok(TokenPair {
            tokens: [
                Token {
                    label: first,
                    color: first_color,
                },
                Token {
                    label: second,
                    color: first_color ^ 1,
                },
            ],
        })
    }

    fn read_field_pairs(&mut self) -> Result<FieldPairs, JointContinuationError> {
        let mut pairs = [TokenPair {
            tokens: [Token {
                label: [0; LABEL_BYTE_LENGTH],
                color: 0,
            }; 2],
        }; FIELD_BIT_WIDTH];
        for pair in &mut pairs {
            *pair = self.read_pair()?;
        }
        Ok(pairs)
    }

    fn finish(self) -> Result<(), JointContinuationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(JointContinuationError::InvalidLabelEntropy)
        }
    }
}

struct GarblingBuilder<'context, 'cursor, 'entropy> {
    context: &'context EvaluationContext,
    participant_position: u16,
    major_ordinal: u32,
    kind: u8,
    next_gate_ordinal: u16,
    rows: Vec<[u8; TOKEN_BYTE_LENGTH]>,
    entropy: &'cursor mut LabelEntropyCursor<'entropy>,
}

impl<'context, 'cursor, 'entropy> GarblingBuilder<'context, 'cursor, 'entropy> {
    fn new(
        context: &'context EvaluationContext,
        participant_position: u16,
        major_ordinal: u32,
        kind: u8,
        entropy: &'cursor mut LabelEntropyCursor<'entropy>,
        gate_capacity: usize,
    ) -> Self {
        Self {
            context,
            participant_position,
            major_ordinal,
            kind,
            next_gate_ordinal: 0,
            rows: Vec::with_capacity(gate_capacity * 4),
            entropy,
        }
    }

    fn append_derived_gate(
        &mut self,
        left: TokenPair,
        right: TokenPair,
        conjunction: bool,
    ) -> Result<TokenPair, JointContinuationError> {
        let output = self.entropy.read_pair()?;
        self.append_gate(left, right, output, conjunction);
        Ok(output)
    }

    fn append_gate(
        &mut self,
        left: TokenPair,
        right: TokenPair,
        output: TokenPair,
        conjunction: bool,
    ) {
        self.rows.extend(garble_binary_gate(
            self.context,
            self.participant_position,
            self.kind,
            self.major_ordinal,
            self.next_gate_ordinal,
            left,
            right,
            output,
            conjunction,
        ));
        self.next_gate_ordinal += 1;
    }

    fn multiply_fields(
        &mut self,
        left: &FieldPairs,
        right: &FieldPairs,
    ) -> Result<FieldPairs, JointContinuationError> {
        let mut products = Vec::with_capacity(16);
        for position in 0..16 {
            products.push(self.append_derived_gate(
                left[position / 4],
                right[position % 4],
                true,
            )?);
        }
        let c0 = products[0];
        let c1 = self.append_derived_gate(products[1], products[4], false)?;
        let c2_left = self.append_derived_gate(products[2], products[5], false)?;
        let c2 = self.append_derived_gate(c2_left, products[8], false)?;
        let c3_left = self.append_derived_gate(products[3], products[6], false)?;
        let c3_right = self.append_derived_gate(products[9], products[12], false)?;
        let c3 = self.append_derived_gate(c3_left, c3_right, false)?;
        let c4_left = self.append_derived_gate(products[7], products[10], false)?;
        let c4 = self.append_derived_gate(c4_left, products[13], false)?;
        let c5 = self.append_derived_gate(products[11], products[14], false)?;
        let c6 = products[15];
        let d0 = self.append_derived_gate(c0, c4, false)?;
        let d1_left = self.append_derived_gate(c1, c4, false)?;
        let d1 = self.append_derived_gate(d1_left, c5, false)?;
        let d2_left = self.append_derived_gate(c2, c5, false)?;
        let d2 = self.append_derived_gate(d2_left, c6, false)?;
        let d3 = self.append_derived_gate(c3, c6, false)?;
        Ok([d0, d1, d2, d3])
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_gate_payload(
    body: &mut Vec<u8>,
    context: &EvaluationContext,
    participant_position: u16,
    gate_ordinal: u32,
    left: FieldPairs,
    right: FieldPairs,
    low_mask_share: Gf16,
    high_mask_share: Gf16,
    affine_commitments: &[Hash512],
    affine_evaluations: &[AffineEvaluation],
    own_affine_material: &DerivedAffineMaterial,
    entropy: &mut LabelEntropyCursor<'_>,
) -> Result<FieldPairs, JointContinuationError> {
    let mut builder = GarblingBuilder::new(
        context,
        participant_position,
        gate_ordinal,
        1,
        entropy,
        LOCAL_MULTIPLICATION_GATE_COUNT,
    );
    let product_pairs = builder.multiply_fields(&left, &right)?;
    let mask_pairs = builder.entropy.read_field_pairs()?;
    let masked_output_pairs = builder.entropy.read_field_pairs()?;
    for basis in 0..FIELD_BIT_WIDTH {
        builder.append_gate(
            product_pairs[basis],
            mask_pairs[basis],
            masked_output_pairs[basis],
            false,
        );
    }
    if usize::from(builder.next_gate_ordinal) != LOCAL_MULTIPLICATION_GATE_COUNT
        || builder.rows.len() != LOCAL_MULTIPLICATION_ROW_COUNT
    {
        return Err(JointContinuationError::InvalidBody);
    }
    for row in &builder.rows {
        body.extend_from_slice(row);
    }
    for (basis, pair) in mask_pairs.iter().enumerate() {
        write_token(
            body,
            pair.tokens[usize::from((high_mask_share.as_u8() >> basis) & 1)],
        );
    }
    body.push(semantic_map(&masked_output_pairs));

    if affine_commitments.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
        || affine_evaluations.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
    {
        return Err(JointContinuationError::InvalidAffineMaterial);
    }
    for receiver_position in 0..usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        for candidate in 0..16_u8 {
            let mut plaintext = affine_evaluations[receiver_position].affine_a;
            module_add_scaled(
                &mut plaintext,
                &affine_evaluations[receiver_position].affine_b,
                Gf16::new(candidate),
            );
            let candidate_tokens = core::array::from_fn(|basis| {
                masked_output_pairs[basis].tokens[usize::from((candidate >> basis) & 1)]
            });
            let mask = joint_row_mask(
                context,
                affine_commitments[receiver_position],
                participant_position,
                receiver_position as u16,
                gate_ordinal,
                Gf16::new(candidate),
                &candidate_tokens,
            );
            module_xor(&mut plaintext, &mask);
            body.extend_from_slice(&plaintext);
            plaintext.zeroize();
        }
    }

    let refreshed_output_pairs = builder.entropy.read_field_pairs()?;
    for candidate in 0..=1_u8 {
        let mut key = own_affine_material.constants[0];
        if candidate != 0 {
            module_xor(&mut key, &own_affine_material.constants[1]);
        }
        let candidate_share = low_mask_share.add(Gf16::new(candidate));
        let selected = refreshed_output_pairs[0].tokens[usize::from(candidate_share.as_u8() & 1)];
        let mut plaintext = [0_u8; CONTINUATION_ROW_BYTE_LENGTH];
        plaintext[..TOKEN_BYTE_LENGTH].copy_from_slice(&selected.encode());
        let mask = continuation_row_mask(
            context,
            own_affine_material.commitment,
            participant_position,
            gate_ordinal,
            candidate,
            &key,
        );
        xor_bytes(&mut plaintext, &mask);
        body.extend_from_slice(&plaintext);
        plaintext.zeroize();
        key.zeroize();
    }
    for (basis, pair) in refreshed_output_pairs.iter().enumerate().skip(1) {
        write_token(
            body,
            pair.tokens[usize::from((low_mask_share.as_u8() >> basis) & 1)],
        );
    }
    Ok(refreshed_output_pairs)
}

#[allow(clippy::too_many_arguments)]
fn generate_terminal_payload(
    body: &mut Vec<u8>,
    context: &EvaluationContext,
    participant_position: u16,
    output_ordinal: u32,
    input_pairs: FieldPairs,
    mask_share: Gf16,
    entropy: &mut LabelEntropyCursor<'_>,
) -> Result<(), JointContinuationError> {
    let mask_pairs = entropy.read_field_pairs()?;
    let output_pairs = entropy.read_field_pairs()?;
    for basis in 0..FIELD_BIT_WIDTH {
        let rows = garble_binary_gate(
            context,
            participant_position,
            2,
            output_ordinal,
            basis as u16,
            input_pairs[basis],
            mask_pairs[basis],
            output_pairs[basis],
            false,
        );
        for row in rows {
            body.extend_from_slice(&row);
        }
    }
    for (basis, pair) in mask_pairs.iter().enumerate() {
        write_token(
            body,
            pair.tokens[usize::from((mask_share.as_u8() >> basis) & 1)],
        );
    }
    body.push(semantic_map(&output_pairs));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn garble_binary_gate(
    context: &EvaluationContext,
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
    left: TokenPair,
    right: TokenPair,
    output: TokenPair,
    conjunction: bool,
) -> [[u8; TOKEN_BYTE_LENGTH]; 4] {
    let mut rows = [[0_u8; TOKEN_BYTE_LENGTH]; 4];
    for left_semantic in 0..=1_usize {
        for right_semantic in 0..=1_usize {
            let left_token = left.tokens[left_semantic];
            let right_token = right.tokens[right_semantic];
            let physical_row = usize::from(left_token.color | (right_token.color << 1));
            let output_semantic = if conjunction {
                left_semantic & right_semantic
            } else {
                left_semantic ^ right_semantic
            };
            let mut row = local_row_mask(
                context,
                participant_position,
                kind,
                major_ordinal,
                minor_ordinal,
                physical_row as u8,
                &left_token.label,
                &right_token.label,
            );
            xor_bytes(&mut row, &output.tokens[output_semantic].encode());
            rows[physical_row] = row;
        }
    }
    rows
}

#[allow(clippy::too_many_arguments)]
fn evaluate_binary_gate(
    context: &EvaluationContext,
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
    left: Token,
    right: Token,
    rows: &[[u8; TOKEN_BYTE_LENGTH]; 4],
) -> Result<Token, JointContinuationError> {
    let physical_row = usize::from(left.color | (right.color << 1));
    let mut plaintext = rows[physical_row];
    let mask = local_row_mask(
        context,
        participant_position,
        kind,
        major_ordinal,
        minor_ordinal,
        physical_row as u8,
        &left.label,
        &right.label,
    );
    xor_bytes(&mut plaintext, &mask);
    Token::decode(&plaintext)
}

struct ParsedBody<'a> {
    bytes: &'a [u8],
    participant_position: u16,
    affine_commitments: Vec<Hash512>,
    payload_offset: usize,
}

impl<'a> ParsedBody<'a> {
    fn new(
        bytes: &'a [u8],
        context: &EvaluationContext,
        plan: &JointContinuationPlan,
    ) -> Result<Self, JointContinuationError> {
        if bytes.len() != plan.participant_body_byte_length()? {
            return Err(JointContinuationError::InvalidBody);
        }
        let mut reader = ByteReader::new(bytes);
        if reader.read_array::<4>()? != BODY_MAGIC
            || reader.read_u16()? != BODY_VERSION
            || Hash512::from_bytes(reader.read_array::<64>()?) != context.target_identity
            || Hash512::from_bytes(reader.read_array::<64>()?) != context.plan_identity
            || reader.read_u16()? != COMPLETION_PROFILE_PARTICIPANT_COUNT
        {
            return Err(JointContinuationError::InvalidContext);
        }
        let participant_position = reader.read_u16()?;
        validate_position(participant_position)?;
        let mut affine_commitments = Vec::with_capacity(plan.gates.len());
        for _ in 0..plan.gates.len() {
            affine_commitments.push(Hash512::from_bytes(reader.read_array::<64>()?));
        }
        Ok(Self {
            bytes,
            participant_position,
            affine_commitments,
            payload_offset: reader.offset,
        })
    }

    fn initial_tokens(
        &self,
        plan: &JointContinuationPlan,
    ) -> Result<Vec<FieldTokens>, JointContinuationError> {
        let mut reader = ByteReader::new(&self.bytes[self.payload_offset..]);
        let mut initial = Vec::with_capacity(usize::from(plan.input_wire_count));
        for _ in 0..plan.input_wire_count {
            initial.push(read_field_tokens(&mut reader)?);
        }
        Ok(initial)
    }

    fn gate_bytes(
        &self,
        plan: &JointContinuationPlan,
        gate_index: usize,
    ) -> Result<&'a [u8], JointContinuationError> {
        if gate_index >= plan.gates.len() {
            return Err(JointContinuationError::InvalidPlan);
        }
        let initial_length = usize::from(plan.input_wire_count)
            .checked_mul(FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let start = self
            .payload_offset
            .checked_add(initial_length)
            .and_then(|offset| {
                gate_index
                    .checked_mul(GATE_PAYLOAD_BYTE_LENGTH)
                    .and_then(|gate_offset| offset.checked_add(gate_offset))
            })
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        self.bytes
            .get(start..start + GATE_PAYLOAD_BYTE_LENGTH)
            .ok_or(JointContinuationError::InvalidBody)
    }

    fn terminal_bytes(
        &self,
        plan: &JointContinuationPlan,
        output_index: usize,
    ) -> Result<&'a [u8], JointContinuationError> {
        if output_index >= plan.output_wires.len() {
            return Err(JointContinuationError::InvalidPlan);
        }
        let initial_length = usize::from(plan.input_wire_count)
            .checked_mul(FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let gate_length = plan
            .gates
            .len()
            .checked_mul(GATE_PAYLOAD_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let start = self
            .payload_offset
            .checked_add(initial_length)
            .and_then(|offset| offset.checked_add(gate_length))
            .and_then(|offset| {
                output_index
                    .checked_mul(TERMINAL_PAYLOAD_BYTE_LENGTH)
                    .and_then(|terminal_offset| offset.checked_add(terminal_offset))
            })
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        self.bytes
            .get(start..start + TERMINAL_PAYLOAD_BYTE_LENGTH)
            .ok_or(JointContinuationError::InvalidBody)
    }
}

struct EvaluatedGate<'a> {
    masked_tokens: FieldTokens,
    masked_value: Gf16,
    joint_rows: &'a [u8],
    continuation_rows: [[u8; CONTINUATION_ROW_BYTE_LENGTH]; 2],
    direct_output_tokens: [Token; FIELD_BIT_WIDTH - 1],
}

impl EvaluatedGate<'_> {
    fn joint_row(
        &self,
        receiver_position: usize,
        candidate: Gf16,
    ) -> Result<ModuleValue, JointContinuationError> {
        let row_index = receiver_position
            .checked_mul(16)
            .and_then(|index| index.checked_add(usize::from(candidate.as_u8())))
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let start = row_index
            .checked_mul(MODULE_VALUE_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        self.joint_rows
            .get(start..start + MODULE_VALUE_BYTE_LENGTH)
            .ok_or(JointContinuationError::InvalidBody)?
            .try_into()
            .map_err(|_| JointContinuationError::InvalidBody)
    }
}

fn evaluate_gate_payload<'a>(
    body: &ParsedBody<'a>,
    context: &EvaluationContext,
    plan: &JointContinuationPlan,
    gate_index: usize,
    left: FieldTokens,
    right: FieldTokens,
) -> Result<EvaluatedGate<'a>, JointContinuationError> {
    let gate_bytes = body.gate_bytes(plan, gate_index)?;
    let mut reader = ByteReader::new(gate_bytes);
    let row_bytes = reader.read_exact(LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH)?;
    let mask_tokens = read_field_tokens(&mut reader)?;
    let semantic_map = reader.read_u8()?;
    if semantic_map & 0xf0 != 0 {
        return Err(JointContinuationError::InvalidBody);
    }
    let joint_rows = reader.read_exact(JOINT_ROW_COUNT_PER_GARBLER * MODULE_VALUE_BYTE_LENGTH)?;
    let continuation_rows = [
        reader.read_array::<CONTINUATION_ROW_BYTE_LENGTH>()?,
        reader.read_array::<CONTINUATION_ROW_BYTE_LENGTH>()?,
    ];
    let direct_output_tokens = [
        read_token(&mut reader)?,
        read_token(&mut reader)?,
        read_token(&mut reader)?,
    ];
    reader.finish()?;

    let mut rows = LocalRowsReader::new(row_bytes);
    let (masked_tokens, consumed_gate_count) = {
        let mut builder = EvaluationGarblingBuilder {
            context,
            participant_position: body.participant_position,
            major_ordinal: gate_index as u32,
            kind: 1,
            next_gate_ordinal: 0,
            rows: &mut rows,
        };
        let product = builder.multiply_fields(&left, &right)?;
        let mut masked_tokens = [Token {
            label: [0; LABEL_BYTE_LENGTH],
            color: 0,
        }; FIELD_BIT_WIDTH];
        for basis in 0..FIELD_BIT_WIDTH {
            masked_tokens[basis] = builder.append_gate(product[basis], mask_tokens[basis])?;
        }
        (masked_tokens, usize::from(builder.next_gate_ordinal))
    };
    rows.finish()?;
    if consumed_gate_count != LOCAL_MULTIPLICATION_GATE_COUNT {
        return Err(JointContinuationError::InvalidBody);
    }
    let masked_value = decode_field_tokens(&masked_tokens, semantic_map)?;
    Ok(EvaluatedGate {
        masked_tokens,
        masked_value,
        joint_rows,
        continuation_rows,
        direct_output_tokens,
    })
}

struct LocalRowsReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> LocalRowsReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_rows(&mut self) -> Result<[[u8; TOKEN_BYTE_LENGTH]; 4], JointContinuationError> {
        Ok([
            self.read_row()?,
            self.read_row()?,
            self.read_row()?,
            self.read_row()?,
        ])
    }

    fn read_row(&mut self) -> Result<[u8; TOKEN_BYTE_LENGTH], JointContinuationError> {
        let end = self
            .offset
            .checked_add(TOKEN_BYTE_LENGTH)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let row = self
            .bytes
            .get(self.offset..end)
            .ok_or(JointContinuationError::InvalidBody)?
            .try_into()
            .map_err(|_| JointContinuationError::InvalidBody)?;
        self.offset = end;
        Ok(row)
    }

    fn finish(&self) -> Result<(), JointContinuationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(JointContinuationError::InvalidBody)
        }
    }
}

struct EvaluationGarblingBuilder<'a, 'b> {
    context: &'a EvaluationContext,
    participant_position: u16,
    major_ordinal: u32,
    kind: u8,
    next_gate_ordinal: u16,
    rows: &'b mut LocalRowsReader<'a>,
}

impl EvaluationGarblingBuilder<'_, '_> {
    fn append_gate(&mut self, left: Token, right: Token) -> Result<Token, JointContinuationError> {
        let rows = self.rows.read_rows()?;
        let output = evaluate_binary_gate(
            self.context,
            self.participant_position,
            self.kind,
            self.major_ordinal,
            self.next_gate_ordinal,
            left,
            right,
            &rows,
        )?;
        self.next_gate_ordinal += 1;
        Ok(output)
    }

    fn multiply_fields(
        &mut self,
        left: &FieldTokens,
        right: &FieldTokens,
    ) -> Result<FieldTokens, JointContinuationError> {
        let mut products = Vec::with_capacity(16);
        for position in 0..16 {
            products.push(self.append_gate(left[position / 4], right[position % 4])?);
        }
        let c0 = products[0];
        let c1 = self.append_gate(products[1], products[4])?;
        let c2_left = self.append_gate(products[2], products[5])?;
        let c2 = self.append_gate(c2_left, products[8])?;
        let c3_left = self.append_gate(products[3], products[6])?;
        let c3_right = self.append_gate(products[9], products[12])?;
        let c3 = self.append_gate(c3_left, c3_right)?;
        let c4_left = self.append_gate(products[7], products[10])?;
        let c4 = self.append_gate(c4_left, products[13])?;
        let c5 = self.append_gate(products[11], products[14])?;
        let c6 = products[15];
        let d0 = self.append_gate(c0, c4)?;
        let d1_left = self.append_gate(c1, c4)?;
        let d1 = self.append_gate(d1_left, c5)?;
        let d2_left = self.append_gate(c2, c5)?;
        let d2 = self.append_gate(d2_left, c6)?;
        let d3 = self.append_gate(c3, c6)?;
        Ok([d0, d1, d2, d3])
    }
}

fn evaluate_terminal_payload(
    body: &ParsedBody<'_>,
    context: &EvaluationContext,
    plan: &JointContinuationPlan,
    output_index: usize,
    input: FieldTokens,
) -> Result<Gf16, JointContinuationError> {
    let bytes = body.terminal_bytes(plan, output_index)?;
    let mut reader = ByteReader::new(bytes);
    let mut rows = Vec::with_capacity(FIELD_BIT_WIDTH);
    for _ in 0..FIELD_BIT_WIDTH {
        rows.push([
            reader.read_array::<TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<TOKEN_BYTE_LENGTH>()?,
        ]);
    }
    let mask_tokens = read_field_tokens(&mut reader)?;
    let semantic_map = reader.read_u8()?;
    reader.finish()?;
    if semantic_map & 0xf0 != 0 {
        return Err(JointContinuationError::InvalidBody);
    }
    let mut output = [Token {
        label: [0; LABEL_BYTE_LENGTH],
        color: 0,
    }; FIELD_BIT_WIDTH];
    for basis in 0..FIELD_BIT_WIDTH {
        output[basis] = evaluate_binary_gate(
            context,
            body.participant_position,
            2,
            output_index as u32,
            basis as u16,
            input[basis],
            mask_tokens[basis],
            &rows[basis],
        )?;
    }
    decode_field_tokens(&output, semantic_map)
}

fn semantic_map(pairs: &FieldPairs) -> u8 {
    pairs.iter().enumerate().fold(0_u8, |map, (basis, pair)| {
        map | (pair.tokens[0].color << basis)
    })
}

fn decode_field_tokens(
    tokens: &FieldTokens,
    semantic_map: u8,
) -> Result<Gf16, JointContinuationError> {
    if semantic_map & 0xf0 != 0 {
        return Err(JointContinuationError::InvalidBody);
    }
    Ok(Gf16::new(
        tokens
            .iter()
            .enumerate()
            .fold(0_u8, |value, (basis, token)| {
                value | ((token.color ^ ((semantic_map >> basis) & 1)) << basis)
            }),
    ))
}

fn verify_codeword(values: &[Gf16], degree: usize) -> Result<Gf16, JointContinuationError> {
    if values.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) || degree >= values.len() {
        return Err(JointContinuationError::InvalidCodeword);
    }
    let coefficients = interpolate_prefix(values, degree)?;
    for (position, value) in values.iter().copied().enumerate() {
        if evaluate_field_polynomial(&coefficients, Gf16::new((position + 1) as u8)) != value {
            return Err(JointContinuationError::InvalidCodeword);
        }
    }
    Ok(coefficients[0])
}

fn verify_masked_product_codeword(values: &[Gf16]) -> Result<Gf16, JointContinuationError> {
    verify_codeword(values, 6)
}

fn verify_terminal_codeword(values: &[Gf16]) -> Result<Gf16, JointContinuationError> {
    verify_codeword(values, 3)
}

fn interpolate_prefix(values: &[Gf16], degree: usize) -> Result<Vec<Gf16>, JointContinuationError> {
    let mut coefficients = vec![Gf16::ZERO; degree + 1];
    for (value_position, value) in values.iter().copied().enumerate().take(degree + 1) {
        let point = Gf16::new((value_position + 1) as u8);
        let mut basis = vec![Gf16::ONE];
        let mut denominator = Gf16::ONE;
        for other_position in 0..=degree {
            if other_position == value_position {
                continue;
            }
            let other_point = Gf16::new((other_position + 1) as u8);
            basis = multiply_field_polynomials(&basis, &[other_point, Gf16::ONE]);
            denominator = denominator.multiply(point.add(other_point));
        }
        let scale = value.multiply(
            denominator
                .inverse()
                .ok_or(JointContinuationError::InvalidCodeword)?,
        );
        for (coefficient, basis_coefficient) in coefficients.iter_mut().zip(basis) {
            *coefficient = coefficient.add(basis_coefficient.multiply(scale));
        }
    }
    Ok(coefficients)
}

fn multiply_field_polynomials(left: &[Gf16], right: &[Gf16]) -> Vec<Gf16> {
    let mut product = vec![Gf16::ZERO; left.len() + right.len() - 1];
    for (left_degree, left_coefficient) in left.iter().copied().enumerate() {
        for (right_degree, right_coefficient) in right.iter().copied().enumerate() {
            product[left_degree + right_degree] = product[left_degree + right_degree]
                .add(left_coefficient.multiply(right_coefficient));
        }
    }
    product
}

fn evaluate_field_polynomial(coefficients: &[Gf16], point: Gf16) -> Gf16 {
    coefficients
        .iter()
        .rev()
        .copied()
        .fold(Gf16::ZERO, |value, coefficient| {
            value.multiply(point).add(coefficient)
        })
}

fn evaluate_module_polynomial(coefficients: &[ModuleValue], point: Gf16) -> ModuleValue {
    let mut value = [0_u8; MODULE_VALUE_BYTE_LENGTH];
    for coefficient in coefficients.iter().rev() {
        let previous = value;
        value = *coefficient;
        module_add_scaled(&mut value, &previous, point);
    }
    value
}

fn interpolate_module_at_zero(
    values: &[ModuleValue],
) -> Result<ModuleValue, JointContinuationError> {
    if values.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        return Err(JointContinuationError::InvalidCodeword);
    }
    let mut result = [0_u8; MODULE_VALUE_BYTE_LENGTH];
    for (position, value) in values.iter().enumerate() {
        let point = Gf16::new((position + 1) as u8);
        let mut numerator = Gf16::ONE;
        let mut denominator = Gf16::ONE;
        for other_position in 0..usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
            if position == other_position {
                continue;
            }
            let other_point = Gf16::new((other_position + 1) as u8);
            numerator = numerator.multiply(other_point);
            denominator = denominator.multiply(point.add(other_point));
        }
        let weight = numerator.multiply(
            denominator
                .inverse()
                .ok_or(JointContinuationError::InvalidCodeword)?,
        );
        module_add_scaled(&mut result, value, weight);
    }
    Ok(result)
}

fn module_add_scaled(output: &mut ModuleValue, input: &ModuleValue, scalar: Gf16) {
    for (output_byte, input_byte) in output.iter_mut().zip(input) {
        let low = Gf16::new(*input_byte & 0x0f).multiply(scalar).as_u8();
        let high = Gf16::new(*input_byte >> 4).multiply(scalar).as_u8();
        *output_byte ^= low | (high << 4);
    }
}

fn module_xor(output: &mut ModuleValue, input: &ModuleValue) {
    xor_bytes(output, input);
}

fn xor_bytes<const LENGTH: usize>(output: &mut [u8; LENGTH], input: &[u8; LENGTH]) {
    for (output_byte, input_byte) in output.iter_mut().zip(input) {
        *output_byte ^= input_byte;
    }
}

#[allow(clippy::too_many_arguments)]
fn local_row_mask(
    context: &EvaluationContext,
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
    physical_row: u8,
    left_label: &Label,
    right_label: &Label,
) -> [u8; TOKEN_BYTE_LENGTH] {
    let mut hasher = contextual_xof(LOCAL_ROW_DOMAIN, context);
    hasher.update(&participant_position.to_le_bytes());
    hasher.update(&[kind]);
    hasher.update(&major_ordinal.to_le_bytes());
    hasher.update(&minor_ordinal.to_le_bytes());
    hasher.update(&[physical_row]);
    hasher.update(left_label);
    hasher.update(right_label);
    read_xof(hasher)
}

#[allow(clippy::too_many_arguments)]
fn joint_row_mask(
    context: &EvaluationContext,
    affine_commitment: Hash512,
    garbler_position: u16,
    receiver_position: u16,
    gate_ordinal: u32,
    candidate: Gf16,
    candidate_tokens: &FieldTokens,
) -> ModuleValue {
    let mut hasher = contextual_xof(JOINT_ROW_DOMAIN, context);
    hasher.update(affine_commitment.as_bytes());
    hasher.update(&garbler_position.to_le_bytes());
    hasher.update(&receiver_position.to_le_bytes());
    hasher.update(&gate_ordinal.to_le_bytes());
    hasher.update(&[candidate.as_u8()]);
    for token in candidate_tokens {
        hasher.update(&token.label);
    }
    read_xof(hasher)
}

#[allow(clippy::too_many_arguments)]
fn continuation_row_mask(
    context: &EvaluationContext,
    affine_commitment: Hash512,
    receiver_position: u16,
    gate_ordinal: u32,
    candidate: u8,
    key: &ModuleValue,
) -> [u8; CONTINUATION_ROW_BYTE_LENGTH] {
    let mut hasher = contextual_xof(CONTINUATION_ROW_DOMAIN, context);
    hasher.update(affine_commitment.as_bytes());
    hasher.update(&receiver_position.to_le_bytes());
    hasher.update(&gate_ordinal.to_le_bytes());
    hasher.update(&[candidate]);
    hasher.update(key);
    read_xof(hasher)
}

fn contextual_xof(domain: &[u8], context: &EvaluationContext) -> Shake256 {
    let mut hasher = Shake256::default();
    hasher.update(&(domain.len() as u16).to_le_bytes());
    hasher.update(domain);
    hasher.update(context.target_identity.as_bytes());
    hasher.update(context.plan_identity.as_bytes());
    hasher
}

fn read_xof<const LENGTH: usize>(hasher: Shake256) -> [u8; LENGTH] {
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; LENGTH];
    reader.read(&mut output);
    output
}

fn hash_bytes(domain: &str, bytes: &[u8]) -> Result<Hash512, JointContinuationError> {
    hash_foundation_tuple_512(
        domain,
        &[
            CanonicalItem::variable_bytes(bytes)
                .map_err(|_| JointContinuationError::InvalidBody)?,
        ],
    )
    .map_err(|_| JointContinuationError::InvalidBody)
}

fn validate_capability(
    capability: &VerifiedFinalityCapability,
) -> Result<(), JointContinuationError> {
    if capability.target.context().participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(JointContinuationError::WrongParticipantCount);
    }
    if capability.target.target_kind() != FinalityTargetKind::Computation {
        return Err(JointContinuationError::WrongTargetKind);
    }
    if capability
        .target
        .body_identity()
        .map_err(|_| JointContinuationError::InvalidContext)?
        != capability.target_identity
    {
        return Err(JointContinuationError::InvalidContext);
    }
    Ok(())
}

fn validate_position(position: u16) -> Result<(), JointContinuationError> {
    if position < COMPLETION_PROFILE_PARTICIPANT_COUNT {
        Ok(())
    } else {
        Err(JointContinuationError::WrongParticipantPosition)
    }
}

fn decode_hashes(bytes: &[u8]) -> Result<Vec<Hash512>, JointContinuationError> {
    if !bytes.len().is_multiple_of(Hash512::BYTE_LENGTH) {
        return Err(JointContinuationError::InvalidAffineMaterial);
    }
    bytes
        .chunks_exact(Hash512::BYTE_LENGTH)
        .map(|chunk| {
            Ok(Hash512::from_bytes(chunk.try_into().map_err(|_| {
                JointContinuationError::InvalidAffineMaterial
            })?))
        })
        .collect()
}

fn decode_affine_evaluations(
    bytes: &[u8],
) -> Result<Vec<AffineEvaluation>, JointContinuationError> {
    if !bytes.len().is_multiple_of(2 * MODULE_VALUE_BYTE_LENGTH) {
        return Err(JointContinuationError::InvalidAffineMaterial);
    }
    bytes
        .chunks_exact(2 * MODULE_VALUE_BYTE_LENGTH)
        .map(|chunk| {
            Ok(AffineEvaluation {
                affine_a: chunk[..MODULE_VALUE_BYTE_LENGTH]
                    .try_into()
                    .map_err(|_| JointContinuationError::InvalidAffineMaterial)?,
                affine_b: chunk[MODULE_VALUE_BYTE_LENGTH..]
                    .try_into()
                    .map_err(|_| JointContinuationError::InvalidAffineMaterial)?,
            })
        })
        .collect()
}

fn ensure_unique_commitments(commitments: &[Hash512]) -> Result<(), JointContinuationError> {
    let mut seen = BTreeSet::new();
    for commitment in commitments {
        if !seen.insert(*commitment.as_bytes()) {
            return Err(JointContinuationError::DuplicateCommitment);
        }
    }
    Ok(())
}

fn write_token(bytes: &mut Vec<u8>, token: Token) {
    bytes.extend_from_slice(&token.encode());
}

fn read_token(reader: &mut ByteReader<'_>) -> Result<Token, JointContinuationError> {
    Token::decode(reader.read_exact(TOKEN_BYTE_LENGTH)?)
}

fn read_field_tokens(reader: &mut ByteReader<'_>) -> Result<FieldTokens, JointContinuationError> {
    Ok([
        read_token(reader)?,
        read_token(reader)?,
        read_token(reader)?,
        read_token(reader)?,
    ])
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], JointContinuationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(JointContinuationError::ArithmeticOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(JointContinuationError::InvalidBody)?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], JointContinuationError> {
        self.read_exact(LENGTH)?
            .try_into()
            .map_err(|_| JointContinuationError::InvalidBody)
    }

    fn read_u8(&mut self) -> Result<u8, JointContinuationError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, JointContinuationError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn finish(self) -> Result<(), JointContinuationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(JointContinuationError::InvalidBody)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARTICIPANT_COUNT: usize = COMPLETION_PROFILE_PARTICIPANT_COUNT as usize;

    struct ReducedFixture {
        context: EvaluationContext,
        plan: JointContinuationPlan,
        bodies: Vec<Vec<u8>>,
        body_identities: Vec<Hash512>,
        affine_material: Vec<Vec<DerivedAffineMaterial>>,
        high_mask_polynomials: Vec<Vec<Gf16>>,
        label_entropy: Vec<Vec<u8>>,
        wire_polynomials: Vec<Vec<Gf16>>,
        selectors: Vec<u8>,
        expected_terminal_bits: Vec<bool>,
    }

    fn reduced_plan() -> JointContinuationPlan {
        reviewed_reduced_plan().expect("reduced relation plan")
    }

    fn deterministic_affine_entropy(gate_index: usize, receiver_position: usize) -> Vec<u8> {
        let identity = (gate_index * PARTICIPANT_COUNT + receiver_position + 1) as u64;
        let mut entropy = vec![0_u8; AFFINE_ENTROPY_BYTE_LENGTH];
        for (index, byte) in entropy.iter_mut().enumerate() {
            *byte = (identity as u8)
                .wrapping_mul(41)
                .wrapping_add((index as u8).wrapping_mul(73))
                .wrapping_add((index >> 8) as u8);
        }
        entropy[..8].copy_from_slice(&identity.to_le_bytes());
        entropy[10 * MODULE_VALUE_BYTE_LENGTH..10 * MODULE_VALUE_BYTE_LENGTH + 8]
            .copy_from_slice(&(!identity).to_le_bytes());
        entropy
    }

    fn deterministic_label_entropy(
        plan: &JointContinuationPlan,
        participant_position: usize,
    ) -> Vec<u8> {
        let length = plan
            .label_entropy_byte_length()
            .expect("reduced entropy length");
        let pair_count = length / TOKEN_PAIR_ENTROPY_BYTE_LENGTH;
        let mut entropy = Vec::with_capacity(length);
        for pair_index in 0..pair_count {
            for semantic in 0..2_u64 {
                let label_identity = ((participant_position as u64 + 1) << 48)
                    | ((pair_index as u64) << 1)
                    | semantic;
                let mut label = [0_u8; LABEL_BYTE_LENGTH];
                label[..8].copy_from_slice(&label_identity.to_le_bytes());
                for (index, byte) in label[8..].iter_mut().enumerate() {
                    *byte = (label_identity as u8)
                        .wrapping_mul(29)
                        .wrapping_add((index as u8).wrapping_mul(101))
                        .wrapping_add((label_identity >> ((index % 7) + 1)) as u8);
                }
                entropy.extend_from_slice(&label);
            }
            entropy.push(((participant_position + pair_index) & 1) as u8);
        }
        assert_eq!(entropy.len(), length);
        entropy
    }

    fn polynomial(constant: u8, degree: usize, domain: usize) -> Vec<Gf16> {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(Gf16::new(constant));
        for coefficient_index in 1..=degree {
            coefficients.push(Gf16::new((domain * 7 + coefficient_index * 5 + 3) as u8));
        }
        coefficients
    }

    fn build_reduced_fixture() -> ReducedFixture {
        let plan = reduced_plan();
        let context = EvaluationContext {
            target_identity: Hash512::from_bytes([0xa5; Hash512::BYTE_LENGTH]),
            plan_identity: plan.identity().expect("plan identity"),
        };

        let input_bits = [1_u8, 1, 1, 0];
        let mut wire_polynomials = input_bits
            .iter()
            .copied()
            .enumerate()
            .map(|(wire_index, bit)| polynomial(bit, 3, wire_index + 1))
            .collect::<Vec<_>>();
        let mut gate_masks = (0..PARTICIPANT_COUNT)
            .map(|_| Vec::with_capacity(plan.gates.len() * 2))
            .collect::<Vec<_>>();
        let mut high_mask_polynomials = Vec::with_capacity(plan.gates.len());
        let mut selectors = Vec::with_capacity(plan.gates.len());
        for (gate_index, gate) in plan.gates.iter().enumerate() {
            let product = multiply_field_polynomials(
                &wire_polynomials[usize::from(gate.left_wire)],
                &wire_polynomials[usize::from(gate.right_wire)],
            );
            let selector = (gate_index & 1) as u8;
            let mask_constant = product[0].as_u8() ^ selector;
            let low_mask = polynomial(mask_constant, 3, 100 + gate_index);
            let high_mask = polynomial(mask_constant, 6, 200 + gate_index);
            for (participant_position, shares) in gate_masks.iter_mut().enumerate() {
                let point = Gf16::new((participant_position + 1) as u8);
                shares.push(evaluate_field_polynomial(&low_mask, point).as_u8());
                shares.push(evaluate_field_polynomial(&high_mask, point).as_u8());
            }
            let mut refreshed = low_mask;
            refreshed[0] = product[0];
            wire_polynomials.push(refreshed);
            high_mask_polynomials.push(high_mask);
            selectors.push(selector);
        }

        let mut initial_values = (0..PARTICIPANT_COUNT)
            .map(|_| Vec::with_capacity(input_bits.len()))
            .collect::<Vec<_>>();
        for (participant_position, values) in initial_values.iter_mut().enumerate() {
            let point = Gf16::new((participant_position + 1) as u8);
            for polynomial in wire_polynomials.iter().take(input_bits.len()) {
                values.push(evaluate_field_polynomial(polynomial, point).as_u8());
            }
        }

        let mut terminal_masks = (0..PARTICIPANT_COUNT)
            .map(|_| Vec::with_capacity(plan.output_wires.len()))
            .collect::<Vec<_>>();
        for output_index in 0..plan.output_wires.len() {
            let mask = polynomial(0, 3, 300 + output_index);
            for (participant_position, shares) in terminal_masks.iter_mut().enumerate() {
                shares.push(
                    evaluate_field_polynomial(&mask, Gf16::new((participant_position + 1) as u8))
                        .as_u8(),
                );
            }
        }
        let expected_terminal_bits = plan
            .output_wires
            .iter()
            .map(|wire| wire_polynomials[usize::from(*wire)][0] == Gf16::ONE)
            .collect::<Vec<_>>();

        let mut affine_entropy = vec![vec![Vec::new(); PARTICIPANT_COUNT]; plan.gates.len()];
        let mut affine_material = vec![Vec::with_capacity(PARTICIPANT_COUNT); plan.gates.len()];
        for gate_index in 0..plan.gates.len() {
            for receiver_position in 0..PARTICIPANT_COUNT {
                let entropy = deterministic_affine_entropy(gate_index, receiver_position);
                affine_material[gate_index].push(
                    derive_affine_material(&entropy).expect("fixture affine material derives"),
                );
                affine_entropy[gate_index][receiver_position] = entropy;
            }
        }

        let affine_commitments = affine_material
            .iter()
            .flat_map(|gate| gate.iter())
            .flat_map(|material| material.commitment.as_bytes().iter().copied())
            .collect::<Vec<_>>();
        let mut bodies = Vec::with_capacity(PARTICIPANT_COUNT);
        let mut body_identities = Vec::with_capacity(PARTICIPANT_COUNT);
        let mut label_entropy_corpora = Vec::with_capacity(PARTICIPANT_COUNT);
        for participant_position in 0..PARTICIPANT_COUNT {
            let own_affine_entropy = affine_entropy
                .iter()
                .flat_map(|gate| gate[participant_position].iter().copied())
                .collect::<Vec<_>>();
            let affine_evaluations = affine_material
                .iter()
                .flat_map(|gate| gate.iter())
                .flat_map(|material| {
                    let evaluation = material.evaluations[participant_position];
                    evaluation.affine_a.into_iter().chain(evaluation.affine_b)
                })
                .collect::<Vec<_>>();
            let label_entropy = deterministic_label_entropy(&plan, participant_position);
            let generated = generate_participant_body_for_context(
                &context,
                &plan,
                ParticipantGenerationInput {
                    participant_position: participant_position as u16,
                    initial_wire_values: &initial_values[participant_position],
                    gate_mask_shares: &gate_masks[participant_position],
                    terminal_mask_shares: &terminal_masks[participant_position],
                    label_entropy: &label_entropy,
                    own_affine_entropy: &own_affine_entropy,
                    affine_commitments: &affine_commitments,
                    affine_evaluations: &affine_evaluations,
                },
            )
            .expect("participant body generates");
            assert_eq!(generated.body.len(), 109_859);
            body_identities.push(generated.body_identity);
            bodies.push(generated.body);
            label_entropy_corpora.push(label_entropy);
        }

        ReducedFixture {
            context,
            plan,
            bodies,
            body_identities,
            affine_material,
            high_mask_polynomials,
            label_entropy: label_entropy_corpora,
            wire_polynomials,
            selectors,
            expected_terminal_bits,
        }
    }

    fn gate_payload_offset(plan: &JointContinuationPlan, gate_index: usize) -> usize {
        let header_length =
            4 + 2 + 2 * Hash512::BYTE_LENGTH + 2 + 2 + plan.gates.len() * Hash512::BYTE_LENGTH;
        header_length
            + usize::from(plan.input_wire_count) * FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH
            + gate_index * GATE_PAYLOAD_BYTE_LENGTH
    }

    fn terminal_payload_offset(plan: &JointContinuationPlan, output_index: usize) -> usize {
        gate_payload_offset(plan, plan.gates.len()) + output_index * TERMINAL_PAYLOAD_BYTE_LENGTH
    }

    fn evaluated_initial_gate<'a>(
        fixture: &'a ReducedFixture,
        participant_position: usize,
        gate_index: usize,
    ) -> (ParsedBody<'a>, EvaluatedGate<'a>) {
        let parsed = ParsedBody::new(
            &fixture.bodies[participant_position],
            &fixture.context,
            &fixture.plan,
        )
        .expect("fixture body parses");
        let initial = parsed
            .initial_tokens(&fixture.plan)
            .expect("initial tokens");
        let gate = fixture.plan.gates[gate_index];
        assert!(usize::from(gate.left_wire) < usize::from(fixture.plan.input_wire_count));
        assert!(usize::from(gate.right_wire) < usize::from(fixture.plan.input_wire_count));
        let evaluated = evaluate_gate_payload(
            &parsed,
            &fixture.context,
            &fixture.plan,
            gate_index,
            initial[usize::from(gate.left_wire)],
            initial[usize::from(gate.right_wire)],
        )
        .expect("initial-input fixture gate evaluates");
        (parsed, evaluated)
    }

    fn body_identities(bodies: &[Vec<u8>]) -> Vec<Hash512> {
        bodies
            .iter()
            .map(|body| hash_bytes(BODY_IDENTITY_DOMAIN, body).expect("body identity"))
            .collect()
    }

    fn interpolation_weights_at_zero() -> [Gf16; PARTICIPANT_COUNT] {
        core::array::from_fn(|position| {
            let point = Gf16::new((position + 1) as u8);
            let mut numerator = Gf16::ONE;
            let mut denominator = Gf16::ONE;
            for other_position in 0..PARTICIPANT_COUNT {
                if position == other_position {
                    continue;
                }
                let other_point = Gf16::new((other_position + 1) as u8);
                numerator = numerator.multiply(other_point);
                denominator = denominator.multiply(point.add(other_point));
            }
            numerator.multiply(denominator.inverse().expect("distinct interpolation point"))
        })
    }

    fn counterfactual_authenticator(
        fixture: &ReducedFixture,
        gate_index: usize,
        receiver_position: usize,
    ) -> [u8; CONTINUATION_AUTHENTICATOR_BYTE_LENGTH] {
        let parsed = ParsedBody::new(
            &fixture.bodies[receiver_position],
            &fixture.context,
            &fixture.plan,
        )
        .expect("fixture body parses");
        let initial = parsed
            .initial_tokens(&fixture.plan)
            .expect("initial tokens");
        let gate = fixture.plan.gates[gate_index];
        let evaluated = evaluate_gate_payload(
            &parsed,
            &fixture.context,
            &fixture.plan,
            gate_index,
            initial[usize::from(gate.left_wire)],
            initial[usize::from(gate.right_wire)],
        )
        .expect("initial-only fixture gate evaluates");
        let selected = fixture.selectors[gate_index];
        let mut selected_key = fixture.affine_material[gate_index][receiver_position].constants[0];
        if selected != 0 {
            module_xor(
                &mut selected_key,
                &fixture.affine_material[gate_index][receiver_position].constants[1],
            );
        }
        let counterfactual = selected ^ 1;
        let mut plaintext = evaluated.continuation_rows[usize::from(counterfactual)];
        let mask = continuation_row_mask(
            &fixture.context,
            parsed.affine_commitments[gate_index],
            receiver_position as u16,
            gate_index as u32,
            counterfactual,
            &selected_key,
        );
        xor_bytes(&mut plaintext, &mask);
        plaintext[TOKEN_BYTE_LENGTH..]
            .try_into()
            .expect("authenticator has fixed length")
    }

    #[test]
    fn affine_material_uses_exact_entropy_and_distinct_keys() {
        let mut entropy = [0_u8; AFFINE_ENTROPY_BYTE_LENGTH];
        for (index, byte) in entropy.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(73).wrapping_add(19);
        }
        let material = derive_affine_material(&entropy).expect("affine material derives");
        assert_eq!(material.evaluations.len(), 10);
        assert_ne!(material.constants[1], [0_u8; MODULE_VALUE_BYTE_LENGTH]);
        assert_eq!(
            material.evaluations[0].affine_a.len(),
            MODULE_VALUE_BYTE_LENGTH
        );

        let mut repeated = entropy;
        repeated[0] ^= 1;
        assert_ne!(
            derive_affine_material(&repeated)
                .expect("different entropy derives")
                .commitment,
            material.commitment
        );
        assert_eq!(
            derive_affine_material(&[0_u8; AFFINE_ENTROPY_BYTE_LENGTH]),
            Err(JointContinuationError::InvalidAffineMaterial)
        );

        let mut zero_difference_constant = [0_u8; AFFINE_ENTROPY_BYTE_LENGTH];
        zero_difference_constant[0] = 1;
        zero_difference_constant[11 * MODULE_VALUE_BYTE_LENGTH] = 1;
        assert_eq!(
            derive_affine_material(&zero_difference_constant),
            Err(JointContinuationError::InvalidAffineMaterial)
        );
    }

    #[test]
    fn label_entropy_preserves_both_labels_and_the_canonical_point_bit() {
        let mut entropy = [0_u8; TOKEN_PAIR_ENTROPY_BYTE_LENGTH];
        entropy[..LABEL_BYTE_LENGTH].fill(0x31);
        entropy[LABEL_BYTE_LENGTH..2 * LABEL_BYTE_LENGTH].fill(0xc7);
        entropy[2 * LABEL_BYTE_LENGTH] = 1;
        let pair = LabelEntropyCursor::new(&entropy)
            .read_pair()
            .expect("canonical entropy pair");
        assert_eq!(pair.tokens[0].label, [0x31; LABEL_BYTE_LENGTH]);
        assert_eq!(pair.tokens[1].label, [0xc7; LABEL_BYTE_LENGTH]);
        assert_eq!(pair.tokens[0].color, 1);
        assert_eq!(pair.tokens[1].color, 0);

        entropy[2 * LABEL_BYTE_LENGTH] = 2;
        assert_eq!(
            LabelEntropyCursor::new(&entropy).read_pair(),
            Err(JointContinuationError::InvalidLabelEntropy)
        );
    }

    #[test]
    fn plan_binds_serial_fanout_and_multiple_outputs() {
        let plan = reduced_plan();
        let encoded = plan.encode().expect("plan encodes");
        assert_eq!(
            encoded,
            vec![
                0x53, 0x4c, 0x4a, 0x50, 0x01, 0x00, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x03, 0x00, 0x06, 0x00,
                0x07, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0x03, 0x00, 0x04, 0x00,
                0x07, 0x00, 0x0a, 0x00,
            ]
        );
        assert_eq!(JointContinuationPlan::decode(&encoded), Ok(plan.clone()));
        assert_eq!(
            plan.identity().expect("plan identity").into_bytes(),
            [
                157, 248, 115, 223, 35, 202, 98, 63, 207, 103, 235, 143, 211, 62, 216, 196, 56,
                200, 122, 0, 210, 177, 229, 156, 125, 104, 207, 254, 52, 82, 116, 217, 45, 53, 0,
                116, 29, 223, 15, 211, 213, 33, 122, 94, 145, 183, 162, 246, 239, 124, 117, 84, 37,
                209, 22, 245, 219, 181, 17, 50, 214, 158, 243, 102,
            ]
        );
        assert_eq!(plan.gates.len(), 7);
        assert_eq!(plan.label_entropy_byte_length(), Ok(33_077));
        assert_eq!(plan.participant_body_byte_length(), Ok(109_859));

        let alternate = JointContinuationPlan::new(
            4,
            vec![JointContinuationGate {
                left_wire: 0,
                right_wire: 1,
            }],
            vec![0],
        )
        .expect("syntactically valid alternate plan");
        assert_eq!(
            validate_reviewed_reduced_plan(&alternate),
            Err(JointContinuationError::InvalidPlan)
        );
    }

    #[test]
    fn emitted_masked_coordinates_use_the_degree_six_mask() {
        let fixture = build_reduced_fixture();
        let gate = fixture.plan.gates[0];
        for participant_position in 0..PARTICIPANT_COUNT {
            let (_, evaluated) = evaluated_initial_gate(&fixture, participant_position, 0);
            let point = Gf16::new((participant_position + 1) as u8);
            let left = evaluate_field_polynomial(
                &fixture.wire_polynomials[usize::from(gate.left_wire)],
                point,
            );
            let right = evaluate_field_polynomial(
                &fixture.wire_polynomials[usize::from(gate.right_wire)],
                point,
            );
            let high_mask = evaluate_field_polynomial(&fixture.high_mask_polynomials[0], point);
            assert_eq!(evaluated.masked_value, left.multiply(right).add(high_mask));
        }
    }

    #[test]
    fn refreshed_opaque_token_uses_the_supplied_random_point_bit() {
        let fixture = build_reduced_fixture();
        let receiver_position = 0;
        let gate_index = 0;
        let (parsed, evaluated) = evaluated_initial_gate(&fixture, receiver_position, gate_index);
        let selector = fixture.selectors[gate_index];
        let mut key = fixture.affine_material[gate_index][receiver_position].constants[0];
        if selector != 0 {
            module_xor(
                &mut key,
                &fixture.affine_material[gate_index][receiver_position].constants[1],
            );
        }
        let mut plaintext = evaluated.continuation_rows[usize::from(selector)];
        let mask = continuation_row_mask(
            &fixture.context,
            parsed.affine_commitments[gate_index],
            receiver_position as u16,
            gate_index as u32,
            selector,
            &key,
        );
        xor_bytes(&mut plaintext, &mask);
        let selected = Token::decode(&plaintext[..TOKEN_BYTE_LENGTH]).expect("selected token");

        let refreshed_pair_index = usize::from(fixture.plan.input_wire_count) * FIELD_BIT_WIDTH
            + 31
            + FIELD_BIT_WIDTH
            + FIELD_BIT_WIDTH;
        let mut entropy = LabelEntropyCursor::new(&fixture.label_entropy[receiver_position]);
        for _ in 0..refreshed_pair_index {
            entropy.read_pair().expect("preceding entropy pair");
        }
        let low_pair = entropy.read_pair().expect("refreshed low pair");
        let refreshed_share = evaluate_field_polynomial(
            &fixture.wire_polynomials[usize::from(fixture.plan.input_wire_count)],
            Gf16::new(1),
        );
        assert_eq!(
            selected,
            low_pair.tokens[usize::from(refreshed_share.as_u8() & 1)]
        );
        assert_eq!(low_pair.tokens[0].color, 1);
        assert_eq!(low_pair.tokens[1].color, 0);
    }

    #[test]
    fn reduced_batch_composes_serial_fanout_and_multiple_outputs() {
        let fixture = build_reduced_fixture();
        assert_eq!(
            fixture.body_identities[0].into_bytes(),
            [
                238, 230, 197, 6, 250, 234, 245, 9, 38, 109, 2, 255, 19, 159, 212, 58, 171, 153,
                93, 74, 80, 239, 45, 66, 58, 76, 34, 213, 245, 150, 55, 81, 44, 163, 25, 232, 101,
                105, 249, 72, 192, 99, 8, 183, 104, 19, 239, 153, 220, 167, 212, 197, 137, 81, 43,
                176, 216, 89, 196, 247, 47, 24, 252, 15,
            ]
        );
        assert!(fixture.selectors.contains(&0));
        assert!(fixture.selectors.contains(&1));
        let result = evaluate_bodies(
            &fixture.context,
            &fixture.plan,
            &fixture.bodies,
            &fixture.body_identities,
        )
        .expect("reduced batch evaluates");
        assert_eq!(
            result.batch_identity.into_bytes(),
            [
                183, 217, 32, 194, 47, 172, 193, 108, 79, 209, 40, 174, 53, 101, 56, 64, 170, 94,
                248, 40, 137, 115, 180, 109, 56, 9, 166, 126, 222, 87, 93, 63, 27, 200, 86, 91, 3,
                166, 156, 134, 3, 157, 30, 37, 174, 86, 31, 117, 61, 47, 240, 211, 218, 142, 20,
                207, 84, 209, 225, 4, 63, 16, 119, 131,
            ]
        );
        assert_eq!(result.terminal_bits, fixture.expected_terminal_bits);
        assert_eq!(result.terminal_bits, vec![true, false, false]);
    }

    #[test]
    fn selected_key_rejects_both_cross_gate_counterfactual_rows() {
        let fixture = build_reduced_fixture();
        assert_eq!(fixture.selectors[0], 0);
        assert_eq!(fixture.selectors[1], 1);
        for gate_index in 0..=1 {
            assert!(
                counterfactual_authenticator(&fixture, gate_index, 0)
                    .iter()
                    .any(|byte| *byte != 0),
                "the selected key must not authenticate the other row at gate {gate_index}"
            );
        }
    }

    #[test]
    fn selected_labels_do_not_open_any_counterfactual_joint_aggregate() {
        let fixture = build_reduced_fixture();
        for gate_index in 0..=1 {
            let receiver_position = 0;
            let mut counterfactual_evaluations = Vec::with_capacity(PARTICIPANT_COUNT);
            for garbler_position in 0..PARTICIPANT_COUNT {
                let (_parsed, evaluated) =
                    evaluated_initial_gate(&fixture, garbler_position, gate_index);
                let selected_candidate = evaluated.masked_value;
                let selected_mask = joint_row_mask(
                    &fixture.context,
                    fixture.affine_material[gate_index][receiver_position].commitment,
                    garbler_position as u16,
                    receiver_position as u16,
                    gate_index as u32,
                    selected_candidate,
                    &evaluated.masked_tokens,
                );
                for basis in 0..FIELD_BIT_WIDTH {
                    let mut changed_tokens = evaluated.masked_tokens;
                    changed_tokens[basis].label[0] ^= 1;
                    assert_ne!(
                        joint_row_mask(
                            &fixture.context,
                            fixture.affine_material[gate_index][receiver_position].commitment,
                            garbler_position as u16,
                            receiver_position as u16,
                            gate_index as u32,
                            selected_candidate,
                            &changed_tokens,
                        ),
                        selected_mask,
                        "every candidate-label input is load bearing"
                    );
                }

                let counterfactual_candidate = Gf16::new(selected_candidate.as_u8() ^ 1);
                let mut plaintext = evaluated
                    .joint_row(receiver_position, counterfactual_candidate)
                    .expect("counterfactual row");
                let wrong_mask = joint_row_mask(
                    &fixture.context,
                    fixture.affine_material[gate_index][receiver_position].commitment,
                    garbler_position as u16,
                    receiver_position as u16,
                    gate_index as u32,
                    counterfactual_candidate,
                    &evaluated.masked_tokens,
                );
                module_xor(&mut plaintext, &wrong_mask);
                let mut actual = fixture.affine_material[gate_index][receiver_position].evaluations
                    [garbler_position]
                    .affine_a;
                module_add_scaled(
                    &mut actual,
                    &fixture.affine_material[gate_index][receiver_position].evaluations
                        [garbler_position]
                        .affine_b,
                    counterfactual_candidate,
                );
                assert_ne!(
                    plaintext, actual,
                    "selected labels must not open candidate {counterfactual_candidate:?}"
                );
                counterfactual_evaluations.push(plaintext);
            }

            let counterfactual_key = interpolate_module_at_zero(&counterfactual_evaluations)
                .expect("ten counterfactual probes interpolate");
            let (receiver, evaluated) =
                evaluated_initial_gate(&fixture, receiver_position, gate_index);
            let opposite_selector = fixture.selectors[gate_index] ^ 1;
            let mut plaintext = evaluated.continuation_rows[usize::from(opposite_selector)];
            let mask = continuation_row_mask(
                &fixture.context,
                receiver.affine_commitments[gate_index],
                receiver_position as u16,
                gate_index as u32,
                opposite_selector,
                &counterfactual_key,
            );
            xor_bytes(&mut plaintext, &mask);
            assert!(
                plaintext[TOKEN_BYTE_LENGTH..].iter().any(|byte| *byte != 0),
                "public counterfactual probes must not authenticate at gate {gate_index}"
            );
        }
    }

    #[test]
    fn selected_translation_and_continuation_corruption_fail_closed() {
        let fixture = build_reduced_fixture();
        let parsed = ParsedBody::new(&fixture.bodies[0], &fixture.context, &fixture.plan)
            .expect("fixture body parses");
        let initial = parsed
            .initial_tokens(&fixture.plan)
            .expect("initial tokens");
        let gate = fixture.plan.gates[0];
        let evaluated = evaluate_gate_payload(
            &parsed,
            &fixture.context,
            &fixture.plan,
            0,
            initial[usize::from(gate.left_wire)],
            initial[usize::from(gate.right_wire)],
        )
        .expect("first gate evaluates");

        let mut corrupt_translation = fixture.bodies.clone();
        let joint_rows_offset = gate_payload_offset(&fixture.plan, 0)
            + LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH
            + 1;
        let selected_row_offset = joint_rows_offset
            + usize::from(evaluated.masked_value.as_u8()) * MODULE_VALUE_BYTE_LENGTH;
        corrupt_translation[0][selected_row_offset] ^= 1;
        let corrupt_identities = corrupt_translation
            .iter()
            .map(|body| hash_bytes(BODY_IDENTITY_DOMAIN, body).expect("body identity"))
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &corrupt_translation,
                &corrupt_identities,
            ),
            Err(JointContinuationError::ContinuationAuthenticationFailed)
        );

        let continuation_offset = joint_rows_offset
            + JOINT_ROW_COUNT_PER_GARBLER * MODULE_VALUE_BYTE_LENGTH
            + usize::from(fixture.selectors[0]) * CONTINUATION_ROW_BYTE_LENGTH;
        for authenticator_byte in 0..CONTINUATION_AUTHENTICATOR_BYTE_LENGTH {
            let mut corrupt_continuation = fixture.bodies.clone();
            corrupt_continuation[0]
                [continuation_offset + TOKEN_BYTE_LENGTH + authenticator_byte] ^= 1;
            let corrupt_identities = body_identities(&corrupt_continuation);
            assert_eq!(
                evaluate_bodies(
                    &fixture.context,
                    &fixture.plan,
                    &corrupt_continuation,
                    &corrupt_identities,
                ),
                Err(JointContinuationError::ContinuationAuthenticationFailed),
                "every authenticator byte is checked"
            );
        }

        let selector = fixture.selectors[0];
        let mut selected_key = fixture.affine_material[0][0].constants[0];
        if selector != 0 {
            module_xor(
                &mut selected_key,
                &fixture.affine_material[0][0].constants[1],
            );
        }
        let continuation_mask = continuation_row_mask(
            &fixture.context,
            parsed.affine_commitments[0],
            0,
            0,
            selector,
            &selected_key,
        );
        let mut noncanonical_plaintext = evaluated.continuation_rows[usize::from(selector)];
        xor_bytes(&mut noncanonical_plaintext, &continuation_mask);
        noncanonical_plaintext[LABEL_BYTE_LENGTH] = 2;
        xor_bytes(&mut noncanonical_plaintext, &continuation_mask);
        let mut noncanonical_continuation = fixture.bodies.clone();
        noncanonical_continuation[0]
            [continuation_offset..continuation_offset + CONTINUATION_ROW_BYTE_LENGTH]
            .copy_from_slice(&noncanonical_plaintext);
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &noncanonical_continuation,
                &body_identities(&noncanonical_continuation),
            ),
            Err(JointContinuationError::InvalidBody)
        );
    }

    #[test]
    fn three_corrupt_aggregate_errors_accept_only_when_the_constant_is_unchanged() {
        let fixture = build_reduced_fixture();
        let gate_index = 0;
        let receiver_position = 3;
        let weights = interpolation_weights_at_zero();
        let mut deltas = [[0_u8; MODULE_VALUE_BYTE_LENGTH]; 3];
        deltas[0].fill(0x31);
        deltas[1].fill(0xa7);
        let weighted_sum_factor = weights[0];
        let first_delta = deltas[0];
        module_add_scaled(&mut deltas[2], &first_delta, weighted_sum_factor);
        let second_factor = weights[1];
        let second_delta = deltas[1];
        module_add_scaled(&mut deltas[2], &second_delta, second_factor);
        let inverse = weights[2].inverse().expect("nonzero interpolation weight");
        let pending = deltas[2];
        deltas[2].fill(0);
        module_add_scaled(&mut deltas[2], &pending, inverse);

        let mut confluent = fixture.bodies.clone();
        let joint_rows_offset = gate_payload_offset(&fixture.plan, gate_index)
            + LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH
            + 1;
        for corrupt_position in 0..3 {
            let (_, evaluated) = evaluated_initial_gate(&fixture, corrupt_position, gate_index);
            let row_offset = joint_rows_offset
                + (receiver_position * 16 + usize::from(evaluated.masked_value.as_u8()))
                    * MODULE_VALUE_BYTE_LENGTH;
            for (byte, delta) in confluent[corrupt_position]
                [row_offset..row_offset + MODULE_VALUE_BYTE_LENGTH]
                .iter_mut()
                .zip(deltas[corrupt_position])
            {
                *byte ^= delta;
            }
        }
        let result = evaluate_bodies(
            &fixture.context,
            &fixture.plan,
            &confluent,
            &body_identities(&confluent),
        )
        .expect("zero-weight corrupt errors are semantically confluent");
        assert_eq!(result.terminal_bits, fixture.expected_terminal_bits);

        let (_, first_evaluated) = evaluated_initial_gate(&fixture, 0, gate_index);
        let first_selected_offset = joint_rows_offset
            + (receiver_position * 16 + usize::from(first_evaluated.masked_value.as_u8()))
                * MODULE_VALUE_BYTE_LENGTH;
        confluent[0][first_selected_offset] ^= 1;
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &confluent,
                &body_identities(&confluent),
            ),
            Err(JointContinuationError::ContinuationAuthenticationFailed)
        );
    }

    #[test]
    fn corrupt_receiver_coordinate_is_constrained_by_the_next_codeword() {
        let fixture = build_reduced_fixture();
        let receiver_position = 0;
        let gate_index = 0;
        let (parsed, _) = evaluated_initial_gate(&fixture, receiver_position, gate_index);
        let selector = fixture.selectors[gate_index];
        let mut key = fixture.affine_material[gate_index][receiver_position].constants[0];
        if selector != 0 {
            module_xor(
                &mut key,
                &fixture.affine_material[gate_index][receiver_position].constants[1],
            );
        }
        let mut row_mask = continuation_row_mask(
            &fixture.context,
            parsed.affine_commitments[gate_index],
            receiver_position as u16,
            gate_index as u32,
            selector,
            &key,
        );

        let refreshed_pair_index = usize::from(fixture.plan.input_wire_count) * FIELD_BIT_WIDTH
            + 31
            + FIELD_BIT_WIDTH
            + FIELD_BIT_WIDTH;
        let mut entropy = LabelEntropyCursor::new(&fixture.label_entropy[receiver_position]);
        for _ in 0..refreshed_pair_index {
            entropy.read_pair().expect("preceding entropy pair");
        }
        let low_pair = entropy.read_pair().expect("refreshed low pair");
        let honest_share = evaluate_field_polynomial(
            &fixture.wire_polynomials[usize::from(fixture.plan.input_wire_count)],
            Gf16::new((receiver_position + 1) as u8),
        );
        let wrong_token = low_pair.tokens[usize::from((honest_share.as_u8() & 1) ^ 1)];
        let mut wrong_plaintext = [0_u8; CONTINUATION_ROW_BYTE_LENGTH];
        wrong_plaintext[..TOKEN_BYTE_LENGTH].copy_from_slice(&wrong_token.encode());
        xor_bytes(&mut wrong_plaintext, &row_mask);

        let continuation_offset = gate_payload_offset(&fixture.plan, gate_index)
            + LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH
            + 1
            + JOINT_ROW_COUNT_PER_GARBLER * MODULE_VALUE_BYTE_LENGTH
            + usize::from(selector) * CONTINUATION_ROW_BYTE_LENGTH;
        let mut corrupt_receiver = fixture.bodies.clone();
        corrupt_receiver[receiver_position]
            [continuation_offset..continuation_offset + CONTINUATION_ROW_BYTE_LENGTH]
            .copy_from_slice(&wrong_plaintext);
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &corrupt_receiver,
                &body_identities(&corrupt_receiver),
            ),
            Err(JointContinuationError::InvalidCodeword)
        );

        row_mask.zeroize();
        key.zeroize();
        wrong_plaintext.zeroize();
    }

    #[test]
    fn masked_and_terminal_verifiers_enforce_the_exact_degree_bounds() {
        let degree_seven = polynomial(1, 7, 0x51);
        let degree_seven_values = (1..=PARTICIPANT_COUNT)
            .map(|point| evaluate_field_polynomial(&degree_seven, Gf16::new(point as u8)))
            .collect::<Vec<_>>();
        assert_eq!(
            verify_masked_product_codeword(&degree_seven_values),
            Err(JointContinuationError::InvalidCodeword)
        );
        assert_eq!(
            verify_codeword(&degree_seven_values, 9),
            Ok(Gf16::ONE),
            "the hostile word must isolate the degree-six call-site bound"
        );

        let degree_four = polynomial(0, 4, 0x72);
        let degree_four_values = (1..=PARTICIPANT_COUNT)
            .map(|point| evaluate_field_polynomial(&degree_four, Gf16::new(point as u8)))
            .collect::<Vec<_>>();
        assert_eq!(
            verify_terminal_codeword(&degree_four_values),
            Err(JointContinuationError::InvalidCodeword)
        );
        assert_eq!(
            verify_codeword(&degree_four_values, 9),
            Ok(Gf16::ZERO),
            "the hostile word must isolate the degree-three call-site bound"
        );
    }

    #[test]
    fn gate_and_terminal_codewords_reject_nonbinary_noncodeword_and_noncanonical_maps() {
        let fixture = build_reduced_fixture();
        let gate_map_offset = gate_payload_offset(&fixture.plan, 0)
            + LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH;
        let mut nonbinary_gate = fixture.bodies.clone();
        for body in &mut nonbinary_gate {
            body[gate_map_offset] ^= 2;
        }
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &nonbinary_gate,
                &body_identities(&nonbinary_gate),
            ),
            Err(JointContinuationError::InvalidCodeword)
        );

        let mut noncodeword_gate = fixture.bodies.clone();
        noncodeword_gate[0][gate_map_offset] ^= 1;
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &noncodeword_gate,
                &body_identities(&noncodeword_gate),
            ),
            Err(JointContinuationError::InvalidCodeword)
        );

        let mut noncanonical_gate = fixture.bodies.clone();
        noncanonical_gate[0][gate_map_offset] |= 0x10;
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &noncanonical_gate,
                &body_identities(&noncanonical_gate),
            ),
            Err(JointContinuationError::InvalidBody)
        );

        let terminal_map_offset = terminal_payload_offset(&fixture.plan, 0)
            + FIELD_BIT_WIDTH * 4 * TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH;
        let mut nonbinary_terminal = fixture.bodies.clone();
        for body in &mut nonbinary_terminal {
            body[terminal_map_offset] ^= 2;
        }
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &nonbinary_terminal,
                &body_identities(&nonbinary_terminal),
            ),
            Err(JointContinuationError::InvalidCodeword)
        );

        let mut noncodeword_terminal = fixture.bodies.clone();
        noncodeword_terminal[0][terminal_map_offset] ^= 1;
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &noncodeword_terminal,
                &body_identities(&noncodeword_terminal),
            ),
            Err(JointContinuationError::InvalidCodeword)
        );

        let mut noncanonical_terminal = fixture.bodies.clone();
        noncanonical_terminal[0][terminal_map_offset] |= 0x80;
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &noncanonical_terminal,
                &body_identities(&noncanonical_terminal),
            ),
            Err(JointContinuationError::InvalidBody)
        );
    }

    #[test]
    fn duplicate_affine_commitments_fail_before_evaluation() {
        let fixture = build_reduced_fixture();
        let affine_commitment_offset = 4 + 2 + 2 * Hash512::BYTE_LENGTH + 2 + 2;

        let mut duplicate_affine = fixture.bodies.clone();
        let repeated = duplicate_affine[1]
            [affine_commitment_offset..affine_commitment_offset + Hash512::BYTE_LENGTH]
            .to_vec();
        duplicate_affine[0]
            [affine_commitment_offset..affine_commitment_offset + Hash512::BYTE_LENGTH]
            .copy_from_slice(&repeated);
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &duplicate_affine,
                &body_identities(&duplicate_affine),
            ),
            Err(JointContinuationError::DuplicateCommitment)
        );
    }

    #[test]
    fn context_replay_reordering_and_losing_rows_do_not_change_acceptance() {
        let fixture = build_reduced_fixture();
        let wrong_context = EvaluationContext {
            target_identity: Hash512::from_bytes([0x5a; Hash512::BYTE_LENGTH]),
            plan_identity: fixture.context.plan_identity,
        };
        assert_eq!(
            evaluate_bodies(
                &wrong_context,
                &fixture.plan,
                &fixture.bodies,
                &fixture.body_identities,
            ),
            Err(JointContinuationError::InvalidContext)
        );

        let mut reordered = fixture.bodies.clone();
        reordered.swap(0, 1);
        let reordered_identities = reordered
            .iter()
            .map(|body| hash_bytes(BODY_IDENTITY_DOMAIN, body).expect("body identity"))
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &reordered,
                &reordered_identities,
            ),
            Err(JointContinuationError::DuplicateParticipant)
        );

        let parsed = ParsedBody::new(&fixture.bodies[0], &fixture.context, &fixture.plan)
            .expect("fixture body parses");
        let initial = parsed
            .initial_tokens(&fixture.plan)
            .expect("initial tokens");
        let gate = fixture.plan.gates[0];
        let evaluated = evaluate_gate_payload(
            &parsed,
            &fixture.context,
            &fixture.plan,
            0,
            initial[usize::from(gate.left_wire)],
            initial[usize::from(gate.right_wire)],
        )
        .expect("first gate evaluates");
        let joint_rows_offset = gate_payload_offset(&fixture.plan, 0)
            + LOCAL_MULTIPLICATION_ROW_COUNT * TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * TOKEN_BYTE_LENGTH
            + 1;
        for candidate_delta in 1..=2_u8 {
            let mut losing_variant = fixture.bodies.clone();
            let unselected_candidate = (evaluated.masked_value.as_u8() + candidate_delta) & 0x0f;
            losing_variant[0][joint_rows_offset
                + usize::from(unselected_candidate) * MODULE_VALUE_BYTE_LENGTH] ^= 1;
            let losing_identities = losing_variant
                .iter()
                .map(|body| hash_bytes(BODY_IDENTITY_DOMAIN, body).expect("body identity"))
                .collect::<Vec<_>>();
            let result = evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &losing_variant,
                &losing_identities,
            )
            .expect("unselected losing row remains opaque");
            assert_eq!(result.terminal_bits, fixture.expected_terminal_bits);
        }
    }

    #[test]
    fn gate_and_receiver_domains_refuse_replayed_material() {
        let fixture = build_reduced_fixture();

        let mut replayed_gate = fixture.bodies.clone();
        let first_gate_start = gate_payload_offset(&fixture.plan, 0);
        let second_gate_start = gate_payload_offset(&fixture.plan, 1);
        let first_gate = replayed_gate[0]
            [first_gate_start..first_gate_start + GATE_PAYLOAD_BYTE_LENGTH]
            .to_vec();
        replayed_gate[0][second_gate_start..second_gate_start + GATE_PAYLOAD_BYTE_LENGTH]
            .copy_from_slice(&first_gate);
        let replayed_identities = replayed_gate
            .iter()
            .map(|body| hash_bytes(BODY_IDENTITY_DOMAIN, body).expect("body identity"))
            .collect::<Vec<_>>();
        assert!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &replayed_gate,
                &replayed_identities,
            )
            .is_err(),
            "a gate payload cannot be replayed under another gate ordinal"
        );

        let mut wrong_receiver = fixture.bodies.clone();
        let commitment_offset = 4 + 2 + 2 * Hash512::BYTE_LENGTH + 2 + 2 + Hash512::BYTE_LENGTH;
        let receiver_zero_commitment =
            wrong_receiver[0][commitment_offset..commitment_offset + Hash512::BYTE_LENGTH].to_vec();
        let receiver_one_commitment =
            wrong_receiver[1][commitment_offset..commitment_offset + Hash512::BYTE_LENGTH].to_vec();
        wrong_receiver[0][commitment_offset..commitment_offset + Hash512::BYTE_LENGTH]
            .copy_from_slice(&receiver_one_commitment);
        wrong_receiver[1][commitment_offset..commitment_offset + Hash512::BYTE_LENGTH]
            .copy_from_slice(&receiver_zero_commitment);
        let wrong_receiver_identities = wrong_receiver
            .iter()
            .map(|body| hash_bytes(BODY_IDENTITY_DOMAIN, body).expect("body identity"))
            .collect::<Vec<_>>();
        assert!(
            evaluate_bodies(
                &fixture.context,
                &fixture.plan,
                &wrong_receiver,
                &wrong_receiver_identities,
            )
            .is_err(),
            "receiver-specific rows cannot move to another receiver"
        );
    }
}
