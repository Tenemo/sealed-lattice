use core::fmt;
use std::collections::BTreeSet;

use aes::Aes256;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::foundation::{CanonicalItem, Hash512, Roster, hash_foundation_tuple_512, kmac256};

use super::finality::{
    COMPLETION_PROFILE_PARTICIPANT_COUNT, FinalityTargetKind, VerifiedFinalityCapability,
};
use super::preparation_parent::{ActionSignatureCarrier, ActionSignaturePurpose};
use super::preparation_plaintext::HeldSubsetKey;
#[cfg(test)]
use super::preparation_plaintext::PairwiseMasterInventory;
use super::roster::{require_roster_identity, signing_verification_key};
use super::source::VerifiedCompletePreparation;

mod tally;

pub use tally::{
    PaddedTallyEvaluationInitializationInput, PaddedTallyGenerationInitializationInput,
    compile_padded_tally_plan_summary, evaluate_next_padded_tally_chunk,
    generate_next_padded_tally_chunk, initialize_padded_tally_evaluation,
    initialize_padded_tally_generation,
};

pub const PADDED_LABEL_BYTE_LENGTH: usize = 40;
pub const PADDED_MODULE_VALUE_BYTE_LENGTH: usize = 40;
pub const PADDED_TOKEN_BYTE_LENGTH: usize = PADDED_LABEL_BYTE_LENGTH + 1;
pub const PADDED_ALLOCATION_NONCE_BYTE_LENGTH: usize = 32;
#[cfg(test)]
const PADDED_GATE_MATERIAL_BYTE_LENGTH: usize =
    (2 + COMPLETION_PROFILE_PARTICIPANT_COUNT as usize * 5) * PADDED_MODULE_VALUE_BYTE_LENGTH;

const FIELD_BIT_WIDTH: usize = 4;
const LOCAL_MULTIPLICATION_GATE_COUNT: usize = 35;
const LOCAL_MULTIPLICATION_ROW_COUNT: usize = LOCAL_MULTIPLICATION_GATE_COUNT * 4;
const PADDED_TRANSLATION_ROW_COUNT_PER_GARBLER: usize =
    COMPLETION_PROFILE_PARTICIPANT_COUNT as usize * FIELD_BIT_WIDTH * 2;
const CONTINUATION_AUTHENTICATOR_BYTE_LENGTH: usize = PADDED_MODULE_VALUE_BYTE_LENGTH;
const CONTINUATION_ROW_BYTE_LENGTH: usize =
    PADDED_TOKEN_BYTE_LENGTH + CONTINUATION_AUTHENTICATOR_BYTE_LENGTH;
pub const PADDED_GATE_PAYLOAD_BYTE_LENGTH: usize = LOCAL_MULTIPLICATION_ROW_COUNT
    * PADDED_TOKEN_BYTE_LENGTH
    + FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH
    + 1
    + PADDED_TRANSLATION_ROW_COUNT_PER_GARBLER * PADDED_MODULE_VALUE_BYTE_LENGTH
    + 2 * CONTINUATION_ROW_BYTE_LENGTH
    + (FIELD_BIT_WIDTH - 1) * PADDED_TOKEN_BYTE_LENGTH;
pub const PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH: usize =
    FIELD_BIT_WIDTH * 4 * PADDED_TOKEN_BYTE_LENGTH + FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH + 1;
const TOKEN_PAIR_ENTROPY_BYTE_LENGTH: usize = 2 * PADDED_LABEL_BYTE_LENGTH + 1;
#[cfg(test)]
const REDUCED_INPUT_WIRE_COUNT: usize = 4;
#[cfg(test)]
const REDUCED_GATE_COUNT: usize = 7;
#[cfg(test)]
const REDUCED_OUTPUT_COUNT: usize = 3;
#[cfg(test)]
const REDUCED_INITIAL_PAYLOAD_BYTE_LENGTH: usize =
    REDUCED_INPUT_WIRE_COUNT * FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH;
#[cfg(test)]
pub const PADDED_REDUCED_PAYLOAD_BYTE_LENGTH: usize = REDUCED_INITIAL_PAYLOAD_BYTE_LENGTH
    + REDUCED_GATE_COUNT * PADDED_GATE_PAYLOAD_BYTE_LENGTH
    + REDUCED_OUTPUT_COUNT * PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH;
pub const PADDED_CHUNK_HEADER_BYTE_LENGTH: usize = 250;
pub const PADDED_MANIFEST_HEADER_BYTE_LENGTH: usize = 176;
pub const PADDED_MANIFEST_DESCRIPTOR_BYTE_LENGTH: usize = 78;
#[cfg(test)]
pub const PADDED_REDUCED_CHUNK_BYTE_LENGTH: usize =
    PADDED_CHUNK_HEADER_BYTE_LENGTH + PADDED_REDUCED_PAYLOAD_BYTE_LENGTH;
#[cfg(test)]
pub const PADDED_REDUCED_MANIFEST_BYTE_LENGTH: usize =
    PADDED_MANIFEST_HEADER_BYTE_LENGTH + PADDED_MANIFEST_DESCRIPTOR_BYTE_LENGTH;
#[cfg(test)]
pub const PADDED_REDUCED_LABEL_ENTROPY_BYTE_LENGTH: usize =
    (4 * REDUCED_INPUT_WIRE_COUNT + 43 * REDUCED_GATE_COUNT + 8 * REDUCED_OUTPUT_COUNT)
        * TOKEN_PAIR_ENTROPY_BYTE_LENGTH;

const CHUNK_MAGIC: [u8; 4] = *b"SLPC";
const CHUNK_VERSION: u16 = 1;
const MANIFEST_MAGIC: [u8; 4] = *b"SLPM";
const MANIFEST_VERSION: u16 = 1;
const CHUNK_IDENTITY_DOMAIN: &str = "sealed-lattice/padded-continuation/chunk/v1";
const MANIFEST_IDENTITY_DOMAIN: &str = "sealed-lattice/padded-continuation/manifest/v1";
const BATCH_IDENTITY_DOMAIN: &str = "sealed-lattice/padded-continuation/batch/v1";
const KMAC_CUSTOMIZATION: &[u8] = b"sealed-lattice/padded-continuation/pad/v1";
const SUBKEY_CUSTOMIZATION: &[u8] = b"sealed-lattice/padded-continuation/subkey/v1";
const LOCAL_ROW_DOMAIN: &[u8] = b"sealed-lattice/padded-continuation/local-row/v1";
const JOINT_ROW_DOMAIN: &[u8] = b"sealed-lattice/padded-continuation/joint-row/v1";
const CONTINUATION_ROW_DOMAIN: &[u8] = b"sealed-lattice/padded-continuation/continuation-row/v1";
const OPERATION_KIND_LOCAL_MULTIPLICATION: u8 = 1;
const OPERATION_KIND_LINEAR_XOR: u8 = 2;
const OPERATION_KIND_TERMINAL_XOR: u8 = 3;
const ABSENT_U16: u16 = u16::MAX;
const ABSENT_U8: u8 = u8::MAX;
const SUBSET_FAMILY_SIZE_SEVEN: u16 = 7;
const SUBSET_FAMILY_SIZE_EIGHT: u16 = 8;
const DERIVED_STREAM_ADDRESS_VERSION: u8 = 2;
const DERIVED_STREAM_FAMILY_MATCHED_LOW: u8 = 2;
const DERIVED_STREAM_FAMILY_MATCHED_HIGH_ZERO: u8 = 3;
const DERIVED_STREAM_FAMILY_TERMINAL_ZERO: u8 = 4;
const DERIVED_STREAM_FAMILY_JOINT_B: u8 = 5;
const DERIVED_STREAM_FAMILY_JOINT_PAD: u8 = 6;

type Label = [u8; PADDED_LABEL_BYTE_LENGTH];
type ModuleValue = [u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
type FieldPairs = [TokenPair; FIELD_BIT_WIDTH];
type FieldTokens = [Token; FIELD_BIT_WIDTH];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddedContinuationError {
    ArithmeticOverflow,
    AuthenticatedParticipantViolation,
    ContinuationAuthenticationFailed,
    DuplicateAllocationNonce,
    DuplicateParticipant,
    InvalidBody,
    InvalidChunk,
    InvalidCodeword,
    InvalidContext,
    InvalidGateMaterial,
    InvalidLabelEntropy,
    InvalidManifest,
    InvalidPlan,
    InvalidSignature,
    UnexpectedChunkIdentity,
    WrongParticipantCount,
    WrongParticipantPosition,
    WrongTargetKind,
}

impl fmt::Display for PaddedContinuationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArithmeticOverflow => "padded continuation arithmetic overflow",
            Self::AuthenticatedParticipantViolation => {
                "authenticated participant bytes violate their public relation"
            }
            Self::ContinuationAuthenticationFailed => "padded continuation authentication failed",
            Self::DuplicateAllocationNonce => "padded continuation reuses a label-allocation nonce",
            Self::DuplicateParticipant => {
                "padded continuation contains a duplicate participant position"
            }
            Self::InvalidBody => "padded continuation body is invalid",
            Self::InvalidChunk => "padded continuation chunk is invalid",
            Self::InvalidCodeword => "padded continuation codeword is invalid",
            Self::InvalidContext => "padded continuation context is invalid",
            Self::InvalidGateMaterial => "padded continuation gate material is invalid",
            Self::InvalidLabelEntropy => "padded continuation label entropy is invalid",
            Self::InvalidManifest => "padded continuation manifest is invalid",
            Self::InvalidPlan => "padded continuation plan is invalid",
            Self::InvalidSignature => "padded continuation signature is invalid",
            Self::UnexpectedChunkIdentity => {
                "padded continuation chunk does not match its signed identity"
            }
            Self::WrongParticipantCount => {
                "padded continuation requires the ten-participant completion roster"
            }
            Self::WrongParticipantPosition => "padded continuation participant position is invalid",
            Self::WrongTargetKind => "padded continuation requires a finalized computation target",
        })
    }
}

impl std::error::Error for PaddedContinuationError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlanGate {
    left_wire: u16,
    right_wire: u16,
}

#[cfg(test)]
#[derive(Clone)]
struct PlanView {
    input_wire_count: u16,
    gates: Vec<PlanGate>,
    output_wires: Vec<u16>,
}

#[cfg(test)]
fn reviewed_reduced_plan() -> PlanView {
    PlanView {
        input_wire_count: 4,
        gates: vec![
            PlanGate {
                left_wire: 0,
                right_wire: 1,
            },
            PlanGate {
                left_wire: 2,
                right_wire: 3,
            },
            PlanGate {
                left_wire: 4,
                right_wire: 2,
            },
            PlanGate {
                left_wire: 4,
                right_wire: 3,
            },
            PlanGate {
                left_wire: 6,
                right_wire: 7,
            },
            PlanGate {
                left_wire: 5,
                right_wire: 0,
            },
            PlanGate {
                left_wire: 8,
                right_wire: 9,
            },
        ],
        output_wires: vec![4, 7, 10],
    }
}

#[cfg(test)]
fn padded_label_entropy_byte_length(plan: &PlanView) -> Result<usize, PaddedContinuationError> {
    let pair_count = usize::from(plan.input_wire_count)
        .checked_mul(FIELD_BIT_WIDTH)
        .and_then(|count| {
            plan.gates
                .len()
                .checked_mul(43)
                .and_then(|gate_pairs| count.checked_add(gate_pairs))
        })
        .and_then(|count| {
            plan.output_wires
                .len()
                .checked_mul(8)
                .and_then(|terminal_pairs| count.checked_add(terminal_pairs))
        })
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let byte_length = pair_count
        .checked_mul(TOKEN_PAIR_ENTROPY_BYTE_LENGTH)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    if byte_length != PADDED_REDUCED_LABEL_ENTROPY_BYTE_LENGTH {
        return Err(PaddedContinuationError::InvalidPlan);
    }
    Ok(byte_length)
}

#[cfg(test)]
fn padded_participant_payload_byte_length(
    plan: &PlanView,
) -> Result<usize, PaddedContinuationError> {
    let initial_length = usize::from(plan.input_wire_count)
        .checked_mul(FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH)
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    Some(initial_length)
        .and_then(|length| {
            plan.gates
                .len()
                .checked_mul(PADDED_GATE_PAYLOAD_BYTE_LENGTH)
                .and_then(|payload| length.checked_add(payload))
        })
        .and_then(|length| {
            plan.output_wires
                .len()
                .checked_mul(PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH)
                .and_then(|payload| length.checked_add(payload))
        })
        .ok_or(PaddedContinuationError::ArithmeticOverflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
struct Token {
    label: Label,
    color: u8,
}

impl Token {
    fn decode(bytes: &[u8]) -> Result<Self, PaddedContinuationError> {
        if bytes.len() != PADDED_TOKEN_BYTE_LENGTH || bytes[PADDED_LABEL_BYTE_LENGTH] > 1 {
            return Err(PaddedContinuationError::InvalidBody);
        }
        Ok(Self {
            label: bytes[..PADDED_LABEL_BYTE_LENGTH]
                .try_into()
                .map_err(|_| PaddedContinuationError::InvalidBody)?,
            color: bytes[PADDED_LABEL_BYTE_LENGTH],
        })
    }

    fn encode(self) -> [u8; PADDED_TOKEN_BYTE_LENGTH] {
        let mut bytes = [0_u8; PADDED_TOKEN_BYTE_LENGTH];
        bytes[..PADDED_LABEL_BYTE_LENGTH].copy_from_slice(&self.label);
        bytes[PADDED_LABEL_BYTE_LENGTH] = self.color;
        bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
struct TokenPair {
    tokens: [Token; 2],
}

struct LabelEntropyCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> LabelEntropyCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_pair(&mut self) -> Result<TokenPair, PaddedContinuationError> {
        let end = self
            .offset
            .checked_add(TOKEN_PAIR_ENTROPY_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        if end > self.bytes.len() {
            return Err(PaddedContinuationError::InvalidLabelEntropy);
        }
        let first: Label = self.bytes[self.offset..self.offset + PADDED_LABEL_BYTE_LENGTH]
            .try_into()
            .map_err(|_| PaddedContinuationError::InvalidLabelEntropy)?;
        let second: Label = self.bytes
            [self.offset + PADDED_LABEL_BYTE_LENGTH..self.offset + 2 * PADDED_LABEL_BYTE_LENGTH]
            .try_into()
            .map_err(|_| PaddedContinuationError::InvalidLabelEntropy)?;
        let first_color = self.bytes[self.offset + 2 * PADDED_LABEL_BYTE_LENGTH];
        self.offset = end;
        if first_color > 1 || first == second {
            return Err(PaddedContinuationError::InvalidLabelEntropy);
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

    fn read_field_pairs(&mut self) -> Result<FieldPairs, PaddedContinuationError> {
        let mut pairs = [TokenPair {
            tokens: [Token {
                label: [0; PADDED_LABEL_BYTE_LENGTH],
                color: 0,
            }; 2],
        }; FIELD_BIT_WIDTH];
        for pair in &mut pairs {
            *pair = self.read_pair()?;
        }
        Ok(pairs)
    }

    fn finish(self) -> Result<(), PaddedContinuationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PaddedContinuationError::InvalidLabelEntropy)
        }
    }
}

fn padded_kmac256<const LENGTH: usize>(key: &[u8], message: &[u8]) -> [u8; LENGTH] {
    #[cfg(test)]
    KMAC_TRACE.with(|trace| {
        if let Some(entries) = trace.borrow_mut().as_mut() {
            entries.push((key.to_vec(), message.to_vec()));
        }
    });
    kmac256(key, message, KMAC_CUSTOMIZATION)
}

#[cfg(test)]
type KmacTraceEntry = (Vec<u8>, Vec<u8>);

#[cfg(test)]
type KmacTrace = Vec<KmacTraceEntry>;

#[cfg(test)]
std::thread_local! {
    static KMAC_TRACE: std::cell::RefCell<Option<KmacTrace>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn begin_kmac_trace() {
    KMAC_TRACE.with(|trace| {
        assert!(trace.borrow().is_none(), "KMAC trace is already active");
        *trace.borrow_mut() = Some(Vec::new());
    });
}

#[cfg(test)]
fn finish_kmac_trace() -> KmacTrace {
    KMAC_TRACE.with(|trace| trace.borrow_mut().take().expect("KMAC trace is active"))
}

#[derive(Clone, Copy)]
struct EvaluationContext {
    target_identity: Hash512,
    circuit_identity: Hash512,
    top_count: u16,
}

#[derive(Clone, Copy)]
struct PadAddress {
    operation_kind: u8,
    garbler_position: u16,
    receiver_position: u16,
    major_ordinal: u32,
    minor_ordinal: u16,
    physical_row: u8,
    role: u8,
    basis: u8,
}

fn pad_message(
    domain: &[u8],
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    address: PadAddress,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(2 + domain.len() + 2 * Hash512::BYTE_LENGTH + 47);
    message.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    message.extend_from_slice(domain);
    message.extend_from_slice(context.target_identity.as_bytes());
    message.extend_from_slice(context.circuit_identity.as_bytes());
    message.extend_from_slice(allocation_nonce);
    message.push(address.operation_kind);
    message.extend_from_slice(&address.garbler_position.to_le_bytes());
    message.extend_from_slice(&address.receiver_position.to_le_bytes());
    message.extend_from_slice(&address.major_ordinal.to_le_bytes());
    message.extend_from_slice(&address.minor_ordinal.to_le_bytes());
    message.push(address.physical_row);
    message.push(address.role);
    message.push(address.basis);
    message
}

#[allow(clippy::too_many_arguments)]
fn local_row_pad(
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
    physical_row: u8,
    role: u8,
    label: &Label,
) -> [u8; PADDED_TOKEN_BYTE_LENGTH] {
    let mut message = pad_message(
        LOCAL_ROW_DOMAIN,
        context,
        allocation_nonce,
        PadAddress {
            operation_kind: kind,
            garbler_position: participant_position,
            receiver_position: ABSENT_U16,
            major_ordinal,
            minor_ordinal,
            physical_row,
            role,
            basis: ABSENT_U8,
        },
    );
    let output = padded_kmac256(label, &message);
    message.zeroize();
    output
}

#[allow(clippy::too_many_arguments)]
fn joint_row_pad(
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    garbler_position: u16,
    receiver_position: u16,
    gate_ordinal: u32,
    basis: u8,
    physical_row: u8,
    label: &Label,
) -> ModuleValue {
    let mut message = pad_message(
        JOINT_ROW_DOMAIN,
        context,
        allocation_nonce,
        PadAddress {
            operation_kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
            garbler_position,
            receiver_position,
            major_ordinal: gate_ordinal,
            minor_ordinal: ABSENT_U16,
            physical_row,
            role: 0,
            basis,
        },
    );
    let output = padded_kmac256(label, &message);
    message.zeroize();
    output
}

fn continuation_row_pad(
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    receiver_position: u16,
    gate_ordinal: u32,
    selector: u8,
    key: &ModuleValue,
) -> [u8; CONTINUATION_ROW_BYTE_LENGTH] {
    let mut message = pad_message(
        CONTINUATION_ROW_DOMAIN,
        context,
        allocation_nonce,
        PadAddress {
            operation_kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
            garbler_position: receiver_position,
            receiver_position,
            major_ordinal: gate_ordinal,
            minor_ordinal: ABSENT_U16,
            physical_row: selector,
            role: ABSENT_U8,
            basis: ABSENT_U8,
        },
    );
    let output = padded_kmac256(key, &message);
    message.zeroize();
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
struct ReceiverGateMaterial {
    affine_b_evaluation: ModuleValue,
    basis_pads: [ModuleValue; FIELD_BIT_WIDTH],
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct GateMaterial {
    own_affine_a_constant: ModuleValue,
    own_affine_b_constant: ModuleValue,
    receivers: [ReceiverGateMaterial; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize],
}

#[cfg(test)]
fn decode_gate_material(bytes: &[u8]) -> Result<GateMaterial, PaddedContinuationError> {
    if bytes.len() != PADDED_GATE_MATERIAL_BYTE_LENGTH {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    let mut reader = ByteReader::new(bytes);
    let own_affine_a_constant = reader.read_array()?;
    let own_affine_b_constant: ModuleValue = reader.read_array()?;
    if own_affine_b_constant.iter().all(|byte| *byte == 0) {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    let mut receivers = [ReceiverGateMaterial {
        affine_b_evaluation: [0; PADDED_MODULE_VALUE_BYTE_LENGTH],
        basis_pads: [[0; PADDED_MODULE_VALUE_BYTE_LENGTH]; FIELD_BIT_WIDTH],
    }; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];
    for receiver in &mut receivers {
        receiver.affine_b_evaluation = reader.read_array()?;
        for pad in &mut receiver.basis_pads {
            *pad = reader.read_array()?;
        }
    }
    reader.finish()?;
    Ok(GateMaterial {
        own_affine_a_constant,
        own_affine_b_constant,
        receivers,
    })
}

fn validate_operation_fresh_gate_material(
    gate_material: &[GateMaterial],
) -> Result<(), PaddedContinuationError> {
    let mut continuation_keys = BTreeSet::new();
    for material in gate_material {
        let first_key = material.own_affine_a_constant;
        let mut second_key = first_key;
        module_xor(&mut second_key, &material.own_affine_b_constant);
        if !continuation_keys.insert(first_key) || !continuation_keys.insert(second_key) {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DerivedStreamScope {
    family: u8,
    subset: u16,
    receiver_position: u16,
    garbler_position: u16,
}

#[derive(Clone, Copy)]
struct DerivedStreamAddress {
    scope: DerivedStreamScope,
    gate_ordinal: u32,
    basis: u8,
}

fn derived_subkey(
    master: &[u8; 32],
    context: &EvaluationContext,
    scope: DerivedStreamScope,
) -> [u8; 32] {
    let mut message = Vec::with_capacity(2 * Hash512::BYTE_LENGTH + 7);
    message.extend_from_slice(context.target_identity.as_bytes());
    message.extend_from_slice(context.circuit_identity.as_bytes());
    message.push(scope.family);
    message.extend_from_slice(&scope.subset.to_le_bytes());
    message.extend_from_slice(&scope.receiver_position.to_le_bytes());
    message.extend_from_slice(&scope.garbler_position.to_le_bytes());
    let subkey = kmac256(master, &message, SUBKEY_CUSTOMIZATION);
    message.zeroize();
    subkey
}

#[cfg(test)]
fn derived_module_value(
    master: &[u8; 32],
    context: &EvaluationContext,
    stream_address: DerivedStreamAddress,
) -> Result<ModuleValue, PaddedContinuationError> {
    let mut subkey = derived_subkey(master, context, stream_address.scope);
    let output = derived_module_value_from_subkey(&subkey, stream_address);
    subkey.zeroize();
    output
}

fn derived_module_value_from_subkey(
    subkey: &[u8; 32],
    stream_address: DerivedStreamAddress,
) -> Result<ModuleValue, PaddedContinuationError> {
    let cipher =
        Aes256::new_from_slice(subkey).map_err(|_| PaddedContinuationError::InvalidGateMaterial)?;
    let mut output = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
    for block_index in 0..3_u8 {
        let mut address_block = Block::<Aes256>::default();
        address_block[0] = DERIVED_STREAM_ADDRESS_VERSION;
        address_block[1] = stream_address.scope.family;
        address_block[2..4].copy_from_slice(&stream_address.scope.receiver_position.to_le_bytes());
        address_block[4..6].copy_from_slice(&stream_address.scope.garbler_position.to_le_bytes());
        address_block[6..10].copy_from_slice(&stream_address.gate_ordinal.to_le_bytes());
        address_block[10] = stream_address.basis;
        address_block[11] = block_index;
        cipher.encrypt_block(&mut address_block);
        let output_start = usize::from(block_index) * 16;
        let output_end = (output_start + 16).min(PADDED_MODULE_VALUE_BYTE_LENGTH);
        output[output_start..output_end]
            .copy_from_slice(&address_block[..output_end - output_start]);
        address_block.as_mut_slice().zeroize();
    }
    Ok(output)
}

fn normalized_subset_basis(subset: u16, point: Gf16) -> Result<Gf16, PaddedContinuationError> {
    let admitted_mask = (1_u16 << COMPLETION_PROFILE_PARTICIPANT_COUNT) - 1;
    if subset & !admitted_mask != 0 || subset.count_ones() != u32::from(SUBSET_FAMILY_SIZE_SEVEN) {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    let mut numerator = Gf16::ONE;
    let mut denominator = Gf16::ONE;
    for participant_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
        if subset & (1_u16 << participant_position) != 0 {
            continue;
        }
        let coordinate = Gf16::new((participant_position + 1) as u8);
        numerator = numerator.multiply(point.add(coordinate));
        denominator = denominator.multiply(coordinate);
    }
    Ok(numerator.multiply(
        denominator
            .inverse()
            .ok_or(PaddedContinuationError::InvalidGateMaterial)?,
    ))
}

fn coordinate_interpolation_weight_at_zero(
    participant_position: u16,
) -> Result<Gf16, PaddedContinuationError> {
    validate_position(participant_position)?;
    let point = Gf16::new((participant_position + 1) as u8);
    let mut numerator = Gf16::ONE;
    let mut denominator = Gf16::ONE;
    for other_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
        if other_position == participant_position {
            continue;
        }
        let other_point = Gf16::new((other_position + 1) as u8);
        numerator = numerator.multiply(other_point);
        denominator = denominator.multiply(point.add(other_point));
    }
    Ok(numerator.multiply(
        denominator
            .inverse()
            .ok_or(PaddedContinuationError::InvalidGateMaterial)?,
    ))
}

#[cfg(test)]
fn derive_b_value(
    context: &EvaluationContext,
    held_subset_keys: &[HeldSubsetKey],
    local_position: u16,
    receiver_position: u16,
    gate_ordinal: u32,
    point: Gf16,
) -> Result<ModuleValue, PaddedContinuationError> {
    let mut value = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
    let mut used_subset_count = 0_usize;
    for held_key in held_subset_keys {
        if held_key.family != SUBSET_FAMILY_SIZE_SEVEN
            || held_key.subset & (1_u16 << receiver_position) == 0
        {
            continue;
        }
        if held_key.subset & (1_u16 << local_position) == 0 {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        let scalar = normalized_subset_basis(held_key.subset, point)?;
        let mut stream = derived_module_value(
            &held_key.key,
            context,
            DerivedStreamAddress {
                scope: DerivedStreamScope {
                    family: DERIVED_STREAM_FAMILY_JOINT_B,
                    subset: held_key.subset,
                    receiver_position,
                    garbler_position: ABSENT_U16,
                },
                gate_ordinal,
                basis: ABSENT_U8,
            },
        )?;
        module_add_scaled(&mut value, &stream, scalar);
        stream.zeroize();
        used_subset_count += 1;
    }
    let expected_subset_count = if receiver_position == local_position {
        84
    } else {
        56
    };
    if used_subset_count != expected_subset_count {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    Ok(value)
}

#[cfg(test)]
fn derive_pairwise_pad(
    context: &EvaluationContext,
    master: &[u8; 32],
    receiver_position: u16,
    garbler_position: u16,
    gate_ordinal: u32,
    basis: u8,
) -> Result<ModuleValue, PaddedContinuationError> {
    if basis >= FIELD_BIT_WIDTH as u8 {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    derived_module_value(
        master,
        context,
        DerivedStreamAddress {
            scope: DerivedStreamScope {
                family: DERIVED_STREAM_FAMILY_JOINT_PAD,
                subset: 0,
                receiver_position,
                garbler_position,
            },
            gate_ordinal,
            basis,
        },
    )
}

#[cfg(test)]
fn derive_gate_material(
    context: &EvaluationContext,
    participant_position: u16,
    held_subset_keys: &[HeldSubsetKey],
    pairwise_masters: &PairwiseMasterInventory,
    gate_count: usize,
) -> Result<Vec<GateMaterial>, PaddedContinuationError> {
    let gate_ordinals = (0..gate_count)
        .map(|gate_index| {
            u32::try_from(gate_index).map_err(|_| PaddedContinuationError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    derive_gate_material_for_ordinals(
        context,
        participant_position,
        held_subset_keys,
        pairwise_masters,
        &gate_ordinals,
    )
}

#[cfg(test)]
fn derive_gate_material_for_ordinals(
    context: &EvaluationContext,
    participant_position: u16,
    held_subset_keys: &[HeldSubsetKey],
    pairwise_masters: &PairwiseMasterInventory,
    gate_ordinals: &[u32],
) -> Result<Vec<GateMaterial>, PaddedContinuationError> {
    validate_position(participant_position)?;
    let mut material = Vec::with_capacity(gate_ordinals.len());
    for gate_ordinal in gate_ordinals.iter().copied() {
        let own_affine_b_constant = derive_b_value(
            context,
            held_subset_keys,
            participant_position,
            participant_position,
            gate_ordinal,
            Gf16::ZERO,
        )?;
        if own_affine_b_constant.iter().all(|byte| *byte == 0) {
            return Err(PaddedContinuationError::InvalidGateMaterial);
        }
        let mut own_affine_a_constant = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
        for garbler_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            let interpolation_weight = coordinate_interpolation_weight_at_zero(garbler_position)?;
            let master = pairwise_masters
                .outgoing_to(garbler_position)
                .ok_or(PaddedContinuationError::InvalidGateMaterial)?;
            for basis in 0..FIELD_BIT_WIDTH {
                let mut pad = derive_pairwise_pad(
                    context,
                    master,
                    participant_position,
                    garbler_position,
                    gate_ordinal,
                    basis as u8,
                )?;
                module_add_scaled(&mut own_affine_a_constant, &pad, interpolation_weight);
                pad.zeroize();
            }
        }
        let mut receivers = [ReceiverGateMaterial {
            affine_b_evaluation: [0; PADDED_MODULE_VALUE_BYTE_LENGTH],
            basis_pads: [[0; PADDED_MODULE_VALUE_BYTE_LENGTH]; FIELD_BIT_WIDTH],
        }; COMPLETION_PROFILE_PARTICIPANT_COUNT as usize];
        for (receiver_position, receiver_material) in receivers.iter_mut().enumerate() {
            let receiver_position = receiver_position as u16;
            receiver_material.affine_b_evaluation = derive_b_value(
                context,
                held_subset_keys,
                participant_position,
                receiver_position,
                gate_ordinal,
                Gf16::new(participant_position as u8 + 1),
            )?;
            let master = pairwise_masters
                .incoming_from(receiver_position)
                .ok_or(PaddedContinuationError::InvalidGateMaterial)?;
            for (basis, pad) in receiver_material.basis_pads.iter_mut().enumerate() {
                *pad = derive_pairwise_pad(
                    context,
                    master,
                    receiver_position,
                    participant_position,
                    gate_ordinal,
                    basis as u8,
                )?;
            }
        }
        material.push(GateMaterial {
            own_affine_a_constant,
            own_affine_b_constant,
            receivers,
        });
    }
    validate_operation_fresh_gate_material(&material)?;
    if material.len() != gate_ordinals.len() {
        return Err(PaddedContinuationError::InvalidGateMaterial);
    }
    Ok(material)
}

fn validate_preparation_context(
    capability: &VerifiedFinalityCapability,
    preparation: &VerifiedCompletePreparation,
    participant_position: u16,
) -> Result<(), PaddedContinuationError> {
    let target = capability.target.context();
    if preparation.root != target.verified_preparation_root
        || preparation.context.action_proposal_identity != target.action_proposal_identity
        || preparation.context.roster_identity != target.roster_identity
        || preparation.context.preparation_attempt != target.preparation_attempt
        || preparation.context.predecessor_identity != target.predecessor_identity
        || preparation.context.sender_position != participant_position
    {
        return Err(PaddedContinuationError::InvalidContext);
    }
    Ok(())
}

#[cfg(test)]
pub struct PaddedParticipantGenerationInput<'a> {
    pub participant_position: u16,
    pub initial_wire_values: &'a [u8],
    pub gate_mask_shares: &'a [u8],
    pub terminal_mask_shares: &'a [u8],
    pub allocation_nonce: &'a [u8],
    pub label_entropy: &'a [u8],
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedPaddedParticipant {
    pub chunk: Vec<u8>,
    pub chunk_identity: Hash512,
    pub manifest: Vec<u8>,
    pub manifest_identity: Hash512,
}

#[cfg(test)]
fn generate_participant_for_context(
    context: &EvaluationContext,
    plan: &PlanView,
    input: PaddedParticipantGenerationInput<'_>,
    gate_material: &[GateMaterial],
) -> Result<GeneratedPaddedParticipant, PaddedContinuationError> {
    validate_position(input.participant_position)?;
    if input.initial_wire_values.len() != usize::from(plan.input_wire_count)
        || input.initial_wire_values.iter().any(|value| *value > 0x0f)
        || input.gate_mask_shares.len() != plan.gates.len() * 2
        || input.gate_mask_shares.iter().any(|value| *value > 0x0f)
        || input.terminal_mask_shares.len() != plan.output_wires.len()
        || input.terminal_mask_shares.iter().any(|value| *value > 0x0f)
        || input.allocation_nonce.len() != PADDED_ALLOCATION_NONCE_BYTE_LENGTH
        || input.label_entropy.len() != padded_label_entropy_byte_length(plan)?
        || gate_material.len() != plan.gates.len()
    {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH] = input
        .allocation_nonce
        .try_into()
        .map_err(|_| PaddedContinuationError::InvalidBody)?;
    validate_operation_fresh_gate_material(gate_material)?;

    let mut entropy = LabelEntropyCursor::new(input.label_entropy);
    let payload_byte_length = padded_participant_payload_byte_length(plan)?;
    let mut payload = Vec::with_capacity(payload_byte_length);

    let wire_count = usize::from(plan.input_wire_count)
        .checked_add(plan.gates.len())
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut wire_pairs = vec![None; wire_count];
    for (wire_index, value) in input.initial_wire_values.iter().copied().enumerate() {
        let pairs = entropy.read_field_pairs()?;
        for (basis, pair) in pairs.iter().enumerate() {
            write_token(&mut payload, pair.tokens[usize::from((value >> basis) & 1)]);
        }
        wire_pairs[wire_index] = Some(pairs);
    }

    for (gate_index, gate) in plan.gates.iter().enumerate() {
        let left = wire_pairs
            .get(usize::from(gate.left_wire))
            .and_then(|pairs| *pairs)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        let right = wire_pairs
            .get(usize::from(gate.right_wire))
            .and_then(|pairs| *pairs)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        let output_pairs = generate_gate_payload(
            &mut payload,
            context,
            &allocation_nonce,
            input.participant_position,
            gate_index as u32,
            left,
            right,
            Gf16::new(input.gate_mask_shares[2 * gate_index]),
            Gf16::new(input.gate_mask_shares[2 * gate_index + 1]),
            &gate_material[gate_index],
            &mut entropy,
        )?;
        wire_pairs[usize::from(plan.input_wire_count) + gate_index] = Some(output_pairs);
    }

    for (output_index, output_wire) in plan.output_wires.iter().copied().enumerate() {
        let input_pairs = wire_pairs
            .get(usize::from(output_wire))
            .and_then(|pairs| *pairs)
            .ok_or(PaddedContinuationError::InvalidPlan)?;
        generate_terminal_payload(
            &mut payload,
            context,
            &allocation_nonce,
            input.participant_position,
            output_index as u32,
            input_pairs,
            Gf16::new(input.terminal_mask_shares[output_index]),
            &mut entropy,
        )?;
    }
    entropy.finish()?;
    if payload.len() != payload_byte_length {
        payload.zeroize();
        return Err(PaddedContinuationError::InvalidBody);
    }

    let mut chunk = Vec::with_capacity(PADDED_CHUNK_HEADER_BYTE_LENGTH + payload.len());
    chunk.extend_from_slice(&CHUNK_MAGIC);
    chunk.extend_from_slice(&CHUNK_VERSION.to_le_bytes());
    chunk.extend_from_slice(context.target_identity.as_bytes());
    chunk.extend_from_slice(context.circuit_identity.as_bytes());
    chunk.extend_from_slice(&COMPLETION_PROFILE_PARTICIPANT_COUNT.to_le_bytes());
    chunk.extend_from_slice(&input.participant_position.to_le_bytes());
    chunk.extend_from_slice(&context.top_count.to_le_bytes());
    chunk.extend_from_slice(&allocation_nonce);
    chunk.extend_from_slice(&0_u32.to_le_bytes());
    chunk.extend_from_slice(&0_u32.to_le_bytes());
    chunk.extend_from_slice(&(plan.gates.len() as u32).to_le_bytes());
    chunk.push(1);
    chunk.push(1);
    chunk.extend_from_slice(&[0_u8; Hash512::BYTE_LENGTH]);
    if chunk.len() != PADDED_CHUNK_HEADER_BYTE_LENGTH {
        payload.zeroize();
        chunk.zeroize();
        return Err(PaddedContinuationError::InvalidChunk);
    }
    chunk.extend_from_slice(&payload);
    payload.zeroize();
    let chunk_identity = hash_bytes(CHUNK_IDENTITY_DOMAIN, &chunk)?;

    let mut manifest = Vec::with_capacity(PADDED_REDUCED_MANIFEST_BYTE_LENGTH);
    manifest.extend_from_slice(&MANIFEST_MAGIC);
    manifest.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
    manifest.extend_from_slice(context.target_identity.as_bytes());
    manifest.extend_from_slice(context.circuit_identity.as_bytes());
    manifest.extend_from_slice(&COMPLETION_PROFILE_PARTICIPANT_COUNT.to_le_bytes());
    manifest.extend_from_slice(&input.participant_position.to_le_bytes());
    manifest.extend_from_slice(&context.top_count.to_le_bytes());
    manifest.extend_from_slice(&allocation_nonce);
    manifest.extend_from_slice(&1_u32.to_le_bytes());
    manifest.extend_from_slice(&0_u32.to_le_bytes());
    manifest.extend_from_slice(&(plan.gates.len() as u32).to_le_bytes());
    manifest.push(1);
    manifest.push(1);
    manifest.extend_from_slice(
        &u32::try_from(chunk.len())
            .map_err(|_| PaddedContinuationError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    manifest.extend_from_slice(chunk_identity.as_bytes());
    if manifest.len() != PADDED_REDUCED_MANIFEST_BYTE_LENGTH {
        chunk.zeroize();
        manifest.zeroize();
        return Err(PaddedContinuationError::InvalidManifest);
    }
    let manifest_identity = hash_bytes(MANIFEST_IDENTITY_DOMAIN, &manifest)?;
    Ok(GeneratedPaddedParticipant {
        chunk,
        chunk_identity,
        manifest,
        manifest_identity,
    })
}

pub fn encode_padded_activation_signature(
    participant_position: u16,
    manifest_identity: Hash512,
    signature: &[u8],
) -> Result<Vec<u8>, PaddedContinuationError> {
    ActionSignatureCarrier::new(
        COMPLETION_PROFILE_PARTICIPANT_COUNT,
        participant_position,
        ActionSignaturePurpose::Activation,
        manifest_identity,
        signature,
    )
    .map_err(|_| PaddedContinuationError::InvalidSignature)?
    .encode()
    .map_err(|_| PaddedContinuationError::InvalidSignature)
}

struct GarblingBuilder<'context, 'cursor, 'entropy> {
    context: &'context EvaluationContext,
    allocation_nonce: &'context [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    major_ordinal: u32,
    kind: u8,
    next_gate_ordinal: u16,
    rows: Vec<[u8; PADDED_TOKEN_BYTE_LENGTH]>,
    entropy: &'cursor mut LabelEntropyCursor<'entropy>,
}

impl<'context, 'cursor, 'entropy> GarblingBuilder<'context, 'cursor, 'entropy> {
    fn append_derived_gate(
        &mut self,
        left: TokenPair,
        right: TokenPair,
        conjunction: bool,
    ) -> Result<TokenPair, PaddedContinuationError> {
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
            self.allocation_nonce,
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
    ) -> Result<FieldPairs, PaddedContinuationError> {
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
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    gate_ordinal: u32,
    left: FieldPairs,
    right: FieldPairs,
    low_mask_share: Gf16,
    high_mask_share: Gf16,
    material: &GateMaterial,
    entropy: &mut LabelEntropyCursor<'_>,
) -> Result<FieldPairs, PaddedContinuationError> {
    let mut builder = GarblingBuilder {
        context,
        allocation_nonce,
        participant_position,
        major_ordinal: gate_ordinal,
        kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
        next_gate_ordinal: 0,
        rows: Vec::with_capacity(LOCAL_MULTIPLICATION_ROW_COUNT),
        entropy,
    };
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
        return Err(PaddedContinuationError::InvalidBody);
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

    for (receiver_position, receiver_material) in material.receivers.iter().enumerate() {
        for (basis, pair) in masked_output_pairs.iter().enumerate() {
            for physical_color in 0..=1_u8 {
                let semantic_value = pair
                    .tokens
                    .iter()
                    .position(|token| token.color == physical_color)
                    .ok_or(PaddedContinuationError::InvalidBody)?;
                let selected_token = pair.tokens[semantic_value];
                let mut plaintext = receiver_material.basis_pads[basis];
                if semantic_value == 1 {
                    module_add_scaled(
                        &mut plaintext,
                        &receiver_material.affine_b_evaluation,
                        Gf16::new(1 << basis),
                    );
                }
                let pad = joint_row_pad(
                    context,
                    allocation_nonce,
                    participant_position,
                    receiver_position as u16,
                    gate_ordinal,
                    basis as u8,
                    physical_color,
                    &selected_token.label,
                );
                module_xor(&mut plaintext, &pad);
                body.extend_from_slice(&plaintext);
                plaintext.zeroize();
            }
        }
    }

    let refreshed_output_pairs = builder.entropy.read_field_pairs()?;
    for selector in 0..=1_u8 {
        let mut key = material.own_affine_a_constant;
        if selector != 0 {
            module_xor(&mut key, &material.own_affine_b_constant);
        }
        let selected =
            refreshed_output_pairs[0].tokens[usize::from((low_mask_share.as_u8() & 1) ^ selector)];
        let mut plaintext = [0_u8; CONTINUATION_ROW_BYTE_LENGTH];
        plaintext[..PADDED_TOKEN_BYTE_LENGTH].copy_from_slice(&selected.encode());
        let pad = continuation_row_pad(
            context,
            allocation_nonce,
            participant_position,
            gate_ordinal,
            selector,
            &key,
        );
        xor_bytes(&mut plaintext, &pad);
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
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    output_ordinal: u32,
    input_pairs: FieldPairs,
    mask_share: Gf16,
    entropy: &mut LabelEntropyCursor<'_>,
) -> Result<(), PaddedContinuationError> {
    let mask_pairs = entropy.read_field_pairs()?;
    let output_pairs = entropy.read_field_pairs()?;
    for basis in 0..FIELD_BIT_WIDTH {
        let rows = garble_binary_gate(
            context,
            allocation_nonce,
            participant_position,
            OPERATION_KIND_TERMINAL_XOR,
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
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
    left: TokenPair,
    right: TokenPair,
    output: TokenPair,
    conjunction: bool,
) -> [[u8; PADDED_TOKEN_BYTE_LENGTH]; 4] {
    let mut rows = [[0_u8; PADDED_TOKEN_BYTE_LENGTH]; 4];
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
            let mut row = output.tokens[output_semantic].encode();
            let left_pad = local_row_pad(
                context,
                allocation_nonce,
                participant_position,
                kind,
                major_ordinal,
                minor_ordinal,
                physical_row as u8,
                0,
                &left_token.label,
            );
            let right_pad = local_row_pad(
                context,
                allocation_nonce,
                participant_position,
                kind,
                major_ordinal,
                minor_ordinal,
                physical_row as u8,
                1,
                &right_token.label,
            );
            xor_bytes(&mut row, &left_pad);
            xor_bytes(&mut row, &right_pad);
            rows[physical_row] = row;
        }
    }
    rows
}

#[allow(clippy::too_many_arguments)]
fn evaluate_binary_gate(
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    kind: u8,
    major_ordinal: u32,
    minor_ordinal: u16,
    left: Token,
    right: Token,
    rows: &[[u8; PADDED_TOKEN_BYTE_LENGTH]; 4],
) -> Result<Token, PaddedContinuationError> {
    let physical_row = usize::from(left.color | (right.color << 1));
    let mut plaintext = rows[physical_row];
    let left_pad = local_row_pad(
        context,
        allocation_nonce,
        participant_position,
        kind,
        major_ordinal,
        minor_ordinal,
        physical_row as u8,
        0,
        &left.label,
    );
    let right_pad = local_row_pad(
        context,
        allocation_nonce,
        participant_position,
        kind,
        major_ordinal,
        minor_ordinal,
        physical_row as u8,
        1,
        &right.label,
    );
    xor_bytes(&mut plaintext, &left_pad);
    xor_bytes(&mut plaintext, &right_pad);
    Token::decode(&plaintext)
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedPaddedBatch {
    pub batch_identity: Hash512,
    pub terminal_bits: Vec<bool>,
}

#[cfg(test)]
fn evaluate_padded_batch(
    context: &EvaluationContext,
    manifests: &[Vec<u8>],
    chunks: &[Vec<u8>],
    manifest_identities: &[Hash512],
) -> Result<EvaluatedPaddedBatch, PaddedContinuationError> {
    let participant_count = usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT);
    if manifests.len() != participant_count
        || chunks.len() != participant_count
        || manifest_identities.len() != participant_count
    {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    let plan_view = reviewed_reduced_plan();
    let mut parsed_chunks = Vec::with_capacity(participant_count);
    let mut seen_positions = BTreeSet::new();
    let mut seen_nonces = BTreeSet::new();
    let mut seen_manifests = BTreeSet::new();
    let mut seen_chunks = BTreeSet::new();
    for participant_position in 0..participant_count {
        let manifest_identity = manifest_identities[participant_position];
        if !seen_manifests.insert(*manifest_identity.as_bytes()) {
            return Err(PaddedContinuationError::InvalidManifest);
        }
        let manifest = ParsedManifest::new(&manifests[participant_position], context)?;
        if manifest.participant_position != participant_position as u16
            || !seen_positions.insert(manifest.participant_position)
        {
            return Err(PaddedContinuationError::DuplicateParticipant);
        }
        if !seen_nonces.insert(manifest.allocation_nonce) {
            return Err(PaddedContinuationError::DuplicateAllocationNonce);
        }
        let chunk_identity = hash_bytes(CHUNK_IDENTITY_DOMAIN, &chunks[participant_position])?;
        if chunk_identity != manifest.chunk_identity
            || !seen_chunks.insert(*chunk_identity.as_bytes())
        {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        let chunk = ParsedChunk::new(&chunks[participant_position], context)?;
        if chunk.participant_position != manifest.participant_position
            || chunk.allocation_nonce != manifest.allocation_nonce
        {
            return Err(PaddedContinuationError::InvalidContext);
        }
        parsed_chunks.push(chunk);
    }

    let wire_count = usize::from(plan_view.input_wire_count)
        .checked_add(plan_view.gates.len())
        .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
    let mut active_tokens = vec![vec![None; wire_count]; participant_count];
    for (participant_position, chunk) in parsed_chunks.iter().enumerate() {
        for (wire_index, tokens) in chunk.initial_tokens(&plan_view)?.into_iter().enumerate() {
            active_tokens[participant_position][wire_index] = Some(tokens);
        }
    }

    for (gate_index, gate) in plan_view.gates.iter().enumerate() {
        let mut evaluated_gates = Vec::with_capacity(participant_count);
        let mut masked_values = Vec::with_capacity(participant_count);
        for (participant_position, chunk) in parsed_chunks.iter().enumerate() {
            let left = active_tokens[participant_position]
                .get(usize::from(gate.left_wire))
                .and_then(|tokens| *tokens)
                .ok_or(PaddedContinuationError::InvalidBody)?;
            let right = active_tokens[participant_position]
                .get(usize::from(gate.right_wire))
                .and_then(|tokens| *tokens)
                .ok_or(PaddedContinuationError::InvalidBody)?;
            let evaluated = evaluate_gate_payload_from_chunk(
                chunk, context, &plan_view, gate_index, left, right,
            )?;
            masked_values.push(evaluated.masked_value);
            evaluated_gates.push(evaluated);
        }
        let selector = verify_codeword(&masked_values, 6)?;
        if selector.as_u8() > 1 {
            return Err(PaddedContinuationError::InvalidCodeword);
        }

        let mut refreshed = Vec::with_capacity(participant_count);
        for receiver_position in 0..participant_count {
            let mut aggregate_evaluations = Vec::with_capacity(participant_count);
            for (garbler_position, evaluated) in evaluated_gates.iter().enumerate() {
                let mut aggregate = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
                for (basis, active_token) in evaluated.masked_tokens.iter().copied().enumerate() {
                    let mut plaintext =
                        evaluated.padded_row(receiver_position, basis, active_token.color)?;
                    let pad = joint_row_pad(
                        context,
                        &parsed_chunks[garbler_position].allocation_nonce,
                        garbler_position as u16,
                        receiver_position as u16,
                        gate_index as u32,
                        basis as u8,
                        active_token.color,
                        &active_token.label,
                    );
                    module_xor(&mut plaintext, &pad);
                    module_xor(&mut aggregate, &plaintext);
                    plaintext.zeroize();
                }
                aggregate_evaluations.push(aggregate);
            }
            let mut selected_key = interpolate_module_at_zero(&aggregate_evaluations)?;
            let receiver_gate = &evaluated_gates[receiver_position];
            let mut plaintext = receiver_gate.continuation_rows[usize::from(selector.as_u8())];
            let pad = continuation_row_pad(
                context,
                &parsed_chunks[receiver_position].allocation_nonce,
                receiver_position as u16,
                gate_index as u32,
                selector.as_u8(),
                &selected_key,
            );
            xor_bytes(&mut plaintext, &pad);
            if plaintext[PADDED_TOKEN_BYTE_LENGTH..]
                .iter()
                .any(|byte| *byte != 0)
            {
                plaintext.zeroize();
                selected_key.zeroize();
                return Err(PaddedContinuationError::ContinuationAuthenticationFailed);
            }
            let low_token = Token::decode(&plaintext[..PADDED_TOKEN_BYTE_LENGTH])?;
            refreshed.push([
                low_token,
                receiver_gate.direct_output_tokens[0],
                receiver_gate.direct_output_tokens[1],
                receiver_gate.direct_output_tokens[2],
            ]);
            plaintext.zeroize();
            selected_key.zeroize();
        }

        let output_wire = usize::from(plan_view.input_wire_count)
            .checked_add(gate_index)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        for (participant_position, tokens) in refreshed.into_iter().enumerate() {
            active_tokens[participant_position][output_wire] = Some(tokens);
        }
    }

    let mut terminal_bits = Vec::with_capacity(plan_view.output_wires.len());
    for (output_index, output_wire) in plan_view.output_wires.iter().copied().enumerate() {
        let mut values = Vec::with_capacity(participant_count);
        for (participant_position, chunk) in parsed_chunks.iter().enumerate() {
            let input = active_tokens[participant_position]
                .get(usize::from(output_wire))
                .and_then(|tokens| *tokens)
                .ok_or(PaddedContinuationError::InvalidBody)?;
            values.push(evaluate_terminal_payload_from_chunk(
                chunk,
                context,
                &plan_view,
                output_index,
                input,
            )?);
        }
        let terminal = verify_codeword(&values, 3)?;
        if terminal.as_u8() > 1 {
            return Err(PaddedContinuationError::InvalidCodeword);
        }
        terminal_bits.push(terminal == Gf16::ONE);
    }

    let identity_bytes = manifest_identities
        .iter()
        .flat_map(|identity| identity.as_bytes().iter().copied())
        .collect::<Vec<_>>();
    let batch_identity = hash_foundation_tuple_512(
        BATCH_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(context.target_identity.into_bytes()),
            CanonicalItem::hash512(context.circuit_identity.into_bytes()),
            CanonicalItem::unsigned16(context.top_count),
            CanonicalItem::fixed_bytes(identity_bytes)
                .map_err(|_| PaddedContinuationError::InvalidManifest)?,
        ],
    )
    .map_err(|_| PaddedContinuationError::InvalidManifest)?;
    Ok(EvaluatedPaddedBatch {
        batch_identity,
        terminal_bits,
    })
}

#[derive(Clone, Copy)]
#[cfg(test)]
struct ParsedManifest {
    participant_position: u16,
    allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    chunk_identity: Hash512,
}

#[cfg(test)]
impl ParsedManifest {
    fn new(bytes: &[u8], context: &EvaluationContext) -> Result<Self, PaddedContinuationError> {
        if bytes.len() != PADDED_REDUCED_MANIFEST_BYTE_LENGTH {
            return Err(PaddedContinuationError::InvalidManifest);
        }
        let mut reader = ByteReader::new(bytes);
        if reader.read_array::<4>()? != MANIFEST_MAGIC
            || reader.read_u16()? != MANIFEST_VERSION
            || Hash512::from_bytes(reader.read_array()?) != context.target_identity
            || Hash512::from_bytes(reader.read_array()?) != context.circuit_identity
            || reader.read_u16()? != COMPLETION_PROFILE_PARTICIPANT_COUNT
        {
            return Err(PaddedContinuationError::InvalidContext);
        }
        let participant_position = reader.read_u16()?;
        validate_position(participant_position)?;
        if reader.read_u16()? != context.top_count {
            return Err(PaddedContinuationError::InvalidContext);
        }
        let allocation_nonce = reader.read_array()?;
        if reader.read_u32()? != 1
            || reader.read_u32()? != 0
            || reader.read_u32()? != REDUCED_GATE_COUNT as u32
            || reader.read_u8()? != 1
            || reader.read_u8()? != 1
            || reader.read_u32()? != PADDED_REDUCED_CHUNK_BYTE_LENGTH as u32
        {
            return Err(PaddedContinuationError::InvalidManifest);
        }
        let chunk_identity = Hash512::from_bytes(reader.read_array()?);
        reader.finish()?;
        Ok(Self {
            participant_position,
            allocation_nonce,
            chunk_identity,
        })
    }
}

#[cfg(test)]
struct ParsedChunk<'a> {
    bytes: &'a [u8],
    participant_position: u16,
    allocation_nonce: [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    payload_offset: usize,
}

#[cfg(test)]
impl<'a> ParsedChunk<'a> {
    fn new(bytes: &'a [u8], context: &EvaluationContext) -> Result<Self, PaddedContinuationError> {
        if bytes.len() != PADDED_REDUCED_CHUNK_BYTE_LENGTH {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        let mut reader = ByteReader::new(bytes);
        if reader.read_array::<4>()? != CHUNK_MAGIC
            || reader.read_u16()? != CHUNK_VERSION
            || Hash512::from_bytes(reader.read_array()?) != context.target_identity
            || Hash512::from_bytes(reader.read_array()?) != context.circuit_identity
            || reader.read_u16()? != COMPLETION_PROFILE_PARTICIPANT_COUNT
        {
            return Err(PaddedContinuationError::InvalidContext);
        }
        let participant_position = reader.read_u16()?;
        validate_position(participant_position)?;
        if reader.read_u16()? != context.top_count {
            return Err(PaddedContinuationError::InvalidContext);
        }
        let allocation_nonce = reader.read_array()?;
        if reader.read_u32()? != 0
            || reader.read_u32()? != 0
            || reader.read_u32()? != REDUCED_GATE_COUNT as u32
            || reader.read_u8()? != 1
            || reader.read_u8()? != 1
            || reader.read_array::<64>()? != [0_u8; Hash512::BYTE_LENGTH]
            || reader.offset != PADDED_CHUNK_HEADER_BYTE_LENGTH
        {
            return Err(PaddedContinuationError::InvalidChunk);
        }
        Ok(Self {
            bytes,
            participant_position,
            allocation_nonce,
            payload_offset: reader.offset,
        })
    }

    fn initial_tokens(&self, plan: &PlanView) -> Result<Vec<FieldTokens>, PaddedContinuationError> {
        let mut reader = ByteReader::new(&self.bytes[self.payload_offset..]);
        let mut initial = Vec::with_capacity(usize::from(plan.input_wire_count));
        for _ in 0..plan.input_wire_count {
            initial.push(read_field_tokens(&mut reader)?);
        }
        Ok(initial)
    }

    fn gate_bytes(
        &self,
        plan: &PlanView,
        gate_index: usize,
    ) -> Result<&'a [u8], PaddedContinuationError> {
        if gate_index >= plan.gates.len() {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        let start = self
            .payload_offset
            .checked_add(REDUCED_INITIAL_PAYLOAD_BYTE_LENGTH)
            .and_then(|offset| {
                gate_index
                    .checked_mul(PADDED_GATE_PAYLOAD_BYTE_LENGTH)
                    .and_then(|gate_offset| offset.checked_add(gate_offset))
            })
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        self.bytes
            .get(start..start + PADDED_GATE_PAYLOAD_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::InvalidChunk)
    }

    fn terminal_bytes(
        &self,
        plan: &PlanView,
        output_index: usize,
    ) -> Result<&'a [u8], PaddedContinuationError> {
        if output_index >= plan.output_wires.len() {
            return Err(PaddedContinuationError::InvalidPlan);
        }
        let gate_length = plan
            .gates
            .len()
            .checked_mul(PADDED_GATE_PAYLOAD_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let start = self
            .payload_offset
            .checked_add(REDUCED_INITIAL_PAYLOAD_BYTE_LENGTH)
            .and_then(|offset| offset.checked_add(gate_length))
            .and_then(|offset| {
                output_index
                    .checked_mul(PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH)
                    .and_then(|terminal_offset| offset.checked_add(terminal_offset))
            })
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        self.bytes
            .get(start..start + PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::InvalidChunk)
    }
}

struct EvaluatedGate<'a> {
    masked_tokens: FieldTokens,
    masked_value: Gf16,
    padded_rows: &'a [u8],
    continuation_rows: [[u8; CONTINUATION_ROW_BYTE_LENGTH]; 2],
    direct_output_tokens: [Token; FIELD_BIT_WIDTH - 1],
}

impl EvaluatedGate<'_> {
    fn padded_row(
        &self,
        receiver_position: usize,
        basis: usize,
        physical_color: u8,
    ) -> Result<ModuleValue, PaddedContinuationError> {
        if receiver_position >= usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT)
            || basis >= FIELD_BIT_WIDTH
            || physical_color > 1
        {
            return Err(PaddedContinuationError::InvalidBody);
        }
        let row_index = receiver_position
            .checked_mul(FIELD_BIT_WIDTH * 2)
            .and_then(|index| {
                basis
                    .checked_mul(2)
                    .and_then(|basis_offset| index.checked_add(basis_offset))
            })
            .and_then(|index| index.checked_add(usize::from(physical_color)))
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let start = row_index
            .checked_mul(PADDED_MODULE_VALUE_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        self.padded_rows
            .get(start..start + PADDED_MODULE_VALUE_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::InvalidBody)?
            .try_into()
            .map_err(|_| PaddedContinuationError::InvalidBody)
    }
}

#[cfg(test)]
fn evaluate_gate_payload_from_chunk<'a>(
    chunk: &ParsedChunk<'a>,
    context: &EvaluationContext,
    plan: &PlanView,
    gate_index: usize,
    left: FieldTokens,
    right: FieldTokens,
) -> Result<EvaluatedGate<'a>, PaddedContinuationError> {
    let bytes = chunk.gate_bytes(plan, gate_index)?;
    evaluate_gate_payload(
        bytes,
        context,
        &chunk.allocation_nonce,
        chunk.participant_position,
        gate_index,
        left,
        right,
    )
}

fn evaluate_gate_payload<'a>(
    bytes: &'a [u8],
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    gate_index: usize,
    left: FieldTokens,
    right: FieldTokens,
) -> Result<EvaluatedGate<'a>, PaddedContinuationError> {
    let mut reader = ByteReader::new(bytes);
    let local_rows =
        reader.read_exact(LOCAL_MULTIPLICATION_ROW_COUNT * PADDED_TOKEN_BYTE_LENGTH)?;
    let mask_tokens = read_field_tokens(&mut reader)?;
    let masked_semantic_map = reader.read_u8()?;
    if masked_semantic_map & 0xf0 != 0 {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let padded_rows = reader
        .read_exact(PADDED_TRANSLATION_ROW_COUNT_PER_GARBLER * PADDED_MODULE_VALUE_BYTE_LENGTH)?;
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

    let mut rows = LocalRowsReader::new(local_rows);
    let (masked_tokens, consumed_gate_count) = {
        let mut builder = EvaluationGarblingBuilder {
            context,
            allocation_nonce,
            participant_position,
            major_ordinal: gate_index as u32,
            kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
            next_gate_ordinal: 0,
            rows: &mut rows,
        };
        let product = builder.multiply_fields(&left, &right)?;
        let mut masked_tokens = [Token {
            label: [0; PADDED_LABEL_BYTE_LENGTH],
            color: 0,
        }; FIELD_BIT_WIDTH];
        for basis in 0..FIELD_BIT_WIDTH {
            masked_tokens[basis] = builder.append_gate(product[basis], mask_tokens[basis])?;
        }
        (masked_tokens, usize::from(builder.next_gate_ordinal))
    };
    rows.finish()?;
    if consumed_gate_count != LOCAL_MULTIPLICATION_GATE_COUNT {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let masked_value = decode_field_tokens(&masked_tokens, masked_semantic_map)?;
    Ok(EvaluatedGate {
        masked_tokens,
        masked_value,
        padded_rows,
        continuation_rows,
        direct_output_tokens,
    })
}

struct LocalRowsReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> LocalRowsReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_rows(
        &mut self,
    ) -> Result<[[u8; PADDED_TOKEN_BYTE_LENGTH]; 4], PaddedContinuationError> {
        Ok([
            self.read_row()?,
            self.read_row()?,
            self.read_row()?,
            self.read_row()?,
        ])
    }

    fn read_row(&mut self) -> Result<[u8; PADDED_TOKEN_BYTE_LENGTH], PaddedContinuationError> {
        let end = self
            .offset
            .checked_add(PADDED_TOKEN_BYTE_LENGTH)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let row = self
            .bytes
            .get(self.offset..end)
            .ok_or(PaddedContinuationError::InvalidBody)?
            .try_into()
            .map_err(|_| PaddedContinuationError::InvalidBody)?;
        self.offset = end;
        Ok(row)
    }

    fn finish(&self) -> Result<(), PaddedContinuationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PaddedContinuationError::InvalidBody)
        }
    }
}

struct EvaluationGarblingBuilder<'a, 'b> {
    context: &'a EvaluationContext,
    allocation_nonce: &'a [u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    major_ordinal: u32,
    kind: u8,
    next_gate_ordinal: u16,
    rows: &'b mut LocalRowsReader<'a>,
}

impl EvaluationGarblingBuilder<'_, '_> {
    fn append_gate(&mut self, left: Token, right: Token) -> Result<Token, PaddedContinuationError> {
        let rows = self.rows.read_rows()?;
        let output = evaluate_binary_gate(
            self.context,
            self.allocation_nonce,
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
    ) -> Result<FieldTokens, PaddedContinuationError> {
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

#[cfg(test)]
fn evaluate_terminal_payload_from_chunk(
    chunk: &ParsedChunk<'_>,
    context: &EvaluationContext,
    plan: &PlanView,
    output_index: usize,
    input: FieldTokens,
) -> Result<Gf16, PaddedContinuationError> {
    let bytes = chunk.terminal_bytes(plan, output_index)?;
    evaluate_terminal_payload(
        bytes,
        context,
        &chunk.allocation_nonce,
        chunk.participant_position,
        output_index,
        input,
    )
}

fn evaluate_terminal_payload(
    bytes: &[u8],
    context: &EvaluationContext,
    allocation_nonce: &[u8; PADDED_ALLOCATION_NONCE_BYTE_LENGTH],
    participant_position: u16,
    output_index: usize,
    input: FieldTokens,
) -> Result<Gf16, PaddedContinuationError> {
    let mut reader = ByteReader::new(bytes);
    let mut rows = Vec::with_capacity(FIELD_BIT_WIDTH);
    for _ in 0..FIELD_BIT_WIDTH {
        rows.push([
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
            reader.read_array::<PADDED_TOKEN_BYTE_LENGTH>()?,
        ]);
    }
    let mask_tokens = read_field_tokens(&mut reader)?;
    let output_semantic_map = reader.read_u8()?;
    reader.finish()?;
    if output_semantic_map & 0xf0 != 0 {
        return Err(PaddedContinuationError::InvalidBody);
    }
    let mut output = [Token {
        label: [0; PADDED_LABEL_BYTE_LENGTH],
        color: 0,
    }; FIELD_BIT_WIDTH];
    for basis in 0..FIELD_BIT_WIDTH {
        output[basis] = evaluate_binary_gate(
            context,
            allocation_nonce,
            participant_position,
            OPERATION_KIND_TERMINAL_XOR,
            output_index as u32,
            basis as u16,
            input[basis],
            mask_tokens[basis],
            &rows[basis],
        )?;
    }
    decode_field_tokens(&output, output_semantic_map)
}

fn semantic_map(pairs: &FieldPairs) -> u8 {
    pairs.iter().enumerate().fold(0_u8, |map, (basis, pair)| {
        map | (pair.tokens[0].color << basis)
    })
}

fn decode_field_tokens(
    tokens: &FieldTokens,
    semantic_map: u8,
) -> Result<Gf16, PaddedContinuationError> {
    if semantic_map & 0xf0 != 0 {
        return Err(PaddedContinuationError::InvalidBody);
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

fn verify_codeword(values: &[Gf16], degree: usize) -> Result<Gf16, PaddedContinuationError> {
    if values.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) || degree >= values.len() {
        return Err(PaddedContinuationError::InvalidCodeword);
    }
    let coefficients = interpolate_prefix(values, degree)?;
    for (position, value) in values.iter().copied().enumerate() {
        if evaluate_field_polynomial(&coefficients, Gf16::new((position + 1) as u8)) != value {
            return Err(PaddedContinuationError::InvalidCodeword);
        }
    }
    Ok(coefficients[0])
}

fn interpolate_prefix(
    values: &[Gf16],
    degree: usize,
) -> Result<Vec<Gf16>, PaddedContinuationError> {
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
                .ok_or(PaddedContinuationError::InvalidCodeword)?,
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

fn interpolate_module_at_zero(
    values: &[ModuleValue],
) -> Result<ModuleValue, PaddedContinuationError> {
    if values.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        return Err(PaddedContinuationError::InvalidCodeword);
    }
    let mut result = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
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
                .ok_or(PaddedContinuationError::InvalidCodeword)?,
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

fn hash_bytes(domain: &str, bytes: &[u8]) -> Result<Hash512, PaddedContinuationError> {
    hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(bytes)
            .map_err(|_| PaddedContinuationError::InvalidBody)?],
    )
    .map_err(|_| PaddedContinuationError::InvalidBody)
}

fn validate_capability(
    capability: &VerifiedFinalityCapability,
) -> Result<(), PaddedContinuationError> {
    if capability.target.context().participant_count != COMPLETION_PROFILE_PARTICIPANT_COUNT {
        return Err(PaddedContinuationError::WrongParticipantCount);
    }
    if capability.target.target_kind() != FinalityTargetKind::Computation {
        return Err(PaddedContinuationError::WrongTargetKind);
    }
    if capability
        .target
        .body_identity()
        .map_err(|_| PaddedContinuationError::InvalidContext)?
        != capability.target_identity
    {
        return Err(PaddedContinuationError::InvalidContext);
    }
    Ok(())
}

fn validate_position(position: u16) -> Result<(), PaddedContinuationError> {
    if position < COMPLETION_PROFILE_PARTICIPANT_COUNT {
        Ok(())
    } else {
        Err(PaddedContinuationError::WrongParticipantPosition)
    }
}

fn write_token(bytes: &mut Vec<u8>, token: Token) {
    bytes.extend_from_slice(&token.encode());
}

fn read_token(reader: &mut ByteReader<'_>) -> Result<Token, PaddedContinuationError> {
    Token::decode(reader.read_exact(PADDED_TOKEN_BYTE_LENGTH)?)
}

fn read_field_tokens(reader: &mut ByteReader<'_>) -> Result<FieldTokens, PaddedContinuationError> {
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

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PaddedContinuationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PaddedContinuationError::ArithmeticOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PaddedContinuationError::InvalidBody)?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], PaddedContinuationError> {
        self.read_exact(LENGTH)?
            .try_into()
            .map_err(|_| PaddedContinuationError::InvalidBody)
    }

    fn read_u8(&mut self) -> Result<u8, PaddedContinuationError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PaddedContinuationError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, PaddedContinuationError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn finish(self) -> Result<(), PaddedContinuationError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PaddedContinuationError::InvalidBody)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::preparation_plaintext::sender_subset_slots;
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };
    use std::collections::BTreeMap;

    const PARTICIPANT_COUNT: usize = COMPLETION_PROFILE_PARTICIPANT_COUNT as usize;

    fn decode_hex<const BYTE_LENGTH: usize>(hex: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(hex.len(), 2 * BYTE_LENGTH);
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("valid hex")
        })
    }

    struct ReducedFixture {
        context: EvaluationContext,
        plan: PlanView,
        chunks: Vec<Vec<u8>>,
        manifests: Vec<Vec<u8>>,
        manifest_identities: Vec<Hash512>,
        gate_material: Vec<Vec<u8>>,
        initial_values: Vec<Vec<u8>>,
        gate_masks: Vec<Vec<u8>>,
        terminal_masks: Vec<Vec<u8>>,
        selectors: Vec<u8>,
        expected_terminal_bits: Vec<bool>,
    }

    fn deterministic_label_entropy(plan: &PlanView, participant_position: usize) -> Vec<u8> {
        let length = padded_label_entropy_byte_length(plan).expect("reduced entropy length");
        let mut entropy = deterministic_bytes(length, 0x720_000 + participant_position as u64);
        for offset in (0..entropy.len()).step_by(TOKEN_PAIR_ENTROPY_BYTE_LENGTH) {
            entropy[offset + 2 * PADDED_LABEL_BYTE_LENGTH] &= 1;
            if entropy[offset..offset + PADDED_LABEL_BYTE_LENGTH]
                == entropy[offset + PADDED_LABEL_BYTE_LENGTH..offset + 2 * PADDED_LABEL_BYTE_LENGTH]
            {
                entropy[offset + PADDED_LABEL_BYTE_LENGTH] ^= 1;
            }
        }
        assert_eq!(entropy.len(), length);
        entropy
    }

    fn deterministic_bytes(length: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn add_scalar_polynomials(left: &[Gf16], right: &[Gf16]) -> Vec<Gf16> {
        (0..left.len().max(right.len()))
            .map(|index| {
                left.get(index)
                    .copied()
                    .unwrap_or(Gf16::ZERO)
                    .add(right.get(index).copied().unwrap_or(Gf16::ZERO))
            })
            .collect()
    }

    fn scalar_polynomial_key<const LENGTH: usize>(polynomial: &[Gf16]) -> [u8; LENGTH] {
        core::array::from_fn(|index| polynomial.get(index).copied().unwrap_or(Gf16::ZERO).as_u8())
    }

    fn normalized_vanishing_polynomial(corrupt_positions: [usize; 3]) -> Vec<Gf16> {
        let mut polynomial = vec![Gf16::ONE];
        for position in corrupt_positions {
            polynomial = multiply_field_polynomials(
                &polynomial,
                &[Gf16::new((position + 1) as u8), Gf16::ONE],
            );
        }
        let scale = polynomial[0]
            .inverse()
            .expect("vanishing polynomial has nonzero constant");
        for coefficient in &mut polynomial {
            *coefficient = coefficient.multiply(scale);
        }
        polynomial
    }

    fn interpolate_scalar_at_zero(values: &[Gf16; PARTICIPANT_COUNT]) -> Gf16 {
        interpolation_weights_at_zero()
            .into_iter()
            .zip(values)
            .fold(Gf16::ZERO, |constant, (weight, value)| {
                constant.add(weight.multiply(*value))
            })
    }

    fn vanishing_coordinates_for(vanishing: &[Gf16], position: usize, scalar: Gf16) -> Gf16 {
        evaluate_field_polynomial(vanishing, Gf16::new((position + 1) as u8)).multiply(scalar)
    }

    fn divide_scalar_polynomials_exact(numerator: &[Gf16], denominator: &[Gf16]) -> Vec<Gf16> {
        let mut divisor = denominator.to_vec();
        while divisor.len() > 1 && divisor.last() == Some(&Gf16::ZERO) {
            divisor.pop();
        }
        assert!(divisor.iter().any(|value| *value != Gf16::ZERO));
        let mut remainder = numerator.to_vec();
        while remainder.len() > 1 && remainder.last() == Some(&Gf16::ZERO) {
            remainder.pop();
        }
        let mut quotient = vec![Gf16::ZERO; remainder.len().saturating_sub(divisor.len()) + 1];
        while remainder.iter().any(|value| *value != Gf16::ZERO) && remainder.len() >= divisor.len()
        {
            let shift = remainder.len() - divisor.len();
            let factor = remainder[remainder.len() - 1].multiply(
                divisor[divisor.len() - 1]
                    .inverse()
                    .expect("leading coefficient is nonzero"),
            );
            quotient[shift] = quotient[shift].add(factor);
            for (index, coefficient) in divisor.iter().copied().enumerate() {
                remainder[index + shift] =
                    remainder[index + shift].add(factor.multiply(coefficient));
            }
            while remainder.len() > 1 && remainder.last() == Some(&Gf16::ZERO) {
                remainder.pop();
            }
        }
        assert!(remainder.iter().all(|value| *value == Gf16::ZERO));
        while quotient.len() > 1 && quotient.last() == Some(&Gf16::ZERO) {
            quotient.pop();
        }
        quotient
    }

    struct ScalarFixturePrng(u32);

    impl ScalarFixturePrng {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }

        fn polynomial_with_constant(&mut self, constant: u8, degree: usize) -> Vec<Gf16> {
            let mut polynomial = Vec::with_capacity(degree + 1);
            polynomial.push(Gf16::new(constant));
            polynomial.extend((0..degree).map(|_| Gf16::new(self.next() as u8)));
            polynomial
        }
    }

    fn field_polynomial(constant: u8, degree: usize, domain: usize) -> Vec<Gf16> {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(Gf16::new(constant));
        for coefficient_index in 1..=degree {
            coefficients.push(Gf16::new((domain * 7 + coefficient_index * 5 + 3) as u8));
        }
        coefficients
    }

    fn deterministic_module(identity: u64) -> ModuleValue {
        let mut hasher = Shake256::default();
        hasher.update(&identity.to_le_bytes());
        let mut reader = hasher.finalize_xof();
        let mut value = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
        reader.read(&mut value);
        value
    }

    fn module_polynomial(
        gate_index: usize,
        receiver_position: usize,
        family: usize,
        degree: usize,
    ) -> Vec<ModuleValue> {
        (0..=degree)
            .map(|coefficient| {
                deterministic_module(
                    1 + (((gate_index * PARTICIPANT_COUNT + receiver_position) * 3 + family) * 16
                        + coefficient) as u64,
                )
            })
            .collect()
    }

    fn evaluate_module_polynomial(coefficients: &[ModuleValue], point: Gf16) -> ModuleValue {
        let mut value = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
        for coefficient in coefficients.iter().rev() {
            let previous = value;
            value = *coefficient;
            module_add_scaled(&mut value, &previous, point);
        }
        value
    }

    fn explicit_gate_material(participant_position: usize, gate_index: usize) -> Vec<u8> {
        let own_a = module_polynomial(gate_index, participant_position, 0, 9);
        let own_b = module_polynomial(gate_index, participant_position, 1, 3);
        let mut bytes = Vec::with_capacity(PADDED_GATE_MATERIAL_BYTE_LENGTH);
        bytes.extend_from_slice(&own_a[0]);
        bytes.extend_from_slice(&own_b[0]);
        let point = Gf16::new((participant_position + 1) as u8);
        for receiver_position in 0..PARTICIPANT_COUNT {
            let affine_a = module_polynomial(gate_index, receiver_position, 0, 9);
            let affine_b = module_polynomial(gate_index, receiver_position, 1, 3);
            let affine_a_evaluation = evaluate_module_polynomial(&affine_a, point);
            let affine_b_evaluation = evaluate_module_polynomial(&affine_b, point);
            bytes.extend_from_slice(&affine_b_evaluation);
            let mut final_pad = affine_a_evaluation;
            for basis in 0..FIELD_BIT_WIDTH - 1 {
                let pad = deterministic_module(
                    1 + (((gate_index * PARTICIPANT_COUNT + receiver_position) * PARTICIPANT_COUNT
                        + participant_position)
                        * FIELD_BIT_WIDTH
                        + basis) as u64
                        + (1_u64 << 40),
                );
                bytes.extend_from_slice(&pad);
                module_xor(&mut final_pad, &pad);
            }
            bytes.extend_from_slice(&final_pad);
        }
        assert_eq!(bytes.len(), PADDED_GATE_MATERIAL_BYTE_LENGTH);
        bytes
    }

    fn build_reduced_fixture() -> ReducedFixture {
        let plan = reviewed_reduced_plan();
        let context = EvaluationContext {
            target_identity: Hash512::from_bytes(decode_hex::<64>(
                "9f67e3d94c776f2ba59d87ea059d545dd43f166054f0ee716aa1d532986da34a9d3c68100bb5f9be9c36d9a06e954ba283ca7d0a570f4f8d0aafbbfcdeb9cd76",
            )),
            circuit_identity: Hash512::from_bytes(decode_hex::<64>(
                "6fb96c7ddb8fd1d847b8608460675c03ac902440d103fc97a23c5df76d08418514029b16ed4443549d75ff335aaeba2d4e0c28efd2b0fe28a2b4f1b870b7e141",
            )),
            top_count: 1,
        };

        let input_bits = [1_u8, 1, 1, 0];
        let mut wire_polynomials = input_bits
            .iter()
            .copied()
            .enumerate()
            .map(|(wire_index, bit)| field_polynomial(bit, 3, wire_index + 1))
            .collect::<Vec<_>>();
        let mut gate_masks = (0..PARTICIPANT_COUNT)
            .map(|_| Vec::with_capacity(plan.gates.len() * 2))
            .collect::<Vec<_>>();
        let mut selectors = Vec::with_capacity(plan.gates.len());
        for (gate_index, gate) in plan.gates.iter().enumerate() {
            let product = multiply_field_polynomials(
                &wire_polynomials[usize::from(gate.left_wire)],
                &wire_polynomials[usize::from(gate.right_wire)],
            );
            let selector = (gate_index & 1) as u8;
            let mask_constant = product[0].as_u8() ^ selector;
            let low_mask = field_polynomial(mask_constant, 3, 100 + gate_index);
            let high_mask = field_polynomial(mask_constant, 6, 200 + gate_index);
            for (participant_position, shares) in gate_masks.iter_mut().enumerate() {
                let point = Gf16::new((participant_position + 1) as u8);
                shares.push(evaluate_field_polynomial(&low_mask, point).as_u8());
                shares.push(evaluate_field_polynomial(&high_mask, point).as_u8());
            }
            let mut refreshed = low_mask;
            refreshed[0] = product[0];
            wire_polynomials.push(refreshed);
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
            let mask = field_polynomial(0, 3, 300 + output_index);
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

        let gate_material = (0..PARTICIPANT_COUNT)
            .map(|participant_position| {
                (0..plan.gates.len())
                    .flat_map(|gate_index| explicit_gate_material(participant_position, gate_index))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut chunks = Vec::with_capacity(PARTICIPANT_COUNT);
        let mut manifests = Vec::with_capacity(PARTICIPANT_COUNT);
        let mut manifest_identities = Vec::with_capacity(PARTICIPANT_COUNT);
        for participant_position in 0..PARTICIPANT_COUNT {
            let allocation_nonce = deterministic_bytes(
                PADDED_ALLOCATION_NONCE_BYTE_LENGTH,
                0x710_000 + participant_position as u64,
            );
            let label_entropy = deterministic_label_entropy(&plan, participant_position);
            let decoded_gate_material = gate_material[participant_position]
                .chunks_exact(PADDED_GATE_MATERIAL_BYTE_LENGTH)
                .map(decode_gate_material)
                .collect::<Result<Vec<_>, _>>()
                .expect("explicit fixture gate material decodes");
            let generated = generate_participant_for_context(
                &context,
                &plan,
                PaddedParticipantGenerationInput {
                    participant_position: participant_position as u16,
                    initial_wire_values: &initial_values[participant_position],
                    gate_mask_shares: &gate_masks[participant_position],
                    terminal_mask_shares: &terminal_masks[participant_position],
                    allocation_nonce: &allocation_nonce,
                    label_entropy: &label_entropy,
                },
                &decoded_gate_material,
            )
            .expect("padded participant body generates");
            assert_eq!(generated.chunk.len(), PADDED_REDUCED_CHUNK_BYTE_LENGTH);
            assert_eq!(generated.chunk.len(), 69_099);
            assert_eq!(generated.manifest.len(), 254);
            chunks.push(generated.chunk);
            manifests.push(generated.manifest);
            manifest_identities.push(generated.manifest_identity);
        }
        ReducedFixture {
            context,
            plan,
            chunks,
            manifests,
            manifest_identities,
            gate_material,
            initial_values,
            gate_masks,
            terminal_masks,
            selectors,
            expected_terminal_bits,
        }
    }

    fn rebind_manifests(
        base_manifests: &[Vec<u8>],
        chunks: &[Vec<u8>],
    ) -> (Vec<Vec<u8>>, Vec<Hash512>) {
        let manifests = base_manifests
            .iter()
            .zip(chunks)
            .map(|(base, chunk)| {
                let mut manifest = base.clone();
                let chunk_identity =
                    hash_bytes(CHUNK_IDENTITY_DOMAIN, chunk).expect("chunk identity");
                let identity_offset = manifest.len() - Hash512::BYTE_LENGTH;
                manifest[identity_offset..].copy_from_slice(chunk_identity.as_bytes());
                manifest
            })
            .collect::<Vec<_>>();
        let identities = manifests
            .iter()
            .map(|manifest| {
                hash_bytes(MANIFEST_IDENTITY_DOMAIN, manifest).expect("manifest identity")
            })
            .collect();
        (manifests, identities)
    }

    fn gate_payload_offset(plan: &PlanView, gate_index: usize) -> usize {
        PADDED_CHUNK_HEADER_BYTE_LENGTH
            + usize::from(plan.input_wire_count) * FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH
            + gate_index * PADDED_GATE_PAYLOAD_BYTE_LENGTH
    }

    fn joint_rows_offset(plan: &PlanView, gate_index: usize) -> usize {
        gate_payload_offset(plan, gate_index)
            + LOCAL_MULTIPLICATION_ROW_COUNT * PADDED_TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH
            + 1
    }

    fn continuation_rows_offset(plan: &PlanView, gate_index: usize) -> usize {
        joint_rows_offset(plan, gate_index)
            + PADDED_TRANSLATION_ROW_COUNT_PER_GARBLER * PADDED_MODULE_VALUE_BYTE_LENGTH
    }

    fn terminal_payload_offset(plan: &PlanView, output_index: usize) -> usize {
        gate_payload_offset(plan, plan.gates.len())
            + output_index * PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH
    }

    fn evaluated_input_gate<'a>(
        fixture: &'a ReducedFixture,
        participant_position: usize,
        gate_index: usize,
    ) -> EvaluatedGate<'a> {
        let chunk = ParsedChunk::new(&fixture.chunks[participant_position], &fixture.context)
            .expect("chunk parses");
        let initial = chunk.initial_tokens(&fixture.plan).expect("initial tokens");
        let gate = fixture.plan.gates[gate_index];
        evaluate_gate_payload_from_chunk(
            &chunk,
            &fixture.context,
            &fixture.plan,
            gate_index,
            initial[usize::from(gate.left_wire)],
            initial[usize::from(gate.right_wire)],
        )
        .expect("input-only gate evaluates")
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
            numerator.multiply(denominator.inverse().expect("distinct points"))
        })
    }

    fn deterministic_held_subset_keys(participant_position: u16) -> Vec<HeldSubsetKey> {
        sender_subset_slots(participant_position)
            .into_iter()
            .map(|(family, subset)| HeldSubsetKey {
                family,
                subset,
                key: deterministic_bytes(32, (u64::from(family) << 16) | u64::from(subset))
                    .try_into()
                    .expect("subset key length"),
            })
            .collect()
    }

    fn deterministic_pairwise_master(sender_position: u16, recipient_position: u16) -> [u8; 32] {
        deterministic_bytes(
            32,
            0x990_000 + u64::from(sender_position) * 16 + u64::from(recipient_position),
        )
        .try_into()
        .expect("pairwise master length")
    }

    fn deterministic_pairwise_inventory(
        participant_position: u16,
        changed_recipient: Option<u16>,
    ) -> PairwiseMasterInventory {
        let mut outgoing = core::array::from_fn(|recipient_position| {
            deterministic_pairwise_master(participant_position, recipient_position as u16)
        });
        if let Some(recipient_position) = changed_recipient {
            outgoing[usize::from(recipient_position)][0] ^= 1;
        }
        let mut remote_incoming = [[0_u8; 32]; PARTICIPANT_COUNT - 1];
        let mut remote_index = 0;
        for sender_position in 0..COMPLETION_PROFILE_PARTICIPANT_COUNT {
            if sender_position == participant_position {
                continue;
            }
            remote_incoming[remote_index] =
                deterministic_pairwise_master(sender_position, participant_position);
            remote_index += 1;
        }
        PairwiseMasterInventory::from_position_ordered(
            participant_position,
            outgoing,
            remote_incoming,
        )
    }

    #[test]
    fn preparation_derived_b_and_pairwise_a_interpolate_exactly() {
        let context = EvaluationContext {
            target_identity: Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
            circuit_identity: Hash512::from_bytes([0x72; Hash512::BYTE_LENGTH]),
            top_count: 1,
        };
        let all_material = (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
            .map(|participant_position| {
                derive_gate_material(
                    &context,
                    participant_position,
                    &deterministic_held_subset_keys(participant_position),
                    &deterministic_pairwise_inventory(participant_position, None),
                    2,
                )
                .expect("derived material")
            })
            .collect::<Vec<_>>();

        for receiver_position in 0..PARTICIPANT_COUNT {
            for gate_index in 0..2 {
                let b_coordinates = all_material
                    .iter()
                    .map(|garbler_material| {
                        garbler_material[gate_index].receivers[receiver_position]
                            .affine_b_evaluation
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    interpolate_module_at_zero(&b_coordinates).expect("B interpolates"),
                    all_material[receiver_position][gate_index].own_affine_b_constant,
                );

                let a_coordinates = all_material
                    .iter()
                    .map(|garbler_material| {
                        let mut coordinate = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
                        for pad in
                            garbler_material[gate_index].receivers[receiver_position].basis_pads
                        {
                            module_xor(&mut coordinate, &pad);
                        }
                        coordinate
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    interpolate_module_at_zero(&a_coordinates).expect("A interpolates"),
                    all_material[receiver_position][gate_index].own_affine_a_constant,
                );
            }
        }

        assert_ne!(all_material[0][0], all_material[0][1]);
        let replay_context = EvaluationContext {
            target_identity: Hash512::from_bytes([0x73; Hash512::BYTE_LENGTH]),
            ..context
        };
        let replayed = derive_gate_material(
            &replay_context,
            0,
            &deterministic_held_subset_keys(0),
            &deterministic_pairwise_inventory(0, None),
            2,
        )
        .expect("replay-context material derives");
        assert_ne!(all_material[0], replayed);

        let inconsistent_receiver = derive_gate_material(
            &context,
            0,
            &deterministic_held_subset_keys(0),
            &deterministic_pairwise_inventory(0, Some(1)),
            2,
        )
        .expect("inconsistent local material still derives");
        assert_ne!(
            inconsistent_receiver[0].own_affine_a_constant,
            all_material[0][0].own_affine_a_constant,
        );
        assert_eq!(
            inconsistent_receiver[0].receivers[0],
            all_material[0][0].receivers[0],
        );
    }

    #[test]
    fn kmac256_matches_nist_sample_four() {
        let key: Vec<u8> = (0x40..=0x5f).collect();
        let output = kmac256::<64>(&key, &[0x00, 0x01, 0x02, 0x03], b"My Tagged Application");
        assert_eq!(
            output,
            [
                0x20, 0xc5, 0x70, 0xc3, 0x13, 0x46, 0xf7, 0x03, 0xc9, 0xac, 0x36, 0xc6, 0x1c, 0x03,
                0xcb, 0x64, 0xc3, 0x97, 0x0d, 0x0c, 0xfc, 0x78, 0x7e, 0x9b, 0x79, 0x59, 0x9d, 0x27,
                0x3a, 0x68, 0xd2, 0xf7, 0xf6, 0x9d, 0x4c, 0xc3, 0xde, 0x9d, 0x10, 0x4a, 0x35, 0x16,
                0x89, 0xf2, 0x7c, 0xf6, 0xf5, 0x95, 0x1f, 0x01, 0x03, 0xf3, 0x3f, 0x4f, 0x24, 0x87,
                0x10, 0x24, 0xd9, 0xc2, 0x77, 0x73, 0xa8, 0xdd,
            ]
        );
    }

    #[test]
    fn preparation_subkeys_and_aes_streams_match_independent_vectors() {
        let master = core::array::from_fn(|index| index as u8);
        let context = EvaluationContext {
            target_identity: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            circuit_identity: Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            top_count: 1,
        };
        assert_eq!(
            derived_subkey(
                &master,
                &context,
                DerivedStreamScope {
                    family: DERIVED_STREAM_FAMILY_JOINT_B,
                    subset: 0x007f,
                    receiver_position: 2,
                    garbler_position: ABSENT_U16,
                },
            ),
            decode_hex::<32>("992d3484c8f39d6a9fb4cf5dfeedf5d489f2cf0e102338e80841ebe2ce96d7b1",),
        );
        assert_eq!(
            derived_module_value(
                &master,
                &context,
                DerivedStreamAddress {
                    scope: DerivedStreamScope {
                        family: DERIVED_STREAM_FAMILY_JOINT_B,
                        subset: 0x007f,
                        receiver_position: 2,
                        garbler_position: ABSENT_U16,
                    },
                    gate_ordinal: 0x01020304,
                    basis: ABSENT_U8,
                },
            )
            .expect("B stream derives"),
            decode_hex::<40>(
                "8d1bded07b4f6c3952318c19a268fbe1a8278f6d8a2ee503c9adb2410665e3f5\
                 8670ed430a5cc162",
            ),
        );
        assert_eq!(
            derived_subkey(
                &master,
                &context,
                DerivedStreamScope {
                    family: DERIVED_STREAM_FAMILY_JOINT_PAD,
                    subset: 0,
                    receiver_position: 2,
                    garbler_position: 3,
                },
            ),
            decode_hex::<32>("a596f932078c50fb091ddf3371b1a152e2636eb87c5a61ef534bf54b7f648b8e",),
        );
        assert_eq!(
            derive_pairwise_pad(&context, &master, 2, 3, 7, 1).expect("pairwise stream derives"),
            decode_hex::<40>(
                "7dda5d39792d8c0f229fdc6e67ef16537c60a4ad1df644ace08187cbf7edf99b\
                 c79e76bd767da0db",
            ),
        );
    }

    #[test]
    fn production_kmac_addresses_match_independent_vectors_and_are_injective() {
        let context = EvaluationContext {
            target_identity: Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            circuit_identity: Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            top_count: 1,
        };
        let allocation_nonce = [0x33; PADDED_ALLOCATION_NONCE_BYTE_LENGTH];
        let key: Label = core::array::from_fn(|index| 0x40 + index as u8);
        let local_address = PadAddress {
            operation_kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
            garbler_position: 2,
            receiver_position: ABSENT_U16,
            major_ordinal: 0x0102_0304,
            minor_ordinal: 0x0506,
            physical_row: 3,
            role: 1,
            basis: ABSENT_U8,
        };
        let joint_address = PadAddress {
            operation_kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
            garbler_position: 2,
            receiver_position: 7,
            major_ordinal: 0x0102_0304,
            minor_ordinal: ABSENT_U16,
            physical_row: 1,
            role: 0,
            basis: 3,
        };
        let continuation_address = PadAddress {
            operation_kind: OPERATION_KIND_LOCAL_MULTIPLICATION,
            garbler_position: 7,
            receiver_position: 7,
            major_ordinal: 0x0102_0304,
            minor_ordinal: ABSENT_U16,
            physical_row: 1,
            role: ABSENT_U8,
            basis: ABSENT_U8,
        };

        let local_message =
            pad_message(LOCAL_ROW_DOMAIN, &context, &allocation_nonce, local_address);
        let joint_message =
            pad_message(JOINT_ROW_DOMAIN, &context, &allocation_nonce, joint_address);
        let continuation_message = pad_message(
            CONTINUATION_ROW_DOMAIN,
            &context,
            &allocation_nonce,
            continuation_address,
        );
        assert_eq!(
            local_message,
            decode_hex::<223>(
                "2f007365616c65642d6c6174746963652f7061646465642d636f6e74696e756174696f6e2f6c6f63616c2d726f772f763111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333010200ffff0403020106050301ff"
            )
        );
        assert_eq!(
            joint_message,
            decode_hex::<223>(
                "2f007365616c65642d6c6174746963652f7061646465642d636f6e74696e756174696f6e2f6a6f696e742d726f772f763111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333010200070004030201ffff010003"
            )
        );
        assert_eq!(
            continuation_message,
            decode_hex::<230>(
                "36007365616c65642d6c6174746963652f7061646465642d636f6e74696e756174696f6e2f636f6e74696e756174696f6e2d726f772f763111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333010700070004030201ffff01ffff"
            )
        );
        assert_eq!(
            padded_kmac256::<PADDED_TOKEN_BYTE_LENGTH>(&key, &local_message),
            decode_hex::<PADDED_TOKEN_BYTE_LENGTH>(
                "d4314351319fb715cbe0673ffbeb50f708e4324ff174276610ff00d19a292fab551743737d3c1c959f"
            )
        );
        assert_eq!(
            padded_kmac256::<PADDED_MODULE_VALUE_BYTE_LENGTH>(&key, &joint_message),
            decode_hex::<PADDED_MODULE_VALUE_BYTE_LENGTH>(
                "880c52f4968e60686193f624e13d8cc0b6d4e33576af6e8b31722b8db4a1f88536381c090d74a901"
            )
        );
        assert_eq!(
            padded_kmac256::<CONTINUATION_ROW_BYTE_LENGTH>(&key, &continuation_message),
            decode_hex::<CONTINUATION_ROW_BYTE_LENGTH>(
                "d269de75c18374ff743a10f2e49df78b12cf418cc5528ad2576f99d2c5f6f43c85b9288534f650a33ebadf47e1bcd97a0f12b33417357e1e5d589ff1666f08a97524a684cfd50c4123d0c54829eac3989c"
            )
        );

        let baseline = padded_kmac256::<PADDED_MODULE_VALUE_BYTE_LENGTH>(&key, &joint_message);
        let mut distinct_messages = Vec::new();
        let mut changed_context = context;
        changed_context.target_identity = Hash512::from_bytes([0x12; Hash512::BYTE_LENGTH]);
        distinct_messages.push(pad_message(
            JOINT_ROW_DOMAIN,
            &changed_context,
            &allocation_nonce,
            joint_address,
        ));
        changed_context = context;
        changed_context.circuit_identity = Hash512::from_bytes([0x23; Hash512::BYTE_LENGTH]);
        distinct_messages.push(pad_message(
            JOINT_ROW_DOMAIN,
            &changed_context,
            &allocation_nonce,
            joint_address,
        ));
        let mut changed_nonce = allocation_nonce;
        changed_nonce[0] ^= 1;
        distinct_messages.push(pad_message(
            JOINT_ROW_DOMAIN,
            &context,
            &changed_nonce,
            joint_address,
        ));
        for address in [
            PadAddress {
                operation_kind: 3,
                ..joint_address
            },
            PadAddress {
                garbler_position: 3,
                ..joint_address
            },
            PadAddress {
                receiver_position: 8,
                ..joint_address
            },
            PadAddress {
                major_ordinal: 0x0102_0305,
                ..joint_address
            },
            PadAddress {
                minor_ordinal: 0,
                ..joint_address
            },
            PadAddress {
                physical_row: 0,
                ..joint_address
            },
            PadAddress {
                role: 1,
                ..joint_address
            },
            PadAddress {
                basis: 2,
                ..joint_address
            },
        ] {
            distinct_messages.push(pad_message(
                JOINT_ROW_DOMAIN,
                &context,
                &allocation_nonce,
                address,
            ));
        }
        for message in distinct_messages {
            assert_ne!(
                padded_kmac256::<PADDED_MODULE_VALUE_BYTE_LENGTH>(&key, &message),
                baseline
            );
        }
    }

    #[test]
    fn emitted_reduced_kmac_key_fan_out_census_is_exact() {
        begin_kmac_trace();
        let fixture = build_reduced_fixture();
        let trace = finish_kmac_trace();
        assert_eq!(trace.len(), 26_300);

        let mut label_keys = BTreeSet::new();
        for participant_position in 0..PARTICIPANT_COUNT {
            let entropy = deterministic_label_entropy(&fixture.plan, participant_position);
            for pair in entropy.chunks_exact(TOKEN_PAIR_ENTROPY_BYTE_LENGTH) {
                label_keys.insert(
                    pair[..PADDED_LABEL_BYTE_LENGTH]
                        .try_into()
                        .expect("first label has the exact width"),
                );
                label_keys.insert(
                    pair[PADDED_LABEL_BYTE_LENGTH..2 * PADDED_LABEL_BYTE_LENGTH]
                        .try_into()
                        .expect("second label has the exact width"),
                );
            }
        }
        assert_eq!(label_keys.len(), 20 * 341);

        let mut continuation_keys = BTreeSet::new();
        for participant_material in &fixture.gate_material {
            for gate_bytes in participant_material.chunks_exact(PADDED_GATE_MATERIAL_BYTE_LENGTH) {
                let material = decode_gate_material(gate_bytes).expect("exact gate material");
                let first = material.own_affine_a_constant;
                let mut second = first;
                module_xor(&mut second, &material.own_affine_b_constant);
                continuation_keys.insert(first);
                continuation_keys.insert(second);
            }
        }
        assert_eq!(continuation_keys.len(), 20 * fixture.plan.gates.len());
        assert!(
            label_keys.is_disjoint(&continuation_keys),
            "the deterministic census has no cross-family key collision"
        );

        let mut label_outputs = BTreeMap::<ModuleValue, BTreeSet<Vec<u8>>>::new();
        let mut continuation_outputs = BTreeMap::<ModuleValue, BTreeSet<Vec<u8>>>::new();
        for (key, message) in trace {
            let key: ModuleValue = key.try_into().expect("every emitted KMAC key is 320 bits");
            if label_keys.contains(&key) {
                label_outputs.entry(key).or_default().insert(message);
            } else if continuation_keys.contains(&key) {
                continuation_outputs.entry(key).or_default().insert(message);
            } else {
                panic!("emitted KMAC call uses an uncensused key");
            }
        }

        let mut fan_out_distribution = BTreeMap::<usize, usize>::new();
        for key in &label_keys {
            let output_count = label_outputs.get(key).map_or(0, BTreeSet::len);
            *fan_out_distribution.entry(output_count).or_default() += 1;
        }
        let label_output_count = label_outputs.values().map(BTreeSet::len).sum::<usize>();
        let continuation_output_count = continuation_outputs
            .values()
            .map(BTreeSet::len)
            .sum::<usize>();
        assert_eq!(
            fan_out_distribution,
            BTreeMap::from([
                (0, 240),
                (2, 4_800),
                (4, 420),
                (8, 400),
                (10, 640),
                (16, 240),
                (18, 80),
            ])
        );
        assert_eq!(label_output_count, 26_160);
        assert_eq!(continuation_output_count, 140);
        assert!(
            continuation_outputs
                .values()
                .all(|messages| messages.len() == 1)
        );

        begin_kmac_trace();
        evaluate_padded_batch(
            &fixture.context,
            &fixture.manifests,
            &fixture.chunks,
            &fixture.manifest_identities,
        )
        .expect("the traced reduced corpus evaluates");
        let evaluation_trace = finish_kmac_trace();
        assert_eq!(evaluation_trace.len(), 8_010);
        let selected_keys = evaluation_trace
            .into_iter()
            .map(|(key, _message)| {
                ModuleValue::try_from(key).expect("every evaluated KMAC key is 320 bits")
            })
            .collect::<BTreeSet<_>>();
        let replacement_output_count = label_outputs
            .iter()
            .chain(&continuation_outputs)
            .filter(|(key, _messages)| !selected_keys.contains(*key))
            .map(|(_key, messages)| messages.len())
            .sum::<usize>();
        assert_eq!(replacement_output_count, 13_150);
    }

    #[test]
    fn finite_reduced_lemma_census_is_source_controlled_and_exact() {
        let mut prng = ScalarFixturePrng(0x9e37_79b9);
        let mut corrupt_triple_count = 0;
        let mut share_fixing_count = 0;
        let mut conditioned_word_count = 0;
        let mut negative_control_count = 0;

        for first in 0..PARTICIPANT_COUNT - 2 {
            for second in first + 1..PARTICIPANT_COUNT - 1 {
                for third in second + 1..PARTICIPANT_COUNT {
                    let corrupt = [first, second, third];
                    corrupt_triple_count += 1;
                    let vanishing = normalized_vanishing_polynomial(corrupt);
                    assert_eq!(vanishing.len(), 4);
                    assert_eq!(vanishing[0], Gf16::ONE);
                    for position in corrupt {
                        assert_eq!(
                            evaluate_field_polynomial(&vanishing, Gf16::new((position + 1) as u8),),
                            Gf16::ZERO
                        );
                    }
                    let honest = (0..PARTICIPANT_COUNT)
                        .filter(|position| !corrupt.contains(position))
                        .collect::<Vec<_>>();

                    let mut hidden_words = Vec::<[Gf16; 7]>::with_capacity(8_192);
                    let mut hidden_word_keys = BTreeSet::<[u8; 7]>::new();
                    for constant in 0..=1_u8 {
                        for first_coefficient in 0..16_u8 {
                            for second_coefficient in 0..16_u8 {
                                for third_coefficient in 0..16_u8 {
                                    let word = multiply_field_polynomials(
                                        &vanishing,
                                        &[
                                            Gf16::new(constant),
                                            Gf16::new(first_coefficient),
                                            Gf16::new(second_coefficient),
                                            Gf16::new(third_coefficient),
                                        ],
                                    );
                                    let word: [Gf16; 7] = word
                                        .try_into()
                                        .expect("hidden word has degree at most six");
                                    hidden_word_keys.insert(scalar_polynomial_key(&word));
                                    hidden_words.push(word);
                                }
                            }
                        }
                    }
                    assert_eq!(hidden_words.len(), 8_192);
                    assert_eq!(hidden_word_keys.len(), 8_192);

                    for _ in 0..5 {
                        let first_zero = prng.polynomial_with_constant(0, 3);
                        let second_zero = prng.polynomial_with_constant(0, 3);
                        let first_one = add_scalar_polynomials(&first_zero, &vanishing);
                        let second_one = add_scalar_polynomials(&second_zero, &vanishing);
                        for position in corrupt {
                            let point = Gf16::new((position + 1) as u8);
                            assert_eq!(
                                evaluate_field_polynomial(&first_zero, point),
                                evaluate_field_polynomial(&first_one, point)
                            );
                            assert_eq!(
                                evaluate_field_polynomial(&second_zero, point),
                                evaluate_field_polynomial(&second_one, point)
                            );
                        }
                        let products = [
                            multiply_field_polynomials(&first_zero, &second_zero),
                            multiply_field_polynomials(&first_zero, &second_one),
                            multiply_field_polynomials(&first_one, &second_zero),
                            multiply_field_polynomials(&first_one, &second_one),
                        ];
                        for product in products.iter().skip(1) {
                            let difference = add_scalar_polynomials(&products[0], product);
                            assert!(
                                hidden_word_keys.contains(&scalar_polynomial_key::<7>(&difference))
                            );
                        }
                        let base_coset = hidden_words
                            .iter()
                            .map(|mask| {
                                scalar_polynomial_key::<7>(&add_scalar_polynomials(
                                    &products[0],
                                    mask,
                                ))
                            })
                            .collect::<BTreeSet<_>>();
                        let one_one_coset = hidden_words
                            .iter()
                            .map(|mask| {
                                scalar_polynomial_key::<7>(&add_scalar_polynomials(
                                    &products[3],
                                    mask,
                                ))
                            })
                            .collect::<BTreeSet<_>>();
                        assert_eq!(base_coset, one_one_coset);
                        share_fixing_count += 1;
                    }

                    let mut no_exposure_word_count = 0;
                    for masked_word in &hidden_words {
                        let masked_coordinates: [Gf16; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                evaluate_field_polynomial(
                                    masked_word,
                                    Gf16::new((position + 1) as u8),
                                )
                            });
                        if honest
                            .iter()
                            .all(|position| masked_coordinates[*position].as_u8() <= 1)
                        {
                            no_exposure_word_count += 1;
                        }

                        let mut difference_constant = (prng.next() as u8) & 0x0f;
                        if difference_constant == 0 {
                            difference_constant = 1;
                        }
                        let difference_polynomial =
                            prng.polynomial_with_constant(difference_constant, 3);
                        let difference_coordinates: [Gf16; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                evaluate_field_polynomial(
                                    &difference_polynomial,
                                    Gf16::new((position + 1) as u8),
                                )
                            });
                        let vanishing_coordinates: [Gf16; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                evaluate_field_polynomial(
                                    &vanishing,
                                    Gf16::new((position + 1) as u8),
                                )
                            });
                        let pads: [[Gf16; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT] =
                            core::array::from_fn(|_| {
                                core::array::from_fn(|_| Gf16::new(prng.next() as u8))
                            });
                        let mut selected_before =
                            [[Gf16::ZERO; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT];
                        let mut selected_after = [[Gf16::ZERO; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT];
                        let mut shifted_pads = pads;
                        for position in 0..PARTICIPANT_COUNT {
                            for basis in 0..FIELD_BIT_WIDTH {
                                let selected = (masked_coordinates[position].as_u8() >> basis) & 1;
                                let basis_factor = Gf16::new(selected << basis);
                                selected_before[position][basis] = pads[position][basis]
                                    .add(basis_factor.multiply(difference_coordinates[position]));
                                shifted_pads[position][basis] = pads[position][basis]
                                    .add(basis_factor.multiply(vanishing_coordinates[position]));
                                selected_after[position][basis] = shifted_pads[position][basis]
                                    .add(
                                        basis_factor.multiply(
                                            difference_coordinates[position]
                                                .add(vanishing_coordinates[position]),
                                        ),
                                    );
                                assert_eq!(
                                    selected_before[position][basis],
                                    selected_after[position][basis]
                                );
                            }
                        }
                        for position in corrupt {
                            assert_eq!(pads[position], shifted_pads[position]);
                        }
                        let before_sums = core::array::from_fn(|position| {
                            selected_before[position]
                                .into_iter()
                                .fold(Gf16::ZERO, Gf16::add)
                        });
                        let after_sums = core::array::from_fn(|position| {
                            selected_after[position]
                                .into_iter()
                                .fold(Gf16::ZERO, Gf16::add)
                        });
                        let selected_key = interpolate_scalar_at_zero(&before_sums);
                        assert_eq!(selected_key, interpolate_scalar_at_zero(&after_sums));
                        let alternative_before = selected_key.add(difference_polynomial[0]);
                        let alternative_after =
                            selected_key.add(difference_polynomial[0]).add(vanishing[0]);
                        assert_eq!(alternative_before.add(alternative_after), Gf16::ONE);

                        let mut unselected_changed = false;
                        for position in &honest {
                            for basis in 0..FIELD_BIT_WIDTH {
                                let unselected =
                                    ((masked_coordinates[*position].as_u8() >> basis) & 1) ^ 1;
                                let basis_factor = Gf16::new(unselected << basis);
                                let before = pads[*position][basis]
                                    .add(basis_factor.multiply(difference_coordinates[*position]));
                                let after = shifted_pads[*position][basis].add(
                                    basis_factor.multiply(
                                        difference_coordinates[*position]
                                            .add(vanishing_coordinates[*position]),
                                    ),
                                );
                                unselected_changed |= before != after;
                            }
                        }
                        assert!(unselected_changed);
                        conditioned_word_count += 1;
                    }
                    assert_eq!(no_exposure_word_count, 1);

                    let conditioned_constant = prng.next() as u8;
                    let conditioned_difference =
                        prng.polynomial_with_constant(conditioned_constant, 3);
                    let corrupt_values = corrupt.map(|position| {
                        evaluate_field_polynomial(
                            &conditioned_difference,
                            Gf16::new((position + 1) as u8),
                        )
                    });
                    let mut agreeing = BTreeSet::<[u8; 4]>::new();
                    for encoded in 0..=u16::MAX {
                        let candidate = [
                            Gf16::new(encoded as u8),
                            Gf16::new((encoded >> 4) as u8),
                            Gf16::new((encoded >> 8) as u8),
                            Gf16::new((encoded >> 12) as u8),
                        ];
                        if corrupt.iter().enumerate().all(|(index, position)| {
                            evaluate_field_polynomial(&candidate, Gf16::new((*position + 1) as u8))
                                == corrupt_values[index]
                        }) {
                            agreeing.insert(scalar_polynomial_key(&candidate));
                        }
                    }
                    let coset = (0..16_u8)
                        .map(|scalar| {
                            let shift = vanishing
                                .iter()
                                .copied()
                                .map(|coefficient| coefficient.multiply(Gf16::new(scalar)))
                                .collect::<Vec<_>>();
                            scalar_polynomial_key::<4>(&add_scalar_polynomials(
                                &conditioned_difference,
                                &shift,
                            ))
                        })
                        .collect::<BTreeSet<_>>();
                    assert_eq!(agreeing.len(), 16);
                    assert_eq!(agreeing, coset);

                    let weights = interpolation_weights_at_zero();
                    let mut zero_constant_errors = 0;
                    let mut single_nonzero_accepted = false;
                    for first_error in 0..16_u8 {
                        for second_error in 0..16_u8 {
                            for third_error in 0..16_u8 {
                                let errors = [first_error, second_error, third_error];
                                let constant_error = errors.iter().enumerate().fold(
                                    Gf16::ZERO,
                                    |constant, (index, error)| {
                                        constant.add(
                                            weights[corrupt[index]].multiply(Gf16::new(*error)),
                                        )
                                    },
                                );
                                if constant_error == Gf16::ZERO {
                                    zero_constant_errors += 1;
                                    single_nonzero_accepted |=
                                        errors.iter().filter(|error| **error != 0).count() == 1;
                                }
                            }
                        }
                    }
                    assert_eq!(zero_constant_errors, 256);
                    assert!(!single_nonzero_accepted);

                    let representative_word = hidden_words[137];
                    let representative_coordinates: [Gf16; PARTICIPANT_COUNT] =
                        core::array::from_fn(|position| {
                            evaluate_field_polynomial(
                                &representative_word,
                                Gf16::new((position + 1) as u8),
                            )
                        });
                    let representative_difference = prng.polynomial_with_constant(7, 3);
                    let representative_difference_coordinates: [Gf16; PARTICIPANT_COUNT] =
                        core::array::from_fn(|position| {
                            evaluate_field_polynomial(
                                &representative_difference,
                                Gf16::new((position + 1) as u8),
                            )
                        });
                    let representative_pads: [[Gf16; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT] =
                        core::array::from_fn(|_| {
                            core::array::from_fn(|_| Gf16::new(prng.next() as u8))
                        });
                    let representative_selected: [[Gf16; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT] =
                        core::array::from_fn(|position| {
                            core::array::from_fn(|basis| {
                                let selected =
                                    (representative_coordinates[position].as_u8() >> basis) & 1;
                                representative_pads[position][basis].add(
                                    Gf16::new(selected << basis)
                                        .multiply(representative_difference_coordinates[position]),
                                )
                            })
                        });
                    let representative_sums: [Gf16; PARTICIPANT_COUNT] =
                        core::array::from_fn(|position| {
                            representative_selected[position]
                                .into_iter()
                                .fold(Gf16::ZERO, Gf16::add)
                        });
                    let representative_selected_key =
                        interpolate_scalar_at_zero(&representative_sums);
                    let mut alternatives = BTreeSet::new();
                    for scalar in 0..16_u8 {
                        let scalar = Gf16::new(scalar);
                        let shifted_difference_coordinates: [Gf16; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                representative_difference_coordinates[position]
                                    .add(vanishing_coordinates_for(&vanishing, position, scalar))
                            });
                        let shifted_pads: [[Gf16; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                core::array::from_fn(|basis| {
                                    let selected =
                                        (representative_coordinates[position].as_u8() >> basis) & 1;
                                    representative_pads[position][basis].add(
                                        Gf16::new(selected << basis).multiply(
                                            vanishing_coordinates_for(&vanishing, position, scalar),
                                        ),
                                    )
                                })
                            });
                        let shifted_selected: [[Gf16; FIELD_BIT_WIDTH]; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                core::array::from_fn(|basis| {
                                    let selected =
                                        (representative_coordinates[position].as_u8() >> basis) & 1;
                                    shifted_pads[position][basis].add(
                                        Gf16::new(selected << basis)
                                            .multiply(shifted_difference_coordinates[position]),
                                    )
                                })
                            });
                        assert_eq!(shifted_selected, representative_selected);
                        for position in corrupt {
                            assert_eq!(shifted_pads[position], representative_pads[position]);
                        }
                        let shifted_sums: [Gf16; PARTICIPANT_COUNT] =
                            core::array::from_fn(|position| {
                                shifted_selected[position]
                                    .into_iter()
                                    .fold(Gf16::ZERO, Gf16::add)
                            });
                        let shifted_selected_key = interpolate_scalar_at_zero(&shifted_sums);
                        assert_eq!(shifted_selected_key, representative_selected_key);
                        alternatives.insert(
                            shifted_selected_key
                                .add(representative_difference[0])
                                .add(scalar)
                                .as_u8(),
                        );
                    }
                    assert_eq!(alternatives.len(), 16);

                    let action_wide_constant = prng.next() as u8;
                    let action_wide_first = prng.polynomial_with_constant(action_wide_constant, 9);
                    let mut action_wide_difference_constant = (prng.next() as u8) & 0x0f;
                    if action_wide_difference_constant == 0 {
                        action_wide_difference_constant = 1;
                    }
                    let action_wide_difference =
                        prng.polynomial_with_constant(action_wide_difference_constant, 3);
                    let selector = (prng.next() as u8) & 1;
                    let first_masked = prng.polynomial_with_constant(selector, 6);
                    let mut second_masked = prng.polynomial_with_constant(selector, 6);
                    if scalar_polynomial_key::<7>(&first_masked)
                        == scalar_polynomial_key::<7>(&second_masked)
                    {
                        second_masked[1] = second_masked[1].add(Gf16::ONE);
                    }
                    let first_aggregate = add_scalar_polynomials(
                        &action_wide_first,
                        &multiply_field_polynomials(&first_masked, &action_wide_difference),
                    );
                    let second_aggregate = add_scalar_polynomials(
                        &action_wide_first,
                        &multiply_field_polynomials(&second_masked, &action_wide_difference),
                    );
                    let recovered_difference = divide_scalar_polynomials_exact(
                        &add_scalar_polynomials(&first_aggregate, &second_aggregate),
                        &add_scalar_polynomials(&first_masked, &second_masked),
                    );
                    let recovered_first = add_scalar_polynomials(
                        &first_aggregate,
                        &multiply_field_polynomials(&first_masked, &recovered_difference),
                    );
                    assert_eq!(
                        scalar_polynomial_key::<4>(&recovered_difference),
                        scalar_polynomial_key::<4>(&action_wide_difference)
                    );
                    assert_eq!(
                        scalar_polynomial_key::<10>(&recovered_first),
                        scalar_polynomial_key::<10>(&action_wide_first)
                    );
                    negative_control_count += 1;
                }
            }
        }

        assert_eq!(corrupt_triple_count, 120);
        assert_eq!(share_fixing_count, 600);
        assert_eq!(conditioned_word_count, 983_040);
        assert_eq!(negative_control_count, 120);
    }

    #[test]
    fn reduced_relation_is_exact_and_exercises_structural_reuse() {
        let fixture = build_reduced_fixture();
        assert_eq!(
            PADDED_GATE_PAYLOAD_BYTE_LENGTH, 9_390,
            "the accepted padded gate grammar is exact"
        );
        assert_eq!(
            PADDED_GATE_PAYLOAD_BYTE_LENGTH,
            LOCAL_MULTIPLICATION_ROW_COUNT * PADDED_TOKEN_BYTE_LENGTH
                + FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH
                + 1
                + PADDED_TRANSLATION_ROW_COUNT_PER_GARBLER * PADDED_MODULE_VALUE_BYTE_LENGTH
                + 2 * CONTINUATION_ROW_BYTE_LENGTH
                + (FIELD_BIT_WIDTH - 1) * PADDED_TOKEN_BYTE_LENGTH,
            "the only private-gate semantic map is the permitted masked-word map",
        );
        assert_eq!(
            padded_label_entropy_byte_length(&fixture.plan).expect("entropy length"),
            27_621
        );
        assert!(fixture.selectors.contains(&0));
        assert!(fixture.selectors.contains(&1));
        let result = evaluate_padded_batch(
            &fixture.context,
            &fixture.manifests,
            &fixture.chunks,
            &fixture.manifest_identities,
        )
        .expect("reduced padded relation evaluates");
        assert_eq!(result.terminal_bits, fixture.expected_terminal_bits);
        assert_eq!(result.terminal_bits, [true, false, false]);
        assert_eq!(
            hash_bytes(CHUNK_IDENTITY_DOMAIN, &fixture.chunks[0]).expect("chunk identity"),
            Hash512::from_bytes(decode_hex::<64>(
                "ecdb906e707e8a55c381ab1b1b81b5e14e21eba0d84ab4353f2e5b8d0e85d133c49fca3f13e14a29c3fb19bbe3d6f66bd9203b48448440bb482d8589c7b337d6",
            ))
        );
        assert_eq!(
            fixture.manifests[0],
            decode_hex::<PADDED_REDUCED_MANIFEST_BYTE_LENGTH>(
                "534c504d01009f67e3d94c776f2ba59d87ea059d545dd43f166054f0ee716aa1d532986da34a9d3c68100bb5f9be9c36d9a06e954ba283ca7d0a570f4f8d0aafbbfcdeb9cd766fb96c7ddb8fd1d847b8608460675c03ac902440d103fc97a23c5df76d08418514029b16ed4443549d75ff335aaeba2d4e0c28efd2b0fe28a2b4f1b870b7e1410a000000010000c4c722b87319a38e0bf5a0c7908b52a0572f230fd576ec7d71e96c624008f60100000000000000070000000101eb0d0100ecdb906e707e8a55c381ab1b1b81b5e14e21eba0d84ab4353f2e5b8d0e85d133c49fca3f13e14a29c3fb19bbe3d6f66bd9203b48448440bb482d8589c7b337d6"
            )
        );
        assert_eq!(
            fixture.manifest_identities[0],
            Hash512::from_bytes(decode_hex::<64>(
                "c599a7052a543529ed053f77c7a146dfabe374d9feada206c5fbfa5c3d35b098a6ee0af12658ad3bf15878e6899884675de0fef4cb4cf5932db625bdeea6e821",
            ))
        );
        assert_eq!(
            result.batch_identity,
            Hash512::from_bytes(decode_hex::<64>(
                "33f51b3fbf0e9587c51d196e8ecf068ad9ef45b5c90fd8c1e8c3c20449255ed9892cc7a18d52b1155698a4cd4524686edcb18fb2e7b8e5139ed865226dcff630",
            ))
        );
        assert_eq!(fixture.plan.output_wires, vec![4, 7, 10]);
        assert_eq!(fixture.plan.gates[2].left_wire, 4, "serial reuse");
        assert_eq!(fixture.plan.gates[3].left_wire, 4, "fan-out");
        assert_eq!(fixture.plan.gates[4].left_wire, 6, "reconvergence");
    }

    #[test]
    fn selected_padded_row_opens_and_other_color_does_not() {
        let fixture = build_reduced_fixture();
        let evaluated = evaluated_input_gate(&fixture, 0, 0);
        let receiver_position = 0;
        let basis = 0;
        let token = evaluated.masked_tokens[basis];
        let allocation_nonce = ParsedChunk::new(&fixture.chunks[0], &fixture.context)
            .expect("chunk parses")
            .allocation_nonce;
        let material =
            decode_gate_material(&fixture.gate_material[0][..PADDED_GATE_MATERIAL_BYTE_LENGTH])
                .expect("fixture material");
        let receiver_material = material.receivers[receiver_position];
        let semantic = usize::from((evaluated.masked_value.as_u8() >> basis) & 1);
        let mut expected = receiver_material.basis_pads[basis];
        if semantic == 1 {
            module_add_scaled(
                &mut expected,
                &receiver_material.affine_b_evaluation,
                Gf16::new(1 << basis),
            );
        }
        let selected_ciphertext = evaluated
            .padded_row(receiver_position, basis, token.color)
            .expect("selected row");
        let mut opened = selected_ciphertext;
        let pad = joint_row_pad(
            &fixture.context,
            &allocation_nonce,
            0,
            receiver_position as u16,
            0,
            basis as u8,
            token.color,
            &token.label,
        );
        module_xor(&mut opened, &pad);
        assert_eq!(opened, expected);

        let opposite_color = token.color ^ 1;
        let mut wrong = evaluated
            .padded_row(receiver_position, basis, opposite_color)
            .expect("opposite row");
        let wrong_pad = joint_row_pad(
            &fixture.context,
            &allocation_nonce,
            0,
            receiver_position as u16,
            0,
            basis as u8,
            opposite_color,
            &token.label,
        );
        module_xor(&mut wrong, &wrong_pad);
        let mut alternatives = [receiver_material.basis_pads[basis]; 2];
        module_add_scaled(
            &mut alternatives[1],
            &receiver_material.affine_b_evaluation,
            Gf16::new(1 << basis),
        );
        assert_ne!(wrong, alternatives[0]);
        assert_ne!(wrong, alternatives[1]);

        let mut wrong_context = fixture.context;
        wrong_context.target_identity = Hash512::from_bytes([0x5a; Hash512::BYTE_LENGTH]);
        let wrong_address_pads = [
            joint_row_pad(
                &fixture.context,
                &allocation_nonce,
                0,
                receiver_position as u16,
                1,
                basis as u8,
                token.color,
                &token.label,
            ),
            joint_row_pad(
                &fixture.context,
                &allocation_nonce,
                0,
                1,
                0,
                basis as u8,
                token.color,
                &token.label,
            ),
            joint_row_pad(
                &fixture.context,
                &allocation_nonce,
                0,
                receiver_position as u16,
                0,
                basis as u8,
                token.color ^ 1,
                &token.label,
            ),
            joint_row_pad(
                &wrong_context,
                &allocation_nonce,
                0,
                receiver_position as u16,
                0,
                basis as u8,
                token.color,
                &token.label,
            ),
        ];
        for wrong_pad in wrong_address_pads {
            let mut wrong_plaintext = selected_ciphertext;
            module_xor(&mut wrong_plaintext, &wrong_pad);
            assert_ne!(wrong_plaintext, expected);
        }
    }

    #[test]
    fn selected_continuation_opens_but_cross_gate_counterfactuals_do_not() {
        let fixture = build_reduced_fixture();
        let receiver_position = 0;
        let mut selected_keys = Vec::new();
        for gate_index in 0..2 {
            let evaluated = (0..PARTICIPANT_COUNT)
                .map(|position| evaluated_input_gate(&fixture, position, gate_index))
                .collect::<Vec<_>>();
            let mut aggregate_evaluations = Vec::with_capacity(PARTICIPANT_COUNT);
            for (garbler_position, gate) in evaluated.iter().enumerate() {
                let allocation_nonce =
                    ParsedChunk::new(&fixture.chunks[garbler_position], &fixture.context)
                        .expect("chunk parses")
                        .allocation_nonce;
                let mut aggregate = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
                for (basis, token) in gate.masked_tokens.iter().copied().enumerate() {
                    let mut plaintext = gate
                        .padded_row(receiver_position, basis, token.color)
                        .expect("selected padded row");
                    let pad = joint_row_pad(
                        &fixture.context,
                        &allocation_nonce,
                        garbler_position as u16,
                        receiver_position as u16,
                        gate_index as u32,
                        basis as u8,
                        token.color,
                        &token.label,
                    );
                    module_xor(&mut plaintext, &pad);
                    module_xor(&mut aggregate, &plaintext);
                }
                aggregate_evaluations.push(aggregate);
            }
            let selected_key = interpolate_module_at_zero(&aggregate_evaluations)
                .expect("selected continuation key reconstructs");
            let receiver_nonce =
                ParsedChunk::new(&fixture.chunks[receiver_position], &fixture.context)
                    .expect("receiver chunk parses")
                    .allocation_nonce;
            let selector = fixture.selectors[gate_index];
            let mut selected_plaintext =
                evaluated[receiver_position].continuation_rows[usize::from(selector)];
            let selected_pad = continuation_row_pad(
                &fixture.context,
                &receiver_nonce,
                receiver_position as u16,
                gate_index as u32,
                selector,
                &selected_key,
            );
            xor_bytes(&mut selected_plaintext, &selected_pad);
            assert!(
                selected_plaintext[PADDED_TOKEN_BYTE_LENGTH..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            Token::decode(&selected_plaintext[..PADDED_TOKEN_BYTE_LENGTH])
                .expect("selected continuation token decodes");

            let counterfactual_selector = selector ^ 1;
            let mut counterfactual = evaluated[receiver_position].continuation_rows
                [usize::from(counterfactual_selector)];
            let counterfactual_pad = continuation_row_pad(
                &fixture.context,
                &receiver_nonce,
                receiver_position as u16,
                gate_index as u32,
                counterfactual_selector,
                &selected_key,
            );
            xor_bytes(&mut counterfactual, &counterfactual_pad);
            assert!(
                counterfactual[PADDED_TOKEN_BYTE_LENGTH..]
                    .iter()
                    .any(|byte| *byte != 0),
                "the selected key must not open the opposite row",
            );
            selected_keys.push(selected_key);
        }
        assert_eq!(fixture.selectors[..2], [0, 1]);
        assert_ne!(selected_keys[0], selected_keys[1]);

        let receiver_nonce = ParsedChunk::new(&fixture.chunks[receiver_position], &fixture.context)
            .expect("receiver chunk parses")
            .allocation_nonce;
        let gate_zero = evaluated_input_gate(&fixture, receiver_position, 0);
        let gate_one = evaluated_input_gate(&fixture, receiver_position, 1);
        for selector in 0..=1_u8 {
            let mut cross_gate = gate_one.continuation_rows[usize::from(selector)];
            let pad = continuation_row_pad(
                &fixture.context,
                &receiver_nonce,
                receiver_position as u16,
                1,
                selector,
                &selected_keys[0],
            );
            xor_bytes(&mut cross_gate, &pad);
            assert!(
                cross_gate[PADDED_TOKEN_BYTE_LENGTH..]
                    .iter()
                    .any(|byte| *byte != 0),
                "a selected key from another gate must open neither row",
            );
        }

        let other_receiver = 1_usize;
        let other_receiver_gate = evaluated_input_gate(&fixture, other_receiver, 0);
        let other_receiver_nonce =
            ParsedChunk::new(&fixture.chunks[other_receiver], &fixture.context)
                .expect("other receiver chunk parses")
                .allocation_nonce;
        for selector in 0..=1_u8 {
            let mut wrong_receiver = other_receiver_gate.continuation_rows[usize::from(selector)];
            let pad = continuation_row_pad(
                &fixture.context,
                &other_receiver_nonce,
                other_receiver as u16,
                0,
                selector,
                &selected_keys[0],
            );
            xor_bytes(&mut wrong_receiver, &pad);
            assert!(
                wrong_receiver[PADDED_TOKEN_BYTE_LENGTH..]
                    .iter()
                    .any(|byte| *byte != 0),
                "a selected key from another receiver must open neither row",
            );
        }

        let selected_selector = fixture.selectors[0];
        let selected_ciphertext = gate_zero.continuation_rows[usize::from(selected_selector)];
        let mut changed_context = fixture.context;
        changed_context.target_identity = Hash512::from_bytes([0x5a; Hash512::BYTE_LENGTH]);
        let wrong_target_pad = continuation_row_pad(
            &changed_context,
            &receiver_nonce,
            receiver_position as u16,
            0,
            selected_selector,
            &selected_keys[0],
        );
        let mut wrong_target = selected_ciphertext;
        xor_bytes(&mut wrong_target, &wrong_target_pad);
        assert!(
            wrong_target[PADDED_TOKEN_BYTE_LENGTH..]
                .iter()
                .any(|byte| *byte != 0)
        );

        for (hostile_gate_index, selected_key) in selected_keys.iter().enumerate().take(2) {
            let selected_selector = fixture.selectors[hostile_gate_index];
            let selected_gate =
                evaluated_input_gate(&fixture, receiver_position, hostile_gate_index);
            let selected_ciphertext =
                selected_gate.continuation_rows[usize::from(selected_selector)];
            let selected_pad = continuation_row_pad(
                &fixture.context,
                &receiver_nonce,
                receiver_position as u16,
                hostile_gate_index as u32,
                selected_selector,
                selected_key,
            );
            let row_offset = continuation_rows_offset(&fixture.plan, hostile_gate_index)
                + usize::from(selected_selector) * CONTINUATION_ROW_BYTE_LENGTH;
            for authenticator_byte in 0..CONTINUATION_AUTHENTICATOR_BYTE_LENGTH {
                let mut mutated_ciphertext = selected_ciphertext;
                mutated_ciphertext[PADDED_TOKEN_BYTE_LENGTH + authenticator_byte] ^= 1;
                xor_bytes(&mut mutated_ciphertext, &selected_pad);
                assert!(
                    mutated_ciphertext[PADDED_TOKEN_BYTE_LENGTH..]
                        .iter()
                        .any(|byte| *byte != 0),
                    "every continuation authenticator byte is checked",
                );

                let mut mutated_chunks = fixture.chunks.clone();
                mutated_chunks[receiver_position]
                    [row_offset + PADDED_TOKEN_BYTE_LENGTH + authenticator_byte] ^= 1;
                let (mutated_manifests, mutated_identities) =
                    rebind_manifests(&fixture.manifests, &mutated_chunks);
                assert_eq!(
                    evaluate_padded_batch(
                        &fixture.context,
                        &mutated_manifests,
                        &mutated_chunks,
                        &mutated_identities,
                    ),
                    Err(PaddedContinuationError::ContinuationAuthenticationFailed),
                    "gate {hostile_gate_index} row {selected_selector} authenticator byte \
                     {authenticator_byte} reaches the evaluator check"
                );
            }

            let mut invalid_plaintext = selected_ciphertext;
            xor_bytes(&mut invalid_plaintext, &selected_pad);
            invalid_plaintext[PADDED_LABEL_BYTE_LENGTH] = 2;
            invalid_plaintext[PADDED_TOKEN_BYTE_LENGTH..].fill(0);
            let mut invalid_ciphertext = invalid_plaintext;
            xor_bytes(&mut invalid_ciphertext, &selected_pad);
            let mut invalid_chunks = fixture.chunks.clone();
            invalid_chunks[receiver_position]
                [row_offset..row_offset + CONTINUATION_ROW_BYTE_LENGTH]
                .copy_from_slice(&invalid_ciphertext);
            let (invalid_manifests, invalid_identities) =
                rebind_manifests(&fixture.manifests, &invalid_chunks);
            assert_eq!(
                evaluate_padded_batch(
                    &fixture.context,
                    &invalid_manifests,
                    &invalid_chunks,
                    &invalid_identities,
                ),
                Err(PaddedContinuationError::InvalidBody),
                "gate {hostile_gate_index} row {selected_selector} refuses a malformed token"
            );
        }
    }

    #[test]
    fn zero_constant_coordinated_error_is_confluent_but_single_error_refuses() {
        let fixture = build_reduced_fixture();
        let evaluated = (0..3)
            .map(|position| evaluated_input_gate(&fixture, position, 0))
            .collect::<Vec<_>>();
        let weights = interpolation_weights_at_zero();
        let mut first_error = deterministic_module(0xfeed);
        first_error[0] |= 1;
        let mut second_error = deterministic_module(0xcafe);
        second_error[0] |= 1;
        let mut third_error = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
        module_add_scaled(&mut third_error, &first_error, weights[0]);
        module_add_scaled(&mut third_error, &second_error, weights[1]);
        let previous = third_error;
        third_error.fill(0);
        module_add_scaled(
            &mut third_error,
            &previous,
            weights[2].inverse().expect("nonzero weight"),
        );
        assert!(first_error.iter().any(|byte| *byte != 0));
        assert!(second_error.iter().any(|byte| *byte != 0));
        assert!(third_error.iter().any(|byte| *byte != 0));

        let mutate = |chunks: &mut [Vec<u8>], garbler: usize, error: &ModuleValue| {
            let receiver_position = 0;
            let basis = 0;
            let color = evaluated[garbler].masked_tokens[basis].color;
            let row_index = (receiver_position * FIELD_BIT_WIDTH + basis) * 2 + usize::from(color);
            let start =
                joint_rows_offset(&fixture.plan, 0) + row_index * PADDED_MODULE_VALUE_BYTE_LENGTH;
            for (byte, delta) in chunks[garbler][start..start + PADDED_MODULE_VALUE_BYTE_LENGTH]
                .iter_mut()
                .zip(error)
            {
                *byte ^= delta;
            }
        };

        let mut single = fixture.chunks.clone();
        mutate(&mut single, 0, &first_error);
        let (single_manifests, single_identities) = rebind_manifests(&fixture.manifests, &single);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &single_manifests,
                &single,
                &single_identities,
            ),
            Err(PaddedContinuationError::ContinuationAuthenticationFailed)
        );

        let mut coordinated = fixture.chunks.clone();
        mutate(&mut coordinated, 0, &first_error);
        mutate(&mut coordinated, 1, &second_error);
        mutate(&mut coordinated, 2, &third_error);
        let (coordinated_manifests, coordinated_identities) =
            rebind_manifests(&fixture.manifests, &coordinated);
        let result = evaluate_padded_batch(
            &fixture.context,
            &coordinated_manifests,
            &coordinated,
            &coordinated_identities,
        )
        .expect("zero-constant errors preserve the selected continuation");
        assert_eq!(result.terminal_bits, fixture.expected_terminal_bits);

        let mut nonzero_constant = fixture.chunks.clone();
        let mut changed_third_error = third_error;
        changed_third_error[0] ^= 1;
        mutate(&mut nonzero_constant, 0, &first_error);
        mutate(&mut nonzero_constant, 1, &second_error);
        mutate(&mut nonzero_constant, 2, &changed_third_error);
        let (nonzero_manifests, nonzero_identities) =
            rebind_manifests(&fixture.manifests, &nonzero_constant);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &nonzero_manifests,
                &nonzero_constant,
                &nonzero_identities,
            ),
            Err(PaddedContinuationError::ContinuationAuthenticationFailed)
        );
    }

    #[test]
    fn losing_fork_variants_separate_continuation_keys_and_rows() {
        let fixture = build_reduced_fixture();
        let make_variant = |variant: usize| {
            let mut gate_material = fixture.gate_material[0].clone();
            let delta = deterministic_module(0x8800 + variant as u64);
            let mut constant_delta = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
            module_add_scaled(
                &mut constant_delta,
                &delta,
                interpolation_weights_at_zero()[0],
            );
            for (byte, change) in gate_material[..PADDED_MODULE_VALUE_BYTE_LENGTH]
                .iter_mut()
                .zip(constant_delta)
            {
                *byte ^= change;
            }
            let first_receiver_first_pad = 3 * PADDED_MODULE_VALUE_BYTE_LENGTH;
            for (byte, change) in gate_material[first_receiver_first_pad
                ..first_receiver_first_pad + PADDED_MODULE_VALUE_BYTE_LENGTH]
                .iter_mut()
                .zip(delta)
            {
                *byte ^= change;
            }
            let allocation_nonce = deterministic_bytes(
                PADDED_ALLOCATION_NONCE_BYTE_LENGTH,
                0x810_000 + variant as u64,
            );
            let label_entropy = deterministic_bytes(
                padded_label_entropy_byte_length(&fixture.plan).expect("entropy length"),
                0x820_000 + variant as u64,
            );
            let mut canonical_label_entropy = label_entropy;
            for pair in canonical_label_entropy.chunks_exact_mut(TOKEN_PAIR_ENTROPY_BYTE_LENGTH) {
                pair[2 * PADDED_LABEL_BYTE_LENGTH] &= 1;
                if pair[..PADDED_LABEL_BYTE_LENGTH]
                    == pair[PADDED_LABEL_BYTE_LENGTH..2 * PADDED_LABEL_BYTE_LENGTH]
                {
                    pair[PADDED_LABEL_BYTE_LENGTH] ^= 1;
                }
            }
            let decoded_gate_material = gate_material
                .chunks_exact(PADDED_GATE_MATERIAL_BYTE_LENGTH)
                .map(decode_gate_material)
                .collect::<Result<Vec<_>, _>>()
                .expect("fork fixture gate material decodes");
            generate_participant_for_context(
                &fixture.context,
                &fixture.plan,
                PaddedParticipantGenerationInput {
                    participant_position: 0,
                    initial_wire_values: &fixture.initial_values[0],
                    gate_mask_shares: &fixture.gate_masks[0],
                    terminal_mask_shares: &fixture.terminal_masks[0],
                    allocation_nonce: &allocation_nonce,
                    label_entropy: &canonical_label_entropy,
                },
                &decoded_gate_material,
            )
            .expect("fork variant generates")
        };

        let variants = [make_variant(0), make_variant(1)];
        assert_ne!(variants[0].chunk, variants[1].chunk);
        assert_ne!(variants[0].manifest_identity, variants[1].manifest_identity);

        let inventory_for = |variant: &GeneratedPaddedParticipant| {
            let mut chunks = fixture.chunks.clone();
            chunks[0] = variant.chunk.clone();
            let mut manifests = fixture.manifests.clone();
            manifests[0] = variant.manifest.clone();
            let identities = manifests
                .iter()
                .map(|manifest| {
                    hash_bytes(MANIFEST_IDENTITY_DOMAIN, manifest).expect("manifest identity")
                })
                .collect::<Vec<_>>();
            (chunks, manifests, identities)
        };
        let first_inventory = inventory_for(&variants[0]);
        let second_inventory = inventory_for(&variants[1]);
        for (chunks, manifests, identities) in [&first_inventory, &second_inventory] {
            let result = evaluate_padded_batch(&fixture.context, manifests, chunks, identities)
                .expect("each losing-fork variant is internally valid");
            assert_eq!(result.terminal_bits, fixture.expected_terminal_bits);
        }

        let selected_key = |chunks: &[Vec<u8>]| {
            let gate_index = 0;
            let receiver_position = 0;
            let gate = fixture.plan.gates[gate_index];
            let mut aggregate_evaluations = Vec::with_capacity(PARTICIPANT_COUNT);
            for (garbler_position, bytes) in chunks.iter().enumerate() {
                let chunk =
                    ParsedChunk::new(bytes, &fixture.context).expect("variant chunk parses");
                let initial = chunk
                    .initial_tokens(&fixture.plan)
                    .expect("variant initial tokens");
                let evaluated = evaluate_gate_payload_from_chunk(
                    &chunk,
                    &fixture.context,
                    &fixture.plan,
                    gate_index,
                    initial[usize::from(gate.left_wire)],
                    initial[usize::from(gate.right_wire)],
                )
                .expect("variant gate evaluates");
                let mut aggregate = [0_u8; PADDED_MODULE_VALUE_BYTE_LENGTH];
                for (basis, token) in evaluated.masked_tokens.iter().copied().enumerate() {
                    let mut plaintext = evaluated
                        .padded_row(receiver_position, basis, token.color)
                        .expect("selected variant row");
                    let pad = joint_row_pad(
                        &fixture.context,
                        &chunk.allocation_nonce,
                        garbler_position as u16,
                        receiver_position as u16,
                        gate_index as u32,
                        basis as u8,
                        token.color,
                        &token.label,
                    );
                    module_xor(&mut plaintext, &pad);
                    module_xor(&mut aggregate, &plaintext);
                }
                aggregate_evaluations.push(aggregate);
            }
            interpolate_module_at_zero(&aggregate_evaluations).expect("variant key interpolates")
        };
        let first_key = selected_key(&first_inventory.0);
        let second_key = selected_key(&second_inventory.0);
        assert_ne!(first_key, second_key);

        for (foreign_key, foreign_inventory) in [
            (&first_key, &second_inventory),
            (&second_key, &first_inventory),
        ] {
            let receiver_chunk = ParsedChunk::new(&foreign_inventory.0[0], &fixture.context)
                .expect("foreign receiver chunk parses");
            let initial = receiver_chunk
                .initial_tokens(&fixture.plan)
                .expect("foreign initial tokens");
            let gate = fixture.plan.gates[0];
            let evaluated = evaluate_gate_payload_from_chunk(
                &receiver_chunk,
                &fixture.context,
                &fixture.plan,
                0,
                initial[usize::from(gate.left_wire)],
                initial[usize::from(gate.right_wire)],
            )
            .expect("foreign gate evaluates");
            for selector in 0..=1_u8 {
                let mut plaintext = evaluated.continuation_rows[usize::from(selector)];
                let pad = continuation_row_pad(
                    &fixture.context,
                    &receiver_chunk.allocation_nonce,
                    0,
                    0,
                    selector,
                    foreign_key,
                );
                xor_bytes(&mut plaintext, &pad);
                assert!(
                    plaintext[PADDED_TOKEN_BYTE_LENGTH..]
                        .iter()
                        .any(|byte| *byte != 0),
                    "a selected key from another fork opens neither row"
                );
            }
        }

        let continuation_offset = continuation_rows_offset(&fixture.plan, 0);
        let continuation_end = continuation_offset + 2 * CONTINUATION_ROW_BYTE_LENGTH;
        for (recipient, donor) in [(&variants[0], &variants[1]), (&variants[1], &variants[0])] {
            let mut chunks = fixture.chunks.clone();
            chunks[0] = recipient.chunk.clone();
            chunks[0][continuation_offset..continuation_end]
                .copy_from_slice(&donor.chunk[continuation_offset..continuation_end]);
            let mut manifests = fixture.manifests.clone();
            manifests[0] = recipient.manifest.clone();
            let (manifests, identities) = rebind_manifests(&manifests, &chunks);
            assert_eq!(
                evaluate_padded_batch(&fixture.context, &manifests, &chunks, &identities),
                Err(PaddedContinuationError::ContinuationAuthenticationFailed)
            );
        }
    }

    #[test]
    fn masked_and_terminal_codeword_degree_limits_are_exact() {
        let fixture = build_reduced_fixture();
        let mut degree_seven_chunks = fixture.chunks.clone();
        let mut degree_seven_error = vec![Gf16::ZERO; 8];
        degree_seven_error[7] = Gf16::ONE;
        let masked_map_offset = gate_payload_offset(&fixture.plan, 0)
            + LOCAL_MULTIPLICATION_ROW_COUNT * PADDED_TOKEN_BYTE_LENGTH
            + FIELD_BIT_WIDTH * PADDED_TOKEN_BYTE_LENGTH;

        let mut noncanonical_masked_map = fixture.chunks.clone();
        noncanonical_masked_map[0][masked_map_offset] |= 0x10;
        let (noncanonical_manifests, noncanonical_identities) =
            rebind_manifests(&fixture.manifests, &noncanonical_masked_map);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &noncanonical_manifests,
                &noncanonical_masked_map,
                &noncanonical_identities,
            ),
            Err(PaddedContinuationError::InvalidBody)
        );

        let mut nonbinary_constant_chunks = fixture.chunks.clone();
        let constant_delta = fixture.selectors[0] ^ 2;
        for chunk in &mut nonbinary_constant_chunks {
            chunk[masked_map_offset] ^= constant_delta;
        }
        let (nonbinary_manifests, nonbinary_identities) =
            rebind_manifests(&fixture.manifests, &nonbinary_constant_chunks);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &nonbinary_manifests,
                &nonbinary_constant_chunks,
                &nonbinary_identities,
            ),
            Err(PaddedContinuationError::InvalidCodeword)
        );

        for (participant_position, chunk) in degree_seven_chunks.iter_mut().enumerate() {
            let error = evaluate_field_polynomial(
                &degree_seven_error,
                Gf16::new((participant_position + 1) as u8),
            );
            chunk[masked_map_offset] ^= error.as_u8();
        }
        let (degree_seven_manifests, degree_seven_identities) =
            rebind_manifests(&fixture.manifests, &degree_seven_chunks);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &degree_seven_manifests,
                &degree_seven_chunks,
                &degree_seven_identities,
            ),
            Err(PaddedContinuationError::InvalidCodeword)
        );

        let mut degree_four_chunks = fixture.chunks.clone();
        let mut degree_four_error = vec![Gf16::ZERO; 5];
        degree_four_error[4] = Gf16::ONE;
        let terminal_map_offset =
            terminal_payload_offset(&fixture.plan, 0) + PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH - 1;
        for (participant_position, chunk) in degree_four_chunks.iter_mut().enumerate() {
            let error = evaluate_field_polynomial(
                &degree_four_error,
                Gf16::new((participant_position + 1) as u8),
            );
            chunk[terminal_map_offset] ^= error.as_u8();
        }
        let (degree_four_manifests, degree_four_identities) =
            rebind_manifests(&fixture.manifests, &degree_four_chunks);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &degree_four_manifests,
                &degree_four_chunks,
                &degree_four_identities,
            ),
            Err(PaddedContinuationError::InvalidCodeword)
        );
    }

    #[test]
    fn malformed_terminal_relations_refuse() {
        let fixture = build_reduced_fixture();
        let map_offset =
            terminal_payload_offset(&fixture.plan, 0) + PADDED_TERMINAL_PAYLOAD_BYTE_LENGTH - 1;

        let mut noncanonical = fixture.chunks.clone();
        noncanonical[0][map_offset] |= 0x10;
        let (noncanonical_manifests, noncanonical_identities) =
            rebind_manifests(&fixture.manifests, &noncanonical);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &noncanonical_manifests,
                &noncanonical,
                &noncanonical_identities,
            ),
            Err(PaddedContinuationError::InvalidBody)
        );

        let mut noncodeword = fixture.chunks.clone();
        noncodeword[0][map_offset] ^= 1;
        let (noncodeword_manifests, noncodeword_identities) =
            rebind_manifests(&fixture.manifests, &noncodeword);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &noncodeword_manifests,
                &noncodeword,
                &noncodeword_identities,
            ),
            Err(PaddedContinuationError::InvalidCodeword)
        );

        let mut nonbinary = fixture.chunks.clone();
        let original = u8::from(fixture.expected_terminal_bits[0]);
        let delta = original ^ 2;
        for body in &mut nonbinary {
            body[map_offset] ^= delta;
        }
        let (nonbinary_manifests, nonbinary_identities) =
            rebind_manifests(&fixture.manifests, &nonbinary);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &nonbinary_manifests,
                &nonbinary,
                &nonbinary_identities,
            ),
            Err(PaddedContinuationError::InvalidCodeword)
        );
    }

    #[test]
    fn context_replay_and_old_transcript_grammar_refuse() {
        let fixture = build_reduced_fixture();
        let mut replayed = fixture.chunks.clone();
        replayed[0][6] ^= 1;
        let (replayed_manifests, replayed_identities) =
            rebind_manifests(&fixture.manifests, &replayed);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &replayed_manifests,
                &replayed,
                &replayed_identities,
            ),
            Err(PaddedContinuationError::InvalidContext)
        );

        let old_body = vec![0_u8; PADDED_REDUCED_CHUNK_BYTE_LENGTH];
        let mut old_chunks = fixture.chunks.clone();
        old_chunks[0] = old_body;
        let (old_manifests, _) = rebind_manifests(&fixture.manifests, &old_chunks);
        assert!(ParsedManifest::new(&old_manifests[0], &fixture.context).is_ok());
        assert!(matches!(
            ParsedChunk::new(&old_chunks[0], &fixture.context),
            Err(PaddedContinuationError::InvalidContext)
        ));
    }

    #[test]
    fn chunk_manifest_and_token_grammars_are_exact_and_fail_closed() {
        let fixture = build_reduced_fixture();
        let chunk = &fixture.chunks[0];
        let manifest = &fixture.manifests[0];
        assert_eq!(&chunk[0..4], &CHUNK_MAGIC);
        assert_eq!(u16::from_le_bytes(chunk[4..6].try_into().unwrap()), 1);
        assert_eq!(&chunk[6..70], fixture.context.target_identity.as_bytes());
        assert_eq!(&chunk[70..134], fixture.context.circuit_identity.as_bytes());
        assert_eq!(u16::from_le_bytes(chunk[134..136].try_into().unwrap()), 10);
        assert_eq!(u16::from_le_bytes(chunk[136..138].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(chunk[138..140].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(chunk[172..176].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(chunk[176..180].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(chunk[180..184].try_into().unwrap()), 7);
        assert_eq!(&chunk[184..186], &[1, 1]);
        assert_eq!(&chunk[186..250], &[0_u8; Hash512::BYTE_LENGTH]);

        assert_eq!(&manifest[0..4], &MANIFEST_MAGIC);
        assert_eq!(u16::from_le_bytes(manifest[4..6].try_into().unwrap()), 1);
        assert_eq!(&manifest[6..70], fixture.context.target_identity.as_bytes());
        assert_eq!(
            &manifest[70..134],
            fixture.context.circuit_identity.as_bytes()
        );
        assert_eq!(
            u16::from_le_bytes(manifest[134..136].try_into().unwrap()),
            10
        );
        assert_eq!(
            u16::from_le_bytes(manifest[136..138].try_into().unwrap()),
            0
        );
        assert_eq!(
            u16::from_le_bytes(manifest[138..140].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(manifest[172..176].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(manifest[176..180].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(manifest[180..184].try_into().unwrap()),
            7
        );
        assert_eq!(&manifest[184..186], &[1, 1]);
        assert_eq!(
            u32::from_le_bytes(manifest[186..190].try_into().unwrap()),
            PADDED_REDUCED_CHUNK_BYTE_LENGTH as u32
        );
        assert_eq!(
            &manifest[190..254],
            hash_bytes(CHUNK_IDENTITY_DOMAIN, chunk)
                .expect("chunk identity")
                .as_bytes()
        );

        for offset in [0, 4, 6, 70, 134, 138, 172, 176, 180, 184, 185, 186] {
            let mut malformed = chunk.clone();
            malformed[offset] ^= 1;
            assert!(ParsedChunk::new(&malformed, &fixture.context).is_err());
        }
        let mut invalid_position = chunk.clone();
        invalid_position[136..138].copy_from_slice(&10_u16.to_le_bytes());
        assert_eq!(
            ParsedChunk::new(&invalid_position, &fixture.context).err(),
            Some(PaddedContinuationError::WrongParticipantPosition)
        );
        for offset in [0, 4, 6, 70, 134, 138, 172, 176, 180, 184, 185, 186] {
            let mut malformed = manifest.clone();
            malformed[offset] ^= 1;
            assert!(ParsedManifest::new(&malformed, &fixture.context).is_err());
        }
        let mut invalid_manifest_position = manifest.clone();
        invalid_manifest_position[136..138].copy_from_slice(&10_u16.to_le_bytes());
        assert_eq!(
            ParsedManifest::new(&invalid_manifest_position, &fixture.context).err(),
            Some(PaddedContinuationError::WrongParticipantPosition)
        );

        let mut malformed_initial = fixture.chunks.clone();
        malformed_initial[0][PADDED_CHUNK_HEADER_BYTE_LENGTH + PADDED_LABEL_BYTE_LENGTH] = 2;
        let (malformed_initial_manifests, malformed_initial_identities) =
            rebind_manifests(&fixture.manifests, &malformed_initial);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &malformed_initial_manifests,
                &malformed_initial,
                &malformed_initial_identities,
            ),
            Err(PaddedContinuationError::InvalidBody)
        );

        let mut malformed_local = fixture.chunks.clone();
        let first_local_rows = gate_payload_offset(&fixture.plan, 0);
        for row in 0..4 {
            malformed_local[0]
                [first_local_rows + row * PADDED_TOKEN_BYTE_LENGTH + PADDED_LABEL_BYTE_LENGTH] ^= 2;
        }
        let (malformed_local_manifests, malformed_local_identities) =
            rebind_manifests(&fixture.manifests, &malformed_local);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &malformed_local_manifests,
                &malformed_local,
                &malformed_local_identities,
            ),
            Err(PaddedContinuationError::InvalidBody)
        );

        let mut malformed_terminal = fixture.chunks.clone();
        let first_terminal_rows = terminal_payload_offset(&fixture.plan, 0);
        for row in 0..4 {
            malformed_terminal[0][first_terminal_rows
                + row * PADDED_TOKEN_BYTE_LENGTH
                + PADDED_LABEL_BYTE_LENGTH] ^= 2;
        }
        let (malformed_terminal_manifests, malformed_terminal_identities) =
            rebind_manifests(&fixture.manifests, &malformed_terminal);
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &malformed_terminal_manifests,
                &malformed_terminal,
                &malformed_terminal_identities,
            ),
            Err(PaddedContinuationError::InvalidBody)
        );
    }

    #[test]
    fn cross_participant_label_collision_is_an_explicit_global_bad_event() {
        let plan = reviewed_reduced_plan();
        let mut first_entropy = deterministic_label_entropy(&plan, 0);
        let second_entropy = deterministic_label_entropy(&plan, 1);
        let exposed_label = second_entropy[..PADDED_LABEL_BYTE_LENGTH].to_vec();
        assert_ne!(
            &first_entropy[..PADDED_LABEL_BYTE_LENGTH],
            exposed_label.as_slice()
        );
        first_entropy[PADDED_LABEL_BYTE_LENGTH..2 * PADDED_LABEL_BYTE_LENGTH]
            .copy_from_slice(&exposed_label);
        let first_pair = LabelEntropyCursor::new(&first_entropy)
            .read_pair()
            .expect("per-body validation accepts the first corpus");
        let second_pair = LabelEntropyCursor::new(&second_entropy)
            .read_pair()
            .expect("per-body validation accepts the second corpus");
        assert_eq!(first_pair.tokens[1].label, second_pair.tokens[0].label);
    }

    #[test]
    fn invalid_entropy_material_and_duplicate_nonce_refuse() {
        let fixture = build_reduced_fixture();
        let mut duplicate_nonce = fixture.chunks.clone();
        let nonce_offset = 4 + 2 + 2 * Hash512::BYTE_LENGTH + 2 + 2 + 2;
        let source_nonce = duplicate_nonce[0]
            [nonce_offset..nonce_offset + PADDED_ALLOCATION_NONCE_BYTE_LENGTH]
            .to_vec();
        duplicate_nonce[1][nonce_offset..nonce_offset + PADDED_ALLOCATION_NONCE_BYTE_LENGTH]
            .copy_from_slice(&source_nonce);
        let (mut duplicate_manifests, _) = rebind_manifests(&fixture.manifests, &duplicate_nonce);
        duplicate_manifests[1][nonce_offset..nonce_offset + PADDED_ALLOCATION_NONCE_BYTE_LENGTH]
            .copy_from_slice(&source_nonce);
        let duplicate_identities = duplicate_manifests
            .iter()
            .map(|manifest| {
                hash_bytes(MANIFEST_IDENTITY_DOMAIN, manifest).expect("manifest identity")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate_padded_batch(
                &fixture.context,
                &duplicate_manifests,
                &duplicate_nonce,
                &duplicate_identities,
            ),
            Err(PaddedContinuationError::DuplicateAllocationNonce)
        );

        let mut invalid_material = fixture.gate_material[0].clone();
        invalid_material[PADDED_MODULE_VALUE_BYTE_LENGTH..2 * PADDED_MODULE_VALUE_BYTE_LENGTH]
            .fill(0);
        assert_eq!(
            decode_gate_material(&invalid_material[..PADDED_GATE_MATERIAL_BYTE_LENGTH]),
            Err(PaddedContinuationError::InvalidGateMaterial)
        );

        let repeated =
            decode_gate_material(&fixture.gate_material[0][..PADDED_GATE_MATERIAL_BYTE_LENGTH])
                .expect("valid gate material");
        assert_eq!(
            validate_operation_fresh_gate_material(&[repeated.clone(), repeated]),
            Err(PaddedContinuationError::InvalidGateMaterial)
        );

        let mut cross_alternative_material = fixture.gate_material[0].clone();
        let second_gate_start = PADDED_GATE_MATERIAL_BYTE_LENGTH;
        let mut second_gate_alternative: ModuleValue = cross_alternative_material
            [second_gate_start..second_gate_start + PADDED_MODULE_VALUE_BYTE_LENGTH]
            .try_into()
            .expect("second gate A");
        let second_gate_difference: ModuleValue = cross_alternative_material[second_gate_start
            + PADDED_MODULE_VALUE_BYTE_LENGTH
            ..second_gate_start + 2 * PADDED_MODULE_VALUE_BYTE_LENGTH]
            .try_into()
            .expect("second gate B");
        module_xor(&mut second_gate_alternative, &second_gate_difference);
        cross_alternative_material[..PADDED_MODULE_VALUE_BYTE_LENGTH]
            .copy_from_slice(&second_gate_alternative);
        let decoded = cross_alternative_material
            .chunks_exact(PADDED_GATE_MATERIAL_BYTE_LENGTH)
            .map(decode_gate_material)
            .collect::<Result<Vec<_>, _>>()
            .expect("cross-alternative material decodes");
        assert_eq!(
            validate_operation_fresh_gate_material(&decoded),
            Err(PaddedContinuationError::InvalidGateMaterial)
        );

        let mut first_to_final_collision = fixture.gate_material[0].clone();
        let final_gate_start = (fixture.plan.gates.len() - 1) * PADDED_GATE_MATERIAL_BYTE_LENGTH;
        let final_gate_key = first_to_final_collision
            [final_gate_start..final_gate_start + PADDED_MODULE_VALUE_BYTE_LENGTH]
            .to_vec();
        first_to_final_collision[..PADDED_MODULE_VALUE_BYTE_LENGTH]
            .copy_from_slice(&final_gate_key);
        let decoded = first_to_final_collision
            .chunks_exact(PADDED_GATE_MATERIAL_BYTE_LENGTH)
            .map(decode_gate_material)
            .collect::<Result<Vec<_>, _>>()
            .expect("nonadjacent collision material decodes");
        assert_eq!(
            validate_operation_fresh_gate_material(&decoded),
            Err(PaddedContinuationError::InvalidGateMaterial)
        );

        let mut invalid_entropy = deterministic_label_entropy(&fixture.plan, 0);
        invalid_entropy[2 * PADDED_LABEL_BYTE_LENGTH] = 2;
        assert_eq!(
            LabelEntropyCursor::new(&invalid_entropy).read_pair(),
            Err(PaddedContinuationError::InvalidLabelEntropy)
        );

        let mut equal_pair_entropy = deterministic_label_entropy(&fixture.plan, 0);
        let first_label = equal_pair_entropy[..PADDED_LABEL_BYTE_LENGTH].to_vec();
        equal_pair_entropy[PADDED_LABEL_BYTE_LENGTH..2 * PADDED_LABEL_BYTE_LENGTH]
            .copy_from_slice(&first_label);
        assert_eq!(
            LabelEntropyCursor::new(&equal_pair_entropy).read_pair(),
            Err(PaddedContinuationError::InvalidLabelEntropy)
        );

        let allocation_nonce = deterministic_bytes(PADDED_ALLOCATION_NONCE_BYTE_LENGTH, 0x710_000);
        let label_entropy = deterministic_label_entropy(&fixture.plan, 0);
        let decoded_gate_material = fixture.gate_material[0]
            .chunks_exact(PADDED_GATE_MATERIAL_BYTE_LENGTH)
            .map(decode_gate_material)
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture gate material decodes");
        for field in 0..3 {
            let mut initial_values = fixture.initial_values[0].clone();
            let mut gate_masks = fixture.gate_masks[0].clone();
            let mut terminal_masks = fixture.terminal_masks[0].clone();
            match field {
                0 => initial_values[0] = 0x10,
                1 => gate_masks[0] = 0x10,
                2 => terminal_masks[0] = 0x10,
                _ => unreachable!(),
            }
            assert_eq!(
                generate_participant_for_context(
                    &fixture.context,
                    &fixture.plan,
                    PaddedParticipantGenerationInput {
                        participant_position: 0,
                        initial_wire_values: &initial_values,
                        gate_mask_shares: &gate_masks,
                        terminal_mask_shares: &terminal_masks,
                        allocation_nonce: &allocation_nonce,
                        label_entropy: &label_entropy,
                    },
                    &decoded_gate_material,
                ),
                Err(PaddedContinuationError::InvalidBody),
                "noncanonical field {field} must refuse before GF(16) truncation"
            );
        }
    }
}
