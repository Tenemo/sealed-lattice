use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::Hash512,
    hashing::hash_framed_parts_512,
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::TallyPreparationError;

pub(crate) const TALLY_PREPARATION_CONTEXT_MAGIC: &[u8] =
    b"sealed-lattice/tally-preparation-context";
pub(crate) const TALLY_PREPARATION_CONTEXT_VERSION: u64 = 1;
pub(crate) const TALLY_PREPARATION_CONTEXT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/tally-preparation-context-identity/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TallyPreparationContext {
    action_context_hash: Hash512,
    roster_hash: Hash512,
    circuit_identity: Hash512,
    compiler_identity: Hash512,
    attempt_identifier: [u8; 32],
    participant_count: u16,
    option_count: u16,
    top_count: u16,
}

impl TallyPreparationContext {
    pub(crate) fn new(
        action_context_hash: Hash512,
        roster_hash: Hash512,
        attempt_identifier: [u8; 32],
        circuit: &CompiledTallyCircuit,
    ) -> Result<Self, TallyPreparationError> {
        let profile = circuit.profile();
        Ok(Self {
            action_context_hash,
            roster_hash,
            circuit_identity: Hash512::from_bytes(circuit.circuit_identity()?),
            compiler_identity: Hash512::from_bytes(CompiledTallyCircuit::compiler_identity()?),
            attempt_identifier,
            participant_count: profile.participant_count(),
            option_count: profile.option_count(),
            top_count: profile.top_count(),
        })
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn action_context_hash(self) -> Hash512 {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(self) -> Hash512 {
        self.roster_hash
    }

    pub(crate) fn is_bound_to_circuit(
        self,
        circuit: &CompiledTallyCircuit,
    ) -> Result<bool, TallyPreparationError> {
        let profile = circuit.profile();
        Ok(
            self.circuit_identity == Hash512::from_bytes(circuit.circuit_identity()?)
                && self.compiler_identity
                    == Hash512::from_bytes(CompiledTallyCircuit::compiler_identity()?)
                && self.participant_count == profile.participant_count()
                && self.option_count == profile.option_count()
                && self.top_count == profile.top_count(),
        )
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(370);
        append_bytes(&mut bytes, TALLY_PREPARATION_CONTEXT_MAGIC);
        append_varuint(&mut bytes, TALLY_PREPARATION_CONTEXT_VERSION);
        append_bytes(&mut bytes, self.action_context_hash.as_bytes());
        append_bytes(&mut bytes, self.roster_hash.as_bytes());
        append_bytes(&mut bytes, self.circuit_identity.as_bytes());
        append_bytes(&mut bytes, self.compiler_identity.as_bytes());
        append_bytes(&mut bytes, &self.attempt_identifier);
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.option_count));
        append_varuint(&mut bytes, u64::from(self.top_count));
        bytes
    }

    /// Decodes one exact preparation context without granting preparation
    /// authority. The caller must still verify every object that binds this
    /// context and the selected circuit identity.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        let magic_byte_length = usize::try_from(reader.read_varuint()?)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if magic_byte_length != TALLY_PREPARATION_CONTEXT_MAGIC.len()
            || reader.read_exact(magic_byte_length)? != TALLY_PREPARATION_CONTEXT_MAGIC
        {
            return Err(TallyPreparationError::PreparationContextEncodingMismatch);
        }
        if reader.read_varuint()? != TALLY_PREPARATION_CONTEXT_VERSION {
            return Err(TallyPreparationError::PreparationContextEncodingMismatch);
        }
        let action_context_hash = read_hash512(&mut reader)?;
        let roster_hash = read_hash512(&mut reader)?;
        let circuit_identity = read_hash512(&mut reader)?;
        let compiler_identity = read_hash512(&mut reader)?;
        let attempt_identifier_byte_length = usize::try_from(reader.read_varuint()?)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        if attempt_identifier_byte_length != 32 {
            return Err(TallyPreparationError::PreparationContextEncodingMismatch);
        }
        let attempt_identifier = reader
            .read_exact(attempt_identifier_byte_length)?
            .try_into()
            .map_err(|_| TallyPreparationError::PreparationContextEncodingMismatch)?;
        let participant_count = read_unsigned16(&mut reader)?;
        let option_count = read_unsigned16(&mut reader)?;
        let top_count = read_unsigned16(&mut reader)?;
        if !reader.is_finished()
            || TallyCircuitProfile::new(participant_count, option_count, top_count).is_err()
        {
            return Err(TallyPreparationError::PreparationContextEncodingMismatch);
        }
        let context = Self {
            action_context_hash,
            roster_hash,
            circuit_identity,
            compiler_identity,
            attempt_identifier,
            participant_count,
            option_count,
            top_count,
        };
        if context.canonical_bytes() != bytes {
            return Err(TallyPreparationError::PreparationContextEncodingMismatch);
        }
        Ok(context)
    }

    pub(crate) fn identity(self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            TALLY_PREPARATION_CONTEXT_IDENTITY_DOMAIN,
            &[&self.canonical_bytes()],
        ))
    }
}

fn read_hash512(reader: &mut CanonicalReader<'_>) -> Result<Hash512, TallyPreparationError> {
    let byte_length = usize::try_from(reader.read_varuint()?)
        .map_err(|_| TallyPreparationError::IntegerConversion)?;
    if byte_length != Hash512::BYTE_LENGTH {
        return Err(TallyPreparationError::PreparationContextEncodingMismatch);
    }
    Ok(Hash512::from_bytes(
        reader
            .read_exact(byte_length)?
            .try_into()
            .map_err(|_| TallyPreparationError::PreparationContextEncodingMismatch)?,
    ))
}

fn read_unsigned16(reader: &mut CanonicalReader<'_>) -> Result<u16, TallyPreparationError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| TallyPreparationError::IntegerConversion)
}
