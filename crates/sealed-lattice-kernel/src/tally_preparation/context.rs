use crate::{
    encoding::{append_bytes, append_varuint},
    foundation::Hash512,
    hashing::hash_framed_parts_512,
    tally_circuit::CompiledTallyCircuit,
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

    pub(crate) fn identity(self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            TALLY_PREPARATION_CONTEXT_IDENTITY_DOMAIN,
            &[&self.canonical_bytes()],
        ))
    }
}
