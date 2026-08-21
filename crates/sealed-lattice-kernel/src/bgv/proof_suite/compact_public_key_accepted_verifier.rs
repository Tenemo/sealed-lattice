//! Source-bound accepted-setup compact public-key verification lifecycle.
//!
//! The durable cursor binds canonical inputs and logical safe boundaries only.
//! CFW and WHIR fold state, decoded columns, Fourier
//! workspaces, and Merkle frontiers are reconstructed deterministically from
//! genesis after worker replacement.

use crate::foundation::{Hash512, RefusalReason};

#[cfg(test)]
use super::compact_public_key_algebraic_verifier::AlgebraicallyVerifiedCompactPublicKeyProof;

use super::{
    SourceVerifiedCompactPublicKeyProof, VerifiedCompactPublicKeyStatementAuthority,
    compact_proof_wire::CompactPublicInputBindings,
    compact_public_key_algebraic_verifier::{
        COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
        COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT,
        COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT,
        CompactPublicKeyAlgebraicVerification, CompactPublicKeyAlgebraicVerificationError,
        CompactPublicKeyAlgebraicVerificationPoll,
        compact_public_key_algebraic_checkpoint_safe_boundary_ordinal,
    },
    compact_public_key_statement_correspondence::CompactPublicKeyStatementCorrespondenceVerificationPoll,
    compact_public_key_verifier::VerifiedCompactPublicKeyTransport,
};

const ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_MAGIC: [u8; 8] = *b"SLCAVC04";
pub(crate) const ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH: usize =
    ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_MAGIC.len()
        + 6 * Hash512::BYTE_LENGTH
        + 2 * size_of::<u64>()
        + size_of::<u32>();
const SELECTED_COMPACT_PUBLIC_KEY_PUBLIC_COLUMN_COUNT: u32 = 122;
const SELECTED_COMPACT_PUBLIC_KEY_STATEMENT_TREE_COUNT: u32 = 4;
const SELECTED_COMPACT_PUBLIC_KEY_STATEMENT_TREE_COSET_COUNT: u32 = 1_024;
pub(crate) const ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT: u32 =
    SELECTED_COMPACT_PUBLIC_KEY_PUBLIC_COLUMN_COUNT
        + SELECTED_COMPACT_PUBLIC_KEY_STATEMENT_TREE_COUNT
            * SELECTED_COMPACT_PUBLIC_KEY_STATEMENT_TREE_COSET_COUNT;
pub(crate) const ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_SAFE_BOUNDARY_COUNT: u32 =
    COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT
        + ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AcceptedCompactPublicKeyVerificationCheckpoint {
    public_input_bindings: CompactPublicInputBindings,
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    completed_cfw_work_unit_count: u64,
    completed_whir_work_unit_count: u64,
    completed_correspondence_work_unit_count: u32,
}

impl AcceptedCompactPublicKeyVerificationCheckpoint {
    fn encode(self) -> [u8; ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH] {
        let mut bytes = [0_u8; ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH];
        let mut cursor = 0_usize;
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_MAGIC,
        );
        for binding in self.public_input_bindings.ordered_hashes() {
            write_checkpoint_bytes(&mut bytes, &mut cursor, binding.as_bytes());
        }
        write_checkpoint_bytes(&mut bytes, &mut cursor, &self.canonical_proof_binding);
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &self.canonical_public_input_binding,
        );
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &self.completed_cfw_work_unit_count.to_le_bytes(),
        );
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &self.completed_whir_work_unit_count.to_le_bytes(),
        );
        write_checkpoint_bytes(
            &mut bytes,
            &mut cursor,
            &self.completed_correspondence_work_unit_count.to_le_bytes(),
        );
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, RefusalReason> {
        if bytes.len() != ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH {
            return Err(RefusalReason::MalformedEncoding);
        }
        let mut cursor = 0_usize;
        if read_checkpoint_array::<8>(bytes, &mut cursor)?
            != ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_MAGIC
        {
            return Err(RefusalReason::MalformedEncoding);
        }
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
            Hash512::from_bytes(read_checkpoint_array(bytes, &mut cursor)?),
        );
        let canonical_proof_binding = read_checkpoint_array(bytes, &mut cursor)?;
        let canonical_public_input_binding = read_checkpoint_array(bytes, &mut cursor)?;
        let completed_cfw_work_unit_count =
            u64::from_le_bytes(read_checkpoint_array(bytes, &mut cursor)?);
        let completed_whir_work_unit_count =
            u64::from_le_bytes(read_checkpoint_array(bytes, &mut cursor)?);
        let completed_correspondence_work_unit_count =
            u32::from_le_bytes(read_checkpoint_array(bytes, &mut cursor)?);
        let checkpoint = Self {
            public_input_bindings,
            canonical_proof_binding,
            canonical_public_input_binding,
            completed_cfw_work_unit_count,
            completed_whir_work_unit_count,
            completed_correspondence_work_unit_count,
        };
        if cursor != bytes.len()
            || compact_public_key_algebraic_checkpoint_safe_boundary_ordinal(
                checkpoint.completed_cfw_work_unit_count,
                checkpoint.completed_whir_work_unit_count,
            )
            .is_none()
            || (checkpoint.completed_whir_work_unit_count
                != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT
                && checkpoint.completed_correspondence_work_unit_count != 0)
            || checkpoint.completed_correspondence_work_unit_count
                > ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT
        {
            return Err(RefusalReason::MalformedEncoding);
        }
        Ok(checkpoint)
    }

    const fn is_source_correspondence_checkpoint(self) -> bool {
        self.completed_whir_work_unit_count
            == COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT
    }

    fn safe_boundary_ordinal(self) -> Result<u32, RefusalReason> {
        if self.is_source_correspondence_checkpoint() {
            return COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT
                .checked_sub(1)
                .and_then(|whir_terminal_ordinal| {
                    whir_terminal_ordinal.checked_add(self.completed_correspondence_work_unit_count)
                })
                .ok_or(RefusalReason::OutsideSupportedProfile);
        }
        compact_public_key_algebraic_checkpoint_safe_boundary_ordinal(
            self.completed_cfw_work_unit_count,
            self.completed_whir_work_unit_count,
        )
        .ok_or(RefusalReason::WrongContext)
    }
}

fn write_checkpoint_bytes<const BYTE_LENGTH: usize>(
    output: &mut [u8],
    cursor: &mut usize,
    bytes: &[u8; BYTE_LENGTH],
) {
    let end = cursor
        .checked_add(BYTE_LENGTH)
        .expect("the fixed accepted verifier checkpoint geometry fits usize");
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn read_checkpoint_array<const BYTE_LENGTH: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; BYTE_LENGTH], RefusalReason> {
    let end = cursor
        .checked_add(BYTE_LENGTH)
        .ok_or(RefusalReason::MalformedEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(RefusalReason::MalformedEncoding)?
        .try_into()
        .map_err(|_| RefusalReason::MalformedEncoding)?;
    *cursor = end;
    Ok(value)
}

pub(crate) struct PreparedAcceptedCompactPublicKeyVerification {
    algebraic_verification: CompactPublicKeyAlgebraicVerification,
    public_input_bindings: CompactPublicInputBindings,
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    resume_target: Option<AcceptedCompactPublicKeyVerificationCheckpoint>,
}

impl PreparedAcceptedCompactPublicKeyVerification {
    pub(crate) fn prepare(
        transport: VerifiedCompactPublicKeyTransport,
        canonical_checkpoint_bytes: Option<&[u8]>,
    ) -> Result<Self, RefusalReason> {
        let public_input_bindings = transport.public_input_bindings();
        let canonical_proof_binding = transport.canonical_proof_binding();
        let canonical_public_input_binding = transport.canonical_public_input_binding();
        let checkpoint = canonical_checkpoint_bytes
            .map(AcceptedCompactPublicKeyVerificationCheckpoint::decode)
            .transpose()?;
        if let Some(checkpoint) = checkpoint
            && (checkpoint.public_input_bindings != public_input_bindings
                || checkpoint.canonical_proof_binding != canonical_proof_binding
                || checkpoint.canonical_public_input_binding != canonical_public_input_binding)
        {
            return Err(RefusalReason::WrongContext);
        }
        let algebraic_verification = match checkpoint {
            Some(checkpoint) => CompactPublicKeyAlgebraicVerification::resume_to_work_unit_counts(
                transport,
                checkpoint.completed_cfw_work_unit_count,
                checkpoint.completed_whir_work_unit_count,
            ),
            _ => CompactPublicKeyAlgebraicVerification::begin(transport),
        }
        .map_err(CompactPublicKeyAlgebraicVerificationError::refusal_reason)?;
        Ok(Self {
            algebraic_verification,
            public_input_bindings,
            canonical_proof_binding,
            canonical_public_input_binding,
            resume_target: checkpoint,
        })
    }
}

enum AcceptedCompactPublicKeyVerificationStage {
    Algebraic(Box<CompactPublicKeyAlgebraicVerification>),
    SourceCorrespondence(Box<
        super::compact_public_key_statement_correspondence::CompactPublicKeyStatementCorrespondenceVerification,
    >),
}

pub(in crate::bgv) struct AcceptedCompactPublicKeyVerification {
    statement_authority: Option<VerifiedCompactPublicKeyStatementAuthority>,
    stage: Option<AcceptedCompactPublicKeyVerificationStage>,
    public_input_bindings: CompactPublicInputBindings,
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    completed_cfw_work_unit_count: u64,
    completed_whir_work_unit_count: u64,
    completed_correspondence_work_unit_count: u32,
    resume_target: Option<AcceptedCompactPublicKeyVerificationCheckpoint>,
}

pub(in crate::bgv) enum AcceptedCompactPublicKeyVerificationPoll {
    WorkCompleted {
        completed_work_unit_count: u32,
        checkpoint_safe_boundary_ordinal: Option<u32>,
    },
    ResumeComplete {
        completed_work_unit_count: u32,
        checkpoint_safe_boundary_ordinal: u32,
    },
    Complete(Box<SourceVerifiedCompactPublicKeyProof>),
}

impl AcceptedCompactPublicKeyVerification {
    pub(crate) fn from_prepared(
        statement_authority: VerifiedCompactPublicKeyStatementAuthority,
        prepared: PreparedAcceptedCompactPublicKeyVerification,
    ) -> Self {
        Self {
            statement_authority: Some(statement_authority),
            stage: Some(AcceptedCompactPublicKeyVerificationStage::Algebraic(
                Box::new(prepared.algebraic_verification),
            )),
            public_input_bindings: prepared.public_input_bindings,
            canonical_proof_binding: prepared.canonical_proof_binding,
            canonical_public_input_binding: prepared.canonical_public_input_binding,
            completed_cfw_work_unit_count: 0,
            completed_whir_work_unit_count: 0,
            completed_correspondence_work_unit_count: 0,
            resume_target: prepared.resume_target,
        }
    }

    /// Enters source correspondence from the positive algebraic terminal.
    ///
    /// This test-only transition lets native evidence persist the combined
    /// accepted-verifier cursor without replaying the complete algebraic proof
    /// in the producer process. The input type has no decoder or public
    /// constructor, so this cannot bypass positive algebraic verification.
    #[cfg(test)]
    pub(crate) fn from_algebraically_verified(
        statement_authority: VerifiedCompactPublicKeyStatementAuthority,
        algebraically_verified_proof: AlgebraicallyVerifiedCompactPublicKeyProof,
    ) -> Result<Self, RefusalReason> {
        let public_input_bindings = algebraically_verified_proof
            .transport()
            .public_input_bindings();
        let canonical_proof_binding = algebraically_verified_proof
            .transport()
            .canonical_proof_binding();
        let canonical_public_input_binding = algebraically_verified_proof
            .transport()
            .canonical_public_input_binding();
        let correspondence = statement_authority
            .begin_binding_algebraically_verified_proof(algebraically_verified_proof)?;
        Ok(Self {
            statement_authority: None,
            stage: Some(
                AcceptedCompactPublicKeyVerificationStage::SourceCorrespondence(Box::new(
                    correspondence,
                )),
            ),
            public_input_bindings,
            canonical_proof_binding,
            canonical_public_input_binding,
            completed_cfw_work_unit_count:
                COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
            completed_whir_work_unit_count:
                COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT,
            completed_correspondence_work_unit_count: 0,
            resume_target: None,
        })
    }

    pub(in crate::bgv) fn canonical_checkpoint_bytes(
        &self,
    ) -> Result<[u8; ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_CHECKPOINT_BYTE_LENGTH], RefusalReason>
    {
        if self.stage.is_none() || self.resume_target.is_some() {
            return Err(RefusalReason::ConsumedState);
        }
        compact_public_key_algebraic_checkpoint_safe_boundary_ordinal(
            self.completed_cfw_work_unit_count,
            self.completed_whir_work_unit_count,
        )
        .ok_or(RefusalReason::ConsumedState)?;
        if self.completed_whir_work_unit_count
            != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT
            && self.completed_correspondence_work_unit_count != 0
        {
            return Err(RefusalReason::ConsumedState);
        }
        Ok(AcceptedCompactPublicKeyVerificationCheckpoint {
            public_input_bindings: self.public_input_bindings,
            canonical_proof_binding: self.canonical_proof_binding,
            canonical_public_input_binding: self.canonical_public_input_binding,
            completed_cfw_work_unit_count: self.completed_cfw_work_unit_count,
            completed_whir_work_unit_count: self.completed_whir_work_unit_count,
            completed_correspondence_work_unit_count: self.completed_correspondence_work_unit_count,
        }
        .encode())
    }

    pub(in crate::bgv) fn advance(
        &mut self,
        maximum_work_unit_count: u32,
    ) -> Result<AcceptedCompactPublicKeyVerificationPoll, RefusalReason> {
        if maximum_work_unit_count == 0 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        loop {
            let stage = self.stage.take().ok_or(RefusalReason::ConsumedState)?;
            match stage {
                AcceptedCompactPublicKeyVerificationStage::Algebraic(mut verification) => {
                    match verification
                        .advance(u64::from(maximum_work_unit_count))
                        .map_err(CompactPublicKeyAlgebraicVerificationError::refusal_reason)?
                    {
                        CompactPublicKeyAlgebraicVerificationPoll::WorkCompleted {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal,
                        } => {
                            let completed_work_unit_count =
                                u32::try_from(completed_work_unit_count)
                                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                            self.completed_cfw_work_unit_count = self
                                .completed_cfw_work_unit_count
                                .checked_add(u64::from(completed_work_unit_count))
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::Algebraic(verification),
                            );
                            if self.resume_target.is_some() {
                                return Ok(
                                    AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                                        completed_work_unit_count,
                                        checkpoint_safe_boundary_ordinal: None,
                                    },
                                );
                            }
                            return Ok(AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                                completed_work_unit_count,
                                checkpoint_safe_boundary_ordinal,
                            });
                        }
                        CompactPublicKeyAlgebraicVerificationPoll::ResumeComplete {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal,
                        } => {
                            let completed_work_unit_count =
                                u32::try_from(completed_work_unit_count)
                                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                            self.completed_cfw_work_unit_count = self
                                .completed_cfw_work_unit_count
                                .checked_add(u64::from(completed_work_unit_count))
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            let target = self
                                .resume_target
                                .take()
                                .ok_or(RefusalReason::WrongContext)?;
                            if target.completed_whir_work_unit_count != 0
                                || self.completed_cfw_work_unit_count
                                    != target.completed_cfw_work_unit_count
                                || checkpoint_safe_boundary_ordinal
                                    != target.safe_boundary_ordinal()?
                            {
                                return Err(RefusalReason::WrongContext);
                            }
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::Algebraic(verification),
                            );
                            return Ok(AcceptedCompactPublicKeyVerificationPoll::ResumeComplete {
                                completed_work_unit_count,
                                checkpoint_safe_boundary_ordinal,
                            });
                        }
                        CompactPublicKeyAlgebraicVerificationPoll::WhirWorkCompleted {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal,
                        } => {
                            if self.completed_cfw_work_unit_count
                                != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT
                            {
                                return Err(RefusalReason::InvalidProof);
                            }
                            let completed_work_unit_count =
                                u32::try_from(completed_work_unit_count)
                                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                            if completed_work_unit_count == 0 {
                                return Err(RefusalReason::InvalidProof);
                            }
                            self.completed_whir_work_unit_count = self
                                .completed_whir_work_unit_count
                                .checked_add(u64::from(completed_work_unit_count))
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::Algebraic(verification),
                            );
                            return Ok(AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                                completed_work_unit_count,
                                checkpoint_safe_boundary_ordinal: self
                                    .resume_target
                                    .is_none()
                                    .then_some(checkpoint_safe_boundary_ordinal)
                                    .flatten(),
                            });
                        }
                        CompactPublicKeyAlgebraicVerificationPoll::WhirResumeComplete {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal,
                        } => {
                            if self.completed_cfw_work_unit_count
                                != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT
                            {
                                return Err(RefusalReason::InvalidProof);
                            }
                            let completed_work_unit_count =
                                u32::try_from(completed_work_unit_count)
                                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                            self.completed_whir_work_unit_count = self
                                .completed_whir_work_unit_count
                                .checked_add(u64::from(completed_work_unit_count))
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            let target = self.resume_target.ok_or(RefusalReason::WrongContext)?;
                            if self.completed_whir_work_unit_count
                                != target.completed_whir_work_unit_count
                                || checkpoint_safe_boundary_ordinal
                                    != compact_public_key_algebraic_checkpoint_safe_boundary_ordinal(
                                        target.completed_cfw_work_unit_count,
                                        target.completed_whir_work_unit_count,
                                    )
                                    .ok_or(RefusalReason::WrongContext)?
                            {
                                return Err(RefusalReason::WrongContext);
                            }
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::Algebraic(verification),
                            );
                            if !target.is_source_correspondence_checkpoint()
                                || target.completed_correspondence_work_unit_count == 0
                            {
                                self.resume_target = None;
                                return Ok(
                                    AcceptedCompactPublicKeyVerificationPoll::ResumeComplete {
                                        completed_work_unit_count,
                                        checkpoint_safe_boundary_ordinal,
                                    },
                                );
                            }
                            return Ok(AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                                completed_work_unit_count,
                                checkpoint_safe_boundary_ordinal: None,
                            });
                        }
                        CompactPublicKeyAlgebraicVerificationPoll::WhirCompleted {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal,
                        } => {
                            if completed_work_unit_count == 0
                                || self.completed_cfw_work_unit_count
                                    != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT
                            {
                                return Err(RefusalReason::InvalidProof);
                            }
                            let completed_work_unit_count =
                                u32::try_from(completed_work_unit_count)
                                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                            self.completed_whir_work_unit_count = self
                                .completed_whir_work_unit_count
                                .checked_add(u64::from(completed_work_unit_count))
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            if self.completed_whir_work_unit_count
                                != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT
                                || self.resume_target.is_some()
                            {
                                return Err(RefusalReason::InvalidProof);
                            }
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::Algebraic(verification),
                            );
                            return Ok(AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                                completed_work_unit_count,
                                checkpoint_safe_boundary_ordinal: Some(
                                    checkpoint_safe_boundary_ordinal,
                                ),
                            });
                        }
                        CompactPublicKeyAlgebraicVerificationPoll::Complete(
                            algebraically_verified_proof,
                        ) => {
                            if self.completed_whir_work_unit_count
                                != COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT
                            {
                                return Err(RefusalReason::InvalidProof);
                            }
                            let correspondence = self
                                .statement_authority
                                .take()
                                .ok_or(RefusalReason::ConsumedState)?
                                .begin_binding_algebraically_verified_proof(
                                    *algebraically_verified_proof,
                                )?;
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::SourceCorrespondence(
                                    Box::new(correspondence),
                                ),
                            );
                        }
                    }
                }
                AcceptedCompactPublicKeyVerificationStage::SourceCorrespondence(
                    mut verification,
                ) => {
                    let bounded_work_unit_count = self
                        .resume_target
                        .filter(|target| target.is_source_correspondence_checkpoint())
                        .map(|target| {
                            target
                                .completed_correspondence_work_unit_count
                                .checked_sub(self.completed_correspondence_work_unit_count)
                                .ok_or(RefusalReason::WrongContext)
                                .map(|remaining| remaining.min(maximum_work_unit_count))
                        })
                        .transpose()?
                        .unwrap_or(maximum_work_unit_count);
                    if bounded_work_unit_count == 0 {
                        return Err(RefusalReason::WrongContext);
                    }
                    match verification.advance(bounded_work_unit_count)? {
                        CompactPublicKeyStatementCorrespondenceVerificationPoll::WorkCompleted {
                            completed_work_unit_count,
                            checkpoint_safe_boundary_ordinal,
                        } => {
                            self.completed_correspondence_work_unit_count = self
                                .completed_correspondence_work_unit_count
                                .checked_add(completed_work_unit_count)
                                .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            if checkpoint_safe_boundary_ordinal
                                != self
                                    .completed_correspondence_work_unit_count
                                    .checked_sub(1)
                                    .ok_or(RefusalReason::InvalidProof)?
                            {
                                return Err(RefusalReason::InvalidProof);
                            }
                            self.stage = Some(
                                AcceptedCompactPublicKeyVerificationStage::SourceCorrespondence(
                                    verification,
                                ),
                            );
                            let global_safe_boundary_ordinal =
                                COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT
                                    .checked_add(checkpoint_safe_boundary_ordinal)
                                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                            if let Some(target) = self.resume_target
                                && target.is_source_correspondence_checkpoint()
                                && self.completed_correspondence_work_unit_count
                                    == target.completed_correspondence_work_unit_count
                            {
                                self.resume_target = None;
                                return Ok(
                                    AcceptedCompactPublicKeyVerificationPoll::ResumeComplete {
                                        completed_work_unit_count,
                                        checkpoint_safe_boundary_ordinal:
                                            global_safe_boundary_ordinal,
                                    },
                                );
                            }
                            return Ok(
                                AcceptedCompactPublicKeyVerificationPoll::WorkCompleted {
                                    completed_work_unit_count,
                                    checkpoint_safe_boundary_ordinal: self
                                        .resume_target
                                        .is_none()
                                        .then_some(global_safe_boundary_ordinal),
                                },
                            );
                        }
                        CompactPublicKeyStatementCorrespondenceVerificationPoll::Complete(
                            verified_proof,
                        ) => {
                            if self.resume_target.is_some()
                                || self.completed_correspondence_work_unit_count
                                    != ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT
                            {
                                return Err(RefusalReason::WrongContext);
                            }
                            return Ok(AcceptedCompactPublicKeyVerificationPoll::Complete(
                                verified_proof,
                            ));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checkpoint(
        completed_cfw_work_unit_count: u64,
        completed_whir_work_unit_count: u64,
        completed_correspondence_work_unit_count: u32,
    ) -> AcceptedCompactPublicKeyVerificationCheckpoint {
        AcceptedCompactPublicKeyVerificationCheckpoint {
            public_input_bindings: CompactPublicInputBindings::new(
                Hash512::from_bytes([1; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([2; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([3; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([4; Hash512::BYTE_LENGTH]),
            ),
            canonical_proof_binding: [5; Hash512::BYTE_LENGTH],
            canonical_public_input_binding: [6; Hash512::BYTE_LENGTH],
            completed_cfw_work_unit_count,
            completed_whir_work_unit_count,
            completed_correspondence_work_unit_count,
        }
    }

    #[test]
    fn accepted_verifier_checkpoint_round_trips_cfw_and_correspondence_boundaries() {
        let cfw = sample_checkpoint(65_536, 0, 0);
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&cfw.encode()),
            Ok(cfw)
        );
        let whir = sample_checkpoint(
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
            65_536,
            0,
        );
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&whir.encode()),
            Ok(whir)
        );
        let correspondence = sample_checkpoint(
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT,
            ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT,
        );
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&correspondence.encode()),
            Ok(correspondence)
        );
        assert_eq!(
            correspondence.safe_boundary_ordinal(),
            Ok(ACCEPTED_COMPACT_PUBLIC_KEY_VERIFICATION_SAFE_BOUNDARY_COUNT - 1)
        );
    }

    #[test]
    fn accepted_verifier_checkpoint_refuses_impossible_phase_combinations() {
        let mut malformed = sample_checkpoint(65_536, 0, 1).encode();
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&malformed),
            Err(RefusalReason::MalformedEncoding)
        );
        malformed = sample_checkpoint(
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT,
            ACCEPTED_COMPACT_PUBLIC_KEY_CORRESPONDENCE_SAFE_BOUNDARY_COUNT + 1,
        )
        .encode();
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&malformed),
            Err(RefusalReason::MalformedEncoding)
        );
        malformed[0] ^= 1;
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&malformed),
            Err(RefusalReason::MalformedEncoding)
        );
    }

    #[test]
    fn accepted_verifier_checkpoint_refuses_the_non_checkpointed_terminal_cfw_remainder() {
        let final_cfw = sample_checkpoint(
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
            0,
            0,
        );
        let post_whir = sample_checkpoint(
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_CFW_WORK_UNIT_COUNT,
            COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_WHIR_WORK_UNIT_COUNT,
            0,
        );
        assert_ne!(final_cfw.encode(), post_whir.encode());
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&final_cfw.encode()),
            Err(RefusalReason::MalformedEncoding)
        );
        assert_eq!(
            AcceptedCompactPublicKeyVerificationCheckpoint::decode(&post_whir.encode()),
            Ok(post_whir)
        );
        assert_eq!(
            post_whir.safe_boundary_ordinal(),
            Ok(COMPACT_PUBLIC_KEY_ALGEBRAIC_VERIFICATION_SAFE_BOUNDARY_COUNT - 1)
        );
    }
}
