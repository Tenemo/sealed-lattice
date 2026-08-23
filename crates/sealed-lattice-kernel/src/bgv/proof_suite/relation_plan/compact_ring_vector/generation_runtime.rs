//! Scalar, pollable runtime for exact compact public-key proof generation.
//!
//! This coordinator sequences the production authenticated assignment, both
//! response epochs, CFW, and both WHIR epochs. It delegates every proof step to
//! the compact producer and exposes only bounded external-memory transactions
//! plus the final canonical public input and proof bytes. It does not mint a
//! verification or workflow capability.

use crate::{
    bgv::proof_suite::{
        CompactGenerationDiagnosticCollector, CompactGenerationDiagnosticObservation,
        CompactGenerationDiagnosticOwner,
        compact_proof_contract::{
            CompactProofContractError, selected_compact_public_key_proof_contract,
        },
        compact_response_generation::CompactResponseGenerationOutput,
        external_memory::{ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryUsage},
        prover::{PrivateRandomnessCommonProofCoinError, PrivateRandomnessCommonProofCoinSource},
        runtime::{CommonProofRuntimeError, CommonProofStorageTransactionRuntime},
    },
    foundation::{Hash512, RefusalReason},
    hashing::hash_framed_parts_512,
};

use super::{
    PreparedCompactPublicKeyAssignmentSources,
    generation_state::{
        CompactPublicKeyGenerationError, CompactPublicKeyGenerationInitializationError,
        CompactPublicKeyGenerationPoll, CompactPublicKeyGenerationState,
        CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError,
        CompactPublicKeyMainEpochPreparationError, PreparedCompactPublicKeyMainEpoch,
    },
};

const RESPONSE_STORAGE_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-public-key-generation/response-storage/v1";
const CFW_STORAGE_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-public-key-generation/cfw-storage/v1";

type CompactPrivateCoinFactory =
    Box<dyn FnOnce([u8; 64]) -> Result<PrivateRandomnessCommonProofCoinSource, RefusalReason>>;

/// Prepared authority-bound inputs for one fresh compact public-key proof.
/// The private-coin factory reenters the retained setup authority only after
/// the producer has independently reconstructed the exact public input and
/// compact construction binding.
pub(crate) struct PreparedCompactPublicKeyGenerationRuntime {
    assignment_sources: PreparedCompactPublicKeyAssignmentSources,
    diagnostics: CompactGenerationDiagnosticCollector,
    private_coin_factory: CompactPrivateCoinFactory,
    whir_batch_counts: [u8; 2],
}

impl PreparedCompactPublicKeyGenerationRuntime {
    pub(crate) fn new_with_diagnostics(
        assignment_sources: PreparedCompactPublicKeyAssignmentSources,
        private_coin_factory: CompactPrivateCoinFactory,
        diagnostics: CompactGenerationDiagnosticCollector,
    ) -> Result<Self, CompactPublicKeyGenerationRuntimeError> {
        let contract = diagnostics
            .measure(
                CompactGenerationDiagnosticOwner::RuntimeContractLoading,
                selected_compact_public_key_proof_contract,
            )
            .map_err(CompactPublicKeyGenerationRuntimeError::Contract)?;
        let [pre_challenge_epoch, main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyGenerationRuntimeError::WrongPhase);
        };
        let whir_batch_counts = [
            u8::try_from(pre_challenge_epoch.folding_schedule.len())
                .map_err(|_| CompactPublicKeyGenerationRuntimeError::WrongPhase)?,
            u8::try_from(main_epoch.folding_schedule.len())
                .map_err(|_| CompactPublicKeyGenerationRuntimeError::WrongPhase)?,
        ];
        if whir_batch_counts.contains(&0) {
            return Err(CompactPublicKeyGenerationRuntimeError::WrongPhase);
        }
        Ok(Self {
            assignment_sources,
            diagnostics,
            private_coin_factory,
            whir_batch_counts,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactWhirEpochOwner {
    PreChallenge,
    Main,
}

impl CompactWhirEpochOwner {
    const fn index(self) -> usize {
        match self {
            Self::PreChallenge => 0,
            Self::Main => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactPublicKeyGenerationRuntimePhase {
    SourceLoading,
    FamilyMaterialization,
    PostLookupResponse,
    CrossEpochResponse,
    Cfw,
    WhirSumcheck {
        owner: CompactWhirEpochOwner,
        batch_ordinal: u8,
    },
    WhirCodeSwitch {
        owner: CompactWhirEpochOwner,
        round_ordinal: u8,
    },
    WhirNextSumcheckPreparation {
        owner: CompactWhirEpochOwner,
        round_ordinal: u8,
    },
    WhirBaseFreshResponse {
        owner: CompactWhirEpochOwner,
    },
    WhirBaseBlindedResponse {
        owner: CompactWhirEpochOwner,
    },
    MainWhirInitialPreparation,
    Complete,
    Cancelled,
}

/// Stable coarse stages exported to the worker driver. These stage codes are
/// progress metadata only and cannot authorize a transition or acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum CompactPublicKeyGenerationRuntimeStage {
    SourceLoading = 1,
    FamilyMaterialization = 2,
    PostLookupResponse = 3,
    CrossEpochResponse = 4,
    Cfw = 5,
    PreChallengeWhirSumcheck = 6,
    PreChallengeWhirCodeSwitch = 7,
    PreChallengeWhirNextSumcheckPreparation = 8,
    PreChallengeWhirBaseFreshResponse = 9,
    PreChallengeWhirBaseBlindedResponse = 10,
    MainWhirInitialPreparation = 11,
    MainWhirSumcheck = 12,
    MainWhirCodeSwitch = 13,
    MainWhirNextSumcheckPreparation = 14,
    MainWhirBaseFreshResponse = 15,
    MainWhirBaseBlindedResponse = 16,
    Complete = 17,
}

impl CompactPublicKeyGenerationRuntimeStage {
    pub(crate) const fn canonical_code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum CompactPublicKeyGenerationStorageOwner {
    ResponseTrees = 1,
    Cfw = 2,
}

impl CompactPublicKeyGenerationStorageOwner {
    pub(crate) const fn canonical_code(self) -> u32 {
        self as u32
    }

    pub(crate) const fn from_canonical_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(Self::ResponseTrees),
            2 => Some(Self::Cfw),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyGenerationRuntimePoll {
    Progress {
        stage: CompactPublicKeyGenerationRuntimeStage,
        first_ordinal: u32,
        completed_work_unit_count: u64,
    },
    CheckpointReady {
        stage: CompactPublicKeyGenerationRuntimeStage,
        safe_boundary_ordinal: u32,
    },
    StorageRequestReady {
        owner: CompactPublicKeyGenerationStorageOwner,
    },
    Complete,
}

#[derive(Debug)]
pub(crate) enum CompactPublicKeyGenerationRuntimeError {
    WrongPhase,
    Refusal(RefusalReason),
    Contract(CompactProofContractError),
    Initialization(CompactPublicKeyGenerationInitializationError),
    Generation(
        CompactPublicKeyGenerationError<
            PrivateRandomnessCommonProofCoinError,
            ProofExternalMemoryTransactionAdapterError,
        >,
    ),
    MainPreparation(CompactPublicKeyMainEpochPreparationError),
    MainPoll(CompactPublicKeyMainEpochPollError<ProofExternalMemoryTransactionAdapterError>),
    Runtime(CommonProofRuntimeError),
}

impl From<CommonProofRuntimeError> for CompactPublicKeyGenerationRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct CompletedCompactPublicKeyGeneration {
    canonical_public_input_bytes: Vec<u8>,
    canonical_proof_bytes: Vec<u8>,
    transport_bindings: [Hash512; 4],
    response_external_memory_usage: ProofExternalMemoryUsage,
    cfw_external_memory_usage: ProofExternalMemoryUsage,
}

/// One scalar, single-threaded compact proof operation. All cryptographic
/// state remains Rust-owned. Browser storage sees only authenticated external-
/// memory transaction bytes and JavaScript receives final public bytes only
/// after every producer phase has completed.
pub(crate) struct CompactPublicKeyGenerationRuntime {
    diagnostics: CompactGenerationDiagnosticCollector,
    phase: CompactPublicKeyGenerationRuntimePhase,
    initial_state: Option<CompactPublicKeyGenerationState>,
    private_coins: Option<PrivateRandomnessCommonProofCoinSource>,
    private_coin_factory: Option<CompactPrivateCoinFactory>,
    main_epoch: Option<PreparedCompactPublicKeyMainEpoch>,
    response_storage: Option<CommonProofStorageTransactionRuntime>,
    cfw_storage: Option<CommonProofStorageTransactionRuntime>,
    whir_batch_counts: [u8; 2],
    completed: Option<CompletedCompactPublicKeyGeneration>,
}

impl CompactPublicKeyGenerationRuntime {
    pub(crate) fn new(prepared: PreparedCompactPublicKeyGenerationRuntime) -> Self {
        let diagnostics = prepared.diagnostics;
        Self {
            diagnostics: diagnostics.clone(),
            phase: CompactPublicKeyGenerationRuntimePhase::SourceLoading,
            initial_state: Some(CompactPublicKeyGenerationState::new_with_diagnostics(
                prepared.assignment_sources,
                diagnostics,
            )),
            private_coins: None,
            private_coin_factory: Some(prepared.private_coin_factory),
            main_epoch: None,
            response_storage: None,
            cfw_storage: None,
            whir_batch_counts: prepared.whir_batch_counts,
            completed: None,
        }
    }

    pub(crate) fn with_diagnostic_observations<ResultValue>(
        &self,
        operation: impl FnOnce(&[CompactGenerationDiagnosticObservation]) -> ResultValue,
    ) -> Option<ResultValue> {
        self.diagnostics.with_observations(operation)
    }

    pub(crate) fn poll(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        if maximum_work_unit_count == 0 {
            return Err(CompactPublicKeyGenerationRuntimeError::WrongPhase);
        }
        if let Some(owner) = self.pending_storage_owner()? {
            return Ok(CompactPublicKeyGenerationRuntimePoll::StorageRequestReady { owner });
        }
        let poll_result = match self.phase {
            CompactPublicKeyGenerationRuntimePhase::SourceLoading => {
                self.poll_source_loading(maximum_work_unit_count)
            }
            CompactPublicKeyGenerationRuntimePhase::FamilyMaterialization => {
                self.poll_family_materialization(maximum_work_unit_count)
            }
            CompactPublicKeyGenerationRuntimePhase::PostLookupResponse
            | CompactPublicKeyGenerationRuntimePhase::CrossEpochResponse => {
                self.poll_post_lookup_response(maximum_work_unit_count)
            }
            CompactPublicKeyGenerationRuntimePhase::Cfw => self.poll_cfw(),
            CompactPublicKeyGenerationRuntimePhase::WhirSumcheck {
                owner,
                batch_ordinal,
            } => self.poll_whir_sumcheck(maximum_work_unit_count, owner, batch_ordinal),
            CompactPublicKeyGenerationRuntimePhase::WhirCodeSwitch {
                owner,
                round_ordinal,
            } => self.poll_whir_code_switch(maximum_work_unit_count, owner, round_ordinal),
            CompactPublicKeyGenerationRuntimePhase::WhirNextSumcheckPreparation {
                owner,
                round_ordinal,
            } => self.poll_whir_next_sumcheck_preparation(
                maximum_work_unit_count,
                owner,
                round_ordinal,
            ),
            CompactPublicKeyGenerationRuntimePhase::WhirBaseFreshResponse { owner } => {
                self.poll_whir_base_fresh_response(maximum_work_unit_count, owner)
            }
            CompactPublicKeyGenerationRuntimePhase::WhirBaseBlindedResponse { owner } => {
                self.poll_whir_base_blinded_response(maximum_work_unit_count, owner)
            }
            CompactPublicKeyGenerationRuntimePhase::MainWhirInitialPreparation => {
                self.poll_main_whir_initial_preparation(maximum_work_unit_count)
            }
            CompactPublicKeyGenerationRuntimePhase::Complete => {
                Ok(CompactPublicKeyGenerationRuntimePoll::Complete)
            }
            CompactPublicKeyGenerationRuntimePhase::Cancelled => {
                Err(CompactPublicKeyGenerationRuntimeError::Runtime(
                    CommonProofRuntimeError::CancellationRequested,
                ))
            }
        };
        match poll_result {
            Err(CompactPublicKeyGenerationRuntimeError::Runtime(
                CommonProofRuntimeError::TransactionPending,
            )) => {
                let owner = self
                    .pending_storage_owner()?
                    .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?;
                Ok(CompactPublicKeyGenerationRuntimePoll::StorageRequestReady { owner })
            }
            result => result,
        }
    }

    fn poll_source_loading(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let state = self
            .initial_state
            .as_mut()
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        match state
            .poll_source_loading(maximum_work_unit_count)
            .map_err(CompactPublicKeyGenerationRuntimeError::Initialization)?
        {
            CompactPublicKeyGenerationPoll::SourceLoaded { column_ordinal } => {
                Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                    stage: CompactPublicKeyGenerationRuntimeStage::SourceLoading,
                    first_ordinal: column_ordinal,
                    completed_work_unit_count: 0,
                })
            }
            CompactPublicKeyGenerationPoll::SourcesComplete => {
                let derivation_binding_hash = state
                    .pre_lookup_material()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?
                    .private_coin_derivation_binding_hash()
                    .into_bytes();
                let private_coin_factory = self
                    .private_coin_factory
                    .take()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
                let private_coins = private_coin_factory(derivation_binding_hash)
                    .map_err(CompactPublicKeyGenerationRuntimeError::Refusal)?;
                self.response_storage =
                    Some(CommonProofStorageTransactionRuntime::for_runtime_binding(
                        hash_framed_parts_512(
                            RESPONSE_STORAGE_BINDING_DOMAIN,
                            &[&derivation_binding_hash],
                        ),
                    ));
                self.cfw_storage = Some(CommonProofStorageTransactionRuntime::for_runtime_binding(
                    hash_framed_parts_512(CFW_STORAGE_BINDING_DOMAIN, &[&derivation_binding_hash]),
                ));
                self.private_coins = Some(private_coins);
                self.phase = CompactPublicKeyGenerationRuntimePhase::FamilyMaterialization;
                Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                    stage: CompactPublicKeyGenerationRuntimeStage::FamilyMaterialization,
                    first_ordinal: 0,
                    completed_work_unit_count: 0,
                })
            }
            CompactPublicKeyGenerationPoll::AuthenticatedSourceReadRequired
            | CompactPublicKeyGenerationPoll::PreChallengeSourceEncoded
            | CompactPublicKeyGenerationPoll::ResponseLeafSupplied { .. }
            | CompactPublicKeyGenerationPoll::OpenedResponseLeafSupplied { .. }
            | CompactPublicKeyGenerationPoll::ResponseArithmeticStepCompleted
            | CompactPublicKeyGenerationPoll::ResponseStorageTransactionCompleted
            | CompactPublicKeyGenerationPoll::PreChallengeCheckpointReady
            | CompactPublicKeyGenerationPoll::LookupInverseArithmeticStepCompleted { .. }
            | CompactPublicKeyGenerationPoll::StructuredRowSourceStepCompleted { .. }
            | CompactPublicKeyGenerationPoll::FamilyMaterializationComplete => {
                Err(CompactPublicKeyGenerationRuntimeError::WrongPhase)
            }
        }
    }

    fn poll_family_materialization(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let poll_result = {
            let state = self
                .initial_state
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let private_coins = self
                .private_coins
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            state.poll(maximum_work_unit_count, private_coins, response_storage)
        };
        let poll = match poll_result {
            Ok(poll) => poll,
            Err(error) => {
                if let Some(owner) = self.capture_yielded_storage_request()? {
                    return Ok(CompactPublicKeyGenerationRuntimePoll::StorageRequestReady {
                        owner,
                    });
                }
                return Err(CompactPublicKeyGenerationRuntimeError::Generation(error));
            }
        };
        self.release_completed_storage_replays()?;
        match poll {
            CompactPublicKeyGenerationPoll::PreChallengeCheckpointReady => {
                self.checkpoint_poll(CompactPublicKeyGenerationRuntimeStage::FamilyMaterialization)
            }
            CompactPublicKeyGenerationPoll::FamilyMaterializationComplete => {
                let initial_state = self
                    .initial_state
                    .take()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
                let mut main_epoch = initial_state
                    .finish()
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
                main_epoch
                    .prepare_post_lookup_response()
                    .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
                self.private_coins = None;
                self.main_epoch = Some(main_epoch);
                self.phase = CompactPublicKeyGenerationRuntimePhase::PostLookupResponse;
                Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                    stage: CompactPublicKeyGenerationRuntimeStage::PostLookupResponse,
                    first_ordinal: 0,
                    completed_work_unit_count: 0,
                })
            }
            CompactPublicKeyGenerationPoll::LookupInverseArithmeticStepCompleted {
                processed_element_count,
            } => Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                stage: CompactPublicKeyGenerationRuntimeStage::FamilyMaterialization,
                first_ordinal: 0,
                completed_work_unit_count: processed_element_count,
            }),
            CompactPublicKeyGenerationPoll::StructuredRowSourceStepCompleted {
                completed_work_unit_count,
                ..
            } => Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                stage: CompactPublicKeyGenerationRuntimeStage::FamilyMaterialization,
                first_ordinal: 0,
                completed_work_unit_count,
            }),
            CompactPublicKeyGenerationPoll::PreChallengeSourceEncoded
            | CompactPublicKeyGenerationPoll::ResponseLeafSupplied { .. }
            | CompactPublicKeyGenerationPoll::OpenedResponseLeafSupplied { .. }
            | CompactPublicKeyGenerationPoll::ResponseArithmeticStepCompleted
            | CompactPublicKeyGenerationPoll::ResponseStorageTransactionCompleted => {
                Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                    stage: CompactPublicKeyGenerationRuntimeStage::FamilyMaterialization,
                    first_ordinal: 0,
                    completed_work_unit_count: 0,
                })
            }
            CompactPublicKeyGenerationPoll::AuthenticatedSourceReadRequired
            | CompactPublicKeyGenerationPoll::SourceLoaded { .. }
            | CompactPublicKeyGenerationPoll::SourcesComplete => {
                Err(CompactPublicKeyGenerationRuntimeError::WrongPhase)
            }
        }
    }

    fn poll_post_lookup_response(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let stage = self.stage();
        let poll_result = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            main_epoch.poll_post_lookup_response(maximum_work_unit_count, response_storage)
        };
        let poll = self.resolve_main_poll_result(poll_result)?;
        match (self.phase, poll) {
            (
                CompactPublicKeyGenerationRuntimePhase::PostLookupResponse,
                CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady,
            ) => {
                self.phase = CompactPublicKeyGenerationRuntimePhase::CrossEpochResponse;
                self.checkpoint_poll(stage)
            }
            (
                CompactPublicKeyGenerationRuntimePhase::CrossEpochResponse,
                CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady,
            ) => {
                self.phase = CompactPublicKeyGenerationRuntimePhase::Cfw;
                self.checkpoint_poll(stage)
            }
            (
                CompactPublicKeyGenerationRuntimePhase::PostLookupResponse,
                CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady,
            )
            | (
                CompactPublicKeyGenerationRuntimePhase::CrossEpochResponse,
                CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady,
            ) => Err(CompactPublicKeyGenerationRuntimeError::WrongPhase),
            (_, poll) => Ok(self.progress_from_main_poll(stage, &poll)),
        }
    }

    fn poll_cfw(
        &mut self,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let poll_result = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let cfw_storage = self
                .cfw_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            main_epoch.poll_cfw(response_storage, cfw_storage)
        };
        let poll = self.resolve_main_poll_result(poll_result)?;
        match poll {
            CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady => {
                let main_epoch = self
                    .main_epoch
                    .as_mut()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
                main_epoch
                    .prepare_pre_challenge_whir_initial_sumcheck()
                    .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
                self.phase = CompactPublicKeyGenerationRuntimePhase::WhirSumcheck {
                    owner: CompactWhirEpochOwner::PreChallenge,
                    batch_ordinal: 0,
                };
                self.checkpoint_poll(CompactPublicKeyGenerationRuntimeStage::Cfw)
            }
            poll => Ok(
                self.progress_from_main_poll(CompactPublicKeyGenerationRuntimeStage::Cfw, &poll)
            ),
        }
    }

    fn poll_whir_sumcheck(
        &mut self,
        maximum_work_unit_count: u64,
        owner: CompactWhirEpochOwner,
        batch_ordinal: u8,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let stage = self.stage();
        let poll_result = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            match owner {
                CompactWhirEpochOwner::PreChallenge => main_epoch
                    .poll_pre_challenge_whir_sumcheck(maximum_work_unit_count, response_storage),
                CompactWhirEpochOwner::Main => {
                    main_epoch.poll_main_whir_sumcheck(maximum_work_unit_count, response_storage)
                }
            }
        };
        let poll = self.resolve_main_poll_result(poll_result)?;
        let completed_batch = match (owner, poll) {
            (
                CompactWhirEpochOwner::PreChallenge,
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { batch_ordinal },
            ) => Some(batch_ordinal),
            (
                CompactWhirEpochOwner::Main,
                CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { batch_ordinal },
            ) => Some(batch_ordinal),
            (_, poll) => return Ok(self.progress_from_main_poll(stage, &poll)),
        };
        let completed_batch = completed_batch
            .filter(|completed| *completed == batch_ordinal)
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        let batch_count = self.whir_batch_counts[owner.index()];
        let next_batch_ordinal = completed_batch
            .checked_add(1)
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        let main_epoch = self
            .main_epoch
            .as_mut()
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        if next_batch_ordinal < batch_count {
            match owner {
                CompactWhirEpochOwner::PreChallenge => {
                    main_epoch.prepare_pre_challenge_whir_code_switch()
                }
                CompactWhirEpochOwner::Main => main_epoch.prepare_main_whir_code_switch(),
            }
            .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
            self.phase = CompactPublicKeyGenerationRuntimePhase::WhirCodeSwitch {
                owner,
                round_ordinal: completed_batch,
            };
        } else if next_batch_ordinal == batch_count {
            match owner {
                CompactWhirEpochOwner::PreChallenge => {
                    main_epoch.prepare_pre_challenge_whir_base_case()
                }
                CompactWhirEpochOwner::Main => main_epoch.prepare_main_whir_base_case(),
            }
            .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
            self.phase = CompactPublicKeyGenerationRuntimePhase::WhirBaseFreshResponse { owner };
        } else {
            return Err(CompactPublicKeyGenerationRuntimeError::WrongPhase);
        }
        Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
            stage: self.stage(),
            first_ordinal: u32::from(completed_batch),
            completed_work_unit_count: 0,
        })
    }

    fn poll_whir_code_switch(
        &mut self,
        maximum_work_unit_count: u64,
        owner: CompactWhirEpochOwner,
        round_ordinal: u8,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let stage = self.stage();
        let poll_result = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            match owner {
                CompactWhirEpochOwner::PreChallenge => main_epoch
                    .poll_pre_challenge_whir_code_switch(maximum_work_unit_count, response_storage),
                CompactWhirEpochOwner::Main => {
                    main_epoch.poll_main_whir_code_switch(maximum_work_unit_count, response_storage)
                }
            }
        };
        let poll = self.resolve_main_poll_result(poll_result)?;
        let completed_round = match (owner, poll) {
            (
                CompactWhirEpochOwner::PreChallenge,
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady {
                    round_ordinal,
                },
            ) => Some(round_ordinal),
            (
                CompactWhirEpochOwner::Main,
                CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady {
                    round_ordinal,
                },
            ) => Some(round_ordinal),
            (_, poll) => return Ok(self.progress_from_main_poll(stage, &poll)),
        };
        if completed_round != Some(round_ordinal) {
            return Err(CompactPublicKeyGenerationRuntimeError::WrongPhase);
        }
        let main_epoch = self
            .main_epoch
            .as_mut()
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        match owner {
            CompactWhirEpochOwner::PreChallenge => {
                main_epoch.prepare_pre_challenge_whir_next_sumcheck()
            }
            CompactWhirEpochOwner::Main => main_epoch.prepare_main_whir_next_sumcheck(),
        }
        .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
        self.phase = CompactPublicKeyGenerationRuntimePhase::WhirNextSumcheckPreparation {
            owner,
            round_ordinal,
        };
        self.checkpoint_poll(stage)
    }

    fn poll_whir_next_sumcheck_preparation(
        &mut self,
        maximum_work_unit_count: u64,
        owner: CompactWhirEpochOwner,
        round_ordinal: u8,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let stage = self.stage();
        let poll = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            match owner {
                CompactWhirEpochOwner::PreChallenge => main_epoch
                    .poll_pre_challenge_whir_next_sumcheck_preparation(maximum_work_unit_count),
                CompactWhirEpochOwner::Main => {
                    main_epoch.poll_main_whir_next_sumcheck_preparation(maximum_work_unit_count)
                }
            }
        }
        .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
        let prepared_batch = match (owner, poll) {
            (
                CompactWhirEpochOwner::PreChallenge,
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared { batch_ordinal },
            ) => Some(batch_ordinal),
            (
                CompactWhirEpochOwner::Main,
                CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { batch_ordinal },
            ) => Some(batch_ordinal),
            (_, poll) => return Ok(self.progress_from_main_poll(stage, &poll)),
        };
        let expected_batch_ordinal = round_ordinal
            .checked_add(1)
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        if prepared_batch != Some(expected_batch_ordinal) {
            return Err(CompactPublicKeyGenerationRuntimeError::WrongPhase);
        }
        self.phase = CompactPublicKeyGenerationRuntimePhase::WhirSumcheck {
            owner,
            batch_ordinal: expected_batch_ordinal,
        };
        Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
            stage: self.stage(),
            first_ordinal: u32::from(expected_batch_ordinal),
            completed_work_unit_count: 0,
        })
    }

    fn poll_whir_base_fresh_response(
        &mut self,
        maximum_work_unit_count: u64,
        owner: CompactWhirEpochOwner,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let stage = self.stage();
        let poll_result = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            match owner {
                CompactWhirEpochOwner::PreChallenge => main_epoch
                    .poll_pre_challenge_whir_base_fresh_response(
                        maximum_work_unit_count,
                        response_storage,
                    ),
                CompactWhirEpochOwner::Main => main_epoch
                    .poll_main_whir_base_fresh_response(maximum_work_unit_count, response_storage),
            }
        };
        let poll = self.resolve_main_poll_result(poll_result)?;
        let checkpoint_ready = matches!(
            (owner, poll),
            (
                CompactWhirEpochOwner::PreChallenge,
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady,
            ) | (
                CompactWhirEpochOwner::Main,
                CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady,
            )
        );
        if checkpoint_ready {
            self.phase = CompactPublicKeyGenerationRuntimePhase::WhirBaseBlindedResponse { owner };
            return self.checkpoint_poll(stage);
        }
        Ok(self.progress_from_main_poll(stage, &poll))
    }

    fn poll_whir_base_blinded_response(
        &mut self,
        maximum_work_unit_count: u64,
        owner: CompactWhirEpochOwner,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let stage = self.stage();
        let poll_result = {
            let main_epoch = self
                .main_epoch
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            let response_storage = self
                .response_storage
                .as_mut()
                .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
            match owner {
                CompactWhirEpochOwner::PreChallenge => main_epoch
                    .poll_pre_challenge_whir_base_blinded_response(
                        maximum_work_unit_count,
                        response_storage,
                    ),
                CompactWhirEpochOwner::Main => main_epoch.poll_main_whir_base_blinded_response(
                    maximum_work_unit_count,
                    response_storage,
                ),
            }
        };
        let poll = self.resolve_main_poll_result(poll_result)?;
        let checkpoint_ready = matches!(
            (owner, poll),
            (
                CompactWhirEpochOwner::PreChallenge,
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady,
            ) | (
                CompactWhirEpochOwner::Main,
                CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady,
            )
        );
        if !checkpoint_ready {
            return Ok(self.progress_from_main_poll(stage, &poll));
        }
        match owner {
            CompactWhirEpochOwner::PreChallenge => {
                let main_epoch = self
                    .main_epoch
                    .as_mut()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
                main_epoch
                    .prepare_main_whir_initial_sumcheck()
                    .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
                self.phase = CompactPublicKeyGenerationRuntimePhase::MainWhirInitialPreparation;
                self.checkpoint_poll(stage)
            }
            CompactWhirEpochOwner::Main => {
                let main_epoch = self
                    .main_epoch
                    .take()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
                let transport_bindings = main_epoch
                    .family_material()
                    .public_input_bindings()
                    .ordered_hashes();
                let canonical_public_input_bytes = main_epoch
                    .family_material()
                    .canonical_public_input_bytes()
                    .to_vec();
                let cfw_external_memory_usage = main_epoch
                    .cfw_external_memory_usage()
                    .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
                let output = main_epoch
                    .finish()
                    .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
                self.finish_output(
                    canonical_public_input_bytes,
                    transport_bindings,
                    cfw_external_memory_usage,
                    output,
                );
                self.phase = CompactPublicKeyGenerationRuntimePhase::Complete;
                Ok(CompactPublicKeyGenerationRuntimePoll::Complete)
            }
        }
    }

    fn poll_main_whir_initial_preparation(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let poll = self
            .main_epoch
            .as_mut()
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?
            .poll_main_whir_initial_sumcheck_preparation(maximum_work_unit_count)
            .map_err(CompactPublicKeyGenerationRuntimeError::MainPreparation)?;
        match poll {
            CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { batch_ordinal: 0 } => {
                self.phase = CompactPublicKeyGenerationRuntimePhase::WhirSumcheck {
                    owner: CompactWhirEpochOwner::Main,
                    batch_ordinal: 0,
                };
                Ok(CompactPublicKeyGenerationRuntimePoll::Progress {
                    stage: CompactPublicKeyGenerationRuntimeStage::MainWhirSumcheck,
                    first_ordinal: 0,
                    completed_work_unit_count: 0,
                })
            }
            CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { .. } => {
                Err(CompactPublicKeyGenerationRuntimeError::WrongPhase)
            }
            poll => Ok(self.progress_from_main_poll(
                CompactPublicKeyGenerationRuntimeStage::MainWhirInitialPreparation,
                &poll,
            )),
        }
    }

    fn resolve_main_poll_result(
        &mut self,
        poll_result: Result<
            CompactPublicKeyMainEpochPoll,
            CompactPublicKeyMainEpochPollError<ProofExternalMemoryTransactionAdapterError>,
        >,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyGenerationRuntimeError> {
        match poll_result {
            Ok(poll) => {
                self.release_completed_storage_replays()?;
                Ok(poll)
            }
            Err(error) => {
                if let Some(owner) = self.capture_yielded_storage_request()? {
                    return Err(CompactPublicKeyGenerationRuntimeError::Runtime(
                        match owner {
                            CompactPublicKeyGenerationStorageOwner::ResponseTrees
                            | CompactPublicKeyGenerationStorageOwner::Cfw => {
                                CommonProofRuntimeError::TransactionPending
                            }
                        },
                    ));
                }
                Err(CompactPublicKeyGenerationRuntimeError::MainPoll(error))
            }
        }
    }

    fn capture_yielded_storage_request(
        &mut self,
    ) -> Result<Option<CompactPublicKeyGenerationStorageOwner>, CommonProofRuntimeError> {
        let response_yielded = self
            .response_storage
            .as_ref()
            .is_some_and(CommonProofStorageTransactionRuntime::yielded_request_is_available);
        let cfw_yielded = self
            .cfw_storage
            .as_ref()
            .is_some_and(CommonProofStorageTransactionRuntime::yielded_request_is_available);
        let owner = match (response_yielded, cfw_yielded) {
            (false, false) => return Ok(None),
            (true, false) => CompactPublicKeyGenerationStorageOwner::ResponseTrees,
            (false, true) => CompactPublicKeyGenerationStorageOwner::Cfw,
            (true, true) => return Err(CommonProofRuntimeError::WrongOperationPhase),
        };
        self.storage_mut(owner)?.capture_yielded_request()?;
        Ok(Some(owner))
    }

    fn release_completed_storage_replays(&mut self) -> Result<(), CommonProofRuntimeError> {
        for storage in [&mut self.response_storage, &mut self.cfw_storage]
            .into_iter()
            .flatten()
        {
            if storage.replay_is_active() {
                match storage.transaction_completed() {
                    Ok(()) | Err(CommonProofRuntimeError::TransactionReplayIncomplete) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn pending_storage_owner(
        &self,
    ) -> Result<Option<CompactPublicKeyGenerationStorageOwner>, CommonProofRuntimeError> {
        let response_pending = self
            .response_storage
            .as_ref()
            .is_some_and(CommonProofStorageTransactionRuntime::request_is_pending);
        let cfw_pending = self
            .cfw_storage
            .as_ref()
            .is_some_and(CommonProofStorageTransactionRuntime::request_is_pending);
        match (response_pending, cfw_pending) {
            (false, false) => Ok(None),
            (true, false) => Ok(Some(CompactPublicKeyGenerationStorageOwner::ResponseTrees)),
            (false, true) => Ok(Some(CompactPublicKeyGenerationStorageOwner::Cfw)),
            (true, true) => Err(CommonProofRuntimeError::WrongOperationPhase),
        }
    }

    fn storage_mut(
        &mut self,
        owner: CompactPublicKeyGenerationStorageOwner,
    ) -> Result<&mut CommonProofStorageTransactionRuntime, CommonProofRuntimeError> {
        match owner {
            CompactPublicKeyGenerationStorageOwner::ResponseTrees => self
                .response_storage
                .as_mut()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase),
            CompactPublicKeyGenerationStorageOwner::Cfw => self
                .cfw_storage
                .as_mut()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase),
        }
    }

    pub(crate) fn pending_storage_request_byte_length(
        &self,
        owner: CompactPublicKeyGenerationStorageOwner,
    ) -> Result<usize, CommonProofRuntimeError> {
        if self.pending_storage_owner()? != Some(owner) {
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        }
        match owner {
            CompactPublicKeyGenerationStorageOwner::ResponseTrees => self.response_storage.as_ref(),
            CompactPublicKeyGenerationStorageOwner::Cfw => self.cfw_storage.as_ref(),
        }
        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
        .pending_request_encoded_byte_length()
    }

    pub(crate) fn pending_storage_request_description(
        &self,
    ) -> Result<(CompactPublicKeyGenerationStorageOwner, usize), CommonProofRuntimeError> {
        let owner = self
            .pending_storage_owner()?
            .ok_or(CommonProofRuntimeError::TransactionResponseMissing)?;
        Ok((owner, self.pending_storage_request_byte_length(owner)?))
    }

    pub(crate) fn copy_pending_storage_request(
        &mut self,
        owner: CompactPublicKeyGenerationStorageOwner,
        destination: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if self.pending_storage_owner()? != Some(owner) {
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        }
        self.storage_mut(owner)?
            .encode_pending_worker_request_into(destination)
    }

    pub(crate) fn supply_storage_response(
        &mut self,
        owner: CompactPublicKeyGenerationStorageOwner,
        encoded_response: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        if self.pending_storage_owner()? != Some(owner) {
            return Err(CommonProofRuntimeError::TransactionResponseMissing);
        }
        self.storage_mut(owner)?
            .supply_worker_response(encoded_response)
    }

    pub(crate) fn canonical_public_input_byte_length(
        &self,
    ) -> Result<usize, CommonProofRuntimeError> {
        Ok(self
            .completed
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .canonical_public_input_bytes
            .len())
    }

    pub(crate) fn canonical_proof_byte_length(&self) -> Result<usize, CommonProofRuntimeError> {
        Ok(self
            .completed
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .canonical_proof_bytes
            .len())
    }

    pub(crate) fn copy_canonical_public_input(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let bytes = &self
            .completed
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .canonical_public_input_bytes;
        copy_exact_range(bytes, offset, destination)
    }

    pub(crate) fn copy_canonical_proof(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let bytes = &self
            .completed
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .canonical_proof_bytes;
        copy_exact_range(bytes, offset, destination)
    }

    pub(crate) fn copy_transport_bindings(
        &self,
        destination: &mut [u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let completed = self
            .completed
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        if destination.len() != completed.transport_bindings.len() * Hash512::BYTE_LENGTH {
            return Err(CommonProofRuntimeError::OutputByteLengthExceeded);
        }
        for (destination_hash, binding) in destination
            .chunks_exact_mut(Hash512::BYTE_LENGTH)
            .zip(completed.transport_bindings)
        {
            destination_hash.copy_from_slice(binding.as_bytes());
        }
        Ok(())
    }

    pub(crate) fn external_memory_usages(
        &self,
    ) -> Result<(ProofExternalMemoryUsage, ProofExternalMemoryUsage), CommonProofRuntimeError> {
        let completed = self
            .completed
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        Ok((
            completed.response_external_memory_usage,
            completed.cfw_external_memory_usage,
        ))
    }

    pub(crate) fn cancel(&mut self) {
        if let Some(storage) = self.response_storage.as_mut() {
            storage.cancel();
        }
        if let Some(storage) = self.cfw_storage.as_mut() {
            storage.cancel();
        }
        self.initial_state = None;
        self.private_coins = None;
        self.private_coin_factory = None;
        self.main_epoch = None;
        self.completed = None;
        self.phase = CompactPublicKeyGenerationRuntimePhase::Cancelled;
    }

    fn finish_output(
        &mut self,
        canonical_public_input_bytes: Vec<u8>,
        transport_bindings: [Hash512; 4],
        cfw_external_memory_usage: ProofExternalMemoryUsage,
        output: CompactResponseGenerationOutput,
    ) {
        let response_external_memory_usage = output.external_memory_usage();
        self.completed = Some(CompletedCompactPublicKeyGeneration {
            canonical_public_input_bytes,
            canonical_proof_bytes: output.into_canonical_proof_bytes(),
            transport_bindings,
            response_external_memory_usage,
            cfw_external_memory_usage,
        });
    }

    fn checkpoint_poll(
        &self,
        stage: CompactPublicKeyGenerationRuntimeStage,
    ) -> Result<CompactPublicKeyGenerationRuntimePoll, CompactPublicKeyGenerationRuntimeError> {
        let safe_boundary_ordinal = self
            .main_epoch
            .as_ref()
            .and_then(|state| state.checkpoint_boundary())
            .map(|boundary| boundary.safe_boundary_ordinal())
            .or_else(|| {
                self.initial_state
                    .as_ref()
                    .and_then(CompactPublicKeyGenerationState::checkpoint_boundary)
                    .map(|boundary| boundary.safe_boundary_ordinal())
            })
            .ok_or(CompactPublicKeyGenerationRuntimeError::WrongPhase)?;
        Ok(CompactPublicKeyGenerationRuntimePoll::CheckpointReady {
            stage,
            safe_boundary_ordinal,
        })
    }

    fn progress_from_main_poll(
        &self,
        stage: CompactPublicKeyGenerationRuntimeStage,
        poll: &CompactPublicKeyMainEpochPoll,
    ) -> CompactPublicKeyGenerationRuntimePoll {
        let (first_ordinal, completed_work_unit_count) = match *poll {
            CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted {
                processed_work_unit_count,
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted {
                processed_work_unit_count,
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted {
                processed_work_unit_count,
            }
            | CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted {
                processed_work_unit_count,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted {
                processed_work_unit_count,
            }
            | CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted {
                processed_work_unit_count,
            } => (0, processed_work_unit_count),
            CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted {
                processed_work_unit_count,
                evaluated_source_element_count,
            } => (
                u32::try_from(evaluated_source_element_count).unwrap_or(u32::MAX),
                processed_work_unit_count,
            ),
            CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted {
                round_ordinal,
                ..
            }
            | CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted { round_ordinal, .. } => {
                (round_ordinal, 0)
            }
            CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                batch_ordinal,
                ..
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                batch_ordinal,
                ..
            }
            | CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                batch_ordinal,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted {
                batch_ordinal,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted {
                batch_ordinal,
                ..
            }
            | CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted {
                batch_ordinal,
                ..
            } => (u32::from(batch_ordinal), 0),
            _ => (0, 0),
        };
        CompactPublicKeyGenerationRuntimePoll::Progress {
            stage,
            first_ordinal,
            completed_work_unit_count,
        }
    }

    const fn stage(&self) -> CompactPublicKeyGenerationRuntimeStage {
        match self.phase {
            CompactPublicKeyGenerationRuntimePhase::SourceLoading => {
                CompactPublicKeyGenerationRuntimeStage::SourceLoading
            }
            CompactPublicKeyGenerationRuntimePhase::FamilyMaterialization => {
                CompactPublicKeyGenerationRuntimeStage::FamilyMaterialization
            }
            CompactPublicKeyGenerationRuntimePhase::PostLookupResponse => {
                CompactPublicKeyGenerationRuntimeStage::PostLookupResponse
            }
            CompactPublicKeyGenerationRuntimePhase::CrossEpochResponse => {
                CompactPublicKeyGenerationRuntimeStage::CrossEpochResponse
            }
            CompactPublicKeyGenerationRuntimePhase::Cfw => {
                CompactPublicKeyGenerationRuntimeStage::Cfw
            }
            CompactPublicKeyGenerationRuntimePhase::WhirSumcheck {
                owner: CompactWhirEpochOwner::PreChallenge,
                ..
            } => CompactPublicKeyGenerationRuntimeStage::PreChallengeWhirSumcheck,
            CompactPublicKeyGenerationRuntimePhase::WhirCodeSwitch {
                owner: CompactWhirEpochOwner::PreChallenge,
                ..
            } => CompactPublicKeyGenerationRuntimeStage::PreChallengeWhirCodeSwitch,
            CompactPublicKeyGenerationRuntimePhase::WhirNextSumcheckPreparation {
                owner: CompactWhirEpochOwner::PreChallenge,
                ..
            } => CompactPublicKeyGenerationRuntimeStage::PreChallengeWhirNextSumcheckPreparation,
            CompactPublicKeyGenerationRuntimePhase::WhirBaseFreshResponse {
                owner: CompactWhirEpochOwner::PreChallenge,
            } => CompactPublicKeyGenerationRuntimeStage::PreChallengeWhirBaseFreshResponse,
            CompactPublicKeyGenerationRuntimePhase::WhirBaseBlindedResponse {
                owner: CompactWhirEpochOwner::PreChallenge,
            } => CompactPublicKeyGenerationRuntimeStage::PreChallengeWhirBaseBlindedResponse,
            CompactPublicKeyGenerationRuntimePhase::MainWhirInitialPreparation => {
                CompactPublicKeyGenerationRuntimeStage::MainWhirInitialPreparation
            }
            CompactPublicKeyGenerationRuntimePhase::WhirSumcheck {
                owner: CompactWhirEpochOwner::Main,
                ..
            } => CompactPublicKeyGenerationRuntimeStage::MainWhirSumcheck,
            CompactPublicKeyGenerationRuntimePhase::WhirCodeSwitch {
                owner: CompactWhirEpochOwner::Main,
                ..
            } => CompactPublicKeyGenerationRuntimeStage::MainWhirCodeSwitch,
            CompactPublicKeyGenerationRuntimePhase::WhirNextSumcheckPreparation {
                owner: CompactWhirEpochOwner::Main,
                ..
            } => CompactPublicKeyGenerationRuntimeStage::MainWhirNextSumcheckPreparation,
            CompactPublicKeyGenerationRuntimePhase::WhirBaseFreshResponse {
                owner: CompactWhirEpochOwner::Main,
            } => CompactPublicKeyGenerationRuntimeStage::MainWhirBaseFreshResponse,
            CompactPublicKeyGenerationRuntimePhase::WhirBaseBlindedResponse {
                owner: CompactWhirEpochOwner::Main,
            } => CompactPublicKeyGenerationRuntimeStage::MainWhirBaseBlindedResponse,
            CompactPublicKeyGenerationRuntimePhase::Complete
            | CompactPublicKeyGenerationRuntimePhase::Cancelled => {
                CompactPublicKeyGenerationRuntimeStage::Complete
            }
        }
    }
}

fn copy_exact_range(
    source: &[u8],
    offset: usize,
    destination: &mut [u8],
) -> Result<(), CommonProofRuntimeError> {
    let end = offset
        .checked_add(destination.len())
        .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
    let source_range = source
        .get(offset..end)
        .ok_or(CommonProofRuntimeError::OutputByteLengthExceeded)?;
    destination.copy_from_slice(source_range);
    Ok(())
}
