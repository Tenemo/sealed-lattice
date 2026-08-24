//! Diagnostic-only timing ownership for scalar compact generation.
//!
//! These observations are deliberately outside every canonical encoder,
//! checkpoint, proof, verifier result, and capability path. Clock values can
//! neither alter generation nor authorize acceptance.

use std::{cell::RefCell, rc::Rc};

use crate::diagnostic_clock::now_milliseconds;

const MAXIMUM_DIAGNOSTIC_OBSERVATION_COUNT: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum CompactGenerationDiagnosticOwner {
    UpstreamAuthorityResolution = 1,
    CommonSecretSampling = 2,
    AnchorOpeningConstruction = 3,
    PublicKeyShareConstruction = 4,
    ReferenceAuthorityRetention = 5,
    RelationSourceResolution = 6,
    SetupIntentSourceResolution = 7,
    StateReservationResolution = 8,
    ProofContractLoading = 9,
    PreparedAttemptResolution = 10,
    StatementDecoding = 11,
    ProductionRelationContextLoading = 12,
    RelationCatalogLoadingAndValidation = 13,
    AssignmentSourceCatalogLoadingAndValidation = 14,
    SourceAdapterPreparation = 15,
    AssignmentCursorPreparation = 16,
    RuntimeContractLoading = 17,
    RuntimeInitializationAndRetention = 18,
    FiatShamirChallengeDerivation = 19,
    FiatShamirPublicInputAbsorption = 20,
}

impl CompactGenerationDiagnosticOwner {
    pub(in crate::bgv) const fn canonical_code(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CompactGenerationDiagnosticObservation {
    owner: CompactGenerationDiagnosticOwner,
    started_at_milliseconds: f64,
    finished_at_milliseconds: f64,
}

impl CompactGenerationDiagnosticObservation {
    pub(in crate::bgv) const fn new(
        owner: CompactGenerationDiagnosticOwner,
        started_at_milliseconds: f64,
        finished_at_milliseconds: f64,
    ) -> Self {
        Self {
            owner,
            started_at_milliseconds,
            finished_at_milliseconds,
        }
    }

    pub(in crate::bgv) const fn owner(self) -> CompactGenerationDiagnosticOwner {
        self.owner
    }

    pub(in crate::bgv) const fn started_at_milliseconds(self) -> f64 {
        self.started_at_milliseconds
    }

    pub(in crate::bgv) const fn finished_at_milliseconds(self) -> f64 {
        self.finished_at_milliseconds
    }
}

#[derive(Clone, Default)]
pub(crate) struct CompactGenerationDiagnosticCollector {
    observations: Rc<RefCell<Vec<CompactGenerationDiagnosticObservation>>>,
}

impl CompactGenerationDiagnosticCollector {
    pub(in crate::bgv) fn new() -> Self {
        Self::default()
    }

    pub(in crate::bgv) fn measure<ResultValue>(
        &self,
        owner: CompactGenerationDiagnosticOwner,
        operation: impl FnOnce() -> ResultValue,
    ) -> ResultValue {
        let started_at_milliseconds = now_milliseconds();
        let result = operation();
        let finished_at_milliseconds = now_milliseconds();
        self.record(CompactGenerationDiagnosticObservation::new(
            owner,
            started_at_milliseconds,
            finished_at_milliseconds,
        ));
        result
    }

    pub(in crate::bgv) fn record(&self, observation: CompactGenerationDiagnosticObservation) {
        let Ok(mut observations) = self.observations.try_borrow_mut() else {
            return;
        };
        if observations.len() >= MAXIMUM_DIAGNOSTIC_OBSERVATION_COUNT
            || observations.try_reserve(1).is_err()
        {
            return;
        }
        observations.push(observation);
    }

    pub(in crate::bgv) fn with_observations<ResultValue>(
        &self,
        operation: impl FnOnce(&[CompactGenerationDiagnosticObservation]) -> ResultValue,
    ) -> Option<ResultValue> {
        let observations = self.observations.try_borrow().ok()?;
        Some(operation(&observations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_collection_is_bounded_and_cannot_change_operation_results() {
        let diagnostics = CompactGenerationDiagnosticCollector::new();
        let operation_result = diagnostics.measure(
            CompactGenerationDiagnosticOwner::RelationCatalogLoadingAndValidation,
            || [0x31_u8; 32],
        );
        assert_eq!(operation_result, [0x31_u8; 32]);

        for ordinal in 0..MAXIMUM_DIAGNOSTIC_OBSERVATION_COUNT + 16 {
            diagnostics.record(CompactGenerationDiagnosticObservation::new(
                CompactGenerationDiagnosticOwner::AssignmentSourceCatalogLoadingAndValidation,
                ordinal as f64,
                ordinal as f64 + 0.5,
            ));
        }
        let observations = diagnostics
            .with_observations(<[_]>::len)
            .expect("diagnostic observations remain readable");
        assert_eq!(observations, MAXIMUM_DIAGNOSTIC_OBSERVATION_COUNT);
    }

    #[test]
    fn diagnostic_borrow_contention_drops_only_the_observation() {
        let diagnostics = CompactGenerationDiagnosticCollector::new();
        diagnostics.record(CompactGenerationDiagnosticObservation::new(
            CompactGenerationDiagnosticOwner::RuntimeContractLoading,
            1.0,
            2.0,
        ));

        diagnostics
            .with_observations(|observations| {
                assert_eq!(observations.len(), 1);
                diagnostics.record(CompactGenerationDiagnosticObservation::new(
                    CompactGenerationDiagnosticOwner::RuntimeInitializationAndRetention,
                    3.0,
                    4.0,
                ));
            })
            .expect("the original observation borrow remains valid");

        assert_eq!(
            diagnostics.with_observations(<[_]>::len),
            Some(1),
            "borrow contention must not escape into the cryptographic operation"
        );
    }
}
