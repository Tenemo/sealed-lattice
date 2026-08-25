use crate::{
    foundation::{Hash512, derive_foundation_roster_parameters},
    hashing::hash_framed_parts_512,
    tally_circuit::CompiledTallyCircuit,
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    output_sharing::canonical_evaluation_point,
    preparation_multiplication_catalog::PreparationMultiplicationCatalog,
    replicated_random_sharing::{BinaryFieldPolynomial, CanonicalPolynomialConsistencyVerifier},
};

const TRIPLE_REDUCTION_OPENING_COORDINATE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/triple-reduction-opening-coordinate-identity/v1";

/// Exact algebra coordinate for one triple-reduction opening.
///
/// The identity binds the preparation context, multiplication catalog,
/// multiplication ordinal, and predecessor root. It is a proof-model
/// coordinate, not a signed protocol carrier or accepted state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TripleReductionOpeningCoordinate {
    identity: Hash512,
    context_identity: Hash512,
    participant_count: u16,
    maximum_degree: usize,
}

impl TripleReductionOpeningCoordinate {
    pub(crate) fn derive(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        predecessor_root: Hash512,
        multiplication_ordinal: u64,
    ) -> Result<Self, TripleReductionOpeningError> {
        let catalog = PreparationMultiplicationCatalog::derive(context, circuit)?;
        Self::derive_from_catalog(context, &catalog, predecessor_root, multiplication_ordinal)
    }

    pub(crate) fn derive_from_catalog(
        context: TallyPreparationContext,
        catalog: &PreparationMultiplicationCatalog,
        predecessor_root: Hash512,
        multiplication_ordinal: u64,
    ) -> Result<Self, TripleReductionOpeningError> {
        if catalog.context_identity() != context.identity() {
            return Err(TallyPreparationError::GeometryMismatch.into());
        }
        catalog.operation(multiplication_ordinal)?;
        let participant_count = context.participant_count();
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let maximum_degree = usize::from(roster_parameters.active_fault_bound)
            .checked_mul(2)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if maximum_degree >= usize::from(participant_count) {
            return Err(TallyPreparationError::GeometryMismatch.into());
        }
        let multiplication_ordinal_bytes = multiplication_ordinal.to_le_bytes();
        let participant_count_bytes = participant_count.to_le_bytes();
        let maximum_degree_bytes = u64::try_from(maximum_degree)
            .map_err(|_| TallyPreparationError::IntegerConversion)?
            .to_le_bytes();
        let identity = Hash512::from_bytes(hash_framed_parts_512(
            TRIPLE_REDUCTION_OPENING_COORDINATE_IDENTITY_DOMAIN,
            &[
                context.identity().as_bytes(),
                catalog.identity().as_bytes(),
                predecessor_root.as_bytes(),
                &multiplication_ordinal_bytes,
                &participant_count_bytes,
                &maximum_degree_bytes,
            ],
        ));
        Ok(Self {
            identity,
            context_identity: context.identity(),
            participant_count,
            maximum_degree,
        })
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.identity
    }

    pub(crate) const fn context_identity(self) -> Hash512 {
        self.context_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn maximum_degree(self) -> usize {
        self.maximum_degree
    }
}

/// One already-authenticated algebra slot supplied to the opening model.
///
/// `from_untrusted_fields` deliberately performs no authentication. The real
/// protocol must parse canonical bytes, verify the sender signature and
/// predecessor state, and only then route the fields here. This model cannot
/// establish that source correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TripleReductionOpeningSubmission {
    source_record_identity: Option<Hash512>,
    coordinate_identity: Hash512,
    participant_count: u16,
    roster_position: u16,
    evaluation_point: BinaryFieldElement256,
    value: BinaryFieldElement256,
}

impl TripleReductionOpeningSubmission {
    pub(crate) fn new(
        coordinate: TripleReductionOpeningCoordinate,
        roster_position: u16,
        value: BinaryFieldElement256,
    ) -> Result<Self, TripleReductionOpeningError> {
        Ok(Self {
            source_record_identity: None,
            coordinate_identity: coordinate.identity,
            participant_count: coordinate.participant_count,
            roster_position,
            evaluation_point: canonical_evaluation_point(
                coordinate.participant_count,
                roster_position,
            )?,
            value,
        })
    }

    pub(crate) const fn from_untrusted_fields(
        coordinate_identity: Hash512,
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement256,
        value: BinaryFieldElement256,
    ) -> Self {
        Self {
            source_record_identity: None,
            coordinate_identity,
            participant_count,
            roster_position,
            evaluation_point,
            value,
        }
    }

    pub(in crate::tally_preparation) const fn from_verified_fields(
        source_record_identity: Hash512,
        coordinate_identity: Hash512,
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement256,
        value: BinaryFieldElement256,
    ) -> Self {
        Self {
            source_record_identity: Some(source_record_identity),
            coordinate_identity,
            participant_count,
            roster_position,
            evaluation_point,
            value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TripleReductionOpeningBurnReason {
    CoordinateMismatch,
    ParticipantCountMismatch,
    SenderPositionOutOfRange,
    EvaluationPointMismatch,
    Equivocation,
    NonCodeword,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TripleReductionOpeningProgress {
    Pending {
        received_sender_count: usize,
        required_sender_count: usize,
    },
    BurnRequired(TripleReductionOpeningBurnReason),
    AlgebraicallyConsistent(AlgebraicallyConsistentTripleReduction),
}

/// Exact polynomial result of the algebra-only all-roster check.
///
/// Private fields prevent raw callers from fabricating this local result, but
/// it is not a preparation capsule or workflow capability. Source signatures,
/// transition state, and attempt burn remain outside this model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AlgebraicallyConsistentTripleReduction {
    coordinate_identity: Hash512,
    polynomial: BinaryFieldPolynomial,
}

impl AlgebraicallyConsistentTripleReduction {
    pub(crate) const fn coordinate_identity(&self) -> Hash512 {
        self.coordinate_identity
    }

    pub(crate) fn polynomial(&self) -> &BinaryFieldPolynomial {
        &self.polynomial
    }

    pub(crate) fn opened_constant(&self) -> BinaryFieldElement256 {
        self.polynomial.evaluate(BinaryFieldElement256::ZERO)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TripleReductionOpeningError {
    Preparation(TallyPreparationError),
    AlreadyTerminal,
}

impl From<TallyPreparationError> for TripleReductionOpeningError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TripleReductionOpeningState {
    Collecting,
    Burned,
    AlgebraicallyConsistent,
}

/// All-roster accepted-or-burn algebra state for one degree-`2t` triple
/// reduction.
///
/// A proper sender subset remains pending. Identical retransmission is
/// idempotent. Conflicting or mismatched authenticated slots require burn.
/// Once all slots are present, the model accepts only an exact degree-bounded
/// codeword and returns no corrected polynomial or position set on failure.
pub(crate) struct TripleReductionOpeningCollector {
    coordinate: TripleReductionOpeningCoordinate,
    consistency_verifier: CanonicalPolynomialConsistencyVerifier,
    submissions: Vec<Option<TripleReductionOpeningSubmission>>,
    received_sender_count: usize,
    state: TripleReductionOpeningState,
}

impl TripleReductionOpeningCollector {
    pub(crate) fn new(
        coordinate: TripleReductionOpeningCoordinate,
    ) -> Result<Self, TripleReductionOpeningError> {
        Ok(Self {
            coordinate,
            consistency_verifier: CanonicalPolynomialConsistencyVerifier::new(
                coordinate.participant_count,
                coordinate.maximum_degree,
            )?,
            submissions: vec![None; usize::from(coordinate.participant_count)],
            received_sender_count: 0,
            state: TripleReductionOpeningState::Collecting,
        })
    }

    pub(crate) fn absorb(
        &mut self,
        submission: TripleReductionOpeningSubmission,
    ) -> Result<TripleReductionOpeningProgress, TripleReductionOpeningError> {
        if self.state != TripleReductionOpeningState::Collecting {
            return Err(TripleReductionOpeningError::AlreadyTerminal);
        }
        if submission.coordinate_identity != self.coordinate.identity {
            return Ok(self.burn(TripleReductionOpeningBurnReason::CoordinateMismatch));
        }
        if submission.participant_count != self.coordinate.participant_count {
            return Ok(self.burn(TripleReductionOpeningBurnReason::ParticipantCountMismatch));
        }
        if submission.roster_position >= self.coordinate.participant_count {
            return Ok(self.burn(TripleReductionOpeningBurnReason::SenderPositionOutOfRange));
        }
        let expected_evaluation_point = canonical_evaluation_point(
            self.coordinate.participant_count,
            submission.roster_position,
        )?;
        if submission.evaluation_point != expected_evaluation_point {
            return Ok(self.burn(TripleReductionOpeningBurnReason::EvaluationPointMismatch));
        }

        let submission_position = usize::from(submission.roster_position);
        if let Some(previous_submission) = self.submissions[submission_position] {
            if previous_submission == submission {
                return Ok(self.pending());
            }
            return Ok(self.burn(TripleReductionOpeningBurnReason::Equivocation));
        }
        self.submissions[submission_position] = Some(submission);
        self.received_sender_count = self
            .received_sender_count
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if self.received_sender_count != self.submissions.len() {
            return Ok(self.pending());
        }

        let values = self
            .submissions
            .iter()
            .map(|submission| {
                submission
                    .as_ref()
                    .map(|submission| submission.value)
                    .ok_or(TallyPreparationError::GeometryMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Some(polynomial) = self.consistency_verifier.interpolate_and_verify(&values)? else {
            return Ok(self.burn(TripleReductionOpeningBurnReason::NonCodeword));
        };
        self.state = TripleReductionOpeningState::AlgebraicallyConsistent;
        Ok(TripleReductionOpeningProgress::AlgebraicallyConsistent(
            AlgebraicallyConsistentTripleReduction {
                coordinate_identity: self.coordinate.identity,
                polynomial,
            },
        ))
    }

    fn pending(&self) -> TripleReductionOpeningProgress {
        TripleReductionOpeningProgress::Pending {
            received_sender_count: self.received_sender_count,
            required_sender_count: self.submissions.len(),
        }
    }

    fn burn(&mut self, reason: TripleReductionOpeningBurnReason) -> TripleReductionOpeningProgress {
        self.state = TripleReductionOpeningState::Burned;
        TripleReductionOpeningProgress::BurnRequired(reason)
    }
}
