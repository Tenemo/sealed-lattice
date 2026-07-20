//! Exact query-local radix-two FRI verification for the common proof.

use super::{
    field::ProofChallengeExtensionElement,
    polynomial::{
        ProofEvaluationDomain, ProofPolynomialError, evaluate_extension_at,
        extension_polynomial_degree, fold_extension_pair,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofFriError {
    InvalidSchedule,
    InvalidQueryRepresentative,
    InvalidLayerOpening,
    TerminalDegreeExceeded,
    TerminalEvaluationMismatch,
    Polynomial(ProofPolynomialError),
}

impl From<ProofPolynomialError> for ProofFriError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenedFriLayerPair {
    first: ProofChallengeExtensionElement,
    opposite: ProofChallengeExtensionElement,
}

impl OpenedFriLayerPair {
    pub(crate) const fn new(
        first: ProofChallengeExtensionElement,
        opposite: ProofChallengeExtensionElement,
    ) -> Self {
        Self { first, opposite }
    }

    pub(crate) const fn first(self) -> ProofChallengeExtensionElement {
        self.first
    }

    pub(crate) const fn opposite(self) -> ProofChallengeExtensionElement {
        self.opposite
    }
}

/// Immutable verifier state shared by every query.  The terminal coefficient
/// vector is retained because its profile bound is small; no oracle layer or
/// complete proof body is retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFriQueryVerifier {
    initial_domain: ProofEvaluationDomain,
    fold_challenges: Vec<ProofChallengeExtensionElement>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
    terminal_domain: ProofEvaluationDomain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofFriQueryState {
    current_domain: ProofEvaluationDomain,
    current_position: usize,
    current_pair: OpenedFriLayerPair,
    next_nonterminal_layer_ordinal: usize,
}

impl ProofFriQueryVerifier {
    pub(crate) fn new(
        initial_domain: ProofEvaluationDomain,
        fold_challenges: Vec<ProofChallengeExtensionElement>,
        terminal_coefficients: Vec<ProofChallengeExtensionElement>,
        final_polynomial_degree_bound_exclusive: usize,
    ) -> Result<Self, ProofFriError> {
        if fold_challenges.is_empty()
            || final_polynomial_degree_bound_exclusive == 0
            || terminal_coefficients.len() != final_polynomial_degree_bound_exclusive
        {
            return Err(ProofFriError::InvalidSchedule);
        }

        let mut terminal_domain = initial_domain;
        for _ in &fold_challenges {
            terminal_domain = terminal_domain
                .folded()
                .map_err(|_| ProofFriError::InvalidSchedule)?;
        }
        if final_polynomial_degree_bound_exclusive > terminal_domain.size() {
            return Err(ProofFriError::InvalidSchedule);
        }
        if extension_polynomial_degree(&terminal_coefficients)
            .is_some_and(|degree| degree >= final_polynomial_degree_bound_exclusive)
        {
            return Err(ProofFriError::TerminalDegreeExceeded);
        }

        Ok(Self {
            initial_domain,
            fold_challenges,
            terminal_coefficients,
            terminal_domain,
        })
    }

    pub(crate) const fn nonterminal_layer_count(&self) -> usize {
        self.fold_challenges.len() - 1
    }

    pub(crate) fn begin_query(
        &self,
        query_representative: u64,
        initial_pair: OpenedFriLayerPair,
    ) -> Result<ProofFriQueryState, ProofFriError> {
        let current_position = usize::try_from(query_representative)
            .map_err(|_| ProofFriError::InvalidQueryRepresentative)?;
        if current_position >= self.initial_domain.size() / 2 {
            return Err(ProofFriError::InvalidQueryRepresentative);
        }
        Ok(ProofFriQueryState {
            current_domain: self.initial_domain,
            current_position,
            current_pair: initial_pair,
            next_nonterminal_layer_ordinal: 0,
        })
    }

    pub(crate) fn verify_nonterminal_layer(
        &self,
        state: &mut ProofFriQueryState,
        fold_ordinal: usize,
        next_layer_pair: OpenedFriLayerPair,
    ) -> Result<(), ProofFriError> {
        if fold_ordinal != state.next_nonterminal_layer_ordinal
            || fold_ordinal >= self.nonterminal_layer_count()
        {
            return Err(ProofFriError::InvalidLayerOpening);
        }
        let current_point = state.current_domain.point(state.current_position)?;
        let folded_value = fold_extension_pair(
            state.current_pair.first,
            state.current_pair.opposite,
            current_point,
            self.fold_challenges[fold_ordinal],
        )?;
        let next_domain = state.current_domain.folded()?;
        let next_leaf_count = next_domain.size() / 2;
        let next_value = if state.current_position < next_leaf_count {
            next_layer_pair.first
        } else {
            next_layer_pair.opposite
        };
        if folded_value != next_value {
            return Err(ProofFriError::InvalidLayerOpening);
        }
        state.current_position %= next_leaf_count;
        state.current_domain = next_domain;
        state.current_pair = next_layer_pair;
        state.next_nonterminal_layer_ordinal += 1;
        Ok(())
    }

    pub(crate) fn finish_query(&self, state: ProofFriQueryState) -> Result<(), ProofFriError> {
        if state.next_nonterminal_layer_ordinal != self.nonterminal_layer_count() {
            return Err(ProofFriError::InvalidLayerOpening);
        }
        let current_point = state.current_domain.point(state.current_position)?;
        let terminal_value = fold_extension_pair(
            state.current_pair.first,
            state.current_pair.opposite,
            current_point,
            *self
                .fold_challenges
                .last()
                .ok_or(ProofFriError::InvalidSchedule)?,
        )?;
        let terminal_position = state.current_position % self.terminal_domain.size();
        let terminal_point = ProofChallengeExtensionElement::from_base(
            self.terminal_domain.point(terminal_position)?,
        );
        if evaluate_extension_at(&self.terminal_coefficients, terminal_point) != terminal_value {
            return Err(ProofFriError::TerminalEvaluationMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn verify_query(
        &self,
        query_representative: u64,
        initial_pair: OpenedFriLayerPair,
        nonterminal_layer_pairs: &[OpenedFriLayerPair],
    ) -> Result<(), ProofFriError> {
        let mut state = self.begin_query(query_representative, initial_pair)?;
        for (fold_ordinal, next_layer_pair) in nonterminal_layer_pairs.iter().copied().enumerate() {
            self.verify_nonterminal_layer(&mut state, fold_ordinal, next_layer_pair)?;
        }
        self.finish_query(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{ProofBaseFieldElement, polynomial::fold_extension_evaluations};

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(value).expect("small canonical value"),
        )
    }

    #[test]
    fn verifies_each_side_selection_and_terminal_evaluation() {
        let initial_domain = ProofEvaluationDomain::new(64, 7).expect("test domain");
        let coefficients = (1_u64..=8).map(extension).collect::<Vec<_>>();
        let challenges = vec![extension(11), extension(13), extension(17)];
        let initial_evaluations = initial_domain
            .evaluate_extension_polynomial(&coefficients)
            .expect("initial evaluations");

        let mut domains = vec![initial_domain];
        let mut evaluation_layers = vec![initial_evaluations];
        for challenge in &challenges {
            let next = fold_extension_evaluations(
                evaluation_layers.last().expect("current layer"),
                *domains.last().expect("current domain"),
                *challenge,
            )
            .expect("valid fold");
            domains.push(
                domains
                    .last()
                    .expect("domain")
                    .folded()
                    .expect("folded domain"),
            );
            evaluation_layers.push(next);
        }
        let mut terminal_coefficients = domains
            .last()
            .expect("terminal domain")
            .interpolate_extension_polynomial(
                evaluation_layers.last().expect("terminal evaluations"),
            )
            .expect("terminal interpolation");
        terminal_coefficients.resize(8, ProofChallengeExtensionElement::ZERO);
        let verifier =
            ProofFriQueryVerifier::new(initial_domain, challenges, terminal_coefficients, 8)
                .expect("valid verifier schedule");

        for representative in [0_usize, 7, 17, 31] {
            let initial_half = evaluation_layers[0].len() / 2;
            let initial_pair = OpenedFriLayerPair::new(
                evaluation_layers[0][representative],
                evaluation_layers[0][representative + initial_half],
            );
            let mut current_position = representative;
            let mut opened_layers = Vec::new();
            for layer in evaluation_layers.iter().skip(1).take(2) {
                let half = layer.len() / 2;
                let leaf_index = current_position % half;
                opened_layers.push(OpenedFriLayerPair::new(
                    layer[leaf_index],
                    layer[leaf_index + half],
                ));
                current_position = leaf_index;
            }
            verifier
                .verify_query(representative as u64, initial_pair, &opened_layers)
                .expect("query path is consistent");
        }
    }

    #[test]
    fn rejects_a_mutated_nonterminal_value_and_terminal_value() {
        let domain = ProofEvaluationDomain::new(16, 7).expect("test domain");
        let challenges = vec![extension(3), extension(5)];
        let initial = domain
            .evaluate_extension_polynomial(&[extension(2), extension(7)])
            .expect("initial evaluations");
        let first_fold =
            fold_extension_evaluations(&initial, domain, challenges[0]).expect("first fold");
        let folded_domain = domain.folded().expect("folded domain");
        let terminal = fold_extension_evaluations(&first_fold, folded_domain, challenges[1])
            .expect("terminal evaluations");
        let mut terminal_coefficients = folded_domain
            .folded()
            .expect("terminal domain")
            .interpolate_extension_polynomial(&terminal)
            .expect("terminal coefficients");
        terminal_coefficients.resize(4, ProofChallengeExtensionElement::ZERO);
        let verifier =
            ProofFriQueryVerifier::new(domain, challenges, terminal_coefficients.clone(), 4)
                .expect("verifier");
        let representative = 3_usize;
        let initial_pair = OpenedFriLayerPair::new(
            initial[representative],
            initial[representative + initial.len() / 2],
        );
        let leaf_index = representative % (first_fold.len() / 2);
        let valid_layer = OpenedFriLayerPair::new(
            first_fold[leaf_index],
            first_fold[leaf_index + first_fold.len() / 2],
        );
        let mutated_layer = OpenedFriLayerPair::new(
            valid_layer.first().add(ProofChallengeExtensionElement::ONE),
            valid_layer.opposite(),
        );
        assert_eq!(
            verifier.verify_query(representative as u64, initial_pair, &[mutated_layer]),
            Err(ProofFriError::InvalidLayerOpening),
        );

        terminal_coefficients[0] =
            terminal_coefficients[0].add(ProofChallengeExtensionElement::ONE);
        let mutated_terminal_verifier = ProofFriQueryVerifier::new(
            domain,
            vec![extension(3), extension(5)],
            terminal_coefficients,
            4,
        )
        .expect("mutated terminal still has a valid shape");
        assert_eq!(
            mutated_terminal_verifier.verify_query(
                representative as u64,
                initial_pair,
                &[valid_layer],
            ),
            Err(ProofFriError::TerminalEvaluationMismatch),
        );
    }
}
