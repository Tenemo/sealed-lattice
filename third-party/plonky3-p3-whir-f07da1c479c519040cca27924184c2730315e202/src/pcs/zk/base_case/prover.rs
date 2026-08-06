//! HVZK base-case prover (Construction 7.2).
//!
//! Local modification: fresh masks come from caller-owned private coins, and
//! transcript-complete preparation can precede bounded authenticated source
//! opening. See `../../../../UPSTREAM.md`.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField, dot_product};
use p3_matrix::dense::RowMajorMatrix;
use p3_sumcheck::zk::stack_codewords;
use p3_zk_codes::{ZkEncoding, ZkEncodingWithRandomness};
use rand::distr::{Distribution, StandardUniform};
use rand::{Rng, RngExt};

use super::config::{BaseCaseZkConfig, MaskGroupWitness};
use crate::pcs::proof::QueryOpening;
use crate::pcs::utils::get_challenge_stir_queries;
use crate::pcs::zk::proof::{BaseCaseZkProof, BlindedMask, MaskOpeningPair};

/// Fresh one-time material for one carried mask group in Construction 7.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseCaseFreshMaskGroup<EF> {
    /// One fresh message per member of the carried mask group.
    pub messages: Vec<Vec<EF>>,
    /// Encoding randomness paired with each fresh message.
    pub randomness: Vec<Vec<EF>>,
}

/// All fresh one-time material consumed by one Construction 7.2 proof.
///
/// Supplying this explicitly lets callers draw every secret value from their
/// protocol-owned private-coin domain while retaining the same base-case
/// transcript and checks as [`BaseCaseZkProver::prove`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseCaseFreshMaterial<EF> {
    /// Fresh source-message pad.
    pub source_message: Vec<EF>,
    /// Fresh source-encoding randomness pad.
    pub source_randomness: Vec<EF>,
    /// Fresh pads for the carried mask groups, in configuration order.
    pub mask_groups: Vec<BaseCaseFreshMaskGroup<EF>>,
}

/// Transcript-complete base-case state awaiting authenticated source rows.
///
/// The source positions are already sampled and bound to every preceding
/// commitment, claim, challenge, and reveal. This split lets a bounded caller
/// fetch those rows from external storage without changing Construction 7.2.
pub struct PreparedBaseCaseZkProof<F: Send + Sync + Clone, EF, MT: Mmcs<F>> {
    proof: BaseCaseZkProof<F, EF, MT>,
    source_positions: Vec<usize>,
}

impl<F: Send + Sync + Clone, EF, MT: Mmcs<F>> PreparedBaseCaseZkProof<F, EF, MT> {
    /// Canonical ascending source positions required by the prepared proof.
    #[must_use]
    pub fn source_positions(&self) -> &[usize] {
        &self.source_positions
    }

    /// Supplies exactly one authenticated source opening per sampled position.
    pub fn finish(
        mut self,
        source_queries: Vec<QueryOpening<F, EF, MT::Proof>>,
    ) -> Result<BaseCaseZkProof<F, EF, MT>, &'static str> {
        if source_queries.len() != self.source_positions.len() {
            return Err("prepared base case received the wrong source-opening count");
        }
        self.proof.source_queries = source_queries;
        Ok(self.proof)
    }
}

/// HVZK base-case prover (Construction 7.2).
pub struct BaseCaseZkProver<'a, F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Protocol shape shared with the verifier.
    pub config: &'a BaseCaseZkConfig<F>,
    /// Commitment scheme for the fresh masks and mask openings.
    pub extension_mmcs: &'a ExtensionMmcs<F, EF, MT>,
}

impl<F, EF, MT> BaseCaseZkProver<'_, F, EF, MT>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F>,
    StandardUniform: Distribution<EF>,
{
    /// Samples fresh one-time material and runs Construction 7.2.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<Dft, Challenger, R>(
        &self,
        dft: &Dft,
        source_message: &[EF],
        source_randomness: &[EF],
        source_covector: &[EF],
        masks: &[MaskGroupWitness<'_, F, EF, MT>],
        open_source: impl FnMut(usize) -> QueryOpening<F, EF, MT::Proof>,
        challenger: &mut Challenger,
        rng: &mut R,
    ) -> BaseCaseZkProof<F, EF, MT>
    where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanSampleUniformBits<F>
            + CanObserve<MT::Commitment>,
        R: Rng,
    {
        let source_code = &self.config.code;
        let mask_groups = self
            .config
            .mask_groups
            .iter()
            .map(|group| {
                let encoding = group.shape.encoding::<EF>();
                BaseCaseFreshMaskGroup {
                    messages: (0..group.width)
                        .map(|_| encoding.sample_message(rng))
                        .collect(),
                    randomness: (0..group.width)
                        .map(|_| encoding.sample_randomness(rng))
                        .collect(),
                }
            })
            .collect();
        let fresh_material = BaseCaseFreshMaterial {
            source_message: (0..source_code.message_len).map(|_| rng.random()).collect(),
            source_randomness: (0..source_code.randomness_len)
                .map(|_| rng.random())
                .collect(),
            mask_groups,
        };
        self.prove_with_material(
            dft,
            source_message,
            source_randomness,
            source_covector,
            masks,
            &fresh_material,
            open_source,
            challenger,
        )
    }

    /// Runs Construction 7.2 and returns the proof payload.
    ///
    /// # Moves
    ///
    /// ```text
    ///     1. commit fresh masks       g, s'_i
    ///     2. send fresh-side claim    mu_g
    ///     3. receive challenge        gamma
    ///     4. reveal one-time pads     f*, r*, xi*_i, r*_i
    ///     5. open spot-check positions
    /// ```
    ///
    /// # Arguments
    ///
    /// - `open_source`: opens the (virtual) source at a folded-domain position.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_with_material<Dft, Challenger>(
        &self,
        dft: &Dft,
        source_message: &[EF],
        source_randomness: &[EF],
        source_covector: &[EF],
        masks: &[MaskGroupWitness<'_, F, EF, MT>],
        fresh_material: &BaseCaseFreshMaterial<EF>,
        mut open_source: impl FnMut(usize) -> QueryOpening<F, EF, MT::Proof>,
        challenger: &mut Challenger,
    ) -> BaseCaseZkProof<F, EF, MT>
    where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanSampleUniformBits<F>
            + CanObserve<MT::Commitment>,
    {
        let prepared = self.prepare_with_material(
            dft,
            source_message,
            source_randomness,
            source_covector,
            masks,
            fresh_material,
            challenger,
        );
        let source_queries = prepared
            .source_positions()
            .iter()
            .copied()
            .map(&mut open_source)
            .collect();
        prepared
            .finish(source_queries)
            .expect("the wrapper supplies every prepared source opening")
    }

    /// Runs every transcript move through source-position sampling, then
    /// yields so a bounded caller can authenticate those positions.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn prepare_with_material<Dft, Challenger>(
        &self,
        dft: &Dft,
        source_message: &[EF],
        source_randomness: &[EF],
        source_covector: &[EF],
        masks: &[MaskGroupWitness<'_, F, EF, MT>],
        fresh_material: &BaseCaseFreshMaterial<EF>,
        challenger: &mut Challenger,
    ) -> PreparedBaseCaseZkProof<F, EF, MT>
    where
        Dft: TwoAdicSubgroupDft<F>,
        Challenger: FieldChallenger<F>
            + GrindingChallenger<Witness = F>
            + CanSampleUniformBits<F>
            + CanObserve<MT::Commitment>,
    {
        let code = &self.config.code;
        // The witness must fit the agreed folded source code exactly.
        assert_eq!(source_message.len(), code.message_len);
        assert_eq!(source_randomness.len(), code.randomness_len);
        assert_eq!(source_covector.len(), code.message_len);
        assert_eq!(masks.len(), self.config.mask_groups.len());
        assert_eq!(fresh_material.source_message.len(), code.message_len);
        assert_eq!(fresh_material.source_randomness.len(), code.randomness_len);
        assert_eq!(
            fresh_material.mask_groups.len(),
            self.config.mask_groups.len()
        );

        // Move 1a: fresh main mask g = Enc(g~, r_g).
        //
        //     g~   ->  uniform vector, future pad of the source reveal f*
        //     r_g  ->  uniform vector, future pad of the randomness reveal r*
        //
        // Why the source's own code: the spot check later compares
        //
        //     Enc(f*, r*)(z)  vs  g(z) + gamma * f(z)
        //
        // and that equation needs all three words in one code.
        let fresh_message = &fresh_material.source_message;
        let fresh_randomness = &fresh_material.source_randomness;
        let codeword = code.encode_column(dft, fresh_message, fresh_randomness);
        let (fresh_main_commitment, fresh_main_data) = self.extension_mmcs.commit_matrix(codeword);
        // Bind the commitment before any challenge depends on it.
        challenger.observe(fresh_main_commitment.clone());

        // Move 1b: one fresh blind s'_i = Enc(s~'_i, r'_i) per carried mask.
        //
        // Blinds are committed group-wise, mirroring how the carried masks
        // were committed:
        //
        //     group of width w  ->  w codewords stacked into one matrix
        //                       ->  one root, one Merkle path per position
        let mut fresh_mask_commitments = Vec::with_capacity(masks.len());
        let mut fresh_groups = Vec::with_capacity(masks.len());
        for ((group, witness), fresh_group) in self
            .config
            .mask_groups
            .iter()
            .zip(masks)
            .zip(&fresh_material.mask_groups)
        {
            // Every member of a group shares the group's code.
            let encoding = group.shape.encoding::<EF>();
            assert_eq!(fresh_group.messages.len(), group.width);
            assert_eq!(fresh_group.randomness.len(), group.width);
            assert!(
                fresh_group
                    .messages
                    .iter()
                    .all(|message| message.len() == encoding.message_len())
            );
            assert!(
                fresh_group
                    .randomness
                    .iter()
                    .all(|randomness| randomness.len() == encoding.randomness_len())
            );
            let codewords: Vec<RowMajorMatrix<EF>> = fresh_group
                .messages
                .iter()
                .zip(&fresh_group.randomness)
                .map(|(message, randomness)| encoding.encode_with_randomness(message, randomness))
                .collect();
            // Row z of the stacked matrix holds position z of every blind.
            let (commitment, data) = self
                .extension_mmcs
                .commit_matrix(stack_codewords(&codewords));
            challenger.observe(commitment.clone());
            fresh_mask_commitments.push(commitment);
            fresh_groups.push((
                &fresh_group.messages,
                &fresh_group.randomness,
                data,
                witness,
            ));
        }

        // Move 2: the fresh-side claim.
        //
        //     mu_g = <g~, W> + sum_i <s~'_i, u_i>
        //
        // The relation evaluated on the fresh masks instead of the secrets.
        // Soundness hinges on mu_g being fixed before gamma is known.
        let mut masked_claim = dot_product::<EF, _, _>(
            fresh_message.iter().copied(),
            source_covector.iter().copied(),
        );
        for (blind_messages, _, _, witness) in &fresh_groups {
            for (message, covector) in blind_messages.iter().zip(witness.covectors) {
                masked_claim +=
                    dot_product::<EF, _, _>(message.iter().copied(), covector.iter().copied());
            }
        }
        challenger.observe_algebra_element(masked_claim);

        // Move 3: the blinding challenge, bound to every commitment above.
        let gamma: EF = challenger.sample_algebra_element();

        // Move 4: the one-time-pad reveals.
        //
        //     reveal = fresh + gamma * secret
        //
        // Uniform fresh, used once: the reveal is uniform and leaks nothing (Lemma 7.3).
        let blind = |fresh: &[EF], hidden: &[EF]| -> Vec<EF> {
            fresh
                .iter()
                .zip(hidden)
                .map(|(&fresh, &hidden)| fresh + gamma * hidden)
                .collect()
        };
        // Source reveals: f* = g~ + gamma * f and r* = r_g + gamma * r.
        let blinded_message = blind(fresh_message, source_message);
        let blinded_randomness = blind(fresh_randomness, source_randomness);
        challenger.observe_algebra_slice(&blinded_message);
        challenger.observe_algebra_slice(&blinded_randomness);
        // Mask reveals:
        // - xi*_i = s~'_i + gamma * xi_i,
        // - the analogous r*_i for each mask's encoding randomness.
        let mut blinded_masks = Vec::new();
        for (blind_messages, blind_randomness, _, witness) in &fresh_groups {
            for ((message, randomness), (hidden_message, hidden_randomness)) in blind_messages
                .iter()
                .zip(blind_randomness.iter())
                .zip(witness.messages.iter().zip(witness.randomness))
            {
                let blinded = BlindedMask {
                    message: blind(message, hidden_message),
                    randomness: blind(randomness, hidden_randomness),
                };
                // Absorb each reveal before the spot positions are drawn.
                challenger.observe_algebra_slice(&blinded.message);
                challenger.observe_algebra_slice(&blinded.randomness);
                blinded_masks.push(blinded);
            }
        }

        // PoW before the spot checks.
        //
        //     pow_bits = 0  ->  no grind, zero witness on the wire
        let pow_witness = if self.config.pow_bits > 0 {
            challenger.grind(self.config.pow_bits)
        } else {
            F::ZERO
        };

        // Move 5a: source spot checks, t positions on the source domain.
        //
        // The verifier will recheck, per position z:
        //
        //     Enc(f*, r*)(z) = g(z) + gamma * f(z)
        //
        // so both committed sides are opened here.
        let positions = get_challenge_stir_queries::<Challenger, F>(
            code.domain_size,
            0,
            self.config.num_queries,
            challenger,
        );
        let mut fresh_main_queries = Vec::with_capacity(positions.len());
        for &position in &positions {
            // g(z): the fresh main mask, committed above.
            let opening = self.extension_mmcs.open_batch(position, &fresh_main_data);
            fresh_main_queries.push(QueryOpening::Extension {
                values: opening.opened_values.into_iter().next().unwrap(),
                proof: opening.opening_proof,
            });
        }

        // Move 5b: mask spot checks, t_zk positions per group.
        //
        // The verifier will recheck, per position y and group member i:
        //
        //     Enc(xi*_i, r*_i)(y) = s'_i(y) + gamma * xi_i(y)
        //
        // Positions are shared across the group, so one opened row of each
        // oracle serves every member.
        let mut mask_queries = Vec::with_capacity(fresh_groups.len());
        for (group, (_, _, fresh_data, witness)) in
            self.config.mask_groups.iter().zip(&fresh_groups)
        {
            let positions = get_challenge_stir_queries::<Challenger, F>(
                group.shape.domain_size,
                0,
                self.config.mask_queries,
                challenger,
            );
            let pairs = positions
                .iter()
                .map(|&position| {
                    // xi_i(y) and s'_i(y): the carried group oracle and its
                    // fresh blind, opened at the same position.
                    let carried = self.extension_mmcs.open_batch(position, witness.data);
                    let fresh = self.extension_mmcs.open_batch(position, fresh_data);
                    MaskOpeningPair {
                        carried: QueryOpening::Extension {
                            values: carried.opened_values.into_iter().next().unwrap(),
                            proof: carried.opening_proof,
                        },
                        fresh: QueryOpening::Extension {
                            values: fresh.opened_values.into_iter().next().unwrap(),
                            proof: fresh.opening_proof,
                        },
                    }
                })
                .collect();
            mask_queries.push(pairs);
        }

        PreparedBaseCaseZkProof {
            proof: BaseCaseZkProof {
                fresh_main_commitment,
                fresh_mask_commitments,
                masked_claim,
                blinded_message,
                blinded_randomness,
                blinded_masks,
                pow_witness,
                source_queries: Vec::new(),
                fresh_main_queries,
                mask_queries,
            },
            source_positions: positions,
        }
    }
}
