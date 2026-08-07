//! Hop ledger that separates the deployed mask generator from its ideal game.
//!
//! Every algebraic masking argument reasons about uniform, independent field
//! samples. Deployment does not produce those: it produces a keyed KMAC256
//! stream over framed canonical inputs, reduced to field elements by a bounded
//! rejection sampler. This module names each replacement hop between the two,
//! records which are exact statistical steps and which are computational
//! reductions, and derives every quantity from the production constants rather
//! than restating them.
//!
//! The ledger is deliberately not a security proof. It is the bookkeeping that
//! keeps a masking argument from silently assuming that values expanded from
//! one keyed stream are information-theoretically independent.

#[cfg(test)]
use super::domain::PrivateRandomnessDomain;
#[cfg(test)]
use super::material::ActionRandomnessDerivationInput;
#[cfg(test)]
use super::proof_coins::PrivateRandomnessAttemptIdentifier;
#[cfg(test)]
use super::stream::PrivateRandomBlockInput;
use super::{
    ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH, ACTION_RANDOMNESS_ROOT_BYTE_LENGTH,
    PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH, PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH,
};
use crate::foundation::DECLARED_ADVERSARIAL_QUERY_BUDGET;
#[cfg(test)]
use crate::foundation::Hash512;

/// What one replacement hop costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaskGeneratorHybridLoss {
    /// The hop is exactly free, for a structural reason named by the hop.
    Exact,
    /// The hop loses at most `query_budget / 2^secret_bit_length`.
    ///
    /// This is the guessing term for a uniformly sampled secret of the stated
    /// length under the stated query budget.
    SecretGuessing {
        secret_bit_length: u32,
        query_budget: u128,
    },
    /// The hop loses at most `(2 * query_budget + 1)^2 / 2^secret_bit_length`.
    ///
    /// This is the generic quantum search bound for a uniformly sampled
    /// secret when the adversary can check candidates through a quantum
    /// oracle. It is deliberately distinct from classical guessing.
    QuantumSecretSearch {
        secret_bit_length: u32,
        query_budget: u128,
    },
    /// The hop is a computational reduction, not a statistical step.
    ///
    /// A number here would be invented. The ledger records the assumption, the
    /// key length it is instantiated at, and the query budget it must hold
    /// against, and requires the surrounding argument to carry the reduction.
    ComputationalReduction {
        assumption: MaskGeneratorHybridAssumption,
        key_bit_length: u32,
        classical_query_budget: u128,
    },
    /// The hop is exact once conditioned on an honest-abort event owned
    /// elsewhere.
    ///
    /// The rejection sampler is exactly uniform on every non-exhausting run, so
    /// its only cost is the exhaustion probability, which the correctness and
    /// honest-failure ledger already sums per modulus.
    ExactGivenHonestAbort {
        abort_event: MaskGeneratorHonestAbortEvent,
    },
}

/// A named computational assumption a hop depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaskGeneratorHybridAssumption {
    /// KMAC256 is a pseudorandom function of its message under its key.
    Kmac256PseudorandomFunction,
    /// KMAC256 remains pseudorandom against superposition queries.
    ///
    /// This is strictly stronger than the classical assumption and is the one a
    /// QROM masking argument needs. No theorem proves it for fixed KMAC256.
    Kmac256QuantumPseudorandomFunction,
}

impl MaskGeneratorHybridAssumption {
    pub(crate) const fn identifier(self) -> &'static str {
        match self {
            Self::Kmac256PseudorandomFunction => "kmac256-pseudorandom-function",
            Self::Kmac256QuantumPseudorandomFunction => "kmac256-quantum-pseudorandom-function",
        }
    }
}

/// An honest-abort event whose probability is owned by another ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaskGeneratorHonestAbortEvent {
    /// One logical output exhausted its rejection-candidate draw ceiling.
    RejectionSamplerExhaustion,
}

impl MaskGeneratorHonestAbortEvent {
    pub(crate) const fn identifier(self) -> &'static str {
        match self {
            Self::RejectionSamplerExhaustion => "rejection-sampler-exhaustion",
        }
    }
}

/// One replacement step between the deployed generator and the ideal sampler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaskGeneratorHybridHop {
    /// The action root is fresh browser CSPRNG entropy of the pinned length.
    ///
    /// Nothing derives it from a lower-entropy source, so the only way past it
    /// is to guess it.
    ActionRootEntropy,
    /// Replace the action key hierarchy with a random function of its context.
    ///
    /// The hierarchy is the SP 800-108 KMAC key-derivation construction: one
    /// keyed call over the canonical derivation input, split into disjoint
    /// fixed-length segments. Replacing that one call replaces every derived
    /// segment at once.
    ActionKeyHierarchyReplacement,
    /// Replace each block derivation with a random function of its framed input.
    ///
    /// The stream key is one segment of the hierarchy output, so this hop is
    /// only meaningful after the hierarchy hop has already made that segment
    /// uniform.
    BlockStreamReplacement,
    /// Distinct sampling coordinates have distinct framed block inputs.
    ///
    /// Once the block derivation is a random function, two blocks are
    /// independent exactly when their inputs differ. The canonical block-input
    /// encoding is injective in the whole coordinate, so this costs nothing
    /// instead of a birthday term.
    FramedInputInjectivity,
    /// Replace rejection-sampled residues with uniform field elements.
    RejectionSamplerUniformity,
}

impl MaskGeneratorHybridHop {
    pub(crate) const fn identifier(self) -> &'static str {
        match self {
            Self::ActionRootEntropy => "action-root-entropy",
            Self::ActionKeyHierarchyReplacement => "action-key-hierarchy-replacement",
            Self::BlockStreamReplacement => "block-stream-replacement",
            Self::FramedInputInjectivity => "framed-input-injectivity",
            Self::RejectionSamplerUniformity => "rejection-sampler-uniformity",
        }
    }
}

/// The ordered hop ledger through one raw private block stream.
///
/// The order is the deployment order: entropy, then key hierarchy, then block
/// stream, then input distinctness. A construction that consumes raw bytes
/// adds its own downstream expansion argument; a direct modular sampler adds
/// the rejection-sampler hop below.
pub(crate) fn deployed_private_stream_hybrid()
-> [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 4] {
    [
        (
            MaskGeneratorHybridHop::ActionRootEntropy,
            MaskGeneratorHybridLoss::SecretGuessing {
                secret_bit_length: byte_length_in_bits(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH),
                query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            },
        ),
        (
            MaskGeneratorHybridHop::ActionKeyHierarchyReplacement,
            MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                key_bit_length: byte_length_in_bits(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH),
                classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            },
        ),
        (
            MaskGeneratorHybridHop::BlockStreamReplacement,
            MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                key_bit_length: byte_length_in_bits(PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH),
                classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            },
        ),
        (
            MaskGeneratorHybridHop::FramedInputInjectivity,
            MaskGeneratorHybridLoss::Exact,
        ),
    ]
}

/// The private-stream ledger in the quantum-query model.
///
/// The root-entropy hop uses quantum search rather than classical guessing,
/// and both KMAC hops require quantum pseudorandomness. Framed-input
/// injectivity remains exact.
pub(crate) fn quantum_private_stream_hybrid()
-> [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 4] {
    let mut ledger = deployed_private_stream_hybrid();
    ledger[0].1 = MaskGeneratorHybridLoss::QuantumSecretSearch {
        secret_bit_length: byte_length_in_bits(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH),
        query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
    };
    for (_, loss) in &mut ledger {
        if let MaskGeneratorHybridLoss::ComputationalReduction {
            assumption,
            key_bit_length,
            classical_query_budget,
        } = *loss
        {
            debug_assert_eq!(
                assumption,
                MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction
            );
            *loss = MaskGeneratorHybridLoss::ComputationalReduction {
                assumption: MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                key_bit_length,
                classical_query_budget,
            };
        }
    }
    ledger
}

/// The ordered hop ledger for direct modular samples.
pub(crate) fn deployed_mask_generator_hybrid()
-> [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 5] {
    let private_stream = deployed_private_stream_hybrid();
    [
        private_stream[0],
        private_stream[1],
        private_stream[2],
        private_stream[3],
        (
            MaskGeneratorHybridHop::RejectionSamplerUniformity,
            MaskGeneratorHybridLoss::ExactGivenHonestAbort {
                abort_event: MaskGeneratorHonestAbortEvent::RejectionSamplerExhaustion,
            },
        ),
    ]
}

/// The direct modular-sample ledger in the quantum-query model.
pub(crate) fn quantum_mask_generator_hybrid()
-> [(MaskGeneratorHybridHop, MaskGeneratorHybridLoss); 5] {
    let private_stream = quantum_private_stream_hybrid();
    [
        private_stream[0],
        private_stream[1],
        private_stream[2],
        private_stream[3],
        (
            MaskGeneratorHybridHop::RejectionSamplerUniformity,
            MaskGeneratorHybridLoss::ExactGivenHonestAbort {
                abort_event: MaskGeneratorHonestAbortEvent::RejectionSamplerExhaustion,
            },
        ),
    ]
}

const fn byte_length_in_bits(byte_length: usize) -> u32 {
    (byte_length * 8) as u32
}

/// Bytes the deployed generator expands from one action root, for the record.
///
/// Recording it keeps the ledger honest about scale: one 64-byte root keys the
/// whole action, and every later block is a deterministic function of it.
pub(crate) const fn action_root_expansion_summary() -> (usize, usize, usize) {
    (
        ACTION_RANDOMNESS_ROOT_BYTE_LENGTH,
        ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH,
        PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use zeroize::Zeroizing;

    use super::super::material::ActionRandomnessRoot;
    use super::*;
    use crate::foundation::ParticipantIdentity;

    fn derivation_input() -> ActionRandomnessDerivationInput {
        ActionRandomnessDerivationInput::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
        )
    }

    fn attempt_identifier() -> PrivateRandomnessAttemptIdentifier {
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(derivation_input())
        .expect("the fixed action root derives")
        .setup_attempt_identifier()
    }

    /// The ledger names every replacement step, in deployment order.
    ///
    /// A masking argument that skips a hop is assuming something the deployed
    /// generator does not provide, so the order and the loss class of each hop
    /// are the load-bearing content.
    #[test]
    fn deployed_hybrid_names_every_replacement_hop_with_its_loss_class() {
        let ledger = deployed_mask_generator_hybrid();
        assert_eq!(
            ledger.map(|(hop, _)| hop),
            [
                MaskGeneratorHybridHop::ActionRootEntropy,
                MaskGeneratorHybridHop::ActionKeyHierarchyReplacement,
                MaskGeneratorHybridHop::BlockStreamReplacement,
                MaskGeneratorHybridHop::FramedInputInjectivity,
                MaskGeneratorHybridHop::RejectionSamplerUniformity,
            ],
        );

        // The root is 512 bits, so guessing it at the declared budget costs far
        // more than the 2^-262 the selected construction targets.
        let MaskGeneratorHybridLoss::SecretGuessing {
            secret_bit_length,
            query_budget,
        } = ledger[0].1
        else {
            panic!("the entropy hop is a guessing term");
        };
        assert_eq!(secret_bit_length, 512);
        assert_eq!(query_budget, DECLARED_ADVERSARIAL_QUERY_BUDGET);
        assert!(u128::from(secret_bit_length) > 80 + 262);

        // Both PRF hops are computational, at the production key lengths.
        assert_eq!(
            [ledger[1].1, ledger[2].1],
            [
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                },
                MaskGeneratorHybridLoss::ComputationalReduction {
                    assumption: MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction,
                    key_bit_length: 512,
                    classical_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                },
            ],
        );

        // The sampler hop defers to the honest-failure ledger rather than
        // inventing an invalid-acceptance term for an abort.
        assert_eq!(
            ledger[4].1,
            MaskGeneratorHybridLoss::ExactGivenHonestAbort {
                abort_event: MaskGeneratorHonestAbortEvent::RejectionSamplerExhaustion,
            },
        );

        // One 64-byte root keys 192 bytes of hierarchy output and every later
        // 64-byte block, so no downstream value is independent of it.
        assert_eq!(action_root_expansion_summary(), (64, 192, 64));

        // Stable identifiers, so a ledger row can name a hop without repeating
        // its definition.
        assert_eq!(
            ledger.map(|(hop, _)| hop.identifier()),
            [
                "action-root-entropy",
                "action-key-hierarchy-replacement",
                "block-stream-replacement",
                "framed-input-injectivity",
                "rejection-sampler-uniformity",
            ],
        );
        assert_eq!(
            MaskGeneratorHybridAssumption::Kmac256PseudorandomFunction.identifier(),
            "kmac256-pseudorandom-function",
        );
    }

    /// A quantum masking argument may not reuse classical guessing or PRF hops.
    #[test]
    fn quantum_hybrid_raises_every_query_model_dependent_hop() {
        let classical = deployed_mask_generator_hybrid();
        let quantum = quantum_mask_generator_hybrid();
        assert_eq!(classical.map(|(hop, _)| hop), quantum.map(|(hop, _)| hop));
        for (index, ((_, classical_loss), (_, quantum_loss))) in
            classical.iter().zip(&quantum).enumerate()
        {
            match classical_loss {
                MaskGeneratorHybridLoss::SecretGuessing { .. } => {
                    assert_eq!(
                        *quantum_loss,
                        MaskGeneratorHybridLoss::QuantumSecretSearch {
                            secret_bit_length: 512,
                            query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
                        },
                    );
                }
                MaskGeneratorHybridLoss::ComputationalReduction { .. } => {
                    assert_ne!(classical_loss, quantum_loss, "hop {index} did not change");
                    let MaskGeneratorHybridLoss::ComputationalReduction { assumption, .. } =
                        quantum_loss
                    else {
                        panic!("hop {index} must stay computational");
                    };
                    assert_eq!(
                        *assumption,
                        MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction,
                    );
                }
                _ => assert_eq!(classical_loss, quantum_loss, "hop {index} changed"),
            }
        }
        assert_eq!(
            deployed_private_stream_hybrid(),
            deployed_mask_generator_hybrid()[..4],
        );
        assert_eq!(
            quantum_private_stream_hybrid(),
            quantum_mask_generator_hybrid()[..4],
        );
        assert_eq!(
            MaskGeneratorHybridAssumption::Kmac256QuantumPseudorandomFunction.identifier(),
            "kmac256-quantum-pseudorandom-function",
        );
        assert_eq!(
            MaskGeneratorHonestAbortEvent::RejectionSamplerExhaustion.identifier(),
            "rejection-sampler-exhaustion",
        );
    }

    /// The framed-input hop costs nothing because the encoding is injective.
    ///
    /// This is the step that would otherwise need a birthday term. Varying each
    /// coordinate part independently, including parts that differ only in where
    /// a boundary falls, must always change the encoded bytes.
    #[test]
    fn distinct_sampling_coordinates_have_distinct_framed_block_inputs() {
        let derivation = derivation_input();
        let attempt = attempt_identifier();
        let encode = |domain: PrivateRandomnessDomain, context: Hash512, counter: u64| {
            PrivateRandomBlockInput::new(derivation, domain, context, attempt, counter)
                .expect("the varied sampling coordinate is well formed")
                .encode()
                .expect("a well-formed block input encodes canonically")
        };

        let mut encodings = BTreeSet::new();
        let mut coordinate_count = 0_usize;
        // Purpose three is unassigned for this family, so the sweep uses the
        // three purposes the domain table actually allocates.
        for purpose in [1_u16, 2, 4] {
            let domain =
                PrivateRandomnessDomain::setup_source(purpose).expect("assigned setup-source pair");
            for context_fill in [0x00_u8, 0x01, 0xfe, 0xff] {
                let context = Hash512::from_bytes([context_fill; Hash512::BYTE_LENGTH]);
                for counter in [0_u64, 1, 255, 256, u64::MAX - 1, u64::MAX] {
                    coordinate_count += 1;
                    assert!(
                        encodings.insert(encode(domain, context, counter)),
                        "purpose {purpose}, context {context_fill}, counter {counter} collided",
                    );
                }
            }
        }
        assert_eq!(encodings.len(), coordinate_count);
        assert_eq!(coordinate_count, 3 * 4 * 6);

        // Coordinates from different families are distinct too, which is what
        // keeps one family's mask stream independent of another's.
        let setup_source = encode(
            PrivateRandomnessDomain::setup_source(1).expect("assigned setup-source pair"),
            Hash512::from_bytes([0x7f; Hash512::BYTE_LENGTH]),
            9,
        );
        let vss_expansion = encode(
            PrivateRandomnessDomain::vss_expansion(1).expect("assigned VSS-expansion pair"),
            Hash512::from_bytes([0x7f; Hash512::BYTE_LENGTH]),
            9,
        );
        assert_ne!(setup_source, vss_expansion);

        // Every encoding has the same length, so distinctness comes from the
        // framed content rather than from a length difference.
        let single_length = setup_source.len();
        assert!(
            encodings
                .iter()
                .all(|encoding| encoding.len() == single_length)
        );
    }
}
