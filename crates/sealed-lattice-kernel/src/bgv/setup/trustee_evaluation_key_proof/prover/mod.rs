use super::extension_field::ChallengeExtensionElement;
use super::low_degree_proof::LowDegreeProof;
use super::merkle_commitment::{BatchedMerkleOpening, MerkleDigest};

mod challenges;
mod claim_masking;
mod polynomial;
#[cfg(test)]
mod prove;
#[cfg(test)]
mod salted_tree;
#[cfg(test)]
mod witness;

pub(super) use challenges::*;
pub(super) use claim_masking::*;
pub(super) use polynomial::*;
#[cfg(test)]
pub(crate) use prove::prove_evaluation_key_share;

#[cfg(test)]
const COLUMN_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/column-mask";
#[cfg(test)]
const LEAF_SALT_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/leaf-salt";
#[cfg(test)]
const CLAIM_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/claim-mask";

pub(crate) struct SuccinctEvaluationKeyProof {
    pub(super) limb_proofs: Vec<LimbProof>,
}

pub(super) struct LimbProof {
    pub(super) witness_tree_root: MerkleDigest,
    pub(super) quotient_tree_root: MerkleDigest,
    // Smudging-masked consistency claims in local claim order (consistency
    // vector major, repetition minor).
    pub(super) masked_consistency_claims: Vec<u64>,
    // Per out-of-domain point: every committed column evaluation in the
    // challenge extension, phase-one columns in layout order, the four
    // logical phase-two columns.
    pub(super) deep_evaluations: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) low_degree: LowDegreeProof,
    pub(super) sumcheck_residual_low_degree: LowDegreeProof,
    pub(super) query_openings: Vec<PhaseQueryOpening>,
    // One batched authentication opening per phase tree. The phase-two opening
    // authenticates the shared positions used by the main and residual
    // low-degree openings.
    pub(super) witness_batch_opening: BatchedMerkleOpening,
    pub(super) quotient_batch_opening: BatchedMerkleOpening,
}

// Openings of both phase trees at the queried extension pair positions. Each
// phase tree leaf binds the ordered row pair with one salt; authentication
// nodes live in the per-tree batched openings on `LimbProof`, not here.
pub(super) struct PhaseQueryOpening {
    pub(super) phase_one_rows: [Vec<u64>; 2],
    pub(super) phase_one_pair_salt: Vec<u8>,
    pub(super) phase_two_rows: [Vec<u64>; 2],
    pub(super) phase_two_pair_salt: Vec<u8>,
}
