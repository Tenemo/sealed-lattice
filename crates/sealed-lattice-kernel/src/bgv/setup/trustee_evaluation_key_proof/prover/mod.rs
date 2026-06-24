use super::extension_field::ChallengeExtensionElement;
use super::low_degree_proof::LowDegreeProof;
use super::merkle_commitment::BatchedMerkleOpening;

mod challenges;
mod claim_masking;
mod polynomial;
mod prove;
mod salted_tree;
mod witness;

pub(super) use challenges::*;
pub(super) use claim_masking::*;
pub(super) use polynomial::*;
pub(crate) use prove::prove_evaluation_key_share;
#[cfg(test)]
pub(crate) use prove::prove_evaluation_key_share_with_test_limb_batch_size;

const COLUMN_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/column-mask-v2";
const LEAF_SALT_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/leaf-salt-v2";
const CLAIM_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/claim-mask-v2";

pub(crate) struct SuccinctEvaluationKeyProof {
    pub(super) limb_proofs: Vec<LimbProof>,
}

pub(super) struct LimbProof {
    pub(super) witness_tree_root: [u8; 64],
    pub(super) quotient_tree_root: [u8; 64],
    // Smudging-masked consistency claims in local claim order (consistency
    // vector major, repetition minor).
    pub(super) masked_consistency_claims: Vec<u64>,
    // Per out-of-domain point: every committed column evaluation in the
    // challenge extension, phase-one columns in layout order followed by the
    // four logical phase-two columns.
    pub(super) deep_evaluations: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) low_degree: LowDegreeProof,
    pub(super) sumcheck_residual_low_degree: LowDegreeProof,
    pub(super) query_openings: Vec<PhaseQueryOpening>,
    pub(super) sumcheck_residual_query_openings: Vec<PhaseTwoQueryOpening>,
    // One batched authentication opening per phase tree, covering every queried
    // position and its coset partner at once instead of an independent path per
    // query slot.
    pub(super) witness_batch_opening: BatchedMerkleOpening,
    pub(super) quotient_batch_opening: BatchedMerkleOpening,
    pub(super) sumcheck_residual_batch_opening: BatchedMerkleOpening,
}

// Openings of both phase trees at the queried extension pair positions,
// including the leaf salts. The authentication nodes live in the per-tree
// batched openings on `LimbProof`, not here.
pub(super) struct PhaseQueryOpening {
    pub(super) phase_one_rows: [Vec<u64>; 2],
    pub(super) phase_one_salts: [Vec<u8>; 2],
    pub(super) phase_two_rows: [Vec<u64>; 2],
    pub(super) phase_two_salts: [Vec<u8>; 2],
}

// Openings of the phase-two tree at the residual low-degree query positions.
// The residual FRI instance authenticates only the fourth logical phase-two
// column, but the Merkle leaf still binds the whole phase-two row.
pub(super) struct PhaseTwoQueryOpening {
    pub(super) phase_two_rows: [Vec<u64>; 2],
    pub(super) phase_two_salts: [Vec<u8>; 2],
}
