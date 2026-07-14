use super::extension_field::ChallengeExtensionElement;
use super::low_degree_proof::LowDegreeProof;
use super::merkle_commitment::{BatchedMerkleOpening, MerkleDigest};

mod challenges;
mod claim_masking;
mod polynomial;
mod prove;
mod salted_tree;
mod vss_committed_material;
mod witness;

pub(super) use challenges::*;
pub(super) use claim_masking::*;
pub(super) use polynomial::*;
pub(crate) use prove::prove_evaluation_key_share;
#[cfg(test)]
pub(crate) use prove::prove_evaluation_key_share_with_test_limb_batch_size;
pub(crate) use vss_committed_material::{
    VSS_COMMITTED_MATERIAL_COLUMN_MASK_DEGREE_CAP, VssCommittedMaterialTreeInput,
    vss_committed_material_roots_by_commitment_field,
};

const COLUMN_MASK_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/column-mask";
const LEAF_SALT_DOMAIN: &str = "sealed-lattice/setup/trustee-evaluation-key/leaf-salt";
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
    // logical phase-two columns, then the bound committed-material columns
    // (bound-message-major, digit-major, half-minor).
    pub(super) deep_evaluations: Vec<Vec<ChallengeExtensionElement>>,
    pub(super) low_degree: LowDegreeProof,
    pub(super) sumcheck_residual_low_degree: LowDegreeProof,
    pub(super) query_openings: Vec<PhaseQueryOpening>,
    // One batched authentication opening per phase tree. The phase-two opening
    // authenticates the shared positions used by the main and residual
    // low-degree openings.
    pub(super) witness_batch_opening: BatchedMerkleOpening,
    pub(super) quotient_batch_opening: BatchedMerkleOpening,
    // Committed-material openings: per bound tree, per query ordinal, the
    // opened pair rows and pair salt, plus one batched authentication opening
    // per tree. The verifier authenticates these against the STATEMENT's
    // material roots for this limb's commitment field, never against a
    // proof-supplied root.
    pub(super) material_query_openings: Vec<Vec<MaterialTreeQueryOpening>>,
    pub(super) material_batch_openings: Vec<BatchedMerkleOpening>,
}

// One bound material tree's opened pair at one query ordinal: the ordered
// row pair across that tree's physical columns plus the pair salt, in the
// exact shape the phase trees use.
pub(super) struct MaterialTreeQueryOpening {
    pub(super) rows: [Vec<u64>; 2],
    pub(super) pair_salt: Vec<u8>,
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
