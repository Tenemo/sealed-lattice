//! Bounded-memory private Merkle salts for aggregate-wide commitments.
//!
//! Production aggregate commitments contain one matrix. Secret-bearing
//! commitments append a virtual seven-element suffix to each row. The suffix
//! is derived on demand from an attempt-private key and injectively encodes a
//! 1,024-bit salt; it is never materialized as a resident salt matrix. The
//! leaf hasher removes the suffix and absorbs the original salt bytes in its
//! initial 512-bit frame, so salting adds neither retained oracle columns nor
//! transition hashes. Openings transport the raw salt once beside the opened
//! row and retain the ordinary compact Merkle frontier.

use std::sync::{Arc, Mutex};

use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::{Dimensions, Matrix, dense::RowMajorMatrix, stack::HorizontalPair};
use p3_merkle_tree::{MerkleTreeError, MerkleTreeMmcs};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::private_leaf_salt::{
    PRIVATE_LEAF_SALT_BYTE_LENGTH, PrivateLeafSalt, derive_private_leaf_salt,
};
use super::{
    ChallengeField, LeafHasher, MERKLE_DIGEST_WORD_LENGTH, PlainCommitmentScheme,
    aggregate_leaf_hasher, aggregate_node_compressor,
};
use crate::bgv::proof_suite::relation_plan::ProofPrivacyMode;

pub(super) const AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT: usize = 7;
pub(super) const AGGREGATE_PRIVATE_LEAF_SALT_KEY_EXTENSION_ELEMENT_COUNT: usize = 2;
const PRIVATE_LEAF_SALT_U32_COORDINATE_COUNT: usize = PRIVATE_LEAF_SALT_BYTE_LENGTH / 4;
const PRIVATE_LEAF_SALT_PADDING_COORDINATES: [u64; 3] = [
    0x7365_616c_6564_0001,
    0x6c61_7474_6963_6501,
    0x7361_6c74_7631_0001,
];
pub(super) const MATERIALIZED_COMMITMENT_ROLES: [AggregateLeafSaltRole; 3] = [
    AggregateLeafSaltRole::AggregateWidePad,
    AggregateLeafSaltRole::FreshSource,
    AggregateLeafSaltRole::FreshPad,
];
const BTREE_ENTRY_LINK_WORD_COUNT: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AggregateLeafSaltRole {
    InitialSource,
    FoldedSource { epoch_ordinal: usize },
    AggregateWidePad,
    FreshSource,
    FreshPad,
}

impl AggregateLeafSaltRole {
    pub(super) const fn domain(self) -> &'static [u8] {
        match self {
            Self::InitialSource => b"aggregate-source/initial",
            Self::FoldedSource { .. } => b"aggregate-source/folded",
            Self::AggregateWidePad => b"aggregate-mask/carried-pad",
            Self::FreshSource => b"aggregate-mask/fresh-source",
            Self::FreshPad => b"aggregate-mask/fresh-pad",
        }
    }

    pub(super) const fn derivation_ordinal(self) -> usize {
        match self {
            Self::FoldedSource { epoch_ordinal } => epoch_ordinal,
            Self::InitialSource | Self::AggregateWidePad | Self::FreshSource | Self::FreshPad => 0,
        }
    }
}

struct AggregatePrivateLeafSaltKeyMaterial {
    bytes: Zeroizing<[u8; 80]>,
}

/// Attempt-private aggregate salt key sampled independently of every mask.
#[derive(Clone)]
pub(super) struct AggregatePrivateLeafSaltKey {
    material: Arc<AggregatePrivateLeafSaltKeyMaterial>,
}

impl AggregatePrivateLeafSaltKey {
    pub(super) fn from_extension_elements(
        elements: [ChallengeField; AGGREGATE_PRIVATE_LEAF_SALT_KEY_EXTENSION_ELEMENT_COUNT],
    ) -> Self {
        let mut bytes = [0_u8; 80];
        let mut offset = 0_usize;
        for element in elements {
            for coordinate in
                <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                    &element,
                )
            {
                bytes[offset..offset + 8]
                    .copy_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
                offset += 8;
            }
        }
        debug_assert_eq!(offset, bytes.len());
        Self {
            material: Arc::new(AggregatePrivateLeafSaltKeyMaterial {
                bytes: Zeroizing::new(bytes),
            }),
        }
    }

    pub(super) fn derive(
        &self,
        role: AggregateLeafSaltRole,
        leaf_count: usize,
        logical_leaf_width: usize,
        matrix_ordinal: usize,
        leaf_index: usize,
    ) -> Result<PrivateLeafSalt, String> {
        let combined_ordinal = role
            .derivation_ordinal()
            .checked_mul(2)
            .and_then(|ordinal| ordinal.checked_add(matrix_ordinal))
            .ok_or_else(|| "aggregate private leaf-salt ordinal overflowed".to_owned())?;
        derive_private_leaf_salt(
            self.material.bytes.as_slice(),
            role.domain(),
            leaf_count,
            logical_leaf_width,
            combined_ordinal,
            leaf_index,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct TransportedPrivateLeafSalt {
    chunks: [[u8; 32]; 4],
}

impl TransportedPrivateLeafSalt {
    pub(super) fn from_bytes(bytes: PrivateLeafSalt) -> Self {
        Self {
            chunks: core::array::from_fn(|chunk_ordinal| {
                bytes[chunk_ordinal * 32..(chunk_ordinal + 1) * 32]
                    .try_into()
                    .expect("private leaf-salt chunk has 32 bytes")
            }),
        }
    }

    pub(super) fn bytes(&self) -> PrivateLeafSalt {
        let mut bytes = [0_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];
        for (chunk_ordinal, chunk) in self.chunks.iter().enumerate() {
            bytes[chunk_ordinal * 32..(chunk_ordinal + 1) * 32].copy_from_slice(chunk);
        }
        bytes
    }

    pub(super) fn zeroize(&mut self) {
        for chunk in &mut self.chunks {
            chunk.fill(0);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct CoordinateDerivedLeafSaltProof {
    pub(super) private_leaf_salts: Vec<TransportedPrivateLeafSalt>,
    pub(super) siblings: Vec<[u64; MERKLE_DIGEST_WORD_LENGTH]>,
}

#[derive(Clone)]
struct AggregateLeafSaltDerivationContext {
    key: AggregatePrivateLeafSaltKey,
    role: AggregateLeafSaltRole,
    leaf_count: usize,
    logical_leaf_width: usize,
    matrix_ordinal: usize,
}

impl AggregateLeafSaltDerivationContext {
    fn derive(&self, leaf_index: usize) -> PrivateLeafSalt {
        self.key
            .derive(
                self.role,
                self.leaf_count,
                self.logical_leaf_width,
                self.matrix_ordinal,
                leaf_index,
            )
            .expect("validated aggregate private leaf-salt geometry derives")
    }
}

struct MaterializedCommitmentScheduleState {
    key: AggregatePrivateLeafSaltKey,
    next_role_ordinal: usize,
}

/// Additional resident allocation owned by the private aggregate salt adapter.
/// The 80 key bytes are already charged as private material. This bound adds
/// their Arc header and the one shared schedule allocation. Coordinate contexts
/// retained by materialized trees are charged in those trees' dynamic payloads;
/// other handles are inline in the generation-engine control structure.
pub(super) fn aggregate_private_leaf_salt_resident_state_byte_length() -> Result<usize, String> {
    let arc_header_byte_length = 2_usize
        .checked_mul(core::mem::size_of::<usize>())
        .ok_or_else(|| "aggregate private leaf-salt Arc header overflowed".to_owned())?;
    let schedule_allocation_byte_length = arc_header_byte_length
        .checked_add(core::mem::size_of::<
            Mutex<MaterializedCommitmentScheduleState>,
        >())
        .ok_or_else(|| "aggregate private leaf-salt schedule allocation overflowed".to_owned())?;
    arc_header_byte_length
        .checked_add(schedule_allocation_byte_length)
        .ok_or_else(|| "aggregate private leaf-salt resident state overflowed".to_owned())
}

/// Peak temporary row allocation while the MMCS injectively converts one raw
/// salt into its seven extension-field suffix elements.
pub(super) const fn aggregate_private_leaf_salt_row_workspace_byte_length() -> usize {
    2 * core::mem::size_of::<[ChallengeField; AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT]>(
    ) + core::mem::size_of::<Vec<ChallengeField>>()
}

/// Conservative B-tree allocation for canonical duplicate-salt refusal.
pub(super) fn transported_private_leaf_salt_uniqueness_set_byte_length(
    entry_count: usize,
) -> Result<usize, String> {
    let entry_byte_length = core::mem::size_of::<TransportedPrivateLeafSalt>()
        .checked_add(
            BTREE_ENTRY_LINK_WORD_COUNT
                .checked_mul(core::mem::size_of::<usize>())
                .ok_or_else(|| "private leaf-salt B-tree link size overflowed".to_owned())?,
        )
        .ok_or_else(|| "private leaf-salt B-tree entry size overflowed".to_owned())?;
    entry_count
        .checked_mul(entry_byte_length)
        .and_then(|payload| {
            payload.checked_add(core::mem::size_of::<
                std::collections::BTreeSet<TransportedPrivateLeafSalt>,
            >())
        })
        .ok_or_else(|| "private leaf-salt uniqueness set size overflowed".to_owned())
}

/// Exact dynamic payload retained by one single-column materialized aggregate
/// commitment. The containing Rust structs are part of the generation-engine
/// control allocation; this function accounts for every backing allocation:
/// the matrix, salted-matrix catalog, digest-layer catalog and payloads, and
/// arity schedule.
pub(super) fn materialized_single_column_commitment_payload_byte_length(
    leaf_count: usize,
) -> Result<usize, String> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err("materialized aggregate commitment leaf count is invalid".to_owned());
    }
    type MaterializedMatrix = SaltedMatrix<RowMajorMatrix<ChallengeField>>;
    let digest_count = leaf_count
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or_else(|| "materialized aggregate digest count overflowed".to_owned())?;
    let layer_count = usize::try_from(leaf_count.ilog2())
        .map_err(|_| "materialized aggregate layer count exceeds usize".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "materialized aggregate layer count overflowed".to_owned())?;
    leaf_count
        .checked_mul(core::mem::size_of::<ChallengeField>())
        .and_then(|total| total.checked_add(core::mem::size_of::<MaterializedMatrix>()))
        .and_then(|total| {
            layer_count
                .checked_mul(core::mem::size_of::<Vec<[u64; MERKLE_DIGEST_WORD_LENGTH]>>())
                .and_then(|catalog| total.checked_add(catalog))
        })
        .and_then(|total| {
            digest_count
                .checked_mul(core::mem::size_of::<[u64; MERKLE_DIGEST_WORD_LENGTH]>())
                .and_then(|digests| total.checked_add(digests))
        })
        .and_then(|total| {
            layer_count
                .checked_sub(1)
                .and_then(|arity_count| arity_count.checked_mul(core::mem::size_of::<usize>()))
                .and_then(|arity| total.checked_add(arity))
        })
        .ok_or_else(|| "materialized aggregate commitment payload overflowed".to_owned())
}

/// Shared handle that binds cloned P3 adapters to one fixed commit chronology.
#[derive(Clone)]
pub(super) struct MaterializedCommitmentSchedule {
    state: Arc<Mutex<MaterializedCommitmentScheduleState>>,
}

impl MaterializedCommitmentSchedule {
    pub(super) fn new(key: AggregatePrivateLeafSaltKey) -> Self {
        Self {
            state: Arc::new(Mutex::new(MaterializedCommitmentScheduleState {
                key,
                next_role_ordinal: 0,
            })),
        }
    }

    fn next_context(
        &self,
        leaf_count: usize,
        logical_leaf_width: usize,
        matrix_ordinal: usize,
    ) -> AggregateLeafSaltDerivationContext {
        let mut state = self
            .state
            .lock()
            .expect("aggregate materialized-commitment schedule mutex is not poisoned");
        let role = *MATERIALIZED_COMMITMENT_ROLES
            .get(state.next_role_ordinal)
            .expect("aggregate materialized commitment exceeded its fixed chronology");
        state.next_role_ordinal += 1;
        AggregateLeafSaltDerivationContext {
            key: state.key.clone(),
            role,
            leaf_count,
            logical_leaf_width,
            matrix_ordinal,
        }
    }

    pub(super) fn ensure_complete(&self) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "aggregate materialized-commitment schedule mutex is poisoned")?;
        if state.next_role_ordinal != MATERIALIZED_COMMITMENT_ROLES.len() {
            return Err(format!(
                "aggregate materialized-commitment chronology consumed {} of {} roles",
                state.next_role_ordinal,
                MATERIALIZED_COMMITMENT_ROLES.len()
            ));
        }
        Ok(())
    }
}

pub(super) struct CoordinateDerivedSaltMatrix {
    height: usize,
    context: Option<AggregateLeafSaltDerivationContext>,
}

impl Matrix<ChallengeField> for CoordinateDerivedSaltMatrix {
    fn width(&self) -> usize {
        if self.context.is_some() {
            AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT
        } else {
            0
        }
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_unchecked(
        &self,
        row_index: usize,
    ) -> impl IntoIterator<
        Item = ChallengeField,
        IntoIter = impl Iterator<Item = ChallengeField> + Send + Sync,
    > {
        self.context
            .as_ref()
            .map(|context| encode_private_leaf_salt(&context.derive(row_index)).to_vec())
            .unwrap_or_default()
    }
}

type SaltedMatrix<M> = HorizontalPair<M, CoordinateDerivedSaltMatrix>;

/// MMCS wrapper with lazy coordinate-derived salts and raw-salt proofs.
#[derive(Clone)]
pub(super) struct CoordinateDerivedHidingMmcs {
    inner: PlainCommitmentScheme,
    privacy_mode: ProofPrivacyMode,
    materialized_schedule: Option<MaterializedCommitmentSchedule>,
}

impl core::fmt::Debug for CoordinateDerivedHidingMmcs {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CoordinateDerivedHidingMmcs")
            .field("privacy_mode", &self.privacy_mode)
            .field(
                "has_materialized_schedule",
                &self.materialized_schedule.is_some(),
            )
            .finish()
    }
}

impl CoordinateDerivedHidingMmcs {
    pub(super) fn verifier(privacy_mode: ProofPrivacyMode) -> Self {
        Self::new(privacy_mode, None)
    }

    pub(super) fn prover(
        privacy_mode: ProofPrivacyMode,
        materialized_schedule: MaterializedCommitmentSchedule,
    ) -> Self {
        Self::new(privacy_mode, Some(materialized_schedule))
    }

    fn new(
        privacy_mode: ProofPrivacyMode,
        materialized_schedule: Option<MaterializedCommitmentSchedule>,
    ) -> Self {
        let leaf_hasher: LeafHasher = aggregate_leaf_hasher(privacy_mode);
        let inner = MerkleTreeMmcs::new(leaf_hasher, aggregate_node_compressor(), 0);
        Self {
            inner,
            privacy_mode,
            materialized_schedule,
        }
    }
}

impl Mmcs<ChallengeField> for CoordinateDerivedHidingMmcs {
    type ProverData<M> =
        <PlainCommitmentScheme as Mmcs<ChallengeField>>::ProverData<SaltedMatrix<M>>;
    type Commitment = <PlainCommitmentScheme as Mmcs<ChallengeField>>::Commitment;
    type Proof = CoordinateDerivedLeafSaltProof;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<ChallengeField>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        assert_eq!(
            inputs.len(),
            1,
            "aggregate commitment requires exactly one production matrix"
        );
        let salted_inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(matrix_ordinal, matrix)| {
                let height = matrix.height();
                let logical_leaf_width = matrix.width();
                let context = match self.privacy_mode {
                    ProofPrivacyMode::PublicOnly => None,
                    ProofPrivacyMode::SecretBearing => Some(
                        self.materialized_schedule
                            .as_ref()
                            .expect(
                                "secret-bearing aggregate commitment has no private salt schedule",
                            )
                            .next_context(height, logical_leaf_width, matrix_ordinal),
                    ),
                };
                HorizontalPair::new::<ChallengeField>(
                    matrix,
                    CoordinateDerivedSaltMatrix { height, context },
                )
            })
            .collect();
        self.inner.commit(salted_inputs)
    }

    fn open_batch<M: Matrix<ChallengeField>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<ChallengeField, Self> {
        let (salted_openings, siblings) = self.inner.open_batch(index, prover_data).unpack();
        let salt_element_count = if self.privacy_mode == ProofPrivacyMode::SecretBearing {
            AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT
        } else {
            0
        };
        let (openings, private_leaf_salts): (Vec<_>, Vec<_>) = salted_openings
            .into_iter()
            .map(|row| {
                let split_index = row
                    .len()
                    .checked_sub(salt_element_count)
                    .expect("aggregate opening contains its private salt suffix");
                let (values, encoded_salt) = row.split_at(split_index);
                let transported_salt = if encoded_salt.is_empty() {
                    None
                } else {
                    Some(TransportedPrivateLeafSalt::from_bytes(
                        decode_private_leaf_salt(encoded_salt)
                            .expect("committed aggregate private salt is canonical"),
                    ))
                };
                (values.to_vec(), transported_salt)
            })
            .unzip();
        BatchOpening::new(
            openings,
            CoordinateDerivedLeafSaltProof {
                private_leaf_salts: private_leaf_salts.into_iter().flatten().collect(),
                siblings,
            },
        )
    }

    fn get_matrices<'a, M: Matrix<ChallengeField>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        self.inner
            .get_matrices(prover_data)
            .into_iter()
            .map(|matrix| &matrix.left)
            .collect()
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, ChallengeField, Self>,
    ) -> Result<(), Self::Error> {
        let (opened_values, proof) = batch_opening.unpack();
        if dimensions.len() != 1 || opened_values.len() != dimensions.len() {
            return Err(MerkleTreeError::WrongBatchSize);
        }
        for (matrix_ordinal, (dimension, values)) in
            dimensions.iter().zip(opened_values).enumerate()
        {
            if dimension.width != values.len() {
                return Err(MerkleTreeError::WrongWidth {
                    matrix: matrix_ordinal,
                    expected: dimension.width,
                    got: values.len(),
                });
            }
        }
        let expected_salt_count =
            usize::from(self.privacy_mode == ProofPrivacyMode::SecretBearing) * dimensions.len();
        if proof.private_leaf_salts.len() != expected_salt_count {
            return Err(MerkleTreeError::WrongBatchSize);
        }
        let salted_openings = opened_values
            .iter()
            .enumerate()
            .map(|(matrix_ordinal, values)| {
                let mut salted = values.to_vec();
                if let Some(transported_salt) = proof.private_leaf_salts.get(matrix_ordinal) {
                    salted.extend(encode_private_leaf_salt(&transported_salt.bytes()));
                }
                salted
            })
            .collect::<Vec<_>>();
        let salted_dimensions = dimensions
            .iter()
            .map(|dimension| Dimensions {
                width: dimension.width
                    + if self.privacy_mode == ProofPrivacyMode::SecretBearing {
                        AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT
                    } else {
                        0
                    },
                height: dimension.height,
            })
            .collect::<Vec<_>>();
        self.inner.verify_batch(
            commitment,
            &salted_dimensions,
            index,
            BatchOpeningRef::new(&salted_openings, &proof.siblings),
        )
    }
}

pub(super) fn encode_private_leaf_salt(
    salt: &PrivateLeafSalt,
) -> [ChallengeField; AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT] {
    let mut coordinates = [0_u64; 35];
    for (coordinate, chunk) in coordinates[..PRIVATE_LEAF_SALT_U32_COORDINATE_COUNT]
        .iter_mut()
        .zip(salt.chunks_exact(4))
    {
        *coordinate = u64::from(u32::from_le_bytes(
            chunk
                .try_into()
                .expect("private salt coordinate has four bytes"),
        ));
    }
    coordinates[PRIVATE_LEAF_SALT_U32_COORDINATE_COUNT..]
        .copy_from_slice(&PRIVATE_LEAF_SALT_PADDING_COORDINATES);
    core::array::from_fn(|element_ordinal| {
        ChallengeField::new(core::array::from_fn(|coordinate_ordinal| {
            Goldilocks::from_u64(coordinates[element_ordinal * 5 + coordinate_ordinal])
        }))
    })
}

pub(super) fn decode_private_leaf_salt(
    encoded: &[ChallengeField],
) -> Result<PrivateLeafSalt, String> {
    if encoded.len() != AGGREGATE_PRIVATE_LEAF_SALT_EXTENSION_ELEMENT_COUNT {
        return Err("aggregate private leaf salt has the wrong encoded width".to_owned());
    }
    let coordinates = encoded
        .iter()
        .flat_map(|element| {
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(element)
                .iter()
                .map(PrimeField64::as_canonical_u64)
        })
        .collect::<Vec<_>>();
    if coordinates.len() != 35
        || coordinates[..PRIVATE_LEAF_SALT_U32_COORDINATE_COUNT]
            .iter()
            .any(|coordinate| *coordinate > u64::from(u32::MAX))
        || coordinates[PRIVATE_LEAF_SALT_U32_COORDINATE_COUNT..]
            != PRIVATE_LEAF_SALT_PADDING_COORDINATES
    {
        return Err("aggregate private leaf salt is not injectively encoded".to_owned());
    }
    let mut salt = [0_u8; PRIVATE_LEAF_SALT_BYTE_LENGTH];
    for (coordinate_ordinal, coordinate) in coordinates
        .into_iter()
        .take(PRIVATE_LEAF_SALT_U32_COORDINATE_COUNT)
        .enumerate()
    {
        salt[coordinate_ordinal * 4..(coordinate_ordinal + 1) * 4]
            .copy_from_slice(&(coordinate as u32).to_le_bytes());
    }
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use p3_commit::Mmcs;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::{Matrix, dense::RowMajorMatrix};

    use super::*;

    fn sample_key(marker: u64) -> AggregatePrivateLeafSaltKey {
        AggregatePrivateLeafSaltKey::from_extension_elements([
            ChallengeField::from_u64(marker),
            ChallengeField::from_u64(marker + 1),
        ])
    }

    #[test]
    fn private_leaf_salt_field_encoding_is_injective_and_canonical() {
        let salt = core::array::from_fn(|index| (index * 17 + 3) as u8);
        let encoded = encode_private_leaf_salt(&salt);
        assert_eq!(decode_private_leaf_salt(&encoded), Ok(salt));

        let mut changed_padding = encoded;
        let mut coordinates: [Goldilocks; 5] =
            <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                &changed_padding[6],
            )
            .try_into()
            .expect("challenge extension has five base-field coordinates");
        coordinates[4] += Goldilocks::ONE;
        changed_padding[6] = ChallengeField::new(coordinates);
        assert!(decode_private_leaf_salt(&changed_padding).is_err());
    }

    #[test]
    fn lazy_private_salt_mmcs_roundtrips_and_refuses_wrong_missing_or_reused_salts() {
        let key = sample_key(17);
        let schedule = MaterializedCommitmentSchedule::new(key);
        let prover =
            CoordinateDerivedHidingMmcs::prover(ProofPrivacyMode::SecretBearing, schedule.clone());
        let verifier = CoordinateDerivedHidingMmcs::verifier(ProofPrivacyMode::SecretBearing);
        let matrix = RowMajorMatrix::new(
            (0..64)
                .map(|index| ChallengeField::from_u64(index as u64 + 9))
                .collect(),
            4,
        );
        let dimensions = [matrix.dimensions()];
        let (commitment, prover_data) = prover.commit_matrix(matrix);
        let opening = prover.open_batch(7, &prover_data);
        verifier
            .verify_batch(&commitment, &dimensions, 7, (&opening).into())
            .expect("genuine privately salted opening verifies");

        let (values, proof) = opening.unpack();
        let mut missing = proof.clone();
        missing.private_leaf_salts.clear();
        assert!(
            verifier
                .verify_batch(
                    &commitment,
                    &dimensions,
                    7,
                    BatchOpeningRef::new(&values, &missing),
                )
                .is_err()
        );

        let mut changed = proof.clone();
        changed.private_leaf_salts[0].chunks[0][0] ^= 1;
        assert!(
            verifier
                .verify_batch(
                    &commitment,
                    &dimensions,
                    7,
                    BatchOpeningRef::new(&values, &changed),
                )
                .is_err()
        );

        let other_opening = prover.open_batch(8, &prover_data);
        let (_, other_proof) = other_opening.unpack();
        let mut reused = proof;
        reused.private_leaf_salts = other_proof.private_leaf_salts;
        assert!(
            verifier
                .verify_batch(
                    &commitment,
                    &dimensions,
                    7,
                    BatchOpeningRef::new(&values, &reused),
                )
                .is_err()
        );
    }

    #[test]
    fn private_salt_adapter_resident_bounds_cover_keys_contexts_rows_and_uniqueness() {
        assert_eq!(
            aggregate_private_leaf_salt_resident_state_byte_length(),
            Ok(56),
        );
        assert_eq!(aggregate_private_leaf_salt_row_workspace_byte_length(), 584);
        assert_eq!(
            transported_private_leaf_salt_uniqueness_set_byte_length(2_783),
            Ok(489_832),
        );
        assert_eq!(
            materialized_single_column_commitment_payload_byte_length(8_192),
            Ok(1_376_720),
        );
        assert_eq!(
            materialized_single_column_commitment_payload_byte_length(262_144),
            Ok(44_040_816),
        );
    }
}
