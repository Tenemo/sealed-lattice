use core::ops::Range;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_sumcheck::zk::ZkSumcheckData;
use p3_symmetric::MerkleCap;
use p3_whir::{BaseCaseZkProof, BlindedMask, MaskOpeningPair, QueryOpening, ZkRoundProof};

use super::{
    CompactChallengeField, MaskGroupShape, SmallChainCommitment, SmallChainWhirConfiguration,
    SmallChainWhirProof, SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH,
};
use crate::bgv::proof_suite::{
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
};

const SMALL_CHAIN_CANONICAL_PROOF_MAGIC: &[u8; 8] = b"SLCPCH01";
const SMALL_CHAIN_CANONICAL_SECTION_COUNT: u16 = 8;
const SMALL_CHAIN_FIELD_BYTE_LENGTH: usize = size_of::<u64>();
const SMALL_CHAIN_EXTENSION_FIELD_BYTE_LENGTH: usize =
    PROOF_CHALLENGE_EXTENSION_DEGREE * SMALL_CHAIN_FIELD_BYTE_LENGTH;
const SMALL_CHAIN_MERKLE_NODE_BYTE_LENGTH: usize =
    SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH * size_of::<u64>();

type SmallChainMerkleNode = [u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH];
type SmallChainMerkleProof = Vec<SmallChainMerkleNode>;
type SmallChainQueryOpening =
    QueryOpening<Goldilocks, CompactChallengeField, SmallChainMerkleProof>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SmallChainCanonicalSection {
    OuterCfwProof,
    PreChallengeSourceRoot,
    InnerMaskRoot,
    MainSourceRoot,
    OuterMaskRoot,
    SharedMaskRoot,
    PreChallengeWhirProof,
    MainWhirProof,
}

impl SmallChainCanonicalSection {
    const ORDERED: [Self; SMALL_CHAIN_CANONICAL_SECTION_COUNT as usize] = [
        Self::OuterCfwProof,
        Self::PreChallengeSourceRoot,
        Self::InnerMaskRoot,
        Self::MainSourceRoot,
        Self::OuterMaskRoot,
        Self::SharedMaskRoot,
        Self::PreChallengeWhirProof,
        Self::MainWhirProof,
    ];

    const fn tag(self) -> u16 {
        match self {
            Self::OuterCfwProof => 1,
            Self::PreChallengeSourceRoot => 2,
            Self::InnerMaskRoot => 3,
            Self::MainSourceRoot => 4,
            Self::OuterMaskRoot => 5,
            Self::SharedMaskRoot => 6,
            Self::PreChallengeWhirProof => 7,
            Self::MainWhirProof => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmallChainSourceFieldKind {
    Base,
    Extension,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SmallChainCanonicalTransportError {
    AllocationFailed,
    ByteLengthExceeded,
    EmptySection,
    InvalidGeometry,
    LengthOverflow,
    NonCanonicalField,
    NonCanonicalProofShape,
    TrailingBytes,
    Truncated,
    WrongMagic,
    WrongQueryVariant,
    WrongSectionCount,
    WrongSectionOrder,
}

#[derive(Clone)]
pub(super) struct SmallChainExternalCommitments {
    pub(super) pre_challenge_source: SmallChainCommitment,
    pub(super) inner_masks: SmallChainCommitment,
    pub(super) main_source: SmallChainCommitment,
    pub(super) outer_masks: SmallChainCommitment,
    pub(super) shared_masks: SmallChainCommitment,
}

pub(super) struct DecodedSmallChainCanonicalProof {
    pub(super) canonical_cfw_proof_bytes: Vec<u8>,
    pub(super) commitments: SmallChainExternalCommitments,
    pub(super) pre_challenge_whir_proof: SmallChainWhirProof,
    pub(super) main_whir_proof: SmallChainWhirProof,
}

pub(super) fn encode_small_chain_canonical_proof(
    pre_challenge_configuration: &SmallChainWhirConfiguration,
    main_configuration: &SmallChainWhirConfiguration,
    inner_mask_shape: MaskGroupShape,
    outer_mask_shape: MaskGroupShape,
    shared_mask_shape: MaskGroupShape,
    canonical_cfw_proof_bytes: &[u8],
    commitments: &SmallChainExternalCommitments,
    pre_challenge_whir_proof: &SmallChainWhirProof,
    main_whir_proof: &SmallChainWhirProof,
) -> Result<Vec<u8>, SmallChainCanonicalTransportError> {
    if canonical_cfw_proof_bytes.is_empty() {
        return Err(SmallChainCanonicalTransportError::EmptySection);
    }

    let pre_challenge_whir_bytes = encode_small_chain_whir_proof(
        pre_challenge_configuration,
        SmallChainSourceFieldKind::Base,
        1,
        &[shared_mask_shape],
        pre_challenge_whir_proof,
    )?;
    let main_whir_bytes = encode_small_chain_whir_proof(
        main_configuration,
        SmallChainSourceFieldKind::Extension,
        2,
        &[inner_mask_shape, outer_mask_shape, shared_mask_shape],
        main_whir_proof,
    )?;
    let commitment_sections = [
        encode_commitment(&commitments.pre_challenge_source)?,
        encode_commitment(&commitments.inner_masks)?,
        encode_commitment(&commitments.main_source)?,
        encode_commitment(&commitments.outer_masks)?,
        encode_commitment(&commitments.shared_masks)?,
    ];

    let payloads: [&[u8]; SMALL_CHAIN_CANONICAL_SECTION_COUNT as usize] = [
        canonical_cfw_proof_bytes,
        &commitment_sections[0],
        &commitment_sections[1],
        &commitment_sections[2],
        &commitment_sections[3],
        &commitment_sections[4],
        &pre_challenge_whir_bytes,
        &main_whir_bytes,
    ];
    let mut writer = SmallChainCanonicalWriter::new();
    writer.write_bytes(SMALL_CHAIN_CANONICAL_PROOF_MAGIC)?;
    writer.write_u16(SMALL_CHAIN_CANONICAL_SECTION_COUNT)?;
    for (section, payload) in SmallChainCanonicalSection::ORDERED
        .into_iter()
        .zip(payloads)
    {
        writer.write_section(section, payload)?;
    }
    writer.finish()
}

pub(super) fn decode_small_chain_canonical_proof(
    pre_challenge_configuration: &SmallChainWhirConfiguration,
    main_configuration: &SmallChainWhirConfiguration,
    inner_mask_shape: MaskGroupShape,
    outer_mask_shape: MaskGroupShape,
    shared_mask_shape: MaskGroupShape,
    canonical: &[u8],
) -> Result<DecodedSmallChainCanonicalProof, SmallChainCanonicalTransportError> {
    if canonical.is_empty() || canonical.len() > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(SmallChainCanonicalTransportError::ByteLengthExceeded);
    }
    let mut reader = SmallChainCanonicalReader::new(canonical);
    if reader.read_array::<8>()? != *SMALL_CHAIN_CANONICAL_PROOF_MAGIC {
        return Err(SmallChainCanonicalTransportError::WrongMagic);
    }
    if reader.read_u16()? != SMALL_CHAIN_CANONICAL_SECTION_COUNT {
        return Err(SmallChainCanonicalTransportError::WrongSectionCount);
    }
    let outer_cfw_proof =
        copy_bytes(reader.read_section(SmallChainCanonicalSection::OuterCfwProof)?)?;
    let pre_challenge_source = decode_commitment(
        reader.read_section(SmallChainCanonicalSection::PreChallengeSourceRoot)?,
    )?;
    let inner_masks =
        decode_commitment(reader.read_section(SmallChainCanonicalSection::InnerMaskRoot)?)?;
    let main_source =
        decode_commitment(reader.read_section(SmallChainCanonicalSection::MainSourceRoot)?)?;
    let outer_masks =
        decode_commitment(reader.read_section(SmallChainCanonicalSection::OuterMaskRoot)?)?;
    let shared_masks =
        decode_commitment(reader.read_section(SmallChainCanonicalSection::SharedMaskRoot)?)?;
    let pre_challenge_whir_proof = decode_small_chain_whir_proof(
        pre_challenge_configuration,
        SmallChainSourceFieldKind::Base,
        1,
        &[shared_mask_shape],
        reader.read_section(SmallChainCanonicalSection::PreChallengeWhirProof)?,
    )?;
    let main_whir_proof = decode_small_chain_whir_proof(
        main_configuration,
        SmallChainSourceFieldKind::Extension,
        2,
        &[inner_mask_shape, outer_mask_shape, shared_mask_shape],
        reader.read_section(SmallChainCanonicalSection::MainWhirProof)?,
    )?;
    reader.finish()?;

    Ok(DecodedSmallChainCanonicalProof {
        canonical_cfw_proof_bytes: outer_cfw_proof,
        commitments: SmallChainExternalCommitments {
            pre_challenge_source,
            inner_masks,
            main_source,
            outer_masks,
            shared_masks,
        },
        pre_challenge_whir_proof,
        main_whir_proof,
    })
}

pub(super) fn small_chain_canonical_section_payload_range(
    canonical: &[u8],
    target: SmallChainCanonicalSection,
) -> Result<Range<usize>, SmallChainCanonicalTransportError> {
    if canonical.is_empty() || canonical.len() > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(SmallChainCanonicalTransportError::ByteLengthExceeded);
    }
    let mut reader = SmallChainCanonicalReader::new(canonical);
    if reader.read_array::<8>()? != *SMALL_CHAIN_CANONICAL_PROOF_MAGIC {
        return Err(SmallChainCanonicalTransportError::WrongMagic);
    }
    if reader.read_u16()? != SMALL_CHAIN_CANONICAL_SECTION_COUNT {
        return Err(SmallChainCanonicalTransportError::WrongSectionCount);
    }
    let mut target_range = None;
    for section in SmallChainCanonicalSection::ORDERED {
        let range = reader.read_section_range(section)?;
        if section == target {
            target_range = Some(range);
        }
    }
    reader.finish()?;
    target_range.ok_or(SmallChainCanonicalTransportError::WrongSectionOrder)
}

fn encode_small_chain_whir_proof(
    configuration: &SmallChainWhirConfiguration,
    initial_source_field_kind: SmallChainSourceFieldKind,
    expected_evaluation_count: usize,
    precommitted_mask_shapes: &[MaskGroupShape],
    proof: &SmallChainWhirProof,
) -> Result<Vec<u8>, SmallChainCanonicalTransportError> {
    let round_count = configuration.n_rounds();
    if proof.evals.len() != expected_evaluation_count
        || proof.sumchecks.len() != round_count + 1
        || proof.sumcheck_mask_commitments.len() != round_count + 1
        || proof.rounds.len() != round_count
    {
        return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
    }
    let mut writer = SmallChainCanonicalWriter::new();
    writer.write_extension_fields(&proof.evals)?;
    writer.write_commitment(&proof.sumcheck_mask_commitments[0])?;
    writer.write_sumcheck(
        &proof.sumchecks[0],
        configuration.zk.ell_zk,
        configuration.round_folding_factor(0),
        configuration.starting_folding_pow_bits,
    )?;

    for (round_ordinal, round) in proof.rounds.iter().enumerate() {
        let round_configuration = &configuration.round_parameters[round_ordinal];
        let folding_factor = configuration.round_folding_factor(round_ordinal);
        writer.write_commitment(&round.commitment)?;
        writer.write_commitment(&round.mask_commitment)?;
        if round.ood_answers.len() != round_configuration.ood_samples
            || round.queries.len() != round_configuration.num_queries
        {
            return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
        }
        writer.write_extension_fields(&round.ood_answers)?;
        writer.write_optional_base_field(round.pow_witness, round_configuration.pow_bits)?;
        let query_field_kind = if round_ordinal == 0 {
            initial_source_field_kind
        } else {
            SmallChainSourceFieldKind::Extension
        };
        writer.write_query_batch(
            &round.queries,
            round_configuration.domain_size >> folding_factor,
            1 << folding_factor,
            query_field_kind,
        )?;
        writer.write_commitment(&proof.sumcheck_mask_commitments[round_ordinal + 1])?;
        writer.write_sumcheck(
            &proof.sumchecks[round_ordinal + 1],
            configuration.zk.ell_zk,
            configuration.round_folding_factor(round_ordinal + 1),
            round_configuration.folding_pow_bits,
        )?;
    }

    let base_mask_shapes = final_mask_group_shapes(configuration, precommitted_mask_shapes);
    writer.write_base_case(
        configuration,
        initial_source_field_kind,
        &base_mask_shapes,
        &proof.base_case,
    )?;
    writer.finish()
}

fn decode_small_chain_whir_proof(
    configuration: &SmallChainWhirConfiguration,
    initial_source_field_kind: SmallChainSourceFieldKind,
    expected_evaluation_count: usize,
    precommitted_mask_shapes: &[MaskGroupShape],
    canonical: &[u8],
) -> Result<SmallChainWhirProof, SmallChainCanonicalTransportError> {
    if canonical.is_empty() {
        return Err(SmallChainCanonicalTransportError::EmptySection);
    }
    let mut reader = SmallChainCanonicalReader::new(canonical);
    let evals = reader.read_extension_fields(expected_evaluation_count)?;
    let round_count = configuration.n_rounds();
    let mut sumchecks = allocate_vector(round_count + 1)?;
    let mut sumcheck_mask_commitments = allocate_vector(round_count + 1)?;
    sumcheck_mask_commitments.push(reader.read_commitment()?);
    sumchecks.push(reader.read_sumcheck(
        configuration.zk.ell_zk,
        configuration.round_folding_factor(0),
        configuration.starting_folding_pow_bits,
    )?);

    let mut rounds = allocate_vector(round_count)?;
    for round_ordinal in 0..round_count {
        let round_configuration = &configuration.round_parameters[round_ordinal];
        let folding_factor = configuration.round_folding_factor(round_ordinal);
        let commitment = reader.read_commitment()?;
        let mask_commitment = reader.read_commitment()?;
        let ood_answers = reader.read_extension_fields(round_configuration.ood_samples)?;
        let pow_witness = reader.read_optional_base_field(round_configuration.pow_bits)?;
        let query_field_kind = if round_ordinal == 0 {
            initial_source_field_kind
        } else {
            SmallChainSourceFieldKind::Extension
        };
        let queries = reader.read_typed_query_batch(
            round_configuration.num_queries,
            round_configuration.domain_size >> folding_factor,
            1 << folding_factor,
            query_field_kind,
        )?;
        sumcheck_mask_commitments.push(reader.read_commitment()?);
        sumchecks.push(reader.read_sumcheck(
            configuration.zk.ell_zk,
            configuration.round_folding_factor(round_ordinal + 1),
            round_configuration.folding_pow_bits,
        )?);
        rounds.push(ZkRoundProof {
            commitment,
            mask_commitment,
            ood_answers,
            pow_witness,
            queries,
        });
    }

    let base_mask_shapes = final_mask_group_shapes(configuration, precommitted_mask_shapes);
    let base_case =
        reader.read_base_case(configuration, initial_source_field_kind, &base_mask_shapes)?;
    reader.finish()?;
    Ok(SmallChainWhirProof {
        evals,
        sumchecks,
        sumcheck_mask_commitments,
        rounds,
        base_case,
    })
}

fn final_mask_group_shapes(
    configuration: &SmallChainWhirConfiguration,
    precommitted_mask_shapes: &[MaskGroupShape],
) -> Vec<MaskGroupShape> {
    let mut shapes =
        Vec::with_capacity(precommitted_mask_shapes.len() + 2 * configuration.n_rounds() + 1);
    shapes.extend_from_slice(precommitted_mask_shapes);
    shapes.push(MaskGroupShape {
        shape: configuration.sumcheck_mask,
        width: configuration.round_folding_factor(0),
    });
    for round_ordinal in 0..configuration.n_rounds() {
        shapes.push(MaskGroupShape {
            shape: configuration.switch_masks[round_ordinal],
            width: 1,
        });
        shapes.push(MaskGroupShape {
            shape: configuration.sumcheck_mask,
            width: configuration.round_folding_factor(round_ordinal + 1),
        });
    }
    shapes
}

fn encode_commitment(
    commitment: &SmallChainCommitment,
) -> Result<Vec<u8>, SmallChainCanonicalTransportError> {
    let mut writer = SmallChainCanonicalWriter::new();
    writer.write_commitment(commitment)?;
    writer.finish()
}

fn decode_commitment(
    canonical: &[u8],
) -> Result<SmallChainCommitment, SmallChainCanonicalTransportError> {
    let mut reader = SmallChainCanonicalReader::new(canonical);
    let commitment = reader.read_commitment()?;
    reader.finish()?;
    Ok(commitment)
}

fn checked_merkle_path_length(
    leaf_count: usize,
) -> Result<usize, SmallChainCanonicalTransportError> {
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(SmallChainCanonicalTransportError::InvalidGeometry);
    }
    Ok(leaf_count.ilog2() as usize)
}

fn allocate_vector<T>(capacity: usize) -> Result<Vec<T>, SmallChainCanonicalTransportError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| SmallChainCanonicalTransportError::AllocationFailed)?;
    Ok(values)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, SmallChainCanonicalTransportError> {
    let mut copy = allocate_vector(bytes.len())?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

struct SmallChainCanonicalWriter {
    bytes: Vec<u8>,
}

impl SmallChainCanonicalWriter {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), SmallChainCanonicalTransportError> {
        let following_length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .ok_or(SmallChainCanonicalTransportError::ByteLengthExceeded)?;
        self.bytes
            .try_reserve_exact(following_length - self.bytes.len())
            .map_err(|_| SmallChainCanonicalTransportError::AllocationFailed)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<(), SmallChainCanonicalTransportError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), SmallChainCanonicalTransportError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), SmallChainCanonicalTransportError> {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_section(
        &mut self,
        section: SmallChainCanonicalSection,
        payload: &[u8],
    ) -> Result<(), SmallChainCanonicalTransportError> {
        if payload.is_empty() {
            return Err(SmallChainCanonicalTransportError::EmptySection);
        }
        let payload_length = u32::try_from(payload.len())
            .map_err(|_| SmallChainCanonicalTransportError::LengthOverflow)?;
        self.write_u16(section.tag())?;
        self.write_u32(payload_length)?;
        self.write_bytes(payload)
    }

    fn write_base_field(
        &mut self,
        value: Goldilocks,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        self.write_u64(value.as_canonical_u64())
    }

    fn write_extension_field(
        &mut self,
        value: CompactChallengeField,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        let coefficients =
            <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                &value,
            );
        if coefficients.len() != PROOF_CHALLENGE_EXTENSION_DEGREE {
            return Err(SmallChainCanonicalTransportError::InvalidGeometry);
        }
        for coefficient in coefficients {
            self.write_base_field(*coefficient)?;
        }
        Ok(())
    }

    fn write_extension_fields(
        &mut self,
        values: &[CompactChallengeField],
    ) -> Result<(), SmallChainCanonicalTransportError> {
        for value in values {
            self.write_extension_field(*value)?;
        }
        Ok(())
    }

    fn write_merkle_node(
        &mut self,
        node: &SmallChainMerkleNode,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        for word in node {
            self.write_u64(*word)?;
        }
        Ok(())
    }

    fn write_commitment(
        &mut self,
        commitment: &SmallChainCommitment,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        let [root] = commitment.roots() else {
            return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
        };
        self.write_merkle_node(root)
    }

    fn write_optional_base_field(
        &mut self,
        witness: Goldilocks,
        proof_of_work_bits: usize,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        if proof_of_work_bits == 0 {
            if witness != Goldilocks::ZERO {
                return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
            }
            Ok(())
        } else {
            self.write_base_field(witness)
        }
    }

    fn write_sumcheck(
        &mut self,
        sumcheck: &ZkSumcheckData<Goldilocks, CompactChallengeField>,
        expected_mask_message_length: usize,
        expected_round_count: usize,
        proof_of_work_bits: usize,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        let expected_coefficient_count = expected_mask_message_length
            .checked_sub(1)
            .ok_or(SmallChainCanonicalTransportError::InvalidGeometry)?;
        let expected_witness_count = if proof_of_work_bits == 0 {
            0
        } else {
            expected_round_count
        };
        if sumcheck.ell_zk != expected_mask_message_length
            || sumcheck.round_coefficients.len() != expected_round_count
            || sumcheck
                .round_coefficients
                .iter()
                .any(|coefficients| coefficients.len() != expected_coefficient_count)
            || sumcheck.pow_witnesses.len() != expected_witness_count
        {
            return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
        }
        self.write_extension_field(sumcheck.mu_tilde)?;
        for (round_ordinal, coefficients) in sumcheck.round_coefficients.iter().enumerate() {
            self.write_extension_fields(coefficients)?;
            if proof_of_work_bits > 0 {
                self.write_base_field(sumcheck.pow_witnesses[round_ordinal])?;
            }
        }
        Ok(())
    }

    fn write_query_batch(
        &mut self,
        queries: &[SmallChainQueryOpening],
        leaf_count: usize,
        row_width: usize,
        field_kind: SmallChainSourceFieldKind,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        if row_width == 0 {
            return Err(SmallChainCanonicalTransportError::InvalidGeometry);
        }
        let path_length = checked_merkle_path_length(leaf_count)?;
        for query in queries {
            match (field_kind, query) {
                (SmallChainSourceFieldKind::Base, QueryOpening::Base { values, proof }) => {
                    if values.len() != row_width || proof.len() != path_length {
                        return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
                    }
                    for value in values {
                        self.write_base_field(*value)?;
                    }
                    for node in proof {
                        self.write_merkle_node(node)?;
                    }
                }
                (
                    SmallChainSourceFieldKind::Extension,
                    QueryOpening::Extension { values, proof },
                ) => {
                    if values.len() != row_width || proof.len() != path_length {
                        return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
                    }
                    self.write_extension_fields(values)?;
                    for node in proof {
                        self.write_merkle_node(node)?;
                    }
                }
                _ => return Err(SmallChainCanonicalTransportError::WrongQueryVariant),
            }
        }
        Ok(())
    }

    fn write_base_case(
        &mut self,
        configuration: &SmallChainWhirConfiguration,
        initial_source_field_kind: SmallChainSourceFieldKind,
        mask_shapes: &[MaskGroupShape],
        base_case: &BaseCaseZkProof<
            Goldilocks,
            CompactChallengeField,
            super::SmallChainCommitmentScheme,
        >,
    ) -> Result<(), SmallChainCanonicalTransportError> {
        let mask_count = mask_shapes
            .iter()
            .try_fold(0_usize, |count, group| count.checked_add(group.width));
        let Some(mask_count) = mask_count else {
            return Err(SmallChainCanonicalTransportError::LengthOverflow);
        };
        if base_case.fresh_mask_commitments.len() != mask_shapes.len()
            || base_case.blinded_masks.len() != mask_count
            || base_case.mask_queries.len() != mask_shapes.len()
        {
            return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
        }
        self.write_commitment(&base_case.fresh_main_commitment)?;
        for commitment in &base_case.fresh_mask_commitments {
            self.write_commitment(commitment)?;
        }
        self.write_extension_field(base_case.masked_claim)?;
        let final_configuration = configuration.final_round_config();
        let expected_source_message_length = 1 << final_configuration.num_variables;
        let expected_source_randomness_length =
            configuration.oracle_randomness[configuration.n_rounds()];
        if base_case.blinded_message.len() != expected_source_message_length
            || base_case.blinded_randomness.len() != expected_source_randomness_length
        {
            return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
        }
        self.write_extension_fields(&base_case.blinded_message)?;
        self.write_extension_fields(&base_case.blinded_randomness)?;
        let mut mask_ordinal = 0_usize;
        for group in mask_shapes {
            for _ in 0..group.width {
                let blinded_mask = &base_case.blinded_masks[mask_ordinal];
                if blinded_mask.message.len() != group.shape.message_len
                    || blinded_mask.randomness.len() != group.shape.randomness_len
                {
                    return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
                }
                self.write_extension_fields(&blinded_mask.message)?;
                self.write_extension_fields(&blinded_mask.randomness)?;
                mask_ordinal += 1;
            }
        }
        self.write_optional_base_field(base_case.pow_witness, configuration.final_pow_bits)?;

        let source_leaf_count =
            final_configuration.domain_size >> final_configuration.folding_factor;
        let source_row_width = 1 << final_configuration.folding_factor;
        let source_query_field_kind = if configuration.n_rounds() == 0 {
            initial_source_field_kind
        } else {
            SmallChainSourceFieldKind::Extension
        };
        if base_case.source_queries.len() != configuration.final_queries
            || base_case.fresh_main_queries.len() != configuration.final_queries
        {
            return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
        }
        self.write_query_batch(
            &base_case.source_queries,
            source_leaf_count,
            source_row_width,
            source_query_field_kind,
        )?;
        self.write_query_batch(
            &base_case.fresh_main_queries,
            source_leaf_count,
            1,
            SmallChainSourceFieldKind::Extension,
        )?;
        for (group, pairs) in mask_shapes.iter().zip(&base_case.mask_queries) {
            if pairs.len() != configuration.mask_queries {
                return Err(SmallChainCanonicalTransportError::NonCanonicalProofShape);
            }
            for pair in pairs {
                self.write_query_batch(
                    core::slice::from_ref(&pair.carried),
                    group.shape.domain_size,
                    group.width,
                    SmallChainSourceFieldKind::Extension,
                )?;
                self.write_query_batch(
                    core::slice::from_ref(&pair.fresh),
                    group.shape.domain_size,
                    group.width,
                    SmallChainSourceFieldKind::Extension,
                )?;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, SmallChainCanonicalTransportError> {
        if self.bytes.is_empty() {
            Err(SmallChainCanonicalTransportError::EmptySection)
        } else {
            Ok(self.bytes)
        }
    }
}

struct SmallChainCanonicalReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SmallChainCanonicalReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_COUNT: usize>(
        &mut self,
    ) -> Result<[u8; BYTE_COUNT], SmallChainCanonicalTransportError> {
        let source = self.read_bytes(BYTE_COUNT)?;
        let mut output = [0_u8; BYTE_COUNT];
        output.copy_from_slice(source);
        Ok(output)
    }

    fn read_bytes(
        &mut self,
        byte_length: usize,
    ) -> Result<&'a [u8], SmallChainCanonicalTransportError> {
        let following_offset = self
            .offset
            .checked_add(byte_length)
            .ok_or(SmallChainCanonicalTransportError::LengthOverflow)?;
        let source = self
            .bytes
            .get(self.offset..following_offset)
            .ok_or(SmallChainCanonicalTransportError::Truncated)?;
        self.offset = following_offset;
        Ok(source)
    }

    fn read_u16(&mut self) -> Result<u16, SmallChainCanonicalTransportError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, SmallChainCanonicalTransportError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, SmallChainCanonicalTransportError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_section(
        &mut self,
        expected_section: SmallChainCanonicalSection,
    ) -> Result<&'a [u8], SmallChainCanonicalTransportError> {
        let range = self.read_section_range(expected_section)?;
        Ok(&self.bytes[range])
    }

    fn read_section_range(
        &mut self,
        expected_section: SmallChainCanonicalSection,
    ) -> Result<Range<usize>, SmallChainCanonicalTransportError> {
        if self.read_u16()? != expected_section.tag() {
            return Err(SmallChainCanonicalTransportError::WrongSectionOrder);
        }
        let byte_length = usize::try_from(self.read_u32()?)
            .map_err(|_| SmallChainCanonicalTransportError::LengthOverflow)?;
        if byte_length == 0 {
            return Err(SmallChainCanonicalTransportError::EmptySection);
        }
        if byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
            return Err(SmallChainCanonicalTransportError::ByteLengthExceeded);
        }
        let start = self.offset;
        self.read_bytes(byte_length)?;
        Ok(start..self.offset)
    }

    fn read_base_field(&mut self) -> Result<Goldilocks, SmallChainCanonicalTransportError> {
        let canonical = self.read_u64()?;
        if canonical >= PROOF_BASE_FIELD_MODULUS {
            return Err(SmallChainCanonicalTransportError::NonCanonicalField);
        }
        Ok(Goldilocks::new(canonical))
    }

    fn read_extension_field(
        &mut self,
    ) -> Result<CompactChallengeField, SmallChainCanonicalTransportError> {
        let mut coefficients = [Goldilocks::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for coefficient in &mut coefficients {
            *coefficient = self.read_base_field()?;
        }
        Ok(CompactChallengeField::new(coefficients))
    }

    fn read_extension_fields(
        &mut self,
        count: usize,
    ) -> Result<Vec<CompactChallengeField>, SmallChainCanonicalTransportError> {
        let required_byte_length = count
            .checked_mul(SMALL_CHAIN_EXTENSION_FIELD_BYTE_LENGTH)
            .ok_or(SmallChainCanonicalTransportError::LengthOverflow)?;
        if self.offset.saturating_add(required_byte_length) > self.bytes.len() {
            return Err(SmallChainCanonicalTransportError::Truncated);
        }
        let mut values = allocate_vector(count)?;
        for _ in 0..count {
            values.push(self.read_extension_field()?);
        }
        Ok(values)
    }

    fn read_merkle_node(
        &mut self,
    ) -> Result<SmallChainMerkleNode, SmallChainCanonicalTransportError> {
        let mut node = [0_u64; SMALL_CHAIN_HASH_OUTPUT_WORD_LENGTH];
        for word in &mut node {
            *word = self.read_u64()?;
        }
        Ok(node)
    }

    fn read_commitment(
        &mut self,
    ) -> Result<SmallChainCommitment, SmallChainCanonicalTransportError> {
        Ok(MerkleCap::new(vec![self.read_merkle_node()?]))
    }

    fn read_optional_base_field(
        &mut self,
        proof_of_work_bits: usize,
    ) -> Result<Goldilocks, SmallChainCanonicalTransportError> {
        if proof_of_work_bits == 0 {
            Ok(Goldilocks::ZERO)
        } else {
            self.read_base_field()
        }
    }

    fn read_sumcheck(
        &mut self,
        mask_message_length: usize,
        round_count: usize,
        proof_of_work_bits: usize,
    ) -> Result<ZkSumcheckData<Goldilocks, CompactChallengeField>, SmallChainCanonicalTransportError>
    {
        let coefficient_count = mask_message_length
            .checked_sub(1)
            .ok_or(SmallChainCanonicalTransportError::InvalidGeometry)?;
        let mu_tilde = self.read_extension_field()?;
        let mut round_coefficients = allocate_vector(round_count)?;
        let mut pow_witnesses = allocate_vector(if proof_of_work_bits == 0 {
            0
        } else {
            round_count
        })?;
        for _ in 0..round_count {
            round_coefficients.push(self.read_extension_fields(coefficient_count)?);
            if proof_of_work_bits > 0 {
                pow_witnesses.push(self.read_base_field()?);
            }
        }
        Ok(ZkSumcheckData {
            mu_tilde,
            ell_zk: mask_message_length,
            round_coefficients,
            pow_witnesses,
        })
    }

    fn read_typed_query_batch(
        &mut self,
        query_count: usize,
        leaf_count: usize,
        row_width: usize,
        field_kind: SmallChainSourceFieldKind,
    ) -> Result<Vec<SmallChainQueryOpening>, SmallChainCanonicalTransportError> {
        if row_width == 0 {
            return Err(SmallChainCanonicalTransportError::InvalidGeometry);
        }
        let path_length = checked_merkle_path_length(leaf_count)?;
        let mut queries = allocate_vector(query_count)?;
        for _ in 0..query_count {
            let query = match field_kind {
                SmallChainSourceFieldKind::Base => {
                    let mut values = allocate_vector(row_width)?;
                    for _ in 0..row_width {
                        values.push(self.read_base_field()?);
                    }
                    QueryOpening::Base {
                        values,
                        proof: self.read_merkle_path(path_length)?,
                    }
                }
                SmallChainSourceFieldKind::Extension => QueryOpening::Extension {
                    values: self.read_extension_fields(row_width)?,
                    proof: self.read_merkle_path(path_length)?,
                },
            };
            queries.push(query);
        }
        Ok(queries)
    }

    fn read_merkle_path(
        &mut self,
        node_count: usize,
    ) -> Result<SmallChainMerkleProof, SmallChainCanonicalTransportError> {
        let required_byte_length = node_count
            .checked_mul(SMALL_CHAIN_MERKLE_NODE_BYTE_LENGTH)
            .ok_or(SmallChainCanonicalTransportError::LengthOverflow)?;
        if self.offset.saturating_add(required_byte_length) > self.bytes.len() {
            return Err(SmallChainCanonicalTransportError::Truncated);
        }
        let mut path = allocate_vector(node_count)?;
        for _ in 0..node_count {
            path.push(self.read_merkle_node()?);
        }
        Ok(path)
    }

    fn read_base_case(
        &mut self,
        configuration: &SmallChainWhirConfiguration,
        initial_source_field_kind: SmallChainSourceFieldKind,
        mask_shapes: &[MaskGroupShape],
    ) -> Result<
        BaseCaseZkProof<Goldilocks, CompactChallengeField, super::SmallChainCommitmentScheme>,
        SmallChainCanonicalTransportError,
    > {
        let fresh_main_commitment = self.read_commitment()?;
        let mut fresh_mask_commitments = allocate_vector(mask_shapes.len())?;
        for _ in mask_shapes {
            fresh_mask_commitments.push(self.read_commitment()?);
        }
        let masked_claim = self.read_extension_field()?;
        let final_configuration = configuration.final_round_config();
        let blinded_message = self.read_extension_fields(1 << final_configuration.num_variables)?;
        let blinded_randomness =
            self.read_extension_fields(configuration.oracle_randomness[configuration.n_rounds()])?;
        let mask_count = mask_shapes
            .iter()
            .try_fold(0_usize, |count, group| count.checked_add(group.width));
        let Some(mask_count) = mask_count else {
            return Err(SmallChainCanonicalTransportError::LengthOverflow);
        };
        let mut blinded_masks = allocate_vector(mask_count)?;
        for group in mask_shapes {
            for _ in 0..group.width {
                blinded_masks.push(BlindedMask {
                    message: self.read_extension_fields(group.shape.message_len)?,
                    randomness: self.read_extension_fields(group.shape.randomness_len)?,
                });
            }
        }
        let pow_witness = self.read_optional_base_field(configuration.final_pow_bits)?;
        let source_leaf_count =
            final_configuration.domain_size >> final_configuration.folding_factor;
        let source_row_width = 1 << final_configuration.folding_factor;
        let source_query_field_kind = if configuration.n_rounds() == 0 {
            initial_source_field_kind
        } else {
            SmallChainSourceFieldKind::Extension
        };
        let source_queries = self.read_typed_query_batch(
            configuration.final_queries,
            source_leaf_count,
            source_row_width,
            source_query_field_kind,
        )?;
        let fresh_main_queries = self.read_typed_query_batch(
            configuration.final_queries,
            source_leaf_count,
            1,
            SmallChainSourceFieldKind::Extension,
        )?;
        let mut mask_queries = allocate_vector(mask_shapes.len())?;
        for group in mask_shapes {
            let mut pairs = allocate_vector(configuration.mask_queries)?;
            for _ in 0..configuration.mask_queries {
                let carried = self
                    .read_typed_query_batch(
                        1,
                        group.shape.domain_size,
                        group.width,
                        SmallChainSourceFieldKind::Extension,
                    )?
                    .pop()
                    .ok_or(SmallChainCanonicalTransportError::InvalidGeometry)?;
                let fresh = self
                    .read_typed_query_batch(
                        1,
                        group.shape.domain_size,
                        group.width,
                        SmallChainSourceFieldKind::Extension,
                    )?
                    .pop()
                    .ok_or(SmallChainCanonicalTransportError::InvalidGeometry)?;
                pairs.push(MaskOpeningPair { carried, fresh });
            }
            mask_queries.push(pairs);
        }
        Ok(BaseCaseZkProof {
            fresh_main_commitment,
            fresh_mask_commitments,
            masked_claim,
            blinded_message,
            blinded_randomness,
            blinded_masks,
            pow_witness,
            source_queries,
            fresh_main_queries,
            mask_queries,
        })
    }

    fn finish(self) -> Result<(), SmallChainCanonicalTransportError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SmallChainCanonicalTransportError::TrailingBytes)
        }
    }
}
