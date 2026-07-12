use core::fmt;
use std::collections::BTreeSet;

use super::{
    CanonicalCodecError, CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE,
    Hash512, ProofFamily, ProofObjectHeader, hash512,
};

const INITIAL_TRANSCRIPT_DOMAIN: &str = "sealed-lattice/proof/transcript/v1";
const ABSORB_TRANSCRIPT_DOMAIN: &str = "sealed-lattice/proof/transcript/absorb/v1";
const SQUEEZE_TRANSCRIPT_DOMAIN: &str = "sealed-lattice/proof/transcript/squeeze/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofTranscriptError {
    CanonicalCodec(CanonicalCodecError),
    CounterExhausted,
    EmptyRoundMessage,
    InvalidApplicationStatement,
    InvalidExcludedPoint,
    InvalidModulus,
    InvalidCoordinateCount,
    PointCardinalityExceeded,
    QueryCardinalityExceeded,
}

impl fmt::Display for ProofTranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalCodec(error) => write!(formatter, "{error}"),
            Self::CounterExhausted => {
                formatter.write_str("the proof challenge stream counter is exhausted")
            }
            Self::EmptyRoundMessage => {
                formatter.write_str("the canonical proof round message must not be empty")
            }
            Self::InvalidApplicationStatement => formatter
                .write_str("the proof header does not contain the declared application statement"),
            Self::InvalidExcludedPoint => {
                formatter.write_str("the proof challenge exclusion set contains an invalid point")
            }
            Self::InvalidModulus => {
                formatter.write_str("the proof challenge modulus must be positive")
            }
            Self::InvalidCoordinateCount => {
                formatter.write_str("the proof extension challenge must contain coordinates")
            }
            Self::PointCardinalityExceeded => formatter.write_str(
                "the requested distinct proof points exceed the available extension-field set",
            ),
            Self::QueryCardinalityExceeded => formatter
                .write_str("the requested distinct proof queries exceed the representative set"),
        }
    }
}

impl std::error::Error for ProofTranscriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CanonicalCodec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalCodecError> for ProofTranscriptError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::CanonicalCodec(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRoundTag {
    BaseRoot { tree_ordinal: u16 },
    AuxiliaryRoot { tree_ordinal: u16 },
    QuotientRoot { component_ordinal: u16 },
    DeepValues,
    OpeningBatchMaskRoot,
    FriLayerRoot { fold_ordinal: u16 },
    FriTerminal,
    QueryOpenings,
}

impl ProofRoundTag {
    fn canonical_tag(self, application_statement_schema_identifier: u16) -> String {
        let prefix = format!("proof/{application_statement_schema_identifier:04x}");
        match self {
            Self::BaseRoot { tree_ordinal } => {
                format!("{prefix}/base-root/{tree_ordinal:04x}")
            }
            Self::AuxiliaryRoot { tree_ordinal } => {
                format!("{prefix}/auxiliary-root/{tree_ordinal:04x}")
            }
            Self::QuotientRoot { component_ordinal } => {
                format!("{prefix}/quotient-root/{component_ordinal:04x}")
            }
            Self::DeepValues => format!("{prefix}/deep-values"),
            Self::OpeningBatchMaskRoot => format!("{prefix}/opening-batch-mask-root"),
            Self::FriLayerRoot { fold_ordinal } => {
                format!("{prefix}/fri-layer-root/{fold_ordinal:04x}")
            }
            Self::FriTerminal => format!("{prefix}/fri-terminal"),
            Self::QueryOpenings => format!("{prefix}/query-openings"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofChallengeTag {
    Theta {
        modulus_ordinal: u16,
        challenge_ordinal: u16,
    },
    Alpha {
        modulus_ordinal: u16,
        challenge_ordinal: u16,
        unit_ordinal: u16,
    },
    Composition {
        constraint_ordinal: u16,
    },
    DeepPoint {
        point_ordinal: u16,
    },
    OpeningBatch {
        claim_ordinal: u16,
    },
    FriFold {
        fold_ordinal: u16,
    },
    QueryRepresentative {
        query_ordinal: u32,
    },
}

impl ProofChallengeTag {
    fn canonical_tag(self, application_statement_schema_identifier: u16) -> String {
        let prefix = format!("proof/{application_statement_schema_identifier:04x}");
        match self {
            Self::Theta {
                modulus_ordinal,
                challenge_ordinal,
            } => format!("{prefix}/theta/{modulus_ordinal:04x}/{challenge_ordinal:04x}"),
            Self::Alpha {
                modulus_ordinal,
                challenge_ordinal,
                unit_ordinal,
            } => format!(
                "{prefix}/alpha/{modulus_ordinal:04x}/{challenge_ordinal:04x}/{unit_ordinal:04x}"
            ),
            Self::Composition { constraint_ordinal } => {
                format!("{prefix}/composition/{constraint_ordinal:04x}")
            }
            Self::DeepPoint { point_ordinal } => {
                format!("{prefix}/deep-point/{point_ordinal:04x}")
            }
            Self::OpeningBatch { claim_ordinal } => {
                format!("{prefix}/opening-batch/{claim_ordinal:04x}")
            }
            Self::FriFold { fold_ordinal } => {
                format!("{prefix}/fri-fold/{fold_ordinal:04x}")
            }
            Self::QueryRepresentative { query_ordinal } => {
                format!("{prefix}/query-representative/{query_ordinal:08x}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProofTranscript {
    application_statement_schema_identifier: u16,
    state: Hash512,
}

impl CanonicalProofTranscript {
    pub fn new(
        suite_identifier: Hash512,
        application_statement_schema_identifier: u16,
        canonical_proof_object_header: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, ProofTranscriptError> {
        if ProofFamily::from_statement_schema_identifier(application_statement_schema_identifier)
            .is_none()
        {
            return Err(ProofTranscriptError::InvalidApplicationStatement);
        }
        let proof_object_header = ProofObjectHeader::decode(canonical_proof_object_header, limits)
            .map_err(|_| ProofTranscriptError::InvalidApplicationStatement)?;
        let application_statement =
            CanonicalTuple::decode(&proof_object_header.canonical_application_statement, limits)?;
        if application_statement.schema_identifier != application_statement_schema_identifier {
            return Err(ProofTranscriptError::InvalidApplicationStatement);
        }

        let state = hash512(
            INITIAL_TRANSCRIPT_DOMAIN,
            &[
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(suite_identifier.into_bytes()),
                CanonicalItem::unsigned16(application_statement_schema_identifier),
                CanonicalItem::variable_bytes(canonical_proof_object_header)?,
            ],
        )?;
        Ok(Self {
            application_statement_schema_identifier,
            state,
        })
    }

    pub const fn state(&self) -> Hash512 {
        self.state
    }

    pub fn absorb_round(
        &mut self,
        round_tag: ProofRoundTag,
        canonical_round_message: &[u8],
    ) -> Result<(), ProofTranscriptError> {
        if canonical_round_message.is_empty() {
            return Err(ProofTranscriptError::EmptyRoundMessage);
        }
        let canonical_tag = round_tag.canonical_tag(self.application_statement_schema_identifier);
        self.state = hash512(
            ABSORB_TRANSCRIPT_DOMAIN,
            &[
                CanonicalItem::hash512(self.state.into_bytes()),
                CanonicalItem::ascii(&canonical_tag)?,
                CanonicalItem::variable_bytes(canonical_round_message)?,
            ],
        )?;
        Ok(())
    }

    pub fn absorb_root(
        &mut self,
        round_tag: ProofRoundTag,
        root: Hash512,
    ) -> Result<(), ProofTranscriptError> {
        self.absorb_round(round_tag, root.as_bytes())
    }

    pub fn sample_modulo(
        &self,
        challenge_tag: ProofChallengeTag,
        modulus: u64,
    ) -> Result<u64, ProofTranscriptError> {
        let canonical_tag =
            challenge_tag.canonical_tag(self.application_statement_schema_identifier);
        let mut challenge_stream = ChallengeByteStream::new(self.state, canonical_tag);
        sample_modulo_from_stream(&mut challenge_stream, modulus)
    }

    pub fn sample_extension_coordinates(
        &self,
        challenge_tag: ProofChallengeTag,
        modulus: u64,
        coordinate_count: u16,
    ) -> Result<Vec<u64>, ProofTranscriptError> {
        if coordinate_count == 0 {
            return Err(ProofTranscriptError::InvalidCoordinateCount);
        }
        let canonical_tag =
            challenge_tag.canonical_tag(self.application_statement_schema_identifier);
        let mut challenge_stream = ChallengeByteStream::new(self.state, canonical_tag);
        let mut coordinates = Vec::with_capacity(usize::from(coordinate_count));
        for _ in 0..coordinate_count {
            coordinates.push(sample_modulo_from_stream(&mut challenge_stream, modulus)?);
        }
        Ok(coordinates)
    }

    pub fn sample_distinct_deep_points(
        &self,
        point_count: u16,
        modulus: u64,
        coordinate_count: u16,
        excluded_points: &[Vec<u64>],
    ) -> Result<Vec<Vec<u64>>, ProofTranscriptError> {
        if modulus == 0 {
            return Err(ProofTranscriptError::InvalidModulus);
        }
        if coordinate_count == 0 {
            return Err(ProofTranscriptError::InvalidCoordinateCount);
        }

        let mut occupied_points = BTreeSet::new();
        for point in excluded_points {
            if point.len() != usize::from(coordinate_count)
                || point.iter().any(|coordinate| *coordinate >= modulus)
                || !occupied_points.insert(point.clone())
            {
                return Err(ProofTranscriptError::InvalidExcludedPoint);
            }
        }
        if extension_field_cardinality(modulus, coordinate_count).is_some_and(|cardinality| {
            u128::try_from(occupied_points.len())
                .ok()
                .and_then(|excluded_count| cardinality.checked_sub(excluded_count))
                .is_none_or(|available_count| u128::from(point_count) > available_count)
        }) {
            return Err(ProofTranscriptError::PointCardinalityExceeded);
        }

        let mut points = Vec::with_capacity(usize::from(point_count));
        for point_ordinal in 0..point_count {
            let canonical_tag = ProofChallengeTag::DeepPoint { point_ordinal }
                .canonical_tag(self.application_statement_schema_identifier);
            let mut challenge_stream = ChallengeByteStream::new(self.state, canonical_tag);
            loop {
                let mut point = Vec::with_capacity(usize::from(coordinate_count));
                for _ in 0..coordinate_count {
                    point.push(sample_modulo_from_stream(&mut challenge_stream, modulus)?);
                }
                if occupied_points.insert(point.clone()) {
                    points.push(point);
                    break;
                }
            }
        }
        Ok(points)
    }

    pub fn sample_distinct_query_representatives(
        &self,
        unique_query_count: u32,
        representative_set_cardinality: u64,
    ) -> Result<Vec<u64>, ProofTranscriptError> {
        if representative_set_cardinality == 0 {
            return Err(ProofTranscriptError::InvalidModulus);
        }
        if u64::from(unique_query_count) > representative_set_cardinality {
            return Err(ProofTranscriptError::QueryCardinalityExceeded);
        }

        let mut representatives = BTreeSet::new();
        for query_ordinal in 0..unique_query_count {
            let canonical_tag = ProofChallengeTag::QueryRepresentative { query_ordinal }
                .canonical_tag(self.application_statement_schema_identifier);
            let mut challenge_stream = ChallengeByteStream::new(self.state, canonical_tag);
            loop {
                let representative = sample_modulo_from_stream(
                    &mut challenge_stream,
                    representative_set_cardinality,
                )?;
                if representatives.insert(representative) {
                    break;
                }
            }
        }
        Ok(representatives.into_iter().collect())
    }
}

fn extension_field_cardinality(modulus: u64, coordinate_count: u16) -> Option<u128> {
    let mut cardinality = 1u128;
    for _ in 0..coordinate_count {
        cardinality = cardinality.checked_mul(u128::from(modulus))?;
    }
    Some(cardinality)
}

struct ChallengeByteStream {
    block: [u8; Hash512::BYTE_LENGTH],
    block_byte_offset: usize,
    canonical_challenge_tag: String,
    next_squeeze_counter: u64,
    state: Hash512,
    squeeze_counter_exhausted: bool,
}

impl ChallengeByteStream {
    fn new(state: Hash512, canonical_challenge_tag: String) -> Self {
        Self {
            block: [0u8; Hash512::BYTE_LENGTH],
            block_byte_offset: Hash512::BYTE_LENGTH,
            canonical_challenge_tag,
            next_squeeze_counter: 0,
            state,
            squeeze_counter_exhausted: false,
        }
    }

    fn read_candidate(&mut self, byte_length: usize) -> Result<u64, ProofTranscriptError> {
        let mut candidate = 0u64;
        for byte_ordinal in 0..byte_length {
            let byte = self.read_byte()?;
            candidate |= u64::from(byte) << (byte_ordinal * 8);
        }
        Ok(candidate)
    }

    fn read_byte(&mut self) -> Result<u8, ProofTranscriptError> {
        if self.block_byte_offset == Hash512::BYTE_LENGTH {
            self.refill()?;
        }
        let byte = self.block[self.block_byte_offset];
        self.block_byte_offset += 1;
        Ok(byte)
    }

    fn refill(&mut self) -> Result<(), ProofTranscriptError> {
        if self.squeeze_counter_exhausted {
            return Err(ProofTranscriptError::CounterExhausted);
        }
        self.block = hash512(
            SQUEEZE_TRANSCRIPT_DOMAIN,
            &[
                CanonicalItem::hash512(self.state.into_bytes()),
                CanonicalItem::ascii(&self.canonical_challenge_tag)?,
                CanonicalItem::unsigned64(self.next_squeeze_counter),
            ],
        )?
        .into_bytes();
        self.block_byte_offset = 0;
        if self.next_squeeze_counter == u64::MAX {
            self.squeeze_counter_exhausted = true;
        } else {
            self.next_squeeze_counter += 1;
        }
        Ok(())
    }
}

fn sample_modulo_from_stream(
    challenge_stream: &mut ChallengeByteStream,
    modulus: u64,
) -> Result<u64, ProofTranscriptError> {
    if modulus == 0 {
        return Err(ProofTranscriptError::InvalidModulus);
    }
    let bit_length = u64::BITS - modulus.leading_zeros();
    let candidate_byte_length =
        usize::try_from(bit_length.div_ceil(8)).expect("a u64 challenge width always fits usize");
    let candidate_space_size = 1u128 << (candidate_byte_length * 8);
    let modulus_u128 = u128::from(modulus);
    let acceptance_limit = candidate_space_size / modulus_u128 * modulus_u128;

    loop {
        let candidate = challenge_stream.read_candidate(candidate_byte_length)?;
        if u128::from(candidate) < acceptance_limit {
            return Ok(candidate % modulus);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER;

    fn proof_header(statement_schema_identifier: u16) -> Vec<u8> {
        let statement = CanonicalTuple::new(
            statement_schema_identifier,
            1,
            vec![CanonicalItem::unsigned16(7)],
        )
        .encode()
        .expect("statement encodes");
        ProofObjectHeader {
            canonical_application_statement: statement,
        }
        .encode(&CanonicalDecodeLimits::default())
        .expect("proof header encodes")
    }

    fn transcript() -> CanonicalProofTranscript {
        CanonicalProofTranscript::new(
            Hash512::from_bytes([0x5a; Hash512::BYTE_LENGTH]),
            ProofFamily::BallotValidity.statement_schema_identifier(),
            &proof_header(ProofFamily::BallotValidity.statement_schema_identifier()),
            &CanonicalDecodeLimits::default(),
        )
        .expect("transcript initializes")
    }

    #[test]
    fn initialization_and_absorption_match_the_canonical_hash_chain() {
        let suite_identifier = Hash512::from_bytes([0x5a; Hash512::BYTE_LENGTH]);
        let statement_schema_identifier = ProofFamily::BallotValidity.statement_schema_identifier();
        let header = proof_header(statement_schema_identifier);
        let expected_initial = hash512(
            INITIAL_TRANSCRIPT_DOMAIN,
            &[
                CanonicalItem::unsigned16(FOUNDATION_PROFILE.protocol_version),
                CanonicalItem::hash512(suite_identifier.into_bytes()),
                CanonicalItem::unsigned16(statement_schema_identifier),
                CanonicalItem::variable_bytes(&header).expect("header item"),
            ],
        )
        .expect("initial hash");
        let mut transcript = CanonicalProofTranscript::new(
            suite_identifier,
            statement_schema_identifier,
            &header,
            &CanonicalDecodeLimits::default(),
        )
        .expect("transcript initializes");
        assert_eq!(transcript.state(), expected_initial);

        let root = Hash512::from_bytes([0x7c; Hash512::BYTE_LENGTH]);
        transcript
            .absorb_root(ProofRoundTag::BaseRoot { tree_ordinal: 2 }, root)
            .expect("root absorbs");
        let expected_absorbed = hash512(
            ABSORB_TRANSCRIPT_DOMAIN,
            &[
                CanonicalItem::hash512(expected_initial.into_bytes()),
                CanonicalItem::ascii("proof/1302/base-root/0002").expect("round tag"),
                CanonicalItem::variable_bytes(root.as_bytes()).expect("root bytes"),
            ],
        )
        .expect("absorbed hash");
        assert_eq!(transcript.state(), expected_absorbed);
        assert_eq!(
            transcript.absorb_round(ProofRoundTag::DeepValues, &[]),
            Err(ProofTranscriptError::EmptyRoundMessage)
        );
    }

    #[test]
    fn application_statement_and_header_must_match() {
        let limits = CanonicalDecodeLimits::default();
        let suite_identifier = Hash512::from_bytes([0u8; Hash512::BYTE_LENGTH]);
        assert_eq!(
            CanonicalProofTranscript::new(
                suite_identifier,
                ProofFamily::BallotValidity.statement_schema_identifier(),
                &proof_header(ProofFamily::PublicKeyShare.statement_schema_identifier()),
                &limits,
            ),
            Err(ProofTranscriptError::InvalidApplicationStatement)
        );
        assert_eq!(
            CanonicalProofTranscript::new(suite_identifier, 0xffff, &proof_header(0xffff), &limits,),
            Err(ProofTranscriptError::InvalidApplicationStatement)
        );
        let malformed = CanonicalTuple::new(PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER, 1, Vec::new())
            .encode()
            .expect("malformed header still has canonical tuple framing");
        assert!(matches!(
            CanonicalProofTranscript::new(
                suite_identifier,
                ProofFamily::BallotValidity.statement_schema_identifier(),
                &malformed,
                &limits,
            ),
            Err(ProofTranscriptError::InvalidApplicationStatement)
        ));
    }

    #[test]
    fn rejection_sampling_matches_the_declared_little_endian_stream() {
        let transcript = transcript();
        let challenge_tag = ProofChallengeTag::Alpha {
            modulus_ordinal: 3,
            challenge_ordinal: 4,
            unit_ordinal: 5,
        };
        let canonical_tag = "proof/1302/alpha/0003/0004/0005";
        let modulus = (1u64 << 63) + 1;
        let mut reference_stream =
            ChallengeByteStream::new(transcript.state(), canonical_tag.to_owned());
        let expected = sample_modulo_from_stream(&mut reference_stream, modulus)
            .expect("reference sampling succeeds");
        assert_eq!(
            transcript
                .sample_modulo(challenge_tag, modulus)
                .expect("sampling succeeds"),
            expected
        );
        assert_eq!(
            transcript.sample_modulo(challenge_tag, 0),
            Err(ProofTranscriptError::InvalidModulus)
        );
    }

    #[test]
    fn extension_coordinates_continue_across_squeeze_blocks() {
        let transcript = transcript();
        let tag = ProofChallengeTag::OpeningBatch { claim_ordinal: 19 };
        let actual = transcript
            .sample_extension_coordinates(tag, 65_537, 40)
            .expect("extension coordinates sample");
        assert_eq!(actual.len(), 40);
        assert!(actual.iter().all(|coordinate| *coordinate < 65_537));

        let mut reference_stream = ChallengeByteStream::new(
            transcript.state(),
            "proof/1302/opening-batch/0013".to_owned(),
        );
        let expected = (0..40)
            .map(|_| sample_modulo_from_stream(&mut reference_stream, 65_537))
            .collect::<Result<Vec<_>, _>>()
            .expect("reference coordinates sample");
        assert_eq!(actual, expected);
        assert!(reference_stream.next_squeeze_counter >= 2);
        assert_eq!(
            transcript.sample_extension_coordinates(tag, 65_537, 0),
            Err(ProofTranscriptError::InvalidCoordinateCount)
        );
    }

    #[test]
    fn query_representatives_are_distinct_sorted_and_reject_oversubscription() {
        let transcript = transcript();
        let representatives = transcript
            .sample_distinct_query_representatives(127, 129)
            .expect("representatives sample");
        assert_eq!(representatives.len(), 127);
        assert!(representatives.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(representatives.iter().all(|value| *value < 129));
        assert_eq!(
            transcript.sample_distinct_query_representatives(130, 129),
            Err(ProofTranscriptError::QueryCardinalityExceeded)
        );
        assert_eq!(
            transcript.sample_distinct_query_representatives(0, 0),
            Err(ProofTranscriptError::InvalidModulus)
        );
    }

    #[test]
    fn deep_points_are_distinct_and_continue_after_excluded_candidates() {
        let transcript = transcript();
        let all_but_one_point = vec![vec![0, 0], vec![0, 1], vec![1, 0]];
        assert_eq!(
            transcript
                .sample_distinct_deep_points(1, 2, 2, &all_but_one_point)
                .expect("the sole available point samples"),
            vec![vec![1, 1]]
        );

        let excluded = vec![vec![0, 0]];
        let points = transcript
            .sample_distinct_deep_points(3, 3, 2, &excluded)
            .expect("deep points sample");
        assert_eq!(points.len(), 3);
        assert!(points.iter().all(|point| {
            point.len() == 2
                && point.iter().all(|coordinate| *coordinate < 3)
                && !excluded.contains(point)
        }));
        assert_eq!(points.iter().collect::<BTreeSet<_>>().len(), points.len());
    }

    #[test]
    fn deep_point_sampling_rejects_invalid_sets_and_exhausted_domains() {
        let transcript = transcript();
        assert_eq!(
            transcript.sample_distinct_deep_points(1, 0, 2, &[]),
            Err(ProofTranscriptError::InvalidModulus)
        );
        assert_eq!(
            transcript.sample_distinct_deep_points(1, 2, 0, &[]),
            Err(ProofTranscriptError::InvalidCoordinateCount)
        );
        assert_eq!(
            transcript.sample_distinct_deep_points(1, 2, 2, &[vec![2, 0]]),
            Err(ProofTranscriptError::InvalidExcludedPoint)
        );
        assert_eq!(
            transcript.sample_distinct_deep_points(1, 2, 2, &[vec![0, 0], vec![0, 0]]),
            Err(ProofTranscriptError::InvalidExcludedPoint)
        );
        assert_eq!(
            transcript.sample_distinct_deep_points(
                1,
                2,
                2,
                &[vec![0, 0], vec![0, 1], vec![1, 0], vec![1, 1]],
            ),
            Err(ProofTranscriptError::PointCardinalityExceeded)
        );
        assert_eq!(
            transcript.sample_distinct_deep_points(5, 2, 2, &[]),
            Err(ProofTranscriptError::PointCardinalityExceeded)
        );
    }

    #[test]
    fn final_squeeze_counter_block_is_available_exactly_once() {
        let mut stream = ChallengeByteStream::new(
            Hash512::from_bytes([1u8; Hash512::BYTE_LENGTH]),
            "proof/1302/fri-fold/0000".to_owned(),
        );
        stream.next_squeeze_counter = u64::MAX;
        let final_block = (0..Hash512::BYTE_LENGTH)
            .map(|_| stream.read_byte())
            .collect::<Result<Vec<_>, _>>()
            .expect("final counter block is readable");
        assert_eq!(final_block.len(), Hash512::BYTE_LENGTH);
        assert_eq!(
            stream.read_byte(),
            Err(ProofTranscriptError::CounterExhausted)
        );
    }
}
