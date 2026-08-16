//! Attempt-bound private randomness for compact proof generation.
//!
//! Two coordinate-separated seeds are drawn from action-private randomness:
//! the hiding-argument coordinate drives bounded WHIR field sampling and the
//! proof-salt coordinate supports random-access response salts. Public
//! transcript bytes never seed either stream.

use core::{convert::Infallible, mem::size_of};

use rand::{TryCryptoRng, TryRng};
use tiny_keccak::Kmac;
use zeroize::Zeroizing;

use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    compact_proof_wire::COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
    compact_response_generation::CompactOwnedResponseLeaf,
    prover::{CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource},
};
use crate::foundation::SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT;

pub(crate) const COMPACT_PRIVATE_SEED_BYTE_LENGTH: usize = 64;
pub(crate) const COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH: usize = 64;
pub(crate) const COMPACT_WHIR_RANDOM_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/compact-proof/whir-private-randomness/v1";
pub(crate) const COMPACT_PRIVATE_LEAF_SALT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/compact-proof/private-leaf-salt/v1";
pub(crate) const COMPACT_FIAT_SHAMIR_ROUND_SALT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/compact-proof/fiat-shamir-round-salt/v1";
pub(crate) const COMPACT_GENERATION_PRIVATE_SEED_COORDINATES: [CommonProofPrivateCoinCoordinate;
    2] = [
    CommonProofPrivateCoinCoordinate::hiding_argument(),
    CommonProofPrivateCoinCoordinate::proof_salt(),
];
const COMPACT_GENERATION_RANDOMNESS_CURSOR_MAGIC: [u8; 8] = *b"SLCPRN02";
const COMPACT_GENERATION_RANDOMNESS_CURSOR_VERSION: u16 = 2;
pub(crate) const COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH: usize = 56;
const COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH_U32: u32 = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactGenerationRandomnessCursorError {
    NonCanonicalCursor,
    WrongLiveCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactGenerationRandomnessError {
    FieldSamplerExhausted,
    UnsupportedRandomAccess,
}

pub(crate) struct CompactGenerationAttemptRandomness {
    proof_attempt_identifier: [u8; 32],
    response_salt_seed: Zeroizing<[u8; COMPACT_PRIVATE_SEED_BYTE_LENGTH]>,
    whir_random_source: CompactWhirRandomSource,
}

pub(crate) struct CompactWhirRandomSource {
    private_seed: Zeroizing<[u8; COMPACT_PRIVATE_SEED_BYTE_LENGTH]>,
    next_block_ordinal: u64,
    buffered_block: Zeroizing<[u8; COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH]>,
    next_buffered_byte_ordinal: usize,
    consumed_byte_count: u64,
    field_sampler_exhausted: bool,
    unsupported_random_access: bool,
}

impl CompactGenerationAttemptRandomness {
    pub(crate) fn from_private_coins<Coins: CommonProofPrivateCoinSource>(
        private_coins: &mut Coins,
        proof_attempt_identifier: [u8; 32],
    ) -> Result<Self, Coins::Error> {
        let [whir_seed_coordinate, response_salt_seed_coordinate] =
            COMPACT_GENERATION_PRIVATE_SEED_COORDINATES;
        let whir_random_seed = sample_compact_private_seed(private_coins, whir_seed_coordinate)?;
        let response_salt_seed =
            sample_compact_private_seed(private_coins, response_salt_seed_coordinate)?;
        Ok(Self {
            proof_attempt_identifier,
            response_salt_seed,
            whir_random_source: CompactWhirRandomSource::new(whir_random_seed),
        })
    }

    pub(crate) const fn proof_attempt_identifier(&self) -> [u8; 32] {
        self.proof_attempt_identifier
    }

    pub(crate) const fn whir_random_source_mut(&mut self) -> &mut CompactWhirRandomSource {
        &mut self.whir_random_source
    }

    pub(crate) fn ensure_field_sampling_valid(
        &self,
    ) -> Result<(), CompactGenerationRandomnessError> {
        if self.whir_random_source.unsupported_random_access {
            Err(CompactGenerationRandomnessError::UnsupportedRandomAccess)
        } else if self.whir_random_source.field_sampler_exhausted {
            Err(CompactGenerationRandomnessError::FieldSamplerExhausted)
        } else {
            Ok(())
        }
    }

    pub(crate) fn private_leaf_salt(
        &self,
        response_ordinal: u32,
        leaf_count: u64,
        leaf_ordinal: u64,
        leaf: &CompactOwnedResponseLeaf,
    ) -> [u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
        let value_kind = match leaf {
            CompactOwnedResponseLeaf::BaseField(_) => [0_u8],
            CompactOwnedResponseLeaf::ExtensionField(_) => [1_u8],
            CompactOwnedResponseLeaf::Padding => [2_u8],
        };
        let field_element_count = leaf
            .field_element_count()
            .expect("an owned compact response leaf has a representable element count")
            .to_le_bytes();
        let mut salt = [0_u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
        fill_compact_kmac(
            self.response_salt_seed.as_ref(),
            COMPACT_PRIVATE_LEAF_SALT_CUSTOMIZATION,
            &[
                &self.proof_attempt_identifier,
                &response_ordinal.to_le_bytes(),
                &leaf_count.to_le_bytes(),
                &leaf_ordinal.to_le_bytes(),
                &value_kind,
                &field_element_count,
            ],
            &mut salt,
        );
        salt
    }

    pub(crate) fn fiat_shamir_round_salt(
        &self,
        response_ordinal: u32,
    ) -> [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH] {
        let mut salt = [0_u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH];
        fill_compact_kmac(
            self.response_salt_seed.as_ref(),
            COMPACT_FIAT_SHAMIR_ROUND_SALT_CUSTOMIZATION,
            &[
                &self.proof_attempt_identifier,
                &response_ordinal.to_le_bytes(),
            ],
            &mut salt,
        );
        salt
    }

    /// Encodes the attempt-bound construction cursor without serializing either
    /// private seed. Restoration deterministically replays from the action root
    /// and must arrive at this exact WHIR byte position.
    pub(crate) fn canonical_checkpoint_cursor_bytes(
        &self,
    ) -> [u8; COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH] {
        let mut canonical_bytes = [0_u8; COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH];
        canonical_bytes[..8].copy_from_slice(&COMPACT_GENERATION_RANDOMNESS_CURSOR_MAGIC);
        canonical_bytes[8..10]
            .copy_from_slice(&COMPACT_GENERATION_RANDOMNESS_CURSOR_VERSION.to_le_bytes());
        canonical_bytes[12..16]
            .copy_from_slice(&COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH_U32.to_le_bytes());
        canonical_bytes[16..48].copy_from_slice(&self.proof_attempt_identifier);
        canonical_bytes[48..]
            .copy_from_slice(&self.whir_random_source.consumed_byte_count().to_le_bytes());
        canonical_bytes
    }

    /// Checks an authenticated cursor against the live replayed state. A
    /// cursor cannot seek or reconstruct the private stream by itself.
    pub(crate) fn validate_checkpoint_cursor_bytes(
        &self,
        canonical_cursor_bytes: &[u8],
    ) -> Result<(), CompactGenerationRandomnessCursorError> {
        if canonical_cursor_bytes.len() != COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH
            || canonical_cursor_bytes[..8] != COMPACT_GENERATION_RANDOMNESS_CURSOR_MAGIC
            || u16::from_le_bytes(
                canonical_cursor_bytes[8..10]
                    .try_into()
                    .expect("the cursor length was checked"),
            ) != COMPACT_GENERATION_RANDOMNESS_CURSOR_VERSION
            || u16::from_le_bytes(
                canonical_cursor_bytes[10..12]
                    .try_into()
                    .expect("the cursor length was checked"),
            ) != 0
            || u32::from_le_bytes(
                canonical_cursor_bytes[12..16]
                    .try_into()
                    .expect("the cursor length was checked"),
            ) != COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH_U32
        {
            return Err(CompactGenerationRandomnessCursorError::NonCanonicalCursor);
        }
        if canonical_cursor_bytes != self.canonical_checkpoint_cursor_bytes() {
            return Err(CompactGenerationRandomnessCursorError::WrongLiveCursor);
        }
        Ok(())
    }
}

impl CompactWhirRandomSource {
    fn new(private_seed: Zeroizing<[u8; COMPACT_PRIVATE_SEED_BYTE_LENGTH]>) -> Self {
        Self {
            private_seed,
            next_block_ordinal: 0,
            buffered_block: Zeroizing::new([0_u8; COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH]),
            next_buffered_byte_ordinal: COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH,
            consumed_byte_count: 0,
            field_sampler_exhausted: false,
            unsupported_random_access: false,
        }
    }

    const fn consumed_byte_count(&self) -> u64 {
        self.consumed_byte_count
    }

    fn refill(&mut self) {
        let block_ordinal = self.next_block_ordinal;
        self.next_block_ordinal = self
            .next_block_ordinal
            .checked_add(1)
            .expect("the compact WHIR random stream cannot exhaust its block ordinal");
        fill_compact_kmac(
            self.private_seed.as_ref(),
            COMPACT_WHIR_RANDOM_CUSTOMIZATION,
            &[&block_ordinal.to_le_bytes()],
            self.buffered_block.as_mut(),
        );
        self.next_buffered_byte_ordinal = 0;
    }

    fn fill(&mut self, mut destination: &mut [u8]) {
        while !destination.is_empty() {
            if self.next_buffered_byte_ordinal == COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH {
                self.refill();
            }
            let available_byte_count =
                COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH - self.next_buffered_byte_ordinal;
            let copied_byte_count = available_byte_count.min(destination.len());
            let buffered_end = self.next_buffered_byte_ordinal + copied_byte_count;
            destination[..copied_byte_count].copy_from_slice(
                &self.buffered_block[self.next_buffered_byte_ordinal..buffered_end],
            );
            self.next_buffered_byte_ordinal = buffered_end;
            self.consumed_byte_count = self
                .consumed_byte_count
                .checked_add(
                    u64::try_from(copied_byte_count)
                        .expect("one compact WHIR random block fits u64"),
                )
                .expect("the compact WHIR random stream cannot exceed u64 bytes");
            destination = &mut destination[copied_byte_count..];
        }
    }

    fn next_raw_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; size_of::<u64>()];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

impl TryRng for CompactWhirRandomSource {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.unsupported_random_access = true;
        let mut bytes = [0_u8; size_of::<u32>()];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let sampled = sample_bounded_canonical_base_field_value(|| self.next_raw_u64());
        if let Some(value) = sampled {
            Ok(value)
        } else {
            self.field_sampler_exhausted = true;
            // `rand::Rng` is infallible. Production callers check the retained
            // exhaustion flag before accepting or emitting the sampled batch.
            Ok(0)
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        if !destination.is_empty() {
            self.unsupported_random_access = true;
        }
        self.fill(destination);
        Ok(())
    }
}

impl TryCryptoRng for CompactWhirRandomSource {}

fn sample_compact_private_seed<Coins: CommonProofPrivateCoinSource>(
    private_coins: &mut Coins,
    coordinate: CommonProofPrivateCoinCoordinate,
) -> Result<Zeroizing<[u8; COMPACT_PRIVATE_SEED_BYTE_LENGTH]>, Coins::Error> {
    let mut seed = Zeroizing::new([0_u8; COMPACT_PRIVATE_SEED_BYTE_LENGTH]);
    private_coins.fill_raw_bytes(coordinate, seed.as_mut())?;
    Ok(seed)
}

fn sample_bounded_canonical_base_field_value(
    mut next_candidate: impl FnMut() -> u64,
) -> Option<u64> {
    for _candidate_ordinal in 0..SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT {
        let candidate = next_candidate();
        if candidate < PROOF_BASE_FIELD_MODULUS {
            return Some(candidate);
        }
    }
    None
}

fn fill_compact_kmac(
    key: &[u8],
    customization: &[u8],
    framed_parts: &[&[u8]],
    destination: &mut [u8],
) {
    let mut kmac = Kmac::v256(key, customization);
    for part in framed_parts {
        tiny_keccak::Hasher::update(&mut kmac, &(part.len() as u64).to_le_bytes());
        tiny_keccak::Hasher::update(&mut kmac, part);
    }
    tiny_keccak::Hasher::finalize(kmac, destination);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeterministicPrivateCoins {
        next_byte: u8,
        observed_raw_fills: Vec<(CommonProofPrivateCoinCoordinate, usize)>,
    }

    impl CommonProofPrivateCoinSource for DeterministicPrivateCoins {
        type Error = Infallible;

        fn sample_modulo(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            _modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            unreachable!("compact attempt seeds use raw coordinate bytes")
        }

        fn fill_raw_bytes(
            &mut self,
            coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.observed_raw_fills
                .push((coordinate, destination.len()));
            for byte in destination {
                *byte = self.next_byte;
                self.next_byte = self.next_byte.wrapping_add(1);
            }
            Ok(())
        }

        fn replay_modulo_samples(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            _modulus: u64,
            _maximum_candidate_draws_per_output: u32,
            _destination: &mut [u64],
        ) -> Result<(), Self::Error> {
            unreachable!("the seed construction does not replay during generation")
        }
    }

    #[test]
    fn attempt_and_response_coordinates_separate_every_random_output() {
        let mut first_coins = deterministic_private_coins();
        let mut replayed_coins = deterministic_private_coins();
        let mut first =
            CompactGenerationAttemptRandomness::from_private_coins(&mut first_coins, [0x11; 32])
                .expect("the compact attempt randomness derives");
        let mut replayed =
            CompactGenerationAttemptRandomness::from_private_coins(&mut replayed_coins, [0x11; 32])
                .expect("the compact attempt randomness rederives");
        assert_eq!(
            first_coins.observed_raw_fills,
            vec![
                (
                    CommonProofPrivateCoinCoordinate::hiding_argument(),
                    COMPACT_PRIVATE_SEED_BYTE_LENGTH,
                ),
                (
                    CommonProofPrivateCoinCoordinate::proof_salt(),
                    COMPACT_PRIVATE_SEED_BYTE_LENGTH,
                ),
            ],
        );
        assert_eq!(first.try_next_u64(), replayed.try_next_u64());
        first
            .ensure_field_sampling_valid()
            .expect("the deterministic KMAC field sampler remains live");

        let leaf = CompactOwnedResponseLeaf::base_field(vec![
            super::super::ProofBaseFieldElement::from_canonical(7)
                .expect("the test leaf is canonical"),
        ]);
        let first_salt = first.private_leaf_salt(0, 8, 3, &leaf);
        assert_eq!(first_salt, replayed.private_leaf_salt(0, 8, 3, &leaf));
        assert_ne!(first_salt, first.private_leaf_salt(0, 8, 4, &leaf));
        assert_ne!(first_salt, first.private_leaf_salt(1, 8, 3, &leaf));
        assert_ne!(
            first.fiat_shamir_round_salt(0),
            first.fiat_shamir_round_salt(1)
        );
    }

    #[test]
    fn checkpoint_cursor_is_canonical_attempt_bound_and_live() {
        let mut first_coins = deterministic_private_coins();
        let mut replayed_coins = deterministic_private_coins();
        let mut changed_attempt_coins = deterministic_private_coins();
        let mut first =
            CompactGenerationAttemptRandomness::from_private_coins(&mut first_coins, [0x31; 32])
                .expect("the first compact attempt randomness derives");
        let mut replayed =
            CompactGenerationAttemptRandomness::from_private_coins(&mut replayed_coins, [0x31; 32])
                .expect("the replayed compact attempt randomness derives");
        let changed_attempt = CompactGenerationAttemptRandomness::from_private_coins(
            &mut changed_attempt_coins,
            [0x32; 32],
        )
        .expect("the changed compact attempt randomness derives");

        let initial_cursor = first.canonical_checkpoint_cursor_bytes();
        assert_eq!(initial_cursor, replayed.canonical_checkpoint_cursor_bytes());
        assert_eq!(
            u64::from_le_bytes(
                initial_cursor[48..]
                    .try_into()
                    .expect("fixed cursor length")
            ),
            0
        );
        assert_ne!(
            initial_cursor,
            changed_attempt.canonical_checkpoint_cursor_bytes()
        );
        first
            .validate_checkpoint_cursor_bytes(&initial_cursor)
            .expect("the live initial cursor validates");

        let mut random_bytes = [0_u8; COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH + 1];
        first
            .whir_random_source_mut()
            .try_fill_bytes(&mut random_bytes)
            .expect("the KMAC stream is infallible");
        assert_eq!(
            first.ensure_field_sampling_valid(),
            Err(CompactGenerationRandomnessError::UnsupportedRandomAccess),
        );
        let advanced_cursor = first.canonical_checkpoint_cursor_bytes();
        assert_ne!(advanced_cursor, initial_cursor);
        assert_eq!(
            u64::from_le_bytes(
                advanced_cursor[48..]
                    .try_into()
                    .expect("fixed cursor length"),
            ),
            65
        );
        assert_eq!(
            first.validate_checkpoint_cursor_bytes(&initial_cursor),
            Err(CompactGenerationRandomnessCursorError::WrongLiveCursor)
        );
        replayed
            .whir_random_source_mut()
            .try_fill_bytes(&mut random_bytes)
            .expect("the replayed KMAC stream is infallible");
        replayed
            .validate_checkpoint_cursor_bytes(&advanced_cursor)
            .expect("the replayed cursor reaches the same live byte position");

        for changed_byte_ordinal in [0_usize, 8, 10, 12, 16, 47, 48, 55] {
            let mut changed = advanced_cursor;
            changed[changed_byte_ordinal] ^= 1;
            assert!(
                first.validate_checkpoint_cursor_bytes(&changed).is_err(),
                "changed cursor byte {changed_byte_ordinal} must fail closed"
            );
        }
        assert_eq!(
            first.validate_checkpoint_cursor_bytes(&advanced_cursor[..55]),
            Err(CompactGenerationRandomnessCursorError::NonCanonicalCursor)
        );
        let mut extended = advanced_cursor.to_vec();
        extended.push(0);
        assert_eq!(
            first.validate_checkpoint_cursor_bytes(&extended),
            Err(CompactGenerationRandomnessCursorError::NonCanonicalCursor)
        );
        let mut superseded_cursor = advanced_cursor;
        superseded_cursor[..8].copy_from_slice(b"SLCPRN01");
        superseded_cursor[8..10].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            first.validate_checkpoint_cursor_bytes(&superseded_cursor),
            Err(CompactGenerationRandomnessCursorError::NonCanonicalCursor),
        );
    }

    impl CompactGenerationAttemptRandomness {
        fn try_next_u64(&mut self) -> u64 {
            self.whir_random_source
                .try_next_u64()
                .expect("the KMAC stream is infallible")
        }
    }

    fn deterministic_private_coins() -> DeterministicPrivateCoins {
        DeterministicPrivateCoins {
            next_byte: 1,
            observed_raw_fills: Vec::new(),
        }
    }

    #[test]
    fn field_sampling_accepts_canonical_values_and_refuses_at_the_exact_draw_ceiling() {
        let mut candidates = [u64::MAX, PROOF_BASE_FIELD_MODULUS, 17_u64].into_iter();
        assert_eq!(
            sample_bounded_canonical_base_field_value(|| {
                candidates.next().expect("the candidate list is sufficient")
            }),
            Some(17),
        );

        let mut attempted_draw_count = 0_u32;
        assert_eq!(
            sample_bounded_canonical_base_field_value(|| {
                attempted_draw_count += 1;
                u64::MAX
            }),
            None,
        );
        assert_eq!(
            attempted_draw_count,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        );
    }
}
