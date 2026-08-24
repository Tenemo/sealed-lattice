use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use super::{TallyPreparationContext, TallyPreparationError, TallyPreparationGeometry};

pub(crate) const SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH: usize = 64 * 1024;
const SEEDED_RANDOM_TAPE_KEY_BYTE_LENGTH: usize = 32;
const SEEDED_RANDOM_TAPE_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/tally-preparation-seeded-random-tape/v1";

pub(crate) trait TallyPreparationRandomTapeSource {
    fn total_byte_length(&self) -> usize;

    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), TallyPreparationError>;

    fn ensure_finished(&self) -> Result<(), TallyPreparationError>;
}

pub(crate) struct ExplicitJointRandomTape<'tape> {
    participant_tapes: Vec<&'tape [u8]>,
    total_byte_length: usize,
    consumed_byte_length: usize,
}

impl<'tape> ExplicitJointRandomTape<'tape> {
    pub(crate) fn new(
        participant_tapes: &[&'tape [u8]],
        participant_count: u16,
        geometry: TallyPreparationGeometry,
    ) -> Result<Self, TallyPreparationError> {
        let expected_participant_count = usize::from(participant_count);
        if participant_tapes.len() != expected_participant_count {
            return Err(TallyPreparationError::RandomTapeParticipantCountMismatch {
                expected: expected_participant_count,
                actual: participant_tapes.len(),
            });
        }
        let total_byte_length = geometry.direct_joint_random_tape_byte_length_usize()?;
        for (participant_position, tape) in participant_tapes.iter().enumerate() {
            if tape.len() != total_byte_length {
                return Err(TallyPreparationError::RandomTapeByteLengthMismatch {
                    participant_position,
                    expected: total_byte_length,
                    actual: tape.len(),
                });
            }
        }

        Ok(Self {
            participant_tapes: participant_tapes.to_vec(),
            total_byte_length,
            consumed_byte_length: 0,
        })
    }
}

impl TallyPreparationRandomTapeSource for ExplicitJointRandomTape<'_> {
    fn total_byte_length(&self) -> usize {
        self.total_byte_length
    }

    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), TallyPreparationError> {
        let end = self
            .consumed_byte_length
            .checked_add(destination.len())
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if end > self.total_byte_length {
            return Err(TallyPreparationError::RandomTapeExhausted);
        }
        destination.fill(0);
        for tape in &self.participant_tapes {
            for (output_byte, tape_byte) in destination
                .iter_mut()
                .zip(&tape[self.consumed_byte_length..end])
            {
                *output_byte ^= *tape_byte;
            }
        }
        self.consumed_byte_length = end;
        Ok(())
    }

    fn ensure_finished(&self) -> Result<(), TallyPreparationError> {
        if self.consumed_byte_length != self.total_byte_length {
            return Err(TallyPreparationError::RandomTapeNotFullyConsumed {
                expected: self.total_byte_length,
                consumed: self.consumed_byte_length,
            });
        }
        Ok(())
    }
}

/// Conditional seeded expansion model for the same canonical random tape.
///
/// The model assumes all participant seeds were irrevocably fixed before any
/// seed was disclosed. A real protocol must compile that ordering and charge
/// the exact quantum-PRF advantage of these KMAC256 XOF calls. This type alone
/// establishes neither premise.
pub(crate) struct SeededJointRandomTape {
    joint_seed: Zeroizing<[u8; SEEDED_RANDOM_TAPE_KEY_BYTE_LENGTH]>,
    context_identity: [u8; 64],
    total_byte_length: usize,
    consumed_byte_length: usize,
    current_block_position: usize,
    current_block: Zeroizing<Vec<u8>>,
}

impl SeededJointRandomTape {
    pub(crate) fn new(
        participant_seeds: &[[u8; SEEDED_RANDOM_TAPE_KEY_BYTE_LENGTH]],
        context: TallyPreparationContext,
        geometry: TallyPreparationGeometry,
    ) -> Result<Self, TallyPreparationError> {
        let expected_seed_count = usize::from(context.participant_count());
        if participant_seeds.len() != expected_seed_count {
            return Err(TallyPreparationError::RandomSeedCountMismatch {
                expected: expected_seed_count,
                actual: participant_seeds.len(),
            });
        }
        if geometry.participant_count != u64::from(context.participant_count()) {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let mut joint_seed = Zeroizing::new([0_u8; SEEDED_RANDOM_TAPE_KEY_BYTE_LENGTH]);
        for seed in participant_seeds {
            for (joint_byte, seed_byte) in joint_seed.iter_mut().zip(seed) {
                *joint_byte ^= *seed_byte;
            }
        }
        let total_byte_length = geometry.direct_joint_random_tape_byte_length_usize()?;
        Ok(Self {
            joint_seed,
            context_identity: context.identity().into_bytes(),
            total_byte_length,
            consumed_byte_length: 0,
            current_block_position: SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH,
            current_block: Zeroizing::new(vec![0_u8; SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH]),
        })
    }

    fn refill_block(&mut self) -> Result<(), TallyPreparationError> {
        let block_index = self.consumed_byte_length / SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH;
        let block_index =
            u64::try_from(block_index).map_err(|_| TallyPreparationError::IntegerConversion)?;
        let total_byte_length = u64::try_from(self.total_byte_length)
            .map_err(|_| TallyPreparationError::IntegerConversion)?;
        self.current_block.fill(0);
        let mut kmac = Kmac::v256(self.joint_seed.as_ref(), SEEDED_RANDOM_TAPE_CUSTOMIZATION);
        update_framed(&mut kmac, &self.context_identity);
        update_framed(&mut kmac, &total_byte_length.to_le_bytes());
        update_framed(&mut kmac, &block_index.to_le_bytes());
        kmac.finalize(self.current_block.as_mut());
        self.current_block_position = 0;
        Ok(())
    }
}

impl TallyPreparationRandomTapeSource for SeededJointRandomTape {
    fn total_byte_length(&self) -> usize {
        self.total_byte_length
    }

    fn fill_exact(&mut self, mut destination: &mut [u8]) -> Result<(), TallyPreparationError> {
        let end = self
            .consumed_byte_length
            .checked_add(destination.len())
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if end > self.total_byte_length {
            return Err(TallyPreparationError::RandomTapeExhausted);
        }

        while !destination.is_empty() {
            if self.current_block_position == SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH {
                self.refill_block()?;
            }
            let available = SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH - self.current_block_position;
            let copied_byte_length = available.min(destination.len());
            let block_end = self.current_block_position + copied_byte_length;
            destination[..copied_byte_length]
                .copy_from_slice(&self.current_block[self.current_block_position..block_end]);
            self.current_block_position = block_end;
            self.consumed_byte_length += copied_byte_length;
            destination = &mut destination[copied_byte_length..];
        }
        Ok(())
    }

    fn ensure_finished(&self) -> Result<(), TallyPreparationError> {
        if self.consumed_byte_length != self.total_byte_length {
            return Err(TallyPreparationError::RandomTapeNotFullyConsumed {
                expected: self.total_byte_length,
                consumed: self.consumed_byte_length,
            });
        }
        Ok(())
    }
}

fn update_framed(kmac: &mut Kmac, part: &[u8]) {
    kmac.update(&(part.len() as u64).to_le_bytes());
    kmac.update(part);
}
