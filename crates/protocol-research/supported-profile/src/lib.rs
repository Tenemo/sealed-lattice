//! Sizes of every supported poll profile.
//!
//! A poll has 3 to 20 participants and 2 to 20 options. The tracked profile
//! table carries the parameters that the model owners search for, and its
//! correspondence test rebuilds it from them. Every other size follows from
//! the closed-form rules below.

use std::ops::RangeInclusive;

pub mod relation;

const TABLE: &[u8] = include_bytes!("../profiles.bin");
const MAGIC: &[u8; 4] = b"SPT1";
const RECORD_BYTES: usize = 30;
const PARAMETER_MAGIC: &[u8; 4] = b"SCP1";
const STATEMENT_MAGIC: &[u8; 4] = b"SCO2";

/// Ring degree of the FHE and share-encryption polynomials.
pub const DEGREE: usize = 65_536;
/// Ring degree of the auxiliary encryption.
pub const AUXILIARY_DEGREE: usize = 4_096;
/// FHE witness equations use limbs of this many bits.
pub const FHE_LIMB_BITS: usize = 96;
/// Gadget coordinates are digits of this many bits.
const GADGET_BASE_BITS: usize = 144;
/// Every score is between these values.
pub const MINIMUM_SCORE: usize = 1;
pub const MAXIMUM_SCORE: usize = 10;
/// FHE plaintexts are integers modulo this prime, which divides every
/// ciphertext modulus less one.
pub const PLAINTEXT_MODULUS: u32 = 65_537;
/// Auxiliary-encryption plaintexts are integers modulo this prime, which
/// divides the auxiliary modulus less one.
pub const AUXILIARY_PLAINTEXT_MODULUS: u32 = 257;
/// Setup polynomials of one gadget coordinate, in order: the encryption
/// common polynomial and key, the first relinearization key, the second
/// relinearization common polynomial and key, and the automorphism common
/// polynomial and key.
const GADGET_POLYNOMIALS: usize = 7;
/// The key components of a gadget coordinate. The others are public common
/// polynomials, which a contribution body does not carry.
const GADGET_KEY_COMPONENTS: [usize; 4] = [1, 2, 4, 6];
/// Nonzero coefficients of each FHE secret, share-encryption ephemeral and
/// auxiliary-encryption ephemeral; half of each support is +1 and half -1.
pub const FHE_SECRET_SUPPORT: usize = 1_024;
pub const SHARE_EPHEMERAL_SUPPORT: usize = 256;
pub const AUXILIARY_SECRET_SUPPORT: usize = 256;
/// Nonzero coefficients of each recipient's registration secret.
pub const RECIPIENT_SECRET_SUPPORT: usize = 256;
/// Share encryption scales each message by this prime factor of the share
/// modulus.
pub const SHARE_SCALE: u32 = 998_244_353;
/// Setup equations have signed 16-bit quotients and FHE carries and signed
/// 7-bit errors.
pub const SETUP_QUOTIENT_BITS: usize = 16;
pub const SETUP_FHE_CARRY_BITS: usize = 16;
pub const SETUP_ERROR_BITS: usize = 7;
/// Witness word columns hold sixteen bits.
pub const WORD_BITS: usize = 16;
/// Release equations split the target, the aggregate share, the release
/// noise and quotient and each output into limbs of this many bits, with
/// signed carries of the carry width.
pub const RELEASE_LIMB_BITS: usize = 48;
const RELEASE_CARRY_BITS: usize = 72;
/// The release relation's recipient-key and decoding equations split every
/// operand, and the one aggregate share, at a whole word.
pub const RELEASE_DECODING_LIMB_BITS: usize = 96;
/// The summed decryption error of every contributor's share is below 2^23.
const RELEASE_DECODING_ERROR_BITS: usize = 24;
const RELEASE_DECODING_CARRY_BITS: usize = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unsupported;

struct Table {
    share: &'static [u8],
    auxiliary: &'static [u8],
    fixed_sample_bits: usize,
    participants: RangeInclusive<usize>,
    options: RangeInclusive<usize>,
    records: &'static [u8],
}

// The correspondence test owns the table bytes, so a malformed table is a
// build defect rather than an input to refuse.
fn table() -> Table {
    assert_eq!(&TABLE[..4], MAGIC);
    let share_end = 5 + usize::from(TABLE[4]);
    let auxiliary_end = share_end + 1 + usize::from(TABLE[share_end]);
    let fixed_sample_bits = usize::from(u16::from_le_bytes([
        TABLE[auxiliary_end],
        TABLE[auxiliary_end + 1],
    ]));
    let bounds = &TABLE[auxiliary_end + 2..auxiliary_end + 6];
    let participants = usize::from(bounds[0])..=usize::from(bounds[1]);
    let options = usize::from(bounds[2])..=usize::from(bounds[3]);
    let records = &TABLE[auxiliary_end + 6..];
    assert_eq!(
        records.len(),
        participants.clone().count() * options.clone().count() * RECORD_BYTES
    );
    Table {
        share: &TABLE[5..share_end],
        auxiliary: &TABLE[share_end + 1..auxiliary_end],
        fixed_sample_bits,
        participants,
        options,
        records,
    }
}

/// A prime `odd_factor * 2^exponent + 1` with its Proth witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProthModulus {
    exponent: usize,
    odd_factor: u32,
    witness: u16,
}
impl ProthModulus {
    fn decode(bytes: &[u8]) -> Self {
        Self {
            exponent: usize::from(u16::from_le_bytes([bytes[0], bytes[1]])),
            odd_factor: u32::from_le_bytes(bytes[2..6].try_into().unwrap()),
            witness: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }
    pub fn exponent(self) -> usize {
        self.exponent
    }
    pub fn odd_factor(self) -> u32 {
        self.odd_factor
    }
    pub fn witness(self) -> u16 {
        self.witness
    }
    pub fn bits(self) -> usize {
        self.exponent + (u32::BITS - self.odd_factor.leading_zeros()) as usize
    }
    pub fn byte_length(self) -> usize {
        self.bits().div_ceil(8)
    }
    /// The little-endian magnitude in `byte_length` bytes.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0; self.byte_length()];
        assert!(self.exponent > 0);
        bytes[0] = 1;
        let shifted = u64::from(self.odd_factor) << (self.exponent % 8);
        for (index, byte) in shifted.to_le_bytes().into_iter().enumerate() {
            match bytes.get_mut(self.exponent / 8 + index) {
                Some(slot) => *slot |= byte,
                None => assert_eq!(byte, 0),
            }
        }
        bytes
    }
}

/// Column layout of the setup relation's witness: word columns, then Boolean
/// columns whose first pairs are the sparse secrets' positive and negative
/// supports. A signed variable narrower than a word takes one narrow word
/// column; a wider one takes whole words and one Boolean per remaining bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupShape {
    pub word_columns: usize,
    pub boolean_columns: usize,
    /// Each narrow word column and its width, in column order.
    pub narrow_words: Vec<(usize, usize)>,
    /// The sparse secrets' ring-degree strides and half supports, in
    /// allocation order: the FHE secret, its relinearization auxiliary and
    /// each recipient's share-encryption ephemeral.
    pub sparse_supports: Vec<(usize, usize)>,
}

/// Coefficient families of the setup statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Fhe,
    Sharing,
    Auxiliary,
}

/// The little-endian share-encryption modulus, the same for every profile.
pub fn share_modulus() -> &'static [u8] {
    table().share
}
/// The little-endian auxiliary-encryption modulus, the same for every profile.
pub fn auxiliary_modulus() -> &'static [u8] {
    table().auxiliary
}
/// Bits of each uniform sample of a share or auxiliary common coefficient.
/// Registration fixes the common share polynomial before the roster, and so
/// the profile, is known, so these families have one width.
pub fn fixed_common_sample_bits() -> usize {
    table().fixed_sample_bits
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    participants: usize,
    options: usize,
    ciphertext: ProthModulus,
    release: ProthModulus,
    release_noise_bits: usize,
    release_share_bits: usize,
    release_quotient_bits: usize,
    common_sample_bits: usize,
    sharing_coefficient_bits: usize,
    share_limb_bits: usize,
    share_carry_bits: usize,
}
impl Profile {
    pub fn participant_range() -> RangeInclusive<usize> {
        table().participants
    }
    pub fn option_range() -> RangeInclusive<usize> {
        table().options
    }
    pub fn new(participants: usize, options: usize) -> Result<Self, Unsupported> {
        let table = table();
        if !table.participants.contains(&participants) || !table.options.contains(&options) {
            return Err(Unsupported);
        }
        let index = (participants - table.participants.start()) * table.options.clone().count()
            + (options - table.options.start());
        let record = &table.records[index * RECORD_BYTES..(index + 1) * RECORD_BYTES];
        let word =
            |offset: usize| usize::from(u16::from_le_bytes([record[offset], record[offset + 1]]));
        Ok(Self {
            participants,
            options,
            ciphertext: ProthModulus::decode(&record[..8]),
            release: ProthModulus::decode(&record[8..16]),
            release_noise_bits: word(16),
            release_share_bits: word(18),
            release_quotient_bits: word(20),
            common_sample_bits: word(22),
            sharing_coefficient_bits: word(24),
            share_limb_bits: word(26),
            share_carry_bits: word(28),
        })
    }
    /// Every supported profile by participant count and then option count.
    pub fn all() -> impl Iterator<Item = Self> {
        Self::participant_range().flat_map(|participants| {
            Self::option_range().map(move |options| Self::new(participants, options).unwrap())
        })
    }

    pub fn participants(self) -> usize {
        self.participants
    }
    pub fn options(self) -> usize {
        self.options
    }
    /// At most f = floor((n - 1) / 3) participants are corrupt.
    pub fn corrupt(self) -> usize {
        (self.participants - 1) / 3
    }
    /// Inventory certificates and closing need n - f participants.
    pub fn inventory_threshold(self) -> usize {
        self.participants - self.corrupt()
    }
    /// Result release needs d = max(f + 1, 2) shares.
    pub fn release_threshold(self) -> usize {
        (self.corrupt() + 1).max(2)
    }
    /// A certified setup selection contains d valid contributions.
    pub fn setup_contributors(self) -> usize {
        self.release_threshold()
    }
    /// The fixed eligible prefix leaves d possible contributors after any f
    /// permitted departures; selection preserves the original roster.
    pub fn setup_eligible_contributors(self) -> usize {
        self.setup_contributors() + self.corrupt()
    }
    /// A result needs f + 2 accepted ballots.
    pub fn minimum_turnout(self) -> usize {
        self.corrupt() + 2
    }
    /// Sharing polynomials have degree d - 1, so they have d - 1 random
    /// coefficients.
    pub fn sharing_degree(self) -> usize {
        self.release_threshold() - 1
    }

    /// Roster position a evaluates at Z^a with Z = X^(N/R), where R is the
    /// least power of two whose 2R signed monomials separate every position.
    pub fn interpolation_degree(self) -> usize {
        self.participants.div_ceil(2).next_power_of_two()
    }
    pub fn point_stride(self) -> usize {
        DEGREE / self.interpolation_degree()
    }
    /// The factor 2^ceil(log2 d) clears every reconstruction denominator.
    pub fn clearing_factor(self) -> usize {
        self.release_threshold().next_power_of_two()
    }

    pub fn ciphertext_modulus(self) -> ProthModulus {
        self.ciphertext
    }
    pub fn gadget_length(self) -> usize {
        self.ciphertext.bits().div_ceil(GADGET_BASE_BITS)
    }
    pub fn gadget_base_bits() -> usize {
        GADGET_BASE_BITS
    }
    pub fn fhe_limbs(self) -> usize {
        self.ciphertext.bits().div_ceil(FHE_LIMB_BITS)
    }
    /// Bits of each uniform sample of an FHE common polynomial coefficient.
    pub fn fhe_common_sample_bits(self) -> usize {
        self.common_sample_bits
    }
    pub fn sharing_coefficient_bits(self) -> usize {
        self.sharing_coefficient_bits
    }
    /// Share equations use limbs of this many bits.
    pub fn share_limb_bits(self) -> usize {
        self.share_limb_bits
    }
    /// The carry of each share equation's constant component.
    pub fn share_carry_bits(self) -> usize {
        self.share_carry_bits
    }

    pub fn release_modulus(self) -> ProthModulus {
        self.release
    }
    pub fn release_noise_bits(self) -> usize {
        self.release_noise_bits
    }
    pub fn release_share_bits(self) -> usize {
        self.release_share_bits
    }
    pub fn release_quotient_bits(self) -> usize {
        self.release_quotient_bits
    }
    /// Release limbs of the public target and release modulus, the
    /// aggregate share, the release quotient, the release noise and each
    /// partial-decryption output.
    pub fn release_public_limbs(self) -> usize {
        self.release.bits().div_ceil(RELEASE_LIMB_BITS)
    }
    pub fn release_share_limbs(self) -> usize {
        self.release_share_bits.div_ceil(RELEASE_LIMB_BITS)
    }
    pub fn release_quotient_limbs(self) -> usize {
        self.release_quotient_bits.div_ceil(RELEASE_LIMB_BITS)
    }
    pub fn release_output_limbs(self) -> usize {
        self.release_public_limbs()
            + self
                .release_share_limbs()
                .max(self.release_quotient_limbs())
            - 1
    }
    /// Signed release witness variable widths in allocation order: the
    /// recipient key equation's quotient, carry and error, the aggregate
    /// share, its decoding equation's error, quotient and carry, the release
    /// noise and quotient, and every partial-decryption carry. The key
    /// equation repeats the registration widths.
    pub fn release_variable_bits(self) -> Vec<usize> {
        let mut bits = vec![
            SETUP_QUOTIENT_BITS,
            SETUP_FHE_CARRY_BITS,
            SETUP_ERROR_BITS,
            self.release_share_bits,
            RELEASE_DECODING_ERROR_BITS,
            SETUP_QUOTIENT_BITS,
            RELEASE_DECODING_CARRY_BITS,
            self.release_noise_bits,
            self.release_quotient_bits,
        ];
        bits.extend(std::iter::repeat_n(
            RELEASE_CARRY_BITS,
            self.release_output_limbs() - 1,
        ));
        bits
    }

    /// The comparison polynomial separates every total difference
    /// -(9n)..=9n, so its odd degree is 2 * 9 * n + 1.
    pub fn comparison_degree(self) -> usize {
        2 * (MAXIMUM_SCORE - 1) * self.participants + 1
    }
    /// Ranks sum a power-of-two window of comparison slots.
    pub fn rank_window(self) -> usize {
        self.options.next_power_of_two()
    }

    /// The suite parameter object: its magic, then the FHE, share and
    /// auxiliary moduli.
    pub fn parameters(self) -> Vec<u8> {
        [
            PARAMETER_MAGIC.as_slice(),
            &self.ciphertext.to_bytes(),
            share_modulus(),
            auxiliary_modulus(),
        ]
        .concat()
    }
    pub fn family_modulus(self, family: Family) -> Vec<u8> {
        match family {
            Family::Fhe => self.ciphertext.to_bytes(),
            Family::Sharing => share_modulus().to_vec(),
            Family::Auxiliary => auxiliary_modulus().to_vec(),
        }
    }
    /// Magnitude bytes of one canonical coefficient of a family.
    pub fn family_magnitude_bytes(self, family: Family) -> usize {
        match family {
            Family::Fhe => self.ciphertext.byte_length(),
            Family::Sharing => share_modulus().len(),
            Family::Auxiliary => auxiliary_modulus().len(),
        }
    }
    pub fn family_degree(self, family: Family) -> usize {
        match family {
            Family::Auxiliary => AUXILIARY_DEGREE,
            _ => DEGREE,
        }
    }

    /// Setup polynomials: seven per gadget coordinate, the common share
    /// polynomial and three per recipient.
    pub fn setup_polynomials(self) -> usize {
        GADGET_POLYNOMIALS * self.gadget_length() + 3 * self.participants + 1
    }
    pub fn fhe_polynomial(self, gadget: usize, component: usize) -> usize {
        assert!(gadget < self.gadget_length() && component < GADGET_POLYNOMIALS);
        GADGET_POLYNOMIALS * gadget + component
    }
    /// The gadget coordinate and component of an FHE setup polynomial.
    pub fn fhe_polynomial_position(self, index: usize) -> Option<(usize, usize)> {
        (index < self.share_common_polynomial())
            .then_some((index / GADGET_POLYNOMIALS, index % GADGET_POLYNOMIALS))
    }
    pub fn share_common_polynomial(self) -> usize {
        GADGET_POLYNOMIALS * self.gadget_length()
    }
    pub fn recipient_key_polynomial(self, recipient: usize) -> usize {
        assert!(recipient < self.participants);
        self.share_common_polynomial() + 1 + 3 * recipient
    }
    pub fn share_constant_polynomial(self, recipient: usize) -> usize {
        self.recipient_key_polynomial(recipient) + 1
    }
    pub fn share_linear_polynomial(self, recipient: usize) -> usize {
        self.recipient_key_polynomial(recipient) + 2
    }
    /// Signed witness variable widths in allocation order after the sparse
    /// secrets: each sharing coefficient's low and high limb parts, each
    /// gadget coordinate's encryption, two relinearization and automorphism
    /// key equations and each recipient's constant and linear share equations.
    /// Each equation has its quotient, its carries and its error.
    pub fn setup_variable_bits(self) -> Vec<usize> {
        let mut bits = Vec::new();
        for _ in 0..self.sharing_degree() {
            bits.extend([
                self.share_limb_bits,
                self.sharing_coefficient_bits - self.share_limb_bits,
            ]);
        }
        for _ in 0..4 * self.gadget_length() {
            bits.push(SETUP_QUOTIENT_BITS);
            bits.extend(std::iter::repeat_n(
                SETUP_FHE_CARRY_BITS,
                self.fhe_limbs() - 1,
            ));
            bits.push(SETUP_ERROR_BITS);
        }
        for _ in 0..self.participants {
            bits.extend([
                SETUP_QUOTIENT_BITS,
                self.share_carry_bits,
                SETUP_ERROR_BITS,
                SETUP_QUOTIENT_BITS,
                SETUP_FHE_CARRY_BITS,
                SETUP_ERROR_BITS,
            ]);
        }
        bits
    }
    pub fn setup_shape(self) -> SetupShape {
        let degree = |support: usize, stride: usize| (stride, support / 2);
        let mut sparse_supports = vec![degree(FHE_SECRET_SUPPORT, 1); 2];
        sparse_supports.extend(std::iter::repeat_n(
            degree(SHARE_EPHEMERAL_SUPPORT, 1),
            self.participants,
        ));
        let mut word_columns = 0;
        let mut boolean_columns = 2 * sparse_supports.len();
        let mut narrow_words = Vec::new();
        for bits in self.setup_variable_bits() {
            if bits < WORD_BITS {
                narrow_words.push((word_columns, bits));
                word_columns += 1;
            } else {
                word_columns += bits / WORD_BITS;
                boolean_columns += bits % WORD_BITS;
            }
        }
        SetupShape {
            word_columns,
            boolean_columns,
            narrow_words,
            sparse_supports,
        }
    }
    /// The setup statement header: its magic, the ring degree and the FHE
    /// and share-encryption moduli.
    pub fn setup_statement_header(self) -> Vec<u8> {
        let mut header = STATEMENT_MAGIC.to_vec();
        header.extend((DEGREE as u32).to_le_bytes());
        header.extend(self.ciphertext_modulus().to_bytes());
        header.extend(share_modulus());
        header
    }
    /// Bytes of one setup polynomial: a sign byte and a magnitude for each
    /// coefficient.
    pub fn setup_polynomial_bytes(self, index: usize) -> Option<usize> {
        let family = self.setup_family(index)?;
        Some(self.family_degree(family) * (1 + self.family_magnitude_bytes(family)))
    }
    /// Bytes of the setup statement: the header, then every setup
    /// polynomial.
    pub fn setup_statement_length(self) -> usize {
        self.setup_statement_header().len()
            + (0..self.setup_polynomials())
                .map(|index| self.setup_polynomial_bytes(index).unwrap())
                .sum::<usize>()
    }
    /// The setup polynomials a contribution body carries, in body order:
    /// each gadget coordinate's keys, each recipient's constant and linear
    /// share encryptions.
    pub fn contribution_body_polynomials(self) -> Vec<usize> {
        let mut polynomials: Vec<_> = (0..self.gadget_length())
            .flat_map(|gadget| {
                GADGET_KEY_COMPONENTS.map(|component| self.fhe_polynomial(gadget, component))
            })
            .collect();
        for recipient in 0..self.participants {
            polynomials.extend([
                self.share_constant_polynomial(recipient),
                self.share_linear_polynomial(recipient),
            ]);
        }
        polynomials
    }
    pub fn setup_family(self, index: usize) -> Option<Family> {
        if index < self.share_common_polynomial() {
            Some(Family::Fhe)
        } else if index < self.setup_polynomials() {
            Some(Family::Sharing)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn integer(bytes: &[u8]) -> BigUint {
        BigUint::from_bytes_le(bytes)
    }

    #[test]
    fn every_modulus_is_a_certified_prime_of_its_form() {
        let plaintext = 65_537u32;
        for profile in Profile::all() {
            for (prime, bits) in [
                (
                    profile.ciphertext_modulus(),
                    profile.ciphertext_modulus().bits(),
                ),
                (profile.release_modulus(), profile.release_modulus().bits()),
            ] {
                let modulus = integer(&prime.to_bytes());
                let odd = BigUint::from(prime.odd_factor());
                assert_eq!(prime.odd_factor() % 2, 1);
                assert_eq!(prime.odd_factor() % plaintext, 0);
                assert!(odd < BigUint::from(1u8) << prime.exponent());
                assert_eq!(modulus, (odd << prime.exponent()) + 1u8);
                assert_eq!(modulus.bits() as usize, bits);
                // Proth: w^((q - 1) / 2) = -1 proves q prime.
                let minus_one = &modulus - 1u8;
                assert_eq!(
                    BigUint::from(prime.witness()).modpow(&(&minus_one >> 1), &modulus),
                    minus_one
                );
            }
            assert_eq!(profile.ciphertext_modulus().bits() % 32, 0);
            assert!(profile.release_modulus().bits() < profile.ciphertext_modulus().bits());
        }
    }

    #[test]
    fn completion_parameters_rebuild_the_independent_moduli() {
        let profile = Profile::new(10, 10).unwrap();
        let fhe: BigUint = ((BigUint::from(65_537u32) * 65_319u32) << 832usize) + 1u8;
        let proof_field: BigUint =
            (BigUint::from(1u8) << 128usize) - (BigUint::from(133u8) << 64usize) + 1u8;
        let share: BigUint = proof_field * (119u32 * (1 << 23) + 1);
        let auxiliary: BigUint = (BigUint::from(257u32 * 101) << 20usize) + 1u8;
        let mut expected = b"SCP1".to_vec();
        for (value, length) in [(&fhe, 108), (&share, 20), (&auxiliary, 5)] {
            let mut bytes = value.to_bytes_le();
            assert!(bytes.len() <= length);
            bytes.resize(length, 0);
            expected.extend(bytes);
        }
        assert_eq!(profile.parameters(), expected);
        assert_eq!(profile.parameters().len(), 137);
        assert_eq!(integer(share_modulus()), share);
        assert_eq!(integer(auxiliary_modulus()), auxiliary);
    }

    #[test]
    fn thresholds_and_interpolation_match_the_census() {
        // Participants, corrupt bound, inventory and release thresholds,
        // minimum turnout, interpolation degree and clearing factor.
        for (participants, corrupt, inventory, release, turnout, degree, clearing) in [
            (3, 0, 3, 2, 2, 2, 2),
            (4, 1, 3, 2, 3, 2, 2),
            (5, 1, 4, 2, 3, 4, 2),
            (7, 2, 5, 3, 4, 4, 4),
            (9, 2, 7, 3, 4, 8, 4),
            (10, 3, 7, 4, 5, 8, 4),
            (13, 4, 9, 5, 6, 8, 8),
            (16, 5, 11, 6, 7, 8, 8),
            (17, 5, 12, 6, 7, 16, 8),
            (20, 6, 14, 7, 8, 16, 8),
        ] {
            let profile = Profile::new(participants, 2).unwrap();
            assert_eq!(
                (
                    profile.corrupt(),
                    profile.inventory_threshold(),
                    profile.release_threshold(),
                    profile.minimum_turnout(),
                    profile.interpolation_degree(),
                    profile.clearing_factor()
                ),
                (corrupt, inventory, release, turnout, degree, clearing)
            );
            assert_eq!(profile.sharing_degree(), release - 1);
            assert_eq!(profile.setup_eligible_contributors(), release + corrupt);
            assert!(profile.setup_eligible_contributors() <= participants);
            assert_eq!(profile.point_stride() * degree, DEGREE);
        }
    }

    #[test]
    fn searched_sizes_match_the_census() {
        // Participants, options, ciphertext bits, gadget coordinates, FHE
        // limbs, sharing coefficient, share limb and carry bits, release
        // share and quotient bits, and common-matrix sample bits.
        for (participants, options, bits, gadgets, limbs, sharing, limb, carry, share, quotient) in [
            (3, 2, 576, 4, 6, 108, 96, 32, 112, 144),
            (10, 10, 864, 6, 9, 112, 96, 32, 120, 144),
            (13, 2, 704, 5, 8, 114, 96, 32, 120, 144),
            (16, 2, 736, 6, 8, 115, 95, 33, 120, 144),
            (20, 20, 960, 7, 10, 116, 95, 33, 127, 192),
        ] {
            let profile = Profile::new(participants, options).unwrap();
            assert_eq!(profile.ciphertext_modulus().bits(), bits);
            assert_eq!(profile.gadget_length(), gadgets);
            assert_eq!(profile.fhe_limbs(), limbs);
            assert_eq!(profile.sharing_coefficient_bits(), sharing);
            assert_eq!(profile.share_limb_bits(), limb);
            assert_eq!(profile.share_carry_bits(), carry);
            assert_eq!(profile.release_share_bits(), share);
            assert_eq!(profile.release_quotient_bits(), quotient);
            assert_eq!(profile.release_modulus().bits(), 192);
        }
        for (participants, options, sample) in [(3, 2, 768), (10, 10, 1024), (20, 20, 1152)] {
            assert_eq!(
                Profile::new(participants, options)
                    .unwrap()
                    .fhe_common_sample_bits(),
                sample
            );
        }
        assert_eq!(fixed_common_sample_bits(), 320);
        let completion = Profile::new(10, 10).unwrap();
        assert_eq!(completion.release_noise_bits(), 144);
        assert_eq!(completion.comparison_degree(), 181);
        assert_eq!(completion.rank_window(), 16);
        assert_eq!(Profile::new(3, 2).unwrap().rank_window(), 2);
        assert_eq!(Profile::new(20, 17).unwrap().rank_window(), 32);
    }

    #[test]
    fn setup_polynomials_are_numbered_once_by_family() {
        for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            let mut seen = vec![false; profile.setup_polynomials()];
            let mut mark = |index: usize, family: Family| {
                assert!(!seen[index]);
                seen[index] = true;
                assert_eq!(profile.setup_family(index), Some(family));
            };
            for gadget in 0..profile.gadget_length() {
                for component in 0..7 {
                    let index = profile.fhe_polynomial(gadget, component);
                    mark(index, Family::Fhe);
                    assert_eq!(
                        profile.fhe_polynomial_position(index),
                        Some((gadget, component))
                    );
                }
            }
            assert_eq!(
                profile.fhe_polynomial_position(profile.share_common_polynomial()),
                None
            );
            mark(profile.share_common_polynomial(), Family::Sharing);
            for recipient in 0..participants {
                mark(profile.recipient_key_polynomial(recipient), Family::Sharing);
                mark(
                    profile.share_constant_polynomial(recipient),
                    Family::Sharing,
                );
                mark(profile.share_linear_polynomial(recipient), Family::Sharing);
            }
            assert!(seen.iter().all(|value| *value));
            assert_eq!(profile.setup_family(profile.setup_polynomials()), None);
        }
        let completion = Profile::new(10, 10).unwrap();
        assert_eq!(completion.setup_statement_header().len(), 136);
        assert_eq!(
            completion.setup_statement_length(),
            136 + 42 * DEGREE * 109 + 31 * DEGREE * 21
        );
        assert_eq!(completion.setup_polynomials(), 73);
        assert_eq!(completion.share_common_polynomial(), 42);
        assert_eq!(completion.recipient_key_polynomial(0), 43);
        assert_eq!(completion.share_linear_polynomial(9), 72);
    }

    #[test]
    fn contribution_bodies_carry_every_key_once_and_no_common_polynomial() {
        for profile in Profile::all() {
            let polynomials = profile.contribution_body_polynomials();
            assert_eq!(
                polynomials.len(),
                4 * profile.gadget_length() + 2 * profile.participants()
            );
            assert!(polynomials.windows(2).all(|pair| pair[0] < pair[1]));
            let mut commons = vec![profile.share_common_polynomial()];
            for gadget in 0..profile.gadget_length() {
                commons
                    .extend([0, 3, 5].map(|component| profile.fhe_polynomial(gadget, component)));
            }
            commons.extend(
                (0..profile.participants())
                    .map(|recipient| profile.recipient_key_polynomial(recipient)),
            );
            assert!(polynomials.iter().all(|index| !commons.contains(index)));
            assert_eq!(
                polynomials.len() + commons.len(),
                profile.setup_polynomials()
            );
        }
        // The contribution body model's layout: four FHE keys per gadget
        // coordinate and two share encryptions per recipient, each a sign
        // byte and a magnitude per coefficient.
        let completion = Profile::new(10, 10).unwrap();
        let polynomials = completion.contribution_body_polynomials();
        assert_eq!(polynomials[..4], [1, 2, 4, 6]);
        assert_eq!(polynomials[20..26], [36, 37, 39, 41, 44, 45]);
        assert_eq!(polynomials[43], 72);
        assert_eq!(
            polynomials
                .iter()
                .map(|index| completion.setup_polynomial_bytes(*index).unwrap())
                .sum::<usize>(),
            24 * DEGREE * 109 + 20 * DEGREE * 21
        );
        assert_eq!(
            completion.setup_polynomial_bytes(completion.setup_polynomials()),
            None
        );
    }

    #[test]
    fn setup_shapes_match_the_census() {
        let completion = Profile::new(10, 10).unwrap().setup_shape();
        assert_eq!(
            (completion.word_columns, completion.boolean_columns),
            (331, 24)
        );
        // Twenty-four FHE errors, one per key, then two share errors per
        // recipient.
        let mut narrow: Vec<_> = (0..24).map(|key| (30 + 10 * key, 7)).collect();
        for recipient in 0..10 {
            narrow.extend([(264 + 7 * recipient, 7), (267 + 7 * recipient, 7)]);
        }
        assert_eq!(completion.narrow_words, narrow);
        assert_eq!(completion.sparse_supports.len(), 12);
        assert_eq!(completion.sparse_supports[0], (1, 512));
        assert_eq!(completion.sparse_supports[2], (1, 128));
        // Census ranges of word columns by participant count.
        for (participants, low, high) in [(3, 140, 268), (16, 358, 450), (20, 392, 484)] {
            let words: Vec<_> = Profile::option_range()
                .map(|options| {
                    Profile::new(participants, options)
                        .unwrap()
                        .setup_shape()
                        .word_columns
                })
                .collect();
            assert_eq!(*words.iter().min().unwrap(), low);
            assert_eq!(*words.iter().max().unwrap(), high);
        }
        // Twelve-bit high parts are narrow words for three participants.
        let small = Profile::new(3, 2).unwrap().setup_shape();
        assert_eq!(small.narrow_words[0], (6, 12));
    }

    #[test]
    fn counts_outside_the_supported_ranges_are_refused() {
        for (participants, options) in [(0, 0), (2, 10), (21, 10), (10, 1), (10, 21)] {
            assert_eq!(Profile::new(participants, options), Err(Unsupported));
        }
        assert_eq!(Profile::participant_range(), 3..=20);
        assert_eq!(Profile::option_range(), 2..=20);
        assert_eq!(Profile::all().count(), 342);
    }
}
