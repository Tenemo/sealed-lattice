//! Comparative prime-field arithmetic from the retired lattice-PCS investigation.
//!
//! This module is compiled only for tests and the opt-in primitive-measurement
//! artifact. It does not select a proof suite or enter an accepted verifier
//! path. The arithmetic is a clean-room seven-limb Montgomery implementation
//! for the former 440-bit proof-field candidate. It remains only so the measured
//! cost of that rejected direction stays reproducible.

use core::{cmp::Ordering, mem::size_of};

pub(crate) const RING_NATIVE_PROOF_FIELD_BIT_LENGTH: usize = 440;
pub(crate) const RING_NATIVE_PROOF_FIELD_LIMB_COUNT: usize = 7;
pub(crate) const RING_NATIVE_PROOF_FIELD_ELEMENT_BYTE_LENGTH: usize =
    RING_NATIVE_PROOF_FIELD_LIMB_COUNT * size_of::<u64>();
pub(crate) const RING_NATIVE_PROOF_POLYNOMIAL_DEGREE: usize = 1 << 15;
pub(crate) const RING_NATIVE_PROOF_NEGACYCLIC_ROOT_ORDER: usize =
    RING_NATIVE_PROOF_POLYNOMIAL_DEGREE * 2;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_TRANSFORM_COUNT: usize = 2;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_BUTTERFLY_COUNT: usize =
    RING_NATIVE_PROOF_POLYNOMIAL_DEGREE * RING_NATIVE_PROOF_POLYNOMIAL_DEGREE.ilog2() as usize;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_TWIST_MULTIPLICATION_COUNT: usize =
    RING_NATIVE_PROOF_POLYNOMIAL_DEGREE * 2;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_TRANSFORM_FIELD_MULTIPLICATION_COUNT: usize =
    RING_NATIVE_PROOF_NTT_BUTTERFLY_COUNT + RING_NATIVE_PROOF_NTT_TWIST_MULTIPLICATION_COUNT;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_PLAN_FIELD_ELEMENT_COUNT: usize =
    RING_NATIVE_PROOF_POLYNOMIAL_DEGREE * 4 - 2;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_RETAINED_FIELD_ELEMENT_COUNT: usize =
    RING_NATIVE_PROOF_POLYNOMIAL_DEGREE * 2;
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) const RING_NATIVE_PROOF_NTT_MODELED_PEAK_LIVE_BYTE_LENGTH: usize =
    (RING_NATIVE_PROOF_NTT_PLAN_FIELD_ELEMENT_COUNT
        + RING_NATIVE_PROOF_NTT_RETAINED_FIELD_ELEMENT_COUNT)
        * RING_NATIVE_PROOF_FIELD_ELEMENT_BYTE_LENGTH;

const PROOF_FIELD_MODULUS: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] = [
    10_861_254_589_663_936_513,
    11_698_788_561_769_056_197,
    242_069_657_119_232_701,
    4_985_472_948_575_728_013,
    746_593_965_693_318_127,
    7_908_011_067_337_940_754,
    36_028_940_872_640_212,
];
const MONTGOMERY_NEGATIVE_MODULUS_INVERSE: u64 = 10_861_254_589_663_936_511;
const MONTGOMERY_RADIX_SQUARED: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] = [
    1_917_621_221_835_460_143,
    2_308_959_731_444_405_047,
    17_616_165_135_870_622_612,
    9_491_280_380_307_657_054,
    8_017_761_822_979_019_659,
    4_821_653_488_849_444_410,
    9_661_152_136_639_406,
];
const MONTGOMERY_ONE: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] = [
    2_368_870_868_303_478_273,
    17_110_868_891_616_558_232,
    5_429_613_728_038_950_776,
    16_520_749_523_430_659_974,
    5_872_109_078_615_020_900,
    17_290_040_806_413_630_205,
    35_955_287_790_403_064,
];
const MAXIMUM_NEGACYCLIC_ROOT: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] = [
    17_480_539_304_024_294_586,
    7_968_699_818_781_876_626,
    357_611_660_418_564_749,
    14_452_681_199_353_076_221,
    2_769_471_033_847_719_777,
    15_877_573_658_495_120_951,
    11_272_169_739_908_427,
];
const MAXIMUM_INVERSE_NEGACYCLIC_ROOT: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] = [
    13_708_762_669_243_576_125,
    12_305_382_965_098_761_097,
    2_958_593_571_521_538_363,
    7_563_169_436_403_152_794,
    5_933_189_309_713_846_248,
    14_964_369_268_333_108_911,
    4_516_443_920_370_352,
];
const INVERSE_TWO: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] = [
    14_653_999_331_686_744_065,
    15_072_766_317_739_303_906,
    9_344_406_865_414_392_158,
    11_716_108_511_142_639_814,
    373_296_982_846_659_063,
    3_954_005_533_668_970_377,
    18_014_470_436_320_106,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RingNativeProofFieldElement {
    montgomery_limbs: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
}

impl RingNativeProofFieldElement {
    pub(crate) const ZERO: Self = Self {
        montgomery_limbs: [0; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
    };
    pub(crate) const ONE: Self = Self {
        montgomery_limbs: MONTGOMERY_ONE,
    };

    pub(crate) fn from_u64(value: u64) -> Self {
        let mut canonical_limbs = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
        canonical_limbs[0] = value;
        Self {
            montgomery_limbs: montgomery_multiply(canonical_limbs, MONTGOMERY_RADIX_SQUARED),
        }
    }

    pub(crate) fn from_canonical_limbs(
        canonical_limbs: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
    ) -> Result<Self, String> {
        if compare_limbs(&canonical_limbs, &PROOF_FIELD_MODULUS) != Ordering::Less {
            return Err("ring-native proof-field element is not canonical".to_owned());
        }
        Ok(Self {
            montgomery_limbs: montgomery_multiply(canonical_limbs, MONTGOMERY_RADIX_SQUARED),
        })
    }

    pub(crate) fn canonical_limbs(self) -> [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] {
        let mut canonical_one = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
        canonical_one[0] = 1;
        montgomery_multiply(self.montgomery_limbs, canonical_one)
    }

    pub(crate) fn add(self, right: Self) -> Self {
        let (mut sum, carry) = add_limbs(self.montgomery_limbs, right.montgomery_limbs);
        if carry || compare_limbs(&sum, &PROOF_FIELD_MODULUS) != Ordering::Less {
            sum = subtract_limbs(sum, PROOF_FIELD_MODULUS).0;
        }
        Self {
            montgomery_limbs: sum,
        }
    }

    pub(crate) fn sub(self, right: Self) -> Self {
        let (mut difference, borrow) =
            subtract_limbs(self.montgomery_limbs, right.montgomery_limbs);
        if borrow {
            difference = add_limbs(difference, PROOF_FIELD_MODULUS).0;
        }
        Self {
            montgomery_limbs: difference,
        }
    }

    pub(crate) fn mul(self, right: Self) -> Self {
        Self {
            montgomery_limbs: montgomery_multiply(self.montgomery_limbs, right.montgomery_limbs),
        }
    }

    pub(crate) fn square(self) -> Self {
        self.mul(self)
    }

    pub(crate) fn pow_u64(self, mut exponent: u64) -> Self {
        let mut power = self;
        let mut result = Self::ONE;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.mul(power);
            }
            exponent >>= 1;
            if exponent != 0 {
                power = power.square();
            }
        }
        result
    }
}

fn compare_limbs(
    left: &[u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
    right: &[u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
) -> Ordering {
    for limb_ordinal in (0..RING_NATIVE_PROOF_FIELD_LIMB_COUNT).rev() {
        match left[limb_ordinal].cmp(&right[limb_ordinal]) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

fn add_limbs(
    left: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
    right: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
) -> ([u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT], bool) {
    let mut sum = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
    let mut carry = false;
    for limb_ordinal in 0..RING_NATIVE_PROOF_FIELD_LIMB_COUNT {
        let (partial_sum, first_carry) = left[limb_ordinal].overflowing_add(right[limb_ordinal]);
        let (complete_sum, second_carry) = partial_sum.overflowing_add(u64::from(carry));
        sum[limb_ordinal] = complete_sum;
        carry = first_carry || second_carry;
    }
    (sum, carry)
}

fn subtract_limbs(
    left: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
    right: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
) -> ([u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT], bool) {
    let mut difference = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
    let mut borrow = false;
    for limb_ordinal in 0..RING_NATIVE_PROOF_FIELD_LIMB_COUNT {
        let (partial_difference, first_borrow) =
            left[limb_ordinal].overflowing_sub(right[limb_ordinal]);
        let (complete_difference, second_borrow) =
            partial_difference.overflowing_sub(u64::from(borrow));
        difference[limb_ordinal] = complete_difference;
        borrow = first_borrow || second_borrow;
    }
    (difference, borrow)
}

fn multiply_accumulate_with_carry(value: u64, left: u64, right: u64, carry: &mut u64) -> u64 {
    let accumulation =
        u128::from(left) * u128::from(right) + u128::from(value) + u128::from(*carry);
    *carry = (accumulation >> 64) as u64;
    accumulation as u64
}

fn add_with_carry(value: &mut u64, addend: u64, carry: u64) -> u64 {
    let accumulation = u128::from(*value) + u128::from(addend) + u128::from(carry);
    *value = accumulation as u64;
    (accumulation >> 64) as u64
}

fn montgomery_multiply(
    left: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
    right: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
) -> [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] {
    let mut product = [0_u64; 16];
    for left_limb_ordinal in 0..RING_NATIVE_PROOF_FIELD_LIMB_COUNT {
        let mut carry = 0_u64;
        for right_limb_ordinal in 0..RING_NATIVE_PROOF_FIELD_LIMB_COUNT {
            let product_limb_ordinal = left_limb_ordinal + right_limb_ordinal;
            product[product_limb_ordinal] = multiply_accumulate_with_carry(
                product[product_limb_ordinal],
                left[left_limb_ordinal],
                right[right_limb_ordinal],
                &mut carry,
            );
        }
        let carry_limb_ordinal = left_limb_ordinal + RING_NATIVE_PROOF_FIELD_LIMB_COUNT;
        debug_assert_eq!(product[carry_limb_ordinal], 0);
        product[carry_limb_ordinal] = carry;
    }

    let mut high_carry = 0_u64;
    for reduction_limb_ordinal in 0..RING_NATIVE_PROOF_FIELD_LIMB_COUNT {
        let reduction_factor =
            product[reduction_limb_ordinal].wrapping_mul(MONTGOMERY_NEGATIVE_MODULUS_INVERSE);
        let mut carry = 0_u64;
        let discarded = multiply_accumulate_with_carry(
            product[reduction_limb_ordinal],
            reduction_factor,
            PROOF_FIELD_MODULUS[0],
            &mut carry,
        );
        debug_assert_eq!(discarded, 0);
        for modulus_limb_ordinal in 1..RING_NATIVE_PROOF_FIELD_LIMB_COUNT {
            let product_limb_ordinal = reduction_limb_ordinal + modulus_limb_ordinal;
            product[product_limb_ordinal] = multiply_accumulate_with_carry(
                product[product_limb_ordinal],
                reduction_factor,
                PROOF_FIELD_MODULUS[modulus_limb_ordinal],
                &mut carry,
            );
        }
        high_carry = add_with_carry(
            &mut product[reduction_limb_ordinal + RING_NATIVE_PROOF_FIELD_LIMB_COUNT],
            carry,
            high_carry,
        );
    }

    debug_assert_eq!(high_carry, 0);
    let mut reduced = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
    reduced.copy_from_slice(
        &product[RING_NATIVE_PROOF_FIELD_LIMB_COUNT..RING_NATIVE_PROOF_FIELD_LIMB_COUNT * 2],
    );
    if compare_limbs(&reduced, &PROOF_FIELD_MODULUS) != Ordering::Less {
        reduced = subtract_limbs(reduced, PROOF_FIELD_MODULUS).0;
    }
    reduced
}

pub(crate) struct RingNativeProofFieldNttPlan {
    degree: usize,
    forward_twists: Vec<RingNativeProofFieldElement>,
    inverse_scaled_twists: Vec<RingNativeProofFieldElement>,
    forward_stage_twiddles: Vec<RingNativeProofFieldElement>,
    inverse_stage_twiddles: Vec<RingNativeProofFieldElement>,
}

impl RingNativeProofFieldNttPlan {
    pub(crate) fn new(degree: usize) -> Result<Self, String> {
        if !(2..=RING_NATIVE_PROOF_POLYNOMIAL_DEGREE).contains(&degree) || !degree.is_power_of_two()
        {
            return Err("ring-native proof-field NTT degree is unsupported".to_owned());
        }
        let root_power = u64::try_from(RING_NATIVE_PROOF_POLYNOMIAL_DEGREE / degree)
            .map_err(|_| "ring-native proof-field NTT root power exceeds u64".to_owned())?;
        let maximum_root =
            RingNativeProofFieldElement::from_canonical_limbs(MAXIMUM_NEGACYCLIC_ROOT)?;
        let maximum_inverse_root =
            RingNativeProofFieldElement::from_canonical_limbs(MAXIMUM_INVERSE_NEGACYCLIC_ROOT)?;
        let negacyclic_root = maximum_root.pow_u64(root_power);
        let inverse_negacyclic_root = maximum_inverse_root.pow_u64(root_power);
        let degree_u64 = u64::try_from(degree)
            .map_err(|_| "ring-native proof-field NTT degree exceeds u64".to_owned())?;
        if negacyclic_root.mul(inverse_negacyclic_root) != RingNativeProofFieldElement::ONE
            || negacyclic_root.pow_u64(degree_u64)
                != RingNativeProofFieldElement::ZERO.sub(RingNativeProofFieldElement::ONE)
            || negacyclic_root.pow_u64(degree_u64 * 2) != RingNativeProofFieldElement::ONE
        {
            return Err("ring-native proof-field NTT root certificate is invalid".to_owned());
        }

        let inverse_two = RingNativeProofFieldElement::from_canonical_limbs(INVERSE_TWO)?;
        let inverse_degree = inverse_two.pow_u64(u64::from(degree.ilog2()));
        let forward_twists = collect_powers(negacyclic_root, degree)?;
        let inverse_twists = collect_powers(inverse_negacyclic_root, degree)?;
        let mut inverse_scaled_twists = Vec::new();
        inverse_scaled_twists
            .try_reserve_exact(degree)
            .map_err(|_| "ring-native proof-field inverse-twist allocation failed".to_owned())?;
        for inverse_twist in inverse_twists {
            inverse_scaled_twists.push(inverse_twist.mul(inverse_degree));
        }
        let forward_stage_twiddles = collect_stage_twiddles(negacyclic_root.square(), degree)?;
        let inverse_stage_twiddles =
            collect_stage_twiddles(inverse_negacyclic_root.square(), degree)?;
        if forward_twists.len()
            + inverse_scaled_twists.len()
            + forward_stage_twiddles.len()
            + inverse_stage_twiddles.len()
            != degree * 4 - 2
        {
            return Err("ring-native proof-field NTT plan size is inconsistent".to_owned());
        }
        Ok(Self {
            degree,
            forward_twists,
            inverse_scaled_twists,
            forward_stage_twiddles,
            inverse_stage_twiddles,
        })
    }

    pub(crate) fn forward(&self, values: &mut [RingNativeProofFieldElement]) -> Result<(), String> {
        self.require_width(values)?;
        for (value, twist) in values.iter_mut().zip(&self.forward_twists) {
            *value = value.mul(*twist);
        }
        cyclic_transform(values, &self.forward_stage_twiddles)
    }

    pub(crate) fn inverse(&self, values: &mut [RingNativeProofFieldElement]) -> Result<(), String> {
        self.require_width(values)?;
        cyclic_transform(values, &self.inverse_stage_twiddles)?;
        for (value, inverse_scaled_twist) in values.iter_mut().zip(&self.inverse_scaled_twists) {
            *value = value.mul(*inverse_scaled_twist);
        }
        Ok(())
    }

    fn require_width(&self, values: &[RingNativeProofFieldElement]) -> Result<(), String> {
        if values.len() != self.degree {
            return Err("ring-native proof-field NTT input width is invalid".to_owned());
        }
        Ok(())
    }
}

fn collect_powers(
    root: RingNativeProofFieldElement,
    count: usize,
) -> Result<Vec<RingNativeProofFieldElement>, String> {
    let mut powers = Vec::new();
    powers
        .try_reserve_exact(count)
        .map_err(|_| "ring-native proof-field NTT power allocation failed".to_owned())?;
    let mut power = RingNativeProofFieldElement::ONE;
    for power_ordinal in 0..count {
        powers.push(power);
        if power_ordinal + 1 != count {
            power = power.mul(root);
        }
    }
    Ok(powers)
}

fn collect_stage_twiddles(
    cyclic_root: RingNativeProofFieldElement,
    degree: usize,
) -> Result<Vec<RingNativeProofFieldElement>, String> {
    let mut twiddles = Vec::new();
    twiddles
        .try_reserve_exact(degree - 1)
        .map_err(|_| "ring-native proof-field NTT twiddle allocation failed".to_owned())?;
    let mut stage_width = 2;
    while stage_width <= degree {
        let stage_root = cyclic_root.pow_u64(
            u64::try_from(degree / stage_width)
                .map_err(|_| "ring-native proof-field NTT stage power exceeds u64".to_owned())?,
        );
        let mut twiddle = RingNativeProofFieldElement::ONE;
        for twiddle_ordinal in 0..stage_width / 2 {
            twiddles.push(twiddle);
            if twiddle_ordinal + 1 != stage_width / 2 {
                twiddle = twiddle.mul(stage_root);
            }
        }
        stage_width *= 2;
    }
    Ok(twiddles)
}

fn cyclic_transform(
    values: &mut [RingNativeProofFieldElement],
    stage_twiddles: &[RingNativeProofFieldElement],
) -> Result<(), String> {
    bit_reverse(values);
    let mut stage_width = 2;
    let mut stage_twiddle_offset = 0;
    while stage_width <= values.len() {
        let half_width = stage_width / 2;
        let stage_twiddles = stage_twiddles
            .get(stage_twiddle_offset..stage_twiddle_offset + half_width)
            .ok_or_else(|| {
                "ring-native proof-field NTT twiddle schedule is truncated".to_owned()
            })?;
        for stage_values in values.chunks_exact_mut(stage_width) {
            let (lower_values, upper_values) = stage_values.split_at_mut(half_width);
            for value_ordinal in 0..half_width {
                let lower = lower_values[value_ordinal];
                let weighted_upper = upper_values[value_ordinal].mul(stage_twiddles[value_ordinal]);
                lower_values[value_ordinal] = lower.add(weighted_upper);
                upper_values[value_ordinal] = lower.sub(weighted_upper);
            }
        }
        stage_twiddle_offset += half_width;
        stage_width *= 2;
    }
    if stage_twiddle_offset != stage_twiddles.len() {
        return Err("ring-native proof-field NTT twiddle schedule has trailing values".to_owned());
    }
    Ok(())
}

fn bit_reverse(values: &mut [RingNativeProofFieldElement]) {
    let mut reversed_ordinal = 0;
    for value_ordinal in 1..values.len() {
        let mut bit = values.len() >> 1;
        while reversed_ordinal & bit != 0 {
            reversed_ordinal ^= bit;
            bit >>= 1;
        }
        reversed_ordinal ^= bit;
        if value_ordinal < reversed_ordinal {
            values.swap(value_ordinal, reversed_ordinal);
        }
    }
}

#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) fn ring_native_proof_field_ntt_round_trip() -> Result<u64, String> {
    let plan = RingNativeProofFieldNttPlan::new(RING_NATIVE_PROOF_POLYNOMIAL_DEGREE)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(RING_NATIVE_PROOF_POLYNOMIAL_DEGREE)
        .map_err(|_| "ring-native proof-field NTT input allocation failed".to_owned())?;
    for coefficient_ordinal in 0..RING_NATIVE_PROOF_POLYNOMIAL_DEGREE {
        let coefficient_ordinal = u64::try_from(coefficient_ordinal)
            .map_err(|_| "ring-native proof-field coefficient ordinal exceeds u64".to_owned())?;
        values.push(RingNativeProofFieldElement::from_u64(
            coefficient_ordinal
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .rotate_left(17)
                .wrapping_add(0xd1b5_4a32_d192_ed03),
        ));
    }
    let expected_values = values.clone();
    plan.forward(&mut values)?;
    plan.inverse(&mut values)?;
    if values != expected_values {
        return Err("ring-native proof-field NTT round trip changed a coefficient".to_owned());
    }
    let mut checksum = 0x6a09_e667_f3bc_c909_u64;
    for (coefficient_ordinal, value) in values.into_iter().enumerate() {
        for (limb_ordinal, limb) in value.canonical_limbs().into_iter().enumerate() {
            let rotation = u32::try_from((coefficient_ordinal + limb_ordinal * 11) % 64)
                .map_err(|_| "ring-native proof-field checksum rotation exceeds u32".to_owned())?;
            checksum = checksum
                .rotate_left(rotation)
                .wrapping_add(limb ^ 0x3c6e_f372_fe94_f82b);
        }
    }
    if checksum == 0 {
        return Err("ring-native proof-field NTT checksum is degenerate".to_owned());
    }
    Ok(checksum)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    use super::*;

    fn biguint_from_limbs(limbs: [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT]) -> BigUint {
        let mut bytes = Vec::with_capacity(RING_NATIVE_PROOF_FIELD_ELEMENT_BYTE_LENGTH);
        for limb in limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    fn limbs_from_biguint(value: &BigUint) -> [u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT] {
        let bytes = value.to_bytes_le();
        assert!(bytes.len() <= RING_NATIVE_PROOF_FIELD_ELEMENT_BYTE_LENGTH);
        let mut limbs = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
        for (limb_ordinal, limb_bytes) in bytes.chunks(8).enumerate() {
            let mut padded_limb = [0_u8; 8];
            padded_limb[..limb_bytes.len()].copy_from_slice(limb_bytes);
            limbs[limb_ordinal] = u64::from_le_bytes(padded_limb);
        }
        limbs
    }

    fn field_from_biguint(value: &BigUint) -> RingNativeProofFieldElement {
        RingNativeProofFieldElement::from_canonical_limbs(limbs_from_biguint(value))
            .expect("the reduced test value is canonical")
    }

    #[test]
    fn ring_native_proof_field_matches_big_integer_arithmetic() {
        let modulus = biguint_from_limbs(PROOF_FIELD_MODULUS);
        assert_eq!(modulus.bits(), RING_NATIVE_PROOF_FIELD_BIT_LENGTH as u64);
        assert_eq!(
            modulus,
            BigUint::from(181_765_148_u64).pow(16_u32) + BigUint::one()
        );
        assert_eq!(
            PROOF_FIELD_MODULUS[0].wrapping_mul(MONTGOMERY_NEGATIVE_MODULUS_INVERSE),
            u64::MAX
        );
        assert!(RingNativeProofFieldElement::from_canonical_limbs(PROOF_FIELD_MODULUS).is_err());

        let mut values = vec![
            BigUint::zero(),
            BigUint::one(),
            BigUint::from(2_u8),
            BigUint::from(u64::MAX),
            &modulus - BigUint::one(),
            &modulus - BigUint::from(2_u8),
            (BigUint::one() << 438_usize) + BigUint::from(0xfeed_beef_u64),
            (BigUint::from(0x9e37_79b9_7f4a_7c15_u64).pow(7_u32)) % &modulus,
            biguint_from_limbs(MAXIMUM_NEGACYCLIC_ROOT),
            biguint_from_limbs(MAXIMUM_INVERSE_NEGACYCLIC_ROOT),
        ];
        let mut deterministic_state = 0x6a09_e667_f3bc_c909_u64;
        for sample_ordinal in 0..64_u64 {
            let mut limbs = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
            for limb in &mut limbs {
                deterministic_state ^= deterministic_state << 13;
                deterministic_state ^= deterministic_state >> 7;
                deterministic_state ^= deterministic_state << 17;
                *limb = deterministic_state
                    .wrapping_add(sample_ordinal.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            }
            values.push(biguint_from_limbs(limbs) % &modulus);
        }
        for left_value in &values {
            let left = field_from_biguint(left_value);
            assert_eq!(biguint_from_limbs(left.canonical_limbs()), *left_value);
            for right_value in &values {
                let right = field_from_biguint(right_value);
                assert_eq!(
                    biguint_from_limbs(left.add(right).canonical_limbs()),
                    (left_value + right_value) % &modulus
                );
                assert_eq!(
                    biguint_from_limbs(left.sub(right).canonical_limbs()),
                    (left_value + &modulus - right_value) % &modulus
                );
                assert_eq!(
                    biguint_from_limbs(left.mul(right).canonical_limbs()),
                    (left_value * right_value) % &modulus
                );
            }
        }
    }

    #[test]
    fn ring_native_proof_field_root_has_the_certified_order() {
        let root = RingNativeProofFieldElement::from_canonical_limbs(MAXIMUM_NEGACYCLIC_ROOT)
            .expect("the maximum root is canonical");
        let inverse_root =
            RingNativeProofFieldElement::from_canonical_limbs(MAXIMUM_INVERSE_NEGACYCLIC_ROOT)
                .expect("the inverse maximum root is canonical");
        assert_eq!(root.canonical_limbs(), MAXIMUM_NEGACYCLIC_ROOT);
        assert_eq!(
            inverse_root.canonical_limbs(),
            MAXIMUM_INVERSE_NEGACYCLIC_ROOT
        );
        let mut canonical_one = [0_u64; RING_NATIVE_PROOF_FIELD_LIMB_COUNT];
        canonical_one[0] = 1;
        assert_eq!(
            root,
            field_from_biguint(&biguint_from_limbs(MAXIMUM_NEGACYCLIC_ROOT))
        );
        assert_eq!(
            inverse_root,
            field_from_biguint(&biguint_from_limbs(MAXIMUM_INVERSE_NEGACYCLIC_ROOT))
        );
        assert_eq!(root.mul(inverse_root).canonical_limbs(), canonical_one);
        assert_eq!(
            root.pow_u64(RING_NATIVE_PROOF_POLYNOMIAL_DEGREE as u64),
            RingNativeProofFieldElement::ZERO.sub(RingNativeProofFieldElement::ONE)
        );
        assert_eq!(
            root.pow_u64(RING_NATIVE_PROOF_NEGACYCLIC_ROOT_ORDER as u64),
            RingNativeProofFieldElement::ONE
        );
    }

    #[test]
    fn ring_native_proof_field_ntt_round_trips_varied_degrees() {
        for degree in [2, 4, 16, 256] {
            let plan = RingNativeProofFieldNttPlan::new(degree)
                .expect("the bounded proof-field NTT plan derives");
            let mut values = (0..degree)
                .map(|coefficient_ordinal| {
                    RingNativeProofFieldElement::from_u64(
                        (coefficient_ordinal as u64)
                            .wrapping_mul(0xa076_1d64_78bd_642f)
                            .wrapping_add(0xe703_7ed1_a0b4_28db),
                    )
                })
                .collect::<Vec<_>>();
            let expected_values = values.clone();
            plan.forward(&mut values)
                .expect("the bounded forward transform completes");
            assert_ne!(values, expected_values);
            plan.inverse(&mut values)
                .expect("the bounded inverse transform completes");
            assert_eq!(values, expected_values);
        }
    }

    #[test]
    fn ring_native_proof_field_ntt_refuses_invalid_widths() {
        assert!(RingNativeProofFieldNttPlan::new(0).is_err());
        assert!(RingNativeProofFieldNttPlan::new(3).is_err());
        assert!(RingNativeProofFieldNttPlan::new(RING_NATIVE_PROOF_POLYNOMIAL_DEGREE * 2).is_err());
        let plan = RingNativeProofFieldNttPlan::new(8).expect("the width-eight plan derives");
        let mut short_values = vec![RingNativeProofFieldElement::ZERO; 7];
        assert!(plan.forward(&mut short_values).is_err());
        assert!(plan.inverse(&mut short_values).is_err());
    }
}
