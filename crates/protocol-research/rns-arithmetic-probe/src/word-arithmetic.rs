//! Fixed-width arithmetic on canonical coefficients below the ciphertext
//! modulus, and the exact reconstruction of bounded centered integers from
//! their residues modulo a prefix of the transform primes.

use fhe_math::zq::Modulus;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

/// Coefficients have at most this many 64-bit words.
pub(super) const MAXIMUM_WORDS: usize = 16;
/// A lift reads at most this many primes.
const MAXIMUM_PRIMES: usize = 48;
/// Bits of an accumulation limb. A residue below 2^58 splits into two such
/// limbs, and the product of two limbs is below 2^58.
const LIMB_BITS: usize = 29;
const LIMB_MASK: u64 = (1 << LIMB_BITS) - 1;
/// Columns of limb products: a value below 2^64 times the largest modulus,
/// with room for the carries of every column.
const MAXIMUM_COLUMNS: usize = (64 * MAXIMUM_WORDS).div_ceil(LIMB_BITS) + 3;
/// Terms added between carry propagations. A term adds at most two products
/// below 2^58 to a column, so a column stays below 2^63.
const TERMS_PER_CARRY: usize = 16;
/// Fractional bits of each residue's share of a lift's rounding sum.
const FRACTION_BITS: u32 = 57;

/// The low and high words of the product of two words. WebAssembly has no
/// widening multiplication and forms a 128-bit product in a library routine,
/// so there the product is assembled from four 32-bit partial products.
#[inline(always)]
pub(super) fn widening_multiply(left: u64, right: u64) -> (u64, u64) {
    if cfg!(target_arch = "wasm32") {
        partial_products(left, right)
    } else {
        let product = u128::from(left) * u128::from(right);
        (product as u64, (product >> 64) as u64)
    }
}
/// The low and high words of the product of two words from four 32-bit
/// partial products, which every target compiles so that native tests check
/// the WebAssembly path.
#[inline(always)]
fn partial_products(left: u64, right: u64) -> (u64, u64) {
    let (left_low, left_high) = (left & 0xffff_ffff, left >> 32);
    let (right_low, right_high) = (right & 0xffff_ffff, right >> 32);
    let low = left_low * right_low;
    let first = left_high * right_low;
    let second = left_low * right_high;
    let middle = (low >> 32) + (first & 0xffff_ffff) + (second & 0xffff_ffff);
    (
        (low & 0xffff_ffff) | (middle << 32),
        left_high * right_high + (first >> 32) + (second >> 32) + (middle >> 32),
    )
}

/// The value's little-endian words, zero-extended to the count.
pub(super) fn words_of(value: &BigUint, count: usize) -> Vec<u64> {
    let mut words = value.to_u64_digits();
    assert!(words.len() <= count);
    words.resize(count, 0);
    words
}

/// Whether the left words exceed the right, most significant first.
pub(super) fn larger(left: &[u64], right: &[u64]) -> bool {
    left.iter().rev().cmp(right.iter().rev()).is_gt()
}

/// Bits `start..start + 64` of little-endian words, zero beyond them.
pub(super) fn extract(words: &[u64], start: usize) -> u64 {
    let index = start / 64;
    let shift = start % 64;
    let low = words.get(index).copied().unwrap_or(0) >> shift;
    if shift == 0 {
        low
    } else {
        low | words.get(index + 1).copied().unwrap_or(0) << (64 - shift)
    }
}

/// Subtracts the subtrahend from the value in place, the borrow running into
/// the value's further words, and returns the final borrow.
fn subtract_in_place(value: &mut [u64], subtrahend: &[u64]) -> bool {
    let mut borrow = false;
    for (index, word) in value.iter_mut().enumerate() {
        let other = subtrahend.get(index).copied().unwrap_or(0);
        let (difference, first) = word.overflowing_sub(other);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        *word = difference;
        borrow = first | second;
    }
    borrow
}

/// Adds the addend to the value in place, the carry running into the
/// value's further words, and returns the final carry.
fn add_in_place(value: &mut [u64], addend: &[u64]) -> bool {
    let mut carry = false;
    for (index, word) in value.iter_mut().enumerate() {
        let other = addend.get(index).copied().unwrap_or(0);
        let (sum, first) = word.overflowing_add(other);
        let (sum, second) = sum.overflowing_add(u64::from(carry));
        *word = sum;
        carry = first | second;
    }
    carry
}

/// The ciphertext modulus as words, with the reciprocal that estimates the
/// quotient of a value below 2^64 times the modulus.
pub(super) struct WideModulus {
    pub(super) words: usize,
    pub(super) value: Vec<u64>,
    pub(super) half: Vec<u64>,
    /// The modulus's bit length less 64.
    shift: usize,
    /// floor(2^(bits + 126) / modulus), below 2^127.
    reciprocal: [u64; 2],
}

impl WideModulus {
    pub(super) fn new(modulus: &BigUint) -> Self {
        let bits = usize::try_from(modulus.bits()).unwrap();
        assert!((128..=64 * MAXIMUM_WORDS).contains(&bits));
        let words = bits.div_ceil(64);
        let reciprocal = words_of(&((BigUint::from(1u32) << (bits + 126)) / modulus), 2);
        Self {
            words,
            value: words_of(modulus, words),
            half: words_of(&(modulus >> 1usize), words),
            shift: bits - 64,
            reciprocal: [reciprocal[0], reciprocal[1]],
        }
    }

    /// Whether the words, of any length, are at least the modulus.
    fn at_least(&self, value: &[u64]) -> bool {
        value[self.words..].iter().any(|word| *word != 0)
            || !larger(&self.value, &value[..self.words])
    }

    /// Whether a coefficient's words are canonical: below the modulus.
    pub(super) fn is_canonical(&self, value: &[u64]) -> bool {
        value.len() == self.words && !self.at_least(value)
    }

    /// The quotient by the modulus of a value below 2^64 times it, given in
    /// one word more than the modulus, and its remainder.
    pub(super) fn divide(&self, value: &[u64], remainder: &mut [u64]) -> u64 {
        debug_assert_eq!(value.len(), self.words + 1);
        // The value's bits from the shift on are below 2^128, and their
        // product with the reciprocal, shifted down by 190 bits, is the
        // quotient or one less.
        let top = [extract(value, self.shift), extract(value, self.shift + 64)];
        let (_, first_high) = widening_multiply(top[0], self.reciprocal[0]);
        let (second_low, second_high) = widening_multiply(top[0], self.reciprocal[1]);
        let (third_low, third_high) = widening_multiply(top[1], self.reciprocal[0]);
        let (fourth_low, fourth_high) = widening_multiply(top[1], self.reciprocal[1]);
        let (sum, first_carry) = first_high.overflowing_add(second_low);
        let (_, second_carry) = sum.overflowing_add(third_low);
        let carry = u64::from(first_carry) + u64::from(second_carry);
        let (sum, first_carry) = second_high.overflowing_add(third_high);
        let (sum, second_carry) = sum.overflowing_add(fourth_low);
        let (second_word, third_carry) = sum.overflowing_add(carry);
        let third_word =
            fourth_high + u64::from(first_carry) + u64::from(second_carry) + u64::from(third_carry);
        let mut quotient = (second_word >> 62) | (third_word << 2);
        let mut extended = [0u64; MAXIMUM_WORDS + 1];
        let extended = &mut extended[..=self.words];
        let mut carry = 0u64;
        let mut borrow = false;
        for (index, word) in extended.iter_mut().enumerate() {
            let (low, high) = match self.value.get(index) {
                Some(modulus) => widening_multiply(quotient, *modulus),
                None => (0, 0),
            };
            let (product, overflow) = low.overflowing_add(carry);
            carry = high + u64::from(overflow);
            let (difference, first) = value[index].overflowing_sub(product);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            *word = difference;
            borrow = first | second;
        }
        debug_assert!(!borrow && carry == 0);
        if self.at_least(extended) {
            subtract_in_place(extended, &self.value);
            quotient += 1;
        }
        debug_assert!(!self.at_least(extended));
        remainder.copy_from_slice(&extended[..self.words]);
        quotient
    }

    /// The sum of two canonical coefficients.
    pub(super) fn add(&self, left: &[u64], right: &[u64], output: &mut [u64]) {
        let mut sum = [0u64; MAXIMUM_WORDS + 1];
        let sum = &mut sum[..=self.words];
        sum[..self.words].copy_from_slice(left);
        add_in_place(sum, right);
        if self.at_least(sum) {
            subtract_in_place(sum, &self.value);
        }
        output.copy_from_slice(&sum[..self.words]);
    }

    /// The negation of a canonical coefficient.
    pub(super) fn negate(&self, value: &[u64], output: &mut [u64]) {
        if value.iter().all(|word| *word == 0) {
            output.fill(0);
        } else {
            output.copy_from_slice(&self.value);
            subtract_in_place(output, value);
        }
    }

    /// The product of a canonical coefficient and a signed factor.
    pub(super) fn multiply_signed(&self, value: &[u64], factor: i64, output: &mut [u64]) {
        let magnitude = factor.unsigned_abs();
        let mut product = [0u64; MAXIMUM_WORDS + 1];
        let product = &mut product[..=self.words];
        let mut carry = 0;
        for (word, value) in product.iter_mut().zip(value) {
            let (low, high) = widening_multiply(*value, magnitude);
            let (sum, overflow) = low.overflowing_add(carry);
            *word = sum;
            carry = high + u64::from(overflow);
        }
        product[self.words] = carry;
        let mut remainder = [0u64; MAXIMUM_WORDS];
        let remainder = &mut remainder[..self.words];
        self.divide(product, remainder);
        if factor < 0 {
            self.negate(remainder, output);
        } else {
            output.copy_from_slice(remainder);
        }
    }

    /// A signed integer of magnitude below the modulus as a canonical
    /// coefficient.
    pub(super) fn signed(&self, value: i64, output: &mut [u64]) {
        output.fill(0);
        output[0] = value.unsigned_abs();
        if value < 0 {
            let magnitude = output.to_vec();
            self.negate(&magnitude, output);
        }
    }
}

/// Propagates column carries, leaving every column below 2^29.
fn carry(columns: &mut [u64]) {
    let mut carry = 0;
    for column in columns.iter_mut() {
        let value = *column + carry;
        *column = value & LIMB_MASK;
        carry = value >> LIMB_BITS;
    }
    debug_assert_eq!(carry, 0);
}

/// Packs normalized limbs into little-endian words.
fn pack(columns: &[u64], output: &mut [u64]) {
    output.fill(0);
    for (index, limb) in columns.iter().enumerate() {
        let bit = index * LIMB_BITS;
        let (word, shift) = (bit / 64, bit % 64);
        if word < output.len() {
            output[word] |= limb << shift;
        } else {
            debug_assert_eq!(*limb, 0);
        }
        if shift + LIMB_BITS > 64 && word + 1 < output.len() {
            output[word + 1] |= limb >> (64 - shift);
        }
    }
}

/// Constants that reconstruct a centered integer from its residues modulo a
/// prefix of the primes whose product P exceeds twice the integer's
/// magnitude by the rounding margin, and determine the integer modulo the
/// ciphertext modulus q, or for a tensor its product with the plaintext
/// modulus t divided by q and rounded, modulo q.
///
/// With y_i the residue times the inverse of P / p_i modulo p_i and w the
/// sum of y_i / p_i rounded, the integer is sum y_i P / p_i - w P. For a
/// tensor, with t P / p_i = A_i q + B_i and t P = C q + D, the rounded
/// quotient is sum y_i A_i - w (C + 1) + R modulo q, where R is the rounded
/// quotient of sum y_i B_i + w (q - D) by q.
pub(super) struct Lift {
    pub(super) count: usize,
    tensor: bool,
    /// Accumulation limbs of a value below q.
    limbs: usize,
    /// The inverse of P / p_i modulo p_i and its Shoup quotient.
    inverses: Vec<(u64, u64)>,
    /// floor(2^(64 + FRACTION_BITS) / p_i).
    fractions: Vec<u64>,
    /// Limbs of P / p_i modulo q and then of -P modulo q, or for a tensor of
    /// A_i modulo q and then of -(C + 1) modulo q. A limb's type bounds its
    /// product with a limb of a multiplier below 2^61.
    rows: Vec<u32>,
    /// For a tensor, limbs of B_i and then of q - D.
    remainders: Vec<u32>,
}

impl Lift {
    /// Whether the product of the primes exceeds the bound by the margin
    /// that rounding their fixed-point sum needs. Each of the count terms
    /// underestimates its share by less than two units of 2^-57, and the
    /// rounded sum is exact when the integer's share of P stays that far
    /// from a half: (P - bound) 2^57 >= 4 count P.
    pub(super) fn covers(product: &BigUint, count: usize, bound: &BigUint) -> bool {
        product > bound && ((product - bound) << FRACTION_BITS) >= product * (4 * count)
    }

    pub(super) fn new(
        primes: &[u64],
        reductions: &[Modulus],
        modulus: &BigUint,
        plaintext: u32,
        tensor: bool,
    ) -> Self {
        let count = primes.len();
        assert!(count <= MAXIMUM_PRIMES);
        let limbs = usize::try_from(modulus.bits()).unwrap().div_ceil(LIMB_BITS);
        let push_limbs = |output: &mut Vec<u32>, value: &BigUint| {
            assert!(value < modulus);
            let words = words_of(value, MAXIMUM_WORDS);
            output.extend(
                (0..limbs).map(|limb| (extract(&words, limb * LIMB_BITS) & LIMB_MASK) as u32),
            );
        };
        let product: BigUint = primes.iter().map(|prime| BigUint::from(*prime)).product();
        let mut inverses = Vec::with_capacity(count);
        let mut fractions = Vec::with_capacity(count);
        let mut rows = Vec::with_capacity((count + 1) * limbs);
        let mut remainders = Vec::new();
        for (prime, reduction) in primes.iter().zip(reductions) {
            assert!((1 << FRACTION_BITS) < *prime && *prime < 1 << (2 * LIMB_BITS));
            let cofactor = &product / *prime;
            let inverse = reduction
                .inv((&cofactor % *prime).to_u64().unwrap())
                .unwrap();
            inverses.push((inverse, reduction.shoup(inverse)));
            fractions.push(((1u128 << (64 + FRACTION_BITS)) / u128::from(*prime)) as u64);
            if tensor {
                let scaled = cofactor * plaintext;
                push_limbs(&mut rows, &(&scaled / modulus % modulus));
                push_limbs(&mut remainders, &(scaled % modulus));
            } else {
                push_limbs(&mut rows, &(cofactor % modulus));
            }
        }
        if tensor {
            let scaled = &product * plaintext;
            push_limbs(&mut rows, &(modulus - 1u32 - &scaled / modulus % modulus));
            push_limbs(&mut remainders, &(modulus - scaled % modulus));
        } else {
            push_limbs(&mut rows, &(modulus - &product % modulus));
        }
        Self {
            count,
            tensor,
            limbs,
            inverses,
            fractions,
            rows,
            remainders,
        }
    }

    /// The sum of the multipliers times the rows, below 2^64 times the
    /// modulus, as words.
    fn accumulate(&self, multipliers: &[u64], rows: &[u32], output: &mut [u64]) {
        let mut columns = [0u64; MAXIMUM_COLUMNS];
        let columns = &mut columns[..self.limbs + 3];
        for (index, (multiplier, row)) in multipliers
            .iter()
            .zip(rows.chunks_exact(self.limbs))
            .enumerate()
        {
            if index > 0 && index % TERMS_PER_CARRY == 0 {
                carry(columns);
            }
            // Every multiplier is below 2^58, so its high limb is too.
            debug_assert!(*multiplier >> (2 * LIMB_BITS) == 0);
            let (low, high) = (
                multiplier & LIMB_MASK,
                (multiplier >> LIMB_BITS) & LIMB_MASK,
            );
            for (column, limb) in columns[..self.limbs].iter_mut().zip(row) {
                *column += low * u64::from(*limb);
            }
            for (column, limb) in columns[1..=self.limbs].iter_mut().zip(row) {
                *column += high * u64::from(*limb);
            }
        }
        carry(columns);
        pack(columns, output);
    }

    /// The canonical coefficient the residues at one position determine.
    pub(super) fn coefficient(
        &self,
        residues: &[&[u64]],
        position: usize,
        reductions: &[Modulus],
        modulus: &WideModulus,
        output: &mut [u64],
    ) {
        let mut multipliers = [0u64; MAXIMUM_PRIMES + 1];
        let mut fraction = 0u64;
        for (index, ((values, reduction), (inverse, quotient))) in residues
            .iter()
            .zip(reductions)
            .zip(&self.inverses)
            .enumerate()
        {
            let multiplier = reduction.mul_shoup(values[position], *inverse, *quotient);
            multipliers[index] = multiplier;
            fraction += widening_multiply(multiplier, self.fractions[index]).1;
        }
        multipliers[self.count] = (fraction + (1 << (FRACTION_BITS - 1))) >> FRACTION_BITS;
        let multipliers = &multipliers[..=self.count];
        let mut wide = [0u64; MAXIMUM_WORDS + 1];
        let wide = &mut wide[..=modulus.words];
        if self.tensor {
            self.accumulate(multipliers, &self.remainders, wide);
            add_in_place(wide, &modulus.half);
            let rounded = modulus.divide(wide, output);
            self.accumulate(multipliers, &self.rows, wide);
            add_in_place(wide, &[rounded]);
        } else {
            self.accumulate(multipliers, &self.rows, wide);
        }
        modulus.divide(wide, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::{Signed, Zero};

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
    fn unpack(value: &[u64]) -> BigUint {
        value
            .iter()
            .rev()
            .fold(BigUint::zero(), |result, word| (result << 64usize) + *word)
    }
    fn moduli() -> Vec<BigUint> {
        [(3, 2), (5, 5), (10, 10), (20, 20)]
            .into_iter()
            .map(|(participants, options)| {
                let modulus = supported_profile::Profile::new(participants, options)
                    .unwrap()
                    .ciphertext_modulus();
                (BigUint::from(modulus.odd_factor()) << modulus.exponent()) + 1u32
            })
            .collect()
    }

    #[test]
    fn widening_products_match_128_bit_products() {
        let mut state = 0x0123_4567_89ab_cdef;
        let mut values = vec![
            0,
            1,
            u64::MAX,
            u64::MAX - 1,
            1 << 63,
            (1 << 32) - 1,
            1 << 32,
        ];
        values.extend((0..64).map(|_| next(&mut state)));
        for left in &values {
            for right in &values {
                let product = u128::from(*left) * u128::from(*right);
                let expected = (product as u64, (product >> 64) as u64);
                assert_eq!(widening_multiply(*left, *right), expected);
                assert_eq!(partial_products(*left, *right), expected);
            }
        }
    }

    #[test]
    fn division_matches_big_integer_quotients_at_the_extremes() {
        for modulus in moduli() {
            let wide = WideModulus::new(&modulus);
            let limit = &modulus << 64usize;
            let mut state = 0x5eed ^ modulus.bits();
            let mut values = vec![
                BigUint::zero(),
                BigUint::from(1u32),
                &modulus - 1u32,
                modulus.clone(),
                &modulus + 1u32,
                &limit - 1u32,
                &limit - &modulus,
                &limit - &modulus - 1u32,
                (&modulus << 63usize) - 1u32,
                &modulus * 2u32 - 1u32,
            ];
            for multiple in [2u64, 3, u64::MAX - 1, u64::MAX] {
                values.push(&modulus * multiple);
                values.push(&modulus * multiple - 1u32);
            }
            for _ in 0..200 {
                let words: Vec<u64> = (0..=wide.words).map(|_| next(&mut state)).collect();
                values.push(unpack(&words) % &limit);
            }
            for value in values {
                let mut remainder = vec![0; wide.words];
                let quotient = wide.divide(&words_of(&value, wide.words + 1), &mut remainder);
                assert_eq!(BigUint::from(quotient), &value / &modulus);
                assert_eq!(unpack(&remainder), &value % &modulus);
            }
        }
    }

    #[test]
    fn modular_operations_match_big_integer_results() {
        for modulus in moduli() {
            let wide = WideModulus::new(&modulus);
            let mut state = 0xfeed ^ modulus.bits();
            let mut values = vec![
                BigUint::zero(),
                BigUint::from(1u32),
                &modulus - 1u32,
                &modulus >> 1usize,
                (&modulus >> 1usize) + 1u32,
            ];
            for _ in 0..40 {
                let words: Vec<u64> = (0..wide.words).map(|_| next(&mut state)).collect();
                values.push(unpack(&words) % &modulus);
            }
            let signed_modulus = BigInt::from(modulus.clone());
            let canonical = |value: BigInt| {
                let value = value % &signed_modulus;
                if value.is_negative() {
                    (value + &signed_modulus).magnitude().clone()
                } else {
                    value.magnitude().clone()
                }
            };
            let mut output = vec![0; wide.words];
            for left in &values {
                let left_words = words_of(left, wide.words);
                assert!(wide.is_canonical(&left_words));
                wide.negate(&left_words, &mut output);
                assert_eq!(unpack(&output), canonical(-BigInt::from(left.clone())));
                for factor in [
                    0i64,
                    1,
                    -1,
                    7,
                    -65_537,
                    i64::from(i32::MAX),
                    i64::from(i32::MIN),
                ] {
                    wide.multiply_signed(&left_words, factor, &mut output);
                    assert_eq!(
                        unpack(&output),
                        canonical(BigInt::from(left.clone()) * factor)
                    );
                }
                for right in &values {
                    wide.add(&left_words, &words_of(right, wide.words), &mut output);
                    assert_eq!(unpack(&output), (left + right) % &modulus);
                }
            }
            for value in [0i64, 1, -1, 32_768, -32_768, i64::MAX, -i64::MAX] {
                wide.signed(value, &mut output);
                assert_eq!(unpack(&output), canonical(BigInt::from(value)));
            }
            assert!(!wide.is_canonical(&words_of(&modulus, wide.words)));
            assert!(!wide.is_canonical(&vec![u64::MAX; wide.words]));
        }
    }

    // The reference lift: the centered integer from the product's residues,
    // then its value modulo q or its scaled rounded quotient.
    fn reference(primes: &[u64], residues: &[u64], modulus: &BigUint, tensor: bool) -> BigUint {
        let product: BigUint = primes.iter().map(|prime| BigUint::from(*prime)).product();
        let mut value = BigUint::zero();
        for (prime, residue) in primes.iter().zip(residues) {
            let cofactor = &product / *prime;
            let inverse =
                (&cofactor % *prime).modpow(&BigUint::from(prime - 2), &BigUint::from(*prime));
            value += cofactor * (inverse * residue % *prime);
        }
        value %= &product;
        let negative = value > &product >> 1usize;
        let magnitude = if negative { &product - value } else { value };
        let reduced = if tensor {
            (magnitude * 65_537u32 + (modulus >> 1usize)) / modulus % modulus
        } else {
            magnitude % modulus
        };
        if negative && !reduced.is_zero() {
            modulus - reduced
        } else {
            reduced
        }
    }

    #[test]
    fn lifts_match_big_integer_reconstruction_across_the_bound() {
        let mut primes = Vec::new();
        let mut limit = 1u64 << 58;
        while primes.len() < 36 {
            limit = super::super::super::proth_prime(58, limit);
            primes.push(limit);
        }
        let reductions: Vec<Modulus> = primes
            .iter()
            .map(|prime| Modulus::new(*prime).unwrap())
            .collect();
        for modulus in moduli() {
            let wide = WideModulus::new(&modulus);
            for tensor in [false, true] {
                // The tensor bound is the degree times the square of half
                // the modulus, and a plaintext product's is smaller.
                let half = &modulus >> 1usize;
                let bound = if tensor {
                    2u32 * BigUint::from(65_536u32) * &half * &half
                } else {
                    2u32 * BigUint::from(65_536u32 * 32_768) * &half
                };
                let mut count = 0;
                let mut product = BigUint::from(1u32);
                while !Lift::covers(&product, count, &bound) {
                    product *= primes[count];
                    count += 1;
                }
                let lift = Lift::new(
                    &primes[..count],
                    &reductions[..count],
                    &modulus,
                    65_537,
                    tensor,
                );
                let magnitude = &bound >> 1usize;
                let mut state = 0xabcd ^ count as u64;
                let mut integers: Vec<BigInt> = vec![
                    BigInt::zero(),
                    BigInt::from(1),
                    BigInt::from(-1),
                    BigInt::from(magnitude.clone()),
                    -BigInt::from(magnitude.clone()),
                    BigInt::from(&magnitude - 1u32),
                    BigInt::from(modulus.clone()),
                    -BigInt::from(&half + 1u32),
                    BigInt::from(half.clone()),
                ];
                for _ in 0..300 {
                    let words: Vec<u64> =
                        (0..2 * wide.words + 1).map(|_| next(&mut state)).collect();
                    let value = BigInt::from(unpack(&words) % &magnitude);
                    integers.push(if next(&mut state) & 1 == 0 {
                        value
                    } else {
                        -value
                    });
                }
                let signed_product = BigInt::from(product.clone());
                let residues: Vec<Vec<u64>> = primes[..count]
                    .iter()
                    .map(|prime| {
                        integers
                            .iter()
                            .map(|integer| {
                                let prime = BigInt::from(*prime);
                                (((integer % &prime) + &prime) % &prime).to_u64().unwrap()
                            })
                            .collect()
                    })
                    .collect();
                let residues: Vec<&[u64]> = residues.iter().map(Vec::as_slice).collect();
                let mut output = vec![0; wide.words];
                for (position, integer) in integers.iter().enumerate() {
                    let values: Vec<u64> = residues.iter().map(|values| values[position]).collect();
                    lift.coefficient(
                        &residues,
                        position,
                        &reductions[..count],
                        &wide,
                        &mut output,
                    );
                    assert_eq!(
                        unpack(&output),
                        reference(&primes[..count], &values, &modulus, tensor),
                        "integer {integer}, tensor {tensor}, bits {}",
                        modulus.bits()
                    );
                    assert!(integer.magnitude() < &(&signed_product.magnitude().clone() >> 1usize));
                }
            }
        }
    }
}
