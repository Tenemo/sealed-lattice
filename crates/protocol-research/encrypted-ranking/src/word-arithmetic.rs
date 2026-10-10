//! Fixed-width arithmetic on canonical coefficients below the ciphertext
//! modulus, and the exact reconstruction of bounded centered integers from
//! their residues modulo a prefix of the transform primes.

use super::prime_transform::PrimeModulus;
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
/// Fractional bits of each remainder's share of the ciphertext modulus in a
/// tensor's rounded quotient: two words.
const QUOTIENT_FRACTION_BITS: usize = 128;

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

/// The whole part of a fixed-point sum's three words, of which the first
/// two are its 128 fractional bits, when every addition of less than 2^64
/// units leaves it unchanged: unless the second word is all ones.
fn decided(words: [u64; 3]) -> Option<u64> {
    (words[1] != u64::MAX).then_some(words[2])
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
    /// For a tensor, the low and high words of floor(2^128 B_i / q) and then
    /// of floor(2^128 (q - D) / q).
    quotient_fractions: Vec<[u64; 2]>,
    /// floor(2^128 floor(q / 2) / q), which rounds a tensor's quotient.
    half_fraction: u128,
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
        reductions: &[PrimeModulus],
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
        let fraction = |value: &BigUint| {
            let words = words_of(&((value << QUOTIENT_FRACTION_BITS) / modulus), 2);
            [words[0], words[1]]
        };
        let product: BigUint = primes.iter().map(|prime| BigUint::from(*prime)).product();
        let mut inverses = Vec::with_capacity(count);
        let mut fractions = Vec::with_capacity(count);
        let mut rows = Vec::with_capacity((count + 1) * limbs);
        let mut remainders = Vec::new();
        let mut quotient_fractions = Vec::new();
        for (prime, reduction) in primes.iter().zip(reductions) {
            assert!((1 << FRACTION_BITS) < *prime && *prime < 1 << (2 * LIMB_BITS));
            let cofactor = &product / *prime;
            let inverse = reduction.inverse((&cofactor % *prime).to_u64().unwrap());
            inverses.push((inverse, reduction.shoup(inverse)));
            fractions.push(((1u128 << (64 + FRACTION_BITS)) / u128::from(*prime)) as u64);
            if tensor {
                let scaled = cofactor * plaintext;
                push_limbs(&mut rows, &(&scaled / modulus % modulus));
                let remainder = scaled % modulus;
                push_limbs(&mut remainders, &remainder);
                quotient_fractions.push(fraction(&remainder));
            } else {
                push_limbs(&mut rows, &(cofactor % modulus));
            }
        }
        if tensor {
            let scaled = &product * plaintext;
            push_limbs(&mut rows, &(modulus - 1u32 - &scaled / modulus % modulus));
            let remainder = modulus - scaled % modulus;
            push_limbs(&mut remainders, &remainder);
            quotient_fractions.push(fraction(&remainder));
        } else {
            push_limbs(&mut rows, &(modulus - &product % modulus));
        }
        let [low, high] = fraction(&(modulus >> 1usize));
        Self {
            count,
            tensor,
            limbs,
            inverses,
            fractions,
            rows,
            remainders,
            quotient_fractions,
            half_fraction: (u128::from(high) << 64) | u128::from(low),
        }
    }

    /// A tensor's rounded quotient floor((S + floor(q / 2)) / q), where S
    /// sums the multipliers times the remainders, from the multipliers
    /// times the remainders' fractions of q and the half's fraction, or
    /// none when that fixed-point sum cannot decide it. Each fraction falls
    /// short of its share by less than one unit of 2^-128 per multiplier
    /// unit, so the sum falls short of 2^128 times the exact quotient by
    /// less than one unit more than the multipliers' sum, below 2^64: its
    /// whole part is the quotient unless its fractional part lies within
    /// 2^64 units of a whole number.
    fn rounded_quotient(&self, multipliers: &[u64]) -> Option<u64> {
        // Each product of a multiplier below 2^58 and a fraction word is
        // below 2^122, so at most 49 of them sum below 2^128: the low
        // words' products at word zero, the high words' at word one.
        let (mut low, mut high) = (0u128, 0u128);
        for (multiplier, [fraction_low, fraction_high]) in
            multipliers.iter().zip(&self.quotient_fractions)
        {
            let (first, second) = widening_multiply(*multiplier, *fraction_low);
            low += (u128::from(second) << 64) | u128::from(first);
            let (first, second) = widening_multiply(*multiplier, *fraction_high);
            high += (u128::from(second) << 64) | u128::from(first);
        }
        let (low, carry) = low.overflowing_add(self.half_fraction);
        let middle = (low >> 64) + (high & u128::from(u64::MAX));
        decided([
            low as u64,
            middle as u64,
            (middle >> 64) as u64 + (high >> 64) as u64 + u64::from(carry),
        ])
    }
    /// The same rounded quotient from the exact sum, below 2^64 times the
    /// modulus, in the wide words, with the remainder as scratch.
    fn exact_rounded_quotient(
        &self,
        multipliers: &[u64],
        modulus: &WideModulus,
        wide: &mut [u64],
        remainder: &mut [u64],
    ) -> u64 {
        self.accumulate(multipliers, &self.remainders, wide);
        add_in_place(wide, &modulus.half);
        modulus.divide(wide, remainder)
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
            // A column stays below 2^63 between carries, so no addition
            // wraps.
            let mut previous_high_product = 0;
            for (column, limb) in columns[..self.limbs].iter_mut().zip(row) {
                let limb = u64::from(*limb);
                *column = column
                    .wrapping_add(low * limb)
                    .wrapping_add(previous_high_product);
                previous_high_product = high * limb;
            }
            columns[self.limbs] = columns[self.limbs].wrapping_add(previous_high_product);
        }
        carry(columns);
        pack(columns, output);
    }

    /// The canonical coefficient the residues at one position determine.
    pub(super) fn coefficient(
        &self,
        residues: &[&[u64]],
        position: usize,
        reductions: &[PrimeModulus],
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
            let multiplier = reduction.multiply_shoup(values[position], *inverse, *quotient);
            multipliers[index] = multiplier;
            fraction += widening_multiply(multiplier, self.fractions[index]).1;
        }
        multipliers[self.count] = (fraction + (1 << (FRACTION_BITS - 1))) >> FRACTION_BITS;
        let multipliers = &multipliers[..=self.count];
        let mut wide = [0u64; MAXIMUM_WORDS + 1];
        let wide = &mut wide[..=modulus.words];
        if self.tensor {
            let rounded = self
                .rounded_quotient(multipliers)
                .unwrap_or_else(|| self.exact_rounded_quotient(multipliers, modulus, wide, output));
            self.accumulate(multipliers, &self.rows, wide);
            add_in_place(wide, &[rounded]);
        } else {
            self.accumulate(multipliers, &self.rows, wide);
        }
        modulus.divide(wide, output);
    }
}

#[cfg(test)]
#[path = "word-arithmetic-tests.rs"]
mod tests;
