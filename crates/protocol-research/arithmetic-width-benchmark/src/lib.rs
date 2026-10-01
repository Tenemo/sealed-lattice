//! The encrypted arithmetic's transforms and pointwise products on its
//! current 58-bit primes, against the same work on primes below `2^31`
//! whose product covers the same ciphertext tensor bound. Every width
//! computes the negacyclic products of the same polynomials modulo its own
//! primes; the native checks compare the integers they reconstruct, and the
//! timings run on one thread natively and in scalar WebAssembly. The primes
//! are internal to the arithmetic, so no protocol output depends on the
//! width.
use fhe_math::{ntt::NttOperator, zq::Modulus};
use num_bigint::BigUint;
use supported_profile::{DEGREE, Profile};

/// Fraction bits of the current lift's fixed-point sum, whose rounding
/// margin the coverage rule charges.
const FRACTION_BITS: u32 = 57;

/// The shift of the narrow primes: each is one more than an odd multiple of
/// twice the ring degree, which the negacyclic transform needs.
const NARROW_SHIFT: u32 = (2 * DEGREE).trailing_zeros();

/// The prime family of one arithmetic width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    /// The current primes `odd * 2^32 + 1` of 58 bits on 64-bit words.
    Current,
    /// Primes of 30 bits, whose lazily reduced transform values stay below
    /// four times the prime and so within a 32-bit word.
    Lazy30,
    /// Primes of 31 bits, whose residues the transforms keep reduced.
    Reduced31,
}

impl Width {
    pub const ALL: [Self; 3] = [Self::Current, Self::Lazy30, Self::Reduced31];

    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.get(usize::try_from(code).ok()?).copied()
    }
    pub fn code(self) -> usize {
        match self {
            Self::Current => 0,
            Self::Lazy30 => 1,
            Self::Reduced31 => 2,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Current => "current-58",
            Self::Lazy30 => "lazy-30",
            Self::Reduced31 => "reduced-31",
        }
    }
}

/// One timed workload over every prime of a width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    /// The forward transform of one polynomial.
    Forward,
    /// The backward transform of one polynomial.
    Backward,
    /// The pointwise product of two polynomials.
    Product,
    /// Two forward transforms, their pointwise product and its backward
    /// transform: one negacyclic product, as a ciphertext tensor computes
    /// each of its products.
    Tensor,
}

impl Kernel {
    pub const ALL: [Self; 4] = [Self::Forward, Self::Backward, Self::Product, Self::Tensor];

    pub fn from_code(code: u32) -> Option<Self> {
        Self::ALL.get(usize::try_from(code).ok()?).copied()
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Backward => "backward",
            Self::Product => "product",
            Self::Tensor => "tensor",
        }
    }
}

/// The smallest or the largest ciphertext modulus of the supported profiles.
pub fn ciphertext_modulus(largest: bool) -> BigUint {
    let moduli = Profile::all().map(|profile| {
        let modulus = profile.ciphertext_modulus();
        (BigUint::from(modulus.odd_factor()) << modulus.exponent()) + 1u32
    });
    if largest { moduli.max() } else { moduli.min() }.unwrap()
}

/// Twice the largest magnitude of a ciphertext tensor coefficient, `2 N
/// (q/2)^2`, which the current arithmetic's primes cover.
pub fn tensor_bound(modulus: &BigUint) -> BigUint {
    let half = modulus >> 1usize;
    BigUint::from(2 * DEGREE as u64) * &half * &half
}

/// Whether the product of the primes exceeds the bound by the margin that
/// rounding the current lift's fixed-point sum needs, the rule by which the
/// current arithmetic counts its primes.
pub fn covers(product: &BigUint, count: usize, bound: &BigUint) -> bool {
    product > bound && ((product - bound) << FRACTION_BITS) >= product * (4 * count)
}

/// `value^exponent` modulo the modulus.
pub fn power(mut value: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = (u128::from(result) * u128::from(value) % u128::from(modulus)) as u64;
        }
        value = (u128::from(value) * u128::from(value) % u128::from(modulus)) as u64;
        exponent >>= 1;
    }
    result
}

/// The largest prime `odd * 2^32 + 1` of 58 bits below the limit, certified
/// by Proth's theorem with witness three, as the current arithmetic chooses
/// its primes.
fn current_prime(below: u64) -> u64 {
    let mut odd = (((below - 1) >> 32) - 1) | 1;
    loop {
        let candidate = (odd << 32) + 1;
        assert_eq!(64 - candidate.leading_zeros(), 58);
        assert!(odd < 1u64 << 32);
        if candidate < below && power(3, (candidate - 1) / 2, candidate) == candidate - 1 {
            return candidate;
        }
        odd -= 2;
    }
}

/// The largest prime `odd * 2^NARROW_SHIFT + 1` of the bit length below the
/// limit that has a Proth witness below 64. Proth's theorem certifies it
/// because the odd factor is below the power of two.
fn narrow_prime(below: u64, bits: u32) -> u64 {
    let mut odd = (below - 2) >> NARROW_SHIFT;
    if odd.is_multiple_of(2) {
        odd -= 1;
    }
    loop {
        assert!(odd < 1u64 << NARROW_SHIFT);
        let candidate = (odd << NARROW_SHIFT) + 1;
        assert_eq!(
            64 - candidate.leading_zeros(),
            bits,
            "too few primes of the width"
        );
        for base in 2..64 {
            match power(base, (candidate - 1) / 2, candidate) {
                result if result == candidate - 1 => return candidate,
                1 => continue,
                _ => break,
            }
        }
        odd -= 2;
    }
}

/// The primes of a width, largest first, as many as the current rule needs
/// to cover the bound.
pub fn primes(width: Width, bound: &BigUint) -> Vec<u64> {
    let mut primes = Vec::new();
    let mut product = BigUint::from(1u32);
    let mut limit = match width {
        Width::Current => 1u64 << 58,
        Width::Lazy30 => 1u64 << 30,
        Width::Reduced31 => 1u64 << 31,
    };
    while !covers(&product, primes.len(), bound) {
        limit = match width {
            Width::Current => current_prime(limit),
            Width::Lazy30 => narrow_prime(limit, 30),
            Width::Reduced31 => narrow_prime(limit, 31),
        };
        primes.push(limit);
        product *= limit;
    }
    primes
}

/// The arithmetic modulo one prime that the kernels use.
pub trait PrimeArithmetic {
    type Word: Copy + Default + Into<u64>;
    /// The word of a value below the prime.
    fn word(value: u64) -> Self::Word;
    fn forward(&self, values: &mut [Self::Word]);
    fn backward(&self, values: &mut [Self::Word]);
    fn multiply(&self, left: Self::Word, right: Self::Word) -> Self::Word;
}

/// The current arithmetic modulo one prime: the vendored transform and
/// modular product the encrypted arithmetic calls.
pub struct CurrentTransform {
    modulus: Modulus,
    transform: NttOperator,
}

impl CurrentTransform {
    pub fn new(prime: u64, size: usize) -> Self {
        let modulus = Modulus::new(prime).unwrap();
        let transform = NttOperator::new(&modulus, size).unwrap();
        Self { modulus, transform }
    }
}

impl PrimeArithmetic for CurrentTransform {
    type Word = u64;

    fn word(value: u64) -> u64 {
        value
    }
    fn forward(&self, values: &mut [u64]) {
        self.transform.forward(values);
    }
    fn backward(&self, values: &mut [u64]) {
        self.transform.backward(values);
    }
    fn multiply(&self, left: u64, right: u64) -> u64 {
        self.modulus.mul(left, right)
    }
}

/// `condition ? on_true : on_false` without a branch, as the current
/// arithmetic selects.
const fn select(on_true: u32, on_false: u32, condition: bool) -> u32 {
    let mask = (condition as u32).wrapping_neg();
    ((on_true ^ on_false) & mask) ^ on_false
}

/// The value reduced from below twice the modulus to below it.
const fn reduce_once(value: u32, modulus: u32) -> u32 {
    select(value, value.wrapping_sub(modulus), value < modulus)
}

/// The negacyclic transform and pointwise product modulo one prime below
/// `2^31`, with the current transform's loop structure on 32-bit words. A
/// lazy transform keeps values below four times its prime, which needs the
/// prime below `2^30`; otherwise every butterfly reduces fully.
pub struct NarrowTransform<const LAZY: bool> {
    prime: u32,
    twice: u32,
    bits: u32,
    /// `floor(2^(2 bits) / prime)`, which reduces a product of two
    /// residues.
    barrett: u64,
    omegas: Box<[u32]>,
    omegas_shoup: Box<[u32]>,
    size_inverse: u32,
    size_inverse_shoup: u32,
}

impl<const LAZY: bool> NarrowTransform<LAZY> {
    pub fn new(prime: u64, size: usize) -> Self {
        assert!(size.is_power_of_two() && size >= 2);
        assert_eq!((prime - 1) % (2 * size as u64), 0);
        let bits = 64 - prime.leading_zeros();
        assert!(bits <= if LAZY { 30 } else { 31 });
        // A quadratic non-residue's power by the cofactor of 2 size has
        // order exactly 2 size, because its power by half the group order is
        // -1.
        let non_residue = (2..)
            .find(|&base| power(base, (prime - 1) / 2, prime) == prime - 1)
            .unwrap();
        let root = power(non_residue, (prime - 1) / (2 * size as u64), prime);
        let mut powers = Vec::with_capacity(size);
        let mut value = 1u64;
        for _ in 0..size {
            powers.push(value as u32);
            value = value * root % prime;
        }
        let shoup = |value: u32| ((u64::from(value) << 32) / prime) as u32;
        let omegas: Box<[u32]> = (0..size)
            .map(|index| powers[index.reverse_bits() >> (size.leading_zeros() + 1)])
            .collect();
        let omegas_shoup = omegas.iter().map(|&omega| shoup(omega)).collect();
        let size_inverse = (prime - (prime - 1) / size as u64) as u32;
        Self {
            prime: prime as u32,
            twice: 2 * prime as u32,
            bits,
            barrett: (1u64 << (2 * bits)) / prime,
            omegas,
            omegas_shoup,
            size_inverse,
            size_inverse_shoup: shoup(size_inverse),
        }
    }

    /// `value * omega` modulo the prime, below twice it, for any word.
    #[inline(always)]
    fn lazy_multiply_shoup(&self, value: u32, omega: u32, omega_shoup: u32) -> u32 {
        let quotient = ((u64::from(value) * u64::from(omega_shoup)) >> 32) as u32;
        value
            .wrapping_mul(omega)
            .wrapping_sub(quotient.wrapping_mul(self.prime))
    }

    #[inline(always)]
    fn butterfly(&self, x: &mut u32, y: &mut u32, omega: u32, omega_shoup: u32) {
        if LAZY {
            let left = reduce_once(*x, self.twice);
            let product = self.lazy_multiply_shoup(*y, omega, omega_shoup);
            *y = left + self.twice - product;
            *x = left + product;
        } else {
            let left = *x;
            let product = reduce_once(self.lazy_multiply_shoup(*y, omega, omega_shoup), self.prime);
            *x = reduce_once(left + product, self.prime);
            *y = reduce_once(left + self.prime - product, self.prime);
        }
    }

    #[inline(always)]
    fn inverse_butterfly(&self, x: &mut u32, y: &mut u32, zeta: u32, zeta_shoup: u32) {
        let left = *x;
        if LAZY {
            *x = reduce_once(*y + left, self.twice);
            *y = self.lazy_multiply_shoup(self.twice + left - *y, zeta, zeta_shoup);
        } else {
            *x = reduce_once(*y + left, self.prime);
            *y = reduce_once(
                self.lazy_multiply_shoup(self.prime + left - *y, zeta, zeta_shoup),
                self.prime,
            );
        }
    }
}

impl<const LAZY: bool> PrimeArithmetic for NarrowTransform<LAZY> {
    type Word = u32;

    fn word(value: u64) -> u32 {
        u32::try_from(value).unwrap()
    }
    fn forward(&self, values: &mut [u32]) {
        debug_assert_eq!(values.len(), self.omegas.len());
        let mut half = values.len() >> 1;
        let mut index = 1;
        while half > 0 {
            for chunk in values.chunks_exact_mut(2 * half) {
                let omega = self.omegas[index];
                let omega_shoup = self.omegas_shoup[index];
                index += 1;
                let (left, right) = chunk.split_at_mut(half);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    self.butterfly(x, y, omega, omega_shoup);
                }
                if LAZY && half == 1 {
                    left[0] = reduce_once(reduce_once(left[0], self.twice), self.prime);
                    right[0] = reduce_once(reduce_once(right[0], self.twice), self.prime);
                }
            }
            half >>= 1;
        }
    }
    fn backward(&self, values: &mut [u32]) {
        let size = values.len();
        debug_assert_eq!(size, self.omegas.len());
        let mut index = 0;
        let mut half = 1;
        while half < size {
            for chunk in values.chunks_exact_mut(2 * half) {
                let zeta = self.prime - self.omegas[size - 1 - index];
                let zeta_shoup = !self.omegas_shoup[size - 1 - index];
                index += 1;
                let (left, right) = chunk.split_at_mut(half);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    self.inverse_butterfly(x, y, zeta, zeta_shoup);
                }
            }
            half <<= 1;
        }
        for value in values.iter_mut() {
            *value = reduce_once(
                self.lazy_multiply_shoup(*value, self.size_inverse, self.size_inverse_shoup),
                self.prime,
            );
        }
    }
    /// The product's Barrett quotient from its top bits is at most two
    /// below the exact one, so two reductions finish it.
    fn multiply(&self, left: u32, right: u32) -> u32 {
        let product = u64::from(left) * u64::from(right);
        let quotient = ((product >> (self.bits - 1)) * self.barrett) >> (self.bits + 1);
        let prime = u64::from(self.prime);
        let remainder = product - quotient * prime;
        let once = if remainder >= prime {
            remainder.wrapping_sub(prime)
        } else {
            remainder
        };
        let once = u32::try_from(once).unwrap();
        reduce_once(once, self.prime)
    }
}

/// One width's inputs and outputs modulo each of its primes.
pub struct Residues<A: PrimeArithmetic> {
    arithmetic: Vec<A>,
    primes: Vec<u64>,
    left: Vec<Vec<A::Word>>,
    right: Vec<Vec<A::Word>>,
    output: Vec<Vec<A::Word>>,
    first: Vec<A::Word>,
    second: Vec<A::Word>,
}

impl<A: PrimeArithmetic> Residues<A> {
    fn new(
        arithmetic: Vec<A>,
        primes: &[u64],
        left: &[Vec<u64>],
        right: &[Vec<u64>],
        size: usize,
    ) -> Self {
        let words = |residues: &[Vec<u64>]| -> Vec<Vec<A::Word>> {
            residues
                .iter()
                .zip(primes)
                .map(|(values, &prime)| {
                    assert_eq!(values.len(), size);
                    values
                        .iter()
                        .map(|&value| {
                            assert!(value < prime);
                            A::word(value)
                        })
                        .collect()
                })
                .collect()
        };
        assert_eq!(left.len(), primes.len());
        assert_eq!(right.len(), primes.len());
        Self {
            arithmetic,
            primes: primes.to_vec(),
            left: words(left),
            right: words(right),
            output: vec![vec![A::Word::default(); size]; primes.len()],
            first: vec![A::Word::default(); size],
            second: vec![A::Word::default(); size],
        }
    }

    fn run(&mut self, kernel: Kernel) {
        for (index, arithmetic) in self.arithmetic.iter().enumerate() {
            self.first.copy_from_slice(&self.left[index]);
            match kernel {
                Kernel::Forward => arithmetic.forward(&mut self.first),
                Kernel::Backward => arithmetic.backward(&mut self.first),
                Kernel::Product => {
                    for (value, other) in self.first.iter_mut().zip(&self.right[index]) {
                        *value = arithmetic.multiply(*value, *other);
                    }
                }
                Kernel::Tensor => {
                    self.second.copy_from_slice(&self.right[index]);
                    arithmetic.forward(&mut self.first);
                    arithmetic.forward(&mut self.second);
                    for (value, other) in self.first.iter_mut().zip(&self.second) {
                        *value = arithmetic.multiply(*value, *other);
                    }
                    arithmetic.backward(&mut self.first);
                    self.output[index].copy_from_slice(&self.first);
                }
            }
            std::hint::black_box(&mut self.first);
        }
    }

    fn outputs(&self) -> Vec<Vec<u64>> {
        self.output
            .iter()
            .map(|values| values.iter().map(|&value| value.into()).collect())
            .collect()
    }

    /// FNV-1a over the little-endian outputs, which identifies the same
    /// width's outputs across builds.
    fn digest(&self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for values in &self.output {
            for &value in values {
                for byte in Into::<u64>::into(value).to_le_bytes() {
                    hash ^= u64::from(byte);
                    hash = hash.wrapping_mul(0x0100_0000_01b3);
                }
            }
        }
        hash
    }
}

/// SplitMix64, which draws inputs identically on every target.
pub fn split_mix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// One width's arithmetic and residues at the ring degree.
pub enum Workload {
    Current(Residues<CurrentTransform>),
    Lazy30(Residues<NarrowTransform<true>>),
    Reduced31(Residues<NarrowTransform<false>>),
}

impl Workload {
    /// The width's primes for the smallest or largest ciphertext modulus,
    /// with residues drawn from the seed.
    pub fn new(width: Width, largest: bool, seed: u64) -> Self {
        let primes = primes(width, &tensor_bound(&ciphertext_modulus(largest)));
        let draw = |side: u64| -> Vec<Vec<u64>> {
            primes
                .iter()
                .enumerate()
                .map(|(index, &prime)| {
                    let mut state = seed ^ (((index as u64) << 1 | side) << 32);
                    (0..DEGREE).map(|_| split_mix(&mut state) % prime).collect()
                })
                .collect()
        };
        Self::from_residues(width, &primes, &draw(0), &draw(1))
    }

    /// The width's arithmetic over the given primes and residues below
    /// them.
    pub fn from_residues(
        width: Width,
        primes: &[u64],
        left: &[Vec<u64>],
        right: &[Vec<u64>],
    ) -> Self {
        match width {
            Width::Current => Self::Current(Residues::new(
                primes
                    .iter()
                    .map(|&prime| CurrentTransform::new(prime, DEGREE))
                    .collect(),
                primes,
                left,
                right,
                DEGREE,
            )),
            Width::Lazy30 => Self::Lazy30(Residues::new(
                primes
                    .iter()
                    .map(|&prime| NarrowTransform::new(prime, DEGREE))
                    .collect(),
                primes,
                left,
                right,
                DEGREE,
            )),
            Width::Reduced31 => Self::Reduced31(Residues::new(
                primes
                    .iter()
                    .map(|&prime| NarrowTransform::new(prime, DEGREE))
                    .collect(),
                primes,
                left,
                right,
                DEGREE,
            )),
        }
    }

    pub fn primes(&self) -> &[u64] {
        match self {
            Self::Current(residues) => &residues.primes,
            Self::Lazy30(residues) => &residues.primes,
            Self::Reduced31(residues) => &residues.primes,
        }
    }
    pub fn run(&mut self, kernel: Kernel) {
        match self {
            Self::Current(residues) => residues.run(kernel),
            Self::Lazy30(residues) => residues.run(kernel),
            Self::Reduced31(residues) => residues.run(kernel),
        }
    }
    /// The products of the last tensor run modulo each prime.
    pub fn outputs(&self) -> Vec<Vec<u64>> {
        match self {
            Self::Current(residues) => residues.outputs(),
            Self::Lazy30(residues) => residues.outputs(),
            Self::Reduced31(residues) => residues.outputs(),
        }
    }
    pub fn digest(&self) -> u64 {
        match self {
            Self::Current(residues) => residues.digest(),
            Self::Lazy30(residues) => residues.digest(),
            Self::Reduced31(residues) => residues.digest(),
        }
    }
}

/// The WebAssembly interface, which a host times call by call: each width's
/// workload stays resident so that the host can alternate widths.
#[cfg(target_arch = "wasm32")]
mod exports {
    use super::{Kernel, Width, Workload};
    use std::cell::RefCell;

    thread_local! {
        static WORKLOADS: RefCell<[Option<Workload>; 3]> = const { RefCell::new([None, None, None]) };
    }

    /// Prepares a width's workload for the smallest (0) or largest (1)
    /// ciphertext modulus and returns its prime count, or zero for an
    /// unknown width or modulus.
    #[unsafe(no_mangle)]
    pub extern "C" fn benchmark_prepare(width: u32, largest: u32, seed: u64) -> u32 {
        let (Some(width), true) = (Width::from_code(width), largest <= 1) else {
            return 0;
        };
        WORKLOADS.with(|workloads| {
            let mut workloads = workloads.borrow_mut();
            workloads[width.code()] = None;
            let workload = Workload::new(width, largest == 1, seed);
            let count = u32::try_from(workload.primes().len()).unwrap();
            workloads[width.code()] = Some(workload);
            count
        })
    }

    /// Runs one kernel of a prepared width and returns zero, or one for an
    /// unknown or unprepared request.
    #[unsafe(no_mangle)]
    pub extern "C" fn benchmark_run(width: u32, kernel: u32) -> u32 {
        let (Some(width), Some(kernel)) = (Width::from_code(width), Kernel::from_code(kernel))
        else {
            return 1;
        };
        WORKLOADS.with(
            |workloads| match &mut workloads.borrow_mut()[width.code()] {
                Some(workload) => {
                    workload.run(kernel);
                    0
                }
                None => 1,
            },
        )
    }

    /// The digest of a prepared width's last tensor outputs, or zero.
    #[unsafe(no_mangle)]
    pub extern "C" fn benchmark_digest(width: u32) -> u64 {
        let Some(width) = Width::from_code(width) else {
            return 0;
        };
        WORKLOADS.with(|workloads| {
            workloads.borrow()[width.code()]
                .as_ref()
                .map_or(0, Workload::digest)
        })
    }

    /// Releases every prepared workload.
    #[unsafe(no_mangle)]
    pub extern "C" fn benchmark_release() {
        WORKLOADS.with(|workloads| *workloads.borrow_mut() = [None, None, None]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_prime(value: u64) -> bool {
        value >= 2
            && (2..)
                .take_while(|divisor| divisor * divisor <= value)
                .all(|divisor| !value.is_multiple_of(divisor))
    }

    fn schoolbook(left: &[u64], right: &[u64], prime: u64) -> Vec<u64> {
        let size = left.len();
        let mut output = vec![0u128; size];
        for (first, &a) in left.iter().enumerate() {
            for (second, &b) in right.iter().enumerate() {
                let product = u128::from(a) * u128::from(b) % u128::from(prime);
                let position = first + second;
                if position < size {
                    output[position] = (output[position] + product) % u128::from(prime);
                } else {
                    let slot = &mut output[position - size];
                    *slot = (*slot + u128::from(prime) - product) % u128::from(prime);
                }
            }
        }
        output.into_iter().map(|value| value as u64).collect()
    }

    fn negacyclic<A: PrimeArithmetic>(arithmetic: &A, left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut first: Vec<A::Word> = left.iter().map(|&value| A::word(value)).collect();
        let mut second: Vec<A::Word> = right.iter().map(|&value| A::word(value)).collect();
        arithmetic.forward(&mut first);
        arithmetic.forward(&mut second);
        for (value, other) in first.iter_mut().zip(&second) {
            *value = arithmetic.multiply(*value, *other);
        }
        arithmetic.backward(&mut first);
        first.into_iter().map(Into::into).collect()
    }

    fn inputs(prime: u64, size: usize, seed: u64) -> [(Vec<u64>, Vec<u64>); 3] {
        let mut state = seed;
        let mut draw = || {
            (0..size)
                .map(|_| split_mix(&mut state) % prime)
                .collect::<Vec<_>>()
        };
        [
            (draw(), draw()),
            (vec![prime - 1; size], vec![prime - 1; size]),
            (
                (0..size as u64)
                    .map(|index| index % 2 * (prime - 1))
                    .collect(),
                vec![prime - 1; size],
            ),
        ]
    }

    #[test]
    fn narrow_primes_are_distinct_primes_of_their_width_that_support_the_transform() {
        let bound = tensor_bound(&ciphertext_modulus(true));
        for (width, bits) in [(Width::Lazy30, 30), (Width::Reduced31, 31)] {
            let primes = primes(width, &bound);
            for pair in primes.windows(2) {
                assert!(pair[0] > pair[1]);
            }
            for &prime in &primes {
                assert!(is_prime(prime), "{prime}");
                assert_eq!(64 - prime.leading_zeros(), bits);
                assert_eq!((prime - 1) % (2 * DEGREE as u64), 0);
            }
        }
    }

    #[test]
    fn coverage_charges_the_rounding_margin() {
        // (P - B) 2^57 >= 4 count P decides, not P > B alone.
        let product = BigUint::from(1u32) << 100usize;
        let bound = &product - (BigUint::from(1u32) << 44usize);
        assert!(!covers(&product, 1, &bound));
        assert!(covers(
            &product,
            1,
            &(&product - (BigUint::from(1u32) << 45usize))
        ));
        assert!(!covers(
            &product,
            3,
            &(&product - (BigUint::from(1u32) << 45usize))
        ));
    }

    #[test]
    fn every_width_covers_the_bound_with_its_least_count() {
        for largest in [false, true] {
            let bound = tensor_bound(&ciphertext_modulus(largest));
            for width in Width::ALL {
                let primes = primes(width, &bound);
                let product = |count: usize| {
                    primes[..count]
                        .iter()
                        .fold(BigUint::from(1u32), |product, &prime| product * prime)
                };
                assert!(covers(&product(primes.len()), primes.len(), &bound));
                assert!(!covers(
                    &product(primes.len() - 1),
                    primes.len() - 1,
                    &bound
                ));
            }
        }
    }

    #[test]
    fn narrow_products_reduce_exactly() {
        fn check<A: PrimeArithmetic<Word = u32>>(arithmetic: &A, prime: u64) {
            let mut state = prime;
            let mut values: Vec<u64> =
                vec![0, 1, 2, prime - 2, prime - 1, prime / 2, prime / 2 + 1];
            values.extend((0..64).map(|_| split_mix(&mut state) % prime));
            for &left in &values {
                for &right in &values {
                    let actual = arithmetic.multiply(left as u32, right as u32);
                    assert_eq!(
                        u64::from(actual),
                        left * right % prime,
                        "{prime} {left} {right}"
                    );
                }
            }
        }
        for largest in [false, true] {
            let bound = tensor_bound(&ciphertext_modulus(largest));
            for prime in primes(Width::Lazy30, &bound) {
                check(&NarrowTransform::<true>::new(prime, 8), prime);
            }
            for prime in primes(Width::Reduced31, &bound) {
                check(&NarrowTransform::<false>::new(prime, 8), prime);
            }
        }
    }

    #[test]
    fn narrow_transforms_compute_negacyclic_products() {
        let bound = tensor_bound(&ciphertext_modulus(true));
        let lazy_prime = *primes(Width::Lazy30, &bound).last().unwrap();
        let reduced_prime = primes(Width::Reduced31, &bound)[0];
        for size in [2, 8, 64, 1024] {
            for (left, right) in inputs(lazy_prime, size, 7) {
                assert_eq!(
                    negacyclic(
                        &NarrowTransform::<true>::new(lazy_prime, size),
                        &left,
                        &right
                    ),
                    schoolbook(&left, &right, lazy_prime)
                );
            }
            for (left, right) in inputs(reduced_prime, size, 11) {
                assert_eq!(
                    negacyclic(
                        &NarrowTransform::<false>::new(reduced_prime, size),
                        &left,
                        &right
                    ),
                    schoolbook(&left, &right, reduced_prime)
                );
            }
        }
    }

    #[test]
    fn transforms_at_the_ring_degree_return_their_input() {
        let bound = tensor_bound(&ciphertext_modulus(false));
        let lazy_prime = primes(Width::Lazy30, &bound)[0];
        let reduced_prime = primes(Width::Reduced31, &bound)[0];
        let [(values, _), _, _] = inputs(lazy_prime, DEGREE, 3);
        let lazy = NarrowTransform::<true>::new(lazy_prime, DEGREE);
        let mut words: Vec<u32> = values.iter().map(|&value| value as u32).collect();
        lazy.forward(&mut words);
        assert!(words.iter().all(|&word| u64::from(word) < lazy_prime));
        lazy.backward(&mut words);
        assert!(
            words
                .iter()
                .map(|&word| u64::from(word))
                .eq(values.iter().copied())
        );
        let [(values, _), _, _] = inputs(reduced_prime, DEGREE, 5);
        let reduced = NarrowTransform::<false>::new(reduced_prime, DEGREE);
        let mut words: Vec<u32> = values.iter().map(|&value| value as u32).collect();
        reduced.forward(&mut words);
        assert!(words.iter().all(|&word| u64::from(word) < reduced_prime));
        reduced.backward(&mut words);
        assert!(
            words
                .iter()
                .map(|&word| u64::from(word))
                .eq(values.iter().copied())
        );
    }
}
