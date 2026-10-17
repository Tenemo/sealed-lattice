//! Original source encryption and its private contribution witness.

use crate::{PolynomialOutput, contribution::Contribution, fhe_key_source::FheKeySource};
use num_bigint::BigInt;
use parallel_work::ProtocolHash;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use supported_profile::{
    AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, DEGREE, Profile, auxiliary_modulus,
};
use zeroize::Zeroizing;

pub use supported_profile::source_linked::SOURCE_POLYNOMIALS;

pub fn ciphertext_bytes() -> usize {
    4 * DEGREE * (1 + auxiliary_modulus().len())
}

/// Fixed public block matrices. Smaller ring families use the same block
/// prefixes; there is no poll, roster, participant or private seed input.
pub fn common_polynomials() -> Vec<Vec<i64>> {
    let blocks = DEGREE / AUXILIARY_DEGREE;
    (0..4)
        .map(|component| {
            let mut values = vec![0; DEGREE];
            for block in 0..blocks {
                let mut state = Shake256::default();
                state.update(b"sealed-lattice/source-common/v1");
                state.update(&[component as u8]);
                state.update(&(block as u32).to_le_bytes());
                let mut reader = state.finalize_xof();
                for coefficient in 0..AUXILIARY_DEGREE {
                    let mut sample = [0u8; 72];
                    reader.read(&mut sample);
                    let mut value = 0u64;
                    for byte in sample.iter().rev() {
                        value = ((u128::from(value) * 256 + u128::from(*byte)) % modulus() as u128)
                            as u64;
                    }
                    values[block + blocks * coefficient] = centered(value as i64);
                }
            }
            values
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Encoding,
    Range,
    Binding,
    Arithmetic,
}

pub fn modulus() -> i64 {
    let mut bytes = [0u8; 8];
    let source = auxiliary_modulus();
    assert!(source.len() <= bytes.len());
    bytes[..source.len()].copy_from_slice(source);
    i64::from_le_bytes(bytes)
}
pub fn scale() -> i64 {
    (modulus() - 1) / 257
}
pub fn centered(value: i64) -> i64 {
    let modulus = modulus();
    let residue = value.rem_euclid(modulus);
    if residue > modulus / 2 {
        residue - modulus
    } else {
        residue
    }
}
/// Canonical expanded public operands, common then ciphertext for each of
/// the secret-first, secret-second, error-first and error-second equations.
/// The enclosing protocol supplies its fixed common matrices and the source
/// ciphertexts from the original authenticated registration.
#[derive(Clone)]
pub struct PublicSource {
    pub polynomials: Vec<Vec<i64>>,
}
impl PublicSource {
    pub fn check(&self, degree: usize) -> Result<(), Refusal> {
        if self.polynomials.len() != SOURCE_POLYNOMIALS
            || self
                .polynomials
                .iter()
                .any(|polynomial| polynomial.len() != degree)
        {
            return Err(Refusal::Shape);
        }
        if self
            .polynomials
            .iter()
            .flatten()
            .any(|value| value.unsigned_abs() > (modulus() / 2) as u64)
        {
            return Err(Refusal::Range);
        }
        Ok(())
    }
    pub fn records(&self) -> Result<Vec<Vec<u8>>, Refusal> {
        self.check(DEGREE)?;
        Ok(self
            .polynomials
            .iter()
            .map(|polynomial| {
                let mut bytes =
                    Vec::with_capacity(polynomial.len() * (1 + auxiliary_modulus().len()));
                for value in polynomial {
                    bytes.push(u8::from(*value < 0));
                    bytes.extend_from_slice(
                        &value.unsigned_abs().to_le_bytes()[..auxiliary_modulus().len()],
                    );
                }
                bytes
            })
            .collect())
    }
}

// Sparse negacyclic products with exact integer coefficients. This function
// never reads a secret at a quantum-controlled address.
fn product(public: &[i64], sparse: &[i8]) -> Vec<i64> {
    let degree = public.len();
    assert_eq!(sparse.len(), degree);
    let mut output = vec![0i64; degree];
    for (shift, sign) in sparse
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, value)| *value != 0)
    {
        for (index, coefficient) in public.iter().copied().enumerate() {
            let position = index + shift;
            output[position % degree] += if position < degree {
                coefficient * i64::from(sign)
            } else {
                -coefficient * i64::from(sign)
            };
        }
    }
    output
}

pub(crate) struct SourceWitness {
    words: Zeroizing<Vec<Vec<u16>>>,
    positive: Zeroizing<Vec<u16>>,
    negative: Zeroizing<Vec<u16>>,
}

impl SourceWitness {
    fn append(mut self, profile: Profile, columns: Vec<Vec<u16>>) -> Vec<Vec<u16>> {
        let mut columns = Zeroizing::new(columns);
        let shape = profile.setup_shape();
        assert_eq!(columns.len(), shape.word_columns + shape.boolean_columns);
        let mut booleans = Zeroizing::new(columns.split_off(shape.word_columns));
        let mut output = std::mem::take(&mut *columns);
        output.append(&mut *self.words);
        output.append(&mut *booleans);
        output.push(std::mem::take(&mut *self.positive));
        output.push(std::mem::take(&mut *self.negative));
        output
    }
}

/// One private stream of an original source seed: purpose 0 samples the
/// source and purpose 1 its encryption, each bound to the poll, the owner
/// and the source family's degree, modulus and common-sampler width.
fn private_stream(
    profile: Profile,
    poll: &[u8; 64],
    owner: &[u8; 64],
    seed: &[u8; 64],
    purpose: u8,
) -> impl XofReader + use<> {
    let mut state = Shake256::default();
    state.update(b"sealed-lattice/source-private/v1");
    state.update(&[purpose]);
    state.update(seed);
    state.update(poll);
    state.update(owner);
    state.update(&(DEGREE as u32).to_le_bytes());
    let modulus = profile.ciphertext_modulus().to_bytes();
    state.update(&(modulus.len() as u16).to_le_bytes());
    state.update(&modulus);
    state.update(&(profile.fhe_common_sample_bits() as u32).to_le_bytes());
    state.finalize_xof()
}

/// An original source and its encryption, created before contribution work.
/// The owner retains the original randomness and authenticates the published
/// ciphertexts. This object grants no registration or contribution authority.
pub struct EncryptedSource {
    source: FheKeySource,
    public: PublicSource,
    witness: SourceWitness,
}
impl EncryptedSource {
    pub fn public_coordinate(&self, output: &mut impl PolynomialOutput) {
        self.source.public_coordinate(output);
    }
    /// Reconstructs one original source from its retained seed. Distinct
    /// private purposes separate source sampling from encryption sampling.
    /// The owner authenticates the seed and these public contexts first.
    pub fn from_seed(
        profile: Profile,
        poll: &[u8; 64],
        owner: &[u8; 64],
        seed: [u8; 64],
    ) -> Result<Self, Refusal> {
        let seed = Zeroizing::new(seed);
        let source =
            FheKeySource::from_reader(profile, &mut private_stream(profile, poll, owner, &seed, 0));
        source.encrypt(&mut private_stream(profile, poll, owner, &seed, 1))
    }

    pub(crate) fn new(source: FheKeySource, public: PublicSource, witness: SourceWitness) -> Self {
        Self {
            source,
            public,
            witness,
        }
    }
    pub fn public(&self) -> &PublicSource {
        &self.public
    }
    /// Checks the exact original registered ciphertexts after the owner has
    /// authenticated their registration and context. It creates no capability.
    pub fn check_ciphertexts(&self, expected: &[Vec<u8>]) -> Result<(), Refusal> {
        if self.public.ciphertext_records()? != expected {
            return Err(Refusal::Binding);
        }
        Ok(())
    }
    pub fn into_contribution(
        self,
        profile: Profile,
    ) -> Result<LinkedContribution, crate::contribution::Refusal> {
        let inner = Contribution::from_source(profile, self.source)?;
        Ok(LinkedContribution {
            inner,
            witness: self.witness,
            public: self.public,
        })
    }
}

/// Keeps the original source and its linked witness together while the
/// unchanged native contribution generator consumes that source.
pub struct LinkedContribution {
    inner: Contribution,
    witness: SourceWitness,
    public: PublicSource,
}
impl LinkedContribution {
    pub fn public(&self) -> &PublicSource {
        &self.public
    }
    pub fn profile(&self) -> Profile {
        self.inner.profile()
    }
    pub fn gadget(
        &mut self,
        gadget: usize,
        output: &mut impl PolynomialOutput,
    ) -> Result<(), crate::contribution::Refusal> {
        self.inner.gadget(gadget, output)
    }
    pub fn begin_shares(
        &mut self,
        output: &mut impl PolynomialOutput,
    ) -> Result<(), crate::contribution::Refusal> {
        self.inner.begin_shares(output)
    }
    pub fn share(
        &mut self,
        recipient: usize,
        public_key: &[BigInt],
        output: &mut impl PolynomialOutput,
    ) -> Result<Vec<Vec<BigInt>>, crate::contribution::Refusal> {
        self.inner.share(recipient, public_key, output)
    }
    pub fn finish(&mut self) -> Result<(), crate::contribution::Refusal> {
        self.inner.finish()
    }
    pub fn into_columns(self) -> Result<Vec<Vec<u16>>, crate::contribution::Refusal> {
        let profile = self.inner.profile();
        let columns = self.inner.into_columns()?;
        Ok(self.witness.append(profile, columns))
    }
}

impl PublicSource {
    /// Registration carries only the four ciphertexts; the fixed common
    /// matrices are reconstructed when the linked statement is verified.
    pub fn ciphertext_records(&self) -> Result<Vec<Vec<u8>>, Refusal> {
        Ok(self
            .records()?
            .into_iter()
            .enumerate()
            .filter_map(|(index, bytes)| (index % 2 == 1).then_some(bytes))
            .collect())
    }

    /// The binding included in the original signed registration. Authentication
    /// of that expected binding is an enclosing caller obligation.
    pub fn binding(
        &self,
        profile: Profile,
        poll: &[u8; 64],
        owner: &[u8; 64],
    ) -> Result<[u8; 64], Refusal> {
        let mut hash = source_binding_hasher(profile, poll, owner);
        for record in self.ciphertext_records()? {
            hash.update(record);
        }
        Ok(hash.finalize())
    }
}

fn source_binding_hasher(profile: Profile, poll: &[u8; 64], owner: &[u8; 64]) -> ProtocolHash {
    let mut hash = ProtocolHash::new();
    hash.update(b"sealed-lattice/registered-source/v1");
    hash.update(poll);
    hash.update(owner);
    hash.update((DEGREE as u32).to_le_bytes());
    let modulus = profile.ciphertext_modulus().to_bytes();
    hash.update((modulus.len() as u16).to_le_bytes());
    hash.update(modulus);
    hash.update((profile.fhe_common_sample_bits() as u32).to_le_bytes());
    hash.update((ciphertext_bytes() as u64).to_le_bytes());
    hash
}

/// Canonical source bytes matched to a separately authenticated registration
/// binding. It performs no proof verification and creates no voting authority.
pub struct VerifiedSource {
    profile: Profile,
    public: PublicSource,
}
impl VerifiedSource {
    pub fn public(&self) -> &PublicSource {
        &self.public
    }
    pub fn into_public(self, profile: Profile) -> Result<PublicSource, Refusal> {
        if self.profile.ciphertext_modulus().to_bytes() != profile.ciphertext_modulus().to_bytes()
            || self.profile.fhe_common_sample_bits() != profile.fhe_common_sample_bits()
        {
            return Err(Refusal::Binding);
        }
        Ok(self.public)
    }
}

/// Canonical streaming body verification without retaining its coefficients.
/// Registration admission consumes this result; proof input reopening uses
/// the same parser with its coefficient collector below.
pub struct SourceBodyVerifier {
    expected: [u8; 64],
    remaining: usize,
    pending: Vec<u8>,
    hash: ProtocolHash,
    failed: bool,
}
impl SourceBodyVerifier {
    pub fn new(profile: Profile, poll: &[u8; 64], owner: &[u8; 64], expected: [u8; 64]) -> Self {
        Self {
            expected,
            remaining: ciphertext_bytes(),
            pending: Vec::new(),
            hash: source_binding_hasher(profile, poll, owner),
            failed: false,
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.push_with(bytes, |_| {})
    }
    fn push_with(&mut self, bytes: &[u8], mut decoded: impl FnMut(i64)) -> Result<(), Refusal> {
        let result = self.consume(bytes, &mut decoded);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn consume(&mut self, mut bytes: &[u8], decoded: &mut impl FnMut(i64)) -> Result<(), Refusal> {
        if self.failed
            || bytes.is_empty()
            || bytes.len() > parallel_work::CHUNK_LIMIT
            || bytes.len() > self.remaining
        {
            return Err(Refusal::Shape);
        }
        self.remaining -= bytes.len();
        self.hash.update(bytes);
        let width = 1 + auxiliary_modulus().len();
        while !bytes.is_empty() {
            let count = bytes.len().min(width - self.pending.len());
            self.pending.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.pending.len() == width {
                let mut magnitude = [0u8; 8];
                magnitude[..width - 1].copy_from_slice(&self.pending[1..]);
                let magnitude = u64::from_le_bytes(magnitude);
                if self.pending[0] > 1 || (self.pending[0] == 1 && magnitude == 0) {
                    return Err(Refusal::Encoding);
                }
                if magnitude > (modulus() / 2) as u64 {
                    return Err(Refusal::Range);
                }
                decoded(if self.pending[0] == 1 {
                    -(magnitude as i64)
                } else {
                    magnitude as i64
                });
                self.pending.clear();
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<(), Refusal> {
        if self.failed || self.remaining != 0 || !self.pending.is_empty() {
            return Err(Refusal::Shape);
        }
        if self.hash.finalize() != self.expected {
            return Err(Refusal::Binding);
        }
        Ok(())
    }
}

pub struct SourceCiphertextVerifier {
    profile: Profile,
    body: SourceBodyVerifier,
    ciphertexts: Vec<Vec<i64>>,
}
impl SourceCiphertextVerifier {
    pub fn new(profile: Profile, poll: &[u8; 64], owner: &[u8; 64], expected: [u8; 64]) -> Self {
        Self {
            profile,
            body: SourceBodyVerifier::new(profile, poll, owner, expected),
            ciphertexts: vec![Vec::new()],
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let ciphertexts = &mut self.ciphertexts;
        self.body.push_with(bytes, |value| {
            let current = ciphertexts
                .last_mut()
                .expect("The first ciphertext exists.");
            current.push(value);
            if current.len() == DEGREE && ciphertexts.len() < 4 {
                ciphertexts.push(Vec::new());
            }
        })
    }
    pub fn finish(self) -> Result<VerifiedSource, Refusal> {
        self.body.finish()?;
        if self.ciphertexts.len() != 4
            || self.ciphertexts.iter().any(|values| values.len() != DEGREE)
        {
            return Err(Refusal::Shape);
        }
        let polynomials = common_polynomials()
            .into_iter()
            .zip(self.ciphertexts)
            .flat_map(|(common, ciphertext)| [common, ciphertext])
            .collect();
        Ok(VerifiedSource {
            profile: self.profile,
            public: PublicSource { polynomials },
        })
    }
}

pub(crate) fn generate(
    secret: &[i8],
    first_error: &[i128],
    random: &mut impl XofReader,
) -> Result<(PublicSource, SourceWitness), Refusal> {
    if secret.len() != DEGREE || first_error.len() != DEGREE {
        return Err(Refusal::Shape);
    }
    if secret.iter().any(|value| !(-1..=1).contains(value))
        || first_error.iter().any(|value| !(-64..64).contains(value))
    {
        return Err(Refusal::Range);
    }
    let auxiliary = Zeroizing::new(crate::sparse_values_from_reader(
        AUXILIARY_DEGREE,
        AUXILIARY_SECRET_SUPPORT,
        random,
    ));
    let mut ephemeral = Zeroizing::new(vec![0i8; DEGREE]);
    for (index, value) in auxiliary.iter().copied().enumerate() {
        ephemeral[index * (DEGREE / AUXILIARY_DEGREE)] = value;
    }
    let common = common_polynomials();
    let mut polynomials = Vec::with_capacity(SOURCE_POLYNOMIALS);
    let mut words = Zeroizing::new(Vec::with_capacity(8));
    for (component, common_polynomial) in common.iter().enumerate() {
        let errors = Zeroizing::new(crate::errors_from_reader(DEGREE, random));
        let mut values = product(common_polynomial, &ephemeral);
        let mut quotients = Vec::with_capacity(DEGREE);
        let mut error_words = Vec::with_capacity(DEGREE);
        for position in 0..DEGREE {
            let message = match component {
                0 => 1 + i64::from(secret[position]),
                2 => (first_error[position] + 64) as i64,
                _ => 0,
            };
            let raw = values[position] + errors[position] as i64 + scale() * message;
            let value = centered(raw);
            let quotient = (raw - value) / modulus();
            if !(-32768..32768).contains(&quotient) {
                return Err(Refusal::Arithmetic);
            }
            values[position] = value;
            quotients.push((quotient + 32768) as u16);
            error_words.push((errors[position] + 64) as u16);
        }
        polynomials.push(common_polynomial.clone());
        polynomials.push(values);
        words.push(quotients);
        words.push(error_words);
    }
    Ok((
        PublicSource { polynomials },
        SourceWitness {
            words,
            positive: Zeroizing::new(
                ephemeral
                    .iter()
                    .map(|value| u16::from(*value == 1))
                    .collect(),
            ),
            negative: Zeroizing::new(
                ephemeral
                    .iter()
                    .map(|value| u16::from(*value == -1))
                    .collect(),
            ),
        },
    ))
}

#[cfg(test)]
#[path = "encrypted-source-tests.rs"]
mod tests;
