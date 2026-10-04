use crate::{
    DEGREE, Error, RECIPIENTS, SELECTED, SUPPORT, center, maximum_share, modulus,
    predecessor::VerifiedSeedSharingRecord, profile, share_coefficient_bytes,
};
use num_bigint::{BigInt, Sign};
use parallel_work::ProtocolHash;
use seed_sharing_proof::statement::Statement as SeedStatement;

/// An explicitly supplied fixture descriptor, not a verified selection.
/// Its digest binds this proof's context; it grants no disclosure authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureSelection {
    pub poll: [u8; 64],
    pub roster: [u8; 64],
    pub runtime: [u8; 64],
    pub records: [[u8; 64]; SELECTED],
}
impl FixtureSelection {
    pub fn digest(&self) -> [u8; 64] {
        let mut hash = ProtocolHash::new();
        word_proof::transcript::part(&mut hash, b"bounded-opening-selection-fixture/v1");
        word_proof::transcript::part(&mut hash, &self.poll);
        word_proof::transcript::part(&mut hash, &self.roster);
        word_proof::transcript::part(&mut hash, &self.runtime);
        for record in &self.records {
            word_proof::transcript::part(&mut hash, record);
        }
        hash.finalize()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Package {
    pub constant: Vec<BigInt>,
    pub linear: Vec<BigInt>,
    pub message: Vec<i128>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub(crate) selection: FixtureSelection,
    pub(crate) recipient: u16,
    pub(crate) common: Vec<BigInt>,
    pub(crate) public_key: Vec<BigInt>,
    pub(crate) packages: Vec<Package>,
}

fn header() -> Vec<u8> {
    let mut bytes = b"OPS1".to_vec();
    for value in [
        DEGREE,
        RECIPIENTS,
        SELECTED,
        SUPPORT,
        profile().sharing_coefficient_bits(),
        crate::LIMB_BITS,
        share_coefficient_bytes(),
    ] {
        bytes.extend((value as u32).to_le_bytes());
    }
    bytes.extend(supported_profile::share_modulus());
    bytes
}
pub fn encoded_bytes() -> usize {
    header().len()
        + 64
        + 2
        + (2 + 2 * SELECTED) * DEGREE * 21
        + SELECTED * DEGREE * share_coefficient_bytes()
}
pub(crate) fn valid_polynomial(values: &[BigInt]) -> bool {
    let half = modulus() >> 1usize;
    values.len() == DEGREE
        && values
            .iter()
            .all(|value| value >= &(-&half) && value <= &half)
}
pub(crate) fn valid_message(values: &[i128]) -> bool {
    values.len() == DEGREE
        && values
            .iter()
            .all(|value| (-maximum_share()..=maximum_share()).contains(value))
}
impl Statement {
    pub fn from_records(
        selection: FixtureSelection,
        recipient: u16,
        records: [&VerifiedSeedSharingRecord; SELECTED],
        messages: [Vec<i128>; SELECTED],
    ) -> Result<Self, Error> {
        if records
            .iter()
            .zip(&selection.records)
            .any(|(record, identity)| record.identity() != *identity)
        {
            return Err("Selected record identity");
        }
        Self::from_sources(
            selection,
            recipient,
            records.map(|record| record.statement()),
            messages,
        )
    }

    // Only the public constructor above crosses the verified-record boundary.
    // Algebra fixtures use this to test equations without minting a holder.
    pub(crate) fn from_sources(
        selection: FixtureSelection,
        recipient: u16,
        sources: [&SeedStatement; SELECTED],
        messages: [Vec<i128>; SELECTED],
    ) -> Result<Self, Error> {
        if usize::from(recipient) >= RECIPIENTS
            || selection.records[0] == selection.records[1]
            || sources[0].scope.author == sources[1].scope.author
        {
            return Err("Opening batch scope");
        }
        let pool = profile().release_threshold() + profile().corrupt();
        for source in sources {
            source.encode()?;
            if source.scope.poll != selection.poll
                || source.scope.roster != selection.roster
                || usize::from(source.scope.author) >= pool
                || source.common != sources[0].common
                || source
                    .recipients
                    .iter()
                    .zip(&sources[0].recipients)
                    .any(|(left, right)| left.public_key != right.public_key)
            {
                return Err("Original source context");
            }
        }
        let recipient_index = usize::from(recipient);
        let packages = sources
            .into_iter()
            .zip(messages)
            .map(|(source, message)| Package {
                constant: source.recipients[recipient_index].ciphertext[0].clone(),
                linear: source.recipients[recipient_index].ciphertext[1].clone(),
                message,
            })
            .collect();
        let statement = Self {
            selection,
            recipient,
            common: sources[0].common.clone(),
            public_key: sources[0].recipients[recipient_index].public_key.clone(),
            packages,
        };
        statement.encode()?;
        Ok(statement)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if usize::from(self.recipient) >= RECIPIENTS
            || self.packages.len() != SELECTED
            || self.selection.records[0] == self.selection.records[1]
            || !valid_polynomial(&self.common)
            || !valid_polynomial(&self.public_key)
            || self.packages.iter().any(|package| {
                !valid_polynomial(&package.constant)
                    || !valid_polynomial(&package.linear)
                    || !valid_message(&package.message)
            })
        {
            return Err("Opening statement shape or range");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = header();
        bytes.extend(self.selection.digest());
        bytes.extend(self.recipient.to_le_bytes());
        for polynomial in std::iter::once(&self.common)
            .chain(std::iter::once(&self.public_key))
            .chain(
                self.packages
                    .iter()
                    .flat_map(|package| [&package.constant, &package.linear]),
            )
        {
            for value in polynomial {
                let (sign, magnitude) = value.to_bytes_le();
                bytes.push(u8::from(sign == Sign::Minus));
                bytes.extend(&magnitude);
                bytes.resize(bytes.len() + 20 - magnitude.len(), 0);
            }
        }
        for package in &self.packages {
            for value in &package.message {
                bytes.push(u8::from(*value < 0));
                bytes.extend(&value.unsigned_abs().to_le_bytes()[..share_coefficient_bytes() - 1]);
            }
        }
        debug_assert_eq!(bytes.len(), encoded_bytes());
        Ok(bytes)
    }
    /// A canonical expected statement is reconstructed from verified source
    /// operands. Supplied bytes must match it exactly, including all framing.
    pub fn matches(&self, supplied: &[u8]) -> Result<(), Error> {
        if self.encode()? != supplied {
            return Err("Opening statement context or encoding");
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 64], Error> {
        let mut hash = ProtocolHash::new();
        hash.update(self.encode()?);
        Ok(hash.finalize())
    }
    pub(crate) fn equations(&self) -> impl Iterator<Item = (Vec<BigInt>, &[BigInt])> {
        std::iter::once((self.public_key.clone(), self.common.as_slice())).chain(
            self.packages.iter().map(|package| {
                (
                    package
                        .constant
                        .iter()
                        .zip(&package.message)
                        .map(|(value, message)| {
                            center(value - BigInt::from(crate::SCALE) * message)
                        })
                        .collect(),
                    package.linear.as_slice(),
                )
            }),
        )
    }
}
