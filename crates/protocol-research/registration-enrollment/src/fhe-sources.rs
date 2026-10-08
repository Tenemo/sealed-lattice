//! Original enrollment sources, retained separately from the recipient key.
//! Only the source seed and salt are private; the verified poll derives the
//! complete family inventory and the completed registration binds its custody.

use crate::{Error, random};
use num_bigint::BigInt;
use parallel_work::sealing::{self, Sealed, TAG_BYTES};
use registration_credentials::{
    Credential, SIGNING_PUBLIC_KEY_BYTES,
    contribution_body::{BODY_HEADER_BYTES, body_header},
    foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple},
    poll::VerifiedPoll,
    source_binding::{
        FheKeyCommitmentHasher, SOURCE_SALT_BYTES as SALT_BYTES, fhe_key_families,
        maximum_fhe_key_family_count,
    },
};
use setup_witness::{PolynomialOutput, fhe_key_source::FheKeySource};
use sha3::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update},
};
use supported_profile::Profile;
use zeroize::Zeroizing;

const SEED_BYTES: usize = 64;
const MAGIC: &[u8; 4] = b"FSC1";

struct Entry {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    salt: Zeroizing<[u8; SALT_BYTES]>,
}

pub(crate) struct Sources {
    poll: [u8; 64],
    runtime: [u8; 64],
    owner: [u8; SIGNING_PUBLIC_KEY_BYTES],
    families: Vec<Profile>,
    entries: Vec<Entry>,
    commitments: Vec<[u8; 64]>,
    sealed: bool,
}

/// Capsule length is determined by the original verified poll, not the roster.
pub fn capsule_bytes(poll: &VerifiedPoll) -> usize {
    MAGIC.len() + fhe_key_families(poll).len() * (SEED_BYTES + SALT_BYTES) + TAG_BYTES
}

pub(crate) fn maximum_capsule_bytes() -> usize {
    MAGIC.len() + maximum_fhe_key_family_count() * (SEED_BYTES + SALT_BYTES) + TAG_BYTES
}

fn associated(body: [u8; 64]) -> Vec<u8> {
    CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/fhe-source-custody/v1").unwrap(),
            CanonicalItem::hash512(body),
        ],
    )
    .encode()
    .unwrap()
}

// Absorb a canonical tuple without allocating a copy of the private seed.
fn stream(
    poll: [u8; 64],
    runtime: [u8; 64],
    owner: &[u8; SIGNING_PUBLIC_KEY_BYTES],
    profile: Profile,
    seed: &[u8; SEED_BYTES],
) -> Shake256Reader {
    let mut prefix = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/fhe-source-randomness/v1").unwrap(),
            CanonicalItem::fixed_bytes(owner).unwrap(),
            CanonicalItem::hash512(poll),
            CanonicalItem::hash512(runtime),
            CanonicalItem::variable_bytes(profile.ciphertext_modulus().to_bytes()).unwrap(),
            CanonicalItem::unsigned64(profile.fhe_common_sample_bits() as u64),
        ],
    )
    .encode()
    .unwrap();
    prefix[4..8].copy_from_slice(&7u32.to_le_bytes());
    let mut hash = Shake256::default();
    hash.update(&prefix);
    hash.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    hash.update(&(SEED_BYTES as u32).to_le_bytes());
    hash.update(seed);
    hash.finalize_xof()
}

struct CoordinateHash {
    hash: Option<FheKeyCommitmentHasher>,
    result: Option<[u8; 64]>,
}
impl PolynomialOutput for CoordinateHash {
    fn polynomial(&mut self, values: &[BigInt], _modulus: &BigInt, width: usize) {
        let mut hash = self.hash.take().expect("One FHE source coordinate");
        let mut offset = 0;
        let coefficient_bytes = 1 + width;
        let count = (1 << 20) / coefficient_bytes;
        let mut bytes = vec![0; count * coefficient_bytes];
        for chunk in values.chunks(count) {
            let encoded = &mut bytes[..chunk.len() * coefficient_bytes];
            for (value, coefficient) in chunk
                .iter()
                .zip(encoded.chunks_exact_mut(coefficient_bytes))
            {
                setup_witness::encode_coefficient(value, coefficient);
            }
            hash.push(offset, encoded)
                .expect("Canonical FHE coordinate");
            offset += encoded.len();
        }
        self.result = Some(hash.finish().expect("Complete FHE coordinate"));
    }
}

impl Sources {
    pub(crate) fn create(poll: &VerifiedPoll, credential: &Credential) -> Result<Self, Error> {
        let families = fhe_key_families(poll);
        let mut entries = Vec::with_capacity(families.len());
        let mut commitments = Vec::with_capacity(families.len());
        for profile in &families {
            let entry = Entry {
                seed: random(),
                salt: random(),
            };
            let mut reader = stream(
                poll.identity(),
                poll.runtime(),
                credential.signing_public(),
                *profile,
                &entry.seed,
            );
            let source = FheKeySource::from_reader(*profile, &mut reader);
            let mut output = CoordinateHash {
                hash: Some(
                    FheKeyCommitmentHasher::for_registration(
                        poll,
                        credential,
                        *profile,
                        &entry.salt,
                    )
                    .map_err(|_| Error::State)?,
                ),
                result: None,
            };
            source.public_coordinate(&mut output);
            commitments.push(output.result.ok_or(Error::State)?);
            entries.push(entry);
        }
        Ok(Self {
            poll: poll.identity(),
            runtime: poll.runtime(),
            owner: *credential.signing_public(),
            families,
            entries,
            commitments,
            sealed: false,
        })
    }

    fn index(&self, profile: Profile) -> Result<usize, Error> {
        self.families
            .iter()
            .position(|family| {
                family.ciphertext_modulus().to_bytes() == profile.ciphertext_modulus().to_bytes()
                    && family.fhe_common_sample_bits() == profile.fhe_common_sample_bits()
            })
            .ok_or(Error::State)
    }

    pub(crate) fn commitments(&self) -> &[[u8; 64]] {
        &self.commitments
    }

    pub(crate) fn source(&self, profile: Profile) -> Result<FheKeySource, Error> {
        let entry = &self.entries[self.index(profile)?];
        let mut random = stream(self.poll, self.runtime, &self.owner, profile, &entry.seed);
        Ok(FheKeySource::from_reader(profile, &mut random))
    }

    pub(crate) fn body_header(
        &self,
        profile: Profile,
        proof_length: usize,
    ) -> Result<[u8; BODY_HEADER_BYTES], Error> {
        body_header(
            profile,
            proof_length,
            &self.entries[self.index(profile)?].salt,
        )
        .map_err(|_| Error::State)
    }

    pub(crate) fn seal(&mut self, body: [u8; 64]) -> Result<Sealed, Error> {
        if self.sealed {
            return Err(Error::State);
        }
        self.sealed = true;
        // The buffer holds every entry at once, so building it never moves a
        // seed.
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            MAGIC.len() + self.entries.len() * (SEED_BYTES + SALT_BYTES),
        ));
        bytes.extend(MAGIC);
        for entry in &self.entries {
            bytes.extend(entry.seed.as_ref());
            bytes.extend(entry.salt.as_ref());
        }
        Ok(sealing::seal(&bytes, &associated(body)))
    }

    pub(crate) fn open(
        poll: &VerifiedPoll,
        credential: &Credential,
        commitments: &[[u8; 64]],
        body: [u8; 64],
        key: &[u8; 32],
        capsule: &[u8],
    ) -> Result<Self, Error> {
        let families = fhe_key_families(poll);
        if capsule.len() != capsule_bytes(poll) || commitments.len() != families.len() {
            return Err(Error::Shape);
        }
        let bytes = sealing::open(key, &associated(body), capsule).ok_or(Error::State)?;
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(Error::Shape);
        }
        let entries = bytes[MAGIC.len()..]
            .chunks_exact(SEED_BYTES + SALT_BYTES)
            .map(|entry| Entry {
                seed: Zeroizing::new(entry[..SEED_BYTES].try_into().unwrap()),
                salt: Zeroizing::new(entry[SEED_BYTES..].try_into().unwrap()),
            })
            .collect();
        Ok(Self {
            poll: poll.identity(),
            runtime: poll.runtime(),
            owner: *credential.signing_public(),
            families,
            entries,
            commitments: commitments.to_vec(),
            sealed: true,
        })
    }
}

#[cfg(test)]
#[path = "fhe-sources-tests.rs"]
mod tests;
