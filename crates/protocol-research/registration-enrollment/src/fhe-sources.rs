//! Original enrollment sources, retained separately from the recipient key.
//! Only the source seed and salt are private; the verified poll derives the
//! complete family inventory and the completed registration binds its custody.

use crate::{Error, random};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use num_bigint::{BigInt, Sign};
use registration_credentials::{
    Credential,
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
const TAG_BYTES: usize = 16;

struct Entry {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    salt: Zeroizing<[u8; SALT_BYTES]>,
}

pub(crate) struct Sources {
    poll: [u8; 64],
    runtime: [u8; 64],
    owner: [u8; 1952],
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
    owner: &[u8; 1952],
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
        let mut bytes = Vec::with_capacity(1 << 20);
        let count = (1 << 20) / (1 + width);
        for chunk in values.chunks(count) {
            bytes.clear();
            for value in chunk {
                let (sign, magnitude) = value.to_bytes_le();
                bytes.push(u8::from(sign == Sign::Minus));
                bytes.extend(&magnitude);
                bytes.resize(bytes.len() + width - magnitude.len(), 0);
            }
            hash.push(offset, &bytes).expect("Canonical FHE coordinate");
            offset += bytes.len();
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

    pub(crate) fn seal(&mut self, body: [u8; 64], key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        if self.sealed {
            return Err(Error::State);
        }
        self.sealed = true;
        let mut bytes = Zeroizing::new(MAGIC.to_vec());
        for entry in &self.entries {
            bytes.extend(entry.seed.as_ref());
            bytes.extend(entry.salt.as_ref());
        }
        Aes256Gcm::new(key.into())
            .encrypt_in_place(Nonce::from_slice(&[0; 12]), &associated(body), &mut *bytes)
            .map_err(|_| Error::State)?;
        Ok(std::mem::take(&mut *bytes))
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
        let mut bytes = Zeroizing::new(capsule.to_vec());
        Aes256Gcm::new(key.into())
            .decrypt_in_place(Nonce::from_slice(&[0; 12]), &associated(body), &mut *bytes)
            .map_err(|_| Error::State)?;
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
mod tests {
    use super::*;
    use registration_credentials::{
        foundation::{
            StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
        },
        poll::{PollDraft, verify_poll},
    };
    use sha3::digest::XofReader;

    fn poll() -> (VerifiedPoll, Credential) {
        let text =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let options = (0..2)
            .map(|index| {
                OptionDefinition::new(
                    index,
                    format!("option-{index}"),
                    text(&format!("Option {index}")),
                )
                .unwrap()
            })
            .collect();
        let draft =
            PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 1, 3).unwrap();
        let mut credential = Credential::from_seed([19; 32]);
        let signed = credential.create_poll(draft, [7; 64], [11; 32]).unwrap();
        (
            verify_poll(signed.identity, [7; 64], &signed.body, &signed.signature).unwrap(),
            credential,
        )
    }

    #[test]
    fn source_stream_matches_canonical_tuple_and_binds_each_original_context() {
        let profile = Profile::new(3, 2).unwrap();
        let owner = [23; 1952];
        let seed = [29; 64];
        let canonical = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii("sealed-lattice/fhe-source-randomness/v1").unwrap(),
                CanonicalItem::fixed_bytes(owner).unwrap(),
                CanonicalItem::hash512([3; 64]),
                CanonicalItem::hash512([5; 64]),
                CanonicalItem::variable_bytes(profile.ciphertext_modulus().to_bytes()).unwrap(),
                CanonicalItem::unsigned64(profile.fhe_common_sample_bits() as u64),
                CanonicalItem::fixed_bytes(seed).unwrap(),
            ],
        )
        .encode()
        .unwrap();
        let mut hash = Shake256::default();
        hash.update(&canonical);
        let mut expected = [0; 160];
        hash.finalize_xof().read(&mut expected);
        let output = |poll, runtime, owner: &[u8; 1952], profile, seed: &[u8; 64]| {
            let mut bytes = [0; 160];
            stream(poll, runtime, owner, profile, seed).read(&mut bytes);
            bytes
        };
        assert_eq!(output([3; 64], [5; 64], &owner, profile, &seed), expected);
        assert_ne!(output([4; 64], [5; 64], &owner, profile, &seed), expected);
        assert_ne!(output([3; 64], [6; 64], &owner, profile, &seed), expected);
        assert_ne!(
            output([3; 64], [5; 64], &[24; 1952], profile, &seed),
            expected
        );
        assert_ne!(
            output([3; 64], [5; 64], &owner, profile, &[30; 64]),
            expected
        );
        let other = Profile::all()
            .find(|candidate| candidate.ciphertext_modulus() != profile.ciphertext_modulus())
            .unwrap();
        assert_ne!(output([3; 64], [5; 64], &owner, other, &seed), expected);
    }

    #[test]
    fn source_capsule_restores_original_entries_and_refuses_damage_or_resealing() {
        let (poll, credential) = poll();
        let families = fhe_key_families(&poll);
        // A custody fixture, not a verified registration or public key proof.
        let commitments = vec![[31; 64]; families.len()];
        let mut sources = Sources {
            poll: poll.identity(),
            runtime: poll.runtime(),
            owner: *credential.signing_public(),
            entries: families
                .iter()
                .enumerate()
                .map(|(index, _)| Entry {
                    seed: Zeroizing::new([index as u8 + 41; 64]),
                    salt: Zeroizing::new([index as u8 + 53; 64]),
                })
                .collect(),
            families,
            commitments: commitments.clone(),
            sealed: false,
        };
        let body = [61; 64];
        let key = [67; 32];
        let capsule = sources.seal(body, &key).unwrap();
        assert_eq!(capsule.len(), capsule_bytes(&poll));
        assert!(capsule.len() <= maximum_capsule_bytes());
        assert!(sources.seal(body, &key).is_err());
        let mut restored =
            Sources::open(&poll, &credential, &commitments, body, &key, &capsule).unwrap();
        for (original, retained) in sources.entries.iter().zip(&restored.entries) {
            assert_eq!(original.seed, retained.seed);
            assert_eq!(original.salt, retained.salt);
        }
        assert!(restored.seal(body, &key).is_err());
        assert!(Sources::open(&poll, &credential, &commitments, [62; 64], &key, &capsule).is_err());
        assert!(
            Sources::open(&poll, &credential, &commitments, body, &[68; 32], &capsule).is_err()
        );
        assert!(
            Sources::open(&poll, &credential, &commitments[..0], body, &key, &capsule).is_err()
        );
        for offset in [0, 4, capsule.len() - 1] {
            let mut changed = capsule.clone();
            changed[offset] ^= 1;
            assert!(Sources::open(&poll, &credential, &commitments, body, &key, &changed).is_err());
        }
        assert!(
            Sources::open(
                &poll,
                &credential,
                &commitments,
                body,
                &key,
                &capsule[..capsule.len() - 1]
            )
            .is_err()
        );
    }
}
