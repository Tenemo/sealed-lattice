//! Original source seeds retained under the completed registration body.
//! The authenticated parent owns the required record, key and publication.
use crate::{
    BodyDigest, Credential, Refusal, SIGNING_PUBLIC_KEY_BYTES,
    foundation::{RegistrationHeader, derive_participant_identity},
    poll::VerifiedPoll,
    registration::VerifiedRegistration,
    source_binding::fhe_key_families,
};
use parallel_work::{
    random,
    sealing::{self, Sealed, TAG_BYTES},
};
use setup_witness::encrypted_source::EncryptedSource;
use supported_profile::Profile;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"ESC1";
const SEED_BYTES: usize = 64;
pub struct SourceSeeds {
    poll: [u8; 64],
    signing_public: [u8; SIGNING_PUBLIC_KEY_BYTES],
    owner: [u8; 64],
    families: Vec<Profile>,
    seeds: Zeroizing<Vec<[u8; SEED_BYTES]>>,
    bindings: Vec<[u8; 64]>,
    sealed: bool,
}
pub fn capsule_bytes(poll: &VerifiedPoll) -> usize {
    MAGIC.len() + SEED_BYTES * fhe_key_families(poll).len() + TAG_BYTES
}
pub fn maximum_capsule_bytes() -> usize {
    MAGIC.len() + SEED_BYTES * crate::source_binding::maximum_fhe_key_family_count() + TAG_BYTES
}
pub fn public_bytes(poll: &VerifiedPoll) -> usize {
    fhe_key_families(poll).len() * setup_witness::encrypted_source::ciphertext_bytes()
}
pub fn maximum_public_bytes() -> usize {
    crate::source_binding::maximum_fhe_key_family_count()
        * setup_witness::encrypted_source::ciphertext_bytes()
}
fn associated(body: [u8; 64]) -> Vec<u8> {
    let mut bytes = b"sealed-lattice/encrypted-source-custody/v1".to_vec();
    bytes.extend(body);
    bytes
}

impl SourceSeeds {
    /// The enrollment owner commits its creation intent before calling this.
    /// A failed creation consumes the attempt; it cannot reroll the sources.
    pub fn create(
        poll: &VerifiedPoll,
        credential: &mut Credential,
        mut stage: impl FnMut(usize, &[u8]) -> Result<(), Refusal>,
    ) -> Result<Self, Refusal> {
        if credential.source_creation_consumed || credential.completed_body.is_some() {
            return Err(Refusal::Consumed);
        }
        credential.source_creation_consumed = true;
        let owner = *derive_participant_identity(credential.signing_public())
            .map_err(|_| Refusal::Shape)?
            .as_bytes();
        let families = fhe_key_families(poll);
        let mut seeds = Zeroizing::new(Vec::with_capacity(families.len()));
        let mut bindings = Vec::with_capacity(families.len());
        let mut offset = 0;
        for profile in &families {
            let mut seed = Zeroizing::new([0; SEED_BYTES]);
            random::fresh(seed.as_mut());
            let source = EncryptedSource::from_seed(*profile, &poll.identity(), &owner, *seed)
                .map_err(|_| Refusal::Crypto)?;
            bindings.push(
                source
                    .public()
                    .binding(*profile, &poll.identity(), &owner)
                    .map_err(|_| Refusal::Crypto)?,
            );
            for record in source
                .public()
                .ciphertext_records()
                .map_err(|_| Refusal::Crypto)?
            {
                for chunk in record.chunks(parallel_work::CHUNK_LIMIT) {
                    stage(offset, chunk)?;
                    offset += chunk.len();
                }
            }
            seeds.push(*seed);
        }
        Ok(Self {
            poll: poll.identity(),
            signing_public: *credential.signing_public(),
            owner,
            families,
            seeds,
            bindings,
            sealed: false,
        })
    }
    pub fn bindings(&self) -> &[[u8; 64]] {
        &self.bindings
    }
    /// No seed bytes leave the bank; reconstruction remains tied to the
    /// original signed source and refuses a changed stored seed or family.
    pub fn package(
        &self,
        poll: &VerifiedPoll,
        profile: Profile,
    ) -> Result<EncryptedSource, Refusal> {
        if poll.identity() != self.poll {
            return Err(Refusal::Context);
        }
        crate::source_binding::fhe_key_family_index(poll, profile)?;
        let index = self
            .families
            .iter()
            .position(|family| {
                family.ciphertext_modulus().to_bytes() == profile.ciphertext_modulus().to_bytes()
                    && family.fhe_common_sample_bits() == profile.fhe_common_sample_bits()
            })
            .ok_or(Refusal::Context)?;
        let package =
            EncryptedSource::from_seed(profile, &self.poll, &self.owner, self.seeds[index])
                .map_err(|_| Refusal::Crypto)?;
        if package
            .public()
            .binding(profile, &self.poll, &self.owner)
            .map_err(|_| Refusal::Crypto)?
            != self.bindings[index]
        {
            return Err(Refusal::Crypto);
        }
        Ok(package)
    }
    pub fn seal(
        &mut self,
        credential: &Credential,
        header: &RegistrationHeader,
    ) -> Result<Sealed, Refusal> {
        if self.sealed {
            return Err(Refusal::Consumed);
        }
        let encoded = header.encode().map_err(|_| Refusal::Shape)?;
        let body = BodyDigest::from_header(&encoded, self.poll)?.bytes();
        if credential.completed_body != Some(body)
            || credential.signing_public() != &self.signing_public
            || header.signing_public != self.signing_public
            || header.poll != self.poll
            || header.source_bindings != self.bindings
        {
            return Err(Refusal::Context);
        }
        self.sealed = true;
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            MAGIC.len() + self.seeds.len() * SEED_BYTES,
        ));
        bytes.extend(MAGIC);
        for seed in self.seeds.iter() {
            bytes.extend(seed);
        }
        Ok(sealing::seal(&bytes, &associated(body)))
    }
    /// The parent first authenticates its original required capsule and key.
    /// This method does not recover a missing source record from public data.
    pub fn open(
        poll: &VerifiedPoll,
        credential: &Credential,
        original: &VerifiedRegistration,
        key: &[u8; 32],
        capsule: &[u8],
    ) -> Result<Self, Refusal> {
        if credential.completed_body != Some(original.body_digest())
            || credential.signing_public() != &original.header().signing_public
            || poll.identity() != original.header().poll
        {
            return Err(Refusal::Context);
        }
        if capsule.len() != capsule_bytes(poll) {
            return Err(Refusal::Shape);
        }
        let bytes = sealing::open(key, &associated(original.body_digest()), capsule)
            .ok_or(Refusal::Crypto)?;
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(Refusal::Shape);
        }
        let families = fhe_key_families(poll);
        if original.header().source_bindings.len() != families.len() {
            return Err(Refusal::Context);
        }
        let seeds = Zeroizing::new(
            bytes[MAGIC.len()..]
                .chunks_exact(SEED_BYTES)
                .map(|seed| seed.try_into().unwrap())
                .collect(),
        );
        let owner = *derive_participant_identity(credential.signing_public())
            .map_err(|_| Refusal::Shape)?
            .as_bytes();
        Ok(Self {
            poll: poll.identity(),
            signing_public: *credential.signing_public(),
            owner,
            families,
            seeds,
            bindings: original.header().source_bindings.clone(),
            sealed: true,
        })
    }
}
