use sealed_lattice_sphincs_plus as sphincs_plus;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::foundation::{CanonicalItem, CanonicalTuple, RefusalReason};

use super::{ProtocolRefusal, ProtocolResult};

const ROSTER_SIGNATURE_MESSAGE_SCHEMA_IDENTIFIER: u16 = 0x0202;
const ROSTER_SIGNATURE_MESSAGE_SCHEMA_VERSION: u16 = 1;

pub(crate) const ROSTER_VERIFICATION_KEY_BYTE_LENGTH: usize = sphincs_plus::PUBLIC_KEY_BYTE_LENGTH;
pub(crate) const ROSTER_SIGNING_KEY_BYTE_LENGTH: usize = sphincs_plus::SECRET_KEY_BYTE_LENGTH;
pub(crate) const ROSTER_SIGNATURE_BYTE_LENGTH: usize = sphincs_plus::SIGNATURE_BYTE_LENGTH;
pub(crate) const ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH: usize =
    sphincs_plus::KEY_GENERATION_SEED_BYTE_LENGTH;
pub(crate) const ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH: usize =
    sphincs_plus::SIGNATURE_RANDOMIZER_BYTE_LENGTH;

pub(crate) type RosterVerificationKey = [u8; ROSTER_VERIFICATION_KEY_BYTE_LENGTH];
pub(crate) type RosterSigningKey = [u8; ROSTER_SIGNING_KEY_BYTE_LENGTH];
pub(crate) type RosterSignature = [u8; ROSTER_SIGNATURE_BYTE_LENGTH];
pub(crate) type RosterKeyGenerationSeed = [u8; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH];
pub(crate) type RosterSignatureRandomizer = [u8; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH];

pub(crate) fn generate_roster_signature_keypair(
    seed: RosterKeyGenerationSeed,
) -> (RosterVerificationKey, RosterSigningKey) {
    let seed = Zeroizing::new(seed);
    sphincs_plus::keypair_from_seed(&seed)
}

pub(crate) fn sign_roster_message(
    signature_context: &'static [u8],
    message: &[u8],
    signing_key: &RosterSigningKey,
    expected_verification_key: &RosterVerificationKey,
    signature_randomizer: RosterSignatureRandomizer,
) -> ProtocolResult<RosterSignature> {
    let embedded_verification_key = sphincs_plus::public_key_from_secret_key(signing_key);
    if !bool::from(embedded_verification_key.ct_eq(expected_verification_key)) {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "roster signing key does not match the frozen roster key",
        ));
    }

    let mut key_seed = Zeroizing::new([0_u8; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
    key_seed.copy_from_slice(&signing_key[..ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
    let (derived_verification_key, derived_signing_key) =
        sphincs_plus::keypair_from_seed(&key_seed);
    let derived_signing_key = Zeroizing::new(derived_signing_key);
    if !bool::from(derived_signing_key.ct_eq(signing_key))
        || !bool::from(derived_verification_key.ct_eq(expected_verification_key))
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "roster signing key is not a canonical SPHINCS+-SHA2-192f-robust key",
        ));
    }

    let signature_message = roster_signature_message(signature_context, message)?;
    let signature_randomizer = Zeroizing::new(signature_randomizer);
    Ok(sphincs_plus::sign(
        &signature_message,
        signing_key,
        &signature_randomizer,
    ))
}

pub(crate) fn verify_roster_message(
    signature_context: &'static [u8],
    message: &[u8],
    signature: &RosterSignature,
    verification_key: &RosterVerificationKey,
) -> ProtocolResult<()> {
    let signature_message = roster_signature_message(signature_context, message)?;
    if !sphincs_plus::verify(signature, &signature_message, verification_key) {
        return Err(ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "SPHINCS+-SHA2-192f-robust roster signature verification failed",
        ));
    }
    Ok(())
}

fn roster_signature_message(
    signature_context: &'static [u8],
    message: &[u8],
) -> ProtocolResult<Vec<u8>> {
    Ok(CanonicalTuple::new(
        ROSTER_SIGNATURE_MESSAGE_SCHEMA_IDENTIFIER,
        ROSTER_SIGNATURE_MESSAGE_SCHEMA_VERSION,
        vec![
            CanonicalItem::variable_bytes(signature_context)?,
            CanonicalItem::variable_bytes(message)?,
        ],
    )
    .encode()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_context_and_key_pair_are_load_bearing() {
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x42; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let signature = sign_roster_message(
            b"sealed-lattice/test/first/v1",
            b"message",
            &signing_key,
            &verification_key,
            [0x63; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();

        verify_roster_message(
            b"sealed-lattice/test/first/v1",
            b"message",
            &signature,
            &verification_key,
        )
        .unwrap();
        assert!(
            verify_roster_message(
                b"sealed-lattice/test/second/v1",
                b"message",
                &signature,
                &verification_key,
            )
            .is_err()
        );

        let (wrong_verification_key, _) =
            generate_roster_signature_keypair([0x43; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        assert!(
            verify_roster_message(
                b"sealed-lattice/test/first/v1",
                b"message",
                &signature,
                &wrong_verification_key,
            )
            .is_err()
        );
    }

    #[test]
    fn corrupted_or_mismatched_signing_state_refuses() {
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x51; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let (other_verification_key, _) =
            generate_roster_signature_keypair([0x52; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);

        assert!(
            sign_roster_message(
                b"sealed-lattice/test/v1",
                b"message",
                &signing_key,
                &other_verification_key,
                [0x71; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            )
            .is_err()
        );

        let mut corrupted_signing_key = signing_key;
        corrupted_signing_key[0] ^= 1;
        assert!(
            sign_roster_message(
                b"sealed-lattice/test/v1",
                b"message",
                &corrupted_signing_key,
                &verification_key,
                [0x72; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            )
            .is_err()
        );
    }
}
