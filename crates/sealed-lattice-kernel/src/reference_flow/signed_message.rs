use crate::foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512};

use super::{
    ProtocolResult,
    canonical::{read_fixed_bytes, read_variable_bytes, require_tuple},
    protocol_oracle::protocol_oracle_512,
    roster_signature::{
        ROSTER_SIGNATURE_BYTE_LENGTH, RosterSignatureRandomizer, RosterSigningKey,
        RosterVerificationKey, sign_roster_message, verify_roster_message,
    },
};

const SIGNED_MESSAGE_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0250;
const SIGNED_MESSAGE_SCHEMA_VERSION: u16 = 1;
const SIGNED_MESSAGE_CONTEXT: &[u8] = b"sealed-lattice/public-message/v1";

pub(crate) struct VerifiedSignedMessage {
    body_bytes: Vec<u8>,
    body_identity: Hash512,
    carrier_identity: Hash512,
}

impl core::fmt::Debug for VerifiedSignedMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedSignedMessage")
            .field("body_identity", &self.body_identity)
            .field("carrier_identity", &self.carrier_identity)
            .finish_non_exhaustive()
    }
}

impl VerifiedSignedMessage {
    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    pub(crate) fn body_identity(&self) -> Hash512 {
        self.body_identity
    }

    pub(crate) fn carrier_identity(&self) -> Hash512 {
        self.carrier_identity
    }
}

pub(crate) fn sign_public_message(
    body_bytes: &[u8],
    signing_key_bytes: &RosterSigningKey,
    verification_key_bytes: &RosterVerificationKey,
    signature_randomizer: RosterSignatureRandomizer,
) -> ProtocolResult<Vec<u8>> {
    CanonicalTuple::decode(body_bytes, &CanonicalDecodeLimits::default())?;
    let signature = sign_roster_message(
        SIGNED_MESSAGE_CONTEXT,
        body_bytes,
        signing_key_bytes,
        verification_key_bytes,
        signature_randomizer,
    )?;
    Ok(CanonicalTuple::new(
        SIGNED_MESSAGE_CARRIER_SCHEMA_IDENTIFIER,
        SIGNED_MESSAGE_SCHEMA_VERSION,
        vec![
            CanonicalItem::variable_bytes(body_bytes)?,
            CanonicalItem::fixed_bytes(signature)?,
        ],
    )
    .encode()?)
}

pub(crate) fn verify_public_message(
    carrier_bytes: &[u8],
    expected_verification_key_bytes: &RosterVerificationKey,
) -> ProtocolResult<VerifiedSignedMessage> {
    let carrier = CanonicalTuple::decode(carrier_bytes, &CanonicalDecodeLimits::default())?;
    require_tuple(
        &carrier,
        SIGNED_MESSAGE_CARRIER_SCHEMA_IDENTIFIER,
        SIGNED_MESSAGE_SCHEMA_VERSION,
        2,
    )?;
    let body_bytes = read_variable_bytes(&carrier.items[0])?;
    CanonicalTuple::decode(body_bytes, &CanonicalDecodeLimits::default())?;
    let signature = read_fixed_bytes::<ROSTER_SIGNATURE_BYTE_LENGTH>(&carrier.items[1])?;
    verify_roster_message(
        SIGNED_MESSAGE_CONTEXT,
        body_bytes,
        &signature,
        expected_verification_key_bytes,
    )?;
    Ok(VerifiedSignedMessage {
        body_bytes: body_bytes.to_vec(),
        body_identity: public_message_body_identity(body_bytes)?,
        carrier_identity: public_message_carrier_identity(carrier_bytes)?,
    })
}

pub(crate) fn public_message_body_identity(body_bytes: &[u8]) -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/public-message-body/v1",
        &[CanonicalItem::variable_bytes(body_bytes)?],
    )
}

pub(crate) fn public_message_carrier_identity(carrier_bytes: &[u8]) -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/public-message-carrier/v1",
        &[CanonicalItem::variable_bytes(carrier_bytes)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_flow::roster_signature::{
        ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
        generate_roster_signature_keypair,
    };

    fn body() -> Vec<u8> {
        CanonicalTuple::new(
            0x7a01,
            1,
            vec![
                CanonicalItem::unsigned16(4),
                CanonicalItem::hash512([0x51; 64]),
            ],
        )
        .encode()
        .unwrap()
    }

    #[test]
    fn real_signature_authenticates_one_canonical_body() {
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x23; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let carrier = sign_public_message(
            &body(),
            &signing_key,
            &verification_key,
            [0x71; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();
        let verified = verify_public_message(&carrier, &verification_key).unwrap();
        assert_eq!(verified.body_bytes(), body());
        assert_eq!(
            verified.body_identity(),
            public_message_body_identity(&body()).unwrap()
        );
        assert_eq!(
            verified.carrier_identity(),
            public_message_carrier_identity(&carrier).unwrap()
        );
    }

    #[test]
    fn body_identity_ignores_signature_carrier_variation() {
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x42; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let first = sign_public_message(
            &body(),
            &signing_key,
            &verification_key,
            [0x11; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();
        let second = sign_public_message(
            &body(),
            &signing_key,
            &verification_key,
            [0x12; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();
        let first = verify_public_message(&first, &verification_key).unwrap();
        let second = verify_public_message(&second, &verification_key).unwrap();
        assert_eq!(first.body_identity(), second.body_identity());
        assert_ne!(first.carrier_identity(), second.carrier_identity());
    }

    #[test]
    fn mutation_wrong_key_and_non_tuple_body_refuse() {
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x62; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let mut carrier = sign_public_message(
            &body(),
            &signing_key,
            &verification_key,
            [0x81; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();
        let last = carrier.len() - 1;
        carrier[last] ^= 1;
        assert!(verify_public_message(&carrier, &verification_key).is_err());

        let (wrong_verification_key, _) =
            generate_roster_signature_keypair([0x63; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        let valid = sign_public_message(
            &body(),
            &signing_key,
            &verification_key,
            [0x82; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
        )
        .unwrap();
        assert!(verify_public_message(&valid, &wrong_verification_key).is_err());
        assert!(
            sign_public_message(
                b"not a canonical tuple",
                &signing_key,
                &verification_key,
                [0x83; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH]
            )
            .is_err()
        );
    }
}
