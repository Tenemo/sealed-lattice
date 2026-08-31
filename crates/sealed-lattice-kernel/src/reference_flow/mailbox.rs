use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, SerDes as KemSerDes},
};
use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, Hash512, RefusalReason,
};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{
        read_fixed_bytes, read_hash, read_u16, read_u64, read_variable_bytes, require_tuple,
    },
    protocol_oracle::protocol_oracle_512,
    roster_signature::{
        ROSTER_SIGNATURE_BYTE_LENGTH, RosterSignatureRandomizer, RosterSigningKey,
        RosterVerificationKey, sign_roster_message, verify_roster_message,
    },
};

const MAILBOX_BODY_SCHEMA_IDENTIFIER: u16 = 0x0210;
const MAILBOX_CARRIER_SCHEMA_IDENTIFIER: u16 = 0x0211;
const MAILBOX_PLAINTEXT_SCHEMA_IDENTIFIER: u16 = 0x0212;
const MAILBOX_SIGNATURE_SCHEMA_IDENTIFIER: u16 = 0x0213;
const MAILBOX_SCHEMA_VERSION: u16 = 1;
const MAILBOX_AEAD_TAG_BYTE_LENGTH: usize = 16;
const MAILBOX_NONCE_BYTE_LENGTH: usize = 12;
const MAILBOX_NONCE: [u8; MAILBOX_NONCE_BYTE_LENGTH] = [0; MAILBOX_NONCE_BYTE_LENGTH];
const MAILBOX_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/mailbox/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailboxStreamKind {
    Preparation,
    Source,
}

impl MailboxStreamKind {
    const fn canonical_code(self) -> u16 {
        match self {
            Self::Preparation => 1,
            Self::Source => 2,
        }
    }

    const fn from_canonical_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Preparation),
            2 => Some(Self::Source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MailboxStreamContext {
    pub(crate) suite_identity: Hash512,
    pub(crate) build_identity: Hash512,
    pub(crate) action_identity: Hash512,
    pub(crate) roster_identity: Hash512,
    pub(crate) circuit_identity: Hash512,
    pub(crate) action_predecessor_identity: Hash512,
    pub(crate) phase_predecessor_identity: Hash512,
    pub(crate) attempt_ordinal: u64,
    pub(crate) sender_position: u16,
    pub(crate) recipient_position: u16,
    pub(crate) stream_kind: MailboxStreamKind,
    pub(crate) stream_ordinal: u64,
    pub(crate) output_ordinal: u64,
}

pub(crate) struct OpenedMailboxPlaintext(Zeroizing<Vec<u8>>);

impl core::fmt::Debug for OpenedMailboxPlaintext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OpenedMailboxPlaintext([redacted])")
    }
}

impl OpenedMailboxPlaintext {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn seal_mailbox_stream(
    context: MailboxStreamContext,
    recipient_encapsulation_key_bytes: &[u8; ml_kem_768::EK_LEN],
    sender_signing_key_bytes: &RosterSigningKey,
    sender_verification_key_bytes: &RosterVerificationKey,
    encapsulation_seed: [u8; 32],
    signature_randomizer: RosterSignatureRandomizer,
    plaintext: &[u8],
) -> ProtocolResult<Vec<u8>> {
    let encapsulation_seed = Zeroizing::new(encapsulation_seed);
    let recipient_encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(
        *recipient_encapsulation_key_bytes,
    )
    .map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "recipient mailbox key is not a canonical ML-KEM-768 key",
        )
    })?;
    let (shared_secret, ciphertext) =
        recipient_encapsulation_key.encaps_from_seed(&encapsulation_seed);
    let shared_secret = Zeroizing::new(shared_secret.into_bytes());
    let ciphertext_bytes = ciphertext.into_bytes();
    let recipient_key_identity = mailbox_key_identity(recipient_encapsulation_key_bytes)?;
    let encapsulation_identity = mailbox_encapsulation_identity(&ciphertext_bytes)?;
    let private_plaintext = Zeroizing::new(
        mailbox_plaintext(
            context,
            recipient_key_identity,
            encapsulation_identity,
            plaintext,
        )?
        .encode()?,
    );

    let associated_data = mailbox_associated_data(
        context,
        recipient_key_identity,
        &ciphertext_bytes,
        private_plaintext.len(),
    )?;
    let cipher = Aes256GcmSiv::new_from_slice(&shared_secret[..]).map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "mailbox AEAD key has the wrong length",
        )
    })?;
    let encrypted_payload = cipher
        .encrypt(
            Nonce::from_slice(&MAILBOX_NONCE),
            Payload {
                msg: &private_plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "mailbox payload cannot be encrypted within the supported profile",
            )
        })?;

    let body = mailbox_body(
        context,
        recipient_key_identity,
        &ciphertext_bytes,
        private_plaintext.len(),
        &encrypted_payload,
    )?;
    let body_bytes = body.encode()?;
    let body_identity = mailbox_body_identity(&body_bytes)?;
    let signature_preimage = mailbox_signature_preimage(context, body_identity)?;
    let signature = sign_roster_message(
        MAILBOX_SIGNATURE_CONTEXT,
        &signature_preimage,
        sender_signing_key_bytes,
        sender_verification_key_bytes,
        signature_randomizer,
    )?;

    Ok(CanonicalTuple::new(
        MAILBOX_CARRIER_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        vec![
            CanonicalItem::variable_bytes(body_bytes)?,
            CanonicalItem::fixed_bytes(signature)?,
        ],
    )
    .encode()?)
}

pub(crate) struct VerifiedMailboxEnvelope {
    context: MailboxStreamContext,
    recipient_key_identity: Hash512,
    encapsulation_ciphertext: [u8; ml_kem_768::CT_LEN],
    plaintext_byte_length: usize,
    encrypted_payload: Vec<u8>,
    body_identity: Hash512,
    carrier_identity: Hash512,
}

impl core::fmt::Debug for VerifiedMailboxEnvelope {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedMailboxEnvelope")
            .field("context", &self.context)
            .field("body_identity", &self.body_identity)
            .field("carrier_identity", &self.carrier_identity)
            .finish_non_exhaustive()
    }
}

impl VerifiedMailboxEnvelope {
    pub(crate) fn body_identity(&self) -> Hash512 {
        self.body_identity
    }

    pub(crate) fn context(&self) -> MailboxStreamContext {
        self.context
    }
}

pub(crate) fn verify_mailbox_envelope(
    expected_context: MailboxStreamContext,
    recipient_encapsulation_key_bytes: &[u8; ml_kem_768::EK_LEN],
    sender_verification_key_bytes: &RosterVerificationKey,
    carrier_bytes: &[u8],
) -> ProtocolResult<VerifiedMailboxEnvelope> {
    let carrier = CanonicalTuple::decode(carrier_bytes, &CanonicalDecodeLimits::default())?;
    require_tuple(
        &carrier,
        MAILBOX_CARRIER_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        2,
    )?;
    let body_bytes = read_variable_bytes(&carrier.items[0])?;
    let signature_bytes = read_fixed_bytes::<ROSTER_SIGNATURE_BYTE_LENGTH>(&carrier.items[1])?;
    let body = CanonicalTuple::decode(body_bytes, &CanonicalDecodeLimits::default())?;
    require_tuple(
        &body,
        MAILBOX_BODY_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        17,
    )?;

    let parsed = ParsedMailboxBody::parse(&body)?;
    let expected_recipient_key_identity = mailbox_key_identity(recipient_encapsulation_key_bytes)?;
    parsed.require_context(expected_context, expected_recipient_key_identity)?;
    if parsed.encrypted_payload.len()
        != parsed
            .plaintext_byte_length
            .checked_add(MAILBOX_AEAD_TAG_BYTE_LENGTH)
            .ok_or_else(|| {
                ProtocolRefusal::new(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox ciphertext length overflows",
                )
            })?
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "mailbox ciphertext has the wrong length",
        ));
    }

    let body_identity = mailbox_body_identity(body_bytes)?;
    let signature_preimage = mailbox_signature_preimage(expected_context, body_identity)?;
    verify_roster_message(
        MAILBOX_SIGNATURE_CONTEXT,
        &signature_preimage,
        &signature_bytes,
        sender_verification_key_bytes,
    )?;

    Ok(VerifiedMailboxEnvelope {
        context: expected_context,
        recipient_key_identity: expected_recipient_key_identity,
        encapsulation_ciphertext: parsed.encapsulation_ciphertext,
        plaintext_byte_length: parsed.plaintext_byte_length,
        encrypted_payload: parsed.encrypted_payload.to_vec(),
        body_identity,
        carrier_identity: protocol_oracle_512(
            "sealed-lattice/protocol/mailbox-carrier/v1",
            &[CanonicalItem::variable_bytes(carrier_bytes)?],
        )?,
    })
}

pub(crate) fn open_verified_mailbox_envelope(
    verified: VerifiedMailboxEnvelope,
    recipient_decapsulation_key_bytes: &[u8; ml_kem_768::DK_LEN],
) -> ProtocolResult<OpenedMailboxPlaintext> {
    let recipient_decapsulation_key = ml_kem_768::DecapsKey::try_from_bytes(
        *recipient_decapsulation_key_bytes,
    )
    .map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "recipient mailbox secret is not a canonical ML-KEM-768 key",
        )
    })?;
    let encapsulation_ciphertext = ml_kem_768::CipherText::try_from_bytes(
        verified.encapsulation_ciphertext,
    )
    .map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "mailbox encapsulation ciphertext is not canonical ML-KEM-768",
        )
    })?;
    let shared_secret = recipient_decapsulation_key
        .try_decaps(&encapsulation_ciphertext)
        .map_err(|_| {
            ProtocolRefusal::new(
                RefusalReason::MalformedEncoding,
                "mailbox decapsulation failed",
            )
        })?;
    let shared_secret = Zeroizing::new(shared_secret.into_bytes());

    let associated_data = mailbox_associated_data(
        verified.context,
        verified.recipient_key_identity,
        &verified.encapsulation_ciphertext,
        verified.plaintext_byte_length,
    )?;
    let cipher = Aes256GcmSiv::new_from_slice(&shared_secret[..]).map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "mailbox AEAD key has the wrong length",
        )
    })?;
    let plaintext = cipher.decrypt(
        Nonce::from_slice(&MAILBOX_NONCE),
        Payload {
            msg: &verified.encrypted_payload,
            aad: &associated_data,
        },
    );
    let plaintext = Zeroizing::new(plaintext.map_err(|_| {
        ProtocolRefusal::new(
            RefusalReason::MalformedEncoding,
            "mailbox ciphertext authentication failed",
        )
    })?);
    let mut plaintext_tuple =
        CanonicalTuple::decode(&plaintext, &CanonicalDecodeLimits::default())?;
    let opened = parse_mailbox_plaintext(
        &plaintext_tuple,
        verified.context,
        verified.recipient_key_identity,
        mailbox_encapsulation_identity(&verified.encapsulation_ciphertext)?,
    );
    plaintext_tuple.zeroize();
    opened.map(|payload| OpenedMailboxPlaintext(Zeroizing::new(payload)))
}

#[cfg(test)]
fn open_mailbox_stream(
    expected_context: MailboxStreamContext,
    recipient_encapsulation_key_bytes: &[u8; ml_kem_768::EK_LEN],
    recipient_decapsulation_key_bytes: &[u8; ml_kem_768::DK_LEN],
    sender_verification_key_bytes: &RosterVerificationKey,
    carrier_bytes: &[u8],
) -> ProtocolResult<OpenedMailboxPlaintext> {
    let verified = verify_mailbox_envelope(
        expected_context,
        recipient_encapsulation_key_bytes,
        sender_verification_key_bytes,
        carrier_bytes,
    )?;
    open_verified_mailbox_envelope(verified, recipient_decapsulation_key_bytes)
}

struct ParsedMailboxBody<'a> {
    suite_identity: Hash512,
    build_identity: Hash512,
    action_identity: Hash512,
    roster_identity: Hash512,
    circuit_identity: Hash512,
    action_predecessor_identity: Hash512,
    phase_predecessor_identity: Hash512,
    attempt_ordinal: u64,
    sender_position: u16,
    recipient_position: u16,
    stream_kind: MailboxStreamKind,
    stream_ordinal: u64,
    output_ordinal: u64,
    recipient_key_identity: Hash512,
    encapsulation_ciphertext: [u8; ml_kem_768::CT_LEN],
    plaintext_byte_length: usize,
    encrypted_payload: &'a [u8],
}

impl<'a> ParsedMailboxBody<'a> {
    fn parse(body: &'a CanonicalTuple) -> ProtocolResult<Self> {
        let plaintext_byte_length = usize::try_from(read_u64(&body.items[15])?).map_err(|_| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "mailbox plaintext length does not fit this runtime",
            )
        })?;
        Ok(Self {
            suite_identity: read_hash(&body.items[0])?,
            build_identity: read_hash(&body.items[1])?,
            action_identity: read_hash(&body.items[2])?,
            roster_identity: read_hash(&body.items[3])?,
            circuit_identity: read_hash(&body.items[4])?,
            action_predecessor_identity: read_hash(&body.items[5])?,
            phase_predecessor_identity: read_hash(&body.items[6])?,
            attempt_ordinal: read_u64(&body.items[7])?,
            sender_position: read_u16(&body.items[8])?,
            recipient_position: read_u16(&body.items[9])?,
            stream_kind: MailboxStreamKind::from_canonical_code(read_u16(&body.items[10])?)
                .ok_or_else(|| {
                    ProtocolRefusal::new(
                        RefusalReason::WrongTypeOrLength,
                        "mailbox stream kind is unknown",
                    )
                })?,
            stream_ordinal: read_u64(&body.items[11])?,
            output_ordinal: read_u64(&body.items[12])?,
            recipient_key_identity: read_hash(&body.items[13])?,
            encapsulation_ciphertext: read_fixed_bytes(&body.items[14])?,
            plaintext_byte_length,
            encrypted_payload: read_variable_bytes(&body.items[16])?,
        })
    }

    fn require_context(
        &self,
        expected: MailboxStreamContext,
        expected_recipient_key_identity: Hash512,
    ) -> ProtocolResult<()> {
        if self.suite_identity != expected.suite_identity
            || self.build_identity != expected.build_identity
            || self.action_identity != expected.action_identity
            || self.roster_identity != expected.roster_identity
            || self.circuit_identity != expected.circuit_identity
            || self.action_predecessor_identity != expected.action_predecessor_identity
            || self.phase_predecessor_identity != expected.phase_predecessor_identity
            || self.attempt_ordinal != expected.attempt_ordinal
            || self.sender_position != expected.sender_position
            || self.recipient_position != expected.recipient_position
            || self.stream_kind != expected.stream_kind
            || self.stream_ordinal != expected.stream_ordinal
            || self.output_ordinal != expected.output_ordinal
            || self.recipient_key_identity != expected_recipient_key_identity
        {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "mailbox stream does not match its expected context",
            ));
        }
        Ok(())
    }
}

fn mailbox_body(
    context: MailboxStreamContext,
    recipient_key_identity: Hash512,
    encapsulation_ciphertext: &[u8; ml_kem_768::CT_LEN],
    plaintext_byte_length: usize,
    encrypted_payload: &[u8],
) -> ProtocolResult<CanonicalTuple> {
    Ok(CanonicalTuple::new(
        MAILBOX_BODY_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(context.suite_identity.into_bytes()),
            CanonicalItem::hash512(context.build_identity.into_bytes()),
            CanonicalItem::hash512(context.action_identity.into_bytes()),
            CanonicalItem::hash512(context.roster_identity.into_bytes()),
            CanonicalItem::hash512(context.circuit_identity.into_bytes()),
            CanonicalItem::hash512(context.action_predecessor_identity.into_bytes()),
            CanonicalItem::hash512(context.phase_predecessor_identity.into_bytes()),
            CanonicalItem::unsigned64(context.attempt_ordinal),
            CanonicalItem::unsigned16(context.sender_position),
            CanonicalItem::unsigned16(context.recipient_position),
            CanonicalItem::unsigned16(context.stream_kind.canonical_code()),
            CanonicalItem::unsigned64(context.stream_ordinal),
            CanonicalItem::unsigned64(context.output_ordinal),
            CanonicalItem::hash512(recipient_key_identity.into_bytes()),
            CanonicalItem::fixed_bytes(encapsulation_ciphertext)?,
            CanonicalItem::unsigned64(u64::try_from(plaintext_byte_length).map_err(|_| {
                ProtocolRefusal::new(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox plaintext length does not fit u64",
                )
            })?),
            CanonicalItem::variable_bytes(encrypted_payload)?,
        ],
    ))
}

fn mailbox_plaintext(
    context: MailboxStreamContext,
    recipient_key_identity: Hash512,
    encapsulation_identity: Hash512,
    payload: &[u8],
) -> ProtocolResult<CanonicalTuple> {
    Ok(CanonicalTuple::new(
        MAILBOX_PLAINTEXT_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(context.suite_identity.into_bytes()),
            CanonicalItem::hash512(context.build_identity.into_bytes()),
            CanonicalItem::hash512(context.action_identity.into_bytes()),
            CanonicalItem::hash512(context.roster_identity.into_bytes()),
            CanonicalItem::hash512(context.circuit_identity.into_bytes()),
            CanonicalItem::hash512(context.action_predecessor_identity.into_bytes()),
            CanonicalItem::hash512(context.phase_predecessor_identity.into_bytes()),
            CanonicalItem::unsigned64(context.attempt_ordinal),
            CanonicalItem::unsigned16(context.sender_position),
            CanonicalItem::unsigned16(context.recipient_position),
            CanonicalItem::unsigned16(context.stream_kind.canonical_code()),
            CanonicalItem::unsigned64(context.stream_ordinal),
            CanonicalItem::unsigned64(context.output_ordinal),
            CanonicalItem::hash512(recipient_key_identity.into_bytes()),
            CanonicalItem::hash512(encapsulation_identity.into_bytes()),
            CanonicalItem::variable_bytes(payload)?,
        ],
    ))
}

fn parse_mailbox_plaintext(
    plaintext: &CanonicalTuple,
    expected_context: MailboxStreamContext,
    expected_recipient_key_identity: Hash512,
    expected_encapsulation_identity: Hash512,
) -> ProtocolResult<Vec<u8>> {
    require_tuple(
        plaintext,
        MAILBOX_PLAINTEXT_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        16,
    )?;
    let stream_kind = MailboxStreamKind::from_canonical_code(read_u16(&plaintext.items[10])?)
        .ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "mailbox plaintext stream kind is unknown",
            )
        })?;
    if read_hash(&plaintext.items[0])? != expected_context.suite_identity
        || read_hash(&plaintext.items[1])? != expected_context.build_identity
        || read_hash(&plaintext.items[2])? != expected_context.action_identity
        || read_hash(&plaintext.items[3])? != expected_context.roster_identity
        || read_hash(&plaintext.items[4])? != expected_context.circuit_identity
        || read_hash(&plaintext.items[5])? != expected_context.action_predecessor_identity
        || read_hash(&plaintext.items[6])? != expected_context.phase_predecessor_identity
        || read_u64(&plaintext.items[7])? != expected_context.attempt_ordinal
        || read_u16(&plaintext.items[8])? != expected_context.sender_position
        || read_u16(&plaintext.items[9])? != expected_context.recipient_position
        || stream_kind != expected_context.stream_kind
        || read_u64(&plaintext.items[11])? != expected_context.stream_ordinal
        || read_u64(&plaintext.items[12])? != expected_context.output_ordinal
        || read_hash(&plaintext.items[13])? != expected_recipient_key_identity
        || read_hash(&plaintext.items[14])? != expected_encapsulation_identity
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "mailbox plaintext does not match its authenticated context",
        ));
    }
    Ok(read_variable_bytes(&plaintext.items[15])?.to_vec())
}

fn mailbox_associated_data(
    context: MailboxStreamContext,
    recipient_key_identity: Hash512,
    encapsulation_ciphertext: &[u8; ml_kem_768::CT_LEN],
    plaintext_byte_length: usize,
) -> ProtocolResult<Vec<u8>> {
    let expected_ciphertext_byte_length = plaintext_byte_length
        .checked_add(MAILBOX_AEAD_TAG_BYTE_LENGTH)
        .ok_or_else(|| {
            ProtocolRefusal::new(
                RefusalReason::OutsideSupportedProfile,
                "mailbox ciphertext length overflows",
            )
        })?;
    Ok(CanonicalTuple::new(
        MAILBOX_BODY_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(context.suite_identity.into_bytes()),
            CanonicalItem::hash512(context.build_identity.into_bytes()),
            CanonicalItem::hash512(context.action_identity.into_bytes()),
            CanonicalItem::hash512(context.roster_identity.into_bytes()),
            CanonicalItem::hash512(context.circuit_identity.into_bytes()),
            CanonicalItem::hash512(context.action_predecessor_identity.into_bytes()),
            CanonicalItem::hash512(context.phase_predecessor_identity.into_bytes()),
            CanonicalItem::unsigned64(context.attempt_ordinal),
            CanonicalItem::unsigned16(context.sender_position),
            CanonicalItem::unsigned16(context.recipient_position),
            CanonicalItem::unsigned16(context.stream_kind.canonical_code()),
            CanonicalItem::unsigned64(context.stream_ordinal),
            CanonicalItem::unsigned64(context.output_ordinal),
            CanonicalItem::hash512(recipient_key_identity.into_bytes()),
            CanonicalItem::fixed_bytes(encapsulation_ciphertext)?,
            CanonicalItem::unsigned64(u64::try_from(plaintext_byte_length).map_err(|_| {
                ProtocolRefusal::new(
                    RefusalReason::OutsideSupportedProfile,
                    "mailbox plaintext length does not fit u64",
                )
            })?),
            CanonicalItem::unsigned64(u64::try_from(expected_ciphertext_byte_length).map_err(
                |_| {
                    ProtocolRefusal::new(
                        RefusalReason::OutsideSupportedProfile,
                        "mailbox ciphertext length does not fit u64",
                    )
                },
            )?),
        ],
    )
    .encode()?)
}

fn mailbox_body_identity(body_bytes: &[u8]) -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/mailbox-body/v1",
        &[CanonicalItem::variable_bytes(body_bytes)?],
    )
}

fn mailbox_key_identity(
    recipient_encapsulation_key_bytes: &[u8; ml_kem_768::EK_LEN],
) -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/mailbox-key/v1",
        &[CanonicalItem::fixed_bytes(
            recipient_encapsulation_key_bytes,
        )?],
    )
}

fn mailbox_encapsulation_identity(
    encapsulation_ciphertext: &[u8; ml_kem_768::CT_LEN],
) -> ProtocolResult<Hash512> {
    protocol_oracle_512(
        "sealed-lattice/protocol/mailbox-encapsulation/v1",
        &[CanonicalItem::fixed_bytes(encapsulation_ciphertext)?],
    )
}

fn mailbox_signature_preimage(
    context: MailboxStreamContext,
    body_identity: Hash512,
) -> ProtocolResult<Vec<u8>> {
    Ok(CanonicalTuple::new(
        MAILBOX_SIGNATURE_SCHEMA_IDENTIFIER,
        MAILBOX_SCHEMA_VERSION,
        vec![
            CanonicalItem::hash512(body_identity.into_bytes()),
            CanonicalItem::nonempty_ascii("mailbox-stream")?,
            CanonicalItem::unsigned16(context.sender_position),
            CanonicalItem::hash512(context.action_identity.into_bytes()),
            CanonicalItem::hash512(context.action_predecessor_identity.into_bytes()),
            CanonicalItem::unsigned64(context.stream_ordinal),
            CanonicalItem::unsigned16(context.stream_kind.canonical_code()),
        ],
    )
    .encode()?)
}

#[cfg(test)]
mod tests {
    use fips203::{ml_kem_768, traits::KeyGen as KemKeyGen};

    use super::*;
    use crate::reference_flow::roster_signature::{
        ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH, ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH,
        generate_roster_signature_keypair,
    };

    fn fixture() -> (
        MailboxStreamContext,
        [u8; ml_kem_768::EK_LEN],
        [u8; ml_kem_768::DK_LEN],
        RosterVerificationKey,
        RosterSigningKey,
    ) {
        let (encapsulation_key, decapsulation_key) =
            ml_kem_768::KG::keygen_from_seed([0x21; 32], [0x72; 32]);
        let (verification_key, signing_key) =
            generate_roster_signature_keypair([0x43; ROSTER_KEY_GENERATION_SEED_BYTE_LENGTH]);
        (
            MailboxStreamContext {
                suite_identity: Hash512::from_bytes([0x11; 64]),
                build_identity: Hash512::from_bytes([0x12; 64]),
                action_identity: Hash512::from_bytes([0x22; 64]),
                roster_identity: Hash512::from_bytes([0x33; 64]),
                circuit_identity: Hash512::from_bytes([0x34; 64]),
                action_predecessor_identity: Hash512::from_bytes([0x44; 64]),
                phase_predecessor_identity: Hash512::from_bytes([0x45; 64]),
                attempt_ordinal: 3,
                sender_position: 2,
                recipient_position: 7,
                stream_kind: MailboxStreamKind::Preparation,
                stream_ordinal: 5,
                output_ordinal: 0,
            },
            encapsulation_key.into_bytes(),
            decapsulation_key.into_bytes(),
            verification_key,
            signing_key,
        )
    }

    #[test]
    fn mailbox_round_trip_uses_real_kem_aead_and_signature() {
        let (context, encapsulation_key, decapsulation_key, verification_key, signing_key) =
            fixture();
        let plaintext = b"private preparation coordinate";
        let carrier = seal_mailbox_stream(
            context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x66; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            plaintext,
        )
        .expect("mailbox stream seals");
        let opened = open_mailbox_stream(
            context,
            &encapsulation_key,
            &decapsulation_key,
            &verification_key,
            &carrier,
        )
        .expect("mailbox stream opens");
        assert_eq!(opened.as_bytes(), plaintext);
    }

    #[test]
    fn mailbox_refuses_mutation_wrong_context_and_wrong_key() {
        let (context, encapsulation_key, decapsulation_key, verification_key, signing_key) =
            fixture();
        let carrier = seal_mailbox_stream(
            context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x66; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"secret",
        )
        .expect("mailbox stream seals");

        let mut mutated = carrier.clone();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert_eq!(
            open_mailbox_stream(
                context,
                &encapsulation_key,
                &decapsulation_key,
                &verification_key,
                &mutated,
            )
            .expect_err("mutated carrier refuses")
            .reason,
            RefusalReason::MalformedEncoding
        );

        let wrong_context = MailboxStreamContext {
            action_identity: Hash512::from_bytes([0x92; 64]),
            ..context
        };
        assert_eq!(
            open_mailbox_stream(
                wrong_context,
                &encapsulation_key,
                &decapsulation_key,
                &verification_key,
                &carrier,
            )
            .expect_err("wrong context refuses")
            .reason,
            RefusalReason::WrongContext
        );

        let (wrong_encapsulation_key, wrong_decapsulation_key) =
            ml_kem_768::KG::keygen_from_seed([0xa1; 32], [0xb2; 32]);
        assert_eq!(
            open_mailbox_stream(
                context,
                &wrong_encapsulation_key.into_bytes(),
                &wrong_decapsulation_key.into_bytes(),
                &verification_key,
                &carrier,
            )
            .expect_err("wrong recipient key refuses")
            .reason,
            RefusalReason::WrongContext
        );
    }

    #[test]
    fn mailbox_replay_is_byte_identical_and_context_bound() {
        let (context, encapsulation_key, decapsulation_key, verification_key, signing_key) =
            fixture();
        let first = seal_mailbox_stream(
            context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x66; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"retained bytes",
        )
        .expect("first stream seals");
        let replay = seal_mailbox_stream(
            context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x66; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"retained bytes",
        )
        .expect("same retained inputs seal");
        assert_eq!(first, replay);
        let alternate_signature_carrier = seal_mailbox_stream(
            context,
            &encapsulation_key,
            &signing_key,
            &verification_key,
            [0x55; 32],
            [0x67; ROSTER_SIGNATURE_RANDOMIZER_BYTE_LENGTH],
            b"retained bytes",
        )
        .expect("same mailbox body accepts fresh signature randomness");
        let first_verified =
            verify_mailbox_envelope(context, &encapsulation_key, &verification_key, &first)
                .unwrap();
        let alternate_verified = verify_mailbox_envelope(
            context,
            &encapsulation_key,
            &verification_key,
            &alternate_signature_carrier,
        )
        .unwrap();
        assert_eq!(
            first_verified.body_identity(),
            alternate_verified.body_identity()
        );
        assert_ne!(
            first_verified.carrier_identity,
            alternate_verified.carrier_identity
        );
        assert_eq!(
            open_mailbox_stream(
                context,
                &encapsulation_key,
                &decapsulation_key,
                &verification_key,
                &first,
            )
            .expect("retained replay opens")
            .as_bytes(),
            b"retained bytes"
        );
    }
}
