use core::fmt;

use crate::foundation::{
    CanonicalDecodeLimits, Hash512, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, Roster, RosterEntry,
};

use super::action_signature::{derive_verification_key, validate_verification_key};
use super::pair_encryption::{
    DECRYPTION_KEY_BYTE_LENGTH, ENCRYPTION_KEY_BYTE_LENGTH, validate_encryption_key,
    validate_key_pair,
};

pub const COMPLETION_PROFILE_PARTICIPANT_COUNT: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstructionRosterError {
    InvalidCanonicalRoster,
    WrongParticipantCount,
    WrongRosterIdentity,
    WrongRosterPosition,
    WrongRosterCredentials,
}

impl fmt::Display for ConstructionRosterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCanonicalRoster => "the frozen roster is not canonically encoded",
            Self::WrongParticipantCount => {
                "the frozen roster is not the ten-participant completion roster"
            }
            Self::WrongRosterIdentity => "the frozen roster has the wrong identity",
            Self::WrongRosterPosition => "the roster position is outside the frozen roster",
            Self::WrongRosterCredentials => {
                "the private roster credentials do not match the frozen roster"
            }
        })
    }
}

impl std::error::Error for ConstructionRosterError {}

pub fn decode_completion_roster(bytes: &[u8]) -> Result<Roster, ConstructionRosterError> {
    let roster = Roster::decode(bytes, &CanonicalDecodeLimits::default())
        .map_err(|_| ConstructionRosterError::InvalidCanonicalRoster)?;
    require_completion_roster(&roster)?;
    if roster
        .encode()
        .map_err(|_| ConstructionRosterError::InvalidCanonicalRoster)?
        .as_slice()
        != bytes
    {
        return Err(ConstructionRosterError::InvalidCanonicalRoster);
    }
    Ok(roster)
}

pub fn require_completion_roster(roster: &Roster) -> Result<(), ConstructionRosterError> {
    if roster.entries.len() != usize::from(COMPLETION_PROFILE_PARTICIPANT_COUNT) {
        return Err(ConstructionRosterError::WrongParticipantCount);
    }
    if roster.entries.iter().any(|entry| {
        validate_verification_key(&entry.signing_verification_key).is_err()
            || validate_encryption_key(&entry.mailbox_encapsulation_key).is_err()
    }) {
        return Err(ConstructionRosterError::InvalidCanonicalRoster);
    }
    Ok(())
}

pub fn require_roster_identity(
    roster: &Roster,
    expected_identity: Hash512,
) -> Result<(), ConstructionRosterError> {
    require_completion_roster(roster)?;
    if roster
        .roster_hash()
        .map_err(|_| ConstructionRosterError::InvalidCanonicalRoster)?
        != expected_identity
    {
        return Err(ConstructionRosterError::WrongRosterIdentity);
    }
    Ok(())
}

fn roster_entry(
    roster: &Roster,
    roster_position: u16,
) -> Result<&RosterEntry, ConstructionRosterError> {
    require_completion_roster(roster)?;
    roster
        .entries
        .get(usize::from(roster_position))
        .filter(|entry| entry.roster_position == roster_position)
        .ok_or(ConstructionRosterError::WrongRosterPosition)
}

pub fn signing_verification_key(
    roster: &Roster,
    roster_position: u16,
) -> Result<&[u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH], ConstructionRosterError> {
    Ok(&roster_entry(roster, roster_position)?.signing_verification_key)
}

pub fn mailbox_encapsulation_key(
    roster: &Roster,
    roster_position: u16,
) -> Result<&[u8; ENCRYPTION_KEY_BYTE_LENGTH], ConstructionRosterError> {
    Ok(&roster_entry(roster, roster_position)?.mailbox_encapsulation_key)
}

pub fn verify_roster_credentials(
    roster: &Roster,
    roster_position: u16,
    signing_secret_key: &[u8],
    mailbox_decapsulation_key: &[u8],
) -> Result<(), ConstructionRosterError> {
    let entry = roster_entry(roster, roster_position)?;
    if derive_verification_key(signing_secret_key)
        .map_err(|_| ConstructionRosterError::WrongRosterCredentials)?
        != entry.signing_verification_key
        || mailbox_decapsulation_key.len() != DECRYPTION_KEY_BYTE_LENGTH
        || validate_key_pair(&entry.mailbox_encapsulation_key, mailbox_decapsulation_key).is_err()
    {
        return Err(ConstructionRosterError::WrongRosterCredentials);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fips203::{
        ml_kem_768,
        traits::{KeyGen, SerDes as KemSerDes},
    };

    use super::*;
    use crate::protocol::action_signature::generate_key_pair as generate_signing_key_pair;

    fn sample_roster() -> Roster {
        Roster::new(
            (0..COMPLETION_PROFILE_PARTICIPANT_COUNT)
                .map(|position| {
                    let mut signing_seed = [0x31; 32];
                    signing_seed[0] = u8::try_from(position).expect("position fits");
                    let signing_key = generate_signing_key_pair(&signing_seed)
                        .expect("signing key generation succeeds")
                        .verification_key;
                    let mut d = [0x52; 32];
                    d[0] = u8::try_from(position).expect("position fits");
                    let mut z = [0x83; 32];
                    z[31] = u8::try_from(position).expect("position fits");
                    let (mailbox_key, _) = ml_kem_768::KG::keygen_from_seed(d, z);
                    RosterEntry::new(position, signing_key, mailbox_key.into_bytes())
                        .expect("roster entry is valid")
                })
                .collect(),
        )
        .expect("completion roster is valid")
    }

    #[test]
    fn decodes_the_exact_foundation_roster_and_resolves_keys() {
        let roster = sample_roster();
        let bytes = roster.encode().expect("roster encodes");
        let decoded = decode_completion_roster(&bytes).expect("roster decodes");
        require_roster_identity(
            &decoded,
            roster.roster_hash().expect("roster identity derives"),
        )
        .expect("identity matches");
        assert_eq!(
            signing_verification_key(&decoded, 4).expect("signing key exists"),
            &roster.entries[4].signing_verification_key,
        );
        assert_eq!(
            mailbox_encapsulation_key(&decoded, 7).expect("mailbox key exists"),
            &roster.entries[7].mailbox_encapsulation_key,
        );
    }

    #[test]
    fn refuses_wrong_size_position_and_identity() {
        let roster = sample_roster();
        assert_eq!(
            signing_verification_key(&roster, 10),
            Err(ConstructionRosterError::WrongRosterPosition),
        );
        assert_eq!(
            require_roster_identity(&roster, Hash512::from_bytes([0xff; 64])),
            Err(ConstructionRosterError::WrongRosterIdentity),
        );
        let short = Roster::new(roster.entries[..3].to_vec()).expect("short roster is structural");
        assert_eq!(
            require_completion_roster(&short),
            Err(ConstructionRosterError::WrongParticipantCount),
        );
        let mut malformed_mailbox_roster = roster.clone();
        malformed_mailbox_roster.entries[0].mailbox_encapsulation_key[..3].fill(0xff);
        assert_eq!(
            require_completion_roster(&malformed_mailbox_roster),
            Err(ConstructionRosterError::InvalidCanonicalRoster),
        );
    }

    #[test]
    fn private_credentials_must_match_the_exact_roster_entry() {
        let roster = sample_roster();
        let mut signing_seed = [0x31; 32];
        signing_seed[0] = 0;
        let signing_key = generate_signing_key_pair(&signing_seed)
            .expect("position-zero signing key generation succeeds");
        let mut d = [0x52; 32];
        d[0] = 0;
        let mut z = [0x83; 32];
        z[31] = 0;
        let (_, mailbox_key) = ml_kem_768::KG::keygen_from_seed(d, z);
        let mailbox_key = mailbox_key.into_bytes();
        verify_roster_credentials(&roster, 0, &signing_key.secret_key, &mailbox_key)
            .expect("matching credentials verify");

        let other_signing_key =
            generate_signing_key_pair(&[0x32; 32]).expect("other signing key generation succeeds");
        assert_eq!(
            verify_roster_credentials(&roster, 0, &other_signing_key.secret_key, &mailbox_key,),
            Err(ConstructionRosterError::WrongRosterCredentials),
        );
        let (_, other_mailbox_key) = ml_kem_768::KG::keygen_from_seed([0x92; 32], [0xa3; 32]);
        assert_eq!(
            verify_roster_credentials(
                &roster,
                0,
                &signing_key.secret_key,
                &other_mailbox_key.into_bytes(),
            ),
            Err(ConstructionRosterError::WrongRosterCredentials),
        );
    }
}
