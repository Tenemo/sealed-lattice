//! Registered encrypted-source families and authenticated body reopening.
use crate::{Refusal, poll::VerifiedPoll};
use supported_profile::Profile;

fn families(maximum: usize, options: usize) -> Vec<Profile> {
    let mut families: Vec<Profile> = Vec::new();
    for participants in *Profile::participant_range().start()..=maximum {
        let profile =
            Profile::new(participants, options).expect("A verified poll has supported dimensions.");
        if !families
            .iter()
            .any(|previous| previous.same_fhe_key_family(profile))
        {
            families.push(profile);
        }
    }
    families
}

/// Reopens one source of a complete authenticated registration. The poll
/// chooses the family; the registration supplies its signing-key identity.
pub fn source_verifier(
    poll: &VerifiedPoll,
    registration: &crate::registration::VerifiedRegistration,
    profile: Profile,
) -> Result<setup_witness::encrypted_source::SourceCiphertextVerifier, Refusal> {
    let header = registration.header();
    if header.poll != poll.identity() {
        return Err(Refusal::Context);
    }
    let index = fhe_key_family_index(poll, profile)?;
    let expected = *header.source_bindings.get(index).ok_or(Refusal::Shape)?;
    let owner = crate::foundation::derive_participant_identity(&header.signing_public)
        .map_err(|_| Refusal::Shape)?;
    Ok(
        setup_witness::encrypted_source::SourceCiphertextVerifier::new(
            profile,
            &poll.identity(),
            owner.as_bytes(),
            expected,
        ),
    )
}

pub(crate) fn families_from_dimensions(
    maximum: usize,
    options: usize,
) -> Result<Vec<Profile>, Refusal> {
    Profile::new(maximum, options).map_err(|_| Refusal::Shape)?;
    Ok(families(maximum, options))
}

/// One representative per distinct modulus and common-sampler width, in
/// first-occurrence order among the rosters the verified poll permits.
/// The representative's participant count is not part of family framing.
pub fn fhe_key_families(poll: &VerifiedPoll) -> Vec<Profile> {
    families(
        usize::from(poll.maximum_participants()),
        poll.manifest().option_count(),
    )
}

pub(crate) fn fhe_key_family_index(
    poll: &VerifiedPoll,
    profile: Profile,
) -> Result<usize, Refusal> {
    if profile.options() != poll.manifest().option_count()
        || profile.participants() > usize::from(poll.maximum_participants())
    {
        return Err(Refusal::Context);
    }
    fhe_key_families(poll)
        .iter()
        .position(|family| family.same_fhe_key_family(profile))
        .ok_or(Refusal::Context)
}

pub fn maximum_fhe_key_family_count() -> usize {
    Profile::option_range()
        .map(|options| families(*Profile::participant_range().end(), options).len())
        .max()
        .expect("Supported option range is nonempty.")
}

#[cfg(test)]
#[path = "source-binding-tests.rs"]
mod tests;
