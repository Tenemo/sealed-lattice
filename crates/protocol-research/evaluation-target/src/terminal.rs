use crate::{
    certification::VerifiedTargetCertificate,
    interpolation::cleared_weights,
    release::{self, Error},
    release_body::VerifiedReleaseShare,
};
use linked_release_proof::{
    parameters::SYSTEMATIC,
    statement::{release_coefficient_bytes, release_modulus},
};
use num_bigint::BigInt;
use std::sync::Arc;
use supported_profile::{
    PLAINTEXT_MODULUS as PRIME, Profile,
    plaintext::{multiply, odd_power_values, power, slot_positions},
};

/// The option at each requested rank. The result plaintext is one at the
/// slot of each requested rank's option and zero at every other slot.
fn selected_positions(
    profile: Profile,
    coefficients: &[u32],
    top_count: usize,
) -> Result<Vec<usize>, Error> {
    let options = profile.options();
    let window = profile.rank_window();
    if !(1..=options).contains(&top_count)
        || coefficients.len() != SYSTEMATIC
        || coefficients.iter().any(|value| *value >= PRIME)
        || coefficients
            .iter()
            .skip(1)
            .step_by(2)
            .any(|value| *value != 0)
    {
        return Err(Error::Encoding);
    }
    let length = SYSTEMATIC / 2;
    let values = odd_power_values(coefficients);
    let mut selected = vec![None; top_count];
    let mut used = vec![false; length];
    for (slot, index) in slot_positions(SYSTEMATIC).enumerate() {
        used[index] = true;
        let value = values[index];
        if slot < options * options * window
            && slot.is_multiple_of(window)
            && slot / window % options < top_count
        {
            if value > 1 {
                return Err(Error::Encoding);
            }
            if value == 1 {
                let option = slot / (options * window);
                let rank = slot / window % options;
                if selected[rank].replace(option).is_some() {
                    return Err(Error::Encoding);
                }
            }
        } else if value != 0 {
            return Err(Error::Encoding);
        }
    }
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| !used[index] && *value != 0)
    {
        return Err(Error::Encoding);
    }
    let result = selected
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::Encoding)?;
    let mut seen = vec![false; options];
    for position in &result {
        if seen[*position] {
            return Err(Error::Encoding);
        }
        seen[*position] = true;
    }
    Ok(result)
}

pub struct VerifiedNoResult {
    certificate: Arc<VerifiedTargetCertificate>,
}
impl VerifiedNoResult {
    pub fn certificate(&self) -> &Arc<VerifiedTargetCertificate> {
        &self.certificate
    }
}
pub fn verify_no_result(
    certificate: Arc<VerifiedTargetCertificate>,
) -> Result<VerifiedNoResult, Error> {
    if certificate.target().ciphertext().is_some() {
        return Err(Error::Context);
    }
    Ok(VerifiedNoResult { certificate })
}
pub struct VerifiedResult {
    certificate: Arc<VerifiedTargetCertificate>,
    identifiers: Vec<String>,
    participants: Vec<usize>,
}
impl VerifiedResult {
    pub fn identifiers(&self) -> &[String] {
        &self.identifiers
    }
    pub fn participants(&self) -> &[usize] {
        &self.participants
    }
    pub fn certificate(&self) -> &Arc<VerifiedTargetCertificate> {
        &self.certificate
    }
}
pub struct ReleaseCollector {
    certificate: Arc<VerifiedTargetCertificate>,
    shares: Vec<Option<Arc<VerifiedReleaseShare>>>,
}
impl ReleaseCollector {
    pub fn new(certificate: Arc<VerifiedTargetCertificate>) -> Result<Self, Error> {
        let target = certificate.target();
        if target.ciphertext().is_none() {
            return Err(Error::NoResult);
        }
        let profile = target.setup().profile();
        if target.setup().roster().proposal().records().len() != profile.participants()
            || target.poll().manifest().option_count() != profile.options()
            || !(1..=profile.options()).contains(&usize::from(target.poll().top_count()))
        {
            return Err(Error::Context);
        }
        Ok(Self {
            certificate,
            shares: (0..profile.participants()).map(|_| None).collect(),
        })
    }
    pub fn insert(&mut self, share: Arc<VerifiedReleaseShare>) -> Result<bool, Error> {
        let target = share.body().certificate().target();
        if target.identity() != self.certificate.target().identity()
            || target.body() != self.certificate.target().body()
        {
            return Err(Error::Context);
        }
        let slot = self
            .shares
            .get_mut(share.body().position())
            .ok_or(Error::Context)?;
        if slot.is_some() {
            return Ok(false);
        }
        *slot = Some(share);
        Ok(true)
    }
    /// Decrypts with the first release-threshold shares by roster position.
    /// Each partial carries the clearing factor c and each cleared weight
    /// another, so the phase is c^2 times the target's; one c is removed
    /// modulo the release modulus and the other modulo the plaintext
    /// modulus.
    pub fn result(&self) -> Result<VerifiedResult, Error> {
        let profile = self.certificate.target().setup().profile();
        let threshold = profile.release_threshold();
        let chosen: Vec<_> = self
            .shares
            .iter()
            .enumerate()
            .filter_map(|(position, share)| share.as_ref().map(|share| (position, share)))
            .take(threshold)
            .collect();
        if chosen.len() != threshold {
            return Err(Error::Incomplete);
        }
        let positions: Vec<usize> = chosen.iter().map(|(position, _)| *position).collect();
        let weights = cleared_weights(profile, &positions).map_err(|_| Error::Context)?;
        let modulus = release_modulus(profile);
        let half = &modulus >> 1usize;
        let clearing = BigInt::from(profile.clearing_factor());
        let inverse_clearing = clearing.modpow(&(&modulus - 2u32), &modulus);
        let ciphertext = self
            .certificate
            .target()
            .ciphertext()
            .ok_or(Error::NoResult)?;
        let width = release_coefficient_bytes(profile);
        let constant =
            release::decode_polynomial(&ciphertext[..SYSTEMATIC * width], width, &modulus)?;
        let mut phase: Vec<_> = constant
            .into_iter()
            .map(|value| value * &clearing * &clearing)
            .collect();
        for (ordinal, (_, share)) in chosen.iter().enumerate() {
            for (power, weight) in weights[ordinal].iter().enumerate() {
                if *weight == 0 {
                    continue;
                }
                let shift = power * profile.point_stride();
                for (index, value) in share.body().partial().iter().enumerate() {
                    let position = index + shift;
                    let term = value * BigInt::from(*weight);
                    if position < SYSTEMATIC {
                        phase[position] += &term;
                    } else {
                        phase[position - SYSTEMATIC] -= &term;
                    }
                }
            }
        }
        let inverse_plain_clearing = power(profile.clearing_factor() as u32, PRIME - 2);
        let plaintext: Vec<u32> = phase
            .into_iter()
            .map(|value| {
                let mut value = (value * &inverse_clearing) % &modulus;
                if value < BigInt::from(0) {
                    value += &modulus;
                }
                let negative = value > half;
                let magnitude = if negative { &modulus - value } else { value };
                let rounded = (magnitude * PRIME + &half) / &modulus;
                let value = if negative { -rounded } else { rounded };
                let residue = ((value % PRIME) + PRIME) % PRIME;
                let digits = residue.to_u32_digits().1;
                let value = digits.first().copied().unwrap_or(0);
                multiply(value, inverse_plain_clearing)
            })
            .collect();
        let ordered = selected_positions(
            profile,
            &plaintext,
            usize::from(self.certificate.target().poll().top_count()),
        )?;
        let options = self.certificate.target().poll().manifest().options();
        let identifiers = ordered
            .into_iter()
            .map(|position| options[position].option_identifier().to_owned())
            .collect();
        Ok(VerifiedResult {
            certificate: self.certificate.clone(),
            identifiers,
            participants: positions,
        })
    }
}

#[cfg(test)]
#[path = "terminal-decoder-tests.rs"]
mod decoder_tests;
