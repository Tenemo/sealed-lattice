use crate::{
    certification::VerifiedInventoryCertificate,
    interpolation::cleared_weights,
    release::{self, Refusal},
    release_body::VerifiedReleaseShare,
};
use linked_release_proof::statement::release_modulus;
use num_bigint::BigInt;
use std::sync::Arc;
use supported_profile::{
    PLAINTEXT_MODULUS, Profile,
    plaintext::{ACTIVE_SLOTS, ENCODING_DEGREE, multiply, odd_power_values, power, slot_positions},
    relation::{SYSTEMATIC, release_coefficient_bytes},
};

/// The option at each requested rank. The result plaintext is one at the
/// slot of each requested rank's option and zero at every other slot.
fn selected_positions(
    profile: Profile,
    coefficients: &[u32],
    top_count: usize,
) -> Result<Vec<usize>, Refusal> {
    let options = profile.options();
    let window = profile.rank_window();
    let coefficient_stride = 2 * SYSTEMATIC / ENCODING_DEGREE;
    if !(1..=options).contains(&top_count)
        || coefficients.len() != SYSTEMATIC
        || coefficients.iter().any(|value| *value >= PLAINTEXT_MODULUS)
        || coefficients
            .iter()
            .enumerate()
            .any(|(index, value)| !index.is_multiple_of(coefficient_stride) && *value != 0)
    {
        return Err(Refusal::Encoding);
    }
    let values = odd_power_values(coefficients);
    let mut selected = vec![None; top_count];
    let mut positions = vec![None; ACTIVE_SLOTS];
    for option in 0..options {
        for rank in 0..top_count {
            let slot = (option * window + ACTIVE_SLOTS - rank) % ACTIVE_SLOTS;
            positions[slot] = Some((option, rank));
        }
    }
    for (slot, index) in slot_positions(ENCODING_DEGREE).enumerate() {
        if values[ENCODING_DEGREE / 2 - 1 - index] != 0 {
            return Err(Refusal::Encoding);
        }
        let value = values[index];
        if let Some((option, rank)) = positions[slot] {
            if value > 1 {
                return Err(Refusal::Encoding);
            }
            if value == 1 && selected[rank].replace(option).is_some() {
                return Err(Refusal::Encoding);
            }
        } else if value != 0 {
            return Err(Refusal::Encoding);
        }
    }
    let result = selected
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(Refusal::Encoding)?;
    let mut seen = vec![false; options];
    for position in &result {
        if seen[*position] {
            return Err(Refusal::Encoding);
        }
        seen[*position] = true;
    }
    Ok(result)
}

pub struct VerifiedNoResult {
    certificate: Arc<VerifiedInventoryCertificate>,
}
impl VerifiedNoResult {
    pub fn certificate(&self) -> &Arc<VerifiedInventoryCertificate> {
        &self.certificate
    }
}
pub fn verify_no_result(
    certificate: Arc<VerifiedInventoryCertificate>,
) -> Result<VerifiedNoResult, Refusal> {
    if certificate.target().ciphertext().is_some() {
        return Err(Refusal::Context);
    }
    Ok(VerifiedNoResult { certificate })
}
pub struct VerifiedResult {
    certificate: Arc<VerifiedInventoryCertificate>,
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
    pub fn certificate(&self) -> &Arc<VerifiedInventoryCertificate> {
        &self.certificate
    }
}
pub struct ReleaseCollector {
    certificate: Arc<VerifiedInventoryCertificate>,
    shares: Vec<Option<Arc<VerifiedReleaseShare>>>,
}
impl ReleaseCollector {
    pub fn new(certificate: Arc<VerifiedInventoryCertificate>) -> Result<Self, Refusal> {
        let target = certificate.target();
        if target.ciphertext().is_none() {
            return Err(Refusal::NoResult);
        }
        let profile = target.setup().profile();
        if target.setup().roster().proposal().records().len() != profile.participants()
            || target.poll().manifest().option_count() != profile.options()
            || !(1..=profile.options()).contains(&usize::from(target.poll().top_count()))
        {
            return Err(Refusal::Context);
        }
        Ok(Self {
            certificate,
            shares: (0..profile.participants()).map(|_| None).collect(),
        })
    }
    pub fn insert(&mut self, share: Arc<VerifiedReleaseShare>) -> Result<bool, Refusal> {
        let target = share.body().certificate().target();
        if target.identity() != self.certificate.target().identity()
            || target.body() != self.certificate.target().body()
        {
            return Err(Refusal::Context);
        }
        let slot = self
            .shares
            .get_mut(share.body().position())
            .ok_or(Refusal::Context)?;
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
    pub fn result(&self) -> Result<VerifiedResult, Refusal> {
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
            return Err(Refusal::Incomplete);
        }
        let positions: Vec<usize> = chosen.iter().map(|(position, _)| *position).collect();
        let weights = cleared_weights(profile, &positions).map_err(|_| Refusal::Context)?;
        let modulus = release_modulus(profile);
        let half = &modulus >> 1usize;
        let clearing = BigInt::from(profile.clearing_factor());
        let inverse_clearing = clearing.modpow(&(&modulus - 2u32), &modulus);
        let ciphertext = self
            .certificate
            .target()
            .ciphertext()
            .ok_or(Refusal::NoResult)?;
        let width = release_coefficient_bytes(profile);
        let constant = release::decode_polynomial(
            &ciphertext[..SYSTEMATIC * width],
            &profile.release_modulus().to_bytes(),
        )?;
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
        let inverse_plain_clearing = power(profile.clearing_factor() as u32, PLAINTEXT_MODULUS - 2);
        let plaintext: Vec<u32> = phase
            .into_iter()
            .map(|value| {
                let mut value = (value * &inverse_clearing) % &modulus;
                if value < BigInt::from(0) {
                    value += &modulus;
                }
                let negative = value > half;
                let magnitude = if negative { &modulus - value } else { value };
                let rounded = (magnitude * PLAINTEXT_MODULUS + &half) / &modulus;
                let value = if negative { -rounded } else { rounded };
                let residue = ((value % PLAINTEXT_MODULUS) + PLAINTEXT_MODULUS) % PLAINTEXT_MODULUS;
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
