use crate::{
    certification::VerifiedTargetCertificate,
    interpolation::cleared_weights,
    release::{self, Error},
    release_body::VerifiedReleaseShare,
};
use linked_release_proof::{parameters::SYSTEMATIC, statement::release_modulus};
use num_bigint::BigInt;
use std::sync::Arc;

const PRIME: u32 = 65537;
fn multiply(left: u32, right: u32) -> u32 {
    (u64::from(left) * u64::from(right) % u64::from(PRIME)) as u32
}
fn power(mut value: u32, mut exponent: u32) -> u32 {
    let mut result = 1;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }
    result
}
fn selected_positions(coefficients: &[u32], top_count: usize) -> Result<Vec<usize>, Error> {
    if !(1..=10).contains(&top_count)
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
    let mut twist = 1;
    let mut values: Vec<_> = coefficients
        .iter()
        .step_by(2)
        .map(|value| {
            let result = multiply(*value, twist);
            twist = multiply(twist, 3);
            result
        })
        .collect();
    let logarithm = length.ilog2();
    for index in 0..length {
        let reverse = index.reverse_bits() >> (usize::BITS - logarithm);
        if index < reverse {
            values.swap(index, reverse);
        }
    }
    let mut width = 2;
    while width <= length {
        let step = power(9, (length / width) as u32);
        for block in values.chunks_exact_mut(width) {
            let (left, right) = block.split_at_mut(width / 2);
            let mut twiddle = 1;
            for (first, second) in left.iter_mut().zip(right) {
                let a = *first;
                let b = multiply(*second, twiddle);
                *first = (a + b) % PRIME;
                *second = (a + PRIME - b) % PRIME;
                twiddle = multiply(twiddle, step);
            }
        }
        width *= 2;
    }
    let mut selected = vec![None; top_count];
    let mut used = vec![false; length];
    let mut exponent = 1;
    for slot in 0..SYSTEMATIC / 4 {
        let index = (exponent - 1) / 2;
        used[index] = true;
        let value = values[index];
        exponent = 5 * exponent % SYSTEMATIC;
        if slot < 1600 && slot % 16 == 0 && slot / 16 % 10 < top_count {
            if value > 1 {
                return Err(Error::Encoding);
            }
            if value == 1 {
                let option = slot / 160;
                let rank = slot / 16 % 10;
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
    let mut seen = [false; 10];
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
        if target.inventory().setup().inventory().confirmations().len() != 10
            || target.inventory().poll().manifest().option_count() != 10
            || !(1..=10).contains(&target.inventory().poll().top_count())
        {
            return Err(Error::Context);
        }
        Ok(Self {
            certificate,
            shares: (0..10).map(|_| None).collect(),
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
    pub fn result(&self) -> Result<VerifiedResult, Error> {
        let chosen: Vec<_> = self
            .shares
            .iter()
            .enumerate()
            .filter_map(|(position, share)| share.as_ref().map(|share| (position, share)))
            .take(4)
            .collect();
        if chosen.len() != 4 {
            return Err(Error::Incomplete);
        }
        let positions: [usize; 4] = std::array::from_fn(|index| chosen[index].0);
        let weights = cleared_weights(positions).map_err(|_| Error::Context)?;
        let modulus = release_modulus();
        let half = &modulus >> 1usize;
        let inverse_four = (&modulus * 3u32 + 1u32) / 4u32;
        let ciphertext = self
            .certificate
            .target()
            .ciphertext()
            .ok_or(Error::NoResult)?;
        let constant = release::decode_polynomial(&ciphertext[..SYSTEMATIC * 25], 25, &modulus)?;
        let mut phase: Vec<_> = constant.into_iter().map(|value| value * 16u32).collect();
        for (ordinal, (_, share)) in chosen.iter().enumerate() {
            for (power, weight) in weights[ordinal].iter().enumerate() {
                if *weight == 0 {
                    continue;
                }
                let shift = power * SYSTEMATIC / 8;
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
        let inverse_plain_four = power(4, PRIME - 2);
        let plaintext: Vec<u32> = phase
            .into_iter()
            .map(|value| {
                let mut value = (value * &inverse_four) % &modulus;
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
                multiply(value, inverse_plain_four)
            })
            .collect();
        let ordered = selected_positions(
            &plaintext,
            usize::from(self.certificate.target().inventory().poll().top_count()),
        )?;
        let options = self
            .certificate
            .target()
            .inventory()
            .poll()
            .manifest()
            .options();
        let identifiers = ordered
            .into_iter()
            .map(|position| options[position].option_identifier().to_owned())
            .collect();
        Ok(VerifiedResult {
            certificate: self.certificate.clone(),
            identifiers,
            participants: positions.to_vec(),
        })
    }
}

#[cfg(test)]
mod decoder_tests {
    use super::*;

    // Direct evaluation-basis interpolation, independent of the decoder's NTT.
    // A nonzero evaluation at z contributes z^(-j)/32768 to coefficient j.
    fn encode_evaluations(entries: &[(usize, u32)]) -> Vec<u32> {
        let modulus = BigInt::from(65_537u32);
        let inverse_length = 65_535u64;
        let mut coefficients = vec![0u32; 65_536];
        for (index, value) in entries {
            let root = BigInt::from(3u32).modpow(&BigInt::from(2 * index + 1), &modulus);
            let inverse = root
                .modpow(&BigInt::from(65_535u32), &modulus)
                .to_u64_digits()
                .1[0];
            let mut term = u64::from(*value) * inverse_length % 65_537;
            for coefficient in coefficients.iter_mut().step_by(2) {
                *coefficient = ((u64::from(*coefficient) + term) % 65_537) as u32;
                term = term * inverse % 65_537;
            }
        }
        coefficients
    }
    fn evaluation_index(slot: usize) -> usize {
        let exponent = BigInt::from(5u32)
            .modpow(&BigInt::from(slot), &BigInt::from(65_536u32))
            .to_u64_digits()
            .1[0] as usize;
        (exponent - 1) / 2
    }
    fn entries(order: &[usize]) -> Vec<(usize, u32)> {
        order
            .iter()
            .enumerate()
            .map(|(rank, option)| (evaluation_index((option * 10 + rank) * 16), 1))
            .collect()
    }
    #[test]
    fn direct_interpolation_decodes_varied_exact_rankings() {
        for order in [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
            [4, 1, 8, 0, 7, 2, 9, 5, 3, 6],
        ] {
            for top_count in 1..=10 {
                assert_eq!(
                    selected_positions(
                        &encode_evaluations(&entries(&order[..top_count])),
                        top_count,
                    )
                    .unwrap(),
                    order[..top_count]
                );
            }
        }
    }
    #[test]
    fn decoder_rejects_extra_values_missing_ranks_and_noncanonical_polynomials() {
        let original = entries(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut variants = Vec::new();
        let mut missing = original.clone();
        missing.pop();
        variants.push(missing);
        for extra in [
            (evaluation_index(1), 1),
            (evaluation_index(1600), 1),
            // Root exponent 3 belongs to the complementary packing orbit.
            (1, 1),
            (original[0].0, 1),
            (evaluation_index(160), 1),
        ] {
            let mut changed = original.clone();
            changed.push(extra);
            variants.push(changed);
        }
        variants.push(entries(&[0, 0, 2, 3, 4, 5, 6, 7, 8, 9]));
        for changed in variants {
            assert!(selected_positions(&encode_evaluations(&changed), 10).is_err());
        }
        let valid = encode_evaluations(&original);
        for (index, value) in [(1, 1), (0, 65_537)] {
            let mut changed = valid.clone();
            changed[index] = value;
            assert!(selected_positions(&changed, 10).is_err());
        }
        assert!(selected_positions(&valid[..valid.len() - 1], 10).is_err());
        let mut changed = valid;
        changed.push(0);
        assert!(selected_positions(&changed, 10).is_err());
    }

    #[test]
    fn shorter_outputs_reject_omitted_ranks_in_the_plaintext() {
        let order = [4, 1, 8, 0, 7, 2, 9, 5, 3, 6];
        let complete = encode_evaluations(&entries(&order));
        for top_count in 1..10 {
            assert!(selected_positions(&complete, top_count).is_err());
            let mut extra = entries(&order[..top_count]);
            extra.push((
                evaluation_index((order[top_count] * 10 + top_count) * 16),
                1,
            ));
            assert!(selected_positions(&encode_evaluations(&extra), top_count).is_err());
            let mut missing = entries(&order[..top_count]);
            missing.pop();
            assert!(selected_positions(&encode_evaluations(&missing), top_count).is_err());
        }
        for top_count in [0, 11, usize::MAX] {
            assert!(selected_positions(&complete, top_count).is_err());
        }
    }
}
