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
use supported_profile::{PLAINTEXT_MODULUS as PRIME, Profile};

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
        let profile = target.inventory().setup().profile();
        if target.inventory().setup().inventory().confirmations().len() != profile.participants()
            || target.inventory().poll().manifest().option_count() != profile.options()
            || !(1..=profile.options())
                .contains(&usize::from(target.inventory().poll().top_count()))
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
        let profile = self.certificate.target().inventory().setup().profile();
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
            participants: positions,
        })
    }
}

#[cfg(test)]
mod decoder_tests {
    use super::*;

    // Every boundary shape and the completion profile.
    fn profiles() -> Vec<Profile> {
        [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)]
            .into_iter()
            .map(|(participants, options)| Profile::new(participants, options).unwrap())
            .collect()
    }
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
    fn slot(profile: Profile, option: usize, rank: usize) -> usize {
        (option * profile.options() + rank) * profile.rank_window()
    }
    fn entries(profile: Profile, order: &[usize]) -> Vec<(usize, u32)> {
        order
            .iter()
            .enumerate()
            .map(|(rank, option)| (evaluation_index(slot(profile, *option, rank)), 1))
            .collect()
    }
    // The identity, its reverse and a fixed shuffle of the options.
    fn orders(options: usize) -> Vec<Vec<usize>> {
        let identity: Vec<usize> = (0..options).collect();
        let reverse = identity.iter().rev().copied().collect();
        let shuffled = (0..options)
            .map(|index| (index * 7 + 3) % options)
            .collect::<Vec<_>>();
        let mut orders = vec![identity, reverse];
        let mut sorted = shuffled.clone();
        sorted.sort_unstable();
        if sorted == orders[0] {
            orders.push(shuffled);
        }
        orders
    }
    #[test]
    fn direct_interpolation_decodes_varied_exact_rankings() {
        for profile in profiles() {
            let options = profile.options();
            for order in orders(options) {
                for top_count in [1, options / 2, options - 1, options] {
                    let top_count = top_count.max(1);
                    assert_eq!(
                        selected_positions(
                            profile,
                            &encode_evaluations(&entries(profile, &order[..top_count])),
                            top_count,
                        )
                        .unwrap(),
                        order[..top_count]
                    );
                }
            }
        }
    }
    #[test]
    fn decoder_rejects_extra_values_missing_ranks_and_noncanonical_polynomials() {
        for profile in profiles() {
            let options = profile.options();
            let window = profile.rank_window();
            let identity: Vec<usize> = (0..options).collect();
            let original = entries(profile, &identity);
            let mut variants = Vec::new();
            let mut missing = original.clone();
            missing.pop();
            variants.push(missing);
            for extra in [
                (evaluation_index(1), 1),
                (evaluation_index(options * options * window), 1),
                // Root exponent 3 belongs to the complementary packing orbit.
                (1, 1),
                (original[0].0, 1),
                (evaluation_index(slot(profile, 1, 0)), 1),
            ] {
                let mut changed = original.clone();
                changed.push(extra);
                variants.push(changed);
            }
            let mut repeated = identity.clone();
            repeated[1] = 0;
            variants.push(entries(profile, &repeated));
            for changed in variants {
                assert!(
                    selected_positions(profile, &encode_evaluations(&changed), options).is_err()
                );
            }
            let valid = encode_evaluations(&original);
            for (index, value) in [(1, 1), (0, 65_537)] {
                let mut changed = valid.clone();
                changed[index] = value;
                assert!(selected_positions(profile, &changed, options).is_err());
            }
            assert!(selected_positions(profile, &valid[..valid.len() - 1], options).is_err());
            let mut changed = valid;
            changed.push(0);
            assert!(selected_positions(profile, &changed, options).is_err());
        }
    }

    // Direct evaluation at one packing slot, independent of every transform.
    fn slot_value(coefficients: &[u32], slot: usize) -> u32 {
        let exponent = BigInt::from(5u32)
            .modpow(&BigInt::from(slot), &BigInt::from(65_536u32))
            .to_u64_digits()
            .1[0] as u32;
        let point = u64::from(power(3, exponent));
        coefficients
            .iter()
            .step_by(2)
            .rev()
            .fold(0u64, |sum, value| {
                (sum * point + u64::from(*value)) % u64::from(PRIME)
            }) as u32
    }
    #[test]
    fn packed_ballots_decode_through_every_requested_result_length() {
        for profile in profiles() {
            let options = profile.options();
            let window = profile.rank_window();
            // Scores of every value, with repeated totals so that the
            // canonical tie rule decides positions.
            let ballots: Vec<Vec<u8>> = (0..profile.participants().min(5))
                .map(|ballot| {
                    (0..options)
                        .map(|option| ((option * (ballot + 3) + ballot) % 10 + 1) as u8)
                        .collect()
                })
                .collect();
            let mut sum = vec![0u32; 65_536];
            for scores in &ballots {
                let packed = ballot_encryption::packing::encode(scores).unwrap();
                for (total, value) in sum.iter_mut().zip(packed) {
                    *total = (*total + value.rem_euclid(PRIME as i32) as u32) % PRIME;
                }
            }
            let totals: Vec<i64> = (0..options)
                .map(|option| ballots.iter().map(|scores| i64::from(scores[option])).sum())
                .collect();
            let centered = |value: u32| {
                if value > PRIME / 2 {
                    i64::from(value) - i64::from(PRIME)
                } else {
                    i64::from(value)
                }
            };
            // Every rank window the evaluator reads holds the same
            // comparisons, whatever result length the poll requests.
            let mut ranks = vec![0; options];
            for option in 0..options {
                for rank in [0, options - 1] {
                    let mut ahead = 0;
                    for lane in 0..window {
                        let difference =
                            centered(slot_value(&sum, slot(profile, option, rank) + lane));
                        let expected = if lane < options {
                            2 * (totals[lane] - totals[option])
                        } else {
                            0
                        };
                        assert_eq!(
                            difference, expected,
                            "option={option}, rank={rank}, lane={lane}"
                        );
                        // The evaluator's tie bias favours the lower opponent.
                        let bias = if lane < option { 1 } else { -1 };
                        ahead += usize::from(difference + bias > 0);
                    }
                    if rank == 0 {
                        ranks[option] = ahead;
                    }
                    assert_eq!(ahead, ranks[option]);
                }
                assert_eq!(
                    i64::from(slot_value(&sum, options * options * window + option)),
                    totals[option]
                );
            }
            for padding in [options * options * window + options, 16_383] {
                assert_eq!(slot_value(&sum, padding), 0);
            }
            let mut order: Vec<usize> = (0..options).collect();
            order.sort_by_key(|option| (std::cmp::Reverse(totals[*option]), *option));
            for top_count in 1..=options {
                let output: Vec<_> = (0..options)
                    .filter(|option| ranks[*option] < top_count)
                    .map(|option| (evaluation_index(slot(profile, option, ranks[option])), 1))
                    .collect();
                assert_eq!(
                    selected_positions(profile, &encode_evaluations(&output), top_count).unwrap(),
                    order[..top_count]
                );
            }
        }
    }

    #[test]
    fn shorter_outputs_reject_omitted_ranks_in_the_plaintext() {
        for profile in profiles() {
            let options = profile.options();
            let order: Vec<usize> = (0..options).rev().collect();
            let complete = encode_evaluations(&entries(profile, &order));
            for top_count in [1, options - 1] {
                if top_count == options {
                    continue;
                }
                assert!(selected_positions(profile, &complete, top_count).is_err());
                let mut extra = entries(profile, &order[..top_count]);
                extra.push((
                    evaluation_index(slot(profile, order[top_count], top_count)),
                    1,
                ));
                assert!(
                    selected_positions(profile, &encode_evaluations(&extra), top_count).is_err()
                );
                let mut missing = entries(profile, &order[..top_count]);
                missing.pop();
                assert!(
                    selected_positions(profile, &encode_evaluations(&missing), top_count).is_err()
                );
            }
            for top_count in [0, options + 1, usize::MAX] {
                assert!(selected_positions(profile, &complete, top_count).is_err());
            }
        }
    }
}
