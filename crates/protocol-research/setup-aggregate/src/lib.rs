use num_bigint::{BigInt, Sign};
use supported_profile::{Family, Profile};

mod retained;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "setup-browser.rs"]
pub mod setup_browser;
pub mod verified;
pub use retained::{
    AggregatePolynomialReader, RetainedAggregatePolynomial, RetainedPolynomialReader,
    RetainedSetupInputs, VerifiedAggregatePolynomial,
};

pub const CHUNK_BYTES: usize = 524_288;

/// The family of a setup polynomial that contribution bodies carry, and so
/// the aggregate sums.
pub fn contribution_family(profile: Profile, index: usize) -> Option<Family> {
    profile
        .contribution_body_polynomials()
        .contains(&index)
        .then(|| profile.setup_family(index))
        .flatten()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Encoding,
}

pub struct PolynomialAdder {
    modulus: BigInt,
    half: BigInt,
    width: usize,
}
impl PolynomialAdder {
    pub fn new(profile: Profile, family: Family) -> Self {
        let modulus = BigInt::from_bytes_le(Sign::Plus, &profile.family_modulus(family));
        Self {
            half: &modulus >> 1usize,
            modulus,
            width: 1 + profile.family_magnitude_bytes(family),
        }
    }
    pub(crate) fn decode(&self, bytes: &[u8]) -> Result<BigInt, Refusal> {
        if bytes.len() != self.width || bytes[0] > 1 {
            return Err(Refusal::Encoding);
        }
        let value = BigInt::from_bytes_le(Sign::Plus, &bytes[1..]);
        if value > self.half || (bytes[0] == 1 && value == BigInt::from(0)) {
            return Err(Refusal::Encoding);
        }
        Ok(if bytes[0] == 1 { -value } else { value })
    }
    /// Both inputs are public canonical coefficients. The destination is scratch;
    /// refusal may leave its earlier coefficients changed and grants no capability.
    pub fn add_into(&self, incoming: &[u8], destination: &mut [u8]) -> Result<(), Refusal> {
        if incoming.is_empty()
            || incoming.len() != destination.len()
            || incoming.len() > CHUNK_BYTES
            || !incoming.len().is_multiple_of(self.width)
        {
            return Err(Refusal::Shape);
        }
        for (left, right) in incoming
            .chunks_exact(self.width)
            .zip(destination.chunks_exact_mut(self.width))
        {
            let mut sum = self.decode(left)? + self.decode(right)?;
            if sum > self.half {
                sum -= &self.modulus;
            } else if sum < -&self.half {
                sum += &self.modulus;
            }
            let (sign, magnitude) = sum.to_bytes_le();
            if magnitude.len() >= self.width {
                return Err(Refusal::Encoding);
            }
            right.fill(0);
            right[0] = u8::from(sign == Sign::Minus);
            right[1..1 + magnitude.len()].copy_from_slice(&magnitude);
        }
        Ok(())
    }
}

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
mod browser {
    use super::*;
    use std::cell::RefCell;
    struct Session {
        input: Vec<u8>,
        adder: Option<PolynomialAdder>,
    }
    thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: vec![0; 2 * CHUNK_BYTES], adder: None }); }
    #[unsafe(no_mangle)]
    pub extern "C" fn aggregate_input_pointer() -> usize {
        SESSION.with(|value| value.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn aggregate_begin(participants: usize, options: usize, index: usize) -> u32 {
        SESSION.with(|value| {
            let mut value = value.borrow_mut();
            value.adder = Profile::new(participants, options)
                .ok()
                .and_then(|profile| {
                    contribution_family(profile, index)
                        .map(|family| PolynomialAdder::new(profile, family))
                });
            u32::from(value.adder.is_none())
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn aggregate_add(length: usize) -> u32 {
        SESSION.with(|value| {
            let mut value = value.borrow_mut();
            let Session { input, adder } = &mut *value;
            let Some(adder) = adder else {
                return 1;
            };
            if length > CHUNK_BYTES {
                return 1;
            }
            let (incoming, remaining) = input.split_at_mut(CHUNK_BYTES);
            u32::from(
                adder
                    .add_into(&incoming[..length], &mut remaining[..length])
                    .is_err(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(value: &BigInt, width: usize) -> Vec<u8> {
        let (sign, magnitude) = value.to_bytes_le();
        let mut bytes = vec![0; width];
        bytes[0] = u8::from(sign == Sign::Minus);
        bytes[1..1 + magnitude.len()].copy_from_slice(&magnitude);
        bytes
    }
    #[test]
    fn centered_wraps_and_cancellation_are_exact() {
        for (participants, options, family) in [
            (3, 2, Family::Fhe),
            (20, 20, Family::Fhe),
            (3, 2, Family::Sharing),
            (3, 2, Family::Auxiliary),
        ] {
            let adder = PolynomialAdder::new(Profile::new(participants, options).unwrap(), family);
            let values = [
                BigInt::from(0),
                BigInt::from(1),
                BigInt::from(-1),
                adder.half.clone(),
                -&adder.half,
            ];
            for left in &values {
                for right in &values {
                    let incoming = encode(left, adder.width);
                    let mut destination = encode(right, adder.width);
                    adder.add_into(&incoming, &mut destination).unwrap();
                    let positive =
                        ((left + right) % &adder.modulus + &adder.modulus) % &adder.modulus;
                    let expected = if positive > adder.half {
                        positive - &adder.modulus
                    } else {
                        positive
                    };
                    assert_eq!(adder.decode(&destination).unwrap(), expected);
                }
            }
        }
    }
    #[test]
    fn refuses_noncanonical_values_and_shapes() {
        let profile = Profile::new(3, 2).unwrap();
        let adder = PolynomialAdder::new(profile, Family::Auxiliary);
        let zero = vec![0; adder.width];
        let mut negative_zero = zero.clone();
        negative_zero[0] = 1;
        assert_eq!(
            adder.add_into(&negative_zero, &mut zero.clone()),
            Err(Refusal::Encoding)
        );
        let mut unknown_sign = zero.clone();
        unknown_sign[0] = 2;
        assert_eq!(
            adder.add_into(&unknown_sign, &mut zero.clone()),
            Err(Refusal::Encoding)
        );
        let excessive = encode(&(&adder.half + 1), adder.width);
        assert_eq!(
            adder.add_into(&excessive, &mut zero.clone()),
            Err(Refusal::Encoding)
        );
        assert_eq!(
            adder.add_into(&zero, &mut excessive.clone()),
            Err(Refusal::Encoding)
        );
        assert_eq!(adder.add_into(&[], &mut []), Err(Refusal::Shape));
        assert_eq!(adder.add_into(&zero, &mut [0]), Err(Refusal::Shape));
    }
    #[test]
    fn only_contribution_polynomials_have_an_aggregate_family() {
        for (participants, options) in [(3, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            for index in [
                profile.fhe_polynomial(0, 0),
                profile.fhe_polynomial(profile.gadget_length() - 1, 5),
                profile.share_common_polynomial(),
                profile.recipient_key_polynomial(participants - 1),
                profile.auxiliary_common_polynomial(),
                profile.setup_polynomials(),
            ] {
                assert_eq!(contribution_family(profile, index), None);
            }
            for (index, family) in [
                (profile.fhe_polynomial(0, 1), Family::Fhe),
                (
                    profile.fhe_polynomial(profile.gadget_length() - 1, 6),
                    Family::Fhe,
                ),
                (profile.share_constant_polynomial(0), Family::Sharing),
                (
                    profile.share_linear_polynomial(participants - 1),
                    Family::Sharing,
                ),
                (profile.auxiliary_key_polynomial(), Family::Auxiliary),
            ] {
                assert_eq!(contribution_family(profile, index), Some(family));
            }
        }
    }
}
