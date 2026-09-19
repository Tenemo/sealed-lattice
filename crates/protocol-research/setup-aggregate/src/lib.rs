use num_bigint::{BigInt, Sign};

mod retained;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "setup-browser.rs"]
pub mod setup_browser;
pub mod verified;
pub use retained::{
    AggregatePolynomialReader, RetainedAggregatePolynomial, RetainedPolynomialReader,
    RetainedSetupInputs, VerifiedAggregatePolynomial,
};

const PARAMETERS: &[u8; 137] = include_bytes!("../../setup-proof/parameters.bin");
pub const CHUNK_BYTES: usize = 524_288;

#[derive(Clone, Copy, Debug)]
pub enum ModulusKind {
    Fhe,
    Sharing,
    Auxiliary,
}
impl ModulusKind {
    pub fn for_contribution_polynomial(index: usize) -> Option<Self> {
        if index < 42 && [1, 2, 4, 6].contains(&(index % 7)) {
            Some(Self::Fhe)
        } else if (44..=72).contains(&index) && !(index - 43).is_multiple_of(3) {
            Some(Self::Sharing)
        } else if index == 74 {
            Some(Self::Auxiliary)
        } else {
            None
        }
    }
    pub fn degree(self) -> usize {
        match self {
            Self::Auxiliary => 4096,
            _ => 65536,
        }
    }
    pub fn magnitude_bytes(self) -> &'static [u8] {
        match self {
            Self::Fhe => &PARAMETERS[4..112],
            Self::Sharing => &PARAMETERS[112..132],
            Self::Auxiliary => &PARAMETERS[132..137],
        }
    }
    pub fn coefficient_bytes(self) -> usize {
        self.magnitude_bytes().len() + 1
    }
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
    pub fn new(kind: ModulusKind) -> Self {
        let modulus = BigInt::from_bytes_le(Sign::Plus, kind.magnitude_bytes());
        Self {
            half: &modulus >> 1usize,
            modulus,
            width: kind.coefficient_bytes(),
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
    pub extern "C" fn aggregate_begin(index: usize) -> u32 {
        SESSION.with(|value| {
            let mut value = value.borrow_mut();
            value.adder = ModulusKind::for_contribution_polynomial(index).map(PolynomialAdder::new);
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
        for kind in [
            ModulusKind::Fhe,
            ModulusKind::Sharing,
            ModulusKind::Auxiliary,
        ] {
            let adder = PolynomialAdder::new(kind);
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
        let adder = PolynomialAdder::new(ModulusKind::Auxiliary);
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
        assert!(ModulusKind::for_contribution_polynomial(0).is_none());
        assert!(ModulusKind::for_contribution_polynomial(43).is_none());
        assert!(ModulusKind::for_contribution_polynomial(75).is_none());
    }
}
