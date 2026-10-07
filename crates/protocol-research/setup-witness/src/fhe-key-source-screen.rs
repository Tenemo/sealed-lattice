//! Source reproduction and resource screen with fixed synthetic randomness.
//! Public output only; no registration, proof or participant capability.

use crate::{
    PolynomialOutput, Profile,
    contribution::{Contribution, common_polynomial},
    fhe_key_source::FheKeySource,
    gaussian,
};
use num_bigint::{BigInt, Sign};
use parallel_work::ProtocolHash;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{cell::RefCell, io};
use supported_profile::{DEGREE, FHE_SECRET_SUPPORT, Family};
use zeroize::Zeroizing;

pub const OUTPUT_BYTES: usize = 1024;
// Stage refusal shared with the consumed bounded-output host driver.
const REFUSED: u32 = 6;
const POSITIONS: [usize; 8] = [
    0,
    1,
    63,
    DEGREE / 4 - 1,
    DEGREE / 4,
    DEGREE / 2,
    DEGREE - 2,
    DEGREE - 1,
];

fn source_reader() -> impl XofReader {
    let mut hash = Shake256::default();
    hash.update(b"fhe-key-source-screen/1");
    hash.update(&[0x67; 64]);
    hash.finalize_xof()
}
fn ensure(condition: bool, message: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn encode_coefficient(value: &BigInt, width: usize) -> Vec<u8> {
    let (sign, magnitude) = value.to_bytes_le();
    assert!(magnitude.len() <= width);
    let mut bytes = vec![0; width + 1];
    bytes[0] = u8::from(sign == Sign::Minus);
    bytes[1..1 + magnitude.len()].copy_from_slice(&magnitude);
    bytes
}
struct Capture {
    profile: Profile,
    target: usize,
    count: usize,
    hash: Option<[u8; 64]>,
    samples: Vec<BigInt>,
}
impl Capture {
    fn new(profile: Profile, target: usize) -> Self {
        Self {
            profile,
            target,
            count: 0,
            hash: None,
            samples: Vec::new(),
        }
    }
}
impl PolynomialOutput for Capture {
    fn polynomial(&mut self, values: &[BigInt], modulus: &BigInt, width: usize) {
        if self.count == self.target {
            assert!(self.hash.is_none());
            assert_eq!(values.len(), DEGREE);
            assert_eq!(width, self.profile.family_magnitude_bytes(Family::Fhe));
            assert_eq!(
                modulus,
                &BigInt::from_bytes_le(Sign::Plus, &self.profile.ciphertext_modulus().to_bytes())
            );
            let mut hash = ProtocolHash::new();
            for value in values {
                hash.update(encode_coefficient(value, width));
            }
            self.hash = Some(hash.finalize());
            self.samples = POSITIONS
                .iter()
                .map(|position| values[*position].clone())
                .collect();
        }
        self.count += 1;
    }
}

pub struct Screen {
    profile: Profile,
    phase: u32,
    source: Option<FheKeySource>,
    contribution: Option<Contribution>,
    original: Option<Capture>,
    restored: Option<Capture>,
    report: Vec<u8>,
    pending: bool,
}
impl Default for Screen {
    fn default() -> Self {
        Self::new()
    }
}
impl Screen {
    pub fn new() -> Self {
        Self {
            profile: Profile::new(3, 2).unwrap(),
            phase: 1,
            source: None,
            contribution: None,
            original: None,
            restored: None,
            report: Vec::with_capacity(OUTPUT_BYTES),
            pending: false,
        }
    }
    pub fn phase(&self) -> u32 {
        self.phase
    }
    pub fn step(&mut self) -> io::Result<()> {
        match self.phase {
            1 => {
                self.source = Some(FheKeySource::from_reader(
                    self.profile,
                    &mut source_reader(),
                ))
            }
            2 => {
                let source = self
                    .source
                    .take()
                    .ok_or_else(|| io::Error::other("Missing original source"))?;
                let mut capture = Capture::new(self.profile, 0);
                source.public_coordinate(&mut capture);
                ensure(
                    capture.count == 1 && capture.hash.is_some(),
                    "Source public coordinate is incomplete",
                )?;
                self.original = Some(capture);
                // The original source and every complete public vector drop
                // here. Only public samples/hash survive to reconstruction.
            }
            3 => {
                let wrong = Profile::new(4, 2).unwrap();
                let source = FheKeySource::from_reader(self.profile, &mut source_reader());
                ensure(
                    matches!(
                        Contribution::from_source(wrong, source),
                        Err(crate::contribution::Error::SourceFamily)
                    ),
                    "Wrong family began contribution work",
                )?;
                let source = FheKeySource::from_reader(self.profile, &mut source_reader());
                self.contribution = Some(
                    Contribution::from_source(self.profile, source)
                        .map_err(|_| io::Error::other("Original source refused"))?,
                );
            }
            4 => {
                let mut contribution = self
                    .contribution
                    .take()
                    .ok_or_else(|| io::Error::other("Missing contribution"))?;
                let mut capture = Capture::new(self.profile, 1);
                contribution
                    .gadget(0, &mut capture)
                    .map_err(|_| io::Error::other("First gadget failed"))?;
                ensure(
                    capture.count == 7 && capture.hash.is_some(),
                    "First gadget output is incomplete",
                )?;
                let original = self
                    .original
                    .as_ref()
                    .ok_or_else(|| io::Error::other("Missing original public coordinate"))?;
                ensure(
                    capture.hash == original.hash && capture.samples == original.samples,
                    "Restored contribution changed b[0]",
                )?;
                self.restored = Some(capture);
                // No Contribution or proof witness survives this phase.
            }
            5 => {
                self.check_reference()?;
                self.write_report()?;
                self.phase = 12;
                return Ok(());
            }
            _ => return Err(io::Error::other("Source screen stage")),
        }
        self.phase += 1;
        Ok(())
    }
    fn check_reference(&self) -> io::Result<()> {
        // Independent direct negacyclic convolution at fixed boundary and
        // interior coefficients. This reference does not use source fields,
        // production sparse sampling, Products, Plan or limb reduction.
        let mut random = source_reader();
        let mut secret = Zeroizing::new(vec![0i8; DEGREE]);
        let mut filled = 0;
        while filled < FHE_SECRET_SUPPORT {
            let mut bytes = [0; 4];
            random.read(&mut bytes);
            let position = u32::from_le_bytes(bytes) as usize & (DEGREE - 1);
            if secret[position] != 0 {
                continue;
            }
            secret[position] = if filled < FHE_SECRET_SUPPORT / 2 {
                1
            } else {
                -1
            };
            filled += 1;
        }
        let common = common_polynomial(self.profile, self.profile.fhe_polynomial(0, 0))
            .map_err(|_| io::Error::other("Reference common polynomial"))?;
        let modulus =
            BigInt::from_bytes_le(Sign::Plus, &self.profile.ciphertext_modulus().to_bytes());
        let half = &modulus >> 1usize;
        let samples = &self
            .original
            .as_ref()
            .ok_or_else(|| io::Error::other("Missing source samples"))?
            .samples;
        for position in 0..DEGREE {
            let mut word = Zeroizing::new([0u8; 20]);
            random.read(word.as_mut());
            let error = gaussian::sample(&word);
            let Some(sample) = POSITIONS.iter().position(|value| *value == position) else {
                continue;
            };
            let mut expected = BigInt::from(error);
            for (index, coefficient) in secret.iter().enumerate() {
                match *coefficient {
                    0 => {}
                    sign => {
                        let (at, sign) = if index <= position {
                            (position - index, -sign)
                        } else {
                            (DEGREE + position - index, sign)
                        };
                        if sign > 0 {
                            expected += &common[at];
                        } else {
                            expected -= &common[at];
                        }
                    }
                }
            }
            expected = (expected % &modulus + &modulus) % &modulus;
            if expected > half {
                expected -= &modulus;
            }
            ensure(
                expected == samples[sample],
                "Independent source equation failed",
            )?;
        }
        Ok(())
    }
    fn write_report(&mut self) -> io::Result<()> {
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| io::Error::other("Missing original coordinate"))?;
        let restored = self
            .restored
            .as_ref()
            .ok_or_else(|| io::Error::other("Missing restored coordinate"))?;
        let width = self.profile.family_magnitude_bytes(Family::Fhe);
        self.report.extend_from_slice(b"FKS1");
        for value in [
            self.profile.participants(),
            self.profile.options(),
            DEGREE,
            width,
            self.profile.fhe_common_sample_bits(),
            POSITIONS.len(),
        ] {
            self.report.extend_from_slice(&(value as u32).to_le_bytes());
        }
        self.report.extend_from_slice(&original.hash.unwrap());
        self.report.extend_from_slice(&restored.hash.unwrap());
        for (position, value) in POSITIONS.iter().zip(&original.samples) {
            self.report
                .extend_from_slice(&(*position as u32).to_le_bytes());
            self.report
                .extend_from_slice(&encode_coefficient(value, width));
        }
        ensure(
            self.report.len() <= OUTPUT_BYTES,
            "Source report exceeds capacity",
        )
    }
    pub fn next_output(&mut self) -> io::Result<()> {
        ensure(self.phase == 12 && !self.pending, "Source output stage")?;
        if self.report.is_empty() {
            self.phase = 13;
            return Ok(());
        }
        self.pending = true;
        Ok(())
    }
    pub fn output(&self) -> &[u8] {
        if self.pending { &self.report } else { &[] }
    }
    pub fn acknowledge_output(&mut self) -> io::Result<()> {
        ensure(
            self.phase == 12 && self.pending,
            "Source output acknowledgement",
        )?;
        self.report.clear();
        self.pending = false;
        Ok(())
    }
}

thread_local! { static SESSION: RefCell<Option<Screen>> = const { RefCell::new(None) }; }
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_begin(case: u32) -> u32 {
    SESSION.with(|state| {
        let mut state = state.borrow_mut();
        if case != 0 || state.is_some() {
            return REFUSED;
        }
        *state = Some(Screen::new());
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_phase() -> u32 {
    SESSION.with(|state| state.borrow().as_ref().map_or(0, Screen::phase))
}
fn call(operation: fn(&mut Screen) -> io::Result<()>) -> u32 {
    SESSION.with(|state| {
        state.borrow_mut().as_mut().map_or(REFUSED, |screen| {
            if operation(screen).is_ok() {
                0
            } else {
                REFUSED
            }
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_step() -> u32 {
    call(Screen::step)
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_next_output() -> u32 {
    call(Screen::next_output)
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_ack_output() -> u32 {
    call(Screen::acknowledge_output)
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_output_pointer() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .as_ref()
            .map_or(0, |screen| screen.output().as_ptr() as usize)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_output_length() -> usize {
    SESSION.with(|state| {
        state
            .borrow()
            .as_ref()
            .map_or(0, |screen| screen.output().len())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn key_source_screen_output_capacity() -> usize {
    OUTPUT_BYTES
}

#[cfg(test)]
#[path = "fhe-key-source-screen-tests.rs"]
mod tests;
