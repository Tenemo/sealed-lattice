use crate::encryption::{LinkedBallotWitness, check_ballot_scores};
use num_bigint::Sign;
use setup_aggregate::{VerifiedAggregatePolynomial, setup_browser};
use std::cell::RefCell;

const CHUNK_BYTES: usize = 1_048_576;

pub fn take_witness() -> Option<LinkedBallotWitness> {
    SESSION.with(|session| {
        let mut session = session.borrow_mut();
        let witness = session.witness.take()?;
        session.context.fill(0);
        session.output.fill(0);
        session.used = 0;
        Some(witness)
    })
}
struct Session {
    input: [u8; 88],
    keys: [Option<VerifiedAggregatePolynomial>; 2],
    consumed: bool,
    witness: Option<LinkedBallotWitness>,
    context: [u8; 66],
    output: Vec<u8>,
    used: usize,
}
thread_local! { static SESSION: RefCell<Session> = RefCell::new(Session { input: [0;88], keys: [None,None], consumed: false, witness: None, context: [0;66], output: vec![0;CHUNK_BYTES], used: 0 }); }

#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_input_pointer() -> usize {
    SESSION.with(|value| value.borrow_mut().input.as_mut_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_capture_key() -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value.consumed {
            return 1;
        }
        let Some((_, setup)) = setup_browser::context() else {
            return 1;
        };
        let Some(key) = setup_browser::take_loaded_key() else {
            return 1;
        };
        if key.inventory() != &setup.inventory().identity() {
            return 1;
        }
        let index = match key.index() {
            1 => 0,
            74 => 1,
            _ => return 1,
        };
        if value.keys[index].is_some() {
            return 1;
        }
        value.keys[index] = Some(key);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_create(length: usize) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        if value.consumed || !(68..=88).contains(&length) || value.keys.iter().any(Option::is_none)
        {
            return 1;
        }
        let Some((poll, setup)) = setup_browser::context() else {
            return 1;
        };
        let position = u16::from_le_bytes(value.input[64..66].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(value.input[66..68].try_into().unwrap()) as usize;
        if value.input[..64] != setup.inventory().identity()
            || position >= setup.inventory().confirmations().len()
            || length != 68 + count
            || check_ballot_scores(&poll, &value.input[68..length]).is_err()
        {
            return 1;
        }
        if value
            .keys
            .iter()
            .flatten()
            .any(|key| key.inventory() != &setup.inventory().identity())
        {
            return 1;
        }
        let scores = zeroize::Zeroizing::new(value.input[68..length].to_vec());
        value.input.fill(0);
        let first = value.keys[0].take().unwrap();
        let second = value.keys[1].take().unwrap();
        value.consumed = true;
        let Ok(witness) =
            LinkedBallotWitness::create(poll, setup, first, second, position, &scores)
        else {
            return 1;
        };
        value.context[..64].copy_from_slice(witness.context.inventory());
        value.context[64..].copy_from_slice(&(witness.context.position() as u16).to_le_bytes());
        value.witness = Some(witness);
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_copy(
    family: usize,
    component: usize,
    offset: usize,
    length: usize,
) -> u32 {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        value.used = 0;
        let Session {
            witness,
            output,
            used,
            ..
        } = &mut *value;
        let Some(witness) = witness else {
            return 1;
        };
        let (encryption, width) = match family {
            0 => (&witness.fhe, 109),
            1 => (&witness.auxiliary, 6),
            _ => return 1,
        };
        let Some(component) = encryption.components.get(component) else {
            return 1;
        };
        let total = component.coefficients.len() * width;
        if length == 0
            || length > CHUNK_BYTES
            || !length.is_multiple_of(width)
            || !offset.is_multiple_of(width)
            || offset > total
            || length > total - offset
        {
            return 1;
        }
        output[..length].fill(0);
        for (position, value) in component.coefficients[offset / width..(offset + length) / width]
            .iter()
            .enumerate()
        {
            let (sign, magnitude) = value.to_bytes_le();
            if magnitude.len() >= width {
                return 1;
            }
            output[position * width] = u8::from(sign == Sign::Minus);
            output[position * width + 1..position * width + 1 + magnitude.len()]
                .copy_from_slice(&magnitude);
        }
        *used = length;
        0
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_output_pointer() -> usize {
    SESSION.with(|value| value.borrow().output.as_ptr() as usize)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_output_length() -> usize {
    SESSION.with(|value| value.borrow().used)
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_context_pointer() -> usize {
    SESSION.with(|value| {
        let value = value.borrow();
        if value.witness.is_some() {
            value.context.as_ptr() as usize
        } else {
            0
        }
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn ballot_encryption_clear() {
    SESSION.with(|value| {
        let mut value = value.borrow_mut();
        value.input.fill(0);
        value.output.fill(0);
        value.used = 0;
        value.keys = [None, None];
        value.witness = None;
        value.context.fill(0);
    });
}
