use super::{DEGREE, MAXIMUM_INSTRUCTIONS, Refusal};
use protocol_foundations::identity::identity;
use std::collections::BTreeSet;
use supported_profile::Profile;

const RANKING_PROGRAM_DOMAIN: &str = "sealed-lattice/ranking-program/v1";
pub fn program_identity(program: &[u8]) -> Result<[u8; 64], Refusal> {
    identity(RANKING_PROGRAM_DOMAIN, program).map_err(|_| Refusal::Program)
}
#[derive(Clone, Debug)]
pub struct Instruction {
    pub operation: u32,
    pub inputs: Vec<usize>,
    pub parameter: u32,
}
pub(super) struct Program {
    pub(super) program_hash: [u8; 64],
    pub(super) instructions: Vec<Instruction>,
    pub(super) remaining_uses: Vec<usize>,
    pub(super) top_count: usize,
}
fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}
pub(super) fn decode_program(profile: Profile, program: &[u8]) -> Result<Program, Refusal> {
    if program.len() < 16 || &program[..4] != b"BRK1" || word(&program[4..8]) != DEGREE as u32 {
        return Err(Refusal::Program);
    }
    let count = word(&program[8..12]) as usize;
    if !(1..=MAXIMUM_INSTRUCTIONS).contains(&count)
        || program.len() != 16 + 16 * count
        || word(&program[12..16]) as usize != count - 1
    {
        return Err(Refusal::Program);
    }
    let program_hash = program_identity(program)?;
    let options = profile.options();
    let comparison_degree = profile.comparison_degree();
    let mut instructions = Vec::with_capacity(count);
    let mut input_positions = BTreeSet::new();
    let mut remaining_uses = vec![0; count];
    let mut top_count = None;
    for (index, bytes) in program[16..].chunks_exact(16).enumerate() {
        let operation = word(&bytes[..4]);
        let arity = match operation {
            0 => 0,
            1 | 2 => 2,
            3..=6 => 1,
            _ => return Err(Refusal::Program),
        };
        let candidates = [word(&bytes[4..8]), word(&bytes[8..12])];
        let mut inputs = Vec::with_capacity(arity);
        for (position, value) in candidates.into_iter().enumerate() {
            if position < arity {
                if value as usize >= index {
                    return Err(Refusal::Program);
                }
                inputs.push(value as usize);
                remaining_uses[value as usize] += 1;
            } else if value != u32::MAX {
                return Err(Refusal::Program);
            }
        }
        let parameter = word(&bytes[12..]);
        let valid = match operation {
            0 => (parameter as usize) < profile.participants() && input_positions.insert(parameter),
            1 | 2 | 6 => parameter == 0,
            3 => (1..=comparison_degree).contains(&(parameter as usize)) && parameter % 2 == 1,
            4 => {
                (parameter as usize) < options * options
                    && !(parameter as usize).is_multiple_of(options)
            }
            5 => (parameter as usize) < options + 2,
            _ => false,
        };
        if !valid {
            return Err(Refusal::Program);
        }
        // Rank weights of family zero give the complete ordering; family
        // k gives the first k ranks.
        let declared_top_count = match operation {
            4 => Some(match parameter as usize / options {
                0 => options,
                value => value,
            }),
            5 if parameter >= 2 => Some(match parameter {
                2 => options,
                value => value as usize - 2,
            }),
            _ => None,
        };
        if let Some(declared) = declared_top_count {
            if top_count.is_some_and(|existing| existing != declared) {
                return Err(Refusal::Program);
            }
            top_count = Some(declared);
        }
        instructions.push(Instruction {
            operation,
            inputs,
            parameter,
        });
    }
    if input_positions.len() != profile.participants() || remaining_uses[..count - 1].contains(&0) {
        return Err(Refusal::Program);
    }
    remaining_uses[count - 1] = 1;

    Ok(Program {
        program_hash,
        instructions,
        remaining_uses,
        top_count: top_count.unwrap_or(options),
    })
}
/// The most values a program holds at once when each stays from its
/// instruction until its last use, given each value's count of uses.
pub(super) fn peak_values(instructions: &[Instruction], mut remaining_uses: Vec<usize>) -> usize {
    let (mut held, mut peak) = (0usize, 0usize);
    for instruction in instructions {
        held += 1;
        peak = peak.max(held);
        for input in &instruction.inputs {
            remaining_uses[*input] -= 1;
            if remaining_uses[*input] == 0 {
                held -= 1;
            }
        }
    }
    peak
}
