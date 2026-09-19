use crate::parameters::*;
use ballot_encryption::encryption::LinkedBallotWitness;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct Error;
pub fn from_encryption(witness: &LinkedBallotWitness) -> Result<Zeroizing<Vec<Vec<u16>>>, Error> {
    let mut columns = Zeroizing::new(vec![vec![0; SYSTEMATIC]; COLUMNS]);
    let signed_word = |value: i16| (i32::from(value) + 32768) as u16;
    for (component, input) in witness.fhe.components.iter().enumerate() {
        let offset = component * 10;
        if input.quotients.len() != SYSTEMATIC
            || input.errors.len() != SYSTEMATIC
            || input.carries.len() != 8
            || input
                .carries
                .iter()
                .any(|values| values.len() != SYSTEMATIC)
        {
            return Err(Error);
        }
        for position in 0..SYSTEMATIC {
            columns[offset][position] = signed_word(input.quotients[position]);
            for carry in 0..8 {
                columns[offset + 1 + carry][position] = signed_word(input.carries[carry][position]);
            }
            columns[offset + 9][position] = (i16::from(input.errors[position]) + 64) as u16;
        }
    }
    if witness.packing.message().len() != SYSTEMATIC
        || witness.packing.quotients().len() != SYSTEMATIC
        || witness.fhe.ephemeral.len() != SYSTEMATIC
        || witness.auxiliary.ephemeral.len() != 4096
    {
        return Err(Error);
    }
    for position in 0..SYSTEMATIC {
        let shifted = witness.packing.message()[position] + 32768;
        if !(0..=65536).contains(&shifted) {
            return Err(Error);
        }
        columns[20][position] = (shifted % 65536) as u16;
        columns[31][position] = (shifted / 65536) as u16;
        columns[21][position] = signed_word(witness.packing.quotients()[position]);
        columns[27][position] = u16::from(witness.fhe.ephemeral[position] == 1);
        columns[28][position] = u16::from(witness.fhe.ephemeral[position] == -1);
    }
    for (position, score) in witness.packing.scores().iter().enumerate() {
        columns[22][position] = u16::from(*score) - 1;
    }
    for (component, input) in witness.auxiliary.components.iter().enumerate() {
        if input.quotients.len() != 4096 || input.errors.len() != 4096 || !input.carries.is_empty()
        {
            return Err(Error);
        }
        for position in 0..4096 {
            columns[23 + component * 2][position * 16] = signed_word(input.quotients[position]);
            columns[24 + component * 2][position * 16] =
                (i16::from(input.errors[position]) + 64) as u16;
        }
    }
    for position in 0..4096 {
        columns[29][position * 16] = u16::from(witness.auxiliary.ephemeral[position] == 1);
        columns[30][position * 16] = u16::from(witness.auxiliary.ephemeral[position] == -1);
    }
    Ok(columns)
}
