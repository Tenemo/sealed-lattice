use ballot_encryption::{
    encryption::{EncryptionWitness, LinkedBallotWitness},
    packing::PackingWitness,
};
use supported_profile::{
    AUXILIARY_DEGREE, DEGREE, Profile, SETUP_ERROR_BITS, WORD_BITS,
    relation::{BallotColumns, ballot_relation},
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct Error;
pub fn from_encryption(witness: &LinkedBallotWitness) -> Result<Zeroizing<Vec<Vec<u16>>>, Error> {
    from_parts(
        witness.context.profile(),
        &witness.packing,
        &witness.fhe,
        &witness.auxiliary,
    )
}
/// The ballot relation's witness columns: signed words offset by half their
/// range, narrow errors by half theirs, and the scores less one.
pub(crate) fn from_parts(
    profile: Profile,
    packing: &PackingWitness,
    fhe: &EncryptionWitness,
    auxiliary: &EncryptionWitness,
) -> Result<Zeroizing<Vec<Vec<u16>>>, Error> {
    let layout = BallotColumns::new(profile);
    let limbs = layout.fhe_limbs();
    let mut columns = Zeroizing::new(vec![vec![0; DEGREE]; ballot_relation(profile).columns()]);
    let word_offset = 1i32 << (WORD_BITS - 1);
    let error_offset = 1i16 << (SETUP_ERROR_BITS - 1);
    let signed_word = |value: i16| (i32::from(value) + word_offset) as u16;
    for (component, input) in fhe.components.iter().enumerate() {
        if input.quotients.len() != DEGREE
            || input.errors.len() != DEGREE
            || input.carries.len() != limbs - 1
            || input.carries.iter().any(|values| values.len() != DEGREE)
        {
            return Err(Error);
        }
        for position in 0..DEGREE {
            columns[layout.fhe_quotient(component)][position] =
                signed_word(input.quotients[position]);
            for carry in 0..limbs - 1 {
                columns[layout.fhe_carry(component, carry)][position] =
                    signed_word(input.carries[carry][position]);
            }
            columns[layout.fhe_error(component)][position] =
                (i16::from(input.errors[position]) + error_offset) as u16;
        }
    }
    if packing.message().len() != DEGREE
        || packing.quotients().len() != DEGREE
        || packing.scores().len() != profile.options()
        || fhe.ephemeral.len() != DEGREE
        || auxiliary.ephemeral.len() != AUXILIARY_DEGREE
    {
        return Err(Error);
    }
    // The packed plaintext offset by half a word takes a word and one high
    // bit.
    let word = 1i32 << WORD_BITS;
    for position in 0..DEGREE {
        let shifted = packing.message()[position] + word_offset;
        if !(0..=word).contains(&shifted) {
            return Err(Error);
        }
        columns[layout.plaintext()][position] = (shifted % word) as u16;
        columns[layout.plaintext_high_bit()][position] = (shifted / word) as u16;
        columns[layout.packing_quotient()][position] = signed_word(packing.quotients()[position]);
        columns[layout.fhe_positive()][position] = u16::from(fhe.ephemeral[position] == 1);
        columns[layout.fhe_positive() + 1][position] = u16::from(fhe.ephemeral[position] == -1);
    }
    for (position, score) in packing.scores().iter().enumerate() {
        columns[layout.scores()][position] = u16::from(*score) - 1;
    }
    let stride = DEGREE / AUXILIARY_DEGREE;
    for (component, input) in auxiliary.components.iter().enumerate() {
        if input.quotients.len() != AUXILIARY_DEGREE
            || input.errors.len() != AUXILIARY_DEGREE
            || !input.carries.is_empty()
        {
            return Err(Error);
        }
        for position in 0..AUXILIARY_DEGREE {
            columns[layout.auxiliary_quotient(component)][position * stride] =
                signed_word(input.quotients[position]);
            columns[layout.auxiliary_error(component)][position * stride] =
                (i16::from(input.errors[position]) + error_offset) as u16;
        }
    }
    for position in 0..AUXILIARY_DEGREE {
        columns[layout.auxiliary_positive()][position * stride] =
            u16::from(auxiliary.ephemeral[position] == 1);
        columns[layout.auxiliary_positive() + 1][position * stride] =
            u16::from(auxiliary.ephemeral[position] == -1);
    }
    Ok(columns)
}
