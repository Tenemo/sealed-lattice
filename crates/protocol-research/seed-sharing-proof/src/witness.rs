use crate::{
    DEGREE, Error, RECIPIENTS, SCALE, SEED_BITS, SUPPORT, center, digit,
    layout::{Layout, STRIDE, variable},
    modulus, profile, rotation,
    statement::{Recipient, Scope, Statement, encoded_bytes, valid_polynomial},
};
use num_bigint::BigInt;
use supported_profile::relation::SYSTEMATIC;
use word_proof::oracles::Witness;

/// Explicit private inputs of the bounded relation. This experiment does
/// not sample or derive these values from the later-public opening seed.
pub struct Inputs {
    pub seed: Vec<u8>,
    pub sharing: Vec<i128>,
    pub ephemeral: Vec<Vec<i8>>,
    pub errors: Vec<[Vec<i128>; 2]>,
}
fn in_range(value: i128, bits: usize) -> bool {
    let radius = 1i128 << (bits - 1);
    (-radius..radius).contains(&value)
}
pub(crate) fn product(public: &[BigInt], sparse: &[i8]) -> Vec<BigInt> {
    let mut result = vec![BigInt::from(0); DEGREE];
    for (left, coefficient) in public.iter().enumerate() {
        for (right, &secret) in sparse.iter().enumerate() {
            let exponent = left + right;
            let sign = if exponent < DEGREE { 1 } else { -1 };
            result[exponent % DEGREE] += coefficient * (sign * i32::from(secret));
        }
    }
    result
}
fn write_signed(
    columns: &mut [Vec<u16>],
    layout: &Layout,
    variable: usize,
    values: &[i128],
) -> Result<(), Error> {
    let bits = layout.widths[variable];
    for (row, &value) in values.iter().enumerate() {
        if !in_range(value, bits) {
            return Err("Signed witness range");
        }
        let encoded = (value + (1i128 << (bits - 1))) as u128;
        for &(column, place) in &layout.signed[variable] {
            let mask = if column < layout.relation.words {
                65535
            } else {
                1
            };
            columns[column][row * STRIDE] = ((encoded / place) & mask) as u16;
        }
    }
    Ok(())
}
pub fn create(
    scope: Scope,
    common: Vec<BigInt>,
    public_keys: Vec<Vec<BigInt>>,
    input: Inputs,
) -> Result<(Statement, Witness), Error> {
    let profile = profile();
    if input.seed.len() != SEED_BITS
        || input.seed.iter().any(|bit| *bit > 1)
        || input.sharing.len() != DEGREE
        || input
            .sharing
            .iter()
            .any(|value| !in_range(*value, profile.sharing_coefficient_bits()))
        || input.ephemeral.len() != RECIPIENTS
        || input.errors.len() != RECIPIENTS
        || public_keys.len() != RECIPIENTS
        || usize::from(scope.author) >= RECIPIENTS
        || !valid_polynomial(&common)
        || public_keys.iter().any(|key| !valid_polynomial(key))
    {
        return Err("Private input shape");
    }
    for (ephemeral, errors) in input.ephemeral.iter().zip(&input.errors) {
        if ephemeral.len() != DEGREE
            || ephemeral.iter().any(|value| !(-1..=1).contains(value))
            || [-1, 1]
                .iter()
                .any(|sign| ephemeral.iter().filter(|value| *value == sign).count() != SUPPORT / 2)
            || errors.iter().any(|error| {
                error.len() != DEGREE || error.iter().any(|value| !in_range(*value, 7))
            })
        {
            return Err("Encryption input range");
        }
    }
    let layout = Layout::new(encoded_bytes());
    let mut columns = vec![vec![0; SYSTEMATIC]; layout.relation.columns()];
    let radix = 1i128 << profile.share_limb_bits();
    let low: Vec<_> = input
        .sharing
        .iter()
        .map(|value| value.rem_euclid(radix) - radix / 2)
        .collect();
    let high: Vec<_> = input
        .sharing
        .iter()
        .map(|value| value.div_euclid(radix))
        .collect();
    write_signed(&mut columns, &layout, 0, &low)?;
    write_signed(&mut columns, &layout, 1, &high)?;
    for (row, &bit) in input.seed.iter().enumerate() {
        columns[layout.seed][row * STRIDE] = u16::from(bit);
    }
    let modulus = modulus();
    let mut recipients = Vec::new();
    for (recipient, public_key) in public_keys.into_iter().enumerate() {
        let ephemeral = &input.ephemeral[recipient];
        let positive = layout.relation.words + 2 * recipient;
        for (row, &value) in ephemeral.iter().enumerate() {
            columns[positive][row * STRIDE] = u16::from(value == 1);
            columns[positive + 1][row * STRIDE] = u16::from(value == -1);
        }
        let share: Vec<i128> = (0..DEGREE)
            .map(|row| {
                let (source, sign) = rotation(recipient, row);
                sign * input.sharing[source] + i128::from(input.seed.get(row).copied().unwrap_or(0))
            })
            .collect();
        let mut ciphertext = [Vec::new(), Vec::new()];
        for (component, public) in [&public_key, &common].into_iter().enumerate() {
            let multiplied = product(public, ephemeral);
            let error = &input.errors[recipient][component];
            let raw: Vec<BigInt> = (0..DEGREE)
                .map(|row| {
                    &multiplied[row]
                        + error[row]
                        + if component == 0 {
                            BigInt::from(SCALE) * share[row]
                        } else {
                            BigInt::from(0)
                        }
                })
                .collect();
            ciphertext[component] = raw.iter().cloned().map(center).collect();
            let quotients: Vec<i128> = raw
                .iter()
                .zip(&ciphertext[component])
                .map(|(raw, encrypted)| {
                    i128::try_from((raw - encrypted) / &modulus).map_err(|_| "Quotient overflow")
                })
                .collect::<Result<_, _>>()?;
            let public_low: Vec<_> = public
                .iter()
                .map(|value| BigInt::from(digit(value, 0)))
                .collect();
            let products_low = product(&public_low, ephemeral);
            let mut carries = Vec::with_capacity(DEGREE);
            for row in 0..DEGREE {
                let (source, sign) = rotation(recipient, row);
                let shared = if component == 0 {
                    SCALE
                        * (sign * low[source]
                            + i128::from(input.seed.get(row).copied().unwrap_or(0)))
                        + digit(&BigInt::from(sign * SCALE * (radix / 2)), 0)
                } else {
                    0
                };
                let residual = &products_low[row] - digit(&ciphertext[component][row], 0)
                    + shared
                    + error[row]
                    - BigInt::from(digit(&modulus, 0)) * quotients[row];
                if &residual % radix != BigInt::from(0) {
                    return Err("Nonintegral carry");
                }
                carries.push(i128::try_from(residual / radix).map_err(|_| "Carry overflow")?);
            }
            write_signed(
                &mut columns,
                &layout,
                variable(recipient, component, 0),
                &quotients,
            )?;
            write_signed(
                &mut columns,
                &layout,
                variable(recipient, component, 1),
                &carries,
            )?;
            write_signed(
                &mut columns,
                &layout,
                variable(recipient, component, 2),
                error,
            )?;
        }
        recipients.push(Recipient {
            public_key,
            ciphertext,
        });
    }
    let statement = Statement {
        scope,
        common,
        recipients,
    };
    let witness = Witness::from_columns(&layout.relation, statement.digest()?, columns)?;
    Ok((statement, witness))
}
