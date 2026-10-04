use crate::{
    DEGREE, Error, SUPPORT, center, digit,
    layout::{Layout, STRIDE},
    modulus,
    statement::{Statement, encoded_bytes},
};
use num_bigint::BigInt;
use supported_profile::relation::SYSTEMATIC;
use word_proof::oracles::Witness;
use zeroize::Zeroizing;

pub(crate) fn product(public: &[BigInt], secret: &[i8]) -> Vec<BigInt> {
    let mut output = vec![BigInt::from(0); DEGREE];
    for (left, value) in public.iter().enumerate() {
        for (right, &coefficient) in secret.iter().enumerate() {
            let position = left + right;
            output[position % DEGREE] +=
                value * (i32::from(coefficient) * if position < DEGREE { 1 } else { -1 });
        }
    }
    output
}
fn write_signed(
    columns: &mut [Vec<u16>],
    layout: &Layout,
    variable: usize,
    values: &[i128],
) -> Result<(), Error> {
    let radius = 1i128 << (layout.widths[variable] - 1);
    for (row, &value) in values.iter().enumerate() {
        if !(-radius..radius).contains(&value) {
            return Err("Opening witness range");
        }
        let encoded = (value + radius) as u128;
        for &(column, place) in &layout.signed[variable] {
            columns[column][row * STRIDE] = ((encoded / place)
                & if column < layout.relation.words {
                    65535
                } else {
                    1
                }) as u16;
        }
    }
    Ok(())
}

/// Proves already supplied public shares for the exact predecessor-bound
/// statement. It does not accept an arbitrary ciphertext for decryption.
pub fn create(statement: &Statement, secret: &[i8]) -> Result<Witness, Error> {
    statement.encode()?;
    if secret.len() != DEGREE
        || secret.iter().any(|value| !(-1..=1).contains(value))
        || [-1, 1]
            .iter()
            .any(|sign| secret.iter().filter(|value| *value == sign).count() != SUPPORT / 2)
    {
        return Err("Original recipient secret shape");
    }
    let layout = Layout::new(encoded_bytes());
    let mut columns = Zeroizing::new(vec![vec![0; SYSTEMATIC]; layout.relation.columns()]);
    for (row, &value) in secret.iter().enumerate() {
        columns[layout.relation.words][row * STRIDE] = u16::from(value == 1);
        columns[layout.relation.words + 1][row * STRIDE] = u16::from(value == -1);
    }
    let modulus = modulus();
    let radix = 1i128 << crate::LIMB_BITS;
    for (equation, (constant, linear)) in statement.equations().enumerate() {
        let products = product(linear, secret);
        let raw: Vec<_> = products
            .iter()
            .zip(&constant)
            .map(|(left, right)| left + right)
            .collect();
        let errors: Vec<i128> = raw
            .iter()
            .cloned()
            .map(|value| i128::try_from(center(value)).map_err(|_| "Opening error overflow"))
            .collect::<Result<_, _>>()?;
        let quotients: Vec<i128> = raw
            .iter()
            .zip(&errors)
            .map(|(value, error)| {
                i128::try_from((value - error) / &modulus).map_err(|_| "Opening quotient overflow")
            })
            .collect::<Result<_, _>>()?;
        let low: Vec<_> = linear
            .iter()
            .map(|value| BigInt::from(digit(value, 0)))
            .collect();
        let low_products = product(&low, secret);
        let mut carries = Vec::with_capacity(DEGREE);
        for row in 0..DEGREE {
            let residual = &low_products[row] + digit(&constant[row], 0)
                - errors[row]
                - BigInt::from(digit(&modulus, 0)) * quotients[row];
            if &residual % radix != BigInt::from(0) {
                return Err("Nonintegral opening carry");
            }
            carries.push(i128::try_from(residual / radix).map_err(|_| "Opening carry overflow")?);
        }
        for (offset, values) in [&quotients, &carries, &errors].into_iter().enumerate() {
            write_signed(&mut columns, &layout, 3 * equation + offset, values)?;
        }
    }
    Witness::from_columns(
        &layout.relation,
        statement.digest()?,
        std::mem::take(&mut *columns),
    )
}
