use super::*;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;
use parallel_work::ProtocolHash;

// Every size of the profile over sixteen-coefficient rings.
fn reduced(profile: Profile) -> Layout {
    Layout {
        profile,
        degree: 16,
        fhe_half_support: 2,
        share_half_support: 2,
    }
}

struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn signed(&mut self, bits: usize) -> i128 {
        let value =
            ((u128::from(self.next()) << 64) | u128::from(self.next())) & ((1u128 << bits) - 1);
        value as i128 - (1i128 << (bits - 1))
    }
    fn sparse(&mut self, degree: usize, half_support: usize) -> Vec<i8> {
        let mut values = vec![0; degree];
        let mut placed = 0;
        while placed < 2 * half_support {
            let position = self.next() as usize % degree;
            if values[position] == 0 {
                values[position] = if placed < half_support { 1 } else { -1 };
                placed += 1;
            }
        }
        values
    }
    // Canonical coefficients of magnitude at most a quarter of the modulus.
    fn polynomial(&mut self, degree: usize, modulus: &BigInt) -> Vec<BigInt> {
        let quarter = (modulus >> 2usize).to_bytes_le().1;
        (0..degree)
            .map(|_| {
                let bytes: Vec<u8> = quarter
                    .iter()
                    .map(|byte| byte & self.next() as u8)
                    .collect();
                let magnitude = BigInt::from_bytes_le(Sign::Plus, &bytes);
                if self.next() & 1 == 1 {
                    -magnitude
                } else {
                    magnitude
                }
            })
            .collect()
    }
}

fn integer(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, bytes)
}
fn digit(value: &BigInt, limb: usize, radix_bits: usize) -> BigInt {
    let mask = (BigUint::from(1u8) << radix_bits) - 1u8;
    let magnitude = BigInt::from_biguint(
        Sign::Plus,
        (value.magnitude() >> (radix_bits * limb)) & mask,
    );
    if value.sign() == Sign::Minus {
        -magnitude
    } else {
        magnitude
    }
}
// The representative of a residue in (-q/2, q/2) and the multiple of q
// removed to reach it.
fn centered(value: &BigInt, modulus: &BigInt) -> (BigInt, BigInt) {
    let mut residue = value % modulus;
    if residue.sign() == Sign::Minus {
        residue += modulus;
    }
    if &residue + &residue > *modulus {
        residue -= modulus;
    }
    let multiple = (value - &residue) / modulus;
    (residue, multiple)
}
// Multiplication by X^shift modulo X^degree + 1.
fn rotate(values: &[BigInt], shift: usize) -> Vec<BigInt> {
    let degree = values.len();
    let mut result = vec![BigInt::from(0); degree];
    for (input, value) in values.iter().enumerate() {
        let exponent = (input + shift) % (2 * degree);
        if exponent < degree {
            result[exponent] += value;
        } else {
            result[exponent - degree] -= value;
        }
    }
    result
}
fn product(common: &[BigInt], sparse: &[i8]) -> Vec<BigInt> {
    let mut result = vec![BigInt::from(0); common.len()];
    for (shift, value) in sparse.iter().enumerate() {
        for (position, term) in rotate(common, shift).into_iter().enumerate() {
            result[position] += term * BigInt::from(*value);
        }
    }
    result
}
fn automorphism(values: &[i8], power: usize) -> Vec<BigInt> {
    let degree = values.len();
    let mut result = vec![BigInt::from(0); degree];
    for (position, value) in values.iter().enumerate() {
        let exponent = (position * power) % (2 * degree);
        let value = BigInt::from(*value);
        result[exponent % degree] = if exponent < degree { value } else { -value };
    }
    result
}
fn signed_integers(values: &[i128]) -> Vec<BigInt> {
    values.iter().map(|value| BigInt::from(*value)).collect()
}

#[derive(Clone, Default)]
struct Witness {
    words: Vec<Vec<i128>>,
    booleans: Vec<Vec<i128>>,
    narrow_words: Vec<(usize, usize)>,
}
impl Witness {
    fn sparse(&mut self, values: &[i8]) {
        for sign in [1, -1] {
            self.booleans.push(
                values
                    .iter()
                    .map(|value| i128::from(*value == sign))
                    .collect(),
            );
        }
    }
    // Words from the low end, then one Boolean per remaining bit.
    fn signed(&mut self, width: usize, values: &[BigInt]) {
        let offset = 1i128 << (width - 1);
        let shifted: Vec<u128> = values
            .iter()
            .map(|value| {
                let value = value.to_i128().unwrap();
                assert!(
                    -offset <= value && value < offset,
                    "{value} exceeds {width} bits"
                );
                (value + offset) as u128
            })
            .collect();
        let mut remaining = width;
        let mut shift = 0;
        while remaining >= 16 || shift == 0 {
            let bits = remaining.min(16);
            if bits < 16 {
                self.narrow_words.push((self.words.len(), bits));
            }
            self.words.push(
                shifted
                    .iter()
                    .map(|value| ((value >> shift) & ((1 << bits) - 1)) as i128)
                    .collect(),
            );
            remaining -= bits;
            shift += bits;
        }
        for bit in 0..remaining {
            self.booleans.push(
                shifted
                    .iter()
                    .map(|value| ((value >> (shift + bit)) & 1) as i128)
                    .collect(),
            );
        }
    }
    fn columns(&self) -> Vec<Vec<i128>> {
        self.words.iter().chain(&self.booleans).cloned().collect()
    }
}

struct KeyEquation<'a> {
    common: &'a [BigInt],
    left: &'a [i8],
    direct: Vec<BigInt>,
    multiplier: BigInt,
    modulus: &'a BigInt,
    limbs: usize,
}
// common * left + value - multiplier * direct - error - modulus * quotient
// = 0 in 96-bit limbs, and the key value it defines.
fn key_equation(
    witness: &mut Witness,
    random: &mut Random,
    equation: KeyEquation<'_>,
) -> Vec<BigInt> {
    let KeyEquation {
        common,
        left,
        direct,
        multiplier,
        modulus,
        limbs,
    } = equation;
    let degree = common.len();
    let exact = product(common, left);
    let digits: Vec<Vec<BigInt>> = (0..limbs)
        .map(|limb| {
            let digits: Vec<BigInt> = common
                .iter()
                .map(|value| digit(value, limb, FHE_LIMB_BITS))
                .collect();
            product(&digits, left)
        })
        .collect();
    let errors: Vec<i128> = (0..degree)
        .map(|_| random.signed(SETUP_ERROR_BITS))
        .collect();
    let mut values = Vec::new();
    let mut quotients = Vec::new();
    let mut carries = vec![Vec::new(); limbs - 1];
    for position in 0..degree {
        let error = BigInt::from(errors[position]);
        let (value, multiple) = centered(
            &(&multiplier * &direct[position] - &exact[position] + &error),
            modulus,
        );
        let quotient = -multiple;
        let mut carry = BigInt::from(0);
        for limb in 0..limbs {
            let mut row = &digits[limb][position] + digit(&value, limb, FHE_LIMB_BITS)
                - digit(&multiplier, limb, FHE_LIMB_BITS) * &direct[position]
                - digit(modulus, limb, FHE_LIMB_BITS) * &quotient
                + &carry;
            if limb == 0 {
                row -= &error;
            }
            if limb + 1 < limbs {
                assert_eq!(&row % (BigInt::from(1) << FHE_LIMB_BITS), BigInt::from(0));
                carry = row >> FHE_LIMB_BITS;
                carries[limb].push(carry.clone());
            } else {
                assert_eq!(row, BigInt::from(0));
            }
        }
        quotients.push(quotient);
        values.push(value);
    }
    witness.signed(SETUP_QUOTIENT_BITS, &quotients);
    for carry in &carries {
        witness.signed(SETUP_FHE_CARRY_BITS, carry);
    }
    witness.signed(SETUP_ERROR_BITS, &signed_integers(&errors));
    values
}

#[derive(Clone, Copy)]
struct Message<'a> {
    secret: &'a [i8],
    sharing: &'a [Vec<i128>],
    point: usize,
}
// common * ephemeral - value + scale * message + error - modulus * quotient
// = 0 in share limbs, where the message is the FHE secret plus each
// sharing coefficient c_i times Z^(a * (i + 1)), and c_i = low + 2^L high
// + 2^(L - 1).
fn share_equation(
    witness: &mut Witness,
    random: &mut Random,
    profile: Profile,
    common: &[BigInt],
    ephemeral: &[i8],
    message: Option<Message<'_>>,
) -> Vec<BigInt> {
    let degree = common.len();
    let limb = profile.share_limb_bits();
    let modulus = integer(share_modulus());
    let exact = product(common, ephemeral);
    let digits: Vec<Vec<BigInt>> = (0..2)
        .map(|index| {
            let digits: Vec<BigInt> = common
                .iter()
                .map(|value| digit(value, index, limb))
                .collect();
            product(&digits, ephemeral)
        })
        .collect();
    let scale = BigInt::from(SHARE_SCALE);
    let zero = vec![BigInt::from(0); degree];
    let (mut total, mut low, mut high, mut offset) =
        (zero.clone(), zero.clone(), zero.clone(), zero);
    if let Some(Message {
        secret,
        sharing,
        point,
    }) = message
    {
        for (position, value) in secret.iter().enumerate() {
            total[position] += BigInt::from(*value);
            low[position] += BigInt::from(*value);
        }
        for (index, coefficient) in sharing.iter().enumerate() {
            let shift = point * (index + 1);
            let parts = |part: &dyn Fn(i128) -> i128| {
                rotate(
                    &signed_integers(
                        &coefficient
                            .iter()
                            .map(|value| part(*value))
                            .collect::<Vec<_>>(),
                    ),
                    shift,
                )
            };
            let rotated = [
                parts(&|value| value),
                parts(&|value| value.rem_euclid(1 << limb) - (1 << (limb - 1))),
                parts(&|value| value.div_euclid(1 << limb)),
                parts(&|_| 1 << (limb - 1)),
            ];
            for position in 0..degree {
                total[position] += &rotated[0][position];
                low[position] += &rotated[1][position];
                high[position] += &rotated[2][position];
                offset[position] += &scale * &rotated[3][position];
            }
        }
    }
    let errors: Vec<i128> = (0..degree)
        .map(|_| random.signed(SETUP_ERROR_BITS))
        .collect();
    let radix = BigInt::from(1) << limb;
    let mut values = Vec::new();
    let mut quotients = Vec::new();
    let mut carries = Vec::new();
    for position in 0..degree {
        let error = BigInt::from(errors[position]);
        let (value, quotient) = centered(
            &(&exact[position] + &error + &scale * &total[position]),
            &modulus,
        );
        let row = &digits[0][position] - digit(&value, 0, limb)
            + digit(&offset[position], 0, limb)
            + &scale * &low[position]
            + &error
            - digit(&modulus, 0, limb) * &quotient;
        assert_eq!(&row % &radix, BigInt::from(0));
        let carry = row / &radix;
        let row = &digits[1][position] - digit(&value, 1, limb)
            + digit(&offset[position], 1, limb)
            + &scale * &high[position]
            - digit(&modulus, 1, limb) * &quotient
            + &carry;
        assert_eq!(row, BigInt::from(0));
        carries.push(carry);
        quotients.push(quotient);
        values.push(value);
    }
    witness.signed(SETUP_QUOTIENT_BITS, &quotients);
    witness.signed(
        if message.is_some() {
            profile.share_carry_bits()
        } else {
            SETUP_FHE_CARRY_BITS
        },
        &carries,
    );
    witness.signed(SETUP_ERROR_BITS, &signed_integers(&errors));
    values
}

fn encode(values: &[BigInt], width: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        let (sign, magnitude) = value.to_bytes_le();
        assert!(magnitude.len() <= width);
        bytes.push(u8::from(sign == Sign::Minus));
        bytes.extend(&magnitude);
        bytes.resize(bytes.len() + width - magnitude.len(), 0);
    }
    bytes
}

// A satisfying assignment of the integer setup equations, built from the
// equations rather than from the operator, and the statement it binds.
fn satisfying_relation(layout: Layout, random: &mut Random) -> (Vec<u8>, Witness) {
    let profile = layout.profile;
    let degree = layout.degree;
    let fhe = integer(&profile.family_modulus(Family::Fhe));
    let share = integer(share_modulus());
    let mut witness = Witness::default();
    let mut polynomials = vec![Vec::new(); profile.setup_polynomials()];
    let secret = random.sparse(degree, layout.fhe_half_support);
    let auxiliary = random.sparse(degree, layout.fhe_half_support);
    let ephemerals: Vec<Vec<i8>> = (0..profile.participants())
        .map(|_| random.sparse(degree, layout.share_half_support))
        .collect();
    for values in [&secret, &auxiliary].into_iter().chain(&ephemerals) {
        witness.sparse(values);
    }
    let limb = profile.share_limb_bits();
    let bits = profile.sharing_coefficient_bits();
    let sharing: Vec<Vec<i128>> = (0..profile.sharing_degree())
        .map(|_| (0..degree).map(|_| random.signed(bits)).collect())
        .collect();
    for coefficient in &sharing {
        let low: Vec<i128> = coefficient
            .iter()
            .map(|value| value.rem_euclid(1 << limb) - (1 << (limb - 1)))
            .collect();
        let high: Vec<i128> = coefficient
            .iter()
            .map(|value| value.div_euclid(1 << limb))
            .collect();
        witness.signed(limb, &signed_integers(&low));
        witness.signed(bits - limb, &signed_integers(&high));
    }
    for gadget in 0..profile.gadget_length() {
        let power = BigInt::from(1) << (Profile::gadget_base_bits() * gadget);
        let first = profile.fhe_polynomial(gadget, 0);
        for component in [0, 3, 5] {
            polynomials[first + component] = random.polynomial(degree, &fhe);
        }
        let keys = [
            (0, &secret, automorphism(&auxiliary, 1), BigInt::from(0)),
            (0, &auxiliary, automorphism(&secret, 1), power.clone()),
            (3, &secret, automorphism(&auxiliary, 1), -power.clone()),
            (5, &secret, automorphism(&secret, 5), power),
        ];
        for (index, (common, left, direct, multiplier)) in keys.into_iter().enumerate() {
            let value = key_equation(
                &mut witness,
                random,
                KeyEquation {
                    common: &polynomials[first + common].clone(),
                    left,
                    direct,
                    multiplier,
                    modulus: &fhe,
                    limbs: profile.fhe_limbs(),
                },
            );
            polynomials[first + [1, 2, 4, 6][index]] = value;
        }
    }
    let stride = degree / profile.interpolation_degree();
    polynomials[profile.share_common_polynomial()] = random.polynomial(degree, &share);
    for (recipient, ephemeral) in ephemerals.iter().enumerate() {
        let key = random.polynomial(degree, &share);
        polynomials[profile.share_constant_polynomial(recipient)] = share_equation(
            &mut witness,
            random,
            profile,
            &key,
            ephemeral,
            Some(Message {
                secret: &secret,
                sharing: &sharing,
                point: recipient * stride,
            }),
        );
        polynomials[profile.recipient_key_polynomial(recipient)] = key;
        polynomials[profile.share_linear_polynomial(recipient)] = share_equation(
            &mut witness,
            random,
            profile,
            &polynomials[profile.share_common_polynomial()].clone(),
            ephemeral,
            None,
        );
    }
    let shape = profile.setup_shape();
    assert_eq!(witness.words.len(), shape.word_columns);
    assert_eq!(witness.booleans.len(), shape.boolean_columns);
    assert_eq!(witness.narrow_words, shape.narrow_words);
    let mut statement = layout.header();
    for (index, polynomial) in polynomials.iter().enumerate() {
        let (family, degree) = layout.polynomial(index).unwrap();
        assert_eq!(polynomial.len(), degree);
        statement.extend(encode(polynomial, profile.family_magnitude_bytes(family)));
    }
    assert_eq!(statement.len(), layout.encoded_length());
    (statement, witness)
}

fn geometric(alpha: Element, term: &ProverFixedTerm) -> Vec<Element> {
    (0..term.degree)
        .map(|position| {
            if term.constant {
                return ONE;
            }
            let exponent = (position * term.automorphism + term.shift) % (2 * term.degree);
            let value = power(alpha, exponent % term.degree);
            if exponent < term.degree {
                value
            } else {
                minus(ZERO, value)
            }
        })
        .collect()
}
fn add_scaled(total: &mut Vec<Element>, values: &[Element], weight: Element) {
    if total.is_empty() {
        *total = vec![ZERO; values.len()];
    }
    assert_eq!(total.len(), values.len());
    for (entry, value) in total.iter_mut().zip(values) {
        *entry = plus(*entry, times(weight, *value));
    }
}
// Each witness column's coefficients over the ring positions, and the
// target, for one statement.
fn systematic_operator(
    layout: Layout,
    alpha: Element,
    statement: &[u8],
) -> (Vec<Vec<Element>>, Element) {
    let profile = layout.profile;
    let shape = profile.setup_shape();
    let mut accumulator = Accumulator::build(layout, alpha, &[], true).unwrap();
    let mut columns = vec![Vec::new(); shape.word_columns + shape.boolean_columns];
    for term in accumulator.recorded_terms.take().unwrap() {
        let geometry = geometric(alpha, &term);
        for (column, weight) in &term.columns {
            add_scaled(&mut columns[*column], &geometry, *weight);
        }
    }
    let mut target = accumulator.target;
    let mut offset = layout.header().len();
    for index in 0..profile.setup_polynomials() {
        let (family, degree) = layout.polynomial(index).unwrap();
        let length = degree * (1 + profile.family_magnitude_bytes(family));
        let mut parser = family_stream(profile, family, degree, alpha).unwrap();
        parser.push(&statement[offset..offset + length]).unwrap();
        offset += length;
        if accumulator.is_common(index) {
            let adjoint = parser.adjoint().unwrap();
            for usage in &accumulator.uses[index] {
                let PublicUse::Common(variable, weight) = usage else {
                    panic!("mixed public use");
                };
                for (column, factor) in &variable.terms {
                    add_scaled(
                        &mut columns[*column],
                        &adjoint,
                        scale(*weight, base(*factor)),
                    );
                }
            }
        } else {
            let value = parser.finish_value().unwrap();
            for usage in &accumulator.uses[index] {
                let PublicUse::Value(weight) = usage else {
                    panic!("mixed public use");
                };
                target = minus(target, times(*weight, value));
            }
        }
    }
    (columns, target)
}
fn apply(columns: &[Vec<Element>], witness: &[Vec<i128>]) -> Element {
    assert_eq!(columns.len(), witness.len());
    let mut total = ZERO;
    for (coefficients, values) in columns.iter().zip(witness) {
        assert_eq!(coefficients.len(), values.len());
        for (coefficient, value) in coefficients.iter().zip(values) {
            total = plus(total, scale(*coefficient, base(*value)));
        }
    }
    total
}
fn stream(
    layout: Layout,
    bytes: &[u8],
    digest: [u8; 64],
    indices: &[u32],
) -> Result<StatementOutput, Error> {
    let mut stream = SetupStatementStream::with_layout(layout, digest, [17, 37, 91], indices)?;
    for part in bytes.chunks(107) {
        stream.push(part)?;
    }
    stream.finish()
}
// Flips the low magnitude bit of a polynomial's first coefficient.
fn change_polynomial(layout: Layout, statement: &mut [u8], polynomial: usize) {
    let offset = layout.header().len()
        + (0..polynomial)
            .map(|index| {
                let (family, degree) = layout.polynomial(index).unwrap();
                degree * (1 + layout.profile.family_magnitude_bytes(family))
            })
            .sum::<usize>();
    statement[offset + 1] ^= 1;
}

#[test]
fn satisfying_integer_witnesses_meet_the_operator_of_every_profile() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let alpha = [17, 37, 91];
    let indices = [0, 3, 17, 63];
    for profile in Profile::all() {
        let label = format!(
            "{} participants, {} options",
            profile.participants(),
            profile.options()
        );
        let layout = reduced(profile);
        let (statement, witness) = satisfying_relation(layout, &mut random);
        let columns = witness.columns();
        let (operator, target) = systematic_operator(layout, alpha, &statement);
        assert_eq!(apply(&operator, &columns), target, "{label}");
        // The verifier's query coefficients encode the same operator.
        let digest: [u8; 64] = ProtocolHash::digest(&statement);
        let output = stream(layout, &statement, digest, &indices).unwrap();
        assert_eq!(output.target, target, "{label}");
        for (column, coefficients) in operator.iter().enumerate() {
            assert_eq!(
                query::evaluate_in(coefficients.clone(), &indices, layout.degree).unwrap(),
                output.coefficients[column * indices.len()..(column + 1) * indices.len()],
                "{label} column {column}"
            );
        }
        // A changed error word or public value no longer meets it.
        let mut changed = columns.clone();
        changed[profile.setup_shape().word_columns - 1][0] ^= 1;
        assert_ne!(apply(&operator, &changed), target, "{label}");
        for polynomial in [
            profile.fhe_polynomial(0, 0),
            profile.share_linear_polynomial(profile.participants() - 1),
        ] {
            let mut changed = statement.clone();
            change_polynomial(layout, &mut changed, polynomial);
            let (operator, target) = systematic_operator(layout, alpha, &changed);
            assert_ne!(apply(&operator, &columns), target, "{label}");
        }
    }
}

#[test]
fn full_layouts_encode_the_profile_statement() {
    for profile in Profile::all() {
        let layout = Layout::full(profile);
        assert_eq!(layout.header(), profile.setup_statement_header());
        assert_eq!(layout.encoded_length(), profile.setup_statement_length());
    }
}

#[test]
fn both_relinearization_equations_keep_the_original_full_ring_auxiliary() {
    let mut random = Random(0x082e_fa98_ec4e_6c89);
    let alpha = [17, 37, 91];
    for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
        let layout = reduced(Profile::new(participants, options).unwrap());
        let (statement, witness) = satisfying_relation(layout, &mut random);
        let columns = witness.columns();
        let (operator, target) = systematic_operator(layout, alpha, &statement);
        assert_eq!(apply(&operator, &columns), target);

        // Move one positive r coefficient to an empty position. Every
        // Boolean, disjointness and support predicate stays satisfied.
        let positive = layout.profile.setup_shape().word_columns + 2;
        let selected = columns[positive]
            .iter()
            .position(|value| *value == 1)
            .unwrap();
        let empty = (0..layout.degree)
            .find(|position| {
                columns[positive][*position] == 0 && columns[positive + 1][*position] == 0
            })
            .unwrap();
        let mut changed = columns.clone();
        changed[positive].swap(selected, empty);
        assert_ne!(apply(&operator, &changed), target);

        for component in [2, 4] {
            let mut changed = statement.clone();
            change_polynomial(
                layout,
                &mut changed,
                layout.profile.fhe_polynomial(0, component),
            );
            let (operator, target) = systematic_operator(layout, alpha, &changed);
            assert_ne!(apply(&operator, &columns), target);
        }
    }
}

#[test]
fn malformed_or_unbound_statements_never_return_an_operator() {
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    for (participants, options) in [(3, 2), (10, 10), (16, 2)] {
        let layout = reduced(Profile::new(participants, options).unwrap());
        let (original, _) = satisfying_relation(layout, &mut random);
        let digest: [u8; 64] = ProtocolHash::digest(&original);
        let header = layout.header().len();
        let share = header
            + (0..layout.profile.share_common_polynomial())
                .map(|index| {
                    let (family, degree) = layout.polynomial(index).unwrap();
                    degree * (1 + layout.profile.family_magnitude_bytes(family))
                })
                .sum::<usize>();
        let expected = [
            Error::Parameters,
            Error::Encoding,
            Error::Incomplete,
            Error::Length,
            Error::Binding,
            Error::Encoding,
            Error::Parameters,
        ];
        for (kind, expected) in expected.into_iter().enumerate() {
            let mut bytes = original.clone();
            match kind {
                0 => bytes[0] ^= 1,
                1 => bytes[header] = 2,
                2 => {
                    bytes.pop();
                }
                3 => bytes.push(0),
                4 => bytes[header + 1] ^= 1,
                // A share coefficient beyond half the modulus.
                5 => bytes[share + 1..share + 1 + share_modulus().len()].fill(0xff),
                // The preceding statement grammar cannot enter this relation.
                _ => bytes[..4].copy_from_slice(b"SCO1"),
            }
            // Each statement but the unbound one is bound, so only its own
            // check can refuse it.
            let bound: [u8; 64] = if kind == 4 {
                digest
            } else {
                ProtocolHash::digest(&bytes)
            };
            assert_eq!(
                stream(layout, &bytes, bound, &[0, 1]).err(),
                Some(expected),
                "kind {kind}"
            );
        }
    }
    let layout = reduced(Profile::new(3, 2).unwrap());
    let mut stream =
        SetupStatementStream::with_layout(layout, [0; 64], [17, 37, 91], &[0, 1]).unwrap();
    assert_eq!(stream.push(&vec![0; CHUNK_LIMIT + 1]), Err(Error::Length));
    assert_eq!(stream.push(&[]), Err(Error::Encoding));
    assert!(stream.finish().is_err());
}
