pub use word_proof::field::{
    Element, MODULUS, ONE, ZERO, add, base, encode, multiply, root, scale, subtract,
};

pub fn power(mut value: Element, mut exponent: usize) -> Element {
    let mut result = ONE;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }
    result
}

pub fn powers(point: Element, length: usize) -> Vec<Element> {
    let mut value = ONE;
    (0..length)
        .map(|_| {
            let output = value;
            value = multiply(value, point);
            output
        })
        .collect()
}

pub fn inverse(value: Element) -> Element {
    base::inverse_extension(value).expect("The checked non-base challenge has no base-field pole")
}

pub fn signed(value: i128) -> u128 {
    if value < 0 {
        base::subtract(0, value.unsigned_abs() % MODULUS)
    } else {
        value as u128 % MODULUS
    }
}

pub fn scale_signed(value: Element, scalar: i128) -> Element {
    scale(value, signed(scalar))
}

pub fn dot(left: &[Element], right: &[Element]) -> Element {
    assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right)
        .fold(ZERO, |sum, (&left, &right)| add(sum, multiply(left, right)))
}

pub fn evaluate(polynomial: &[Element], point: Element) -> Element {
    polynomial.iter().rev().fold(ZERO, |sum, &coefficient| {
        add(multiply(sum, point), coefficient)
    })
}

pub fn encode_fields(values: &[Element]) -> Vec<u8> {
    values.iter().flat_map(|&value| encode(value)).collect()
}

pub fn code_points(domain: usize, positions: &[usize]) -> Vec<Element> {
    let generator = root(domain);
    positions
        .iter()
        .map(|&position| {
            [
                base::multiply(7, base::power(generator, position as u128)),
                0,
                0,
            ]
        })
        .collect()
}

pub fn lagrange(point: Element, length: usize) -> Vec<Element> {
    let vanishing = subtract(power(point, length), ONE);
    let inverse_length = base::power(length as u128, MODULUS - 2);
    let generator = root(length);
    let mut location = 1;
    (0..length)
        .map(|_| {
            let value = scale(
                multiply(vanishing, inverse(subtract(point, [location, 0, 0]))),
                base::multiply(location, inverse_length),
            );
            location = base::multiply(location, generator);
            value
        })
        .collect()
}
