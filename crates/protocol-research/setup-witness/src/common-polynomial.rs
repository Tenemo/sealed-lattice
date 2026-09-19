use num_bigint::{BigInt, Sign};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub(crate) fn public_reader(label: &str) -> impl XofReader + use<> {
    let mut state = Shake256::default();
    Update::update(&mut state, b"synthetic-full-setup-witness/1");
    Update::update(&mut state, &(label.len() as u32).to_le_bytes());
    Update::update(&mut state, label.as_bytes());
    state.finalize_xof()
}
pub(crate) fn public_polynomial(label: &str, degree: usize, modulus: &BigInt) -> Vec<BigInt> {
    let mut random = public_reader(label);
    let mut bytes = [0u8; 128];
    (0..degree)
        .map(|_| {
            random.read(&mut bytes);
            center(BigInt::from_bytes_le(Sign::Plus, &bytes), modulus)
        })
        .collect()
}
pub(crate) fn center(value: BigInt, modulus: &BigInt) -> BigInt {
    let value = (value % modulus + modulus) % modulus;
    if value > (modulus >> 1usize) {
        value - modulus
    } else {
        value
    }
}
