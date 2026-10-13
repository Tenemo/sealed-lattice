use super::super::word_arithmetic::widening_multiply;
use super::{
    DROP_LEFT, DROP_RIGHT, IDENTITY_BYTES, KEYED_BLOCK, RecordContext, extend, number, read,
    read_set, record_hasher, record_identity, session_number, word, words,
};
use protocol_foundations::identity::IdentityHasher;
use std::{cell::RefCell, collections::HashMap};

thread_local! {
    /// The transformed polynomials each session keeps modulo each prime
    /// whose jobs run here, by position: its sources, or a polynomial's
    /// digits.
    pub(super) static KEPT: RefCell<HashMap<(u64, usize, usize), Vec<u64>>> = RefCell::default();
}
pub(super) fn sources(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let (session, slot) = (session_number(rest), number(&rest[8..]));
    let residues = arithmetic.set_residues(set);
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for (prime, mut residues) in set.primes().zip(residues) {
            arithmetic.transform(prime).forward(&mut residues);
            assert!(
                kept.insert((session, prime, slot), residues).is_none(),
                "Kept source"
            );
        }
    });
    Vec::new()
}

pub(super) fn tensor(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let session = session_number(rest);
    let [left, right, drops] = std::array::from_fn(|index| number(&rest[8 + 4 * index..]));
    let drops = drops as u32;
    let mut output = Vec::with_capacity(8 * arithmetic.degree * set.len());
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for prime in set.primes() {
            let reduction = &arithmetic.reductions[prime];
            // A dropped left source becomes the product.
            let mut product = if drops & DROP_LEFT != 0 || (left == right && drops != 0) {
                kept.remove(&(session, prime, left)).expect("Kept source")
            } else {
                kept[&(session, prime, left)].clone()
            };
            if left == right {
                for value in &mut product {
                    *value = reduction.multiply(*value, *value);
                }
            } else {
                for (value, other) in product.iter_mut().zip(&kept[&(session, prime, right)]) {
                    *value = reduction.multiply(*value, *other);
                }
                if drops & DROP_RIGHT != 0 {
                    kept.remove(&(session, prime, right));
                }
            }
            arithmetic.transform(prime).backward(&mut product);
            extend(&mut output, &product);
        }
    });
    output
}

pub(super) fn records(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let context = RecordContext::read(rest);
    let residues = arithmetic.set_residues(set);
    let record_bytes = 8 * arithmetic.degree;
    let mut output = Vec::with_capacity(set.len() * (IDENTITY_BYTES + record_bytes));
    for (prime, mut residues) in set.primes().zip(residues) {
        arithmetic.transform(prime).forward(&mut residues);
        let start = output.len();
        output.resize(start + IDENTITY_BYTES, 0);
        extend(&mut output, &residues);
        let identity = record_identity(
            &context,
            context.ordinal,
            prime,
            &output[start + IDENTITY_BYTES..],
        );
        output[start..start + IDENTITY_BYTES].copy_from_slice(&identity);
    }
    output
}

pub(super) fn digits(input: &[u8]) -> Vec<u8> {
    let (arithmetic, set, rest) = read_set(input);
    let session = session_number(rest);
    let digits = arithmetic.set_digits(set);
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for (prime, digits) in set.primes().zip(digits) {
            let transform = arithmetic.transform(prime);
            for (digit, mut residues) in digits.into_iter().enumerate() {
                transform.forward(&mut residues);
                assert!(
                    kept.insert((session, prime, digit), residues).is_none(),
                    "Kept digits"
                );
            }
        }
    });
    Vec::new()
}

pub(super) fn keyed(input: &[u8]) -> Vec<u8> {
    let (arithmetic, prime, rest) = read(input);
    let (session, last) = (session_number(rest), number(&rest[8..]) != 0);
    let context = RecordContext::read(&rest[12..]);
    let (degree, gadget_length) = (arithmetic.degree, arithmetic.gadget_length);
    let record_bytes = 8 * degree;
    assert_eq!(
        parallel_work::streamed_length(),
        record_bytes * gadget_length
    );
    let reduction = &arithmetic.reductions[prime];
    // Each record's identity absorbs its words as the job reads them.
    let mut hashers: Vec<IdentityHasher> = (0..gadget_length)
        .map(|digit| record_hasher(&context, context.ordinal + digit, prime, record_bytes))
        .collect();
    let mut sum = vec![0u64; degree];
    // A position's products of a digit, below a prime below 2^58, and a
    // key word, below 2^64 even in a changed record, are below 2^122, so at
    // most 64 of them sum below 2^128 and each position reduces once. A
    // changed record then fails only its identity.
    assert!(gadget_length <= 64);
    let mut products = vec![0u128; KEYED_BLOCK.min(degree)];
    let mut words = vec![0u8; 8 * products.len()];
    KEPT.with(|kept| {
        let mut kept = kept.borrow_mut();
        for first in (0..degree).step_by(products.len()) {
            let count = products.len().min(degree - first);
            products.fill(0);
            for (digit, hasher) in hashers.iter_mut().enumerate() {
                let words = &mut words[..8 * count];
                parallel_work::read(digit * record_bytes + 8 * first, words);
                hasher.absorb(words).expect("Record identity");
                let digits = &kept[&(session, prime, digit)][first..first + count];
                for ((product, digit), key) in
                    products.iter_mut().zip(digits).zip(words.chunks_exact(8))
                {
                    let (low, high) = widening_multiply(*digit, word(key));
                    *product += (u128::from(high) << 64) | u128::from(low);
                }
            }
            for (value, product) in sum[first..first + count].iter_mut().zip(&products) {
                *value = reduction.reduce_wide(*product);
            }
        }
        if last {
            for digit in 0..gadget_length {
                kept.remove(&(session, prime, digit));
            }
        }
    });
    drop((products, words));
    let mut output = Vec::with_capacity(IDENTITY_BYTES * gadget_length + 8 * degree);
    for hasher in hashers {
        output.extend(hasher.finish().expect("Record identity"));
    }
    arithmetic.transform(prime).backward(&mut sum);
    extend(&mut output, &sum);
    output
}

pub(super) fn forget(input: &[u8]) -> Vec<u8> {
    let (session, prime) = (session_number(input), number(&input[8..]));
    KEPT.with(|kept| {
        kept.borrow_mut()
            .retain(|(kept_session, kept_prime, _), _| {
                (*kept_session, *kept_prime) != (session, prime)
            });
    });
    Vec::new()
}

pub(super) fn lift(input: &[u8]) -> Vec<u8> {
    let (arithmetic, lifted, rest) = read(input);
    let lift = arithmetic.lift(lifted);
    let positions = number(rest);
    let values = words(&rest[4..]);
    assert_eq!(values.len(), lift.count * positions);
    let residues: Vec<&[u64]> = values.chunks_exact(positions).collect();
    let mut coefficients = vec![0u64; positions * arithmetic.words];
    for (position, coefficient) in coefficients.chunks_exact_mut(arithmetic.words).enumerate() {
        lift.coefficient(
            &residues,
            position,
            &arithmetic.reductions,
            &arithmetic.wide,
            coefficient,
        );
    }
    let mut output = Vec::with_capacity(8 * coefficients.len());
    extend(&mut output, &coefficients);
    output
}
