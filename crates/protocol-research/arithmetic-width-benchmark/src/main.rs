//! `check <seed>` compares, for the smallest and the largest ciphertext
//! modulus, the integers that every width reconstructs from its negacyclic
//! products at the ring degree: of random coefficients of the centered
//! range, checked by direct convolution at sampled positions, and of the
//! range's extreme coefficients, checked against their closed forms at every
//! position. It prints a JSON summary and fails on any difference.
//!
//! `time <repetitions> <seed>` times each kernel of each width on one thread
//! after two warm-up runs, alternating the widths, and prints every sample
//! with the digest of each width's tensor outputs.
use arithmetic_width_benchmark::{
    Kernel, Width, Workload, ciphertext_modulus, power, primes, split_mix, tensor_bound,
};
use num_bigint::{BigInt, BigUint, Sign};
use std::time::Instant;
use supported_profile::DEGREE;

/// The residues of the coefficients modulo each prime.
fn residues(coefficients: &[BigInt], primes: &[u64]) -> Vec<Vec<u64>> {
    let digits: Vec<(bool, Vec<u64>)> = coefficients
        .iter()
        .map(|value| {
            (
                value.sign() == Sign::Minus,
                value.magnitude().to_u64_digits(),
            )
        })
        .collect();
    primes
        .iter()
        .map(|&prime| {
            digits
                .iter()
                .map(|(negative, digits)| {
                    let magnitude = digits.iter().rev().fold(0u128, |accumulator, &digit| {
                        ((accumulator << 64) | u128::from(digit)) % u128::from(prime)
                    }) as u64;
                    if *negative && magnitude != 0 {
                        prime - magnitude
                    } else {
                        magnitude
                    }
                })
                .collect()
        })
        .collect()
}

/// The centered integers whose residues the outputs are, by the Chinese
/// remainder theorem.
fn reconstruct(outputs: &[Vec<u64>], primes: &[u64]) -> Vec<BigInt> {
    let product = primes
        .iter()
        .fold(BigUint::from(1u32), |product, &prime| product * prime);
    let half = &product >> 1usize;
    let basis: Vec<BigUint> = primes
        .iter()
        .map(|&prime| {
            let cofactor = &product / prime;
            let residue = u64::try_from(&(&cofactor % prime)).unwrap();
            let inverse = power(residue, prime - 2, prime);
            cofactor * inverse
        })
        .collect();
    let modulus = BigInt::from(product.clone());
    (0..DEGREE)
        .map(|position| {
            let sum = basis
                .iter()
                .zip(outputs)
                .fold(BigUint::from(0u32), |sum, (term, values)| {
                    sum + term * values[position]
                });
            let value = BigInt::from(sum % &product);
            if value.magnitude() > &half {
                value - &modulus
            } else {
                value
            }
        })
        .collect()
}

/// The negacyclic product's coefficient at the position, directly.
fn convolution(left: &[BigInt], right: &[BigInt], position: usize) -> BigInt {
    let mut sum = BigInt::from(0);
    for (index, value) in left.iter().enumerate() {
        if index <= position {
            sum += value * &right[position - index];
        } else {
            sum -= value * &right[DEGREE + position - index];
        }
    }
    sum
}

/// Coefficients drawn from the centered range `[-half, half]`.
fn random_coefficients(half: &BigUint, state: &mut u64) -> Vec<BigInt> {
    let span = half * 2u32 + 1u32;
    let words = usize::try_from(span.bits().div_ceil(64)).unwrap() + 1;
    let offset = BigInt::from(half.clone());
    (0..DEGREE)
        .map(|_| {
            let bytes: Vec<u8> = (0..words)
                .flat_map(|_| split_mix(state).to_le_bytes())
                .collect();
            BigInt::from(BigUint::from_bytes_le(&bytes) % &span) - &offset
        })
        .collect()
}

/// Every width's reconstruction of the product of the coefficients, which
/// must agree.
fn products(left: &[BigInt], right: &[BigInt], bound: &BigUint) -> Vec<BigInt> {
    let mut agreed: Option<Vec<BigInt>> = None;
    for width in Width::ALL {
        let primes = primes(width, bound);
        let mut workload = Workload::from_residues(
            width,
            &primes,
            &residues(left, &primes),
            &residues(right, &primes),
        );
        workload.run(Kernel::Tensor);
        let reconstructed = reconstruct(&workload.outputs(), &primes);
        match &agreed {
            Some(agreed) => assert!(
                agreed == &reconstructed,
                "the {} products differ from the current ones",
                width.name()
            ),
            None => agreed = Some(reconstructed),
        }
    }
    agreed.unwrap()
}

fn check(seed: u64) -> String {
    let mut state = seed;
    let mut moduli = Vec::new();
    for largest in [false, true] {
        let modulus = ciphertext_modulus(largest);
        let bound = tensor_bound(&modulus);
        let half = &modulus >> 1usize;
        let half_square = BigInt::from(&half * &half);
        let random = [
            random_coefficients(&half, &mut state),
            random_coefficients(&half, &mut state),
        ];
        let product = products(&random[0], &random[1], &bound);
        let mut positions = vec![0, 1, 2, DEGREE / 2 - 1, DEGREE / 2, DEGREE - 2, DEGREE - 1];
        positions.extend((0..5).map(|_| (split_mix(&mut state) % DEGREE as u64) as usize));
        for &position in &positions {
            assert_eq!(
                product[position],
                convolution(&random[0], &random[1], position),
                "position {position}"
            );
        }
        let top = vec![BigInt::from(half.clone()); DEGREE];
        let bottom = vec![-BigInt::from(half.clone()); DEGREE];
        // With every coefficient at the range's top, coefficient k gathers
        // k + 1 products and subtracts the N - 1 - k that wrap around.
        let closed =
            |position: usize| BigInt::from(2 * position as i64 + 2 - DEGREE as i64) * &half_square;
        let positive = products(&top, &top, &bound);
        let mixed = products(&top, &bottom, &bound);
        for position in 0..DEGREE {
            assert_eq!(positive[position], closed(position), "position {position}");
            assert_eq!(mixed[position], -closed(position), "position {position}");
        }
        let widths: Vec<String> = Width::ALL
            .iter()
            .map(|&width| {
                let primes = primes(width, &bound);
                let bits = primes
                    .iter()
                    .fold(BigUint::from(1u32), |product, &prime| product * prime)
                    .bits();
                format!(
                    "{{\"width\":\"{}\",\"primes\":{},\"productBits\":{bits}}}",
                    width.name(),
                    primes.len()
                )
            })
            .collect();
        moduli.push(format!(
            "{{\"largest\":{largest},\"modulusBits\":{},\"boundBits\":{},\"widths\":[{}],\"inputs\":[\"random\",\"top by top\",\"top by bottom\"],\"coefficientsCompared\":{DEGREE},\"directPositions\":{}}}",
            modulus.bits(),
            bound.bits(),
            widths.join(","),
            positions.len()
        ));
    }
    format!(
        "{{\"seed\":{seed},\"degree\":{DEGREE},\"moduli\":[{}]}}",
        moduli.join(",")
    )
}

fn time(repetitions: usize, seed: u64) -> String {
    let mut moduli = Vec::new();
    for largest in [false, true] {
        let mut workloads: Vec<Workload> = Width::ALL
            .iter()
            .map(|&width| Workload::new(width, largest, seed))
            .collect();
        for workload in &mut workloads {
            for kernel in Kernel::ALL {
                for _ in 0..2 {
                    workload.run(kernel);
                }
            }
        }
        let mut samples = vec![vec![Vec::new(); Kernel::ALL.len()]; Width::ALL.len()];
        for repetition in 0..repetitions {
            for (kernel_index, &kernel) in Kernel::ALL.iter().enumerate() {
                for offset in 0..Width::ALL.len() {
                    let width = (repetition + offset) % Width::ALL.len();
                    let start = Instant::now();
                    workloads[width].run(kernel);
                    samples[width][kernel_index].push(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
        let widths: Vec<String> = Width::ALL
            .iter()
            .zip(&workloads)
            .zip(&samples)
            .map(|((width, workload), samples)| {
                let kernels: Vec<String> = Kernel::ALL
                    .iter()
                    .zip(samples)
                    .map(|(kernel, values)| {
                        let values: Vec<String> = values.iter().map(f64::to_string).collect();
                        format!("\"{}\":[{}]", kernel.name(), values.join(","))
                    })
                    .collect();
                format!(
                    "{{\"width\":\"{}\",\"primes\":{},\"digest\":\"{:016x}\",\"milliseconds\":{{{}}}}}",
                    width.name(),
                    workload.primes().len(),
                    workload.digest(),
                    kernels.join(",")
                )
            })
            .collect();
        moduli.push(format!(
            "{{\"largest\":{largest},\"widths\":[{}]}}",
            widths.join(",")
        ));
    }
    format!(
        "{{\"repetitions\":{repetitions},\"seed\":{seed},\"moduli\":[{}]}}",
        moduli.join(",")
    )
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match arguments.as_slice() {
        ["check", seed] => println!("{}", check(seed.parse().unwrap())),
        ["time", repetitions, seed] => {
            println!(
                "{}",
                time(repetitions.parse().unwrap(), seed.parse().unwrap())
            )
        }
        _ => {
            eprintln!("usage: arithmetic-width-benchmark check <seed> | time <repetitions> <seed>");
            std::process::exit(2);
        }
    }
}
