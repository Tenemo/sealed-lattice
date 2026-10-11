use super::*;
use num_traits::Zero;

// The profile's moduli, gadget and prime prefixes at a small ring degree,
// checked against exact integer arithmetic.
const TEST_DEGREE: usize = 16;

fn profiles() -> Vec<Profile> {
    [(3, 2), (10, 10), (20, 20)]
        .into_iter()
        .map(|(participants, options)| Profile::new(participants, options).unwrap())
        .collect()
}
fn convolution(left: &[BigInt], right: &[BigInt]) -> Vec<BigInt> {
    let degree = left.len();
    let mut output = vec![BigInt::zero(); degree];
    for (first, left) in left.iter().enumerate() {
        for (second, right) in right.iter().enumerate() {
            let product = left * right;
            if first + second < degree {
                output[first + second] += product;
            } else {
                output[first + second - degree] -= product;
            }
        }
    }
    output
}
fn centered(arithmetic: &Arithmetic, polynomial: &[u64]) -> Vec<BigInt> {
    let half = BigInt::from(&arithmetic.modulus >> 1usize);
    arithmetic
        .coefficients(polynomial)
        .map(|value| {
            let value = BigInt::from(unpack(value));
            if value > half {
                value - &arithmetic.signed_modulus
            } else {
                value
            }
        })
        .collect()
}
fn canonical(arithmetic: &Arithmetic, values: Vec<BigInt>) -> Polynomial {
    let mut output = Vec::new();
    for value in values {
        arithmetic.push_normalized(&mut output, value);
    }
    output
}
fn plaintext(values: &[i64]) -> Vec<u64> {
    values
        .iter()
        .map(|value| value.rem_euclid(i64::from(PLAINTEXT_MODULUS)) as u64)
        .collect()
}
fn plaintext_product(left: &[i16], right: &[i16]) -> Vec<u64> {
    let integers = |values: &[i16]| {
        values
            .iter()
            .map(|value| BigInt::from(*value))
            .collect::<Vec<_>>()
    };
    plaintext(
        &convolution(&integers(left), &integers(right))
            .into_iter()
            .map(|value| value.to_i64().unwrap())
            .collect::<Vec<_>>(),
    )
}
fn record_context(cache: u32, ordinal: usize) -> RecordContext {
    RecordContext {
        program: [3; 64],
        cache,
        ordinal,
    }
}
// Delivers the records that each request of keyed work names until the
// work ends.
fn finish(
    arithmetic: &Arithmetic,
    mut work: KeyedWork,
    (identities, records): &jobs::HeldRecords,
) -> [Polynomial; 2] {
    loop {
        match arithmetic.advance(&mut work, identities).unwrap() {
            Step::Done(value) => return value,
            Step::Waiting(_) => {}
            Step::Records(request) => {
                for (ordinal, record) in records
                    .iter()
                    .enumerate()
                    .skip(request.first)
                    .take(request.count)
                {
                    assert!(arithmetic.deliver(
                        &mut work,
                        ordinal,
                        request.prime,
                        &record[request.prime]
                    ));
                }
            }
        }
    }
}
fn plaintext_automorphism(values: &[i16]) -> Vec<u64> {
    let mut output = vec![0i64; values.len()];
    for (index, value) in values.iter().enumerate() {
        let exponent = index * 5;
        let sign = if (exponent / values.len()).is_multiple_of(2) {
            1
        } else {
            -1
        };
        output[exponent % values.len()] = sign * i64::from(*value);
    }
    plaintext(&output)
}

#[test]
fn digit_residues_match_big_integer_digits_at_every_offset() {
    let prime = super::super::proth_prime(58, 1 << 58);
    let reduction = PrimeModulus::new(prime);
    let mut power = 1;
    let powers: Vec<(u64, u64)> = (0..16)
        .map(|_| {
            let current = (power, reduction.shoup(power));
            power = reduction.multiply(power, ((1u128 << 64) % u128::from(prime)) as u64);
            current
        })
        .collect();
    for words in [9, 14, 16] {
        let mut state = 0x5eed ^ words as u64;
        let mut values: Vec<Vec<u64>> = vec![vec![u64::MAX; words], vec![0; words]];
        values.push((0..words).map(|_| next(&mut state)).collect());
        for value in values {
            let integer = unpack(&value);
            assert_eq!(
                words_residue(&reduction, &powers, &value, 0),
                (&integer % prime).to_u64().unwrap()
            );
            assert_eq!(
                words_residue(&reduction, &powers, &value, prime - 1),
                ((&integer + prime - 1u32) % prime).to_u64().unwrap()
            );
            for bits in [1, 63, 64, 65, 144] {
                for start in [
                    0,
                    1,
                    63,
                    64,
                    100,
                    144 * 3,
                    64 * words - bits,
                    64 * words - 1,
                ] {
                    let digit = (&integer >> start) & ((BigUint::from(1u32) << bits) - 1u32);
                    let mut output = vec![0; bits.div_ceil(64)];
                    digit_words(&value, start, bits, &mut output);
                    assert_eq!(
                        unpack(&output),
                        digit,
                        "words={words}, bits={bits}, start={start}"
                    );
                    assert_eq!(
                        words_residue(&reduction, &powers, &output, 0),
                        (digit % prime).to_u64().unwrap(),
                        "words={words}, bits={bits}, start={start}"
                    );
                }
            }
        }
    }
}

#[test]
fn products_match_exact_negacyclic_convolution() {
    for profile in profiles() {
        let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
        assert_eq!(
            arithmetic.words,
            profile.ciphertext_modulus().bits().div_ceil(64)
        );
        let left = arithmetic.uniform(1);
        let right = arithmetic.uniform(2);
        // Plaintext coefficients at both ends of their range.
        let small: Vec<i16> = (0..TEST_DEGREE)
            .map(|index| [i16::MAX, i16::MIN, 0, 5][index % 4])
            .collect();
        let small = arithmetic.small(&small);
        let exact = convolution(
            &centered(&arithmetic, &left),
            &centered(&arithmetic, &small),
        );
        assert_eq!(
            arithmetic.multiply(&left, &small, false),
            canonical(&arithmetic, exact)
        );
        let exact = convolution(
            &centered(&arithmetic, &left),
            &centered(&arithmetic, &right),
        )
        .into_iter()
        .map(|value| {
            let rounded = (value.magnitude() * PLAINTEXT_MODULUS + (&arithmetic.modulus >> 1usize))
                / &arithmetic.modulus;
            if value.sign() == Sign::Minus {
                -BigInt::from(rounded)
            } else {
                BigInt::from(rounded)
            }
        })
        .collect();
        let tensor = arithmetic.multiply(&left, &right, true);
        assert_eq!(tensor, canonical(&arithmetic, exact));
        // The constant tensor multiplies both first components, the linear
        // one adds the two cross products, each lifted on its own, and
        // the quadratic one multiplies both second components.
        let [constant, linear, quadratic] = arithmetic.tensors(
            &[left.clone(), right.clone()],
            &[right.clone(), left.clone()],
        );
        assert_eq!(constant, tensor);
        assert_eq!(quadratic, tensor);
        let mut cross = arithmetic.multiply(&left, &left, true);
        arithmetic.add(&mut cross, &arithmetic.multiply(&right, &right, true));
        assert_eq!(linear, cross);
        // A square's tensors equal those of the value and its copy.
        let value = [left, right];
        assert_eq!(
            arithmetic.tensors(&value, &value),
            arithmetic.tensors(&value, &value.clone())
        );
    }
}

// Each group's external product, beside the next group's, equals the
// exact sum of the gadget digits' products with its keys.
#[test]
fn keyed_products_match_exact_gadget_digit_sums() {
    let bits = Profile::gadget_base_bits();
    for profile in profiles() {
        let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
        assert_eq!(
            arithmetic.gadget_length,
            profile.ciphertext_modulus().bits().div_ceil(bits)
        );
        let value = arithmetic.uniform(3);
        let groups: Vec<Vec<Polynomial>> = (0..3)
            .map(|group| {
                (0..arithmetic.gadget_length)
                    .map(|digit| arithmetic.uniform(10 + (8 * group + digit) as u64))
                    .collect()
            })
            .collect();
        let held = arithmetic.held_records(
            &groups.iter().flatten().collect::<Vec<_>>(),
            record_context(0, 0),
        );
        let keyed = |group: usize| {
            let product = arithmetic
                .keyed_product(&value, record_context(0, group * arithmetic.gadget_length));
            arithmetic.run_keyed(product, &held).unwrap()
        };
        let mask = (BigUint::from(1u32) << bits) - 1u32;
        let exact = |keys: &[Polynomial]| {
            let mut exact = vec![BigInt::zero(); TEST_DEGREE];
            for (digit, key) in keys.iter().enumerate() {
                let digits: Vec<BigInt> = arithmetic
                    .coefficients(&value)
                    .map(|coefficient| {
                        BigInt::from((unpack(coefficient) >> (bits * digit)) & &mask)
                    })
                    .collect();
                for (sum, term) in exact
                    .iter_mut()
                    .zip(convolution(&digits, &centered(&arithmetic, key)))
                {
                    *sum += term;
                }
            }
            canonical(&arithmetic, exact)
        };
        let [second, third] = keyed(1);
        assert_eq!(second, exact(&groups[1]));
        assert_eq!(third, exact(&groups[2]));
        assert_eq!(keyed(0), [exact(&groups[0]), second]);
    }
}

#[test]
fn relinearized_products_and_rotations_decrypt_to_the_plaintext_results() {
    for profile in profiles() {
        let arithmetic = Arithmetic::new(profile, TEST_DEGREE);
        let weight = TEST_DEGREE / 2;
        let contributors = profile.setup_contributors();
        let secret_values = secret(TEST_DEGREE, contributors, weight, 0x1234_5678_9abc_def1);
        let auxiliary_values = secret(TEST_DEGREE, contributors, weight, 0x9876_5432_10ab_cdef);
        let secret = arithmetic.small(&secret_values);
        let auxiliary = arithmetic.small(&auxiliary_values);
        let rotated_secret = arithmetic.automorphism(&secret);
        let zeros = vec![0; TEST_DEGREE];
        let mut encryption = Vec::new();
        let mut first_relinearization = Vec::new();
        let mut second_relinearization = Vec::new();
        let mut rotation = Vec::new();
        let mut second_commons = Vec::new();
        let mut rotation_commons = Vec::new();
        for digit in 0..arithmetic.gadget_length {
            let gadget = BigInt::from(BigUint::from(1u64) << (Profile::gadget_base_bits() * digit));
            let common = arithmetic.uniform(0x6a09_e667_f3bc_c909 ^ digit as u64);
            let second_common = arithmetic.uniform(0xbb67_ae85_84ca_a73b ^ digit as u64);
            let rotation_common = arithmetic.uniform(0x3c6e_f372_fe94_f82b ^ digit as u64);
            encryption.push(arithmetic.affine(
                &arithmetic.multiply(&secret, &common, false),
                true,
                &zeros,
                &BigInt::zero(),
                -640,
            ));
            first_relinearization.push(arithmetic.affine(
                &arithmetic.multiply(&auxiliary, &common, false),
                true,
                &secret_values,
                &gadget,
                630,
            ));
            second_relinearization.push(arithmetic.affine(
                &arithmetic.multiply(&secret, &second_common, false),
                true,
                &auxiliary_values,
                &-gadget.clone(),
                -640,
            ));
            // The automorphism key encrypts the rotated secret times the
            // gadget coordinate.
            let mut key = arithmetic.affine(
                &arithmetic.multiply(&secret, &rotation_common, false),
                true,
                &zeros,
                &BigInt::zero(),
                -640,
            );
            let mut shifted = Vec::new();
            for value in arithmetic.coefficients(&rotated_secret) {
                arithmetic.push_normalized(&mut shifted, BigInt::from(unpack(value)) * &gadget);
            }
            arithmetic.add(&mut key, &shifted);
            rotation.push(key);
            second_commons.push(second_common);
            rotation_commons.push(rotation_common);
        }
        let multiplication_keys = arithmetic.held_records(
            &encryption
                .iter()
                .chain(&first_relinearization)
                .chain(&second_relinearization)
                .chain(&second_commons)
                .collect::<Vec<_>>(),
            record_context(0, 0),
        );
        let rotation_keys = arithmetic.held_records(
            &rotation.iter().chain(&rotation_commons).collect::<Vec<_>>(),
            record_context(1, 0),
        );
        let delta = BigInt::from((&arithmetic.modulus + PLAINTEXT_MODULUS / 2) / PLAINTEXT_MODULUS);
        let encrypt = |plain: &[i16], seed| {
            let ephemeral = arithmetic.small(&ephemeral(TEST_DEGREE, weight, seed));
            let common = arithmetic.uniform(0x6a09_e667_f3bc_c909);
            [
                arithmetic.affine(
                    &arithmetic.multiply(&ephemeral, &encryption[0], false),
                    false,
                    plain,
                    &delta,
                    63,
                ),
                arithmetic.affine(
                    &arithmetic.multiply(&ephemeral, &common, false),
                    false,
                    &zeros,
                    &BigInt::zero(),
                    -64,
                ),
            ]
        };
        let first_plain: Vec<i16> = (0..TEST_DEGREE as i16)
            .map(|index| 3 * index - 17)
            .collect();
        let second_plain: Vec<i16> = (0..TEST_DEGREE as i16).map(|index| 7 - 2 * index).collect();
        let first = encrypt(&first_plain, 0x12ab_cdef_1234_5679);
        let second = encrypt(&second_plain, 0xfe01_9876_dcba_3211);
        assert_eq!(
            arithmetic.decode(&first, &secret),
            plaintext(
                &first_plain
                    .iter()
                    .map(|value| i64::from(*value))
                    .collect::<Vec<_>>()
            )
        );
        let product = finish(
            &arithmetic,
            arithmetic.start_product(&first, &second, record_context(0, 0)),
            &multiplication_keys,
        );
        assert_eq!(
            arithmetic.decode(&product, &secret),
            plaintext_product(&first_plain, &second_plain),
            "profile={profile:?}"
        );
        let square = finish(
            &arithmetic,
            arithmetic.start_product(&first, &first, record_context(0, 0)),
            &multiplication_keys,
        );
        assert_eq!(
            arithmetic.decode(&square, &secret),
            plaintext_product(&first_plain, &first_plain),
            "profile={profile:?}"
        );
        let rotated = finish(
            &arithmetic,
            arithmetic.start_rotation(&first, record_context(1, 0)),
            &rotation_keys,
        );
        assert_eq!(
            arithmetic.decode(&rotated, &secret),
            plaintext_automorphism(&first_plain),
            "profile={profile:?}"
        );
    }
}
