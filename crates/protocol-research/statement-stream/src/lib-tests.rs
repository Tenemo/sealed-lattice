use super::*;

#[test]
fn cubic_field_uses_the_selected_nonresidue() {
    assert_ne!(arithmetic::power(2, (MODULUS - 1) / 3), 1);
}

fn auxiliary_stream() -> PolynomialStream {
    PolynomialStream::new(
        supported_profile::auxiliary_modulus(),
        supported_profile::AUXILIARY_DEGREE,
        supported_profile::FHE_LIMB_BITS,
        [17, 37, 91],
    )
    .unwrap()
}

#[test]
fn limb_fingerprints_follow_the_selected_radix() {
    // 2^100 + 2^95 + 5 has 96-bit limbs (2^95 + 5, 2^4) and 95-bit
    // limbs (5, 2^5 + 1).
    let mut bytes = [0u8; 20];
    bytes[0] = 5;
    bytes[11] = 0x80;
    bytes[12] = 0x10;
    let weight = [3, 0, 0];
    assert_eq!(
        fingerprint_in(&bytes, 96, weight),
        [(1 << 95) + 5 + 3 * 16, 0, 0]
    );
    assert_eq!(fingerprint_in(&bytes, 95, weight), [5 + 3 * 33, 0, 0]);
    // Precomputed powers give the same fingerprint for an extension
    // weight, including a magnitude with every limb bit set.
    let weight = [17, MODULUS - 5, 1 << 90];
    for (bytes, radix_bits) in [(&bytes[..], 96), (&bytes[..], 17), (&[0xff; 73][..], 64)] {
        assert_eq!(
            fingerprint_with(
                bytes,
                radix_bits,
                &limb_powers(bytes.len(), radix_bits, weight)
            ),
            fingerprint_in(bytes, radix_bits, weight)
        );
    }
    assert_eq!(limb_value(&[0xff; 20], 1, 95), (1 << 65) - 1);
}

// A modulus whose limbs reach the column sums' bound of products is
// accepted at the least and the greatest radix, and one byte more is
// refused. At that bound, with every limb and power coordinate at its
// largest, the fingerprint equals the sum of its reduced products.
#[test]
fn refuses_moduli_whose_limbs_exceed_the_column_sum_bound() {
    for (radix_bits, bytes) in [(17, 8_704), (96, 49_152)] {
        let mut modulus = vec![0xff; bytes];
        assert_eq!((8 * bytes).div_ceil(radix_bits), MAXIMUM_PRODUCTS);
        assert_eq!(check_parameters(&modulus, 2, radix_bits, ZERO), Ok(()));
        modulus.push(0);
        assert_eq!(
            check_parameters(&modulus, 2, radix_bits, ZERO),
            Err(Error::Parameters)
        );
    }
    let magnitude = vec![0xff; 8_704];
    let powers = vec![[MODULUS - 1; 3]; MAXIMUM_PRODUCTS];
    let mut expected = ZERO;
    for (limb, power) in powers.iter().enumerate() {
        let value = limb_value(&magnitude, limb, 17);
        assert_eq!(value, (1 << 17) - 1);
        for (sum, coordinate) in expected.iter_mut().zip(power) {
            *sum = add(*sum, multiply(value, *coordinate));
        }
    }
    assert_eq!(fingerprint_with(&magnitude, 17, &powers), expected);
}

#[test]
fn rejects_partial_records_and_forbidden_lengths_without_output() {
    let mut stream = auxiliary_stream();
    stream.push(&[0; 5]).unwrap();
    assert_eq!(stream.finish_value(), Err(Error::Incomplete));
    let mut stream = auxiliary_stream();
    assert_eq!(stream.push(&vec![0; CHUNK_LIMIT + 1]), Err(Error::Length));
    assert_eq!(stream.push(&[]), Err(Error::Encoding));
    assert_eq!(stream.finish_value(), Err(Error::Encoding));
}

#[test]
fn record_runs_and_their_jobs_match_one_stream() {
    use supported_profile::{DEGREE, FHE_LIMB_BITS, Family, Profile};
    // The widest full-degree records span several runs, and parts of
    // 1,000 bytes split them.
    let modulus = Profile::all()
        .map(|profile| profile.family_modulus(Family::Fhe))
        .max_by_key(Vec::len)
        .unwrap();
    let (width, alpha) = (modulus.len() + 1, [17, 37, 91]);
    let half = half_modulus(&modulus);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut bytes = Vec::with_capacity(DEGREE * width);
    for index in 0..DEGREE {
        let mut record = vec![0; width];
        if index < 2 {
            // The largest magnitude of either sign.
            record[0] = index as u8;
            record[1..].copy_from_slice(&half);
        } else {
            for byte in &mut record[1..width - 2] {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            record[0] = u8::from(state >> 40 & 1 == 1);
        }
        bytes.extend(record);
    }
    let stream = || {
        let mut stream = PolynomialStream::new(&modulus, DEGREE, FHE_LIMB_BITS, alpha).unwrap();
        for part in bytes.chunks(CHUNK_LIMIT) {
            stream.push(part).unwrap();
        }
        stream
    };
    let indices = [0, 5, 70_000, 262_143];
    let expected = query::evaluate_in(stream().adjoint().unwrap(), &indices, DEGREE).unwrap();
    let (mut total, mut value, mut fingerprints, mut runs) = (ZERO, ZERO, Vec::new(), 0);
    let mut records = PolynomialRecords::new(&modulus, DEGREE, FHE_LIMB_BITS, alpha).unwrap();
    for part in bytes.chunks(1_000) {
        records
            .push(part, |position, run, last| {
                assert_eq!(last, position + run.len() / width == DEGREE);
                for retain in [true, false] {
                    let output = jobs::fingerprints_job(
                        width,
                        FHE_LIMB_BITS,
                        DEGREE,
                        position,
                        retain,
                        alpha,
                        run,
                    )
                    .wait();
                    let (sum, retained) = jobs::split_fingerprints(&output);
                    if retain {
                        total = plus(total, sum);
                        fingerprints.extend_from_slice(retained);
                    } else {
                        assert!(retained.is_empty());
                        value = plus(value, sum);
                    }
                }
                runs += 1;
                Ok(())
            })
            .unwrap();
    }
    assert!(runs > 1 && records.remaining() == 0);
    assert_eq!(value, stream().finish_value().unwrap());
    assert_eq!(total, value);
    let adjoint = |total| {
        jobs::decode_adjoint(
            &jobs::adjoint_job(&fingerprints, total, alpha, &indices, DEGREE)
                .unwrap()
                .wait(),
        )
    };
    assert_eq!(adjoint(total), Ok(expected));
    // Fingerprints whose weighted sum is not the total never close.
    assert_eq!(adjoint(plus(total, ONE)), Err(Error::Arithmetic));
    // A run refuses a magnitude beyond half the modulus, a negative zero
    // and a sign byte beyond one.
    for (offset, value) in [(width - 1, half[half.len() - 1] + 1), (0, 1), (0, 2)] {
        let mut changed = bytes[..CHUNK_LIMIT].to_vec();
        changed[2 * width..3 * width].fill(0);
        changed[2 * width + offset] = value;
        let mut records = PolynomialRecords::new(&modulus, DEGREE, FHE_LIMB_BITS, alpha).unwrap();
        assert_eq!(
            records.push(&changed, |_, _, _| Ok(())),
            Err(Error::Encoding)
        );
        assert_eq!(
            records.push(&bytes[..width], |_, _, _| Ok(())),
            Err(Error::Length)
        );
    }
}
