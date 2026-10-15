use super::*;

// The value of g at the point, where the plaintext is g(x^2), by direct
// evaluation of its even coefficients.
fn evaluate(coefficients: &[i32], point: u32) -> u32 {
    coefficients
        .iter()
        .step_by(2 * coefficients.len() / encoding_degree(coefficients.len()))
        .rev()
        .fold(0, |sum, coefficient| {
            (multiply(sum, point) + coefficient.rem_euclid(PLAINTEXT_MODULUS as i32) as u32)
                % PLAINTEXT_MODULUS
        })
}

fn canonical(coefficients: &[i32]) -> Vec<u32> {
    coefficients
        .iter()
        .map(|value| value.rem_euclid(PLAINTEXT_MODULUS as i32) as u32)
        .collect()
}

#[test]
fn slots_are_the_values_at_the_orbit_of_five() {
    for degree in [16, 64, 256] {
        let slots: Vec<u32> = (0..degree / 4)
            .map(|slot| (slot as u32 * 7_919 + 13) % PLAINTEXT_MODULUS)
            .collect();
        let coefficients = encode_slots(&slots, degree);
        assert_eq!(coefficients.len(), degree);
        assert!(
            coefficients
                .iter()
                .skip(1)
                .step_by(2)
                .all(|value| *value == 0)
        );
        assert!(
            coefficients
                .iter()
                .all(|value| value.unsigned_abs() <= PLAINTEXT_MODULUS / 2)
        );
        let root = power(11, (PLAINTEXT_MODULUS - 1) / degree as u32);
        let positions: Vec<usize> = slot_positions(degree).collect();
        let mut exponent = 1;
        for (slot, position) in slots.iter().zip(&positions) {
            assert_eq!(*position, (exponent - 1) / 2);
            assert_eq!(evaluate(&coefficients, power(root, exponent as u32)), *slot);
            exponent = 5 * exponent % degree;
        }
        let values = odd_power_values(&canonical(&coefficients));
        for (index, value) in values.iter().enumerate() {
            let expected = evaluate(&coefficients, power(root, 2 * index as u32 + 1));
            assert_eq!(*value, expected);
            if !positions.contains(&index) {
                assert_eq!(*value, 0);
            }
        }
    }
}

#[test]
fn embedded_slots_and_complementary_orbit_survive_a_round_trip() {
    let degree = 65_536;
    let slots: Vec<u32> = (0..ACTIVE_SLOTS)
        .map(|slot| (slot as u32).wrapping_mul(2_654_435_761) % PLAINTEXT_MODULUS)
        .collect();
    let complementary: Vec<_> = slots
        .iter()
        .map(|value| (value + 17) % PLAINTEXT_MODULUS)
        .collect();
    let coefficients = canonical(&encode_orbits(&slots, &complementary, degree));
    let values = odd_power_values(&coefficients);
    let positions: Vec<usize> = slot_positions(ENCODING_DEGREE).collect();
    let mut distinct = positions.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), ACTIVE_SLOTS);
    assert_eq!(
        positions
            .iter()
            .map(|position| values[*position])
            .collect::<Vec<_>>(),
        slots
    );
    assert_eq!(
        positions
            .iter()
            .map(|position| values[ENCODING_DEGREE / 2 - 1 - position])
            .collect::<Vec<_>>(),
        complementary
    );
    assert!(
        coefficients
            .iter()
            .enumerate()
            .all(|(index, value)| index % 32 == 0 || *value == 0)
    );
}

#[test]
fn centered_residues_stay_within_half_the_modulus() {
    assert_eq!(centered(0), 0);
    assert_eq!(
        centered(PLAINTEXT_MODULUS / 2),
        (PLAINTEXT_MODULUS / 2) as i32
    );
    assert_eq!(
        centered(PLAINTEXT_MODULUS / 2 + 1),
        -((PLAINTEXT_MODULUS / 2) as i32)
    );
    assert_eq!(centered(PLAINTEXT_MODULUS - 1), -1);
    assert_eq!(multiply(power(3, PLAINTEXT_MODULUS - 2), 3), 1);
    assert_eq!(
        power(11, (PLAINTEXT_MODULUS - 1) / 2),
        PLAINTEXT_MODULUS - 1
    );
}
