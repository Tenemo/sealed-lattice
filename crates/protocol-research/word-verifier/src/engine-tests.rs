use super::*;
use supported_profile::{
    Profile,
    relation::{PROOF_HEADER_BYTES, ballot_relation},
};

// A statement that refuses every byte, so no proof it opens completes.
struct Refused;
impl Statement for Refused {
    fn push(&mut self, _bytes: &[u8]) -> bool {
        false
    }
    fn finish(self) -> Option<StatementOutput> {
        None
    }
}
fn open(role: &[u8], statement: [u8; 64], bytes: &[u8]) -> Result<Verifier<Refused>, Refusal> {
    Verifier::open(
        ballot_relation(Profile::new(3, 2).unwrap()),
        role,
        statement,
        bytes,
        |_, _| Some(Refused),
    )
}
fn header() -> Vec<u8> {
    let mut bytes = vec![0; HEADER_LENGTH];
    bytes[..4].copy_from_slice(ballot_relation(Profile::new(3, 2).unwrap()).proof_magic);
    bytes
}
#[test]
fn malformed_headers_and_unfinished_streams_cannot_verify() {
    assert_eq!(HEADER_LENGTH, PROOF_HEADER_BYTES);
    let bytes = header();
    assert!(open(b"role", [0; 64], &bytes).is_ok());
    assert!(!open(b"role", [0; 64], &bytes).unwrap().finish());
    assert!(open(b"", [0; 64], &bytes).is_err());
    assert!(open(b"role", [1; 64], &bytes).is_err());
    assert!(open(b"role", [0; 64], &bytes[..HEADER_LENGTH - 1]).is_err());
    let mut other = bytes.clone();
    other[..4].copy_from_slice(b"SWP3");
    assert!(matches!(
        open(b"role", [0; 64], &other),
        Err(Refusal::Encoding)
    ));
    assert!(matches!(
        Verifier::<Refused>::open(
            ballot_relation(Profile::new(3, 2).unwrap()),
            b"role",
            [0; 64],
            &bytes,
            |_, _| { None }
        ),
        Err(Refusal::Context)
    ));
    for offset in [324, HEADER_LENGTH - 48] {
        let mut changed = bytes.clone();
        changed[offset..offset + 16].copy_from_slice(&MODULUS.to_le_bytes());
        assert!(matches!(
            open(b"role", [0; 64], &changed),
            Err(Refusal::Encoding)
        ));
    }
    let mut verifier = open(b"role", [0; 64], &bytes).unwrap();
    assert!(matches!(verifier.push_proof(&[0]), Err(Refusal::Stage)));
    assert!(matches!(
        verifier.push_statement(&[0]),
        Err(Refusal::Encoding)
    ));
    assert!(matches!(verifier.finish_statement(), Err(Refusal::Stage)));
    assert!(!verifier.finish());
}
// The table-driven values at a point equal direct powers of the point
// 7 w^index, at both ends of the domain and at every residue modulo four.
#[test]
fn points_match_direct_powers() {
    for index in [
        0,
        1,
        2,
        3,
        4,
        511,
        512,
        513,
        H - 1,
        H,
        D / 2 + 5,
        D - 2,
        D - 1,
    ] {
        let value = multiply_base(7, power_base(root(D), index as u128));
        let vanishing = subtract_base(power_base(value, H as u128), 1);
        let point = Point::new(index, 11);
        assert_eq!(point.inverse, power_base(value, MODULUS - 2));
        assert_eq!(multiply_base(point.inverse, value), 1);
        assert_eq!(point.vanishing, vanishing);
        assert_eq!(point.inverse_vanishing, power_base(vanishing, MODULUS - 2));
        for (power, degree) in point.powers.iter().zip(CORRECTED_DEGREES) {
            assert_eq!(*power, power_base(value, (MAX_DEGREE - degree) as u128));
        }
        assert_eq!(point.table, 11);
    }
}
// Each fold round's point inverse is the direct inverse of the round's
// point 7^(2^round) w_length^index, and the halving and systematic
// constants invert two and the subgroup's size.
#[test]
fn fold_points_invert_the_direct_points() {
    let coset = Coset::get();
    assert_eq!(multiply_base(coset.half, 2), 1);
    assert_eq!(multiply_base(coset.inverse_systematic, H as u128), 1);
    for round in [0, 1, 7, FOLDS - 2, FOLDS - 1] {
        let length = D >> round;
        for index in [0, 1, 2, 3, length / 4 + 1, length / 2 - 1] {
            if index >= length / 2 {
                continue;
            }
            let point = multiply_base(
                power_base(7, 1 << round),
                power_base(root(length), index as u128),
            );
            assert_eq!(
                coset.inverse_fold_point(round, index),
                power_base(point, MODULUS - 2)
            );
        }
    }
}
// A hash that continues a prefix's sponge equals the direct hash of the
// prefix's domain and parts followed by its own parts.
#[test]
fn prefixed_hashes_equal_the_direct_hashes() {
    let role: Vec<u8> = (0..282).map(|index| index as u8).collect();
    for (stage, rest) in [
        (0u32, vec![vec![1, 2, 3, 4], vec![5; 128], vec![6; 144]]),
        (3, vec![vec![9; 4], vec![7; 64], vec![8; 64]]),
        (19, vec![]),
    ] {
        let stage = stage.to_le_bytes();
        let parts: Vec<&[u8]> = rest.iter().map(Vec::as_slice).collect();
        let direct: Vec<&[u8]> = [role.as_slice(), &stage]
            .into_iter()
            .chain(parts.iter().copied())
            .collect();
        assert_eq!(
            hash_after(&prefix(b"bounded-proof/node", &[&role, &stage]), &parts),
            hash(b"bounded-proof/node", &direct)
        );
    }
}
#[test]
fn folded_queries_preserve_required_partners() {
    assert_eq!(requested(&[0, 1, 7, 7, 15], 16), vec![0, 1, 7, 8, 9, 15]);
}
