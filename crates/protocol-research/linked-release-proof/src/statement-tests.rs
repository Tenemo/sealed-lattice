use super::*;
use crate::witness::tests::synthetic_release;

// A coefficient record is canonical only with a sign byte of zero or one, a
// magnitude of at most half its modulus and no negative zero. The statement
// refuses every other record, in share-modulus and release-modulus
// polynomials alike, and accepts both signs of the largest magnitude.
#[test]
fn statements_refuse_non_canonical_coefficients() {
    let profile = Profile::new(3, 2).unwrap();
    let (prepared, _) = synthetic_release(profile);
    let statement = &prepared.statement;
    let alpha = [5, 7, 11];
    assert!(statement.operator(alpha).is_ok());
    for index in [0, SHARE_POLYNOMIALS] {
        let width = coefficient_bytes(profile, index);
        let modulus = if index < SHARE_POLYNOMIALS {
            share_modulus()
        } else {
            release_modulus(profile)
        };
        let half = &modulus >> 1usize;
        let parse = |sign: u8, magnitude: &BigInt| {
            let mut record = vec![sign];
            record.extend(magnitude.to_bytes_le().1);
            record.resize(width, 0);
            let mut polynomials = statement.polynomials.clone();
            polynomials[index][width..2 * width].copy_from_slice(&record);
            PublicStatement {
                profile,
                header: statement.header.clone(),
                polynomials,
            }
            .operator(alpha)
        };
        assert!(parse(0, &half).is_ok());
        assert!(parse(1, &half).is_ok());
        assert!(matches!(parse(0, &(&half + 1)), Err(Error::Encoding)));
        assert!(matches!(parse(1, &(&half + 1)), Err(Error::Encoding)));
        assert!(matches!(parse(1, &BigInt::from(0)), Err(Error::Encoding)));
        assert!(matches!(parse(2, &BigInt::from(1)), Err(Error::Encoding)));
    }
}
