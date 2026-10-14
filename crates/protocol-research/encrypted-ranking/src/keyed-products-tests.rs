use super::{Arithmetic, KEYED_GROUPS, RecordContext};
use supported_profile::Profile;

// A product whose every job has requested its records has no request left.
#[test]
fn a_product_past_its_last_request_refuses_a_record() {
    let profile = Profile::new(3, 2).unwrap();
    let arithmetic = Arithmetic::new(profile, 16);
    let mut product = arithmetic.keyed_product(
        &arithmetic.uniform(1),
        RecordContext {
            program: [7; 64],
            cache: 0,
            ordinal: 0,
        },
    );
    product.requested = KEYED_GROUPS * arithmetic.external_primes;
    assert!(!arithmetic.deliver_record(&mut product, 0, 0, &[0; 8 * 16]));
}
