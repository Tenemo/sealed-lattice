use super::*;
use registration_credentials::identity::identity;

fn payload(index: usize) -> Vec<u8> {
    (0..100 + index)
        .map(|byte| (byte * 7 + index) as u8)
        .collect()
}
fn deferred(bytes: &[u8]) -> PendingDigest {
    let mut hasher = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], bytes.len()).unwrap();
    hasher.absorb(bytes).unwrap();
    hasher.finish_later().unwrap()
}
// A completed polynomial whose previous aggregate was read as the bytes
// and verified as the expected ones.
fn completed(index: usize, read: &[u8], expected: &[u8]) -> FinishingPolynomial {
    let output = payload(index + 50);
    FinishingPolynomial {
        index,
        bytes: output.len(),
        previous: Some((
            deferred(read),
            identity(PUBLIC_POLYNOMIAL_DOMAIN, expected).unwrap(),
        )),
        output: deferred(&output),
    }
}

// Once more than the kept number are pending, the oldest polynomials
// enter the aggregate in order, each with its output's identity.
#[test]
fn deferred_identities_enter_the_aggregate_in_order() {
    let mut finishing = VecDeque::new();
    let mut outputs = Vec::new();
    for index in 0..5 {
        let previous = payload(index);
        finishing.push_back(completed(index, &previous, &previous));
        settle(&mut finishing, 2, &mut outputs).unwrap();
        assert_eq!(finishing.len(), (index + 1).min(2));
        assert_eq!(outputs.len(), (index + 1).saturating_sub(2));
    }
    settle(&mut finishing, 0, &mut outputs).unwrap();
    assert!(finishing.is_empty());
    for (index, output) in outputs.iter().enumerate() {
        let bytes = payload(index + 50);
        assert_eq!(output.index(), index);
        assert_eq!(output.bytes(), bytes.len());
        assert_eq!(
            output.digest(),
            &identity(PUBLIC_POLYNOMIAL_DOMAIN, &bytes).unwrap()
        );
    }
}

// A previous aggregate read with one changed byte is refused when its
// polynomial is checked, and neither it nor a later one enters the
// aggregate.
#[test]
fn a_changed_previous_aggregate_is_refused_when_checked() {
    for kept in [0, 1, 3] {
        let mut finishing = VecDeque::new();
        let mut outputs = Vec::new();
        let mut refused = None;
        for index in 0..4 {
            let expected = payload(index);
            let mut read = expected.clone();
            if index == 1 {
                read[40] ^= 1;
            }
            finishing.push_back(completed(index, &read, &expected));
            if let Err(refusal) = settle(&mut finishing, kept, &mut outputs) {
                refused = Some((index, refusal));
                break;
            }
        }
        if refused.is_none() {
            refused = settle(&mut finishing, 0, &mut outputs)
                .err()
                .map(|refusal| (4, refusal));
        }
        let (checked, refusal) = refused.expect("The changed aggregate is refused");
        assert!(matches!(refusal, Refusal::PreviousAggregate));
        assert_eq!(checked, (1 + kept).min(4), "{kept}");
        assert_eq!(outputs.len(), 1, "{kept}");
        assert_eq!(outputs[0].index(), 0);
    }
}
