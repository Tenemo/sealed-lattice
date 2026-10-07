use super::*;
use registration_credentials::{
    ballot_authentication::ENVELOPE_BYTES,
    close_signing::close_message_identity,
    foundation::{CanonicalItem, hash_foundation_tuple_512},
};

fn identity(state: &mut State, purpose: u32, bytes: &[u8], fragment: usize) -> [u8; 64] {
    state.begin(purpose, bytes.len()).unwrap();
    for part in bytes.chunks(fragment) {
        state.input[..part.len()].copy_from_slice(part);
        state.absorb(part.len()).unwrap();
        assert!(state.input.iter().all(|value| *value == 0));
    }
    state.finish().unwrap();
    state.output
}

#[test]
fn separates_purposes_and_matches_the_target_envelope_and_response_identities() {
    let body: Vec<u8> = (0..INPUT_BYTES + 91)
        .map(|index| (index % 253) as u8)
        .collect();
    let mut state = State::default();
    let target = hash_foundation_tuple_512(
        TARGET_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(&body[..2048]).unwrap()],
    )
    .unwrap()
    .into_bytes();
    assert_eq!(identity(&mut state, 3, &body[..2048], 100), target);
    let envelope = hash_foundation_tuple_512(
        ENVELOPE_IDENTITY_DOMAIN,
        &[CanonicalItem::variable_bytes(&body[..ENVELOPE_BYTES]).unwrap()],
    )
    .unwrap()
    .into_bytes();
    assert_eq!(
        identity(&mut state, 4, &body[..ENVELOPE_BYTES], 50),
        envelope
    );
    let response = close_message_identity(ClosePurpose::Response, &body[..5000]).unwrap();
    assert_eq!(identity(&mut state, 5, &body[..5000], 333), response);
    let identities: Vec<_> = (0..6)
        .map(|purpose| identity(&mut state, purpose, &body, INPUT_BYTES))
        .collect();
    for purpose in 0..6 {
        assert_eq!(
            identity(&mut state, purpose as u32, &body, 7_000),
            identities[purpose]
        );
        for other in purpose + 1..6 {
            assert_ne!(identities[purpose], identities[other]);
        }
    }
}

#[test]
fn refuses_unknown_purposes_and_wrong_lengths() {
    let mut state = State::default();
    assert!(state.begin(6, 1).is_err());
    assert!(state.absorb(1).is_err());
    assert!(state.finish().is_err());
    state.begin(1, 2).unwrap();
    assert!(state.absorb(INPUT_BYTES + 1).is_err());
    assert!(state.finish().is_err());
    state.begin(1, 2).unwrap();
    state.absorb(1).unwrap();
    assert!(state.finish().is_err());
    state.begin(1, 2).unwrap();
    assert!(state.absorb(3).is_err());
    // A new identity replaces an unfinished one.
    state.begin(1, 2).unwrap();
    state.absorb(1).unwrap();
    state.begin(1, 1).unwrap();
    state.absorb(1).unwrap();
    state.finish().unwrap();
    assert_ne!(state.output, [0; 64]);
}
