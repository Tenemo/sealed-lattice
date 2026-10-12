use super::*;

// An operation that draws witnesses and proofs, each filled with its own
// marker byte.
fn witness_and_proof(purpose: Purpose, bytes: &mut [u8]) -> bool {
    let marker = match purpose {
        Purpose::Witness => 0x57,
        Purpose::Proof => 0x50,
        Purpose::Ballot => return false,
    };
    bytes.fill(marker);
    true
}

// Whether a draw filled every byte with the marker, which 64 fresh bytes do
// with probability 2^-512.
fn draws_marker(draw: fn(&mut [u8]), marker: u8) -> bool {
    let mut bytes = [0; 64];
    draw(&mut bytes);
    bytes.iter().all(|value| *value == marker)
}

#[test]
fn serves_the_installed_operation_its_purposes_and_fresh_draws_from_the_system() {
    // Nothing installed: every draw is fresh.
    for draw in [witness, ballot, proof, fresh] {
        let mut first = [0; 64];
        let mut second = [0; 64];
        draw(&mut first);
        draw(&mut second);
        assert_ne!(first, second);
    }
    install(witness_and_proof);
    assert!(draws_marker(witness, 0x57));
    assert!(draws_marker(proof, 0x50));
    // A fresh draw never comes from the operation's seed.
    assert!(!draws_marker(fresh, 0x57) && !draws_marker(fresh, 0x50));
    release();
    assert!(!draws_marker(witness, 0x57));
    assert!(!draws_marker(proof, 0x50));
}

#[test]
#[should_panic(expected = "The installed operation does not draw this randomness.")]
fn refuses_a_draw_the_installed_operation_does_not_make() {
    install(witness_and_proof);
    ballot(&mut [0; 8]);
}

#[test]
#[should_panic]
fn refuses_a_second_operation_while_one_is_installed() {
    install(witness_and_proof);
    install(witness_and_proof);
}
