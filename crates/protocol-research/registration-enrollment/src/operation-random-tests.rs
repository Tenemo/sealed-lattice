use super::*;
use registration_credentials::foundation::hash_foundation_tuple_512;

fn seed(first: u8) -> [u8; SEED_BYTES] {
    std::array::from_fn(|index| first.wrapping_add((index * 29) as u8))
}

fn install(state: &mut State, operation: u32, seed: &[u8; SEED_BYTES]) {
    state.input.copy_from_slice(seed);
    state.command(operation, SEED_BYTES).unwrap();
    assert!(state.input.iter().all(|value| *value == 0));
}

// Reads the whole stream prefix through requests of the given lengths.
fn read(state: &mut State, operation: u32, lengths: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &length in lengths {
        state.command(operation, length).unwrap();
        bytes.extend_from_slice(&state.output[..length]);
    }
    bytes
}

#[test]
fn frames_each_stream_as_the_foundation_hash_of_its_domain_and_seed() {
    let seed = seed(3);
    for (install_operation, purpose) in [
        (0, Purpose::Contribution),
        (4, Purpose::Ballot),
        (5, Purpose::Release),
    ] {
        let mut state = State::default();
        install(&mut state, install_operation, &seed);
        for (operation, domain) in [1, 2].into_iter().zip(purpose.domains()) {
            let Some(domain) = domain else {
                assert!(state.command(operation, 64).is_err());
                continue;
            };
            let expected =
                hash_foundation_tuple_512(domain, &[CanonicalItem::variable_bytes(seed).unwrap()])
                    .unwrap()
                    .into_bytes();
            assert_eq!(read(&mut state, operation, &[64]), expected);
        }
    }
    // Every stream of every purpose has its own domain.
    let mut domains: Vec<_> = [Purpose::Contribution, Purpose::Ballot, Purpose::Release]
        .into_iter()
        .flat_map(|purpose| purpose.domains())
        .flatten()
        .collect();
    domains.sort_unstable();
    domains.dedup();
    assert_eq!(domains.len(), 5);
}

#[test]
fn replays_the_same_bytes_whatever_the_request_lengths_and_interleaving() {
    let seed = seed(11);
    let mut first = State::default();
    install(&mut first, 4, &seed);
    let encryption = read(&mut first, 1, &[1, 17, REQUEST_BYTES, 3]);
    let proof = read(&mut first, 2, &[REQUEST_BYTES - 1, 2]);
    // A restarted operation reads both streams again in another order.
    let mut restarted = State::default();
    install(&mut restarted, 4, &seed);
    assert_eq!(read(&mut restarted, 2, &[REQUEST_BYTES, 1]), proof);
    assert_eq!(read(&mut restarted, 1, &[REQUEST_BYTES, 21]), encryption);
    assert_ne!(encryption[..64], proof[..64]);
    // A seed that differs in its last bit yields other streams.
    let mut changed = seed;
    changed[SEED_BYTES - 1] ^= 1;
    let mut other = State::default();
    install(&mut other, 4, &changed);
    assert_ne!(read(&mut other, 1, &[64]), encryption[..64]);
}

#[test]
fn is_ready_only_for_its_installed_and_undrawn_purpose() {
    let mut state = State::default();
    assert!(!state.ready(Purpose::Release));
    install(&mut state, 5, &seed(7));
    assert!(state.ready(Purpose::Release));
    assert!(!state.ready(Purpose::Ballot));
    read(&mut state, 2, &[1]);
    assert!(!state.ready(Purpose::Release));
    state.command(3, 0).unwrap();
    install(&mut state, 5, &seed(7));
    assert!(state.ready(Purpose::Release));
}

#[test]
fn refuses_reads_without_a_seed_oversized_requests_and_a_second_seed() {
    let mut state = State::default();
    assert!(state.command(1, 1).is_err());
    assert!(state.command(0, SEED_BYTES - 1).is_err());
    install(&mut state, 0, &seed(5));
    for operation in [0, 4, 5] {
        assert!(state.command(operation, SEED_BYTES).is_err());
    }
    assert!(state.command(1, 0).is_err());
    assert!(state.command(2, REQUEST_BYTES + 1).is_err());
    assert!(state.command(6, 1).is_err());
    state.command(1, 8).unwrap();
    // A refused command clears the previous output.
    assert!(state.command(3, 1).is_err());
    assert!(state.output.iter().all(|value| *value == 0));
    state.command(3, 0).unwrap();
    assert!(state.streams.is_none());
    assert!(state.command(2, 1).is_err());
}
