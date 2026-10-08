use super::*;
use registration_credentials::foundation::hash_foundation_tuple_512;

const PURPOSES: [(u32, Purpose); 3] = [
    (0, Purpose::Contribution),
    (4, Purpose::Ballot),
    (5, Purpose::Release),
];
const DRAWS: [random::Purpose; 3] = [
    random::Purpose::Witness,
    random::Purpose::Ballot,
    random::Purpose::Proof,
];

fn seed(first: u8) -> [u8; SEED_BYTES] {
    std::array::from_fn(|index| first.wrapping_add((index * 29) as u8))
}

fn install(state: &mut State, operation: u32, seed: &[u8; SEED_BYTES]) {
    state.input.copy_from_slice(seed);
    state.command(operation, SEED_BYTES).unwrap();
    assert!(state.input.iter().all(|value| *value == 0));
}

// Reads the whole stream prefix through draws of the given lengths.
fn draw(state: &mut State, purpose: random::Purpose, lengths: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &length in lengths {
        let mut drawn = vec![0; length];
        assert!(state.serve(purpose, &mut drawn));
        bytes.extend_from_slice(&drawn);
    }
    bytes
}

// Whether the state refuses the draw and leaves its bytes and the counts
// untouched.
fn refuses(state: &mut State, purpose: random::Purpose) -> bool {
    let drawn = state.drawn;
    let mut bytes = [0; 64];
    !state.serve(purpose, &mut bytes) && bytes == [0; 64] && state.drawn == drawn
}

#[test]
fn frames_each_stream_as_the_foundation_hash_of_its_domain_and_seed() {
    let seed = seed(3);
    for (operation, purpose) in PURPOSES {
        let mut state = State::default();
        install(&mut state, operation, &seed);
        let draws = [purpose.first(), Some(random::Purpose::Proof)];
        for (draw_purpose, domain) in draws.into_iter().zip(purpose.domains()) {
            assert_eq!(draw_purpose.is_some(), domain.is_some());
            let (Some(draw_purpose), Some(domain)) = (draw_purpose, domain) else {
                continue;
            };
            let expected =
                hash_foundation_tuple_512(domain, &[CanonicalItem::variable_bytes(seed).unwrap()])
                    .unwrap()
                    .into_bytes();
            assert_eq!(draw(&mut state, draw_purpose, &[64]), expected);
        }
    }
    // Every stream of every purpose has its own domain.
    let mut domains: Vec<_> = PURPOSES
        .into_iter()
        .flat_map(|(_, purpose)| purpose.domains())
        .flatten()
        .collect();
    domains.sort_unstable();
    domains.dedup();
    assert_eq!(domains.len(), 5);
}

#[test]
fn replays_the_same_bytes_whatever_the_draw_lengths_and_interleaving() {
    let seed = seed(11);
    let mut first = State::default();
    install(&mut first, 4, &seed);
    let encryption = draw(&mut first, random::Purpose::Ballot, &[1, 17, 70_000, 3]);
    let proof = draw(&mut first, random::Purpose::Proof, &[65_535, 2]);
    // A restarted operation reads both streams again in another order.
    let mut restarted = State::default();
    install(&mut restarted, 4, &seed);
    assert_eq!(
        draw(&mut restarted, random::Purpose::Proof, &[65_536, 1]),
        proof
    );
    assert_eq!(
        draw(&mut restarted, random::Purpose::Ballot, &[0, 70_021]),
        encryption
    );
    assert_ne!(encryption[..64], proof[..64]);
    // A seed that differs in its last bit yields other streams.
    let mut changed = seed;
    changed[SEED_BYTES - 1] ^= 1;
    let mut other = State::default();
    install(&mut other, 4, &changed);
    assert_ne!(
        draw(&mut other, random::Purpose::Ballot, &[64]),
        encryption[..64]
    );
}

#[test]
fn refuses_every_draw_its_operation_does_not_make() {
    let mut state = State::default();
    for purpose in DRAWS {
        assert!(refuses(&mut state, purpose));
    }
    for (operation, purpose) in PURPOSES {
        install(&mut state, operation, &seed(5));
        for draw_purpose in DRAWS {
            let made =
                draw_purpose == random::Purpose::Proof || purpose.first() == Some(draw_purpose);
            assert_eq!(
                refuses(&mut state, draw_purpose),
                !made,
                "{purpose:?} {draw_purpose:?}"
            );
        }
        state.command(3, 0).unwrap();
        for draw_purpose in DRAWS {
            assert!(refuses(&mut state, draw_purpose));
        }
    }
}

#[test]
fn counts_each_stream_until_the_next_seed_and_is_ready_only_while_undrawn() {
    let mut state = State::default();
    assert!(!state.ready(Purpose::Contribution));
    install(&mut state, 0, &seed(7));
    assert!(state.ready(Purpose::Contribution));
    assert!(!state.ready(Purpose::Ballot));
    draw(&mut state, random::Purpose::Witness, &[5, 9]);
    draw(&mut state, random::Purpose::Proof, &[3]);
    assert_eq!(state.drawn, [14, 3]);
    assert!(!state.ready(Purpose::Contribution));
    // The counts outlast the discarded streams and restart with the next seed.
    state.command(3, 0).unwrap();
    assert_eq!(state.drawn, [14, 3]);
    install(&mut state, 5, &seed(7));
    assert_eq!(state.drawn, [0, 0]);
    assert!(state.ready(Purpose::Release));
}

#[test]
fn refuses_a_short_or_second_seed_and_every_other_command_and_clears_the_input() {
    let mut state = State::default();
    state.input.fill(9);
    assert!(state.command(0, SEED_BYTES - 1).is_err());
    assert!(state.input.iter().all(|value| *value == 0));
    install(&mut state, 0, &seed(5));
    for operation in [0, 4, 5] {
        state.input.fill(9);
        assert!(state.command(operation, SEED_BYTES).is_err());
        assert!(state.input.iter().all(|value| *value == 0));
    }
    for operation in [1, 2, 6] {
        assert!(state.command(operation, 1).is_err());
    }
    assert!(state.command(3, 1).is_err());
    assert!(state.streams.is_some());
    state.command(3, 0).unwrap();
    assert!(state.streams.is_none());
}
