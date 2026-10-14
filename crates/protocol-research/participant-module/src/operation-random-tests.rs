use super::*;
use protocol_foundations::foundation::hash_foundation_tuple_512;

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

// SHAKE256 prefixes computed outside this crate from the canonical tuple of
// each domain and the seed 3 + 29i. A retained seed must keep deriving the
// same bytes, so no change to the framing may alter them.
#[test]
fn keeps_every_stream_prefix_byte_identical() {
    let seed = seed(3);
    for (domain, prefix) in [
        (
            "sealed-lattice/contribution-witness-randomness/v1",
            "2297d650533fa5fbb4375d4079f7c2c93021294f1af2e8a87e8c726fcde00485",
        ),
        (
            "sealed-lattice/contribution-proof-randomness/v1",
            "6f1b400635987db4ec310467d3c18504a8c20f10db97b3ce363fbd6ab31619e9",
        ),
        (
            "sealed-lattice/ballot-encryption-randomness/v1",
            "6217f66dc66ad2d96f479d088afc2bfa3c3de796225f151400878c8427816cb6",
        ),
        (
            "sealed-lattice/ballot-proof-randomness/v1",
            "2a797736edb78035078707cc60556bc6c4e13cc97c7baae2b89be4cb3f9a3ecc",
        ),
        (
            "sealed-lattice/release-proof-randomness/v1",
            "21623b8240dbaa983801f07031793a9f99024e41941237cf253e01b42539bb3c",
        ),
    ] {
        let mut bytes = [0; 32];
        stream(domain, &seed).read(&mut bytes);
        let actual: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(actual, prefix, "{domain}");
    }
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
