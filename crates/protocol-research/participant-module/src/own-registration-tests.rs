//! The verifier of the participant's own registration: the registration
//! verifies once against its signed poll, and malformed, early and repeated
//! commands are refused without replacing what it holds.
use super::{CONTROL_BYTES, State};
use crate::registration_fixture::{RUNTIME, Record, registration};
use protocol_foundations::{
    Refusal,
    poll::{MAXIMUM_POLL_BYTES, SignedPoll},
    registration::CHUNK_LIMIT,
};

// The begin input: the poll's identity and runtime, its body after a
// four-byte length and its signature, then the registration header after a
// four-byte length and the header's signature.
fn begin_input(packet: &SignedPoll, record: &Record) -> Vec<u8> {
    let mut bytes = [packet.identity, RUNTIME].concat();
    bytes.extend((packet.body.len() as u32).to_le_bytes());
    bytes.extend(&packet.body);
    bytes.extend(packet.signature);
    bytes.extend((record.header.len() as u32).to_le_bytes());
    bytes.extend(&record.header);
    bytes.extend(&record.signature);
    bytes
}

// Writes the bytes to the input buffer and runs the command over them.
fn run(state: &mut State, operation: u32, bytes: &[u8]) -> Result<(), Refusal> {
    state.input[..bytes.len()].copy_from_slice(bytes);
    state.command(operation, bytes.len())
}

#[test]
fn refuses_malformed_and_early_commands() {
    let mut state = State::new();
    // A begin shorter than its fixed prefix, or naming a poll beyond the
    // poll bound.
    assert!(matches!(run(&mut state, 0, &[0; 131]), Err(Refusal::Shape)));
    let mut oversized = vec![0; 132];
    oversized[128..].copy_from_slice(&(MAXIMUM_POLL_BYTES as u32 + 1).to_le_bytes());
    assert!(matches!(
        run(&mut state, 0, &oversized),
        Err(Refusal::Shape)
    ));
    // A length beyond the input buffer.
    assert!(matches!(
        state.command(0, CONTROL_BYTES + 1),
        Err(Refusal::Shape)
    ));
    // Key, source and finish commands before any begin.
    assert!(matches!(
        run(&mut state, 1, &[1; 16]),
        Err(Refusal::Consumed)
    ));
    assert!(matches!(run(&mut state, 2, &[]), Err(Refusal::Consumed)));
    assert!(matches!(
        run(&mut state, 3, &[0; 6]),
        Err(Refusal::Consumed)
    ));
    assert!(matches!(run(&mut state, 4, &[]), Err(Refusal::Consumed)));
    // Unknown operations, and finishing with input.
    for operation in [5, u32::MAX] {
        assert!(matches!(
            run(&mut state, operation, &[]),
            Err(Refusal::Shape)
        ));
    }
    assert!(matches!(run(&mut state, 2, &[0]), Err(Refusal::Shape)));
    assert!(state.poll.is_none() && state.pending.is_none() && state.verified.is_none());
}

#[test]
fn verifies_the_registration_once_against_its_signed_poll() {
    let (packet, poll, record, _) = registration();
    let input = begin_input(&packet, &record);
    let mut state = State::new();
    // A changed poll signature and a trailing byte are refused, and leave
    // the begin open.
    let mut changed = input.clone();
    changed[132 + packet.body.len()] ^= 1;
    assert!(run(&mut state, 0, &changed).is_err());
    assert!(matches!(
        run(&mut state, 0, &[input.as_slice(), &[0]].concat()),
        Err(Refusal::Shape)
    ));
    assert!(state.poll.is_none());
    run(&mut state, 0, &input).unwrap();
    assert_eq!(state.options, poll.manifest().option_count());
    // No later begin replaces the poll.
    assert!(matches!(run(&mut state, 0, &input), Err(Refusal::Consumed)));
    for part in record.key.chunks(CHUNK_LIMIT) {
        run(&mut state, 1, part).unwrap();
    }
    run(&mut state, 2, &[]).unwrap();
    assert!(run(&mut state, 4, &[]).is_err());
    // A failed finalization consumes its pending record, so complete a fresh verifier.
    let mut state = State::new();
    run(&mut state, 0, &input).unwrap();
    for part in record.key.chunks(CHUNK_LIMIT) {
        run(&mut state, 1, part).unwrap();
    }
    run(&mut state, 2, &[]).unwrap();
    for part in record.sources.chunks(CHUNK_LIMIT) {
        run(&mut state, 3, part).unwrap();
    }
    run(&mut state, 4, &[]).unwrap();
    let verified = state.verified.clone().expect("A verified registration");
    assert_eq!(verified.header().encode().unwrap(), record.header);
    // A verified registration takes no further command.
    for operation in [0, 1, 2, 3, 4] {
        assert!(matches!(
            run(&mut state, operation, &[]),
            Err(Refusal::Consumed)
        ));
    }
}
