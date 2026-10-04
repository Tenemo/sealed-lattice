//! Real scalar-controller refusals without fabricating a verified holder.
//! A canonical synthetic header can start a verifier, but absent its proof
//! body it establishes no predecessor and no opening authority.
use crate::browser::State;
use word_verifier::{HEADER_LENGTH, engine::CHUNK_LIMIT};

fn pending_header() -> (seed_sharing_proof::statement::Statement, Vec<u8>, Vec<u8>) {
    let expected = seed_sharing_proof::fixture::create().0;
    let bytes = expected.encode().unwrap();
    let relation = seed_sharing_proof::layout::Layout::new(bytes.len()).relation;
    let mut context =
        word_proof::transcript::context_hasher(&relation, seed_sharing_proof::verification::ROLE);
    context.update(&bytes);
    let mut header = vec![0; HEADER_LENGTH];
    header[..4].copy_from_slice(relation.proof_magic);
    header[4..68].copy_from_slice(&expected.digest().unwrap());
    header[68..132].copy_from_slice(&context.finalize());
    (expected, bytes, header)
}

fn pending_source() -> State {
    let (_, _, header) = pending_header();
    let mut state = State::default();
    state.input[..HEADER_LENGTH].copy_from_slice(&header);
    assert_eq!(state.source_begin(0, HEADER_LENGTH), 0);
    state
}

fn assert_sticky(state: &mut State, first: u32) {
    assert_ne!(first, 0);
    assert_eq!(state.source_begin(0, HEADER_LENGTH), first);
    assert_eq!(state.source_begin(1, HEADER_LENGTH), first);
    assert_eq!(state.source_push(0), first);
    assert_eq!(state.source_finish(), first);
    assert_eq!(state.verifier_begin(0, HEADER_LENGTH), first);
    assert_eq!(state.verifier_push(0), first);
    assert_eq!(state.verifier_finish(), first);
    assert_eq!(state.prover_begin(), first);
    assert_eq!(state.prover_step(), first);
    assert_eq!(state.prover_next_output(), first);
    assert_eq!(state.prover_acknowledge_output(), first);
    assert_eq!(state.prover_phase(), 0);
}

#[test]
fn omitted_first_source_cannot_be_replaced_by_second_source_or_opening_work() {
    let attempts: [fn(&mut State) -> u32; 8] = [
        |state| state.source_begin(1, HEADER_LENGTH),
        |state| state.source_begin(2, HEADER_LENGTH),
        State::source_finish,
        |state| state.verifier_begin(0, HEADER_LENGTH),
        State::prover_begin,
        State::prover_step,
        State::prover_next_output,
        State::prover_acknowledge_output,
    ];
    for attempt in attempts {
        let mut state = State::default();
        assert_eq!(attempt(&mut state), 6);
        assert_sticky(&mut state, 6);
    }
}

#[test]
fn incomplete_first_source_blocks_repeated_start_second_source_and_generation() {
    let attempts: [fn(&mut State) -> u32; 5] = [
        |state| state.source_begin(0, HEADER_LENGTH),
        |state| state.source_begin(1, HEADER_LENGTH),
        |state| state.verifier_begin(0, HEADER_LENGTH),
        State::prover_begin,
        State::prover_acknowledge_output,
    ];
    for attempt in attempts {
        let mut state = pending_source();
        assert_eq!(attempt(&mut state), 6);
        assert_sticky(&mut state, 6);
    }
}

#[test]
fn header_or_partial_record_is_not_a_verified_predecessor_at_end_of_input() {
    for bytes in [0, 1, 3] {
        let mut state = pending_source();
        state.input[..bytes].fill(0);
        assert_eq!(state.source_push(bytes), 0);
        assert_eq!(state.source_finish(), 5);
        // In particular, a second finish cannot turn the pending header's
        // successful start into a completed holder or replace the first error.
        assert_sticky(&mut state, 5);
    }
}

#[test]
fn malformed_stream_count_and_oversized_chunks_preserve_the_owning_refusal() {
    let mut malformed = pending_source();
    malformed.input[..4].fill(0);
    assert_eq!(malformed.source_push(4), 1);
    assert_sticky(&mut malformed, 1);
    for length in [CHUNK_LIMIT + 1, usize::MAX] {
        let mut state = pending_source();
        assert_eq!(state.source_push(length), 2);
        assert_sticky(&mut state, 2);
    }
}

#[test]
fn source_header_bounds_refuse_before_any_predecessor_can_be_started() {
    for length in [
        0,
        HEADER_LENGTH - 1,
        HEADER_LENGTH + 1,
        CHUNK_LIMIT + 1,
        usize::MAX,
    ] {
        let mut state = State::default();
        assert_eq!(state.source_begin(0, length), 2);
        assert_sticky(&mut state, 2);
    }
    let mut state = State::default();
    // A full-sized all-zero header has no valid magic; a host's declared
    // byte count does not establish proof verification.
    assert_eq!(state.source_begin(0, HEADER_LENGTH), 1);
    assert_sticky(&mut state, 1);
}

struct PrefixThenFailure {
    prefix: Vec<u8>,
    read: usize,
    calls: usize,
}
impl std::io::Read for PrefixThenFailure {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        if self.read == self.prefix.len() {
            return Err(std::io::Error::other("fixture transport failure"));
        }
        let count = output.len().min(3).min(self.prefix.len() - self.read);
        output[..count].copy_from_slice(&self.prefix[self.read..self.read + count]);
        self.read += count;
        Ok(count)
    }
}

#[test]
fn native_stream_keeps_partial_io_failure_distinct_from_truncation_or_wrong_statement() {
    use crate::predecessor;
    use seed_sharing_proof::verification::VerificationError;
    use std::io::Cursor;
    use word_verifier::Refusal;
    let (expected, supplied, header) = pending_header();
    for length in [HEADER_LENGTH - 1, HEADER_LENGTH + 3] {
        let mut prefix = header.clone();
        prefix.resize(length, 0);
        let mut broken = PrefixThenFailure {
            prefix,
            read: 0,
            calls: 0,
        };
        assert!(matches!(
            predecessor::verify(&mut broken, &expected, &supplied),
            Err(VerificationError::Read(_))
        ));
        assert_eq!(broken.read, length);
    }
    assert!(matches!(
        predecessor::verify(
            &mut Cursor::new(&header[..HEADER_LENGTH - 1]),
            &expected,
            &supplied
        ),
        Err(VerificationError::Refused(Refusal::Length))
    ));
    let mut changed = supplied;
    changed[0] ^= 1;
    let mut unread = PrefixThenFailure {
        prefix: header,
        read: 0,
        calls: 0,
    };
    assert!(matches!(
        predecessor::verify(&mut unread, &expected, &changed),
        Err(VerificationError::Refused(Refusal::Context))
    ));
    assert_eq!(unread.calls, 0);
}
