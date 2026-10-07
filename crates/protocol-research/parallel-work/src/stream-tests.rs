use super::*;

fn bytes(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 131 % 251) as u8).collect()
}
fn direct(sponge: Sponge, input: &[u8]) -> [u8; 64] {
    let mut local = Local::new(sponge);
    local.update(input);
    local.finish()
}

// Held here or by a helper, a stream's digest is the direct one for any
// division of the bytes, including empty and batch-sized parts.
#[test]
fn digests_match_the_direct_hash_for_every_division() {
    let input = bytes(5 * BATCH_BYTES + 77);
    for sponge in [Sponge::ProtocolHash, Sponge::Shake256] {
        for remote in [false, true] {
            for division in [1, 71, BATCH_BYTES - 1, BATCH_BYTES, 3 * BATCH_BYTES + 5] {
                let mut stream = HashStream::held(sponge, remote);
                stream.update(&[]);
                for part in input.chunks(division) {
                    stream.update(part);
                }
                assert_eq!(
                    stream.finish(),
                    direct(sponge, &input),
                    "{sponge:?} {division}"
                );
            }
            assert_eq!(
                HashStream::held(sponge, remote).finish(),
                direct(sponge, &[])
            );
            // Updates longer than one absorption, after gathered bytes.
            let long = bytes(3 * SEND_BYTES + 5);
            let mut stream = HashStream::held(sponge, remote);
            stream.update(&long[..7]);
            stream.update(&long[7..2 * SEND_BYTES + 1]);
            stream.update(&long[2 * SEND_BYTES + 1..]);
            assert_eq!(stream.finish(), direct(sponge, &long));
        }
    }
}

// Independent prefixed and direct SHAKE256 vectors of "abc".
#[test]
fn digests_match_independent_vectors() {
    let hexadecimal = |digest: [u8; 64]| {
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    for remote in [false, true] {
        let mut protocol = HashStream::held(Sponge::ProtocolHash, remote);
        protocol.update(b"abc");
        assert_eq!(
            hexadecimal(protocol.finish()),
            "a8df42eb0a2bad96d4d5fde4a7896c5f31287bf651801f3335038cd92aaf3b7f35c81fc12490ef51cd4efb534428f6abc938956e876ea85dd5c669bf484d86fc"
        );
        let mut shake = HashStream::held(Sponge::Shake256, remote);
        shake.update(b"abc");
        assert_eq!(
            hexadecimal(shake.finish()),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }
}

// Streams held by helpers interleave without sharing state, and a
// dropped stream leaves no state behind.
#[test]
fn interleaved_and_dropped_streams_stay_separate() {
    let first = bytes(3 * BATCH_BYTES);
    let second = bytes(BATCH_BYTES + 9);
    let mut one = HashStream::held(Sponge::ProtocolHash, true);
    let mut two = HashStream::held(Sponge::Shake256, true);
    let mut abandoned = HashStream::held(Sponge::ProtocolHash, true);
    // Three parts of each, the last of the second only nine bytes.
    for (left, right) in first
        .chunks(BATCH_BYTES)
        .zip(second.chunks(BATCH_BYTES / 2))
    {
        one.update(left);
        abandoned.update(right);
        two.update(right);
    }
    drop(abandoned);
    assert_eq!(one.finish(), direct(Sponge::ProtocolHash, &first));
    assert_eq!(two.finish(), direct(Sponge::Shake256, &second));
    STREAMS.with(|streams| assert!(streams.borrow().is_empty()));
}

// Digests started before earlier ones are waited for resolve, in any
// order, to the direct ones, and an unwaited digest leaves no state
// behind.
#[test]
fn deferred_digests_resolve_in_any_order() {
    let inputs = [0, 7, BATCH_BYTES, 3 * BATCH_BYTES + 1, SEND_BYTES + 3].map(bytes);
    for remote in [false, true] {
        let mut pending: Vec<_> = inputs
            .iter()
            .enumerate()
            .map(|(position, input)| {
                let sponge = [Sponge::ProtocolHash, Sponge::Shake256][position % 2];
                let mut stream = HashStream::held(sponge, remote);
                stream.update(input);
                (sponge, input, stream.finish_later())
            })
            .collect();
        let mut abandoned = HashStream::held(Sponge::Shake256, remote);
        abandoned.update(&inputs[3]);
        drop(abandoned.finish_later());
        // The latest first, then the earliest.
        let earliest = pending.remove(0);
        for (sponge, input, digest) in pending.into_iter().rev().chain([earliest]) {
            assert_eq!(digest.wait(), direct(sponge, input), "{remote}");
        }
    }
    STREAMS.with(|streams| assert!(streams.borrow().is_empty()));
}
