use super::*;

fn message(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 131 % 251) as u8).collect()
}
fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Independent Python hashlib/OpenSSL SHAKE256 vectors over the literal
// domain padded with zeroes to 64 bytes, followed by each message, which
// every chunking absorbs alike.
#[test]
fn matches_independent_shake256_vectors() {
    for (input, expected) in [
        (
            vec![],
            "d8c940acc0de8cce41ce55579e760be740b59361be7f2d66c9e5b45197cfc49d0b92f3ced58af3c303faa81ca9545ac3f108df366592934e21daa45b4c470945",
        ),
        (
            b"abc".to_vec(),
            "57e23be26c7f5327983c44e9d60efac3d2b526474de65a541097c38ef870b6ab189972f952282d7b3115be2b1bd7a9ff30e3237e7f8337d87d972c4a76595efd",
        ),
        (
            (0..137).collect(),
            "47cedf4b667d5975c9e3f0bff6f5b8a6a489624ab70b9b2c6659d778adbde3858d7994f47e65976807d0484089ef28af57367b00256e9482f1e3b9b913e1a95b",
        ),
        (
            message(4097),
            "e4059e37692e41da24faf325e7771aa1b3f2b1e96030c22cc6d65e6eb62e4821d367ed71bee1957823914ca97e83bdeaa97c9328f8bb6cd9b6723f518d4ca380",
        ),
    ] {
        assert_eq!(hexadecimal(&ProtocolHash::digest(&input)), expected);
        for chunk in [1, 3, 7, 8, 9, 64, 135, 136, 137] {
            let mut hash = ProtocolHash::new();
            for part in input.chunks(chunk) {
                hash.update(part);
            }
            assert_eq!(hexadecimal(&hash.finalize()), expected, "chunk {chunk}");
        }
    }
}

#[test]
fn checkpoints_continue_across_absorption_boundaries() {
    let input = message(4097);
    let expected = "e4059e37692e41da24faf325e7771aa1b3f2b1e96030c22cc6d65e6eb62e4821d367ed71bee1957823914ca97e83bdeaa97c9328f8bb6cd9b6723f518d4ca380";
    for split in [0, 1, 71, 72, 73, 135, 136, 137, 207, 208, 209, 4096, 4097] {
        let mut first = ProtocolHash::new();
        first.update(&input[..split]);
        let state = first.serialize();
        assert_eq!(
            usize::from(state[200]),
            ProtocolHash::absorption_cursor_after(split)
        );
        let mut restored = ProtocolHash::deserialize(&state).unwrap();
        for chunk in input[split..].chunks(17) {
            restored.update(chunk);
        }
        assert_eq!(hexadecimal(&restored.finalize()), expected, "split {split}");
    }
    let mut state = ProtocolHash::new().serialize();
    for cursor in [136, 137, 255] {
        state[200] = cursor;
        assert!(ProtocolHash::deserialize(&state).is_none());
    }
}
