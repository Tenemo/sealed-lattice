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
            "29adf64c397cdd7c2a12c1394f67914da8987f45a7101fd4cd7b39eb289ed7df625620af7fd1951404e3042f65b8fb91a69ff9c1ca7ef0975b76f136a9ca6e96",
        ),
        (
            b"abc".to_vec(),
            "a8df42eb0a2bad96d4d5fde4a7896c5f31287bf651801f3335038cd92aaf3b7f35c81fc12490ef51cd4efb534428f6abc938956e876ea85dd5c669bf484d86fc",
        ),
        (
            (0..137).collect(),
            "22144d386270491cf53fe8e489fc2d5be1e79520869e05c840eb8a05c509364ee3c2d369e2a91ceb6c25b1ca0e4b22ed96fe7b73adbbbbc42e7c6fffc5985ca4",
        ),
        (
            message(4097),
            "14a76849aa7c6fd964ce1df16a2683f1c00a1998b5def2934db5b24d017e85d461c729927b4038cad29c986d0b5ae51b5a3a14aaa9d63a81fa1891ed099d7972",
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
    let expected = "14a76849aa7c6fd964ce1df16a2683f1c00a1998b5def2934db5b24d017e85d461c729927b4038cad29c986d0b5ae51b5a3a14aaa9d63a81fa1891ed099d7972";
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
