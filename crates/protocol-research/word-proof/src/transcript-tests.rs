use super::*;
#[test]
fn retained_unused_message_bytes_bind_the_next_state() {
    let length = 4096;
    let mut left = Transcript::new(b"test", [3; 64], length);
    let mut right = Transcript::new(b"test", [3; 64], length);
    left.next();
    right.next();
    right.message[length - 1] ^= 1;
    assert_eq!(
        challenge(&left.message, 0, false),
        challenge(&right.message, 0, false)
    );
    left.respond_with_salt(&[b"root"], [7; 128]);
    right.respond_with_salt(&[b"root"], [7; 128]);
    left.next();
    right.next();
    assert_ne!(left.message, right.message);
}
