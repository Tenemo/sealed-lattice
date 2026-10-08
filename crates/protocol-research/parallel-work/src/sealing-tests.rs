use super::*;

const CONTEXT: &[u8] = b"sealed-lattice/sealing-test";
const PLAINTEXT: &[u8] = b"retained record";

// The record that Node's independent AES-256-GCM seals from the plaintext
// under thirty-two 0x07 bytes, the zero nonce and the context.
const KNOWN: &str = "13bdd0d392fc6e8cc175ea07ab092f8fbb834c769a70f5638eb082a225cbd9";

fn known() -> Vec<u8> {
    (0..KNOWN.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&KNOWN[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn opens_a_record_that_another_implementation_sealed_and_only_that_record() {
    let key = [7; KEY_BYTES];
    let sealed = known();
    assert_eq!(sealed.len(), PLAINTEXT.len() + TAG_BYTES);
    assert_eq!(open(&key, CONTEXT, &sealed).unwrap().as_slice(), PLAINTEXT);
    let mut other_key = key;
    other_key[KEY_BYTES - 1] ^= 1;
    assert!(open(&other_key, CONTEXT, &sealed).is_none());
    assert!(open(&key, b"sealed-lattice/sealing-other", &sealed).is_none());
    for position in [0, PLAINTEXT.len(), sealed.len() - 1] {
        let mut changed = sealed.clone();
        changed[position] ^= 1;
        assert!(open(&key, CONTEXT, &changed).is_none());
    }
    assert!(open(&key, CONTEXT, &sealed[..sealed.len() - 1]).is_none());
    assert!(open(&key, CONTEXT, &[]).is_none());
}

#[test]
fn seals_each_record_under_its_own_fresh_key() {
    let first = seal(PLAINTEXT, CONTEXT);
    let second = seal(PLAINTEXT, CONTEXT);
    assert_ne!(*first.key, *second.key);
    assert_ne!(first.bytes, second.bytes);
    for sealed in [&first, &second] {
        assert_eq!(sealed.bytes.len(), PLAINTEXT.len() + TAG_BYTES);
        assert_eq!(
            open(&sealed.key, CONTEXT, &sealed.bytes)
                .unwrap()
                .as_slice(),
            PLAINTEXT
        );
    }
    assert!(open(&first.key, CONTEXT, &second.bytes).is_none());
    let empty = seal(&[], CONTEXT);
    assert_eq!(empty.bytes.len(), TAG_BYTES);
    assert!(open(&empty.key, CONTEXT, &empty.bytes).unwrap().is_empty());
}
