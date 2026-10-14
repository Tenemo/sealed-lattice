use super::*;
use crate::foundation::hash_foundation_tuple_512;

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn matches_the_foundation_tuple_hash_in_any_fragmentation() {
    let payload: Vec<u8> = (0..1000_u32)
        .map(|index| (index * 37 % 251) as u8)
        .collect();
    let prefix = [
        CanonicalItem::hash512([7; 64]),
        CanonicalItem::unsigned64(9),
    ];
    let mut items = prefix.to_vec();
    items.push(CanonicalItem::variable_bytes(&payload).unwrap());
    let expected = hash_foundation_tuple_512(PUBLIC_POLYNOMIAL_DOMAIN, &items)
        .unwrap()
        .into_bytes();
    for fragment in [1, 17, 999, 1000] {
        let mut hasher =
            IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &prefix, payload.len()).unwrap();
        for part in payload.chunks(fragment) {
            hasher.absorb(part).unwrap();
        }
        assert_eq!(hasher.finish().unwrap(), expected);
    }
}

#[test]
fn matches_independent_shake256_vectors() {
    // SHAKE256 over the canonical tuple, computed outside Rust.
    assert_eq!(
        hexadecimal(&identity(PUBLIC_POLYNOMIAL_DOMAIN, b"").unwrap()),
        "ae4e93421e5300b846a0f24f8a8f637b190afbdd215153a94708eedf948717a047815cfac7aa5e4a01c4d9a6c9daabacdf892ec65fe2e95befb100ca4497c2e2"
    );
    assert_eq!(
        hexadecimal(&identity(PUBLIC_POLYNOMIAL_DOMAIN, &[0, 1, 2, 255]).unwrap()),
        "584f8823279d9ab61e689aa7513a466e917e4204e931b061ea7352d11e6b21d95533cffd89c7bec1cb76a06faf744d37548f2640775aac8781364b2e5d284dae"
    );
}

#[test]
fn refuses_a_short_long_or_empty_domain_payload() {
    let mut hasher = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], 2).unwrap();
    hasher.absorb(&[1]).unwrap();
    assert!(hasher.absorb(&[2, 3]).is_err());
    let mut short = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], 2).unwrap();
    short.absorb(&[1]).unwrap();
    assert!(short.finish().is_err());
    let mut short = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], 2).unwrap();
    short.absorb(&[1]).unwrap();
    assert!(short.finish_later().is_err());
    assert!(IdentityHasher::new("", &[], 0).is_err());
}

#[test]
fn frames_a_fixed_or_variable_payload_as_its_canonical_raw_byte_item() {
    let prefix = [CanonicalItem::hash512([7; 64])];
    let payload = [5; 70];
    for (trailing, item) in [
        (
            Trailing::Fixed(payload.len()),
            CanonicalItem::fixed_bytes(payload).unwrap(),
        ),
        (
            Trailing::Variable(payload.len()),
            CanonicalItem::variable_bytes(payload).unwrap(),
        ),
    ] {
        let mut framed = framing(PUBLIC_POLYNOMIAL_DOMAIN, &prefix, trailing).unwrap();
        framed.extend_from_slice(&payload);
        let mut items = vec![CanonicalItem::nonempty_ascii(PUBLIC_POLYNOMIAL_DOMAIN).unwrap()];
        items.extend_from_slice(&prefix);
        items.push(item);
        let canonical = CanonicalTuple::new(CANONICAL_TUPLE_SCHEMA_IDENTIFIER, items)
            .encode()
            .unwrap();
        assert_eq!(framed, canonical);
    }
    assert!(framing("", &prefix, Trailing::Fixed(1)).is_err());
}
