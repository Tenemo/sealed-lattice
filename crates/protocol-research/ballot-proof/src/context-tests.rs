use super::*;
use protocol_foundations::SIGNING_PUBLIC_KEY_BYTES;
#[test]
fn proof_roles_separate_every_variable_context_input() {
    let owner = derive_participant_identity(&[7; SIGNING_PUBLIC_KEY_BYTES]).unwrap();
    let other_owner = derive_participant_identity(&[8; SIGNING_PUBLIC_KEY_BYTES]).unwrap();
    let original = encode_role(owner, [1; 64], [2; 64], [3; 64], 0).unwrap();
    for changed in [
        encode_role(other_owner, [1; 64], [2; 64], [3; 64], 0),
        encode_role(owner, [4; 64], [2; 64], [3; 64], 0),
        encode_role(owner, [1; 64], [4; 64], [3; 64], 0),
        encode_role(owner, [1; 64], [2; 64], [4; 64], 0),
        encode_role(owner, [1; 64], [2; 64], [3; 64], 1),
    ] {
        assert_ne!(changed.unwrap(), original);
    }
    assert!(original.len() <= 1024);
    assert_eq!(original.len(), 404);
    let tuple = CanonicalTuple::decode(&original, &Default::default()).unwrap();
    assert_eq!(tuple.items.len(), 6);
    assert_eq!(
        tuple.items[0].variable_value_bytes().unwrap(),
        b"sealed-lattice/ballot-proof/v2"
    );
    assert_eq!(
        tuple.items[1].item_type(),
        protocol_foundations::foundation::CanonicalItemType::Ascii
    );
    assert_eq!(
        tuple.items[1].variable_value_bytes().unwrap(),
        owner.to_lowercase_hex().as_bytes()
    );
    assert!(encode_role(owner, [1; 64], [2; 64], [3; 64], usize::MAX).is_err());
}
