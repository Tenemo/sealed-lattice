use super::*;

#[test]
fn proof_role_separates_every_verified_context_input() {
    let owner = derive_participant_identity(&[7; 1952]).unwrap();
    let other_owner = derive_participant_identity(&[8; 1952]).unwrap();
    let original = encode_release_proof_role(owner, [1; 64], [2; 64], [3; 64], [4; 64], 0).unwrap();
    for changed in [
        encode_release_proof_role(other_owner, [1; 64], [2; 64], [3; 64], [4; 64], 0),
        encode_release_proof_role(owner, [9; 64], [2; 64], [3; 64], [4; 64], 0),
        encode_release_proof_role(owner, [1; 64], [9; 64], [3; 64], [4; 64], 0),
        encode_release_proof_role(owner, [1; 64], [2; 64], [9; 64], [4; 64], 0),
        encode_release_proof_role(owner, [1; 64], [2; 64], [3; 64], [9; 64], 0),
        encode_release_proof_role(owner, [1; 64], [2; 64], [3; 64], [4; 64], 1),
    ] {
        assert_ne!(changed.unwrap(), original);
    }
    assert!(original.len() <= 1024);
    assert_eq!(original.len(), 479);
    let tuple = CanonicalTuple::decode(&original, &Default::default()).unwrap();
    assert_eq!(tuple.items.len(), 7);
    assert_eq!(
        tuple.items[0].variable_value_bytes().unwrap(),
        b"sealed-lattice/certified-release/v2"
    );
    assert_eq!(
        tuple.items[1].item_type(),
        registration_credentials::foundation::CanonicalItemType::Ascii
    );
    assert_eq!(
        tuple.items[1].variable_value_bytes().unwrap(),
        owner.to_lowercase_hex().as_bytes()
    );
    assert!(
        encode_release_proof_role(owner, [1; 64], [2; 64], [3; 64], [4; 64], usize::MAX).is_err()
    );
}
