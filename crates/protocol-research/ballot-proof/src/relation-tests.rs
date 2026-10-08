use super::*;

// An unfinished statement parser with a syntactically valid proof header.
// It never finishes a proof or creates a setup or ballot capability.
fn parser(profile: Profile, fhe_key: &[u8]) -> BallotRelationVerifier {
    let fixed = fixed_input_identities(profile).unwrap();
    let mut proof_header = vec![0; crate::HEADER_LENGTH];
    proof_header[..4]
        .copy_from_slice(supported_profile::relation::ballot_relation(profile).proof_magic);
    BallotRelationVerifier {
        profile,
        verifier: Some(
            verifier(profile, b"fixed-input-binding-test", [0; 64], &proof_header).unwrap(),
        ),
        expected_header: statement::header(&[1; 64], &[2; 64], 0, profile.options(), 1).unwrap(),
        expected_inputs: [
            fixed[0],
            identity(PUBLIC_POLYNOMIAL_DOMAIN, fhe_key).unwrap(),
            fixed[1],
            fixed[2],
        ],
        header_offset: 0,
        polynomial: 0,
        polynomial_bytes: 0,
        hash: None,
        statement_done: false,
        statement: [0; 64],
    }
}

#[test]
fn relation_stream_refuses_substituted_fixed_auxiliary_coordinates() {
    let profile = Profile::new(3, 2).unwrap();
    let common =
        setup_witness::contribution::common_records(profile, setup_input(profile).1).unwrap();
    let zero = vec![0; polynomial_bytes(profile, 1)];
    let auxiliary = [
        setup_witness::fixed_auxiliary::common_records(),
        setup_witness::fixed_auxiliary::public_key_records(),
    ];
    for changed in [None, Some(0), Some(1)] {
        let mut verifier = parser(profile, &zero);
        verifier
            .push_statement(&verifier.expected_header.clone())
            .unwrap();
        for polynomial in [&common, &zero, &zero, &zero] {
            for chunk in polynomial.chunks(CHUNK_LIMIT) {
                verifier.push_statement(chunk).unwrap();
            }
        }
        for (index, bytes) in auxiliary.iter().enumerate() {
            let mut bytes = bytes.clone();
            if changed == Some(index) {
                assert!(
                    bytes[1..1 + supported_profile::auxiliary_modulus().len()]
                        .iter()
                        .any(|byte| *byte != 0)
                );
                bytes[0] ^= 1;
                assert!(matches!(
                    verifier.push_statement(&bytes),
                    Err(Refusal::Context)
                ));
                assert!(matches!(verifier.push_statement(&[0]), Err(Refusal::Stage)));
                break;
            }
            verifier.push_statement(&bytes).unwrap();
        }
        if changed.is_none() {
            assert_eq!(verifier.polynomial, 6);
        }
        assert!(verifier.finish().is_err());
    }
}
