use super::*;
use protocol_foundations::SIGNING_PUBLIC_KEY_BYTES;

// A separate sign/magnitude implementation checks the emitted bytes, not
// another call to the streaming encoder.
fn reference_polynomial(values: &[BigInt], width: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * width);
    for value in values {
        let (sign, magnitude) = value.to_bytes_le();
        let start = bytes.len();
        bytes.push(u8::from(sign == num_bigint::Sign::Minus));
        bytes.extend(magnitude);
        bytes.resize(start + width, 0);
    }
    bytes
}

fn public_polynomials(profile: Profile) -> [Vec<BigInt>; 4] {
    std::array::from_fn(|polynomial| {
        let modulus = if polynomial == 3 {
            profile.release_modulus().to_bytes()
        } else {
            supported_profile::share_modulus().to_vec()
        };
        let half = BigInt::from_bytes_le(num_bigint::Sign::Plus, &modulus) >> 1usize;
        (0..SYSTEMATIC)
            .map(|position| match position % 5 {
                0 => half.clone(),
                1 => -&half,
                2 => BigInt::from(0),
                3 => BigInt::from(position + polynomial + 1),
                _ => -BigInt::from(position + polynomial + 1),
            })
            .collect()
    })
}

fn statement_header(profile: Profile) -> [u8; RELEASE_HEADER_BYTES] {
    let mut header = [0; RELEASE_HEADER_BYTES];
    header[..4].copy_from_slice(b"LRS1");
    header[4..68].fill(11);
    header[68..132].fill(19);
    header[132..196].fill(23);
    header[196..].copy_from_slice(&((profile.participants() - 1) as u16).to_le_bytes());
    header
}

#[test]
fn release_statement_stream_matches_independent_bytes_in_bounded_chunks() {
    for (participants, options) in [(3, 2), (4, 7), (20, 20)] {
        let profile = Profile::new(participants, options).unwrap();
        let header = statement_header(profile);
        let polynomials = public_polynomials(profile);
        let partial = reference_polynomial(&polynomials[3], release_coefficient_bytes(profile));
        let materialized_start = std::time::Instant::now();
        let common = setup_witness::contribution::common_share_polynomial();
        let mut expected = vec![header.to_vec()];
        for (index, values) in std::iter::once(common.as_slice())
            .chain(polynomials.iter().map(Vec::as_slice))
            .enumerate()
        {
            let width = if index < 4 {
                1 + supported_profile::share_modulus().len()
            } else {
                release_coefficient_bytes(profile)
            };
            expected.push(reference_polynomial(values, width));
        }
        expected.push(partial.clone());
        let materialized_microseconds = materialized_start.elapsed().as_micros();
        drop(common);
        let mut offsets = [0; 7];
        let mut maximum_chunk_bytes = 0;
        let streaming_start = std::time::Instant::now();
        visit_statement(
            profile,
            &header,
            polynomials.each_ref().map(Vec::as_slice),
            &partial,
            |index, bytes| {
                assert!(!bytes.is_empty());
                assert!(bytes.len() <= CHUNK_LIMIT);
                let end = offsets[index] + bytes.len();
                assert_eq!(bytes, &expected[index][offsets[index]..end]);
                offsets[index] = end;
                maximum_chunk_bytes = maximum_chunk_bytes.max(bytes.len());
                Ok(())
            },
        )
        .unwrap();
        let streaming_microseconds = streaming_start.elapsed().as_micros();
        assert_eq!(
            offsets.as_slice(),
            expected.iter().map(Vec::len).collect::<Vec<_>>()
        );
        let materialized_bytes = expected.iter().map(Vec::len).sum::<usize>();
        assert!(maximum_chunk_bytes < materialized_bytes);
        println!(
            "Release statement {participants}/{options}: materialized encoded bytes={materialized_bytes}, maximum streamed chunk bytes={maximum_chunk_bytes}, materialized microseconds={materialized_microseconds}, streamed microseconds={streaming_microseconds}"
        );
    }
}

#[test]
fn release_statement_stream_preserves_the_digest_and_operator_binding() {
    let profile = Profile::new(3, 2).unwrap();
    let header = statement_header(profile);
    let polynomials = public_polynomials(profile);
    let partial = reference_polynomial(&polynomials[3], release_coefficient_bytes(profile));
    let common = setup_witness::contribution::common_share_polynomial();
    let mut encoded: Vec<Vec<u8>> = std::iter::once(common.as_slice())
        .chain(polynomials.iter().map(Vec::as_slice))
        .enumerate()
        .map(|(index, values)| {
            reference_polynomial(
                values,
                if index < 4 {
                    1 + supported_profile::share_modulus().len()
                } else {
                    release_coefficient_bytes(profile)
                },
            )
        })
        .collect();
    encoded.push(partial.clone());
    let expected = PublicStatement {
        profile,
        header: header.to_vec(),
        polynomials: encoded,
    };
    let alpha = [5, 7, 11];
    let queries = [
        0,
        3,
        31,
        supported_profile::relation::EVALUATION_DOMAIN_SIZE as u32 - 1,
    ];
    let relation = supported_profile::relation::release_relation(profile);
    let operator = expected.operator(alpha).unwrap();
    let target = operator.target;
    let lookup_weight = operator.lookup_weight;
    let coefficients = operator.at_queries(relation.columns(), &queries).unwrap();
    for changed in [None, Some(0), Some(2), Some(6)] {
        let mut stream = linked_release_proof::statement::StatementStream::new(
            profile,
            expected.digest(),
            alpha,
            &queries,
        )
        .unwrap();
        let mut mutated = false;
        visit_statement(
            profile,
            &header,
            polynomials.each_ref().map(Vec::as_slice),
            &partial,
            |index, bytes| {
                if changed == Some(index) && !mutated {
                    let mut bytes = bytes.to_vec();
                    // Alter context or a still-canonical coefficient magnitude.
                    let offset = if index == 0 {
                        4
                    } else {
                        2 * if index < 5 {
                            statement::share_coefficient_bytes()
                        } else {
                            release_coefficient_bytes(profile)
                        } + 1
                    };
                    bytes[offset] ^= 1;
                    mutated = true;
                    stream.push(&bytes).map_err(Refusal::from)
                } else {
                    stream.push(bytes).map_err(Refusal::from)
                }
            },
        )
        .unwrap();
        let result = stream.finish();
        if changed.is_some() {
            assert!(mutated && result.is_err());
        } else {
            let output = result.unwrap();
            assert_eq!(output.target, target);
            assert_eq!(output.lookup_weight, lookup_weight);
            assert_eq!(output.coefficients, coefficients);
        }
    }
}

#[test]
fn release_statement_stream_refuses_malformed_output_before_consuming_inputs() {
    let profile = Profile::new(3, 2).unwrap();
    let header = statement_header(profile);
    let width = release_coefficient_bytes(profile);
    let original = vec![0; SYSTEMATIC * width];
    let refuse = |partial: &[u8]| {
        assert!(matches!(
            visit_statement(profile, &header, [&[]; 4], partial, |_, _| panic!(
                "Invalid output must not reach the consumer"
            )),
            Err(Refusal::Encoding)
        ));
    };
    for length in [0, width - 1, original.len() - 1] {
        refuse(&original[..length]);
    }
    let mut trailing = original.clone();
    trailing.push(0);
    refuse(&trailing);
    let half = BigInt::from_bytes_le(
        num_bigint::Sign::Plus,
        &profile.release_modulus().to_bytes(),
    ) >> 1usize;
    for position in [0, SYSTEMATIC / 2, SYSTEMATIC - 1] {
        for record in [
            {
                let mut record = vec![0; width];
                record[0] = 2;
                record
            },
            {
                let mut record = vec![0; width];
                record[0] = 1;
                record
            },
            reference_polynomial(&[&half + 1u32], width),
            reference_polynomial(&[-(&half + 1u32)], width),
        ] {
            let mut partial = original.clone();
            partial[position * width..(position + 1) * width].copy_from_slice(&record);
            refuse(&partial);
        }
    }
    let mut calls = 0;
    assert!(matches!(
        visit_statement(profile, &header, [&[]; 4], &original, |_, _| {
            calls += 1;
            Err(Refusal::Proof)
        }),
        Err(Refusal::Proof)
    ));
    assert_eq!(calls, 1);
}

#[test]
fn release_polynomial_chunks_preserve_width_errors_and_consumer_refusal() {
    for width in [0, 1, CHUNK_LIMIT + 1, usize::MAX] {
        assert!(matches!(
            statement::polynomial_chunks(
                &[BigInt::from(0)],
                width,
                |_| Ok::<(), statement::Refusal>(())
            ),
            Err(statement::Refusal::Shape)
        ));
    }
    assert!(matches!(
        statement::polynomial_chunks(
            &[BigInt::from(256)],
            2,
            |_| Ok::<(), statement::Refusal>(())
        ),
        Err(statement::Refusal::Encoding)
    ));
    let values = vec![BigInt::from(-255); CHUNK_LIMIT / 2 + 1];
    let mut calls = 0;
    assert!(matches!(
        statement::polynomial_chunks(&values, 2, |_| {
            calls += 1;
            Err(statement::Refusal::Binding)
        }),
        Err(statement::Refusal::Binding)
    ));
    assert_eq!(calls, 1);
}

#[test]
fn proof_role_separates_every_verified_context_input() {
    let owner = derive_participant_identity(&[7; SIGNING_PUBLIC_KEY_BYTES]).unwrap();
    let other_owner = derive_participant_identity(&[8; SIGNING_PUBLIC_KEY_BYTES]).unwrap();
    let original = encode_release_proof_role(owner, [1; 64], [3; 64], [4; 64], 0).unwrap();
    for changed in [
        encode_release_proof_role(other_owner, [1; 64], [3; 64], [4; 64], 0),
        encode_release_proof_role(owner, [9; 64], [3; 64], [4; 64], 0),
        encode_release_proof_role(owner, [1; 64], [9; 64], [4; 64], 0),
        encode_release_proof_role(owner, [1; 64], [3; 64], [9; 64], 0),
        encode_release_proof_role(owner, [1; 64], [3; 64], [4; 64], 1),
    ] {
        assert_ne!(changed.unwrap(), original);
    }
    assert!(original.len() <= 1024);
    assert_eq!(original.len(), 404);
    let tuple = CanonicalTuple::decode(&original, &Default::default()).unwrap();
    assert_eq!(tuple.items.len(), 6);
    assert_eq!(
        tuple.items[0].variable_value_bytes().unwrap(),
        b"sealed-lattice/certified-release"
    );
    assert_eq!(
        tuple.items[1].item_type(),
        protocol_foundations::foundation::CanonicalItemType::Ascii
    );
    assert_eq!(
        tuple.items[1].variable_value_bytes().unwrap(),
        owner.to_lowercase_hex().as_bytes()
    );
    assert!(encode_release_proof_role(owner, [1; 64], [3; 64], [4; 64], usize::MAX).is_err());
}
