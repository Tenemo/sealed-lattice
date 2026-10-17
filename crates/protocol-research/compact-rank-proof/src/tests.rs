use super::*;
use field::*;
use transcript::{Transcript, hash, word};

#[test]
fn compact_rank_transcript_matches_independent_shake_vectors() {
    // These values come from Node's raw SHAKE256 over the explicitly framed
    // messages, independently of either proof implementation.
    let context = [17; 64];
    let mut transcript = Transcript::new(b"rank-test", &context, 4096);
    assert_eq!(
        transcript.challenge(0, true),
        [
            59644687580621660761713731452790270713,
            156796601241897911010467231842182941460,
            251174442622771516580806535655767907947
        ]
    );
    transcript.respond(&[23; 128], &[b"first root"]);
    assert_eq!(
        transcript.challenge(2, false),
        [
            236206569781923014690444725611998190863,
            108194186957013636728141185032425631977,
            103229782171686323543034811772522645640
        ]
    );
    assert_eq!(
        transcript.positions(96, 4, 16384),
        [15791, 15172, 4862, 13715]
    );
}

#[test]
fn compact_rank_lagrange_weights_reproduce_extension_polynomials() {
    for length in [2, 4, 16, 128] {
        for point in [[0, 0, 1], [3, 7, 19]] {
            let coefficients: Vec<_> = (0..length)
                .map(|index| [index as u128, (index * 7) as u128, (index * 11) as u128])
                .collect();
            let generator = root(length);
            let values: Vec<_> = (0..length)
                .map(|index| evaluate(&coefficients, [base::power(generator, index as u128), 0, 0]))
                .collect();
            assert_eq!(
                dot(&values, &lagrange(point, length)),
                evaluate(&coefficients, point)
            );
        }
    }
}

#[test]
fn compact_rank_openings_authenticate_repeated_queries_and_shared_paths() {
    let role = b"rank-opening-test";
    let tree = layout::Tree {
        identifier: 3,
        domain: 4,
        width: 1,
        mask: false,
        stage: 0,
        mask_offset: None,
    };
    let fields = [[1, 2, 3], [5, 7, 11], [13, 17, 19], [23, 29, 31]];
    let leaves: Vec<_> = fields
        .iter()
        .enumerate()
        .map(|(index, &value)| {
            hash(
                b"bounded-proof/leaf",
                &[
                    role,
                    &word(3),
                    &word(index),
                    &[index as u8; 128],
                    &encode(value),
                ],
            )
        })
        .collect();
    let node = |level, left: &[u8; 64], right: &[u8; 64]| {
        hash(
            b"bounded-proof/node",
            &[role, &word(3), &word(level), left, right],
        )
    };
    let left = node(1, &leaves[0], &leaves[1]);
    let right = node(1, &leaves[2], &leaves[3]);
    let root = node(2, &left, &right);
    let mut proof = word(2).to_vec();
    proof.extend(word(0));
    proof.extend(encode(fields[0]));
    proof.extend([0; 128]);
    proof.extend(leaves[1]);
    proof.extend(right);
    proof.extend(word(2));
    proof.extend(encode(fields[2]));
    proof.extend([2; 128]);
    proof.extend(leaves[3]);
    let mut reader = reader::Reader::new(&proof);
    assert_eq!(
        authentication::opening(role, &tree, &root, &[2, 0, 2], &mut reader).unwrap(),
        vec![vec![fields[2], fields[0], fields[2]]]
    );
    reader.finish().unwrap();
    for offset in [0, 4, 8, 56, 184, proof.len() - 1] {
        let mut damaged = proof.clone();
        damaged[offset] ^= 1;
        assert!(
            authentication::opening(
                role,
                &tree,
                &root,
                &[2, 0, 2],
                &mut reader::Reader::new(&damaged)
            )
            .is_err()
        );
    }
    assert!(
        authentication::opening(
            b"different-role",
            &tree,
            &root,
            &[2, 0, 2],
            &mut reader::Reader::new(&proof)
        )
        .is_err()
    );
    let mut noncanonical = proof.clone();
    noncanonical[8..24].copy_from_slice(&MODULUS.to_le_bytes());
    assert!(
        authentication::opening(
            role,
            &tree,
            &root,
            &[2, 0, 2],
            &mut reader::Reader::new(&noncanonical)
        )
        .is_err()
    );
}

#[test]
fn compact_rank_geometry_matches_independent_serialized_fixtures() {
    for (groups, domain, folds) in [
        ([26098, 12342, 12297], 16384, 4),
        ([27223, 12958, 12297], 16384, 4),
        ([29058, 14637, 12297], 32768, 3),
        ([31229, 16463, 12297], 16384, 5),
    ] {
        let plan = plan::Plan::select(&groups);
        assert_eq!(plan.domains, [domain]);
        assert_eq!(plan.folds, [folds]);
        assert_eq!(plan.queries, 450);
        assert_eq!(plan.masks, folds);
        assert_eq!(plan.rounds, folds + 3);
    }
}
