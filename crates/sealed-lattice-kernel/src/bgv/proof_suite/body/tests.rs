use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple};

use super::super::setup_public_polynomial::canonical_setup_public_polynomial_phase_pair_leaf_bytes;
use super::super::{
    CommonProofTranscript, PROOF_BASE_FIELD_MODULUS, ResidentCommonProofByteSource,
    ResidentCommonProofInputChunk,
    field::ProofBaseFieldElement,
    merkle::CanonicalProofMerkleTree,
    prover::{
        CommonProofOpeningGeometry, CommonProofProverError, StatementOwnedMerkleReplay,
        encode_common_proof_query_tree_fragment,
    },
};
use super::*;

#[derive(Clone)]
struct EncodedTreeOpening {
    root: [u8; 64],
    opened_leaf_bytes: Vec<Vec<u8>>,
    frontier: Vec<[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]>,
}

fn catalog_input(
    evaluation_domain_size: u64,
    relation_trees: Vec<RelationProofTreeInput>,
) -> ProofTreeCatalogInput {
    ProofTreeCatalogInput {
        suite_identifier: [0x11; 64],
        canonical_proof_object_header_bytes: vec![0x22; 96],
        application_statement_schema_identifier: 0x1216,
        proof_field_index: 0,
        evaluation_domain_size,
        relation_trees,
    }
}

#[allow(clippy::too_many_arguments)]
fn transcript_schedule(
    privacy_mode: CommonProofPrivacyMode,
    ordered_base_tree_ordinals: Vec<u16>,
    ordered_auxiliary_tree_ordinals: Vec<u16>,
    quotient_component_count: u16,
    opening_claim_count: u32,
    fri_fold_count: u16,
    unique_query_count: u32,
    query_orbit_count: u64,
) -> CommonProofTranscriptSchedule {
    CommonProofTranscriptSchedule::new(
        ordered_base_tree_ordinals,
        Vec::new(),
        ordered_auxiliary_tree_ordinals,
        1,
        quotient_component_count,
        1,
        opening_claim_count,
        fri_fold_count,
        1,
        unique_query_count,
        query_orbit_count,
        64,
        privacy_mode,
    )
    .expect("test transcript schedule is valid")
}

fn base_value(value: u64) -> ProofBaseFieldElement {
    ProofBaseFieldElement::from_canonical(value).expect("test value is canonical")
}

fn extension_value(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_canonical_coordinates([
        value,
        value + 1,
        value + 2,
        value + 3,
        value + 4,
    ])
    .expect("test extension value is canonical")
}

fn canonical_tree_value(value: ProofTreeValue) -> CanonicalItem {
    match value {
        ProofTreeValue::Base(value) => CanonicalItem::from_canonical_bytes(
            CanonicalItemType::FieldElement,
            value.canonical().to_le_bytes().to_vec(),
            &crate::foundation::CanonicalDecodeLimits::default(),
        )
        .expect("base-field item is canonical"),
        ProofTreeValue::Extension(value) => {
            let bytes = value
                .canonical_coordinates()
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect::<Vec<_>>();
            CanonicalItem::from_canonical_bytes(
                CanonicalItemType::ChallengeExtensionElement,
                bytes,
                &crate::foundation::CanonicalDecodeLimits::default(),
            )
            .expect("extension-field item is canonical")
        }
    }
}

fn canonical_tree_value_list(values: &[ProofTreeValue]) -> CanonicalItem {
    let element_type = match values.first().expect("test list is nonempty") {
        ProofTreeValue::Base(_) => CanonicalItemType::FieldElement,
        ProofTreeValue::Extension(_) => CanonicalItemType::ChallengeExtensionElement,
    };
    let items = values
        .iter()
        .copied()
        .map(canonical_tree_value)
        .collect::<Vec<_>>();
    CanonicalItem::homogeneous_list(element_type, &items).expect("tree-value list is canonical")
}

fn common_leaf(entry: &ProofTreeCatalogEntry, leaf_index: u64) -> ProofOraclePhasePairLeaf {
    let context = entry
        .common_context()
        .expect("common test entry has a common context");
    let row_width = context.row_width() as usize;
    let first_seed = u64::from(entry.tree_catalog_index()) * 97 + leaf_index * 11 + 1;
    let value_kind = match entry.source() {
        ProofTreeCatalogSource::RelationProofCreated { .. } => TreeValueKind::Base,
        ProofTreeCatalogSource::QuotientComponent { .. }
        | ProofTreeCatalogSource::OpeningBatchMask
        | ProofTreeCatalogSource::NonterminalFriLayer { .. } => TreeValueKind::Extension,
        ProofTreeCatalogSource::RelationBoundPublic => panic!("bound entry is not common"),
    };
    let values = |offset: u64| {
        (0..row_width)
            .map(|column_index| {
                let value = first_seed + offset + column_index as u64 * 7;
                match value_kind {
                    TreeValueKind::Base => ProofTreeValue::Base(base_value(value)),
                    TreeValueKind::Extension => ProofTreeValue::Extension(extension_value(value)),
                }
            })
            .collect::<Vec<_>>()
    };
    let salt = (context.leaf_visibility() == ProofLeafVisibility::SecretBearing).then_some(
        [entry.tree_catalog_index() as u8 + leaf_index as u8 + 1;
            COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    );
    ProofOraclePhasePairLeaf::new(context, leaf_index, salt, values(0), values(43))
        .expect("test common leaf is valid")
}

fn common_tree_opening(entry: &ProofTreeCatalogEntry) -> EncodedTreeOpening {
    let context = entry
        .common_context()
        .expect("common test entry has a context");
    let leaf_count = context.leaf_count().expect("test leaf count");
    assert!(leaf_count <= 2, "test helper only needs one tree level");
    let leaves = (0..leaf_count)
        .map(|leaf_index| common_leaf(entry, leaf_index as u64))
        .collect::<Vec<_>>();
    let tree = CanonicalProofMerkleTree::from_phase_pair_leaves(context.clone(), &leaves)
        .expect("test tree is valid");
    let frontier = if leaf_count == 1 {
        Vec::new()
    } else {
        vec![leaves[1].digest().expect("sibling leaf hashes")]
    };
    EncodedTreeOpening {
        root: tree.root(),
        opened_leaf_bytes: vec![leaves[0].canonical_bytes().expect("leaf encodes")],
        frontier,
    }
}

fn statement_leaf_bytes(
    schema_identifier: u16,
    context_hash: [u8; 64],
    row_width: usize,
    secret_salt: bool,
    leaf_index: u64,
    value_seed: u64,
) -> Vec<u8> {
    if !secret_salt {
        assert_eq!(
            schema_identifier,
            SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        );
        let first_values = (0..row_width)
            .map(|column_index| base_value(value_seed + column_index as u64))
            .collect::<Vec<_>>();
        let opposite_values = (0..row_width)
            .map(|column_index| base_value(value_seed + 31 + column_index as u64))
            .collect::<Vec<_>>();
        return canonical_setup_public_polynomial_phase_pair_leaf_bytes(
            context_hash,
            leaf_index,
            &first_values,
            &opposite_values,
        )
        .expect("setup polynomial leaf encodes");
    }
    let first_values = (0..row_width)
        .map(|column_index| ProofTreeValue::Base(base_value(value_seed + column_index as u64)))
        .collect::<Vec<_>>();
    let opposite_values = (0..row_width)
        .map(|column_index| ProofTreeValue::Base(base_value(value_seed + 31 + column_index as u64)))
        .collect::<Vec<_>>();
    let mut items = vec![
        CanonicalItem::hash512(context_hash),
        CanonicalItem::unsigned64(leaf_index),
    ];
    if secret_salt {
        items.push(
            CanonicalItem::fixed_bytes(
                [leaf_index as u8 + 0x51; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
            )
            .expect("fixed material salt encodes"),
        );
    }
    items.push(canonical_tree_value_list(&first_values));
    items.push(canonical_tree_value_list(&opposite_values));
    CanonicalTuple::new(schema_identifier, SCHEMA_VERSION, items)
        .encode()
        .expect("statement leaf encodes")
}

fn statement_tree_opening(
    construction: ProofTreeConstruction,
    leaf_hash_domain: &str,
    schema_identifier: u16,
    context_hash: [u8; 64],
    row_width: usize,
    secret_salt: bool,
) -> EncodedTreeOpening {
    let leaf_bytes = [
        statement_leaf_bytes(
            schema_identifier,
            context_hash,
            row_width,
            secret_salt,
            0,
            101,
        ),
        statement_leaf_bytes(
            schema_identifier,
            context_hash,
            row_width,
            secret_salt,
            1,
            211,
        ),
    ];
    let leaf_digests = leaf_bytes
        .iter()
        .map(|bytes| hash_canonical_leaf(leaf_hash_domain, bytes).expect("leaf hashes"))
        .collect::<Vec<_>>();
    let root = statement_owned_node_digest(&construction, 1, 0, leaf_digests[0], leaf_digests[1])
        .expect("statement node hashes");
    EncodedTreeOpening {
        root,
        opened_leaf_bytes: vec![leaf_bytes[0].clone()],
        frontier: vec![leaf_digests[1]],
    }
}

fn canonical_extension_list_bytes(values: &[ProofChallengeExtensionElement]) -> Vec<u8> {
    let items = values
        .iter()
        .copied()
        .map(ProofTreeValue::Extension)
        .map(canonical_tree_value)
        .collect::<Vec<_>>();
    CanonicalItem::homogeneous_list(CanonicalItemType::ChallengeExtensionElement, &items)
        .expect("extension list encodes")
        .canonical_bytes()
        .to_vec()
}

fn canonical_opening_record(tree_catalog_index: u16, opened_leaf_bytes: &[Vec<u8>]) -> Vec<u8> {
    let leaves = opened_leaf_bytes
        .iter()
        .map(|bytes| CanonicalItem::variable_bytes(bytes).expect("opened leaf is bounded"))
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(tree_catalog_index),
            CanonicalItem::homogeneous_list(CanonicalItemType::RawBytes, &leaves)
                .expect("opening list encodes"),
        ],
    )
    .encode()
    .expect("opening record encodes")
}

fn canonical_frontier(
    tree_catalog_index: u16,
    frontier: &[[u8; AUTHENTICATION_DIGEST_BYTE_LENGTH]],
) -> Vec<u8> {
    let nodes = frontier
        .iter()
        .copied()
        .map(CanonicalItem::hash512)
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(tree_catalog_index),
            CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &nodes)
                .expect("frontier list encodes"),
        ],
    )
    .encode()
    .expect("frontier encodes")
}

#[test]
fn authentication_frontier_uses_version_two_and_rejects_the_version_one_digest_list_alias() {
    let canonical_bytes = canonical_frontier(0, &[[0x31; AUTHENTICATION_DIGEST_BYTE_LENGTH]]);
    assert_eq!(
        &canonical_bytes[..4],
        &[
            0x08,
            0x01,
            PROOF_AUTHENTICATION_FRONTIER_SCHEMA_VERSION as u8,
            0x00,
        ]
    );

    let mut version_one_bytes = canonical_bytes;
    version_one_bytes[2..4].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    let mut decoder = BoundedProofDecoder::new(
        version_one_bytes.as_slice(),
        version_one_bytes.len(),
        version_one_bytes.len(),
    )
    .expect("bounded proof decoder");
    assert_eq!(
        authentication::read_authentication_frontier(&mut decoder, 0, 1),
        Err(ProofBodyError::InvalidSchemaVersion)
    );
}

fn encode_body(
    layout: &ProofBodyLayout,
    tree_openings: &[EncodedTreeOpening],
    deep_evaluations: &[ProofChallengeExtensionElement],
    terminal_coefficients: &[ProofChallengeExtensionElement],
) -> Vec<u8> {
    assert_eq!(layout.catalog.entries.len(), tree_openings.len());
    let mut bytes = Vec::new();
    let append_roots = |bytes: &mut Vec<u8>, predicate: &dyn Fn(ProofTreeCatalogSource) -> bool| {
        for (entry, opening) in layout.catalog.entries.iter().zip(tree_openings) {
            if predicate(entry.source) {
                bytes.extend_from_slice(&opening.root);
            }
        }
    };
    append_roots(&mut bytes, &|source| {
        matches!(
            source,
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                ..
            }
        )
    });
    append_roots(&mut bytes, &|source| {
        matches!(
            source,
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                ..
            }
        )
    });
    append_roots(&mut bytes, &|source| {
        matches!(source, ProofTreeCatalogSource::QuotientComponent { .. })
    });
    bytes.extend_from_slice(&canonical_extension_list_bytes(deep_evaluations));
    append_roots(&mut bytes, &|source| {
        matches!(source, ProofTreeCatalogSource::OpeningBatchMask)
    });
    append_roots(&mut bytes, &|source| {
        matches!(source, ProofTreeCatalogSource::NonterminalFriLayer { .. })
    });
    bytes.extend_from_slice(&canonical_extension_list_bytes(terminal_coefficients));
    bytes.extend_from_slice(&(tree_openings.len() as u32).to_le_bytes());
    for (entry, opening) in layout.catalog.entries.iter().zip(tree_openings) {
        bytes.extend_from_slice(&canonical_opening_record(
            entry.tree_catalog_index,
            &opening.opened_leaf_bytes,
        ));
        bytes.extend_from_slice(&canonical_frontier(
            entry.tree_catalog_index,
            &opening.frontier,
        ));
    }
    bytes
}

fn query_opening_absorber(
    exact_byte_length: usize,
) -> (CommonProofTranscript, CommonProofQueryOpeningAbsorber) {
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        Vec::new(),
        Vec::new(),
        1,
        1,
        1,
        1,
        1,
    );
    let mut transcript = CommonProofTranscript::new(1, [0x11; 64], 0x1216, &[0x22; 96], schedule)
        .expect("test transcript starts");
    transcript
        .sample_composition_challenge(0)
        .expect("composition challenge derives");
    transcript
        .absorb_quotient_root(0, [0x31; 64])
        .expect("quotient root absorbs");
    transcript
        .sample_deep_point(0, |_| false)
        .expect("DEEP point derives");
    transcript
        .absorb_deep_values(&canonical_extension_list_bytes(&[extension_value(5)]))
        .expect("DEEP values absorb");
    transcript
        .sample_opening_batch_challenge(0)
        .expect("opening challenge derives");
    transcript
        .sample_fri_fold_challenge(0)
        .expect("FRI challenge derives");
    transcript
        .absorb_fri_terminal(&canonical_extension_list_bytes(&[extension_value(15)]))
        .expect("terminal absorbs");
    assert_eq!(
        transcript
            .sample_query_representatives()
            .expect("query vector derives"),
        vec![0]
    );
    let absorber = transcript
        .begin_query_openings(exact_byte_length)
        .expect("query absorber starts");
    (transcript, absorber)
}

fn decode_complete_body(
    bytes: &[u8],
    layout: &ProofBodyLayout,
) -> Result<DecodedProofBody, ProofBodyError> {
    let pending = decode_proof_body_prefix(bytes, bytes.len(), bytes.len(), layout)?;
    let (mut transcript, mut absorber) =
        query_opening_absorber(pending.query_section_byte_length()?);
    let decoded = pending.decode_query_section(&[0], &mut absorber, |_| Ok(()))?;
    transcript.finish_query_openings(absorber)?;
    transcript.finish()?;
    Ok(decoded)
}

fn simple_public_body() -> (
    ProofBodyLayout,
    Vec<EncodedTreeOpening>,
    Vec<ProofChallengeExtensionElement>,
    Vec<ProofChallengeExtensionElement>,
    Vec<u8>,
) {
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        vec![0],
        Vec::new(),
        1,
        2,
        1,
        1,
        1,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            2,
            vec![RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                row_width: 2,
                leaf_visibility: ProofLeafVisibility::Public,
            }],
        ),
        &schedule,
    )
    .expect("public catalog derives");
    let layout = ProofBodyLayout::new(catalog, &schedule, 2).expect("public layout derives");
    let tree_openings = layout
        .catalog
        .entries
        .iter()
        .map(common_tree_opening)
        .collect::<Vec<_>>();
    let deep_evaluations = vec![extension_value(7), extension_value(17)];
    let terminal_coefficients = vec![extension_value(27), extension_value(37)];
    let bytes = encode_body(
        &layout,
        &tree_openings,
        &deep_evaluations,
        &terminal_coefficients,
    );
    (
        layout,
        tree_openings,
        deep_evaluations,
        terminal_coefficients,
        bytes,
    )
}

#[test]
fn decoder_accepts_exact_public_body_and_streams_one_opening_at_a_time() {
    let (layout, tree_openings, deep_evaluations, terminal_coefficients, bytes) =
        simple_public_body();
    let mut observed_openings = Vec::new();
    let pending = decode_proof_body_prefix(&bytes, bytes.len(), bytes.len(), &layout)
        .expect("public prefix decodes");
    let query_section_byte_length = pending
        .query_section_byte_length()
        .expect("query section length derives");
    let (mut transcript, mut absorber) = query_opening_absorber(query_section_byte_length);
    let decoded = pending
        .decode_query_section(&[0], &mut absorber, |opening| {
            assert_eq!(opening.leaves().len(), 1);
            assert_eq!(opening.leaves()[0].leaf_index(), 0);
            observed_openings.push((
                opening.catalog_entry().tree_catalog_index(),
                opening.leaves()[0].first_point_values().len(),
            ));
            Ok(())
        })
        .expect("canonical public body decodes");
    transcript
        .finish_query_openings(absorber)
        .expect("streamed query bytes finish");
    transcript.finish().expect("test transcript completes");

    assert_eq!(
        decoded.tree_roots(),
        tree_openings
            .iter()
            .map(|opening| opening.root)
            .collect::<Vec<_>>()
    );
    assert_eq!(decoded.deep_evaluations(), deep_evaluations);
    assert_eq!(decoded.terminal_coefficients(), terminal_coefficients);
    assert_eq!(observed_openings, [(0, 2), (1, 1)]);
}

#[test]
fn incremental_query_decoders_cross_header_leaf_and_frontier_chunk_boundaries() {
    let (layout, tree_openings, _, _, bytes) = simple_public_body();
    let query_section_offset =
        proof_body_prefix_byte_length(&layout).expect("the prefix length derives");
    let query_header_end = query_section_offset + 4;
    let query_header_source = ResidentCommonProofByteSource::new(
        bytes.len(),
        vec![
            ResidentCommonProofInputChunk::new(
                query_section_offset,
                &bytes[query_section_offset..query_section_offset + 2],
            ),
            ResidentCommonProofInputChunk::new(
                query_section_offset + 2,
                &bytes[query_section_offset + 2..query_header_end],
            ),
        ],
    )
    .expect("the query header fits two resident chunks");
    assert_eq!(
        decode_proof_query_section_header_at(
            &query_header_source,
            query_section_offset,
            layout.catalog.entries.len(),
        )
        .expect("the query header decodes across its chunk boundary"),
        query_header_end,
    );

    let entry = &layout.catalog.entries[0];
    let opening_record = canonical_opening_record(
        entry.tree_catalog_index,
        &tree_openings[0].opened_leaf_bytes,
    );
    let expected_tree_byte_length =
        proof_query_tree_byte_length(&layout, 0, &[0]).expect("the tree length derives");
    let tree_end = query_header_end + expected_tree_byte_length;
    let encoded_frontier = canonical_frontier(entry.tree_catalog_index, &tree_openings[0].frontier);
    assert_eq!(
        expected_tree_byte_length,
        opening_record.len() + encoded_frontier.len(),
    );

    let leaf_midpoint = query_header_end + 32 + tree_openings[0].opened_leaf_bytes[0].len() / 2;
    let frontier_header_midpoint = query_header_end + opening_record.len() + 1;
    for split_offset in [
        query_header_end + 1,
        leaf_midpoint,
        frontier_header_midpoint,
    ] {
        let source = ResidentCommonProofByteSource::new(
            bytes.len(),
            vec![
                ResidentCommonProofInputChunk::new(
                    query_header_end,
                    &bytes[query_header_end..split_offset],
                ),
                ResidentCommonProofInputChunk::new(split_offset, &bytes[split_offset..tree_end]),
            ],
        )
        .expect("the exact tree range fits two resident chunks");
        let (next_offset, opening) = decode_proof_query_tree_at(
            &source,
            query_header_end,
            &layout,
            0,
            tree_openings[0].root,
            &[0],
        )
        .expect("the tree decodes across a semantic chunk boundary");
        assert_eq!(next_offset, tree_end);
        let opening = opening.as_opening(entry);
        assert_eq!(opening.leaves().len(), 1);
        assert_eq!(opening.leaves()[0].leaf_index(), 0);
    }
}

#[test]
fn frontier_maximum_recurrence_matches_every_small_tree_subset() {
    for leaf_count in [1_usize, 2, 4, 8, 16] {
        let mut exhaustive_maxima = vec![0_usize; leaf_count + 1];
        let subset_count = 1_u32 << u32::try_from(leaf_count).expect("small test tree fits");
        for subset_mask in 1..subset_count {
            let selected_leaf_indexes = (0..leaf_count)
                .filter(|leaf_index| subset_mask & (1_u32 << leaf_index) != 0)
                .map(|leaf_index| u64::try_from(leaf_index).expect("small test index fits"))
                .collect::<Vec<_>>();
            let selected_leaf_count = selected_leaf_indexes.len();
            exhaustive_maxima[selected_leaf_count] = exhaustive_maxima[selected_leaf_count].max(
                minimal_frontier_node_count(&selected_leaf_indexes, leaf_count)
                    .expect("small tree frontier derives"),
            );
        }
        for (selected_leaf_count, exhaustive_maximum) in exhaustive_maxima
            .iter()
            .copied()
            .enumerate()
            .take(leaf_count + 1)
            .skip(1)
        {
            assert_eq!(
                maximum_minimal_frontier_node_count(leaf_count, selected_leaf_count)
                    .expect("frontier maximum derives"),
                exhaustive_maximum,
                "leaf count {leaf_count}, selected leaf count {selected_leaf_count}",
            );
        }
    }
}

#[test]
fn canonical_proof_ceiling_matches_each_tree_maximum_across_folded_query_orbits() {
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        vec![0],
        Vec::new(),
        1,
        1,
        3,
        3,
        8,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            16,
            vec![RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                row_width: 2,
                leaf_visibility: ProofLeafVisibility::Public,
            }],
        ),
        &schedule,
    )
    .expect("test catalog derives");
    let layout = ProofBodyLayout::new(catalog, &schedule, 1).expect("test layout derives");
    let canonical_header_byte_length = 96;
    let ceiling = canonical_common_proof_byte_length_ceiling(canonical_header_byte_length, &layout)
        .expect("canonical proof ceiling derives");
    assert_eq!(ceiling.canonical_header_byte_length(), 96);
    assert_eq!(
        ceiling.body_prefix_byte_length(),
        proof_body_prefix_byte_length(&layout).expect("prefix length derives")
    );
    assert_eq!(ceiling.query_trees().len(), layout.catalog.entries.len());
    assert_eq!(
        ceiling.proof_byte_length(),
        ceiling.canonical_header_byte_length()
            + ceiling.body_prefix_byte_length()
            + ceiling.query_section_byte_length()
    );
    let components = ceiling.component_byte_lengths();
    assert_eq!(
        components.proof_byte_length(),
        Some(ceiling.proof_byte_length())
    );
    assert_eq!(
        components.canonical_framing(),
        canonical_header_byte_length
            + 4
            + 12
            + ceiling
                .query_trees()
                .iter()
                .map(ProofQueryTreeByteLengthCeiling::canonical_framing_byte_length)
                .sum::<usize>()
    );
    assert!(components.relation_commitments_and_openings() > 0);
    assert!(components.quotient_commitments_and_openings() > 0);
    assert!(components.transcript_opening_claims() > 0);
    assert!(components.fri() > 0);
    for tree in ceiling.query_trees() {
        assert_eq!(
            tree.opened_leaf_payload_byte_length()
                + tree.authentication_frontier_digest_byte_length()
                + tree.canonical_framing_byte_length(),
            tree.byte_length()
        );
    }

    let mut exact_tree_maxima = vec![0_usize; layout.catalog.entries.len()];
    for first_query in 0..6_u64 {
        for second_query in first_query + 1..7_u64 {
            for third_query in second_query + 1..8_u64 {
                let query_representatives = [first_query, second_query, third_query];
                let mut exact_proof_byte_length =
                    canonical_header_byte_length + ceiling.body_prefix_byte_length() + 4;
                for (catalog_index, exact_tree_maximum) in exact_tree_maxima.iter_mut().enumerate()
                {
                    let exact_tree_byte_length = proof_query_tree_byte_length(
                        &layout,
                        catalog_index,
                        &query_representatives,
                    )
                    .expect("exact tree length derives");
                    *exact_tree_maximum = (*exact_tree_maximum).max(exact_tree_byte_length);
                    exact_proof_byte_length += exact_tree_byte_length;
                }
                assert!(exact_proof_byte_length <= ceiling.proof_byte_length());
            }
        }
    }
    assert_eq!(
        ceiling
            .query_trees()
            .iter()
            .map(ProofQueryTreeByteLengthCeiling::byte_length)
            .collect::<Vec<_>>(),
        exact_tree_maxima
    );
    assert_eq!(
        ceiling.maximum_query_tree_byte_length(),
        exact_tree_maxima.into_iter().max().unwrap()
    );

    let final_fri_tree = ceiling.query_trees().last().expect("FRI tree exists");
    assert!(matches!(
        final_fri_tree.source(),
        ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal: 1 }
    ));
    assert_eq!(final_fri_tree.tree_height(), 1);
    assert_eq!(final_fri_tree.leaf_count(), 2);
    assert_eq!(final_fri_tree.minimum_opened_leaf_count(), 1);
    assert_eq!(final_fri_tree.maximum_opened_leaf_count(), 2);
    assert!(final_fri_tree.canonical_leaf_byte_length() > 0);
    assert!(final_fri_tree.opened_leaf_count_at_ceiling() > 0);
    assert!(final_fri_tree.authentication_frontier_node_count_at_ceiling() <= 1);
}

#[test]
fn catalog_and_decoder_enforce_secret_root_order_and_leaf_grammar() {
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::SecretBearing,
        vec![0],
        vec![0],
        1,
        1,
        2,
        1,
        2,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            4,
            vec![
                RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::AuxiliaryOracle,
                    row_width: 1,
                    leaf_visibility: ProofLeafVisibility::Public,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    row_width: 2,
                    leaf_visibility: ProofLeafVisibility::SecretBearing,
                },
            ],
        ),
        &schedule,
    )
    .expect("secret catalog derives");
    assert_eq!(
        catalog
            .entries()
            .iter()
            .map(ProofTreeCatalogEntry::source)
            .collect::<Vec<_>>(),
        [
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                tree_ordinal: 0,
            },
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                tree_ordinal: 0,
            },
            ProofTreeCatalogSource::QuotientComponent {
                component_ordinal: 0,
            },
            ProofTreeCatalogSource::OpeningBatchMask,
            ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal: 0 },
        ]
    );
    let layout = ProofBodyLayout::new(catalog, &schedule, 1).expect("secret layout derives");
    let tree_openings = layout
        .catalog
        .entries
        .iter()
        .map(common_tree_opening)
        .collect::<Vec<_>>();
    let bytes = encode_body(
        &layout,
        &tree_openings,
        &[extension_value(9)],
        &[extension_value(19)],
    );
    let mut opened_catalog_indexes = Vec::new();
    let pending = decode_proof_body_prefix(&bytes, bytes.len(), bytes.len(), &layout)
        .expect("secret prefix decodes");
    let (mut transcript, mut absorber) =
        query_opening_absorber(pending.query_section_byte_length().unwrap());
    pending
        .decode_query_section(&[0], &mut absorber, |opening| {
            opened_catalog_indexes.push(opening.catalog_entry().tree_catalog_index());
            Ok(())
        })
        .expect("secret body decodes");
    transcript
        .finish_query_openings(absorber)
        .expect("streamed query bytes finish");
    assert_eq!(opened_catalog_indexes, [0, 1, 2, 3, 4]);
}

#[test]
fn statement_owned_material_and_setup_trees_use_their_exact_leaf_and_node_equations() {
    let material_context_hash = [0x63; 64];
    let setup_context_hash = [0x74; 64];
    let material_construction = ProofTreeConstruction::CommittedMaterial {
        material_context_hash,
        row_width: COMMITTED_MATERIAL_ROW_WIDTH,
    };
    let setup_construction = ProofTreeConstruction::SetupPolynomial {
        public_polynomial_context_hash: setup_context_hash,
        row_width: 2,
    };
    let material_opening = statement_tree_opening(
        material_construction,
        COMMITTED_MATERIAL_LEAF_HASH_DOMAIN,
        COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        material_context_hash,
        COMMITTED_MATERIAL_ROW_WIDTH as usize,
        true,
    );
    let setup_opening = statement_tree_opening(
        setup_construction,
        SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
        SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        setup_context_hash,
        2,
        false,
    );
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::SecretBearing,
        Vec::new(),
        Vec::new(),
        1,
        1,
        1,
        1,
        2,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            4,
            vec![
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash,
                        expected_root: material_opening.root,
                    },
                ),
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::SetupPolynomial {
                        public_polynomial_context_hash: setup_context_hash,
                        row_width: 2,
                        expected_root: setup_opening.root,
                    },
                ),
            ],
        ),
        &schedule,
    )
    .expect("bound-tree catalog derives");
    let layout = ProofBodyLayout::new(catalog, &schedule, 1).expect("bound layout derives");
    let quotient_opening = common_tree_opening(&layout.catalog.entries[2]);
    let opening_batch_mask = common_tree_opening(&layout.catalog.entries[3]);
    let tree_openings = vec![
        material_opening,
        setup_opening,
        quotient_opening,
        opening_batch_mask,
    ];
    let bytes = encode_body(
        &layout,
        &tree_openings,
        &[extension_value(29)],
        &[extension_value(39)],
    );
    for (entry, opening) in layout.catalog.entries().iter().zip(&tree_openings) {
        assert_eq!(
            opening.opened_leaf_bytes[0].len(),
            canonical_leaf_byte_length(entry).expect("planned leaf length derives"),
            "materialized leaf length must equal its storage and proof plan",
        );
    }
    let canonical_header_byte_length = 96;
    let ceiling = canonical_common_proof_byte_length_ceiling(canonical_header_byte_length, &layout)
        .expect("exact statement-owned proof length derives");
    assert_eq!(
        canonical_header_byte_length + bytes.len(),
        ceiling.proof_byte_length(),
        "the complete materialized proof must equal its exact one-query plan",
    );
    let mut observed_widths = Vec::new();
    let pending = decode_proof_body_prefix(&bytes, bytes.len(), bytes.len(), &layout)
        .expect("bound prefix decodes");
    let (mut transcript, mut absorber) =
        query_opening_absorber(pending.query_section_byte_length().unwrap());
    pending
        .decode_query_section(&[0], &mut absorber, |opening| {
            observed_widths.push(opening.leaves()[0].first_point_values().len());
            Ok(())
        })
        .expect("statement-owned openings authenticate");
    transcript
        .finish_query_openings(absorber)
        .expect("streamed query bytes finish");
    assert_eq!(observed_widths, [4, 2, 1, 1]);
}

#[test]
fn planned_secret_leaf_lengths_match_the_production_materializer() {
    let material_context_hash = [0x83; 64];
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::SecretBearing,
        vec![0],
        Vec::new(),
        1,
        1,
        1,
        1,
        2,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            4,
            vec![
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash,
                        expected_root: [0x91; 64],
                    },
                ),
                RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    row_width: 3,
                    leaf_visibility: ProofLeafVisibility::SecretBearing,
                },
            ],
        ),
        &schedule,
    )
    .expect("secret materializer catalog derives");

    for entry in catalog.entries().iter().filter(|entry| {
        matches!(
            entry.source(),
            ProofTreeCatalogSource::RelationBoundPublic
                | ProofTreeCatalogSource::RelationProofCreated { .. }
        )
    }) {
        let row_width = entry
            .materialized_row_width()
            .expect("materialized row width derives");
        let first_point_values = Zeroizing::new(
            (0..row_width)
                .map(|column_ordinal| ProofTreeValue::Base(base_value(101 + column_ordinal as u64)))
                .collect(),
        );
        let opposite_point_values = Zeroizing::new(
            (0..row_width)
                .map(|column_ordinal| ProofTreeValue::Base(base_value(211 + column_ordinal as u64)))
                .collect(),
        );
        let (canonical_bytes, _) = entry
            .encode_materialized_leaf(
                0,
                Some([0xa7; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]),
                first_point_values,
                opposite_point_values,
            )
            .expect("production leaf materializer accepts planned values");
        assert_eq!(
            canonical_bytes.len(),
            canonical_leaf_byte_length(entry).expect("planned leaf length derives"),
            "planned and materialized secret leaf lengths must remain identical",
        );
    }
}

#[test]
fn setup_polynomial_two_pass_replay_emits_exact_decoder_accepted_opening() {
    let context_hash = [0x6d; 64];
    let construction = ProofTreeConstruction::SetupPolynomial {
        public_polynomial_context_hash: context_hash,
        row_width: 2,
    };
    let expected_opening = statement_tree_opening(
        construction.clone(),
        SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
        SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        context_hash,
        2,
        false,
    );
    let entry = ProofTreeCatalogEntry {
        tree_catalog_index: 0,
        source: ProofTreeCatalogSource::RelationBoundPublic,
        construction,
        bound_root: Some(expected_opening.root),
    };
    let leaf_values = |value_seed: u64| {
        (
            Zeroizing::new(
                (0..2)
                    .map(|column_index| ProofTreeValue::Base(base_value(value_seed + column_index)))
                    .collect(),
            ),
            Zeroizing::new(
                (0..2)
                    .map(|column_index| {
                        ProofTreeValue::Base(base_value(value_seed + 31 + column_index))
                    })
                    .collect(),
            ),
        )
    };

    let mut root_pass = StatementOwnedMerkleReplay::new_root_pass(&entry, 4)
        .expect("the compact root pass initializes");
    assert_eq!(
        root_pass
            .resident_owned_payload_byte_length()
            .expect("the root-pass payload is measurable"),
        64,
        "the root pass retains exactly one digest for the sole tree level",
    );
    for value_seed in [101, 211] {
        let (first_values, opposite_values) = leaf_values(value_seed);
        root_pass
            .supply_next_leaf(first_values, opposite_values)
            .expect("the root pass accepts the canonical leaf stream");
    }
    let pass_one_root = root_pass
        .finish_root_pass()
        .expect("the root pass reproduces the statement root");
    assert_eq!(pass_one_root, expected_opening.root);

    let mut opening_pass = StatementOwnedMerkleReplay::new_opening_pass(&entry, 4, &[0], 1_048_576)
        .expect("the compact opening pass initializes");
    assert_eq!(
        opening_pass
            .resident_owned_payload_byte_length()
            .expect("the opening-pass payload is measurable"),
        u64::try_from(
            expected_opening.opened_leaf_bytes[0].len()
                + core::mem::size_of::<u64>()
                + core::mem::size_of::<(u32, u64)>()
                + 64
                + 1
                + 64
        )
        .expect("the small exact payload fits u64"),
        "the opening pass retains one leaf, one frontier digest, their indexes, and one stack digest",
    );
    for value_seed in [101, 211] {
        let (first_values, opposite_values) = leaf_values(value_seed);
        opening_pass
            .supply_next_leaf(first_values, opposite_values)
            .expect("the opening pass accepts the identical canonical leaf stream");
    }
    let artifact = opening_pass
        .finish_opening_pass(pass_one_root)
        .expect("the second pass reproduces the first root and compact frontier");
    assert_eq!(artifact.opened_leaf_indexes(), &[0]);
    assert_eq!(
        artifact
            .canonical_leaf_bytes_by_position(0)
            .expect("the opened leaf is present"),
        expected_opening.opened_leaf_bytes[0],
    );
    assert_eq!(artifact.frontier_coordinates(), &[(0, 1)]);
    assert_eq!(
        artifact
            .frontier_digest_by_position(0)
            .expect("the sibling digest is present"),
        expected_opening.frontier[0],
    );

    let catalog = CompleteProofTreeCatalog {
        evaluation_domain_size: 4,
        entries: vec![entry],
    };
    let geometry = CommonProofOpeningGeometry {
        tree_catalog_index: 0,
        leaf_count: 2,
        canonical_leaf_byte_length: expected_opening.opened_leaf_bytes[0].len(),
    };
    let encoded =
        encode_common_proof_query_tree_fragment(&catalog, 0, geometry, &[0], &artifact, 1_048_576)
            .expect("the recomputed compact opening encodes");
    let expected_bytes = [
        canonical_opening_record(0, &expected_opening.opened_leaf_bytes),
        canonical_frontier(0, &expected_opening.frontier),
    ]
    .concat();
    assert_eq!(encoded, expected_bytes);

    let schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        Vec::new(),
        Vec::new(),
        1,
        1,
        1,
        1,
        2,
    );
    let layout =
        ProofBodyLayout::new(catalog, &schedule, 1).expect("the exact decoder layout is valid");
    let source = ResidentCommonProofByteSource::new(
        encoded.len(),
        vec![ResidentCommonProofInputChunk::new(0, &encoded)],
    )
    .expect("the compact opening is resident");
    let (next_offset, decoded) =
        decode_proof_query_tree_at(&source, 0, &layout, 0, pass_one_root, &[0])
            .expect("the production decoder authenticates the two-pass opening");
    assert_eq!(next_offset, encoded.len());
    assert_eq!(
        decoded
            .as_opening(&layout.catalog.entries[0])
            .leaves()
            .len(),
        1
    );
}

#[test]
fn committed_material_two_pass_replay_requires_and_replays_persistent_salts() {
    let material_context_hash = [0x75; 64];
    let construction = ProofTreeConstruction::CommittedMaterial {
        material_context_hash,
        row_width: 2,
    };
    let expected_opening = statement_tree_opening(
        construction.clone(),
        COMMITTED_MATERIAL_LEAF_HASH_DOMAIN,
        COMMITTED_MATERIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        material_context_hash,
        2,
        true,
    );
    let entry = ProofTreeCatalogEntry {
        tree_catalog_index: 0,
        source: ProofTreeCatalogSource::RelationBoundPublic,
        construction,
        bound_root: Some(expected_opening.root),
    };
    let leaf_values = |value_seed: u64| {
        (
            Zeroizing::new(
                (0..2)
                    .map(|column_index| ProofTreeValue::Base(base_value(value_seed + column_index)))
                    .collect(),
            ),
            Zeroizing::new(
                (0..2)
                    .map(|column_index| {
                        ProofTreeValue::Base(base_value(value_seed + 31 + column_index))
                    })
                    .collect(),
            ),
        )
    };

    let mut root_pass = StatementOwnedMerkleReplay::new_root_pass(&entry, 4)
        .expect("the committed-material root pass initializes");
    for (leaf_index, value_seed) in [101, 211].into_iter().enumerate() {
        let (first_values, opposite_values) = leaf_values(value_seed);
        root_pass
            .supply_next_leaf_with_persistent_salt(
                Some(
                    [u8::try_from(leaf_index).expect("test leaf index fits u8") + 0x51;
                        COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                ),
                first_values,
                opposite_values,
            )
            .expect("the root pass accepts the authenticated salt stream");
    }
    let pass_one_root = root_pass
        .finish_root_pass()
        .expect("the compact pass reproduces the committed root");

    let mut opening_pass = StatementOwnedMerkleReplay::new_opening_pass(&entry, 4, &[0], 1_048_576)
        .expect("the committed-material opening pass initializes");
    for (leaf_index, value_seed) in [101, 211].into_iter().enumerate() {
        let (first_values, opposite_values) = leaf_values(value_seed);
        opening_pass
            .supply_next_leaf_with_persistent_salt(
                Some(
                    [u8::try_from(leaf_index).expect("test leaf index fits u8") + 0x51;
                        COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
                ),
                first_values,
                opposite_values,
            )
            .expect("the opening pass accepts the identical authenticated salt stream");
    }
    let artifact = opening_pass
        .finish_opening_pass(pass_one_root)
        .expect("the compact opening authenticates against the committed root");
    assert_eq!(
        artifact
            .canonical_leaf_bytes_by_position(0)
            .expect("the selected committed leaf is retained"),
        expected_opening.opened_leaf_bytes[0],
    );
    assert_eq!(
        artifact
            .frontier_digest_by_position(0)
            .expect("the committed sibling digest is retained"),
        expected_opening.frontier[0],
    );

    let (first_values, opposite_values) = leaf_values(101);
    let mut missing_salt = StatementOwnedMerkleReplay::new_root_pass(&entry, 4)
        .expect("the negative root pass initializes");
    assert_eq!(
        missing_salt.supply_next_leaf(first_values, opposite_values),
        Err(CommonProofProverError::InvalidTree),
    );
}

#[test]
fn setup_polynomial_two_pass_replay_rejects_stale_or_reset_source_material() {
    let context_hash = [0x7d; 64];
    let construction = ProofTreeConstruction::SetupPolynomial {
        public_polynomial_context_hash: context_hash,
        row_width: 1,
    };
    let expected_opening = statement_tree_opening(
        construction.clone(),
        SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_DOMAIN,
        SETUP_PUBLIC_POLYNOMIAL_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
        context_hash,
        1,
        false,
    );
    let entry = ProofTreeCatalogEntry {
        tree_catalog_index: 0,
        source: ProofTreeCatalogSource::RelationBoundPublic,
        construction,
        bound_root: Some(expected_opening.root),
    };
    let values = |seed: u64| {
        (
            Zeroizing::new(vec![ProofTreeValue::Base(base_value(seed))]),
            Zeroizing::new(vec![ProofTreeValue::Base(base_value(seed + 31))]),
        )
    };

    let mut incomplete = StatementOwnedMerkleReplay::new_root_pass(&entry, 4)
        .expect("the first attempt initializes");
    let (first_values, opposite_values) = values(101);
    incomplete
        .supply_next_leaf(first_values, opposite_values)
        .expect("the first attempt accepts one leaf");
    assert_eq!(
        incomplete.finish_root_pass(),
        Err(CommonProofProverError::InvalidTree),
        "an interrupted pass is never upgraded into a reusable root",
    );

    let mut fresh = StatementOwnedMerkleReplay::new_root_pass(&entry, 4)
        .expect("a fresh reset starts from leaf zero");
    for seed in [101, 211] {
        let (first_values, opposite_values) = values(seed);
        fresh
            .supply_next_leaf(first_values, opposite_values)
            .expect("the fresh pass accepts canonical values");
    }
    let pass_one_root = fresh
        .finish_root_pass()
        .expect("the fresh pass reaches the bound root");

    let mut stale_opening =
        StatementOwnedMerkleReplay::new_opening_pass(&entry, 4, &[0], 1_048_576)
            .expect("the opening replay initializes");
    for seed in [101, 212] {
        let (first_values, opposite_values) = values(seed);
        stale_opening
            .supply_next_leaf(first_values, opposite_values)
            .expect("each stale value remains a canonical field value");
    }
    assert!(
        matches!(
            stale_opening.finish_opening_pass(pass_one_root),
            Err(CommonProofProverError::InvalidTree)
        ),
        "a stale second-pass source cannot open the first-pass root",
    );
}

#[test]
fn oracle_equation_namespace_identity_rejects_repeated_statement_tree_constructions() {
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::SecretBearing,
        Vec::new(),
        Vec::new(),
        1,
        1,
        1,
        1,
        2,
    );
    let repeated_context_hash = [0x6b; 64];
    let repeated_catalog = build_complete_proof_tree_catalog(
        catalog_input(
            4,
            vec![
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: repeated_context_hash,
                        expected_root: [0x31; 64],
                    },
                ),
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: repeated_context_hash,
                        expected_root: [0x32; 64],
                    },
                ),
            ],
        ),
        &schedule,
    )
    .expect("a repeated construction remains a structurally valid catalog");
    assert!(
        !repeated_catalog
            .has_pairwise_distinct_oracle_equation_namespaces()
            .expect("namespace identity derives")
    );

    let distinct_catalog = build_complete_proof_tree_catalog(
        catalog_input(
            4,
            vec![
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: repeated_context_hash,
                        expected_root: [0x31; 64],
                    },
                ),
                RelationProofTreeInput::BoundPublic(
                    StatementOwnedProofTreeInput::CommittedMaterial {
                        material_context_hash: [0x6c; 64],
                        expected_root: [0x32; 64],
                    },
                ),
            ],
        ),
        &schedule,
    )
    .expect("the distinct construction catalog derives");
    assert!(
        distinct_catalog
            .has_pairwise_distinct_oracle_equation_namespaces()
            .expect("namespace identity derives")
    );
}

#[test]
fn statement_owned_frontier_accepts_equal_digests_at_distinct_derived_coordinates() {
    let material_context_hash = [0x63; 64];
    let construction = ProofTreeConstruction::CommittedMaterial {
        material_context_hash,
        row_width: COMMITTED_MATERIAL_ROW_WIDTH,
    };
    let opened_leaf_digest = [0x41; 64];
    let repeated_frontier_digest = [0x5a; 64];
    let first_parent = statement_owned_node_digest(
        &construction,
        1,
        0,
        opened_leaf_digest,
        repeated_frontier_digest,
    )
    .expect("first statement-owned parent hashes");
    let expected_root =
        statement_owned_node_digest(&construction, 2, 0, first_parent, repeated_frontier_digest)
            .expect("statement-owned root hashes");
    let entry = ProofTreeCatalogEntry {
        tree_catalog_index: 0,
        source: ProofTreeCatalogSource::RelationBoundPublic,
        construction,
        bound_root: Some(expected_root),
    };

    authenticate_opening(
        &entry,
        &[(0, opened_leaf_digest)],
        &[repeated_frontier_digest; 2],
        expected_root,
        4,
    )
    .expect("equal digest values have distinct verifier-derived coordinates");
}

#[test]
fn layout_deduplicates_fri_collisions_without_changing_global_catalog_indexes() {
    let schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        vec![0],
        Vec::new(),
        1,
        1,
        3,
        2,
        8,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            16,
            vec![RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                row_width: 1,
                leaf_visibility: ProofLeafVisibility::Public,
            }],
        ),
        &schedule,
    )
    .expect("FRI catalog derives");
    let layout = ProofBodyLayout::new(catalog, &schedule, 1).expect("FRI layout derives");
    let fri_entries = layout
        .catalog
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.source,
                ProofTreeCatalogSource::NonterminalFriLayer { .. }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(fri_entries.len(), 2);
    assert_eq!(
        layout.opened_leaf_indexes(fri_entries[0], &[1, 5]).unwrap(),
        [1]
    );
    assert_eq!(
        layout.opened_leaf_indexes(fri_entries[1], &[1, 5]).unwrap(),
        [1]
    );
    assert_eq!(fri_entries[0].tree_catalog_index(), 2);
    assert_eq!(fri_entries[1].tree_catalog_index(), 3);
}

#[test]
fn catalog_and_layout_reject_invalid_mode_geometry_and_query_sets() {
    let public_schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        vec![0],
        Vec::new(),
        1,
        1,
        1,
        1,
        1,
    );
    assert_eq!(
        build_complete_proof_tree_catalog(
            catalog_input(
                2,
                vec![RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    row_width: 1,
                    leaf_visibility: ProofLeafVisibility::SecretBearing,
                }],
            ),
            &public_schedule,
        ),
        Err(ProofBodyError::InvalidCatalog)
    );

    let impossible_fri_schedule = transcript_schedule(
        CommonProofPrivacyMode::SecretBearing,
        vec![0],
        Vec::new(),
        1,
        1,
        4,
        1,
        2,
    );
    assert_eq!(
        build_complete_proof_tree_catalog(
            catalog_input(
                4,
                vec![RelationProofTreeInput::ProofCreated {
                    tree_role: ProofTreeRole::BaseOracle,
                    row_width: 1,
                    leaf_visibility: ProofLeafVisibility::SecretBearing,
                }],
            ),
            &impossible_fri_schedule,
        ),
        Err(ProofBodyError::InvalidCatalog)
    );

    let two_query_schedule = transcript_schedule(
        CommonProofPrivacyMode::PublicOnly,
        vec![0],
        Vec::new(),
        1,
        1,
        1,
        2,
        4,
    );
    let catalog = build_complete_proof_tree_catalog(
        catalog_input(
            8,
            vec![RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                row_width: 1,
                leaf_visibility: ProofLeafVisibility::Public,
            }],
        ),
        &two_query_schedule,
    )
    .unwrap();
    let layout = ProofBodyLayout::new(catalog, &two_query_schedule, 1).unwrap();
    assert_eq!(
        layout.validate_query_representatives(&[1, 1]),
        Err(ProofBodyError::InvalidQueryRepresentatives)
    );
    assert_eq!(
        layout.validate_query_representatives(&[1, 4]),
        Err(ProofBodyError::InvalidQueryRepresentatives)
    );
    assert_eq!(
        layout.validate_query_representatives(&[1]),
        Err(ProofBodyError::InvalidQueryRepresentatives)
    );
    assert_eq!(minimal_frontier_node_count(&[0, 1, 6], 8).unwrap(), 3);
}

#[test]
fn decoder_rejects_wrong_roots_indices_lengths_noncanonical_fields_and_trailing_bytes() {
    let (layout, _, _, _, canonical_bytes) = simple_public_body();

    let mut wrong_root = canonical_bytes.clone();
    wrong_root[0] ^= 0x80;
    assert_eq!(
        decode_complete_body(&wrong_root, &layout),
        Err(ProofBodyError::Merkle(ProofMerkleError::RootMismatch))
    );

    let opening_header = [0x07, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00];
    let opening_offset = canonical_bytes
        .windows(opening_header.len())
        .position(|window| window == opening_header)
        .expect("opening header occurs");
    let mut wrong_catalog_index = canonical_bytes.clone();
    wrong_catalog_index[opening_offset + 14] = 1;
    assert_eq!(
        decode_complete_body(&wrong_catalog_index, &layout),
        Err(ProofBodyError::InvalidTreeCatalogIndex)
    );

    let mut wrong_leaf_length = canonical_bytes.clone();
    let inner_leaf_length_offset = opening_offset + 28;
    wrong_leaf_length[inner_leaf_length_offset] ^= 1;
    assert_eq!(
        decode_complete_body(&wrong_leaf_length, &layout),
        Err(ProofBodyError::InvalidItemLength)
    );

    let frontier_header = [0x08, 0x01, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00];
    let frontier_offset = canonical_bytes
        .windows(frontier_header.len())
        .position(|window| window == frontier_header)
        .expect("frontier header occurs");
    let mut wrong_frontier_element_type = canonical_bytes.clone();
    wrong_frontier_element_type[frontier_offset + 22..frontier_offset + 24].copy_from_slice(
        &CanonicalItemType::NestedTuple
            .canonical_code()
            .to_le_bytes(),
    );
    assert_eq!(
        decode_complete_body(&wrong_frontier_element_type, &layout),
        Err(ProofBodyError::InvalidItemType)
    );

    let mut wrong_frontier_count = canonical_bytes.clone();
    wrong_frontier_count[frontier_offset + 24..frontier_offset + 28]
        .copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(
        decode_complete_body(&wrong_frontier_count, &layout),
        Err(ProofBodyError::InvalidListCount)
    );

    let mut wrong_frontier_length = canonical_bytes.clone();
    wrong_frontier_length[frontier_offset + 18] ^= 1;
    assert_eq!(
        decode_complete_body(&wrong_frontier_length, &layout),
        Err(ProofBodyError::InvalidItemLength)
    );

    let root_byte_length = layout.catalog.entries.len() * 64;
    let mut noncanonical_field = canonical_bytes.clone();
    noncanonical_field[root_byte_length + 6..root_byte_length + 14]
        .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
    assert_eq!(
        decode_complete_body(&noncanonical_field, &layout),
        Err(ProofBodyError::Decode(
            ProofDecodeError::NonCanonicalFieldElement
        ))
    );

    let mut trailing = canonical_bytes;
    trailing.push(0);
    assert_eq!(
        decode_complete_body(&trailing, &layout),
        Err(ProofBodyError::Decode(ProofDecodeError::TrailingBytes))
    );
}
