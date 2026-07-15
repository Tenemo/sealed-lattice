use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple};

use super::super::{
    CommonProofTranscript, PROOF_BASE_FIELD_MODULUS, field::ProofBaseFieldElement,
    merkle::CanonicalProofMerkleTree,
};
use super::*;

#[derive(Clone)]
struct EncodedTreeOpening {
    root: [u8; 64],
    opened_leaf_bytes: Vec<Vec<u8>>,
    frontier: Vec<ParsedAuthenticationNode>,
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
    opening_claim_count: u16,
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
    let salt = (context.leaf_visibility() == ProofLeafVisibility::SecretBearing)
        .then_some([entry.tree_catalog_index() as u8 + leaf_index as u8 + 1; 48]);
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
        vec![ParsedAuthenticationNode {
            level: 0,
            node_index: 1,
            node_digest: leaves[1].digest().expect("sibling leaf hashes"),
        }]
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
            CanonicalItem::fixed_bytes([leaf_index as u8 + 0x51; 48])
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
        frontier: vec![ParsedAuthenticationNode {
            level: 0,
            node_index: 1,
            node_digest: leaf_digests[1],
        }],
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

fn canonical_frontier(tree_catalog_index: u16, frontier: &[ParsedAuthenticationNode]) -> Vec<u8> {
    let nodes = frontier
        .iter()
        .map(|node| {
            CanonicalItem::nested_tuple(&CanonicalTuple::new(
                PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER,
                SCHEMA_VERSION,
                vec![
                    CanonicalItem::unsigned32(node.level),
                    CanonicalItem::unsigned64(node.node_index),
                    CanonicalItem::hash512(node.node_digest),
                ],
            ))
            .expect("authentication node encodes")
        })
        .collect::<Vec<_>>();
    CanonicalTuple::new(
        PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
        SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(tree_catalog_index),
            CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &nodes)
                .expect("frontier list encodes"),
        ],
    )
    .encode()
    .expect("frontier encodes")
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
