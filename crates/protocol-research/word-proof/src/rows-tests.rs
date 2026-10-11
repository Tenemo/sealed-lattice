use super::*;
use crate::oracles::extension_values;

// A polynomial of the committed kinds, by its coefficients.
enum Polynomial {
    Base(Vec<u128>),
    Extension(Vec<Element>),
}
fn polynomials(state: &mut u128) -> Vec<Polynomial> {
    let mut extension = |length: usize| -> Vec<Element> {
        (0..length)
            .map(|_| [sample(state), sample(state), sample(state)])
            .collect()
    };
    vec![
        Polynomial::Base(
            extension(SYSTEMATIC + MASKS)
                .iter()
                .map(|value| value[0])
                .collect(),
        ),
        Polynomial::Extension(extension(2 * SYSTEMATIC + 1)),
        Polynomial::Base(extension(SYSTEMATIC).iter().map(|value| value[0]).collect()),
        Polynomial::Extension(extension(SYSTEMATIC + MASKS)),
    ]
}
// The tree whose leaves hash each row's values directly.
fn direct_tree(seed: &[u8; tree::SALT_SEED_BYTES], polynomials: &[Polynomial]) -> Tree {
    let mut tree = Tree::with_seed(
        b"row shards",
        3,
        EVALUATION_DOMAIN_SIZE,
        polynomials.len(),
        Zeroizing::new(*seed),
    );
    let prefix = tree.leaf_hash_prefix();
    let mut hashers: Vec<_> = (0..EVALUATION_DOMAIN_SIZE)
        .map(|row| tree.leaf_hasher(row, &prefix))
        .collect();
    let transform = Transform::cached(SYSTEMATIC);
    for polynomial in polynomials {
        for coset_index in 0..4 {
            match polynomial {
                Polynomial::Base(coefficients) => {
                    let lifted: Vec<Element> =
                        coefficients.iter().map(|value| [*value, 0, 0]).collect();
                    let values = extension_values(&lifted, coset(coset_index), transform);
                    for (position, value) in values.iter().enumerate() {
                        hashers[coset_index + 4 * position].update(value[0].to_le_bytes());
                    }
                }
                Polynomial::Extension(coefficients) => {
                    let values = extension_values(coefficients, coset(coset_index), transform);
                    for (position, value) in values.iter().enumerate() {
                        hashers[coset_index + 4 * position].update(field::encode(*value));
                    }
                }
            }
        }
    }
    for (row, hasher) in hashers.into_iter().enumerate() {
        tree.leaf(row, hasher);
    }
    tree.finish();
    tree
}
// The tree's salt seed without its nodes.
fn unfinished(tree: &Tree) -> Tree {
    Tree::with_seed(
        &tree.role,
        tree.stage,
        tree.length,
        tree.width,
        Zeroizing::new(*tree.seed()),
    )
}
fn absorb(shards: &mut RowShards, polynomial: &Polynomial) {
    match polynomial {
        Polynomial::Base(coefficients) => shards.absorb_base(coefficients),
        Polynomial::Extension(coefficients) => shards.absorb_extension(coefficients),
    }
}
fn resident(session: u64) -> bool {
    SHARDS.with(|shards| shards.borrow().keys().any(|key| key.0 == session))
}

#[test]
fn shards_hash_the_rows_of_the_direct_tree() {
    let mut state = 0x9e3779b97f4a7c15f39cc0605cedc834u128;
    let polynomials = polynomials(&mut state);
    let seed = std::array::from_fn(|_| sample(&mut state) as u8);
    let expected = direct_tree(&seed, &polynomials);
    for classes in [1, 2, 16] {
        let mut tree = unfinished(&expected);
        let mut shards = RowShards::with_classes(classes).opened(&tree);
        let session = shards.session;
        for polynomial in &polynomials {
            absorb(&mut shards, polynomial);
        }
        shards.close(&mut tree);
        assert!(!resident(session));
        assert!(tree.root() == expected.root(), "{classes} classes");
    }
    // Rows exported after a polynomial, in ranges that split the
    // shards' rows unevenly, continue where they stopped once imported
    // in other ranges into other classes.
    let mut tree = unfinished(&expected);
    let mut shards = RowShards::with_classes(2).opened(&tree);
    absorb(&mut shards, &polynomials[0]);
    let states = shards.export(0, EVALUATION_DOMAIN_SIZE);
    let mut first = 0;
    for count in [1, 7, 5_216, 20_000, 1] {
        assert_eq!(
            *shards.export(first, count),
            states[STATE_BYTES * first..STATE_BYTES * (first + count)]
        );
        first += count;
    }
    assert_eq!(
        *shards.export(EVALUATION_DOMAIN_SIZE - 3, 3),
        states[STATE_BYTES * (EVALUATION_DOMAIN_SIZE - 3)..]
    );
    let abandoned = shards.session;
    drop(shards);
    assert!(!resident(abandoned));
    let mut shards = RowShards::with_classes(4);
    let mut first = 0;
    while first < EVALUATION_DOMAIN_SIZE {
        let count = 5_216.min(EVALUATION_DOMAIN_SIZE - first);
        shards.import(
            first,
            &states[STATE_BYTES * first..STATE_BYTES * (first + count)],
        );
        first += count;
    }
    for polynomial in &polynomials[1..] {
        absorb(&mut shards, polynomial);
    }
    shards.close(&mut tree);
    assert!(tree.root() == expected.root());
}

// The helpers' rows together cover every shard's, since the helpers
// hold the shards in turn.
#[test]
fn helper_rows_hold_each_helpers_shards() {
    for (helpers, classes) in [
        (0, 1),
        (1, 1),
        (7, 1),
        (8, 2),
        (15, 2),
        (16, 4),
        (31, 4),
        (32, 8),
    ] {
        assert_eq!(super::classes(helpers), classes);
        let shard = (SYSTEMATIC / classes) * size_of::<ProtocolHash>();
        let rows = helper_rows_bytes(helpers);
        assert!(rows.is_multiple_of(shard));
        assert!(helpers.max(1) * rows >= 4 * classes * shard);
        assert!(helpers.max(1) * rows < 4 * classes * shard + helpers.max(1) * shard);
    }
}

fn sample(state: &mut u128) -> u128 {
    *state ^= *state << 23;
    *state ^= *state >> 31;
    *state ^= *state << 17;
    *state % field::base::MODULUS
}

#[test]
fn residue_classes_equal_the_full_coset_transform() {
    let mut state = 0x2545f4914f6cdd1du128;
    let transform = Transform::cached(SYSTEMATIC);
    for length in [
        1,
        SYSTEMATIC,
        SYSTEMATIC + MASKS,
        2 * SYSTEMATIC,
        2 * SYSTEMATIC + 1,
    ] {
        let coefficients: Vec<Element> = (0..length)
            .map(|_| [sample(&mut state), sample(&mut state), sample(&mut state)])
            .collect();
        for coset_index in 0..4 {
            let full = extension_values(&coefficients, coset(coset_index), transform);
            for classes in [1, 2, 8] {
                for residue in [0, classes - 1] {
                    let shard = (coset_index + 4 * residue) as u32;
                    let values = shard_extension_values_of(
                        length,
                        |index| coefficients[index],
                        shard,
                        classes,
                    );
                    let base_values = shard_base_values_of(
                        length,
                        |index| coefficients[index][0],
                        shard,
                        classes,
                    );
                    for (q, (value, base_value)) in
                        values.iter().zip(base_values.iter()).enumerate()
                    {
                        let position = residue + classes * q;
                        assert_eq!(*value, full[position]);
                        assert_eq!(*base_value, full[position][0]);
                    }
                }
            }
        }
    }
}
