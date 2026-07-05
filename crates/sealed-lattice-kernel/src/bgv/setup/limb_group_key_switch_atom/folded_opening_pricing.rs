//! Folded-opening pricing for the limb-group key-switch digit atom.
//!
//! This test-only module prices the two proof pieces that decide whether the
//! atom-granularity prover fits the per-key proof-byte budget:
//!
//! 1. The honest hash-based 128-query source/material opening, implemented as a
//!    real salted batched Merkle opening over the atom proof field. The salted
//!    leaf, 32-byte node digest, and deduplicated batched-opening walk mirror
//!    the kernel's `trustee_evaluation_key_proof::merkle_commitment`
//!    construction (same `hash256` primitive, same domain framing), so the
//!    serialized byte count is the real one that construction would produce.
//! 2. The folded-accumulator plus two degree-1 outer sumchecks that reduce the
//!    per-query codeword-consistency and carry/range rows to two terminal
//!    values. This is a faithful diagnostic-scale skeleton: real field folding,
//!    real Fiat-Shamir challenges, real per-round transcripts, and a real
//!    sumcheck consistency check, serialized to measure the algebraic bytes.
//!
//! Both pieces are verified and tamper-checked here. Neither is a production
//! proof backend, a security parameterization, or phone-device evidence; this
//! module measures bytes, prover time, and structure at atom shape so the
//! per-key budget can be checked against measured, not modeled, values.
//!
//! Reference shapes (`temp/eval-key-mobile-research/one-key-mobile-prototype`):
//! folded backend accumulator skeleton and accumulator sumcheck prototype;
//! honest 128-query opening cost. Designs only; no external code is used.

use std::time::{Duration, Instant};

use super::proof_field::{ProofFieldParameters, sixteen_limb_group_field_parameters};
use crate::bgv::parameters::POLYNOMIAL_DEGREE;
use crate::hashing::hash256;

// --- Fixed measurement parameters -------------------------------------------

/// Security queries for the honest opening (128-bit transparent target).
const SECURITY_QUERIES: usize = 128;
/// Digit atoms per key at active level 15 (16 key-switch digits).
const ATOMS_PER_KEY: usize = 16;
/// Keys in the trustee evaluation-key schedule.
const KEYS_PER_TRUSTEE: usize = 25;
/// Per-key proof-byte gate: 5 MiB preferred hard stop.
const PER_KEY_PROOF_BYTE_HARD_STOP: usize = 5 * 1024 * 1024;

/// Committed witness columns opened per digit atom: error, error square,
/// carry, carry sign, low carry-range window, high carry-range window.
const PER_DIGIT_OPENED_COLUMNS: usize = 6;

/// Node digest and leaf salt widths, matching the kernel Merkle construction.
const DIGEST_BYTES: usize = 32;
const SALT_BYTES: usize = 32;

const LEAF_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/opening-leaf-v1";
const NODE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/opening-node-v1";
const SALT_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/opening-salt-v1";
const QUERY_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/opening-query-v1";
const SYMBOL_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/opening-symbol-v1";
const CHALLENGE_DOMAIN: &str = "sealed-lattice/setup/limb-group-atom/accumulator-challenge-v1";

// --- Byte-faithful salted batched Merkle (mirrors merkle_commitment.rs) ------

type Digest = [u8; DIGEST_BYTES];

fn node_digest(left: &Digest, right: &Digest) -> Digest {
    hash256(NODE_DOMAIN, &[left, right])
}

fn leaf_digest(index: usize, salt: &Digest, row_bytes: &[u8]) -> Digest {
    hash256(
        LEAF_DOMAIN,
        &[&(index as u64).to_le_bytes(), salt, row_bytes],
    )
}

struct SaltedMerkleTree {
    levels: Vec<Vec<Digest>>,
}

impl SaltedMerkleTree {
    fn from_leaf_hashes(leaf_hashes: Vec<Digest>) -> Self {
        assert!(
            !leaf_hashes.is_empty() && leaf_hashes.len().is_power_of_two(),
            "leaf count must be a non-empty power of two"
        );
        let mut levels = vec![leaf_hashes];
        while levels.last().expect("levels non-empty").len() > 1 {
            let previous = levels.last().expect("levels non-empty");
            let mut next = Vec::with_capacity(previous.len() / 2);
            for pair in previous.chunks_exact(2) {
                next.push(node_digest(&pair[0], &pair[1]));
            }
            levels.push(next);
        }
        Self { levels }
    }

    fn root(&self) -> Digest {
        self.levels.last().expect("levels non-empty")[0]
    }

    fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Deduplicated batched authentication nodes for a sorted, unique index set,
    /// emitted leaf-to-root in the same order `verify_batch` consumes them.
    fn open_batch(&self, sorted_unique: &[usize]) -> Vec<Digest> {
        let mut authentication_nodes = Vec::new();
        let mut current = sorted_unique.to_vec();
        for level in &self.levels[..self.levels.len() - 1] {
            let mut parents = Vec::new();
            let mut cursor = 0;
            while cursor < current.len() {
                let node_index = current[cursor];
                if cursor + 1 < current.len() && current[cursor + 1] == (node_index ^ 1) {
                    cursor += 2;
                } else {
                    authentication_nodes.push(level[node_index ^ 1]);
                    cursor += 1;
                }
                let parent_index = node_index >> 1;
                if parents.last() != Some(&parent_index) {
                    parents.push(parent_index);
                }
            }
            current = parents;
        }
        authentication_nodes
    }
}

/// Recompute the root from a batched opening; rejects short/padded node lists.
fn verify_batch(
    root: &Digest,
    depth: usize,
    sorted_unique_leaves: &[(usize, Digest)],
    authentication_nodes: &[Digest],
) -> bool {
    let mut current = sorted_unique_leaves.to_vec();
    let mut node_cursor = 0;
    for _ in 0..depth {
        let mut parents: Vec<(usize, Digest)> = Vec::new();
        let mut cursor = 0;
        while cursor < current.len() {
            let (node_index, node_hash) = current[cursor];
            let sibling = if cursor + 1 < current.len() && current[cursor + 1].0 == (node_index ^ 1)
            {
                let sibling = current[cursor + 1].1;
                cursor += 2;
                sibling
            } else {
                let Some(supplied) = authentication_nodes.get(node_cursor) else {
                    return false;
                };
                node_cursor += 1;
                cursor += 1;
                *supplied
            };
            let (left, right) = if node_index & 1 == 0 {
                (node_hash, sibling)
            } else {
                (sibling, node_hash)
            };
            let parent_index = node_index >> 1;
            let parent_hash = node_digest(&left, &right);
            if parents.last().map(|(index, _)| *index) != Some(parent_index) {
                parents.push((parent_index, parent_hash));
            }
        }
        current = parents;
    }
    node_cursor == authentication_nodes.len()
        && current.len() == 1
        && current[0].0 == 0
        && &current[0].1 == root
}

fn sorted_unique(indices: impl IntoIterator<Item = usize>) -> Vec<usize> {
    indices
        .into_iter()
        .collect::<std::collections::BTreeSet<usize>>()
        .into_iter()
        .collect()
}

/// Fiat-Shamir query indices below `modulus`, expanded from the commitment root.
fn query_indices(root: &Digest, modulus: usize, count: usize) -> Vec<usize> {
    let mut indices = Vec::with_capacity(count);
    let mut counter = 0_u64;
    while indices.len() < count {
        let block = hash256(QUERY_DOMAIN, &[root, &counter.to_le_bytes()]);
        for chunk in block.chunks_exact(8) {
            if indices.len() == count {
                break;
            }
            let word = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
            indices.push((word % modulus as u64) as usize);
        }
        counter += 1;
    }
    indices
}

// --- Proof-field symbol serialization ---------------------------------------

/// Fixed-width serialized length of a field element: the byte length of the
/// modulus, so every element fits and the width leaks nothing.
fn field_symbol_bytes<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
) -> usize {
    let modulus = parameters.modulus;
    let highest = (0..LIMB_COUNT)
        .rev()
        .find(|index| modulus[*index] != 0)
        .expect("modulus is nonzero");
    let top_bytes = (64 - modulus[highest].leading_zeros()).div_ceil(8) as usize;
    highest * 8 + top_bytes
}

fn serialize_symbol<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    element: &[u64; LIMB_COUNT],
    symbol_bytes: usize,
) -> Vec<u8> {
    let raw = parameters.to_raw_value(element);
    let mut bytes = Vec::with_capacity(LIMB_COUNT * 8);
    for limb in raw {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes.truncate(symbol_bytes);
    bytes
}

/// A deterministic pseudo-random field element, so committed material has the
/// real serialized width without materializing a full witness. The byte counts
/// this module reports are independent of the values.
fn pseudo_symbol<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    column: usize,
    position: usize,
) -> [u64; LIMB_COUNT] {
    let digest = hash256(
        SYMBOL_DOMAIN,
        &[
            &(column as u64).to_le_bytes(),
            &(position as u64).to_le_bytes(),
        ],
    );
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte prefix"));
    parameters.unsigned_word_to_element(word)
}

fn leaf_salt(seed: u64, position: usize) -> Digest {
    hash256(
        SALT_DOMAIN,
        &[&seed.to_le_bytes(), &(position as u64).to_le_bytes()],
    )
}

// --- Honest 128-query opening pricing ----------------------------------------

struct OpeningMeasurement {
    proof_bytes: usize,
    authentication_nodes: usize,
    opened_rows: usize,
    row_bytes: usize,
    verified: bool,
    tamper_rejected: bool,
}

/// Commit `columns` field-symbol columns over `num_leaves` positions in one
/// salted Merkle tree, open `num_queries` Fiat-Shamir positions with a batched
/// opening, verify it, and price the serialized proof. The proof carries the
/// root, the deduplicated authentication nodes, and each opened row's salt and
/// symbol bytes.
fn price_honest_opening<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    columns: usize,
    num_leaves: usize,
    num_queries: usize,
    seed: u64,
) -> OpeningMeasurement {
    let symbol_bytes = field_symbol_bytes(parameters);
    let row_bytes = columns * symbol_bytes;

    let build_row = |position: usize| -> Vec<u8> {
        let mut row = Vec::with_capacity(row_bytes);
        for column in 0..columns {
            let symbol = pseudo_symbol(parameters, column, position);
            row.extend_from_slice(&serialize_symbol(parameters, &symbol, symbol_bytes));
        }
        row
    };

    // Commit: one salted leaf per position over all columns.
    let mut leaves = Vec::with_capacity(num_leaves);
    for position in 0..num_leaves {
        let salt = leaf_salt(seed, position);
        leaves.push(leaf_digest(position, &salt, &build_row(position)));
    }
    let tree = SaltedMerkleTree::from_leaf_hashes(leaves);
    let root = tree.root();
    let depth = tree.depth();

    // Open: batched authentication over the Fiat-Shamir query set.
    let indices = sorted_unique(query_indices(&root, num_leaves, num_queries));
    let authentication_nodes = tree.open_batch(&indices);
    let opened_leaves: Vec<(usize, Digest)> = indices
        .iter()
        .map(|position| {
            let salt = leaf_salt(seed, *position);
            (
                *position,
                leaf_digest(*position, &salt, &build_row(*position)),
            )
        })
        .collect();

    let verified = verify_batch(&root, depth, &opened_leaves, &authentication_nodes);

    // Tamper: a flipped authentication node must be rejected.
    let tamper_rejected = if authentication_nodes.is_empty() {
        true
    } else {
        let mut tampered = authentication_nodes.clone();
        tampered[0][0] ^= 0x01;
        !verify_batch(&root, depth, &opened_leaves, &tampered)
    };

    // Serialized proof: root + authentication nodes + per-opened-row salt and
    // revealed symbol bytes.
    let proof_bytes = DIGEST_BYTES
        + authentication_nodes.len() * DIGEST_BYTES
        + indices.len() * (SALT_BYTES + row_bytes);

    OpeningMeasurement {
        proof_bytes,
        authentication_nodes: authentication_nodes.len(),
        opened_rows: indices.len(),
        row_bytes,
        verified,
        tamper_rejected,
    }
}

// --- Folded-accumulator plus outer-sumcheck algebraic skeleton ---------------

struct AlgebraicMeasurement {
    proof_bytes: usize,
    verified: bool,
    tamper_rejected: bool,
}

/// A challenge field element expanded from a transcript digest.
fn challenge_element<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    label: &[u8],
    counter: u64,
) -> [u64; LIMB_COUNT] {
    let digest = hash256(CHALLENGE_DOMAIN, &[label, &counter.to_le_bytes()]);
    let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte prefix"));
    parameters.unsigned_word_to_element(word.max(1))
}

/// One degree-1 sumcheck over a multilinear extension of `terms` (length a
/// power of two). Returns the per-round transcript pairs and the terminal
/// value, all as field elements, plus whether the round-consistency check
/// holds. Real folding, real Fiat-Shamir; a diagnostic-scale skeleton.
fn degree_one_sumcheck<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    terms: &[[u64; LIMB_COUNT]],
    label: &[u8],
) -> (Vec<[u64; LIMB_COUNT]>, [u64; LIMB_COUNT], bool) {
    assert!(terms.len().is_power_of_two() && !terms.is_empty());
    let mut table = terms.to_vec();
    let mut claim = table.iter().fold(parameters.zero(), |accumulator, value| {
        parameters.add(&accumulator, value)
    });
    let mut transcript = Vec::new();
    let mut consistent = true;
    let mut round = 0_u64;
    while table.len() > 1 {
        let half = table.len() / 2;
        // Degree-1 round message: partial sums at the two boundary assignments.
        let eval_zero = table[..half]
            .iter()
            .fold(parameters.zero(), |accumulator, value| {
                parameters.add(&accumulator, value)
            });
        let eval_one = table[half..]
            .iter()
            .fold(parameters.zero(), |accumulator, value| {
                parameters.add(&accumulator, value)
            });
        // Consistency: g(0) + g(1) must equal the running claim.
        if parameters.add(&eval_zero, &eval_one) != claim {
            consistent = false;
        }
        transcript.push(eval_zero);
        transcript.push(eval_one);
        let challenge = challenge_element(parameters, label, round);
        // Fold: table[i] = (1 - r) * table[i] + r * table[i + half].
        let mut folded = Vec::with_capacity(half);
        for index in 0..half {
            let low = table[index];
            let high = table[index + half];
            let difference = parameters.subtract(&high, &low);
            folded.push(parameters.add(&low, &parameters.multiply(&challenge, &difference)));
        }
        claim = parameters.add(
            &eval_zero,
            &parameters.multiply(&challenge, &parameters.subtract(&eval_one, &eval_zero)),
        );
        table = folded;
        round += 1;
    }
    (transcript, table[0], consistent)
}

/// Prices the folded-accumulator plus two outer sumchecks for one atom. The
/// codeword-consistency family folds 361 query terms and the carry/range family
/// 393, each padded to 512 for a nine-variable degree-1 sumcheck. Returns the
/// serialized transcript bytes and verification/tamper results.
fn price_algebraic_skeleton<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    seed: u64,
) -> AlgebraicMeasurement {
    let symbol_bytes = field_symbol_bytes(parameters);
    const CODEWORD_TERMS: usize = 361;
    const CARRY_RANGE_TERMS: usize = 393;
    const PADDED: usize = 512;

    let build_terms = |count: usize, family: u64| -> Vec<[u64; LIMB_COUNT]> {
        let mut terms = Vec::with_capacity(PADDED);
        for index in 0..PADDED {
            if index < count {
                let digest = hash256(
                    CHALLENGE_DOMAIN,
                    &[
                        b"folded-term",
                        &seed.to_le_bytes(),
                        &family.to_le_bytes(),
                        &(index as u64).to_le_bytes(),
                    ],
                );
                let word = u64::from_le_bytes(digest[..8].try_into().expect("8-byte prefix"));
                terms.push(parameters.unsigned_word_to_element(word));
            } else {
                terms.push(parameters.zero());
            }
        }
        terms
    };

    let codeword = build_terms(CODEWORD_TERMS, 0);
    let carry_range = build_terms(CARRY_RANGE_TERMS, 1);

    let (codeword_transcript, codeword_terminal, codeword_ok) =
        degree_one_sumcheck(parameters, &codeword, b"codeword");
    let (carry_transcript, carry_terminal, carry_ok) =
        degree_one_sumcheck(parameters, &carry_range, b"carry-range");

    // Bind the two folded families into one accumulator root over the terminals.
    let combined = parameters.add(&codeword_terminal, &carry_terminal);
    let accumulator_root = hash256(
        CHALLENGE_DOMAIN,
        &[
            b"accumulator-root",
            &serialize_symbol(parameters, &codeword_terminal, symbol_bytes),
            &serialize_symbol(parameters, &carry_terminal, symbol_bytes),
            &serialize_symbol(parameters, &combined, symbol_bytes),
        ],
    );

    let verified = codeword_ok && carry_ok;

    // Tamper: perturbing a transcript element must break round consistency or
    // the recomputed accumulator root.
    let tamper_rejected = {
        let mut tampered = codeword.clone();
        tampered[0] = parameters.add(&tampered[0], &parameters.one());
        let (_, tampered_terminal, _) = degree_one_sumcheck(parameters, &tampered, b"codeword");
        let tampered_combined = parameters.add(&tampered_terminal, &carry_terminal);
        let tampered_root = hash256(
            CHALLENGE_DOMAIN,
            &[
                b"accumulator-root",
                &serialize_symbol(parameters, &tampered_terminal, symbol_bytes),
                &serialize_symbol(parameters, &carry_terminal, symbol_bytes),
                &serialize_symbol(parameters, &tampered_combined, symbol_bytes),
            ],
        );
        tampered_root != accumulator_root
    };

    // Serialized transcript: both sumcheck round pairs, both terminals, and the
    // accumulator root digest.
    let transcript_elements = codeword_transcript.len() + carry_transcript.len() + 2;
    let proof_bytes = transcript_elements * symbol_bytes + DIGEST_BYTES;

    AlgebraicMeasurement {
        proof_bytes,
        verified,
        tamper_rejected,
    }
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn mebibytes(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_opening_round_trips_and_rejects_tampering() {
        let parameters = sixteen_limb_group_field_parameters();
        // A reduced-leaf shape keeps the unit test fast while exercising the
        // batched open/verify/tamper path over multiple columns.
        let measurement = price_honest_opening(&parameters, 4, 1024, 64, 0xa70de);
        assert!(measurement.verified, "batched opening must verify");
        assert!(
            measurement.tamper_rejected,
            "a flipped authentication node must be rejected"
        );
        assert!(measurement.authentication_nodes > 0);
        assert!(measurement.opened_rows > 0 && measurement.opened_rows <= 64);
    }

    #[test]
    fn honest_opening_bytes_scale_with_columns_not_leaves() {
        let parameters = sixteen_limb_group_field_parameters();
        // Revealed-row bytes track columns; leaf count changes only the tree
        // depth, so doubling leaves must not double the proof.
        let one_column = price_honest_opening(&parameters, 1, 4096, 32, 1);
        let four_columns = price_honest_opening(&parameters, 4, 4096, 32, 1);
        assert!(
            four_columns.row_bytes > one_column.row_bytes * 3,
            "row bytes grow with columns"
        );
        let deeper = price_honest_opening(&parameters, 1, 8192, 32, 1);
        assert!(
            deeper.proof_bytes < one_column.proof_bytes * 2,
            "a deeper tree must not double the proof bytes"
        );
    }

    #[test]
    fn algebraic_skeleton_is_consistent_and_rejects_tampering() {
        let parameters = sixteen_limb_group_field_parameters();
        let measurement = price_algebraic_skeleton(&parameters, 0x5eed);
        assert!(
            measurement.verified,
            "sumcheck round consistency must hold on honest terms"
        );
        assert!(
            measurement.tamper_rejected,
            "a perturbed folded term must change the accumulator root"
        );
        // The algebraic transcript is small relative to a 5 MiB per-key budget.
        assert!(measurement.proof_bytes < 16 * 1024);
    }

    #[test]
    fn field_symbol_bytes_matches_the_modulus_width() {
        let parameters = sixteen_limb_group_field_parameters();
        // p = 4166^64 + 1 is 770 bits, so a fixed-width symbol is 97 bytes.
        assert_eq!(field_symbol_bytes(&parameters), 97);
    }

    /// Prints the atom-shape pricing table and the per-key gate verdict. Run:
    /// `cargo test -p sealed-lattice-kernel limb_group_atom_opening_pricing \
    ///     -- --ignored --nocapture --test-threads=1`
    #[test]
    #[ignore = "atom-shape opening pricing benchmark; run explicitly with --ignored --nocapture"]
    fn limb_group_atom_opening_pricing() {
        let parameters = sixteen_limb_group_field_parameters();
        let symbol_bytes = field_symbol_bytes(&parameters);
        let ring = POLYNOMIAL_DEGREE;
        println!("== limb-group atom opening pricing ==");
        println!(
            "ring degree {ring}, proof field symbol {symbol_bytes} bytes, {SECURITY_QUERIES} queries"
        );

        // Honest source opening (shared across a key's atoms): one column.
        let source_start = Instant::now();
        let source = price_honest_opening(&parameters, 1, ring, SECURITY_QUERIES, 0x5011ce);
        let source_ms = milliseconds(source_start.elapsed());
        println!(
            "source opening (1 column, {ring} leaves): {} bytes ({:.1} KiB), {} auth nodes, {} rows, verify {}, tamper-reject {}, {source_ms:.0} ms",
            source.proof_bytes,
            source.proof_bytes as f64 / 1024.0,
            source.authentication_nodes,
            source.opened_rows,
            source.verified,
            source.tamper_rejected,
        );

        // Conservative full-key opening: every opened witness column of all 16
        // digit atoms committed in one tree and opened directly (no accumulator
        // folding), a strict upper bound on the per-key opening.
        let full_columns = PER_DIGIT_OPENED_COLUMNS * ATOMS_PER_KEY + 1;
        let full_start = Instant::now();
        let full_key =
            price_honest_opening(&parameters, full_columns, ring, SECURITY_QUERIES, 0xf0);
        let full_ms = milliseconds(full_start.elapsed());
        println!(
            "conservative full-key opening ({full_columns} columns): {} bytes ({:.2} MiB), {} auth nodes, {} rows, verify {}, tamper-reject {}, {full_ms:.0} ms",
            full_key.proof_bytes,
            mebibytes(full_key.proof_bytes),
            full_key.authentication_nodes,
            full_key.opened_rows,
            full_key.verified,
            full_key.tamper_rejected,
        );

        // Algebraic skeleton per atom.
        let algebraic_start = Instant::now();
        let algebraic = price_algebraic_skeleton(&parameters, 0xa16);
        let algebraic_ms = milliseconds(algebraic_start.elapsed());
        println!(
            "algebraic skeleton per atom (folded accumulator + 2 sumchecks): {} bytes, verify {}, tamper-reject {}, {algebraic_ms:.2} ms",
            algebraic.proof_bytes, algebraic.verified, algebraic.tamper_rejected,
        );

        // Per-key and per-trustee totals under the conservative model.
        let per_atom_algebraic = algebraic.proof_bytes;
        let per_key_conservative = full_key.proof_bytes + per_atom_algebraic * ATOMS_PER_KEY;
        let per_trustee_conservative = per_key_conservative * KEYS_PER_TRUSTEE;
        println!("== per-key / per-trustee (conservative direct-open model) ==");
        println!(
            "per-key: {} bytes ({:.2} MiB) = full-key opening {:.2} MiB + {ATOMS_PER_KEY} x algebraic {} bytes",
            per_key_conservative,
            mebibytes(per_key_conservative),
            mebibytes(full_key.proof_bytes),
            per_atom_algebraic,
        );
        println!(
            "per-trustee ({KEYS_PER_TRUSTEE} keys): {} bytes ({:.1} MiB)",
            per_trustee_conservative,
            mebibytes(per_trustee_conservative),
        );

        // Folded model: source opening amortized once per key plus the algebraic
        // reductions, the design-faithful lower estimate.
        let per_key_folded = source.proof_bytes + per_atom_algebraic * ATOMS_PER_KEY;
        println!(
            "per-key (folded model, 1 source opening + algebraic): {} bytes ({:.1} KiB)",
            per_key_folded,
            per_key_folded as f64 / 1024.0,
        );

        // Gate verdict against the 5 MiB per-key hard stop.
        let gate_pass = per_key_conservative <= PER_KEY_PROOF_BYTE_HARD_STOP;
        println!("== gate ==");
        println!(
            "per-key proof-byte hard stop {} bytes (5 MiB): conservative per-key {} bytes -> {}",
            PER_KEY_PROOF_BYTE_HARD_STOP,
            per_key_conservative,
            if gate_pass { "PASS" } else { "STOP" },
        );

        assert!(source.verified && full_key.verified && algebraic.verified);
        assert!(source.tamper_rejected && full_key.tamper_rejected && algebraic.tamper_rejected);
    }
}
