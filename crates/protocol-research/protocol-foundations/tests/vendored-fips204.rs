//! The vendored `fips204` is the crates.io archive its manifest names except
//! for the change the manifest describes: the inverse transform reduces each
//! input coefficient below q in magnitude before its additions, since
//! verification passes it inputs of up to six times q, and the test-support
//! feature exposes that transform to the test below.
use sha3::{Digest, Sha3_256};
use std::{fs, path::Path};

/// The SHA3-256 digest of each archive file that the vendored copy keeps.
/// The manifest's is taken without the archive's generated preamble and its
/// profile, test, bench and dev-dependency sections, which the vendored
/// manifest omits.
const ARCHIVE: [(&str, &str); 15] = [
    (
        "Cargo.toml",
        "6c97314c25f3082c14d5a23bf8b89994096e5d0f541ad39e3eecab3899d6633c",
    ),
    (
        "LICENSE-APACHE",
        "53622056d64c84a6866848070f2ede344c6684c987ec03fb150d4597951cf644",
    ),
    (
        "LICENSE-MIT",
        "4cd874e8a0f8296afadfb11958043fb6b676ec62c7798608b64b2d0938b355c2",
    ),
    (
        "README.md",
        "1c7e7b890192b2db91d9c0e39a875fbd913a96d15c320c64855baa802ebd1a4e",
    ),
    (
        "rustfmt.toml",
        "25cdee223cec671bf90a60d80f51e787ad26013b83b182b0acc7ca40a5c452d4",
    ),
    (
        "src/conversion.rs",
        "b8c8c6b98befe2f44a6a579610b4c9015624484d798af2d549ba2c2534abcd83",
    ),
    (
        "src/encodings.rs",
        "ba1468eef96c72ab9a8e689a547b3b42eff8f968953b7fb76b38d650a6a9f009",
    ),
    (
        "src/hashing.rs",
        "654ecbd0066de0082f9e92a31da486b8a6cdb7729be89c16bd117237158751cd",
    ),
    (
        "src/helpers.rs",
        "df677ff0baff6d70d5a3e1babe7b79ef444ee8b777b4f7a2ac63ad41ce511ae0",
    ),
    (
        "src/high_low.rs",
        "d7d615fa2b66b5802e3a7e0e7f04778ecc649a512f0a1a333f05413c5b275d5b",
    ),
    (
        "src/lib.rs",
        "d1f8ff93ed4f150e7fb5772069a998bd5069faf4be462d133f6ac4839a8ecd3e",
    ),
    (
        "src/ml_dsa.rs",
        "24d54e437b9aab84ee06d2fad21d3c42ca7f921e746f9ffc3fe5a7bc9b711b73",
    ),
    (
        "src/ntt.rs",
        "f68ff9676caeb85758d1c154d1a16fdb5aed42fe7eab64165ada477e5a573d12",
    ),
    (
        "src/traits.rs",
        "75dcac3210d85564e8ef1193a25ffd779135d8f932e310e523ef6f8366bf08e4",
    ),
    (
        "src/types.rs",
        "e4890a8c4ed16db9166fa63c6b4d2e1b064afbc4b7821e1e2d66ebd0b86a22bd",
    ),
];

/// The vendored change, as the vendored and the archive text of each edit.
const CHANGE: [(&str, &str, &str); 4] = [
    ("Cargo.toml", "test-support = []\n", ""),
    (
        "src/lib.rs",
        r#"
/// Vendored change: the inverse transform of one polynomial, for the
/// workspace's regression test of the transform's input reduction.
#[cfg(feature = "test-support")]
#[must_use]
pub fn inverse_transform(coefficients: [i32; 256]) -> [i32; 256] {
    ntt::inv_ntt(&[types::T(coefficients)])[0].0
}
"#,
        "",
    ),
    (
        "src/ntt.rs",
        "use crate::helpers::{full_reduce32, mont_reduce, partial_reduce32, ZETA_TABLE_MONT};",
        "use crate::helpers::{full_reduce32, mont_reduce, ZETA_TABLE_MONT};",
    ),
    (
        "src/ntt.rs",
        r"    // Vendored change: every input is first reduced below q in magnitude.
    // Callers pass sums of up to six Montgomery products, such as a received
    // signature's response during verification, and the additions below
    // leave the first coefficient a sum of all 256 inputs, which then stays
    // within i32 under checked arithmetic.
    let mut w_out: [R; KL] =
        core::array::from_fn(|x| R(core::array::from_fn(|n| partial_reduce32(w_hat[x].0[n]))));
",
        r"    let mut w_out: [R; KL] = core::array::from_fn(|x| R(core::array::from_fn(|n| w_hat[x].0[n])));
",
    ),
];

/// The text after the comment lines that open it and the blank line after
/// them.
fn without_leading_comment(text: &str) -> String {
    let mut rest = text;
    while rest.starts_with('#') {
        rest = &rest[rest.find('\n').unwrap() + 1..];
    }
    rest.strip_prefix('\n').unwrap().to_owned()
}

#[test]
fn the_vendored_copy_is_its_archive_with_the_vendored_change() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vendor/fips204");
    let mut files = Vec::new();
    let mut directories = vec![root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else {
                let file = path.strip_prefix(&root).unwrap().to_str().unwrap();
                files.push(file.replace('\\', "/"));
            }
        }
    }
    files.sort();
    assert_eq!(files, ARCHIVE.map(|(file, _)| file));
    for (file, digest) in ARCHIVE {
        let mut text = fs::read_to_string(root.join(file)).unwrap();
        if file == "Cargo.toml" {
            text = without_leading_comment(&text);
        }
        for (_, vendored, archive) in CHANGE.iter().filter(|(changed, ..)| *changed == file) {
            assert_eq!(text.matches(vendored).count(), 1, "{file}");
            text = text.replacen(vendored, archive, 1);
        }
        let hex: String = Sha3_256::digest(&text)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, digest, "{file}");
    }
}

/// q = 2^23 - 2^13 + 1 and ζ = 1753, FIPS 204's 512th root of unity modulo q.
const Q: i64 = (1 << 23) - (1 << 13) + 1;
const ZETA: i64 = 1753;

fn power(base: i64, exponent: i64) -> i64 {
    (0..i64::BITS).rev().fold(1, |result, bit| {
        let square = result * result % Q;
        if (exponent >> bit) & 1 == 1 {
            square * base % Q
        } else {
            square
        }
    })
}

/// Inputs of up to six times q in magnitude, of either sign, transform to
/// the definition w_j = 256^-1 Σ_i ŵ_i ζ^-(2 brv(i) + 1) j mod q, although
/// their sum leaves the 32-bit range of the transform's additions.
#[test]
fn inverse_transform_inputs_of_up_to_six_q_give_their_residues() {
    assert_eq!(power(ZETA, 256), Q - 1);
    let inverse_degree = power(256, Q - 2);
    for sign in [1, -1] {
        let input: [i32; 256] = std::array::from_fn(|i| sign * (6 * Q as i32 - 1 - (i * i) as i32));
        let total: i64 = input.iter().map(|value| i64::from(*value)).sum();
        assert!(total.abs() > i64::from(i32::MAX));
        for (j, coefficient) in fips204::inverse_transform(input).iter().enumerate() {
            let sum: i64 = input
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    let exponent = (2 * i64::from((i as u8).reverse_bits()) + 1) * j as i64;
                    i64::from(*value) * power(ZETA, 512 - exponent % 512)
                })
                .sum();
            assert_eq!(
                i64::from(*coefficient),
                sum.rem_euclid(Q) * inverse_degree % Q
            );
        }
    }
}
