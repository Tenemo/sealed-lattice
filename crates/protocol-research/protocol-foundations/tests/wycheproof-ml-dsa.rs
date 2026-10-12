//! ML-DSA-65 conformance of the pinned `fips204` release, which the
//! participant module signs and verifies with, against the Wycheproof
//! vectors in `test-vectors/wycheproof`. The vectors fix the
//! signature of each message and context under a key seed and the signing
//! randomness, and the verdict on modified signatures, public keys, lengths
//! and contexts, including contexts over the 255-byte bound. The runtime
//! derives every signing key from its seed and never decodes an expanded
//! private key, so the expanded-key signing vectors are not used; this
//! release's expanded-key decoder accepts the out-of-range secret vectors of
//! their tests 56 and 57.
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use serde_json::Value as Json;

const VERIFY: &str = include_str!("../../../../test-vectors/wycheproof/mldsa_65_verify_test.json");
const SIGN_SEED: &str =
    include_str!("../../../../test-vectors/wycheproof/mldsa_65_sign_seed_test.json");

/// The bytes of a hexadecimal member, or none when it is absent or null.
fn bytes(value: &Json, name: &str) -> Option<Vec<u8>> {
    value
        .get(name)
        .filter(|value| !value.is_null())
        .map(|value| {
            let text = value.as_str().expect("hexadecimal string").as_bytes();
            assert!(text.len().is_multiple_of(2), "hex member {name}");
            text.chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        })
}

/// Every test of a file with its group, after checking the file's algorithm
/// and its declared test count.
fn tests(file: &Json) -> Vec<(&Json, &Json)> {
    assert_eq!(file["algorithm"].as_str().expect("text field"), "ML-DSA-65");
    let tests: Vec<_> = file["testGroups"]
        .as_array()
        .expect("array field")
        .iter()
        .flat_map(|group| {
            group["tests"]
                .as_array()
                .expect("array field")
                .iter()
                .map(move |test| (group, test))
        })
        .collect();
    assert_eq!(
        tests.len() as i64,
        file["numberOfTests"].as_i64().expect("integer field")
    );
    tests
}

/// Whether a test expects its operation to succeed.
fn expects_valid(test: &Json) -> bool {
    match test["result"].as_str().expect("text field") {
        "valid" => true,
        "invalid" => false,
        other => panic!("result {other}"),
    }
}

fn has_context(test: &Json) -> bool {
    bytes(test, "ctx").is_some_and(|context| !context.is_empty())
}

#[test]
fn verification_matches_every_wycheproof_verdict() {
    let file: Json = serde_json::from_str(VERIFY).expect("valid vector JSON");
    let tests = tests(&file);
    let mut contexts = 0;
    for (group, test) in &tests {
        let identifier = test["tcId"].as_i64().expect("integer field");
        let public = bytes(group, "publicKey").unwrap();
        let message = bytes(test, "msg").unwrap();
        let signature = bytes(test, "sig").unwrap();
        let context = bytes(test, "ctx").unwrap_or_default();
        contexts += usize::from(has_context(test));
        // As the participant module reads a verification key and a
        // signature: fixed lengths, then a decoded key.
        let verified = <[u8; ml_dsa_65::PK_LEN]>::try_from(public.as_slice())
            .ok()
            .and_then(|bytes| ml_dsa_65::PublicKey::try_from_bytes(bytes).ok())
            .zip(<[u8; ml_dsa_65::SIG_LEN]>::try_from(signature.as_slice()).ok())
            .is_some_and(|(key, signature)| key.verify(&message, &signature, &context));
        assert_eq!(
            verified,
            expects_valid(test),
            "verification test {identifier}"
        );
    }
    assert_eq!(tests.len(), 210);
    assert!(contexts > 0);
}

#[test]
fn seeded_signing_reproduces_every_wycheproof_signature() {
    let file: Json = serde_json::from_str(SIGN_SEED).expect("valid vector JSON");
    let tests = tests(&file);
    // A group's key pair, none for a seed of another length.
    let key = |group: &Json| {
        let seed: [u8; 32] = bytes(group, "privateSeed")?.try_into().ok()?;
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&seed);
        assert_eq!(
            public.clone().into_bytes().as_slice(),
            bytes(group, "publicKey").unwrap()
        );
        Some((public, private))
    };
    // Tests that give only the internal message representative, which this
    // interface does not sign, are counted apart.
    let (mut checked, mut contexts, mut internal) = (0, 0, 0);
    for (group, test) in &tests {
        let identifier = test["tcId"].as_i64().expect("integer field");
        let Some(message) = bytes(test, "msg") else {
            assert!(test.get("mu").is_some(), "signing test {identifier}");
            internal += 1;
            continue;
        };
        let context = bytes(test, "ctx").unwrap_or_default();
        contexts += usize::from(has_context(test));
        // Deterministic signing uses all-zero randomness.
        let randomness: [u8; 32] =
            bytes(test, "rnd").map_or([0; 32], |bytes| bytes.try_into().unwrap());
        let signature = key(group).and_then(|(public, private)| {
            let signature = private
                .try_sign_with_seed(&randomness, &message, &context)
                .ok()?;
            assert!(public.verify(&message, &signature, &context));
            Some(signature)
        });
        match signature {
            Some(signature) => {
                assert!(expects_valid(test), "signing test {identifier}");
                assert_eq!(
                    signature.as_slice(),
                    bytes(test, "sig").unwrap(),
                    "signing test {identifier}"
                );
            }
            None => assert!(!expects_valid(test), "signing test {identifier}"),
        }
        checked += 1;
    }
    assert_eq!((checked, internal), (88, 17));
    assert!(contexts > 0);
}
