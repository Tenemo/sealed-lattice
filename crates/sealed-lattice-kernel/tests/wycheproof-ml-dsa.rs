//! ML-DSA-65 conformance of the pinned `fips204` release, which the kernel
//! verifies with and the participant runtime signs with, against the
//! Wycheproof vectors in `test-vectors/wycheproof`. The vectors fix the
//! signature of each message and context under a key seed and the signing
//! randomness, and the verdict on modified signatures, public keys, lengths
//! and contexts, including contexts over the 255-byte bound. The runtime
//! derives every signing key from its seed and never decodes an expanded
//! private key, so the expanded-key signing vectors are not used; this
//! release's expanded-key decoder accepts the out-of-range secret vectors of
//! their tests 56 and 57.
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

const VERIFY: &str = include_str!("../../../test-vectors/wycheproof/mldsa_65_verify_test.json");
const SIGN_SEED: &str =
    include_str!("../../../test-vectors/wycheproof/mldsa_65_sign_seed_test.json");

/// A value of the vector files, which hold objects, arrays, strings,
/// integers and null.
enum Json {
    Object(Vec<(String, Json)>),
    Array(Vec<Json>),
    String(String),
    Integer(i64),
    Null,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn skip_space(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }
    fn expect(&mut self, byte: u8) {
        self.skip_space();
        assert_eq!(self.bytes.get(self.at), Some(&byte), "JSON at {}", self.at);
        self.at += 1;
    }
    fn next_is(&mut self, byte: u8) -> bool {
        self.skip_space();
        let found = self.bytes.get(self.at) == Some(&byte);
        if found {
            self.at += 1;
        }
        found
    }
    fn value(&mut self) -> Json {
        self.skip_space();
        match self.bytes[self.at] {
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                if !self.next_is(b'}') {
                    loop {
                        self.skip_space();
                        let Json::String(name) = self.value() else {
                            panic!("JSON member name at {}", self.at)
                        };
                        self.expect(b':');
                        members.push((name, self.value()));
                        if !self.next_is(b',') {
                            self.expect(b'}');
                            break;
                        }
                    }
                }
                Json::Object(members)
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                if !self.next_is(b']') {
                    loop {
                        items.push(self.value());
                        if !self.next_is(b',') {
                            self.expect(b']');
                            break;
                        }
                    }
                }
                Json::Array(items)
            }
            b'"' => {
                self.at += 1;
                let mut text = String::new();
                loop {
                    let byte = self.bytes[self.at];
                    self.at += 1;
                    match byte {
                        b'"' => break,
                        b'\\' => {
                            let escape = self.bytes[self.at];
                            self.at += 1;
                            text.push(match escape {
                                b'"' => '"',
                                b'\\' => '\\',
                                b'/' => '/',
                                b'b' => '\u{8}',
                                b'f' => '\u{c}',
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                b'u' => {
                                    let unit = |at: usize| {
                                        u32::from_str_radix(
                                            std::str::from_utf8(&self.bytes[at..at + 4]).unwrap(),
                                            16,
                                        )
                                        .unwrap()
                                    };
                                    let mut code = unit(self.at);
                                    self.at += 4;
                                    if (0xd800..0xdc00).contains(&code) {
                                        assert_eq!(&self.bytes[self.at..self.at + 2], b"\\u");
                                        let low = unit(self.at + 2);
                                        self.at += 6;
                                        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                                    }
                                    char::from_u32(code).unwrap()
                                }
                                _ => panic!("JSON escape at {}", self.at),
                            });
                        }
                        _ => {
                            // Multi-byte characters pass through whole.
                            let start = self.at - 1;
                            let length = match byte {
                                0x00..=0x7f => 1,
                                0xc0..=0xdf => 2,
                                0xe0..=0xef => 3,
                                _ => 4,
                            };
                            self.at = start + length;
                            text.push_str(
                                std::str::from_utf8(&self.bytes[start..self.at]).unwrap(),
                            );
                        }
                    }
                }
                Json::String(text)
            }
            b'n' => {
                assert_eq!(&self.bytes[self.at..self.at + 4], b"null");
                self.at += 4;
                Json::Null
            }
            _ => {
                let start = self.at;
                while self
                    .bytes
                    .get(self.at)
                    .is_some_and(|byte| *byte == b'-' || byte.is_ascii_digit())
                {
                    self.at += 1;
                }
                Json::Integer(
                    std::str::from_utf8(&self.bytes[start..self.at])
                        .unwrap()
                        .parse()
                        .unwrap_or_else(|_| panic!("JSON integer at {start}")),
                )
            }
        }
    }
}

fn parse(text: &str) -> Json {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = reader.value();
    reader.skip_space();
    assert_eq!(reader.at, text.len(), "JSON trailing bytes");
    value
}

impl Json {
    fn get(&self, name: &str) -> Option<&Json> {
        let Json::Object(members) = self else {
            panic!("JSON object expected for {name}")
        };
        members
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }
    fn items(&self) -> &[Json] {
        let Json::Array(items) = self else {
            panic!("JSON array expected")
        };
        items
    }
    fn text(&self) -> &str {
        let Json::String(text) = self else {
            panic!("JSON string expected")
        };
        text
    }
    fn integer(&self) -> i64 {
        let Json::Integer(value) = self else {
            panic!("JSON integer expected")
        };
        *value
    }
    fn field(&self, name: &str) -> &Json {
        self.get(name)
            .unwrap_or_else(|| panic!("JSON member {name}"))
    }
    /// The bytes of a hexadecimal member, or none when it is absent or null.
    fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.get(name)
            .filter(|value| !matches!(value, Json::Null))
            .map(|value| {
                let text = value.text().as_bytes();
                assert!(text.len().is_multiple_of(2), "hex member {name}");
                text.chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect()
            })
    }
}

/// Every test of a file with its group, after checking the file's algorithm
/// and its declared test count.
fn tests(file: &Json) -> Vec<(&Json, &Json)> {
    assert_eq!(file.field("algorithm").text(), "ML-DSA-65");
    let tests: Vec<_> = file
        .field("testGroups")
        .items()
        .iter()
        .flat_map(|group| {
            group
                .field("tests")
                .items()
                .iter()
                .map(move |test| (group, test))
        })
        .collect();
    assert_eq!(tests.len() as i64, file.field("numberOfTests").integer());
    tests
}

/// Whether a test expects its operation to succeed.
fn expects_valid(test: &Json) -> bool {
    match test.field("result").text() {
        "valid" => true,
        "invalid" => false,
        other => panic!("result {other}"),
    }
}

fn has_context(test: &Json) -> bool {
    test.bytes("ctx").is_some_and(|context| !context.is_empty())
}

#[test]
fn verification_matches_every_wycheproof_verdict() {
    let file = parse(VERIFY);
    let tests = tests(&file);
    let mut contexts = 0;
    for (group, test) in &tests {
        let identifier = test.field("tcId").integer();
        let public = group.bytes("publicKey").unwrap();
        let message = test.bytes("msg").unwrap();
        let signature = test.bytes("sig").unwrap();
        let context = test.bytes("ctx").unwrap_or_default();
        contexts += usize::from(has_context(test));
        // As the kernel reads a verification key and a signature: fixed
        // lengths, then a decoded key.
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
    let file = parse(SIGN_SEED);
    let tests = tests(&file);
    // A group's key pair, none for a seed of another length.
    let key = |group: &Json| {
        let seed: [u8; 32] = group.bytes("privateSeed")?.try_into().ok()?;
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&seed);
        assert_eq!(
            public.clone().into_bytes().as_slice(),
            group.bytes("publicKey").unwrap()
        );
        Some((public, private))
    };
    // Tests that give only the internal message representative, which this
    // interface does not sign, are counted apart.
    let (mut checked, mut contexts, mut internal) = (0, 0, 0);
    for (group, test) in &tests {
        let identifier = test.field("tcId").integer();
        let Some(message) = test.bytes("msg") else {
            assert!(test.get("mu").is_some(), "signing test {identifier}");
            internal += 1;
            continue;
        };
        let context = test.bytes("ctx").unwrap_or_default();
        contexts += usize::from(has_context(test));
        // Deterministic signing uses all-zero randomness.
        let randomness: [u8; 32] = test
            .bytes("rnd")
            .map_or([0; 32], |bytes| bytes.try_into().unwrap());
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
                    test.bytes("sig").unwrap(),
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
