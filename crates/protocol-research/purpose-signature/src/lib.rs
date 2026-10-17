use parallel_work::ProtocolHash;
use zeroize::Zeroizing;

pub const PURPOSES: usize = 16;
pub const SIGNING_CONTEXTS: [&[u8]; 12] = [
    b"sealed-lattice/poll-definition",
    b"sealed-lattice/registration",
    b"sealed-lattice/roster-proposal",
    b"sealed-lattice/contribution-offer",
    b"sealed-lattice/setup-selection-proposal",
    b"sealed-lattice/setup-selection-endorsement",
    b"sealed-lattice/ballot-envelope",
    b"sealed-lattice/close-intent",
    b"sealed-lattice/close-response",
    b"sealed-lattice/close-proposal",
    b"sealed-lattice/target-certification",
    b"sealed-lattice/release-envelope",
];
pub const CHAINS: usize = 131;
pub const SIGNATURE_BYTES: usize = 2 + (CHAINS + 4) * 64;
type Digest = [u8; 64];

fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut value = ProtocolHash::new();
    value.update(domain);
    for part in parts {
        value.update(part);
    }
    value.finalize()
}

fn step(value: &Digest) -> Digest {
    hash(b"purpose-wots/chain/v1", &[value])
}

fn start(seed: &Digest, purpose: u8, chain: usize) -> Digest {
    hash(
        b"purpose-wots/secret/v1",
        &[seed, &[purpose], &(chain as u16).to_le_bytes()],
    )
}

fn digits(message: &Digest) -> [u8; CHAINS] {
    let mut output = [0; CHAINS];
    let mut checksum = 0u16;
    for (index, byte) in message.iter().copied().enumerate() {
        output[2 * index] = byte >> 4;
        output[2 * index + 1] = byte & 15;
        checksum += 30 - u16::from(byte >> 4) - u16::from(byte & 15);
    }
    output[128] = ((checksum >> 8) & 15) as u8;
    output[129] = ((checksum >> 4) & 15) as u8;
    output[130] = (checksum & 15) as u8;
    output
}

fn message_digest(root: &Digest, purpose: u8, message: &[u8]) -> Digest {
    hash(
        b"purpose-wots/message/v1",
        &[
            root,
            &[purpose],
            &(message.len() as u64).to_le_bytes(),
            message,
        ],
    )
}

fn leaf(purpose: u8, public_key: &[u8]) -> Digest {
    hash(b"purpose-wots/leaf/v1", &[&[purpose], public_key])
}

fn parent(level: u8, left: &Digest, right: &Digest) -> Digest {
    hash(b"purpose-wots/node/v1", &[&[level], left, right])
}

struct UsedPurpose {
    representative: Digest,
    signature: Vec<u8>,
}

// One credential's signer. Within one value it keeps the first representative
// of each purpose, refuses a different frame for it and repeats the first
// signature for the same frame. The protocol credential builds a new signer
// for every signature, so its one-shot purpose flags, the custody capsule and
// the worker's committed purpose generations carry the one-frame rule.
pub struct Credential {
    seed: Zeroizing<Digest>,
    tree: Vec<Digest>,
    used: [Option<UsedPurpose>; PURPOSES],
}

impl Credential {
    pub fn new(seed: Digest) -> Self {
        let seed = Zeroizing::new(seed);
        let mut tree = vec![[0; 64]; 2 * PURPOSES];
        for purpose in 0..PURPOSES {
            if purpose >= SIGNING_CONTEXTS.len() {
                tree[PURPOSES + purpose] = hash(b"purpose-wots/unused/v1", &[&[purpose as u8]]);
                continue;
            }
            let mut public_key = Vec::with_capacity(CHAINS * 64);
            for chain in 0..CHAINS {
                let mut value = Zeroizing::new(start(&seed, purpose as u8, chain));
                for _ in 0..15 {
                    *value = step(&value);
                }
                public_key.extend_from_slice(&*value);
            }
            tree[PURPOSES + purpose] = leaf(purpose as u8, &public_key);
        }
        let mut width = PURPOSES;
        let mut level = 0;
        while width > 1 {
            for index in width / 2..width {
                tree[index] = parent(level, &tree[2 * index], &tree[2 * index + 1]);
            }
            width /= 2;
            level += 1;
        }
        Self {
            seed,
            tree,
            used: std::array::from_fn(|_| None),
        }
    }

    pub fn public_key(&self) -> Digest {
        self.tree[1]
    }

    pub fn sign_context(
        &mut self,
        context: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let purpose = SIGNING_CONTEXTS
            .iter()
            .position(|value| *value == context)
            .ok_or("Unknown signing context")?;
        self.sign(purpose as u8, message)
    }

    pub fn sign(&mut self, purpose: u8, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let index = usize::from(purpose);
        if index >= SIGNING_CONTEXTS.len() {
            return Err("Invalid purpose");
        }
        let representative = message_digest(&self.public_key(), purpose, message);
        if let Some(previous) = &self.used[index] {
            return if previous.representative == representative {
                Ok(previous.signature.clone())
            } else {
                Err("Purpose already used for another frame")
            };
        }
        let encoded = digits(&representative);
        let mut signature = Vec::with_capacity(SIGNATURE_BYTES);
        signature.extend_from_slice(&[1, purpose]);
        for (chain, count) in encoded.into_iter().enumerate() {
            let mut value = Zeroizing::new(start(&self.seed, purpose, chain));
            for _ in 0..count {
                *value = step(&value);
            }
            signature.extend_from_slice(&*value);
        }
        let mut position = PURPOSES + index;
        while position > 1 {
            signature.extend_from_slice(&self.tree[position ^ 1]);
            position /= 2;
        }
        self.used[index] = Some(UsedPurpose {
            representative,
            signature: signature.clone(),
        });
        Ok(signature)
    }
}

pub fn verify(root: &Digest, expected_purpose: u8, message: &[u8], signature: &[u8]) -> bool {
    if expected_purpose as usize >= SIGNING_CONTEXTS.len()
        || signature.len() != SIGNATURE_BYTES
        || signature[0] != 1
        || signature[1] != expected_purpose
    {
        return false;
    }
    let encoded = digits(&message_digest(root, expected_purpose, message));
    let mut public_key = Vec::with_capacity(CHAINS * 64);
    for (chain, count) in encoded.into_iter().enumerate() {
        let mut value: Digest = signature[2 + chain * 64..2 + (chain + 1) * 64]
            .try_into()
            .unwrap();
        for _ in count..15 {
            value = step(&value);
        }
        public_key.extend_from_slice(&value);
    }
    let mut node = leaf(expected_purpose, &public_key);
    let mut position = usize::from(expected_purpose);
    for level in 0..4 {
        let offset = 2 + (CHAINS + level) * 64;
        let sibling: Digest = signature[offset..offset + 64].try_into().unwrap();
        node = if position & 1 == 0 {
            parent(level as u8, &node, &sibling)
        } else {
            parent(level as u8, &sibling, &node)
        };
        position >>= 1;
    }
    node == *root
}

pub fn verify_context(root: &Digest, context: &[u8], message: &[u8], signature: &[u8]) -> bool {
    SIGNING_CONTEXTS
        .iter()
        .position(|value| *value == context)
        .is_some_and(|purpose| verify(root, purpose as u8, message, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_covers_extreme_and_mixed_messages() {
        for message in [
            [0; 64],
            [255; 64],
            [0x5a; 64],
            std::array::from_fn(|i| i as u8),
        ] {
            let encoded = digits(&message);
            let checksum: usize = encoded[..128]
                .iter()
                .map(|value| usize::from(15 - value))
                .sum();
            assert_eq!(
                checksum,
                256 * usize::from(encoded[128])
                    + 16 * usize::from(encoded[129])
                    + usize::from(encoded[130])
            );
            assert!(encoded.iter().all(|value| *value < 16));
        }
    }

    #[test]
    fn all_purposes_are_bound_and_cannot_authorize_replacement() {
        let mut credential = Credential::new([0x39; 64]);
        let root = credential.public_key();
        for purpose in 0..12 {
            let message: Vec<u8> = (0..usize::from(purpose) * 97)
                .map(|i| (i * 11) as u8)
                .collect();
            let context = SIGNING_CONTEXTS[usize::from(purpose)];
            let signature = credential.sign_context(context, &message).unwrap();
            assert!(verify(&root, purpose, &message, &signature));
            assert!(verify_context(&root, context, &message, &signature));
            assert!(!verify_context(
                &root,
                SIGNING_CONTEXTS[usize::from(purpose ^ 1)],
                &message,
                &signature
            ));
            assert_eq!(credential.sign(purpose, &message).unwrap(), signature);
            let mut replacement = message.clone();
            replacement.push(0x80);
            assert!(credential.sign(purpose, &replacement).is_err());
            assert!(!verify(&root, purpose, &replacement, &signature));
            assert!(!verify(&root, purpose ^ 1, &message, &signature));
            for index in [0, 1, 2, 2 + 128 * 64, SIGNATURE_BYTES - 1] {
                let mut changed = signature.clone();
                changed[index] ^= 1;
                assert!(!verify(&root, purpose, &message, &changed));
            }
            assert!(!verify(
                &root,
                purpose,
                &message,
                &signature[..SIGNATURE_BYTES - 1]
            ));
            let mut extended = signature.clone();
            extended.push(0);
            assert!(!verify(&root, purpose, &message, &extended));
        }
        assert!(credential.sign(16, b"invalid").is_err());
        assert!(credential.sign(12, b"unused leaf").is_err());
        assert!(credential.sign(15, b"unused leaf").is_err());
        assert!(
            credential
                .sign_context(b"sealed-lattice/registration", b"invalid")
                .is_err()
        );
        assert!(!verify_context(&root, b"unknown", b"invalid", &[]));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // The independent purpose-signature model computes the same root and
    // signature digests on Node's SHAKE256 for this seed and these frames.
    #[test]
    fn signatures_match_the_independent_model() {
        let mut credential = Credential::new([0x39; 64]);
        assert_eq!(
            hex(&credential.public_key()),
            "1cb9cbd79d9d8a0333b75f285eaaccf81857802b58ac0fda955545688c05fd45\
             85ef64d81f18f860344c622823a5904df69af3a2b44c4c264dc3751cb8e3c310"
        );
        for (purpose, expected) in [
            (
                0,
                "c0831560df1e820c0cfa5efdecd71d9845370ef3cf345128c13a729e3d07bdee\
                 05a85d0f7f87bfca8adcff8bf50817a516d823a0ef13a09ecae08ff3ed38a237",
            ),
            (
                7,
                "bb71e80e088b4d46b8eda9c2a79a8d9a7f80b723f6b9478dd3806b0b3ab4fc37\
                 be65ecc87b7d5593ebc6fbfbd35a5903ea35f69b48de1fbbd74d0b6db1deeac2",
            ),
            (
                11,
                "af861de5533718b1a5e99c3ed3281c45c186b6ead1bea3b007fd811d80ca8cdf\
                 107621a15fd56ad6e4826c5995ebae636c016431f13a3d5761d0c65d23b5476f",
            ),
        ] {
            let message: Vec<u8> = (0..usize::from(purpose) * 97)
                .map(|i| (i * 11) as u8)
                .collect();
            let signature = credential.sign(purpose, &message).unwrap();
            assert_eq!(hex(&ProtocolHash::digest(&signature)), expected);
        }
    }
}
