use crate::{DEGREE, Error, RECIPIENTS, SEED_BITS, modulus, profile};
use num_bigint::{BigInt, Sign};
use parallel_work::ProtocolHash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub poll: [u8; 64],
    pub roster: [u8; 64],
    pub author: u16,
    pub sealed_body: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub public_key: Vec<BigInt>,
    pub ciphertext: [Vec<BigInt>; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub scope: Scope,
    pub common: Vec<BigInt>,
    pub recipients: Vec<Recipient>,
}
fn header() -> Vec<u8> {
    let mut bytes = b"OSS1".to_vec();
    let profile = profile();
    for value in [
        DEGREE,
        RECIPIENTS,
        SEED_BITS,
        profile.release_threshold(),
        profile.sharing_coefficient_bits(),
        profile.share_limb_bits(),
        profile.share_carry_bits(),
    ] {
        bytes.extend((value as u32).to_le_bytes());
    }
    bytes.extend(supported_profile::share_modulus());
    bytes
}
pub fn encoded_bytes() -> usize {
    header().len() + 194 + (1 + 3 * RECIPIENTS) * DEGREE * 21
}
pub(crate) fn valid_polynomial(values: &[BigInt]) -> bool {
    let half = modulus() >> 1usize;
    values.len() == DEGREE
        && values
            .iter()
            .all(|value| value >= &(-&half) && value <= &half)
}
impl Statement {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if usize::from(self.scope.author) >= RECIPIENTS
            || self.recipients.len() != RECIPIENTS
            || !valid_polynomial(&self.common)
            || self.recipients.iter().any(|recipient| {
                !valid_polynomial(&recipient.public_key)
                    || recipient
                        .ciphertext
                        .iter()
                        .any(|values| !valid_polynomial(values))
            })
        {
            return Err("Statement shape or coefficient");
        }
        let mut bytes = header();
        bytes.extend(self.scope.poll);
        bytes.extend(self.scope.roster);
        bytes.extend(self.scope.author.to_le_bytes());
        bytes.extend(self.scope.sealed_body);
        for polynomial in
            std::iter::once(&self.common).chain(self.recipients.iter().flat_map(|recipient| {
                [
                    &recipient.public_key,
                    &recipient.ciphertext[0],
                    &recipient.ciphertext[1],
                ]
            }))
        {
            for value in polynomial {
                let (sign, magnitude) = value.to_bytes_le();
                bytes.push(u8::from(sign == Sign::Minus));
                bytes.extend(&magnitude);
                bytes.resize(bytes.len() + 20 - magnitude.len(), 0);
            }
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], expected: &Scope) -> Result<Self, Error> {
        let prefix = header();
        if bytes.len() != encoded_bytes() || !bytes.starts_with(&prefix) {
            return Err("Statement encoding");
        }
        let mut offset = prefix.len();
        let scope = Scope {
            poll: bytes[offset..offset + 64].try_into().unwrap(),
            roster: bytes[offset + 64..offset + 128].try_into().unwrap(),
            author: u16::from_le_bytes(bytes[offset + 128..offset + 130].try_into().unwrap()),
            sealed_body: bytes[offset + 130..offset + 194].try_into().unwrap(),
        };
        offset += 194;
        if &scope != expected || usize::from(scope.author) >= RECIPIENTS {
            return Err("Statement context");
        }
        let mut polynomial = || -> Result<Vec<BigInt>, Error> {
            let mut values = Vec::with_capacity(DEGREE);
            for _ in 0..DEGREE {
                let record = &bytes[offset..offset + 21];
                offset += 21;
                if record[0] > 1 || (record[0] == 1 && record[1..].iter().all(|byte| *byte == 0)) {
                    return Err("Noncanonical coefficient");
                }
                values.push(BigInt::from_bytes_le(
                    if record[0] == 1 {
                        Sign::Minus
                    } else {
                        Sign::Plus
                    },
                    &record[1..],
                ));
            }
            if !valid_polynomial(&values) {
                return Err("Coefficient outside modulus");
            }
            Ok(values)
        };
        let common = polynomial()?;
        let mut recipients = Vec::new();
        for _ in 0..RECIPIENTS {
            recipients.push(Recipient {
                public_key: polynomial()?,
                ciphertext: [polynomial()?, polynomial()?],
            });
        }
        Ok(Self {
            scope,
            common,
            recipients,
        })
    }
    pub fn digest(&self) -> Result<[u8; 64], Error> {
        let mut hash = ProtocolHash::new();
        hash.update(self.encode()?);
        Ok(hash.finalize())
    }
}
