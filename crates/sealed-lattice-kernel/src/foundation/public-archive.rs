use std::collections::BTreeSet;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FoundationSchemaError,
    Hash512, RefusalReason, hash_foundation_tuple_512,
};

pub(crate) const MAXIMUM_ARCHIVE_PAYLOAD_BYTES: usize = 1_048_576;
pub(crate) const MAXIMUM_ARCHIVE_RECORD_BYTES: usize = 1_572_864;
pub(crate) const MAXIMUM_ARCHIVE_DEPENDENCIES: usize = 4_096;
pub(crate) const MAXIMUM_ARCHIVE_REPLICAS: usize = 32;
const RECORD_DOMAIN: &str = "sealed-lattice/archive-record/v1";
const RECEIPT_DOMAIN: &str = "sealed-lattice/archive-retention/v1";
type ArchiveResult<T> = Result<T, FoundationSchemaError>;

fn malformed() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::MalformedEncoding,
        "invalid public archive record",
    )
}

fn outside_bounds() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::OutsideSupportedProfile,
        "public archive input exceeds its supported bound",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveReference {
    pub identity: Hash512,
    pub byte_length: u64,
}

impl ArchiveReference {
    pub fn validate(&self) -> ArchiveResult<()> {
        if self.byte_length == 0 || self.byte_length > MAXIMUM_ARCHIVE_RECORD_BYTES as u64 {
            return Err(outside_bounds());
        }
        Ok(())
    }
}

/// Authenticated byte structure only. It grants no protocol capability and
/// does not determine whether the declared dependencies are semantically complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveRecord {
    pub context: Hash512,
    pub purpose: String,
    pub dependencies: Vec<ArchiveReference>,
    pub payload: Vec<u8>,
}

impl ArchiveRecord {
    pub fn encode(&self) -> ArchiveResult<Vec<u8>> {
        if self.purpose.is_empty()
            || self.purpose.len() > 128
            || self.dependencies.len() > MAXIMUM_ARCHIVE_DEPENDENCIES
            || self.payload.len() > MAXIMUM_ARCHIVE_PAYLOAD_BYTES
        {
            return Err(outside_bounds());
        }
        let mut dependencies = Vec::with_capacity(self.dependencies.len() * 72);
        for reference in &self.dependencies {
            reference.validate()?;
            dependencies.extend_from_slice(reference.identity.as_bytes());
            dependencies.extend_from_slice(&reference.byte_length.to_le_bytes());
        }
        let bytes = CanonicalTuple::new(
            1,
            1,
            vec![
                CanonicalItem::nonempty_ascii(RECORD_DOMAIN)?,
                CanonicalItem::hash512(self.context.into_bytes()),
                CanonicalItem::nonempty_ascii(&self.purpose)?,
                CanonicalItem::variable_bytes(dependencies)?,
                CanonicalItem::variable_bytes(&self.payload)?,
            ],
        )
        .encode()?;
        if bytes.len() > MAXIMUM_ARCHIVE_RECORD_BYTES {
            return Err(outside_bounds());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], expected_context: Hash512) -> ArchiveResult<Self> {
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_ARCHIVE_RECORD_BYTES,
            maximum_item_count: 5,
            maximum_item_byte_length: MAXIMUM_ARCHIVE_PAYLOAD_BYTES + 4,
            maximum_nesting_depth: 0,
            ..CanonicalDecodeLimits::default()
        };
        let tuple = CanonicalTuple::decode(bytes, &limits)?;
        if tuple.schema_identifier != 1 || tuple.schema_version != 1 || tuple.items.len() != 5 {
            return Err(malformed());
        }
        let expected_types = [
            CanonicalItemType::Ascii,
            CanonicalItemType::Hash512,
            CanonicalItemType::Ascii,
            CanonicalItemType::RawBytes,
            CanonicalItemType::RawBytes,
        ];
        if tuple
            .items
            .iter()
            .zip(expected_types)
            .any(|(item, kind)| item.item_type() != kind)
            || tuple.items[0].variable_value_bytes()? != RECORD_DOMAIN.as_bytes()
            || tuple.items[1].canonical_bytes() != expected_context.as_bytes()
        {
            return Err(malformed());
        }
        let encoded_dependencies = tuple.items[3].variable_value_bytes()?;
        if encoded_dependencies.len() % 72 != 0
            || encoded_dependencies.len() / 72 > MAXIMUM_ARCHIVE_DEPENDENCIES
        {
            return Err(malformed());
        }
        let dependencies = encoded_dependencies
            .chunks_exact(72)
            .map(|reference| {
                Ok(ArchiveReference {
                    identity: Hash512::from_bytes(
                        reference[..64].try_into().map_err(|_| malformed())?,
                    ),
                    byte_length: u64::from_le_bytes(
                        reference[64..].try_into().map_err(|_| malformed())?,
                    ),
                })
            })
            .collect::<ArchiveResult<Vec<_>>>()?;
        let record = Self {
            context: expected_context,
            purpose: String::from_utf8(tuple.items[2].variable_value_bytes()?.to_vec())
                .map_err(|_| malformed())?,
            dependencies,
            payload: tuple.items[4].variable_value_bytes()?.to_vec(),
        };
        if record.encode()? != bytes {
            return Err(malformed());
        }
        Ok(record)
    }

    pub fn identity(bytes: &[u8]) -> ArchiveResult<Hash512> {
        if bytes.len() > MAXIMUM_ARCHIVE_RECORD_BYTES {
            return Err(outside_bounds());
        }
        Ok(hash_foundation_tuple_512(
            "sealed-lattice/archive-record-id/v1",
            &[CanonicalItem::variable_bytes(bytes)?],
        )?)
    }
}

/// Keys are supplied by the application's trusted replica configuration, never
/// selected from an acknowledgement. Distinct keys are necessary but cannot
/// prove distinct physical fault domains or future retention.
pub(crate) struct ArchivePolicy {
    pub fault_bound: u16,
    pub verification_keys: Vec<[u8; ml_dsa_65::PK_LEN]>,
}

impl ArchivePolicy {
    pub fn identity(&self) -> ArchiveResult<Hash512> {
        let count = self.verification_keys.len();
        if count > MAXIMUM_ARCHIVE_REPLICAS
            || count < 2 * usize::from(self.fault_bound) + 1
            || self.verification_keys.iter().collect::<BTreeSet<_>>().len() != count
        {
            return Err(outside_bounds());
        }
        let keys: Vec<u8> = self.verification_keys.iter().flatten().copied().collect();
        Ok(hash_foundation_tuple_512(
            "sealed-lattice/archive-policy/v1",
            &[
                CanonicalItem::unsigned16(self.fault_bound),
                CanonicalItem::variable_bytes(keys)?,
            ],
        )?)
    }

    pub fn receipt_message(
        &self,
        context: Hash512,
        root: &ArchiveReference,
    ) -> ArchiveResult<Hash512> {
        root.validate()?;
        Ok(hash_foundation_tuple_512(
            RECEIPT_DOMAIN,
            &[
                CanonicalItem::hash512(self.identity()?.into_bytes()),
                CanonicalItem::hash512(context.into_bytes()),
                CanonicalItem::hash512(root.identity.into_bytes()),
                CanonicalItem::unsigned64(root.byte_length),
            ],
        )?)
    }

    /// Success authenticates storage promises under this policy. It does not
    /// verify storage, ordering, ballot publication, a target, or a result.
    pub fn verify_acknowledgements(
        &self,
        context: Hash512,
        root: &ArchiveReference,
        acknowledgements: &[(u16, Vec<u8>)],
    ) -> ArchiveResult<Vec<u16>> {
        if acknowledgements.len() > MAXIMUM_ARCHIVE_REPLICAS {
            return Err(outside_bounds());
        }
        let message = self.receipt_message(context, root)?;
        let mut signers = BTreeSet::new();
        for (position, bytes) in acknowledgements {
            let Some(key) = self.verification_keys.get(usize::from(*position)) else {
                continue;
            };
            let Ok(signature) = <&[u8; ml_dsa_65::SIG_LEN]>::try_from(bytes.as_slice()) else {
                continue;
            };
            let Ok(key) = ml_dsa_65::PublicKey::try_from_bytes(*key) else {
                continue;
            };
            if key.verify(message.as_bytes(), signature, RECEIPT_DOMAIN.as_bytes()) {
                signers.insert(*position);
            }
        }
        if signers.len() <= usize::from(self.fault_bound) {
            return Err(FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "insufficient authenticated archive acknowledgements",
            ));
        }
        Ok(signers.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, Signer};

    fn record() -> ArchiveRecord {
        ArchiveRecord {
            context: Hash512::from_bytes([7; 64]),
            purpose: "ballot-body-chunk".into(),
            dependencies: vec![],
            payload: vec![1, 2, 3],
        }
    }

    #[test]
    fn record_roundtrip_and_exact_context() {
        let record = record();
        let bytes = record.encode().expect("record");
        assert_eq!(
            ArchiveRecord::decode(&bytes, record.context).expect("decode"),
            record
        );
        assert!(ArchiveRecord::decode(&bytes, Hash512::from_bytes([8; 64])).is_err());
        for offset in [0, 2, 4, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert_ne!(
                ArchiveRecord::identity(&changed).expect("hash"),
                ArchiveRecord::identity(&bytes).expect("hash")
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ArchiveRecord::decode(&trailing, record.context).is_err());
        for end in [0, 1, 8, bytes.len() - 1] {
            assert!(ArchiveRecord::decode(&bytes[..end], record.context).is_err());
        }
    }

    #[test]
    fn bounded_payload_dependency_and_purpose_inputs() {
        let mut record = record();
        record.payload = vec![2; MAXIMUM_ARCHIVE_PAYLOAD_BYTES];
        let reference = ArchiveReference {
            identity: Hash512::from_bytes([3; 64]),
            byte_length: 200,
        };
        record.dependencies = vec![reference; MAXIMUM_ARCHIVE_DEPENDENCIES];
        record.purpose = "x".repeat(128);
        let bytes = record.encode().expect("maximum inputs");
        assert_eq!(
            ArchiveRecord::decode(&bytes, record.context).expect("maximum decode"),
            record
        );
        record.payload.push(0);
        assert!(record.encode().is_err());
        record.payload.pop();
        record.dependencies.push(record.dependencies[0].clone());
        assert!(record.encode().is_err());
        record.dependencies.pop();
        record.purpose.push('x');
        assert!(record.encode().is_err());
        record.purpose.pop();
        record.dependencies[0].byte_length = MAXIMUM_ARCHIVE_RECORD_BYTES as u64 + 1;
        assert!(record.encode().is_err());
        record.dependencies[0].byte_length = 0;
        assert!(record.encode().is_err());
        assert!(ArchiveRecord::identity(&vec![0; MAXIMUM_ARCHIVE_RECORD_BYTES + 1]).is_err());
    }

    #[test]
    fn receipts_bind_policy_context_root_and_distinct_signers() {
        let keys: Vec<_> = (1..=3)
            .map(|seed| ml_dsa_65::KG::keygen_from_seed(&[seed; 32]))
            .collect();
        let mut policy = ArchivePolicy {
            fault_bound: 1,
            verification_keys: keys
                .iter()
                .map(|(public, _)| public.clone().into_bytes())
                .collect(),
        };
        let context = Hash512::from_bytes([4; 64]);
        let root = ArchiveReference {
            identity: Hash512::from_bytes([5; 64]),
            byte_length: 300,
        };
        let message = policy.receipt_message(context, &root).expect("message");
        let receipts: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(position, (_, private))| {
                (
                    position as u16,
                    private
                        .try_sign_with_seed(&[6; 32], message.as_bytes(), RECEIPT_DOMAIN.as_bytes())
                        .expect("signature")
                        .to_vec(),
                )
            })
            .collect();
        assert_eq!(
            policy
                .verify_acknowledgements(context, &root, &receipts[..2])
                .expect("quorum"),
            vec![0, 1]
        );
        assert!(
            policy
                .verify_acknowledgements(context, &root, &receipts[..1])
                .is_err()
        );
        assert!(
            policy
                .verify_acknowledgements(
                    context,
                    &root,
                    &[receipts[0].clone(), receipts[0].clone()]
                )
                .is_err()
        );
        assert!(
            policy
                .verify_acknowledgements(Hash512::from_bytes([9; 64]), &root, &receipts)
                .is_err()
        );
        let mut changed_root = root.clone();
        changed_root.byte_length += 1;
        assert!(
            policy
                .verify_acknowledgements(context, &changed_root, &receipts)
                .is_err()
        );
        changed_root = root.clone();
        changed_root.identity = Hash512::from_bytes([8; 64]);
        assert!(
            policy
                .verify_acknowledgements(context, &changed_root, &receipts)
                .is_err()
        );
        let mut mixed = receipts.clone();
        mixed[0].1[0] ^= 1;
        assert_eq!(
            policy
                .verify_acknowledgements(context, &root, &mixed)
                .expect("two valid"),
            vec![1, 2]
        );
        policy.verification_keys.swap(0, 1);
        assert!(
            policy
                .verify_acknowledgements(context, &root, &receipts)
                .is_err()
        );
        policy.verification_keys[1] = policy.verification_keys[0];
        assert!(policy.identity().is_err());
        policy.verification_keys.clear();
        assert!(policy.identity().is_err());
    }

    #[test]
    fn replica_and_acknowledgement_bounds_are_checked_before_verification() {
        let keys: Vec<_> = (1..=33)
            .map(|seed| ml_dsa_65::KG::keygen_from_seed(&[seed; 32]))
            .collect();
        let mut policy = ArchivePolicy {
            fault_bound: 0,
            verification_keys: keys[..32]
                .iter()
                .map(|(public, _)| public.clone().into_bytes())
                .collect(),
        };
        assert!(policy.identity().is_ok());
        let root = ArchiveReference {
            identity: Hash512::from_bytes([5; 64]),
            byte_length: 100,
        };
        let context = Hash512::from_bytes([6; 64]);
        let message = policy
            .receipt_message(context, &root)
            .expect("receipt message");
        let signature = keys[0]
            .1
            .try_sign_with_seed(&[7; 32], message.as_bytes(), RECEIPT_DOMAIN.as_bytes())
            .expect("signature");
        let mut acknowledgements = vec![(0, signature.to_vec()); MAXIMUM_ARCHIVE_REPLICAS];
        assert_eq!(
            policy
                .verify_acknowledgements(context, &root, &acknowledgements)
                .expect("one distinct signer"),
            vec![0]
        );
        acknowledgements.push((0, signature.to_vec()));
        assert!(
            policy
                .verify_acknowledgements(context, &root, &acknowledgements)
                .is_err()
        );
        policy
            .verification_keys
            .push(keys[32].0.clone().into_bytes());
        assert!(policy.identity().is_err());
    }
}
