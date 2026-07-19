use crate::foundation::{FOUNDATION_PROFILE, Hash512, RefusalReason, StreamDescriptor};

use super::{
    canonical_package::CanonicalAcceptedSetupPackage,
    verified_public_randomness::VerifiedPublicRandomness,
    verified_terminals::VerifiedVssQualificationTerminals,
};

/// Exact canonical carrier lengths retained while the verifier consumes the
/// five hash-addressed setup object corpora. This is transient read-only
/// verifier data; it is not a package field and cannot be supplied by a setup
/// producer. The two VSS carrier families also retain their verified nested
/// proof descriptors so accounting can count addressed proof bodies exactly
/// once without treating descriptor bytes as proof bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::bgv) struct VerifiedAcceptedSetupConsumedObjectByteLengthCatalog {
    ordered_setup_intent_canonical_byte_lengths: Box<[u64]>,
    ordered_public_randomness_commitment_canonical_byte_lengths: Box<[u64]>,
    ordered_public_randomness_reveal_canonical_byte_lengths: Box<[u64]>,
    ordered_dealer_public_record_canonical_byte_lengths: Box<[u64]>,
    ordered_private_share_acceptance_canonical_byte_lengths: Box<[u64]>,
    ordered_vss_share_linkage_proof_descriptors: Box<[StreamDescriptor]>,
    ordered_aggregate_threshold_share_proof_descriptors: Box<[StreamDescriptor]>,
}

impl VerifiedAcceptedSetupConsumedObjectByteLengthCatalog {
    pub(in crate::bgv) fn from_verified_terminals(
        package: &CanonicalAcceptedSetupPackage,
        verified_public_randomness: &VerifiedPublicRandomness,
        verified_vss_qualification: &VerifiedVssQualificationTerminals,
    ) -> Result<Self, RefusalReason> {
        if verified_public_randomness.context() != verified_vss_qualification.context()
            || verified_public_randomness.public_setup_seed()
                != verified_vss_qualification.public_setup_seed()
            || verified_public_randomness.setup_proof_context_hash()
                != verified_vss_qualification.setup_proof_context_hash()
            || verified_public_randomness.ordered_participant_identities()
                != verified_vss_qualification.ordered_participant_identities()
        {
            return Err(RefusalReason::WrongContext);
        }

        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let (
            ordered_vss_share_linkage_proof_descriptors,
            ordered_aggregate_threshold_share_proof_descriptors,
        ) = require_exact_verified_vss_proof_descriptor_catalog(
            verified_vss_qualification.ordered_share_linkage_proof_descriptors(),
            verified_vss_qualification.ordered_aggregate_threshold_share_proof_descriptors(),
            participant_count,
        )?;
        Ok(Self {
            ordered_setup_intent_canonical_byte_lengths: require_exact_verified_object_catalog(
                package.setup_intent_object_hashes(),
                verified_public_randomness.ordered_setup_intent_object_hashes(),
                verified_public_randomness.ordered_setup_intent_canonical_byte_lengths(),
                participant_count,
            )?,
            ordered_public_randomness_commitment_canonical_byte_lengths:
                require_exact_verified_object_catalog(
                    package.public_randomness_commitment_object_hashes(),
                    verified_public_randomness.ordered_commitment_object_hashes(),
                    verified_public_randomness.ordered_commitment_canonical_byte_lengths(),
                    participant_count,
                )?,
            ordered_public_randomness_reveal_canonical_byte_lengths:
                require_exact_verified_object_catalog(
                    package.public_randomness_reveal_object_hashes(),
                    verified_public_randomness.ordered_reveal_object_hashes(),
                    verified_public_randomness.ordered_reveal_canonical_byte_lengths(),
                    participant_count,
                )?,
            ordered_dealer_public_record_canonical_byte_lengths:
                require_exact_verified_object_catalog(
                    package.dealer_public_record_object_hashes(),
                    verified_vss_qualification.ordered_dealer_public_record_object_hashes(),
                    verified_vss_qualification
                        .ordered_dealer_public_record_canonical_byte_lengths(),
                    participant_count,
                )?,
            ordered_private_share_acceptance_canonical_byte_lengths:
                require_exact_verified_object_catalog(
                    package.private_share_acceptance_object_hashes(),
                    verified_vss_qualification.ordered_private_share_acceptance_object_hashes(),
                    verified_vss_qualification
                        .ordered_private_share_acceptance_canonical_byte_lengths(),
                    participant_count,
                )?,
            ordered_vss_share_linkage_proof_descriptors,
            ordered_aggregate_threshold_share_proof_descriptors,
        })
    }

    pub(in crate::bgv) fn ordered_setup_intent_canonical_byte_lengths(&self) -> &[u64] {
        &self.ordered_setup_intent_canonical_byte_lengths
    }

    pub(in crate::bgv) fn ordered_public_randomness_commitment_canonical_byte_lengths(
        &self,
    ) -> &[u64] {
        &self.ordered_public_randomness_commitment_canonical_byte_lengths
    }

    pub(in crate::bgv) fn ordered_public_randomness_reveal_canonical_byte_lengths(&self) -> &[u64] {
        &self.ordered_public_randomness_reveal_canonical_byte_lengths
    }

    pub(in crate::bgv) fn ordered_dealer_public_record_canonical_byte_lengths(&self) -> &[u64] {
        &self.ordered_dealer_public_record_canonical_byte_lengths
    }

    pub(in crate::bgv) fn ordered_private_share_acceptance_canonical_byte_lengths(&self) -> &[u64] {
        &self.ordered_private_share_acceptance_canonical_byte_lengths
    }

    pub(in crate::bgv) fn ordered_vss_share_linkage_proof_descriptors(
        &self,
    ) -> &[StreamDescriptor] {
        &self.ordered_vss_share_linkage_proof_descriptors
    }

    pub(in crate::bgv) fn ordered_aggregate_threshold_share_proof_descriptors(
        &self,
    ) -> &[StreamDescriptor] {
        &self.ordered_aggregate_threshold_share_proof_descriptors
    }

    #[cfg(test)]
    pub(in crate::bgv) fn deterministic_for_authority_custody_tests(marker: u8) -> Self {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let ordered_lengths = |offset: u64| {
            (0..participant_count)
                .map(|roster_position| {
                    offset
                        .checked_add(u64::try_from(roster_position).unwrap())
                        .unwrap()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice()
        };
        let proof_descriptor = |ordinal: usize| {
            let mut chunk_digest = [marker; Hash512::BYTE_LENGTH];
            chunk_digest[..8].copy_from_slice(&u64::try_from(ordinal).unwrap().to_le_bytes());
            let mut full_object_digest = [marker.wrapping_add(1); Hash512::BYTE_LENGTH];
            full_object_digest[..8].copy_from_slice(&u64::try_from(ordinal).unwrap().to_le_bytes());
            StreamDescriptor::new(
                1,
                vec![Hash512::from_bytes(chunk_digest)],
                Hash512::from_bytes(full_object_digest),
            )
            .unwrap()
        };

        Self {
            ordered_setup_intent_canonical_byte_lengths: ordered_lengths(101),
            ordered_public_randomness_commitment_canonical_byte_lengths: ordered_lengths(201),
            ordered_public_randomness_reveal_canonical_byte_lengths: ordered_lengths(301),
            ordered_dealer_public_record_canonical_byte_lengths: ordered_lengths(401),
            ordered_private_share_acceptance_canonical_byte_lengths: ordered_lengths(501),
            ordered_vss_share_linkage_proof_descriptors: (0..participant_count)
                .map(&proof_descriptor)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            ordered_aggregate_threshold_share_proof_descriptors: (participant_count
                ..participant_count * 2)
                .map(&proof_descriptor)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }
}

fn require_exact_verified_object_catalog(
    package_object_hashes: &[Hash512],
    verified_object_hashes: &[Hash512],
    verified_canonical_byte_lengths: &[u64],
    participant_count: usize,
) -> Result<Box<[u64]>, RefusalReason> {
    if package_object_hashes.len() != participant_count
        || verified_object_hashes.len() != participant_count
        || verified_canonical_byte_lengths.len() != participant_count
        || verified_canonical_byte_lengths.contains(&0)
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    if package_object_hashes != verified_object_hashes {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    Ok(verified_canonical_byte_lengths.to_vec().into_boxed_slice())
}

fn require_exact_verified_vss_proof_descriptor_catalog(
    ordered_vss_share_linkage_proof_descriptors: &[StreamDescriptor],
    ordered_aggregate_threshold_share_proof_descriptors: &[StreamDescriptor],
    participant_count: usize,
) -> Result<(Box<[StreamDescriptor]>, Box<[StreamDescriptor]>), RefusalReason> {
    if ordered_vss_share_linkage_proof_descriptors.len() != participant_count
        || ordered_aggregate_threshold_share_proof_descriptors.len() != participant_count
        || ordered_vss_share_linkage_proof_descriptors
            .iter()
            .chain(ordered_aggregate_threshold_share_proof_descriptors)
            .any(|descriptor| descriptor.total_byte_length == 0)
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let ordered_descriptors = ordered_vss_share_linkage_proof_descriptors
        .iter()
        .chain(ordered_aggregate_threshold_share_proof_descriptors)
        .collect::<Vec<_>>();
    if ordered_descriptors
        .iter()
        .enumerate()
        .any(|(ordinal, descriptor)| ordered_descriptors[..ordinal].contains(descriptor))
    {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    Ok((
        ordered_vss_share_linkage_proof_descriptors
            .to_vec()
            .into_boxed_slice(),
        ordered_aggregate_threshold_share_proof_descriptors
            .to_vec()
            .into_boxed_slice(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_hashes(domain_byte: u8, participant_count: usize) -> Vec<Hash512> {
        (0..participant_count)
            .map(|roster_position| {
                let mut bytes = [domain_byte; Hash512::BYTE_LENGTH];
                bytes[0] = u8::try_from(roster_position).unwrap();
                Hash512::from_bytes(bytes)
            })
            .collect()
    }

    fn proof_descriptor(ordinal: usize) -> StreamDescriptor {
        let mut chunk_digest = [0x61; Hash512::BYTE_LENGTH];
        chunk_digest[..8].copy_from_slice(&u64::try_from(ordinal).unwrap().to_le_bytes());
        let mut full_object_digest = [0x91; Hash512::BYTE_LENGTH];
        full_object_digest[..8].copy_from_slice(&u64::try_from(ordinal).unwrap().to_le_bytes());
        StreamDescriptor::new(
            1,
            vec![Hash512::from_bytes(chunk_digest)],
            Hash512::from_bytes(full_object_digest),
        )
        .unwrap()
    }

    #[test]
    fn exact_verified_object_catalog_rejects_omission_reordering_and_zero_length() {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let package_hashes = object_hashes(0x51, participant_count);
        let verified_lengths = (0..participant_count)
            .map(|roster_position| 1_000 + u64::try_from(roster_position).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            require_exact_verified_object_catalog(
                &package_hashes,
                &package_hashes,
                &verified_lengths,
                participant_count,
            )
            .unwrap()
            .as_ref(),
            verified_lengths
        );

        let mut incomplete_hashes = package_hashes.clone();
        incomplete_hashes.pop();
        assert_eq!(
            require_exact_verified_object_catalog(
                &package_hashes,
                &incomplete_hashes,
                &verified_lengths,
                participant_count,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        );

        let mut reordered_hashes = package_hashes.clone();
        reordered_hashes.swap(2, 7);
        assert_eq!(
            require_exact_verified_object_catalog(
                &package_hashes,
                &reordered_hashes,
                &verified_lengths,
                participant_count,
            ),
            Err(RefusalReason::WrongHashOrRoot)
        );

        let mut invalid_lengths = verified_lengths;
        invalid_lengths[4] = 0;
        assert_eq!(
            require_exact_verified_object_catalog(
                &package_hashes,
                &package_hashes,
                &invalid_lengths,
                participant_count,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        );
    }

    #[test]
    fn exact_vss_proof_descriptor_catalog_rejects_omission_and_cross_family_duplicate() {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let share_linkage_descriptors = (0..participant_count)
            .map(proof_descriptor)
            .collect::<Vec<_>>();
        let aggregate_threshold_descriptors = (participant_count..participant_count * 2)
            .map(proof_descriptor)
            .collect::<Vec<_>>();
        let (retained_share_linkage, retained_aggregate_threshold) =
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors,
                &aggregate_threshold_descriptors,
                participant_count,
            )
            .unwrap();
        assert_eq!(
            retained_share_linkage.as_ref(),
            share_linkage_descriptors.as_slice()
        );
        assert_eq!(
            retained_aggregate_threshold.as_ref(),
            aggregate_threshold_descriptors.as_slice()
        );

        let mut incomplete_aggregate_threshold_descriptors =
            aggregate_threshold_descriptors.clone();
        incomplete_aggregate_threshold_descriptors.pop();
        assert_eq!(
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors,
                &incomplete_aggregate_threshold_descriptors,
                participant_count,
            ),
            Err(RefusalReason::WrongTypeOrLength)
        );

        let mut duplicate_aggregate_threshold_descriptors = aggregate_threshold_descriptors;
        duplicate_aggregate_threshold_descriptors[participant_count / 2] =
            share_linkage_descriptors[participant_count / 3].clone();
        assert_eq!(
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors,
                &duplicate_aggregate_threshold_descriptors,
                participant_count,
            ),
            Err(RefusalReason::WrongHashOrRoot)
        );
    }
}
