use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn public_key_shares_object(participant_count: u64) -> serde_json::Value {
    let mut share_records = Vec::new();
    for trustee_roster_position in 0..participant_count {
        let share_coefficient_hashes = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, _rns_prime)| {
                derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "PublicKeyShareCoefficientVectorFixture",
                    "fixture": "public-key-share-coefficient-vector",
                    "trusteeRosterPosition": trustee_roster_position,
                    "rnsLimbIndex": rns_limb_index,
                }))
                .expect("public-key share coefficient hash")
            })
            .collect::<Vec<_>>();
        let share_record = serde_json::json!({
            "objectType": "PublicKeyShare",
            "shareCoefficientVectorHashesByLimb": share_coefficient_hashes,
        });
        share_records.push(share_record);
    }

    serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "shareRecords": share_records,
    })
}
