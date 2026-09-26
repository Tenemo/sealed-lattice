//! The sizes and randomness budgets from which the participant worker derives
//! every bound it enforces. Each value comes from the code that encodes,
//! verifies or draws its object; the worker adds the layouts of the state it
//! retains itself.

use ballot_encryption::encryption::{ballot_encryptions, encryption_random_bytes};
use num_bigint::BigUint;
use registration_credentials::{
    SEALED_SIGNING_SEED_BYTES, SIGNATURE_BYTES,
    ballot_authentication::ENVELOPE_BYTES,
    ballot_body,
    close_signing::{
        ClosePurpose, MAXIMUM_LISTED_ENVELOPES_PER_SLOT, close_quorum, close_response_bytes,
        maximum_close_message_bytes,
    },
    contribution_authentication::{confirmation_body_bytes, opening_body_bytes},
    contribution_commitment::{self, BODY_HEADER_BYTES, SALT_BYTES},
    foundation::{MAXIMUM_USERNAME_INGRESS_BYTES, RegistrationHeader},
    poll::MAXIMUM_POLL_BYTES,
    registration::KEY_BYTES,
    release_signing::{self, RELEASE_BODY_HEADER_BYTES, RELEASE_ENVELOPE_BYTES},
    roster::{MAXIMUM_PROPOSAL_BYTES, proposal_bytes},
    target_signing::{MAXIMUM_TARGET_BODY_BYTES, TARGET_VOTE_BYTES},
};
use supported_profile::{
    DEGREE, MAXIMUM_SCORE, MINIMUM_SCORE, Profile,
    relation::{
        PROOF_HEADER_BYTES, RANDOM_READ_BYTES, RANDOM_WORD_BYTES, ballot_relation,
        registration_relation, release_relation, setup_relation,
    },
};

/// Every exhaustion of a participant's finite randomness journal, over all
/// participants of a poll, is charged to one allocation of at most 2^-128.
const EXHAUSTION_ALLOCATION_BITS: usize = 128;

/// A probability bound `numerator / 2^denominator_bits`.
struct Probability {
    numerator: BigUint,
    denominator_bits: usize,
}
impl Probability {
    fn sum(values: &[&Self]) -> Self {
        let denominator_bits = values
            .iter()
            .map(|value| value.denominator_bits)
            .max()
            .unwrap_or(0);
        Self {
            numerator: values
                .iter()
                .map(|value| &value.numerator << (denominator_bits - value.denominator_bits))
                .sum(),
            denominator_bits,
        }
    }
    /// Whether the bound is at most `2^-bits`.
    fn at_most(&self, bits: usize) -> bool {
        &self.numerator << bits <= BigUint::from(1u8) << self.denominator_bits
    }
}

fn choose(population: usize, count: usize) -> BigUint {
    (1..=count).fold(BigUint::from(1u8), |value, index| {
        value * BigUint::from(population - index + 1) / BigUint::from(index)
    })
}

/// A participant's proof exhausts a budget of `extra` whole reads past its
/// minimum request only if at least `extra + 1` of the budget's candidate
/// words are rejected. The union bound runs over the participants and over
/// those subsets of candidates.
fn proof_exhaustion(participants: usize, minimum: usize, extra: usize) -> Probability {
    let rejections = extra + 1;
    let candidates = (minimum + extra * RANDOM_READ_BYTES) / RANDOM_WORD_BYTES;
    Probability {
        numerator: BigUint::from(participants)
            * choose(candidates, rejections)
            * BigUint::from(linked_release_proof::field::REJECTED_WORDS).pow(rejections as u32),
        denominator_bits: 8 * RANDOM_WORD_BYTES * rejections,
    }
}

/// A balanced sparse secret of `support` positions among `degree` fails
/// within twice its support in uniform draws only if more than `support`
/// of those draws repeat a taken position, each with probability below
/// `(support - 1) / degree`.
fn sparse_exhaustion(participants: usize, degree: usize, support: usize) -> Probability {
    let failures = support + 1;
    Probability {
        numerator: BigUint::from(participants)
            * choose(2 * support, failures)
            * BigUint::from(support - 1).pow(failures as u32),
        denominator_bits: degree.ilog2() as usize * failures,
    }
}

/// A proof's minimum request and the fewest whole extra reads that keep it,
/// with every other charged exhaustion, within the allocation.
fn proof_random_bytes(participants: usize, minimum: usize, others: &[Probability]) -> usize {
    let mut extra = 0;
    loop {
        let proof = proof_exhaustion(participants, minimum, extra);
        let mut charged: Vec<_> = others.iter().collect();
        charged.push(&proof);
        if Probability::sum(&charged).at_most(EXHAUSTION_ALLOCATION_BITS) {
            return minimum + extra * RANDOM_READ_BYTES;
        }
        extra += 1;
    }
}

/// A ballot's journal: its encryptions' randomness, then its proof's.
pub fn ballot_random_bytes(profile: Profile) -> [usize; 2] {
    let encryptions = ballot_encryptions(profile);
    let sparse: Vec<_> = encryptions
        .iter()
        .map(|(degree, support)| sparse_exhaustion(profile.participants(), *degree, *support))
        .collect();
    [
        encryptions
            .iter()
            .map(|(degree, support)| encryption_random_bytes(*degree, *support))
            .sum(),
        proof_random_bytes(
            profile.participants(),
            ballot_relation(profile).minimum_random_bytes(),
            &sparse,
        ),
    ]
}

/// A release's journal: its noise, then its proof's randomness.
pub fn release_random_bytes(profile: Profile) -> usize {
    linked_release_proof::noise_random_bytes(profile)
        + proof_random_bytes(
            profile.participants(),
            release_relation(profile).minimum_random_bytes(),
            &[],
        )
}

/// A packet is a four-byte body length, the body and its signature.
fn packet_bytes(body: usize) -> usize {
    4 + body + SIGNATURE_BYTES
}

/// The bounds every profile shares, in the order the worker reads them.
pub fn limits() -> Vec<u64> {
    let participants = Profile::participant_range();
    let options = Profile::option_range();
    let intent = maximum_close_message_bytes(ClosePurpose::Intent, *participants.start());
    [
        *participants.start(),
        *participants.end(),
        *options.start(),
        *options.end(),
        KEY_BYTES,
        registration_relation().maximum_proof_bytes(),
        RegistrationHeader::maximum_bytes(),
        MAXIMUM_POLL_BYTES,
        MAXIMUM_USERNAME_INGRESS_BYTES,
        SIGNATURE_BYTES,
        setup_witness::registration::SEALED_KEY_BYTES,
        SEALED_SIGNING_SEED_BYTES,
        MAXIMUM_PROPOSAL_BYTES,
        SALT_BYTES,
        BODY_HEADER_BYTES,
        PROOF_HEADER_BYTES,
        confirmation_body_bytes(),
        opening_body_bytes(),
        packet_bytes(confirmation_body_bytes()),
        MINIMUM_SCORE,
        MAXIMUM_SCORE,
        ballot_proof::CHUNK_LIMIT,
        ballot_body::HEADER_BYTES,
        ENVELOPE_BYTES,
        ENVELOPE_BYTES + SIGNATURE_BYTES,
        intent,
        packet_bytes(intent),
        close_response_bytes(0),
        MAXIMUM_LISTED_ENVELOPES_PER_SLOT,
        MAXIMUM_TARGET_BODY_BYTES,
        TARGET_VOTE_BYTES,
        linked_release_proof::CHUNK_LIMIT,
        RELEASE_BODY_HEADER_BYTES,
        RELEASE_ENVELOPE_BYTES,
        DEGREE,
    ]
    .map(|value| value as u64)
    .to_vec()
}

/// One profile's bounds, in the order the worker reads them. Lists carry
/// their length first.
pub fn profile_bounds(profile: Profile) -> Vec<u64> {
    let participants = profile.participants();
    let contribution = contribution_commitment::proof_lengths(profile);
    let (checkpoint_header, checkpoint_records) = contribution_prover::checkpoint_layout(profile);
    let ballot = ballot_body::body_lengths(profile);
    let ballot_random = ballot_random_bytes(profile);
    let response = maximum_close_message_bytes(ClosePurpose::Response, participants);
    let proposal = maximum_close_message_bytes(ClosePurpose::Proposal, participants);
    let release = release_signing::body_lengths(profile);
    let mut bounds = vec![
        participants,
        profile.options(),
        proposal_bytes(participants),
        profile.setup_polynomials(),
        setup_relation(profile).columns(),
        profile.setup_statement_length(),
        *contribution.start(),
        *contribution.end(),
        checkpoint_header,
        ballot_random[0],
        ballot_random[1],
        *ballot.start(),
        *ballot.end(),
        close_quorum(participants),
        profile.corrupt(),
        response,
        packet_bytes(response),
        proposal,
        packet_bytes(proposal),
        release_random_bytes(profile),
        *release.start(),
        *release.end(),
        evaluation_target::stored_coefficient_bytes(profile),
        checkpoint_records.len(),
    ];
    bounds.extend(checkpoint_records);
    let polynomials = profile.contribution_body_polynomials();
    bounds.push(polynomials.len());
    for index in polynomials {
        let family = profile
            .setup_family(index)
            .expect("A body polynomial is a setup polynomial.");
        bounds.extend([
            index,
            profile
                .setup_polynomial_bytes(index)
                .expect("A body polynomial is a setup polynomial."),
            profile.family_degree(family),
        ]);
    }
    bounds.into_iter().map(|value| value as u64).collect()
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;
    use supported_profile::Profile;

    thread_local! {static OUTPUT: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };}

    fn publish(values: Vec<u64>) -> usize {
        OUTPUT.with(|output| {
            let count = values.len();
            *output.borrow_mut() = values;
            count
        })
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn participant_bounds_pointer() -> usize {
        OUTPUT.with(|output| output.borrow().as_ptr() as usize)
    }

    /// Writes the shared bounds and returns their count of 64-bit words.
    #[unsafe(no_mangle)]
    pub extern "C" fn participant_limits() -> usize {
        publish(super::limits())
    }

    /// Writes a supported profile's bounds and returns their count of
    /// 64-bit words, or zero for an unsupported profile.
    #[unsafe(no_mangle)]
    pub extern "C" fn participant_profile_bounds(participants: usize, options: usize) -> usize {
        Profile::new(participants, options).map_or_else(
            |_| publish(Vec::new()),
            |profile| publish(super::profile_bounds(profile)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use supported_profile::{AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, FHE_SECRET_SUPPORT};

    #[test]
    fn sparse_draws_are_uniform_positions() {
        // A four-byte draw reduced modulo the degree is uniform only when the
        // degree divides 2^32, and the failure bound's denominator is exact
        // only for a power of two.
        for (degree, support) in [
            (DEGREE, FHE_SECRET_SUPPORT),
            (AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT),
        ] {
            assert!(degree.is_power_of_two() && (1u64 << 32).is_multiple_of(degree as u64));
            assert!(0 < support && support < degree);
        }
    }

    #[test]
    fn budgets_are_the_fewest_reads_within_the_allocation() {
        for profile in [Profile::new(3, 2).unwrap(), Profile::new(20, 20).unwrap()] {
            let participants = profile.participants();
            let minimum = release_relation(profile).minimum_random_bytes();
            let budget =
                release_random_bytes(profile) - linked_release_proof::noise_random_bytes(profile);
            let extra = (budget - minimum) / RANDOM_READ_BYTES;
            assert_eq!(budget, minimum + extra * RANDOM_READ_BYTES);
            assert!(proof_exhaustion(participants, minimum, extra).at_most(128));
            assert!(extra == 0 || !proof_exhaustion(participants, minimum, extra - 1).at_most(128));
            let [encryption, proof] = ballot_random_bytes(profile);
            assert_eq!(encryption % RANDOM_READ_BYTES, 0);
            assert!(proof > ballot_relation(profile).minimum_random_bytes());
        }
    }

    #[test]
    fn the_largest_roster_proposal_fits_its_cap() {
        assert!(proposal_bytes(*Profile::participant_range().end()) <= MAXIMUM_PROPOSAL_BYTES);
    }

    #[test]
    fn probability_sums_share_a_denominator() {
        let half = Probability {
            numerator: BigUint::from(1u8),
            denominator_bits: 1,
        };
        let quarter = Probability {
            numerator: BigUint::from(1u8),
            denominator_bits: 2,
        };
        let sum = Probability::sum(&[&half, &quarter]);
        assert_eq!(sum.numerator, BigUint::from(3u8));
        assert_eq!(sum.denominator_bits, 2);
        assert!(!sum.at_most(1));
        assert!(half.at_most(1) && !half.at_most(2));
    }

    #[test]
    fn records_have_their_declared_lengths() {
        let limits = limits();
        assert_eq!(limits.len(), 35);
        for profile in [Profile::new(3, 2).unwrap(), Profile::new(20, 20).unwrap()] {
            let bounds = profile_bounds(profile);
            let checkpoints = bounds[23] as usize;
            let polynomials = bounds[24 + checkpoints] as usize;
            assert_eq!(bounds.len(), 25 + checkpoints + 3 * polynomials);
            assert_eq!(
                bounds[..2],
                [profile.participants() as u64, profile.options() as u64]
            );
        }
    }
}
