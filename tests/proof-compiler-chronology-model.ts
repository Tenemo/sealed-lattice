import {
    proofHashProfiles,
    saltedProofHashInputs,
} from '#tests/proof-hash-work-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

// Proof purposes of a poll. Every honest registration carries one
// registration proof, and each participant emits at most one proof of every
// other purpose.
export const proofPurposes = [
    'registration',
    'setup',
    'ballot',
    'release',
] as const;

// The roster positions that prove each purpose: only the setup contributors
// prove a setup.
export const provingPositions = (
    purpose: (typeof proofPurposes)[number],
    participantCount: bigint,
    setupContributorCount: bigint,
) => (purpose === 'setup' ? setupContributorCount : participantCount);

// The proofs, programming points and commitments that one poll emits when
// every roster that reaches an honest opening has this profile, against the
// caps the proof compiler charges. Every honest registration publishes its
// registration proof before any roster exists, including one no roster
// takes, and uses its own credential, so the honest credential population
// bounds the honest registrations of a poll; by default there is one per
// participant and one roster. A corrupt organizer can complete several rosters
// for disjoint honest groups, but each honest registration confirms at most
// one, and a roster with at most f corrupt members holds n-f honest ones.
// Contribution, ballot and release occupy one-shot slots, and one target per
// roster is certified outside the charged authentication events. A restored
// participant replays identical bytes and a participant that loses unfinished
// work stops, so no honest proof is generated twice. The query cap already
// bounds every oracle call of an experiment within the target, including
// honest verification and expansion.
export const compileProofCompilerChronology = (
    profile: SupportedProfile,
    honestRegistrations = BigInt(profile.participantCount),
    rosterCount = 1n,
) => {
    const participants = BigInt(profile.participantCount);
    const contributors = BigInt(profile.setupContributorCount);
    if (honestRegistrations < participants)
        throw new RangeError('The registrations must cover the roster.');
    if (rosterCount < 1n)
        throw new RangeError('A poll completes at least one roster.');
    const honestMembers =
        participants -
        BigInt(
            compileThresholdCompletionProfile(profile.participantCount)
                .maximumCorruptParticipantCount,
        );
    const rosters =
        honestRegistrations / honestMembers < rosterCount
            ? honestRegistrations / honestMembers
            : rosterCount;
    const rosterProvers = (purpose: (typeof proofPurposes)[number]) =>
        rosters * provingPositions(purpose, participants, contributors);
    const honestProofs = proofPurposes.reduce((sum, purpose) => {
        if (purpose === 'registration') return sum + honestRegistrations;
        const provers = rosterProvers(purpose);
        return (
            sum +
            (provers < honestRegistrations ? provers : honestRegistrations)
        );
    }, 0n);
    // Honest participants accept proofs only for their confirmed roster's
    // registration records and proving positions, one role per purpose each.
    const acceptedRoles = proofPurposes.reduce(
        (sum, purpose) => sum + rosterProvers(purpose),
        0n,
    );
    // The direct simulator programs only the affine-challenge message.
    const programmedMessages = honestProofs;
    // Every leaf and internal node of every tree and every salted message
    // root is a commitment that the privacy argument replaces.
    const query = compileProofVerifierQueryCensus();
    const committedNodesPerProof =
        query.groups.reduce(
            (sum, group) => sum + 2n * BigInt(group.length) - 1n,
            0n,
        ) + BigInt(query.messageRootQueries);
    const roles = proofHashProfiles(profile).map((role) => {
        const salted = saltedProofHashInputs(role, role.roleBytes);
        const widestInputBytes = [
            ...salted.leaves,
            ...salted.messageRoots,
        ].reduce((maximum, value) => (value > maximum ? value : maximum), 0n);
        return {
            role: role.role,
            widestNonSaltInputBits: 8n * (widestInputBytes - salted.saltBytes),
        };
    });
    const widestNonSaltInputBits = roles.reduce(
        (maximum, role) =>
            role.widestNonSaltInputBits > maximum
                ? role.widestNonSaltInputBits
                : maximum,
        0n,
    );
    return {
        honestRegistrations,
        rosters,
        honestProofs,
        acceptedRoles,
        programmedMessages,
        committedNodesPerProof,
        roles,
        widestNonSaltInputBits,
        withinCaps:
            honestProofs <= proofCompilerCaps.honestProofBudget &&
            acceptedRoles <= proofCompilerCaps.roleBudget &&
            programmedMessages <= proofCompilerCaps.programmedMessageBudget &&
            committedNodesPerProof <= proofCompilerCaps.committedNodeBudget &&
            widestNonSaltInputBits <= proofCompilerCaps.maximumNonSaltInputBits,
    };
};
