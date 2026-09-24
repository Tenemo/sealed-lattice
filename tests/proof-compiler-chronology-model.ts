import {
    proofHashProfiles,
    saltedProofHashInputs,
} from '#tests/proof-hash-work-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

// Proof purposes with at most one honest proof per participant in a poll.
export const proofPurposes = [
    'registration',
    'setup',
    'ballot',
    'release',
] as const;

// The proofs, programming points and commitments that one poll of a supported
// profile emits, against the caps the proof compiler charges. The claim
// excludes duplicate registration; contribution, ballot and release occupy
// one-shot slots, and one target is certified outside the charged
// authentication events. A restored participant replays identical bytes and a
// participant that loses unfinished work stops, so no honest proof is
// generated twice. The query cap already bounds every oracle call of an
// experiment within the target, including honest verification and expansion.
export const compileProofCompilerChronology = (profile: SupportedProfile) => {
    const participants = BigInt(profile.participantCount);
    const purposes = BigInt(proofPurposes.length);
    const honestProofsPerPurpose = participants;
    const honestProofs = purposes * honestProofsPerPurpose;
    // Honest participants accept proofs only for the confirmed roster's
    // registration records and positions, one role per purpose each.
    const acceptedRoles = purposes * participants;
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
        honestProofsPerPurpose,
        honestProofs,
        acceptedRoles,
        programmedMessages,
        committedNodesPerProof,
        roles,
        widestNonSaltInputBits,
        withinCaps:
            honestProofs <= proofCompilerCaps.roleBudget &&
            acceptedRoles <= proofCompilerCaps.roleBudget &&
            programmedMessages <= proofCompilerCaps.programmedMessageBudget &&
            committedNodesPerProof <= proofCompilerCaps.committedNodeBudget &&
            widestNonSaltInputBits <= proofCompilerCaps.maximumNonSaltInputBits,
    };
};
