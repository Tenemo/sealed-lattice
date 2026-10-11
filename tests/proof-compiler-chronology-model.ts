import {
    proofHashProfiles,
    saltedProofHashInputs,
} from '#tests/proof-hash-work-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';

// Each original participant emits at most one proof of each purpose after
// confirming its roster. Registration authenticates a key without a proof.
export const proofPurposes = ['setup', 'ballot', 'release'] as const;

// Every eligible position may prove an offer, even when it is not selected.
const provingPositions = (
    purpose: (typeof proofPurposes)[number],
    participantCount: bigint,
) =>
    purpose === 'setup'
        ? BigInt(
              compileSetupSelectionCensus(Number(participantCount))
                  .eligibleCount,
          )
        : participantCount;

// Local producer counts for one roster, including unselected eligible offers.
// The clear-preparation ledger separately counts original registrations,
// stalled exposure scopes and certified continuations. Local counts cannot
// determine the complete experiment's query count or security population.
export const compileProofCompilerChronology = (profile: SupportedProfile) => {
    const participants = BigInt(profile.participantCount);
    const acceptedRoles = proofPurposes.reduce(
        (sum, purpose) => sum + provingPositions(purpose, participants),
        0n,
    );
    const honestProofs = acceptedRoles;
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
