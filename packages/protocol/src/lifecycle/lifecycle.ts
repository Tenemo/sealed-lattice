import type {
    LifecycleState,
    LifecycleTransition,
} from '@sealed-lattice/types';

const transitionMap = {
    draft: ['registrationOpen'],
    registrationOpen: ['trusteeSetupOpen'],
    trusteeSetupOpen: ['registrationClosed', 'pending'],
    registrationClosed: ['rosterFrozen'],
    rosterFrozen: ['votingOpen', 'forkDetected'],
    votingOpen: ['votingClosed', 'forkDetected'],
    votingClosed: ['encryptedBallotsSelected', 'forkDetected'],
    encryptedBallotsSelected: [
        'ballotProofsVerified',
        'pending',
        'forkDetected',
    ],
    ballotProofsVerified: [
        'encryptedBallotAggregateComputed',
        'pending',
        'forkDetected',
    ],
    encryptedBallotAggregateComputed: [
        'evaluatorReplayed',
        'pending',
        'forkDetected',
    ],
    evaluatorReplayed: ['targetFinalityReached', 'pending', 'forkDetected'],
    targetFinalityReached: [
        'targetAccepted',
        'outsideSupportedProfile',
        'pending',
        'forkDetected',
    ],
    targetAccepted: ['decryptionPending', 'forkDetected'],
    decryptionPending: ['decryptionSharesReady', 'pending', 'forkDetected'],
    decryptionSharesReady: [
        'resultDecoded',
        'outsideSupportedProfile',
        'pending',
        'forkDetected',
    ],
    resultDecoded: ['fullyVerified', 'pending', 'forkDetected'],
    fullyVerified: [],
    pending: [],
    outsideSupportedProfile: [],
    forkDetected: [],
} as const satisfies Record<LifecycleState, readonly LifecycleState[]>;

export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => {
    const allowedTargets = transitionMap[transition.from] as
        | readonly LifecycleState[]
        | undefined;

    return allowedTargets?.includes(transition.to) ?? false;
};
