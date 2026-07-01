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
        'isBallotProofsVerified',
        'pending',
        'forkDetected',
    ],
    isBallotProofsVerified: [
        'isEncryptedBallotAggregateComputed',
        'pending',
        'forkDetected',
    ],
    isEncryptedBallotAggregateComputed: [
        'evaluatorReplayed',
        'pending',
        'forkDetected',
    ],
    evaluatorReplayed: ['targetFinalityReached', 'pending', 'forkDetected'],
    targetFinalityReached: [
        'isTargetAccepted',
        'outsideSupportedParameters',
        'pending',
        'forkDetected',
    ],
    isTargetAccepted: ['decryptionPending', 'forkDetected'],
    decryptionPending: ['decryptionSharesReady', 'pending', 'forkDetected'],
    decryptionSharesReady: [
        'resultDecoded',
        'outsideSupportedParameters',
        'pending',
        'forkDetected',
    ],
    resultDecoded: ['fullyVerified', 'pending', 'forkDetected'],
    fullyVerified: [],
    pending: [],
    outsideSupportedParameters: [],
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
