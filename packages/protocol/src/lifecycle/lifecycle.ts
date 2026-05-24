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
    votingClosed: ['aggregatePending', 'forkDetected'],
    aggregatePending: ['aggregateReady', 'pending', 'forkDetected'],
    aggregateReady: ['aggregateBridgeVerified', 'forkDetected'],
    aggregateBridgeVerified: ['evaluationPending', 'forkDetected'],
    evaluationPending: ['topKEvaluated', 'pending', 'forkDetected'],
    topKEvaluated: ['targetFinalityReached', 'pending', 'forkDetected'],
    targetFinalityReached: [
        'evaluationProofPending',
        'pending',
        'forkDetected',
    ],
    evaluationProofPending: [
        'evaluationProofVerified',
        'outsideClaim',
        'pending',
        'forkDetected',
    ],
    evaluationProofVerified: ['targetAccepted', 'pending', 'forkDetected'],
    targetAccepted: ['decryptionPending', 'forkDetected'],
    decryptionPending: ['decryptionSharesReady', 'pending', 'forkDetected'],
    decryptionSharesReady: [
        'cpadProfileVerified',
        'outsideClaim',
        'pending',
        'forkDetected',
    ],
    cpadProfileVerified: ['fullyVerified', 'pending', 'forkDetected'],
    fullyVerified: [],
    pending: [],
    outsideClaim: [],
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
