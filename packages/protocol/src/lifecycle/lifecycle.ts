import type {
    LifecycleState,
    LifecycleTransition,
} from '@sealed-lattice/types';

const transitionMap = {
    DraftPoll: ['RegistrationOpen'],
    RegistrationOpen: ['TrusteeSetupOpen'],
    TrusteeSetupOpen: ['RegistrationClosed', 'Unresolved'],
    RegistrationClosed: ['RosterFrozen'],
    RosterFrozen: ['VotingOpen', 'ForkedElection'],
    VotingOpen: ['VotingClosed', 'ForkedElection'],
    VotingClosed: ['AwaitingAggregateContributors', 'ForkedElection'],
    AwaitingAggregateContributors: [
        'AggregateInputsReady',
        'Unresolved',
        'ForkedElection',
    ],
    AggregateInputsReady: ['AggregateInputsBridgeVerified', 'ForkedElection'],
    AggregateInputsBridgeVerified: ['AwaitingEvaluation', 'ForkedElection'],
    AwaitingEvaluation: ['TopKEvaluated', 'Unresolved', 'ForkedElection'],
    TopKEvaluated: ['TargetFinalityReached', 'Unresolved', 'ForkedElection'],
    TargetFinalityReached: [
        'EvaluationProofOpen',
        'Unresolved',
        'ForkedElection',
    ],
    EvaluationProofOpen: [
        'EvaluationProofVerified',
        'EvaluationProofRejected',
        'EvaluationProofProfileRejected',
        'Unresolved',
        'ForkedElection',
    ],
    EvaluationProofVerified: ['TargetAccepted', 'Unresolved', 'ForkedElection'],
    EvaluationProofRejected: [],
    EvaluationProofProfileRejected: [],
    TargetAccepted: ['AwaitingFirstDecryptionShares', 'ForkedElection'],
    AwaitingFirstDecryptionShares: [
        'FirstThresholdSharesReached',
        'Unresolved',
        'ForkedElection',
    ],
    FirstThresholdSharesReached: [
        'CPADProfileVerified',
        'CPADProfileRejected',
        'Unresolved',
        'ForkedElection',
    ],
    CPADProfileVerified: [
        'FullyVerifiedResult',
        'Unresolved',
        'ForkedElection',
    ],
    CPADProfileRejected: [],
    FullyVerifiedResult: [],
    Unresolved: [],
    ForkedElection: [],
} as const satisfies Record<LifecycleState, readonly LifecycleState[]>;

export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean => {
    const allowedTargets = transitionMap[transition.from] as
        | readonly LifecycleState[]
        | undefined;

    return allowedTargets?.includes(transition.to) ?? false;
};
