import type { LifecycleState, LifecycleTransition } from './types.js';

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
    AggregateInputsReady: ['AwaitingMobileEvaluation', 'ForkedElection'],
    AwaitingMobileEvaluation: [
        'TopKEvaluated',
        'EvaluationRejected',
        'Unresolved',
        'ForkedElection',
    ],
    TopKEvaluated: [
        'EvaluationReplayOpen',
        'EvaluationRejected',
        'ForkedElection',
    ],
    EvaluationReplayOpen: [
        'EvaluationReplayAttested',
        'OptionalEvaluationProofVerified',
        'EvaluationRejected',
        'Unresolved',
        'ForkedElection',
    ],
    EvaluationReplayAttested: [
        'TargetAccepted',
        'EvaluationRejected',
        'ForkedElection',
    ],
    OptionalEvaluationProofVerified: [
        'TargetAccepted',
        'EvaluationRejected',
        'ForkedElection',
    ],
    EvaluationRejected: [],
    TargetAccepted: ['AwaitingFirstDecryptionShares', 'ForkedElection'],
    AwaitingFirstDecryptionShares: [
        'ResultComputedAuditable',
        'FullyVerifiedResult',
        'Unresolved',
        'ForkedElection',
    ],
    ResultComputedAuditable: [],
    FullyVerifiedResult: [],
    Unresolved: [],
    ForkedElection: [],
} as const satisfies Record<LifecycleState, readonly LifecycleState[]>;

export const lifecycleStates = Object.keys(
    transitionMap,
) as readonly LifecycleState[];

export const lifecycleTransitionEntries = Object.entries(transitionMap).flatMap(
    ([from, targets]) =>
        targets.map((to) => ({
            from: from as LifecycleState,
            to,
        })),
);

export const isValidLifecycleTransition = (
    transition: LifecycleTransition,
): boolean =>
    (transitionMap[transition.from] as readonly LifecycleState[]).includes(
        transition.to,
    );
