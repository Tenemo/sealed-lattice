import type {
    EvaluationProofMode,
    FailureStatusLabel,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleState,
    PrimaryStatusLabel,
    ResultClaimLabel,
} from './types.js';

const primaryLabelsByState = {
    DraftPoll: [],
    RegistrationOpen: [],
    TrusteeSetupOpen: [],
    RegistrationClosed: [],
    RosterFrozen: ['RosterAudited'],
    VotingOpen: ['RosterAudited'],
    VotingClosed: ['RosterAudited', 'BallotIncluded'],
    AwaitingAggregateContributors: ['RosterAudited', 'BallotIncluded'],
    AggregateInputsReady: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
    ],
    AwaitingMobileEvaluation: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
    ],
    TopKEvaluated: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
    ],
    EvaluationReplayOpen: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'EvaluationLocallyReplayed',
    ],
    EvaluationReplayAttested: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'EvaluationLocallyReplayed',
        'EvaluationReplayAttested',
    ],
    OptionalEvaluationProofVerified: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'OptionalEvaluationProofVerified',
    ],
    EvaluationRejected: [],
    TargetAccepted: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'TargetAccepted',
    ],
    AwaitingFirstDecryptionShares: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'TargetAccepted',
    ],
    ResultComputedAuditable: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'TargetAccepted',
        'FirstThresholdSharesReached',
        'ResultComputedAuditable',
    ],
    FullyVerifiedResult: [
        'RosterAudited',
        'BallotIncluded',
        'AggregateInputsReady',
        'TopKEvaluated',
        'OptionalEvaluationProofVerified',
        'TargetAccepted',
        'FirstThresholdSharesReached',
        'FullyVerifiedResult',
    ],
    Unresolved: ['Unresolved'],
    ForkedElection: [],
} as const satisfies Record<LifecycleState, readonly PrimaryStatusLabel[]>;

const failureLabelsByState = {
    DraftPoll: [],
    RegistrationOpen: [],
    TrusteeSetupOpen: ['SetupIncomplete'],
    RegistrationClosed: ['SetupIncomplete'],
    RosterFrozen: [],
    VotingOpen: [],
    VotingClosed: [],
    AwaitingAggregateContributors: ['AggregateThresholdNotReached'],
    AggregateInputsReady: [],
    AwaitingMobileEvaluation: ['MobileEvaluationPending'],
    TopKEvaluated: [],
    EvaluationReplayOpen: ['EvaluationReplayThresholdNotReached'],
    EvaluationReplayAttested: [],
    OptionalEvaluationProofVerified: [],
    EvaluationRejected: ['EvaluationRejected'],
    TargetAccepted: [],
    AwaitingFirstDecryptionShares: [],
    ResultComputedAuditable: [],
    FullyVerifiedResult: [],
    Unresolved: [],
    ForkedElection: [
        'BoardForkSuspected',
        'BoardEvidencePublished',
        'ForkedElection',
    ],
} as const satisfies Record<LifecycleState, readonly FailureStatusLabel[]>;

const deriveEvaluationProofMode = (
    input: LifecycleLabelInput,
): EvaluationProofMode => {
    if (input.evaluationProofMode !== undefined) {
        return input.evaluationProofMode;
    }
    if (
        input.lifecycleState === 'OptionalEvaluationProofVerified' ||
        input.lifecycleState === 'FullyVerifiedResult'
    ) {
        return 'OptionalEvaluationProofVerified';
    }

    return 'NoOptionalEvaluationProof';
};

const deriveResultClaimLabel = (
    lifecycleState: LifecycleState,
    claimBearing: boolean,
): ResultClaimLabel | undefined => {
    if (!claimBearing) {
        return undefined;
    }
    if (lifecycleState === 'ResultComputedAuditable') {
        return 'ResultComputedAuditable';
    }
    if (lifecycleState === 'FullyVerifiedResult') {
        return 'FullyVerifiedResult';
    }

    return undefined;
};

export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => {
    const failures: FailureStatusLabel[] = [
        ...failureLabelsByState[input.lifecycleState],
    ];
    const evaluationProofMode = deriveEvaluationProofMode(input);
    let primary: PrimaryStatusLabel[] = [
        ...primaryLabelsByState[input.lifecycleState],
    ];

    if (input.thresholdProfile.rosterProfileKind === 'UnsafeMicroRoster') {
        failures.push('UnsafeMicroRoster');
    }
    if (
        (input.mheSecurityStage ?? 'PassiveMHEPrototype') ===
        'PassiveMHEPrototype'
    ) {
        failures.push('PassiveMHEPrototype');
    }
    if (
        !input.thresholdProfile.claimBearing &&
        (input.lifecycleState === 'ResultComputedAuditable' ||
            input.lifecycleState === 'FullyVerifiedResult')
    ) {
        primary = ['Unresolved'];
    }

    const resultClaimLabel = deriveResultClaimLabel(
        input.lifecycleState,
        input.thresholdProfile.claimBearing,
    );

    return {
        primary,
        failures,
        resultClaimLabel,
        evaluationProofMode,
    };
};
