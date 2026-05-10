import type {
    EvaluationProofMode,
    FailureStatusLabel,
    LifecycleLabelInput,
    LifecycleLabels,
    LifecycleState,
    ModeStatusLabel,
    PrimaryStatusLabel,
    ResultClaimLabel,
} from '@sealed-lattice/types';

const primaryLabelsByState = {
    DraftPoll: [],
    RegistrationOpen: [],
    TrusteeSetupOpen: [],
    RegistrationClosed: [],
    RosterFrozen: [],
    VotingOpen: [],
    VotingClosed: [],
    AwaitingAggregateContributors: [],
    AggregateInputsReady: ['AggregateInputsReady'],
    AwaitingMobileEvaluation: ['AggregateInputsReady'],
    TopKEvaluated: ['AggregateInputsReady', 'TopKEvaluated'],
    EvaluationReplayOpen: ['AggregateInputsReady', 'TopKEvaluated'],
    EvaluationReplayAttested: [
        'AggregateInputsReady',
        'TopKEvaluated',
        'EvaluationReplayAttested',
    ],
    OptionalEvaluationProofVerified: [
        'AggregateInputsReady',
        'TopKEvaluated',
        'OptionalEvaluationProofVerified',
    ],
    EvaluationRejected: [],
    TargetAccepted: ['AggregateInputsReady', 'TopKEvaluated', 'TargetAccepted'],
    AwaitingFirstDecryptionShares: [
        'AggregateInputsReady',
        'TopKEvaluated',
        'TargetAccepted',
    ],
    ResultComputedAuditable: [
        'AggregateInputsReady',
        'TopKEvaluated',
        'TargetAccepted',
        'FirstThresholdSharesReached',
        'ResultComputedAuditable',
    ],
    FullyVerifiedResult: [
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
    mobileClaimGatePassed: boolean,
): ResultClaimLabel | undefined => {
    if (!claimBearing || !mobileClaimGatePassed) {
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

const deriveLocalPrimaryLabels = (
    input: LifecycleLabelInput,
): PrimaryStatusLabel[] => {
    const labels: PrimaryStatusLabel[] = [];

    if (input.rosterAudited === true) {
        labels.push('RosterAudited');
    }
    if (input.ownBallotIncluded === true) {
        labels.push('BallotIncluded');
    }
    if (input.evaluationLocallyReplayed === true) {
        labels.push('EvaluationLocallyReplayed');
    }
    if (input.bridgeProofPending === true) {
        labels.push('BridgeProofPending');
    }
    if (input.bridgeProofLocallyVerified === true) {
        labels.push('BridgeProofLocallyVerified');
    }
    if (input.aggregateInputsBridgeVerified === true) {
        labels.push('AggregateInputsBridgeVerified');
    }

    return labels;
};

export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => {
    const failures: FailureStatusLabel[] = [
        ...failureLabelsByState[input.lifecycleState],
    ];
    const modes: ModeStatusLabel[] = [];
    const evaluationProofMode = deriveEvaluationProofMode(input);
    let primary: PrimaryStatusLabel[] = Array.from(
        new Set([
            ...deriveLocalPrimaryLabels(input),
            ...primaryLabelsByState[input.lifecycleState],
        ]),
    );

    if (input.thresholdProfile.rosterProfileKind === 'UnsafeMicroRoster') {
        modes.push('UnsafeMicroRoster');
    }
    if (
        (input.mheSecurityStage ?? 'PassiveMHEPrototype') ===
        'PassiveMHEPrototype'
    ) {
        modes.push('PassiveMHEPrototype');
    }
    if (input.mobileFlagshipProfile === true) {
        modes.push('MobileFlagshipProfile');
    }
    if (input.foregroundProofGenerationRequired === true) {
        modes.push('ForegroundProofGenerationRequired');
    }
    if (input.foregroundProofVerificationRequired === true) {
        modes.push('ForegroundProofVerificationRequired');
    }
    if (input.bridgeProofRejected === true) {
        failures.push('BridgeProofRejected');
    }
    if (input.brakerskiBackendProfileRejected === true) {
        failures.push('BrakerskiBackendProfileRejected');
    }
    if (input.bridgeMobileCertRejected === true) {
        failures.push('BridgeMobileCertRejected');
    }
    if (input.unsupportedLowResourceDevice === true) {
        failures.push('UnsupportedLowResourceDevice');
    }

    const resultState =
        input.lifecycleState === 'ResultComputedAuditable' ||
        input.lifecycleState === 'FullyVerifiedResult';
    if (
        resultState &&
        (!input.thresholdProfile.claimBearing ||
            input.mobileClaimGatePassed !== true)
    ) {
        primary = ['Unresolved'];
    }

    const resultClaimLabel = deriveResultClaimLabel(
        input.lifecycleState,
        input.thresholdProfile.claimBearing,
        input.mobileClaimGatePassed === true,
    );

    return {
        primary,
        failures,
        modes,
        resultClaimLabel,
        evaluationProofMode,
    };
};
