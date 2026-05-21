import {
    activeMaliciousMheProfileId,
    evaluationProofProfileId,
    passiveMhePrototypeProfileId,
    thresholdDecryptionProfileId,
} from '@sealed-lattice/types';
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
    AggregateInputsBridgeVerified: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
    ],
    AwaitingEvaluation: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
    ],
    TopKEvaluated: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
    ],
    TargetFinalityReached: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
    ],
    EvaluationProofOpen: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofOpen',
    ],
    EvaluationProofVerified: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofVerified',
    ],
    EvaluationProofRejected: [],
    EvaluationProofProfileRejected: [],
    TargetAccepted: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofVerified',
        'TargetAccepted',
    ],
    AwaitingFirstDecryptionShares: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofVerified',
        'TargetAccepted',
    ],
    FirstThresholdSharesReached: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofVerified',
        'TargetAccepted',
        'FirstThresholdSharesReached',
    ],
    CPADProfileVerified: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofVerified',
        'TargetAccepted',
        'FirstThresholdSharesReached',
        'CPADProfileVerified',
    ],
    CPADProfileRejected: [],
    FullyVerifiedResult: [
        'AggregateInputsReady',
        'AggregateInputsBridgeVerified',
        'AwaitingEvaluation',
        'TopKEvaluated',
        'TargetFinalityReached',
        'EvaluationProofVerified',
        'TargetAccepted',
        'FirstThresholdSharesReached',
        'CPADProfileVerified',
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
    AggregateInputsBridgeVerified: [],
    AwaitingEvaluation: [],
    TopKEvaluated: [],
    TargetFinalityReached: [],
    EvaluationProofOpen: [],
    EvaluationProofVerified: [],
    EvaluationProofRejected: ['EvaluationProofRejected'],
    EvaluationProofProfileRejected: ['EvaluationProofProfileRejected'],
    TargetAccepted: [],
    AwaitingFirstDecryptionShares: ['DecryptionThresholdNotReached'],
    FirstThresholdSharesReached: [],
    CPADProfileVerified: [],
    CPADProfileRejected: ['CPADProfileRejected'],
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
    if (input.lifecycleState === 'EvaluationProofRejected') {
        return 'EvaluationProofRejected';
    }
    if (input.lifecycleState === 'EvaluationProofProfileRejected') {
        return 'EvaluationProofProfileRejected';
    }
    if (
        input.lifecycleState === 'EvaluationProofVerified' ||
        input.lifecycleState === 'TargetAccepted' ||
        input.lifecycleState === 'AwaitingFirstDecryptionShares' ||
        input.lifecycleState === 'FirstThresholdSharesReached' ||
        input.lifecycleState === 'CPADProfileVerified' ||
        input.lifecycleState === 'FullyVerifiedResult'
    ) {
        return 'EvaluationProofVerified';
    }

    return 'EvaluationProofOpen';
};

const deriveLocalPrimaryLabels = (
    input: LifecycleLabelInput,
): PrimaryStatusLabel[] => {
    const labels: PrimaryStatusLabel[] = [];

    if (input.localRosterExternallyAccepted === true) {
        labels.push('RosterExternallyAccepted');
    }
    if (input.ownBallotIncluded === true) {
        labels.push('BallotIncluded');
    }
    if (input.evaluationLocallyReplayed === true) {
        labels.push('EvaluationLocallyReplayed');
    }
    if (input.aggregateInputsBridgeVerified === true) {
        labels.push('AggregateInputsBridgeVerified');
    }

    return labels;
};

const pushFailure = (
    failures: FailureStatusLabel[],
    condition: boolean | undefined,
    label: FailureStatusLabel,
): void => {
    if (condition === true) {
        failures.push(label);
    }
};

const resultPathIsFullyGated = (input: LifecycleLabelInput): boolean =>
    input.localRosterExternallyAccepted === true &&
    input.thresholdProfile.claimBearing &&
    input.thresholdProfile.targetBoundShareSelectionProfile !== null &&
    input.thresholdProfile.decryptionShareQuorum !== null &&
    input.mobileClaimGatePassed === true &&
    input.bridgeMobileCertificatePresent === true &&
    input.bridgeProverCertificatePresent === true &&
    input.evaluationProofCertificatePresent === true &&
    input.oneShotDecryptionProofCertificatePresent === true &&
    input.cpadCertificatePresent === true &&
    input.thresholdDecryptionCertificatePresent === true &&
    input.evaluationProofClosureApplied === true &&
    input.cpadClosureApplied === true &&
    input.activeMaliciousClosureApplied === true &&
    input.decodedResultLayoutVerified === true;

const deriveResultClaimLabels = (
    input: LifecycleLabelInput,
): readonly ResultClaimLabel[] => {
    if (
        input.lifecycleState !== 'FullyVerifiedResult' ||
        !resultPathIsFullyGated(input)
    ) {
        return [];
    }

    const labels: ResultClaimLabel[] = ['FullyVerifiedResult'];
    if (input.localReplayCertificateVerified === true) {
        labels.push('ResultLocallyReplayedAuditable');
    }

    return labels;
};

const securityProfileModeLabelsById = new Map<string, ModeStatusLabel>([
    [passiveMhePrototypeProfileId, 'PassiveMHEPrototype'],
    [evaluationProofProfileId, 'EvaluationProofClosure'],
    [thresholdDecryptionProfileId, 'CPADClosure'],
    [activeMaliciousMheProfileId, 'ActiveMaliciousClosure'],
]);

const deriveSecurityProfileModes = (
    input: LifecycleLabelInput,
): readonly ModeStatusLabel[] => {
    const labels: ModeStatusLabel[] = [];

    for (const profileId of input.securityProfileIds ?? []) {
        const label = securityProfileModeLabelsById.get(profileId);
        if (label !== undefined) {
            labels.push(label);
        }
    }
    if (
        (input.securityProfileIds === undefined ||
            input.securityProfileIds.length === 0) &&
        (input.mheSecurityClosure ?? 'PassiveMHEPrototype') ===
            'PassiveMHEPrototype'
    ) {
        labels.push('PassiveMHEPrototype');
    }

    return Array.from(new Set(labels));
};

export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => {
    const failures: FailureStatusLabel[] = [
        ...failureLabelsByState[input.lifecycleState],
    ];
    const modes: ModeStatusLabel[] = [];
    const evaluationProofMode = deriveEvaluationProofMode(input);
    const resultClaimLabels = deriveResultClaimLabels(input);
    let primary: PrimaryStatusLabel[] = Array.from(
        new Set([
            ...deriveLocalPrimaryLabels(input),
            ...primaryLabelsByState[input.lifecycleState],
            ...(resultClaimLabels.includes('ResultLocallyReplayedAuditable')
                ? (['ResultLocallyReplayedAuditable'] as const)
                : []),
        ]),
    );

    if (input.thresholdProfile.rosterProfileKind === 'CasualMicroRoster') {
        modes.push('CasualMicroRoster');
    }
    modes.push(...deriveSecurityProfileModes(input));
    if (input.mobileFlagshipProfile === true) {
        modes.push('MobileFlagshipProfile');
    }
    if (input.foregroundProofGenerationRequired === true) {
        modes.push('ForegroundProofGenerationRequired');
    }
    if (input.foregroundProofVerificationRequired === true) {
        modes.push('ForegroundProofVerificationRequired');
    }
    if (input.proofCheckpointRestored === true) {
        modes.push('ProofCheckpointRestored');
    }
    if (input.proofCheckpointRejected === true) {
        modes.push('ProofCheckpointRejected');
    }
    if (input.longRunningCryptographicCheck === true) {
        modes.push('LongRunningCryptographicCheck');
    }

    pushFailure(failures, input.bridgeProofRejected, 'BridgeProofRejected');
    pushFailure(
        failures,
        input.witnessEquivocationEvidence,
        'WitnessEquivocationEvidence',
    );
    pushFailure(
        failures,
        input.targetFinalityNotReached,
        'TargetFinalityNotReached',
    );
    pushFailure(
        failures,
        input.backendProfileRejected,
        'BackendProfileRejected',
    );
    pushFailure(failures, input.bgvProfileRejected, 'BGVProfileRejected');
    pushFailure(failures, input.cpadProfileRejected, 'CPADProfileRejected');
    pushFailure(
        failures,
        input.decryptionThresholdNotReached,
        'DecryptionThresholdNotReached',
    );
    pushFailure(
        failures,
        input.bridgeMobileCertRejected,
        'BridgeMobileCertRejected',
    );
    pushFailure(
        failures,
        input.boardFinalityProfileRejected,
        'BoardFinalityProfileRejected',
    );
    pushFailure(failures, input.mobileProfileRejected, 'MobileProfileRejected');
    pushFailure(
        failures,
        input.unsupportedLowResourceDevice,
        'UnsupportedLowResourceDevice',
    );

    if (
        input.lifecycleState === 'FullyVerifiedResult' &&
        resultClaimLabels.length === 0
    ) {
        primary = ['Unresolved'];
    }

    return {
        primary,
        failures: Array.from(new Set(failures)),
        modes: Array.from(new Set(modes)),
        resultClaimLabels,
        evaluationProofMode,
    };
};
