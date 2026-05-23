import {
    activeMaliciousMheProfileId,
    developmentIntegrationProfileId,
    evaluationProofProfileId,
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
    draft: ['pending'],
    registrationOpen: ['pending'],
    trusteeSetupOpen: ['pending'],
    registrationClosed: ['pending'],
    rosterFrozen: ['rosterFrozen'],
    votingOpen: ['rosterFrozen'],
    votingClosed: ['rosterFrozen'],
    aggregatePending: ['pending'],
    aggregateReady: ['pending'],
    aggregateBridgeVerified: ['pending'],
    evaluationPending: ['pending'],
    topKEvaluated: ['pending'],
    targetFinalityReached: ['pending'],
    evaluationProofPending: ['pending'],
    evaluationProofVerified: ['evaluationProofVerified'],
    targetAccepted: ['evaluationProofVerified', 'targetAccepted'],
    decryptionPending: ['evaluationProofVerified', 'targetAccepted'],
    decryptionSharesReady: ['evaluationProofVerified', 'targetAccepted'],
    cpadProfileVerified: [
        'evaluationProofVerified',
        'targetAccepted',
        'cpadProfileVerified',
    ],
    fullyVerified: [
        'evaluationProofVerified',
        'targetAccepted',
        'cpadProfileVerified',
        'fullyVerified',
    ],
    pending: ['pending'],
    outsideClaim: ['outsideClaim'],
    forkDetected: ['forkDetected'],
} as const satisfies Record<LifecycleState, readonly PrimaryStatusLabel[]>;

const failureLabelsByState = {
    draft: [],
    registrationOpen: [],
    trusteeSetupOpen: ['setupIncomplete'],
    registrationClosed: ['setupIncomplete'],
    rosterFrozen: [],
    votingOpen: [],
    votingClosed: [],
    aggregatePending: ['missingAggregateContributions'],
    aggregateReady: [],
    aggregateBridgeVerified: [],
    evaluationPending: [],
    topKEvaluated: [],
    targetFinalityReached: [],
    evaluationProofPending: [],
    evaluationProofVerified: [],
    targetAccepted: [],
    decryptionPending: ['missingDecryptionShares'],
    decryptionSharesReady: [],
    cpadProfileVerified: [],
    fullyVerified: [],
    pending: [],
    outsideClaim: ['unsupportedKllpsCpadProfile'],
    forkDetected: [
        'boardForkSuspected',
        'boardEvidencePublished',
        'forkDetected',
    ],
} as const satisfies Record<LifecycleState, readonly FailureStatusLabel[]>;

const deriveEvaluationProofMode = (
    input: LifecycleLabelInput,
): EvaluationProofMode => {
    if (input.evaluationProofMode !== undefined) {
        return input.evaluationProofMode;
    }
    if (
        input.lifecycleState === 'evaluationProofVerified' ||
        input.lifecycleState === 'targetAccepted' ||
        input.lifecycleState === 'decryptionPending' ||
        input.lifecycleState === 'decryptionSharesReady' ||
        input.lifecycleState === 'cpadProfileVerified' ||
        input.lifecycleState === 'fullyVerified'
    ) {
        return 'evaluationProofVerified';
    }

    return 'evaluationProofPending';
};

const deriveLocalPrimaryLabels = (
    input: LifecycleLabelInput,
): PrimaryStatusLabel[] => {
    const labels: PrimaryStatusLabel[] = [];

    if (input.localRosterAccepted === true) {
        labels.push('rosterFrozen');
    }
    if (input.ownBallotSubmitted === true) {
        labels.push('ballotSubmitted');
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
    input.localRosterAccepted === true &&
    input.thresholdProfile.claimBearing &&
    input.thresholdProfile.targetBoundShareSelectionProfile !== null &&
    input.thresholdProfile.decryptionShareQuorum !== null &&
    input.runtimeClaimGatePassed === true &&
    input.bridgeBenchmarkReportPresent === true &&
    input.bridgeProverCertificatePresent === true &&
    input.evaluationProofCertificatePresent === true &&
    input.oneShotDecryptionProofCertificatePresent === true &&
    input.kllpsCpadCertificatePresent === true &&
    input.thresholdDecryptionCertificatePresent === true &&
    input.evaluationProofClosureApplied === true &&
    input.kllpsCpadClosureApplied === true &&
    input.activeMaliciousClosureApplied === true &&
    input.decodedResultLayoutVerified === true;

const deriveResultClaimLabels = (
    input: LifecycleLabelInput,
): readonly ResultClaimLabel[] => {
    if (
        input.lifecycleState !== 'fullyVerified' ||
        !resultPathIsFullyGated(input)
    ) {
        return [];
    }

    return ['fullyVerified'];
};

const securityProfileModeLabelsById = new Map<string, ModeStatusLabel>([
    [developmentIntegrationProfileId, 'developmentIntegration'],
    [evaluationProofProfileId, 'evaluationProofClosure'],
    [thresholdDecryptionProfileId, 'kllpsCpadClosure'],
    [activeMaliciousMheProfileId, 'activeMaliciousClosure'],
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
        (input.mheSecurityClosure ?? 'developmentIntegration') ===
            'developmentIntegration'
    ) {
        labels.push('developmentIntegration');
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
        ]),
    );

    if (input.thresholdProfile.rosterProfileKind === 'CasualMicroRoster') {
        modes.push('casualMicroRoster');
    }
    modes.push(...deriveSecurityProfileModes(input));
    if (input.measuredRuntimeProfile === true) {
        modes.push('measuredRuntimeProfile');
    }
    if (input.longRunningCryptographicCheck === true) {
        modes.push('longRunningCryptographicCheck');
    }
    if (input.localReplayUnavailable === true) {
        modes.push('localReplayUnavailable');
    } else if (input.evaluationLocallyReplayed === true) {
        modes.push('localReplayMatched');
    }
    if (
        input.localReplayUnavailable !== true &&
        input.localReplayDiagnosticVerified === false
    ) {
        modes.push('localReplayFailed');
    }

    pushFailure(failures, input.bridgeProofRejected, 'rejectedBridgeProof');
    pushFailure(
        failures,
        input.witnessEquivocationEvidence,
        'witnessEquivocationEvidence',
    );
    pushFailure(
        failures,
        input.targetFinalityNotReached,
        'missingTargetFinality',
    );
    pushFailure(
        failures,
        input.backendProfileRejected,
        'unsupportedBackendProfile',
    );
    pushFailure(failures, input.bgvProfileRejected, 'unsupportedBgvProfile');
    pushFailure(
        failures,
        input.kllpsCpadProfileRejected,
        'unsupportedKllpsCpadProfile',
    );
    pushFailure(
        failures,
        input.decryptionThresholdNotReached,
        'missingDecryptionShares',
    );
    pushFailure(
        failures,
        input.bridgeBenchmarkReportRejected,
        'rejectedBridgeBenchmarkReport',
    );
    pushFailure(
        failures,
        input.boardFinalityProfileRejected,
        'rejectedBoardFinalityProfile',
    );
    pushFailure(
        failures,
        input.runtimeProfileRejected,
        'outsideMeasuredRuntimeProfile',
    );
    pushFailure(
        failures,
        input.outsideMeasuredRuntimeProfile,
        'outsideMeasuredRuntimeProfile',
    );

    if (
        input.lifecycleState === 'fullyVerified' &&
        resultClaimLabels.length === 0
    ) {
        primary = ['pending'];
    }

    return {
        primary,
        failures: Array.from(new Set(failures)),
        modes: Array.from(new Set(modes)),
        resultClaimLabels,
        evaluationProofMode,
    };
};
