import {
    activeMaliciousMheProfileId,
    passiveMhePrototypeProfileId,
    targetDecryptionProfileId,
} from '@sealed-lattice/types';
import type {
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
    encryptedBallotsSelected: ['encryptedBallotsSelected'],
    ballotProofsVerified: ['ballotProofsVerified'],
    encryptedBallotAggregateComputed: ['encryptedBallotAggregateComputed'],
    evaluatorReplayed: ['evaluatorReplayed'],
    targetFinalityReached: ['evaluatorReplayed'],
    targetAccepted: ['evaluatorReplayed', 'targetAccepted'],
    decryptionPending: ['evaluatorReplayed', 'targetAccepted'],
    decryptionSharesReady: ['evaluatorReplayed', 'targetAccepted'],
    resultDecoded: ['evaluatorReplayed', 'targetAccepted', 'resultDecoded'],
    fullyVerified: [
        'evaluatorReplayed',
        'targetAccepted',
        'resultDecoded',
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
    encryptedBallotsSelected: ['ballotProofsMissing'],
    ballotProofsVerified: [],
    encryptedBallotAggregateComputed: ['evaluatorReplayMissing'],
    evaluatorReplayed: [],
    targetFinalityReached: [],
    targetAccepted: [],
    decryptionPending: ['missingDecryptionShares'],
    decryptionSharesReady: [],
    resultDecoded: [],
    fullyVerified: [],
    pending: [],
    outsideClaim: ['unsupportedTargetDecryptionProfile'],
    forkDetected: [
        'boardForkSuspected',
        'boardEvidencePublished',
        'forkDetected',
    ],
} as const satisfies Record<LifecycleState, readonly FailureStatusLabel[]>;

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
    input.directProofTransportPresent === true &&
    input.mobileReplayEvidencePresent === true &&
    input.targetDecryptionCertificatePresent === true &&
    input.targetDecryptionClosureApplied === true &&
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
    [passiveMhePrototypeProfileId, 'passiveMhePrototype'],
    [targetDecryptionProfileId, 'targetDecryptionClosure'],
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
        (input.mheSecurityClosure ?? 'PassiveMHEPrototype') ===
            'PassiveMHEPrototype'
    ) {
        labels.push('passiveMhePrototype');
    }

    return Array.from(new Set(labels));
};

export const deriveLifecycleLabels = (
    input: LifecycleLabelInput,
): LifecycleLabels => {
    const failures: FailureStatusLabel[] = [
        ...failureLabelsByState[input.lifecycleState],
    ];
    const modes: ModeStatusLabel[] = ['directEncryptedBallotPath'];
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
    if (input.mobileReplayEvidencePresent === true) {
        modes.push('mobileReplayProfile');
    }
    if (input.longRunningCryptographicCheck === true) {
        modes.push('longRunningCryptographicCheck');
    }

    pushFailure(failures, input.ballotProofsMissing, 'ballotProofsMissing');
    pushFailure(
        failures,
        input.evaluatorReplayMissing,
        'evaluatorReplayMissing',
    );
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
        input.ballotProofProfileRejected,
        'rejectedBallotProofProfile',
    );
    pushFailure(
        failures,
        input.evaluatorReplayProfileRejected,
        'rejectedEvaluatorReplayProfile',
    );
    pushFailure(
        failures,
        input.targetDecryptionProfileRejected,
        'unsupportedTargetDecryptionProfile',
    );
    pushFailure(
        failures,
        input.decryptionThresholdNotReached,
        'missingDecryptionShares',
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
    };
};
