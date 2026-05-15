import type {
    LifecycleLabelInput,
    LifecycleState,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveLifecycleLabels,
    deriveThresholdProfile,
    isValidLifecycleTransition,
} from '../../src/index';

const expectValidPath = (states: readonly LifecycleState[]): void => {
    for (let index = 0; index < states.length - 1; index += 1) {
        expect(
            isValidLifecycleTransition({
                from: states[index],
                to: states[index + 1],
            }),
        ).toBe(true);
    }
};

const thresholdProfile = deriveThresholdProfile({ rosterSize: 20 });

const fullyVerifiedLabelInput = (
    overrides: Partial<LifecycleLabelInput> = {},
): LifecycleLabelInput => ({
    lifecycleState: 'FullyVerifiedResult',
    thresholdProfile,
    mheSecurityStage: 'ActiveMalicious',
    localRosterExternallyAccepted: true,
    mobileClaimGatePassed: true,
    bridgeMobileCertificatePresent: true,
    bridgeProverCertificatePresent: true,
    evaluationProofCertificatePresent: true,
    oneShotDecryptionProofCertificatePresent: true,
    cpadCertificatePresent: true,
    thresholdDecryptionCertificatePresent: true,
    stageXClosureApplied: true,
    stageCClosureApplied: true,
    stageAClosureApplied: true,
    decodedResultLayoutVerified: true,
    ...overrides,
});

describe('election foundation lifecycle', () => {
    it('accepts the primary v53 BGV lifecycle path', () => {
        expectValidPath([
            'DraftPoll',
            'RegistrationOpen',
            'TrusteeSetupOpen',
            'RegistrationClosed',
            'RosterFrozen',
            'VotingOpen',
            'VotingClosed',
            'AwaitingAggregateContributors',
            'AggregateInputsReady',
            'AggregateInputsBridgeVerified',
            'AwaitingEvaluation',
            'TopKEvaluated',
            'TargetFinalityReached',
            'EvaluationProofOpen',
            'EvaluationProofVerified',
            'TargetAccepted',
            'AwaitingFirstDecryptionShares',
            'FirstThresholdSharesReached',
            'CPADProfileVerified',
            'FullyVerifiedResult',
        ]);
    });

    it.each([
        ['VotingOpen', 'TargetAccepted'],
        ['AggregateInputsReady', 'FullyVerifiedResult'],
        ['AggregateInputsReady', 'AwaitingEvaluation'],
        ['TopKEvaluated', 'AwaitingFirstDecryptionShares'],
        ['TargetFinalityReached', 'TargetAccepted'],
        ['EvaluationProofOpen', 'TargetAccepted'],
        ['FirstThresholdSharesReached', 'FullyVerifiedResult'],
        ['DraftPoll', 'VotingOpen'],
    ] satisfies readonly (readonly [LifecycleState, LifecycleState])[])(
        'rejects invalid transition %s -> %s',
        (from, to) => {
            expect(isValidLifecycleTransition({ from, to })).toBe(false);
        },
    );

    it('keeps external roster acceptance as a local label', () => {
        expect(
            isValidLifecycleTransition({
                from: 'RosterFrozen',
                to: 'VotingOpen',
            }),
        ).toBe(true);

        expect(
            deriveLifecycleLabels({
                lifecycleState: 'RosterFrozen',
                thresholdProfile,
            }).primary,
        ).not.toContain('RosterExternallyAccepted');

        expect(
            deriveLifecycleLabels({
                lifecycleState: 'RosterFrozen',
                thresholdProfile,
                localRosterExternallyAccepted: true,
            }).primary,
        ).toContain('RosterExternallyAccepted');
    });

    it('emits FullyVerifiedResult only after all v53 theorem gates close', () => {
        const labels = deriveLifecycleLabels(fullyVerifiedLabelInput());

        expect(labels.primary).toContain('FullyVerifiedResult');
        expect(labels.resultClaimLabels).toEqual(['FullyVerifiedResult']);
        expect(labels.evaluationProofMode).toBe('EvaluationProofVerified');
    });

    it.each([
        { localRosterExternallyAccepted: false },
        { evaluationProofCertificatePresent: false },
        { cpadCertificatePresent: false },
        { thresholdDecryptionCertificatePresent: false },
        { stageXClosureApplied: false },
        { stageCClosureApplied: false },
        { stageAClosureApplied: false },
        { decodedResultLayoutVerified: false },
    ] satisfies readonly Partial<LifecycleLabelInput>[])(
        'withholds FullyVerifiedResult when a mandatory gate is missing',
        (missingGate) => {
            const labels = deriveLifecycleLabels(
                fullyVerifiedLabelInput(missingGate),
            );

            expect(labels.primary).toEqual(['Unresolved']);
            expect(labels.resultClaimLabels).toEqual([]);
        },
    );

    it('keeps opt-in local replay additive to the fully verified result', () => {
        const labels = deriveLifecycleLabels(
            fullyVerifiedLabelInput({
                evaluationLocallyReplayed: true,
                localReplayCertificateVerified: true,
            }),
        );

        expect(labels.primary).toEqual(
            expect.arrayContaining([
                'FullyVerifiedResult',
                'EvaluationLocallyReplayed',
                'ResultLocallyReplayedAuditable',
            ]),
        );
        expect(labels.resultClaimLabels).toEqual([
            'FullyVerifiedResult',
            'ResultLocallyReplayedAuditable',
        ]);
    });

    it('keeps unsafe profiles and passive stage out of claim-bearing results', () => {
        const unsafeProfile = deriveThresholdProfile({
            rosterSize: 19,
            unsafeMicroRosterAcknowledged: true,
        });
        const unsafeLabels = deriveLifecycleLabels(
            fullyVerifiedLabelInput({
                thresholdProfile: unsafeProfile,
            }),
        );
        const passiveLabels = deriveLifecycleLabels(
            fullyVerifiedLabelInput({
                mheSecurityStage: 'PassiveMHEPrototype',
                stageAClosureApplied: false,
            }),
        );

        expect(unsafeLabels.primary).toEqual(['Unresolved']);
        expect(unsafeLabels.modes).toContain('UnsafeMicroRoster');
        expect(unsafeLabels.resultClaimLabels).toEqual([]);
        expect(passiveLabels.primary).toEqual(['Unresolved']);
        expect(passiveLabels.modes).toContain('PassiveMHEPrototype');
    });

    it('derives stage profile labels from transcript-visible profile IDs', () => {
        const labels = deriveLifecycleLabels({
            lifecycleState: 'FullyVerifiedResult',
            thresholdProfile,
            mheSecurityStage: 'ActiveMalicious',
            securityProfileIds: [
                'PQEvalProof-STARK-BGVReplay-v1',
                'BGV-RNS-AsyncThresholdDecryption-CPAD-v1',
                'transcript-core-active-malicious-mhe-profile-v1',
            ],
            localRosterExternallyAccepted: true,
            mobileClaimGatePassed: true,
            bridgeMobileCertificatePresent: true,
            bridgeProverCertificatePresent: true,
            evaluationProofCertificatePresent: true,
            oneShotDecryptionProofCertificatePresent: true,
            cpadCertificatePresent: true,
            thresholdDecryptionCertificatePresent: true,
            stageXClosureApplied: true,
            stageCClosureApplied: true,
            stageAClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'StageXEvaluationProofClosure',
                'StageCCPADClosure',
                'StageAActiveMaliciousClosure',
            ]),
        );
        expect(labels.modes).not.toContain('PassiveMHEPrototype');
        expect(labels.resultClaimLabels).toEqual(['FullyVerifiedResult']);
    });

    it('derives BGV, CPAD, bridge, and mobile execution labels from local context', () => {
        const labels = deriveLifecycleLabels({
            lifecycleState: 'EvaluationProofOpen',
            thresholdProfile,
            localRosterExternallyAccepted: true,
            aggregateInputsBridgeVerified: true,
            bridgeProofRejected: true,
            witnessEquivocationEvidence: true,
            targetFinalityNotReached: true,
            backendProfileRejected: true,
            bgvProfileRejected: true,
            cpadProfileRejected: true,
            decryptionThresholdNotReached: true,
            bridgeMobileCertRejected: true,
            boardFinalityProfileRejected: true,
            mobileProfileRejected: true,
            unsupportedLowResourceDevice: true,
            mobileFlagshipProfile: true,
            foregroundProofGenerationRequired: true,
            foregroundProofVerificationRequired: true,
            proofCheckpointRestored: true,
            proofCheckpointRejected: true,
            longRunningCryptographicCheck: true,
        });

        expect(labels.primary).toEqual(
            expect.arrayContaining([
                'RosterExternallyAccepted',
                'AggregateInputsBridgeVerified',
                'AwaitingEvaluation',
                'EvaluationProofOpen',
            ]),
        );
        expect(labels.failures).toEqual(
            expect.arrayContaining([
                'BridgeProofRejected',
                'WitnessEquivocationEvidence',
                'TargetFinalityNotReached',
                'BackendProfileRejected',
                'BGVProfileRejected',
                'CPADProfileRejected',
                'DecryptionThresholdNotReached',
                'BridgeMobileCertRejected',
                'BoardFinalityProfileRejected',
                'MobileProfileRejected',
                'UnsupportedLowResourceDevice',
            ]),
        );
        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'MobileFlagshipProfile',
                'ForegroundProofGenerationRequired',
                'ForegroundProofVerificationRequired',
                'ProofCheckpointRestored',
                'ProofCheckpointRejected',
                'LongRunningCryptographicCheck',
            ]),
        );
    });
});
