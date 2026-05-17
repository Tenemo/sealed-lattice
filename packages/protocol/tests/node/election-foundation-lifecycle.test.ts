import {
    activeMaliciousMheProfileId,
    cpadProfileId,
    evaluationProofProfileId,
    targetBoundShareSelectionProfileId,
    thresholdDecryptionProfileId,
    type LifecycleLabelInput,
    type LifecycleState,
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

const targetBoundShareSelectionProfile = {
    profileId: targetBoundShareSelectionProfileId,
    certificateDigest: 'target-bound-certificate-digest',
    cpadProfileId,
    targetBasisDigest: 'target-basis-digest',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
    selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
} as const;

const uncertifiedThresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const thresholdProfile = deriveThresholdProfile({
    rosterSize: 20,
    targetBoundShareSelectionProfile,
});

const fullyVerifiedLabelInput = (
    overrides: Partial<LifecycleLabelInput> = {},
): LifecycleLabelInput => ({
    lifecycleState: 'FullyVerifiedResult',
    thresholdProfile,
    mheSecurityClosure: 'ActiveMalicious',
    localRosterExternallyAccepted: true,
    mobileClaimGatePassed: true,
    bridgeMobileCertificatePresent: true,
    bridgeProverCertificatePresent: true,
    evaluationProofCertificatePresent: true,
    oneShotDecryptionProofCertificatePresent: true,
    cpadCertificatePresent: true,
    thresholdDecryptionCertificatePresent: true,
    evaluationProofClosureApplied: true,
    cpadClosureApplied: true,
    activeMaliciousClosureApplied: true,
    decodedResultLayoutVerified: true,
    ...overrides,
});

describe('election foundation lifecycle', () => {
    it('accepts the primary packed BGV lifecycle path', () => {
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

    it('returns false for unknown runtime lifecycle states', () => {
        expect(
            isValidLifecycleTransition({
                from: 'NotAState' as never,
                to: 'VotingOpen',
            }),
        ).toBe(false);
    });

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

    it('emits FullyVerifiedResult only after all packed BGV claim gates close', () => {
        const labels = deriveLifecycleLabels(fullyVerifiedLabelInput());

        expect(labels.primary).toContain('FullyVerifiedResult');
        expect(labels.resultClaimLabels).toEqual(['FullyVerifiedResult']);
        expect(labels.evaluationProofMode).toBe('EvaluationProofVerified');
    });

    it.each([
        { localRosterExternallyAccepted: false },
        { evaluationProofCertificatePresent: false },
        { thresholdProfile: uncertifiedThresholdProfile },
        { cpadCertificatePresent: false },
        { thresholdDecryptionCertificatePresent: false },
        { evaluationProofClosureApplied: false },
        { cpadClosureApplied: false },
        { activeMaliciousClosureApplied: false },
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

    it('keeps unsafe profiles and passive prototype out of claim-bearing results', () => {
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
                mheSecurityClosure: 'PassiveMHEPrototype',
                activeMaliciousClosureApplied: false,
            }),
        );

        expect(unsafeLabels.primary).toEqual(['Unresolved']);
        expect(unsafeLabels.modes).toContain('UnsafeMicroRoster');
        expect(unsafeLabels.resultClaimLabels).toEqual([]);
        expect(passiveLabels.primary).toEqual(['Unresolved']);
        expect(passiveLabels.modes).toContain('PassiveMHEPrototype');
    });

    it('derives closure profile labels from transcript-visible profile IDs', () => {
        const labels = deriveLifecycleLabels({
            lifecycleState: 'FullyVerifiedResult',
            thresholdProfile,
            mheSecurityClosure: 'ActiveMalicious',
            securityProfileIds: [
                evaluationProofProfileId,
                thresholdDecryptionProfileId,
                activeMaliciousMheProfileId,
            ],
            localRosterExternallyAccepted: true,
            mobileClaimGatePassed: true,
            bridgeMobileCertificatePresent: true,
            bridgeProverCertificatePresent: true,
            evaluationProofCertificatePresent: true,
            oneShotDecryptionProofCertificatePresent: true,
            cpadCertificatePresent: true,
            thresholdDecryptionCertificatePresent: true,
            evaluationProofClosureApplied: true,
            cpadClosureApplied: true,
            activeMaliciousClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'EvaluationProofClosure',
                'CPADClosure',
                'ActiveMaliciousClosure',
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

    it('does not emit decryption-threshold failure after first shares are reached', () => {
        expect(
            deriveLifecycleLabels({
                lifecycleState: 'AwaitingFirstDecryptionShares',
                thresholdProfile,
            }).failures,
        ).toContain('DecryptionThresholdNotReached');

        expect(
            deriveLifecycleLabels({
                lifecycleState: 'FirstThresholdSharesReached',
                thresholdProfile,
            }).failures,
        ).not.toContain('DecryptionThresholdNotReached');
    });
});
