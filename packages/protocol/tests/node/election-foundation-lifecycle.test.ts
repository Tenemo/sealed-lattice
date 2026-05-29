import {
    activeMaliciousMheProfileId,
    cpadProfileId,
    evaluationProofProfileId,
    passiveMhePrototypeProfileId,
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
} from '#packages/protocol/src/index';

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
    certificateHash: 'target-bound-certificate-hash',
    cpadProfileId,
    targetBasisHash: 'target-basis-hash',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
    selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
} as const;

const dynamicRosterProfileCertificateHash = 'a'.repeat(128);
const uncertifiedThresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const thresholdProfile = deriveThresholdProfile({
    rosterSize: 20,
    targetBoundShareSelectionProfile,
});

const fullyVerifiedLabelInput = (
    overrides: Partial<LifecycleLabelInput> = {},
): LifecycleLabelInput => ({
    lifecycleState: 'fullyVerified',
    thresholdProfile,
    mheSecurityClosure: 'ActiveMalicious',
    localRosterAccepted: true,
    runtimeClaimGatePassed: true,
    bridgeBenchmarkReportPresent: true,
    bridgeProverCertificatePresent: true,
    evaluationProofCertificatePresent: true,
    oneShotDecryptionProofCertificatePresent: true,
    kllpsCpadCertificatePresent: true,
    thresholdDecryptionCertificatePresent: true,
    evaluationProofClosureApplied: true,
    kllpsCpadClosureApplied: true,
    activeMaliciousClosureApplied: true,
    decodedResultLayoutVerified: true,
    ...overrides,
});

describe('election foundation lifecycle', () => {
    it('accepts the primary packed BGV lifecycle path', () => {
        expectValidPath([
            'draft',
            'registrationOpen',
            'trusteeSetupOpen',
            'registrationClosed',
            'rosterFrozen',
            'votingOpen',
            'votingClosed',
            'aggregatePending',
            'aggregateReady',
            'aggregateBridgeVerified',
            'evaluationPending',
            'topKEvaluated',
            'targetFinalityReached',
            'evaluationProofPending',
            'evaluationProofVerified',
            'targetAccepted',
            'decryptionPending',
            'decryptionSharesReady',
            'cpadProfileVerified',
            'fullyVerified',
        ]);
    });

    it.each([
        ['votingOpen', 'targetAccepted'],
        ['aggregateReady', 'fullyVerified'],
        ['aggregateReady', 'evaluationPending'],
        ['topKEvaluated', 'decryptionPending'],
        ['targetFinalityReached', 'targetAccepted'],
        ['evaluationProofPending', 'targetAccepted'],
        ['decryptionSharesReady', 'fullyVerified'],
        ['draft', 'votingOpen'],
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
                to: 'votingOpen',
            }),
        ).toBe(false);
    });

    it('keeps local roster acceptance as a diagnostic label', () => {
        expect(
            isValidLifecycleTransition({
                from: 'rosterFrozen',
                to: 'votingOpen',
            }),
        ).toBe(true);

        expect(
            deriveLifecycleLabels({
                lifecycleState: 'draft',
                thresholdProfile,
            }).primary,
        ).not.toContain('rosterFrozen');

        expect(
            deriveLifecycleLabels({
                lifecycleState: 'draft',
                thresholdProfile,
                localRosterAccepted: true,
            }).primary,
        ).toContain('rosterFrozen');
    });

    it('emits fullyVerified only after all packed BGV claim gates close', () => {
        const labels = deriveLifecycleLabels(fullyVerifiedLabelInput());

        expect(labels.primary).toContain('fullyVerified');
        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
        expect(labels.evaluationProofMode).toBe('evaluationProofVerified');
    });

    it.each([
        { localRosterAccepted: false },
        { evaluationProofCertificatePresent: false },
        { thresholdProfile: uncertifiedThresholdProfile },
        { kllpsCpadCertificatePresent: false },
        { thresholdDecryptionCertificatePresent: false },
        { evaluationProofClosureApplied: false },
        { kllpsCpadClosureApplied: false },
        { activeMaliciousClosureApplied: false },
        { decodedResultLayoutVerified: false },
    ] satisfies readonly Partial<LifecycleLabelInput>[])(
        'withholds fullyVerified when a mandatory gate is missing',
        (missingGate) => {
            const labels = deriveLifecycleLabels(
                fullyVerifiedLabelInput(missingGate),
            );

            expect(labels.primary).toEqual(['pending']);
            expect(labels.resultClaimLabels).toEqual([]);
        },
    );

    it('keeps opt-in local replay additive to the fully verified result', () => {
        const labels = deriveLifecycleLabels(
            fullyVerifiedLabelInput({
                evaluationLocallyReplayed: true,
                localReplayDiagnosticVerified: true,
            }),
        );

        expect(labels.primary).toContain('fullyVerified');
        expect(labels.modes).toContain('localReplayMatched');
        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
    });

    it('reports unavailable local replay as a diagnostic mode only', () => {
        const labels = deriveLifecycleLabels(
            fullyVerifiedLabelInput({
                evaluationLocallyReplayed: true,
                localReplayDiagnosticVerified: false,
                localReplayUnavailable: true,
            }),
        );

        expect(labels.modes).toContain('localReplayUnavailable');
        expect(labels.modes).not.toContain('localReplayMatched');
        expect(labels.modes).not.toContain('localReplayFailed');
        expect(labels.failures).not.toContain('localReplayUnavailable');
        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
    });

    it.each([3, 4, 5, 6, 7, 8, 9])(
        'marks roster size %d as casual while preserving dynamic result claim gates',
        (rosterSize) => {
            const casualProfile = deriveThresholdProfile({
                casualMicroRosterAcknowledged: true,
                rosterSize,
            });
            const dynamicProfile = deriveThresholdProfile({
                dynamicRosterProfileCertificateHash,
                rosterSize: 16,
                targetBoundShareSelectionProfile,
            });
            const casualLabels = deriveLifecycleLabels(
                fullyVerifiedLabelInput({
                    thresholdProfile: casualProfile,
                }),
            );
            const dynamicLabels = deriveLifecycleLabels(
                fullyVerifiedLabelInput({
                    thresholdProfile: dynamicProfile,
                }),
            );
            const passiveLabels = deriveLifecycleLabels(
                fullyVerifiedLabelInput({
                    mheSecurityClosure: 'PassiveMHEPrototype',
                    activeMaliciousClosureApplied: false,
                }),
            );

            expect(casualLabels.modes).toContain('casualMicroRoster');
            expect(casualLabels.resultClaimLabels).toEqual([]);
            expect(dynamicLabels.resultClaimLabels).toEqual(['fullyVerified']);
            expect(passiveLabels.primary).toEqual(['pending']);
            expect(passiveLabels.modes).toContain('passiveMhePrototype');
        },
    );

    it('derives closure profile labels from transcript-visible profile IDs', () => {
        const labels = deriveLifecycleLabels({
            lifecycleState: 'fullyVerified',
            thresholdProfile,
            mheSecurityClosure: 'ActiveMalicious',
            securityProfileIds: [
                passiveMhePrototypeProfileId,
                evaluationProofProfileId,
                thresholdDecryptionProfileId,
                activeMaliciousMheProfileId,
            ],
            localRosterAccepted: true,
            runtimeClaimGatePassed: true,
            bridgeBenchmarkReportPresent: true,
            bridgeProverCertificatePresent: true,
            evaluationProofCertificatePresent: true,
            oneShotDecryptionProofCertificatePresent: true,
            kllpsCpadCertificatePresent: true,
            thresholdDecryptionCertificatePresent: true,
            evaluationProofClosureApplied: true,
            kllpsCpadClosureApplied: true,
            activeMaliciousClosureApplied: true,
            decodedResultLayoutVerified: true,
        });

        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'evaluationProofClosure',
                'kllpsCpadClosure',
                'activeMaliciousClosure',
                'passiveMhePrototype',
            ]),
        );
        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
    });

    it('derives BGV, CPAD, bridge, and mobile execution labels from local context', () => {
        const labels = deriveLifecycleLabels({
            lifecycleState: 'evaluationProofPending',
            thresholdProfile,
            localRosterAccepted: true,
            bridgeProofRejected: true,
            witnessEquivocationEvidence: true,
            targetFinalityNotReached: true,
            backendProfileRejected: true,
            bgvProfileRejected: true,
            kllpsCpadProfileRejected: true,
            decryptionThresholdNotReached: true,
            bridgeBenchmarkReportRejected: true,
            boardFinalityProfileRejected: true,
            runtimeProfileRejected: true,
            outsideMeasuredRuntimeProfile: true,
            measuredRuntimeProfile: true,
            longRunningCryptographicCheck: true,
        });

        expect(labels.primary).toEqual(
            expect.arrayContaining(['rosterFrozen', 'pending']),
        );
        expect(labels.failures).toEqual(
            expect.arrayContaining([
                'rejectedBridgeProof',
                'witnessEquivocationEvidence',
                'missingTargetFinality',
                'unsupportedBackendProfile',
                'unsupportedBgvProfile',
                'unsupportedKllpsCpadProfile',
                'missingDecryptionShares',
                'rejectedBridgeBenchmarkReport',
                'rejectedBoardFinalityProfile',
                'outsideMeasuredRuntimeProfile',
            ]),
        );
        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'measuredRuntimeProfile',
                'longRunningCryptographicCheck',
            ]),
        );
    });

    it('does not emit decryption-threshold failure after first shares are reached', () => {
        expect(
            deriveLifecycleLabels({
                lifecycleState: 'decryptionPending',
                thresholdProfile,
            }).failures,
        ).toContain('missingDecryptionShares');

        expect(
            deriveLifecycleLabels({
                lifecycleState: 'decryptionSharesReady',
                thresholdProfile,
            }).failures,
        ).not.toContain('missingDecryptionShares');
    });
});
