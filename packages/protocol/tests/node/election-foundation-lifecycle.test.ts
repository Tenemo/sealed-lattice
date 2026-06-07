import {
    targetDecryptionProfileId,
    type LifecycleLabelInput,
    type LifecycleState,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    dynamicRosterProfileCertificateHash,
    targetBoundShareSelectionProfile,
} from './election-foundation-fixture-constants.js';

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

const uncertifiedThresholdProfile = deriveThresholdProfile({ rosterSize: 20 });
const thresholdProfile = deriveThresholdProfile({
    rosterSize: 10,
    targetBoundShareSelectionProfile,
});

const fullyVerifiedLabelInput = (
    overrides: Partial<LifecycleLabelInput> = {},
): LifecycleLabelInput => ({
    lifecycleState: 'fullyVerified',
    thresholdProfile,
    localRosterAccepted: true,
    runtimeClaimGatePassed: true,
    directProofTransportPresent: true,
    mobileReplayEvidencePresent: true,
    targetDecryptionCertificatePresent: true,
    targetDecryptionClosureApplied: true,
    activeMaliciousClosureApplied: true,
    decodedResultLayoutVerified: true,
    ...overrides,
});

describe('election foundation lifecycle', () => {
    it('accepts the direct encrypted ballot lifecycle path', () => {
        expectValidPath([
            'draft',
            'registrationOpen',
            'trusteeSetupOpen',
            'registrationClosed',
            'rosterFrozen',
            'votingOpen',
            'votingClosed',
            'encryptedBallotsSelected',
            'ballotProofsVerified',
            'encryptedBallotAggregateComputed',
            'evaluatorReplayed',
            'targetFinalityReached',
            'targetAccepted',
            'decryptionPending',
            'decryptionSharesReady',
            'resultDecoded',
            'fullyVerified',
        ]);
    });

    it.each([
        ['votingOpen', 'targetAccepted'],
        ['encryptedBallotsSelected', 'encryptedBallotAggregateComputed'],
        ['ballotProofsVerified', 'evaluatorReplayed'],
        ['targetFinalityReached', 'decryptionPending'],
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

    it('keeps local roster acceptance and ballot submission as local status labels', () => {
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
                ownBallotSubmitted: true,
            }).primary,
        ).toEqual(expect.arrayContaining(['rosterFrozen', 'ballotSubmitted']));
    });

    it('emits fullyVerified only after every direct-path claim gate closes', () => {
        const labels = deriveLifecycleLabels(fullyVerifiedLabelInput());

        expect(labels.primary).toContain('fullyVerified');
        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'directEncryptedBallotPath',
                'mobileReplayProfile',
            ]),
        );
    });

    it.each([
        { localRosterAccepted: false },
        { thresholdProfile: uncertifiedThresholdProfile },
        { runtimeClaimGatePassed: false },
        { directProofTransportPresent: false },
        { mobileReplayEvidencePresent: false },
        { targetDecryptionCertificatePresent: false },
        { targetDecryptionClosureApplied: false },
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
                fullyVerifiedLabelInput({ thresholdProfile: casualProfile }),
            );
            const dynamicLabels = deriveLifecycleLabels(
                fullyVerifiedLabelInput({ thresholdProfile: dynamicProfile }),
            );

            expect(casualLabels.modes).toContain('casualMicroRoster');
            expect(casualLabels.resultClaimLabels).toEqual([]);
            expect(dynamicLabels.resultClaimLabels).toEqual(['fullyVerified']);
        },
    );

    it('derives closure mode labels from current direct-path claim gates', () => {
        const labels = deriveLifecycleLabels(
            fullyVerifiedLabelInput({
                securityProfileIds: [targetDecryptionProfileId],
            }),
        );

        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'targetDecryptionClosure',
                'activeMaliciousClosure',
            ]),
        );
        expect(labels.resultClaimLabels).toEqual(['fullyVerified']);
    });

    it('derives direct-path failure labels from local context', () => {
        const labels = deriveLifecycleLabels({
            lifecycleState: 'encryptedBallotAggregateComputed',
            thresholdProfile,
            localRosterAccepted: true,
            ballotProofsMissing: true,
            evaluatorReplayMissing: true,
            witnessEquivocationEvidence: true,
            targetFinalityNotReached: true,
            backendProfileRejected: true,
            bgvProfileRejected: true,
            ballotProofProfileRejected: true,
            evaluatorReplayProfileRejected: true,
            targetDecryptionProfileRejected: true,
            decryptionThresholdNotReached: true,
            boardFinalityProfileRejected: true,
            outsideMeasuredRuntimeProfile: true,
            measuredRuntimeProfile: true,
            longRunningCryptographicCheck: true,
        });

        expect(labels.primary).toEqual(
            expect.arrayContaining([
                'rosterFrozen',
                'encryptedBallotAggregateComputed',
            ]),
        );
        expect(labels.failures).toEqual(
            expect.arrayContaining([
                'ballotProofsMissing',
                'evaluatorReplayMissing',
                'witnessEquivocationEvidence',
                'missingTargetFinality',
                'unsupportedBackendProfile',
                'unsupportedBgvProfile',
                'rejectedBallotProofProfile',
                'rejectedEvaluatorReplayProfile',
                'unsupportedTargetDecryptionProfile',
                'missingDecryptionShares',
                'rejectedBoardFinalityProfile',
                'outsideMeasuredRuntimeProfile',
            ]),
        );
        expect(labels.modes).toEqual(
            expect.arrayContaining([
                'directEncryptedBallotPath',
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
