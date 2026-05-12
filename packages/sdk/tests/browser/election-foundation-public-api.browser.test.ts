import { describe, expect, it } from 'vitest';

import {
    deriveValidatedFirstComeOrder,
    deriveLifecycleLabels,
    deriveThresholdProfile,
    evaluateActionCapability,
    isActionCurrentForRecoveryEpoch,
    isValidLifecycleTransition,
    validatePollSpec,
    verifyBoardConsistency,
    verifyCastReceiptShell,
    verifyCloseRecordShell,
    verifyFirstComePolicy,
    verifyRecoveryEpochUpdate,
    verifyRosterManifestTranscript,
    verifyTargetFinality,
    verifyTranscriptCoreFixture,
} from '../../dist/index.js';
import * as publicApi from '../../dist/index.js';

describe('election foundation public package API in browsers', () => {
    it('exposes callable safe runtime functions and keeps obvious raw APIs absent', () => {
        expect(typeof deriveLifecycleLabels).toBe('function');
        expect(typeof deriveValidatedFirstComeOrder).toBe('function');
        expect(typeof deriveThresholdProfile).toBe('function');
        expect(typeof evaluateActionCapability).toBe('function');
        expect(typeof isActionCurrentForRecoveryEpoch).toBe('function');
        expect(typeof isValidLifecycleTransition).toBe('function');
        expect(typeof validatePollSpec).toBe('function');
        expect(typeof verifyBoardConsistency).toBe('function');
        expect(typeof verifyCastReceiptShell).toBe('function');
        expect(typeof verifyCloseRecordShell).toBe('function');
        expect(typeof verifyFirstComePolicy).toBe('function');
        expect(typeof verifyRecoveryEpochUpdate).toBe('function');
        expect(typeof verifyRosterManifestTranscript).toBe('function');
        expect(typeof verifyTargetFinality).toBe('function');
        expect(typeof verifyTranscriptCoreFixture).toBe('function');
        expect('thresholdDecrypt' in publicApi).toBe(false);
        expect('rawHEAdd' in publicApi).toBe(false);
        expect('rawNTT' in publicApi).toBe(false);
        expect('verifyEvaluationReplayAttestationShell' in publicApi).toBe(
            false,
        );
        expect('verifyTargetAcceptedRecordShell' in publicApi).toBe(false);
        expect('verifyTopKDecryptionShareShell' in publicApi).toBe(false);
    });

    it('runs the deterministic election foundation without WASM-specific APIs', () => {
        const thresholdProfile = publicApi.deriveThresholdProfile({
            rosterSize: 20,
        });

        expect(thresholdProfile.releaseQuorum).toBe(14);
        expect(
            publicApi.validatePollSpec({
                pollId: 'browser-poll',
                question: 'Question',
                options: ['A', 'B', 'C'],
                topOptionCount: 2,
            }),
        ).toMatchObject({ ok: true });
        expect(
            publicApi.evaluateActionCapability('DeriveAggregateContribution', {
                lifecycleState: 'VotingClosed',
                thresholdProfile,
                pollSpecValid: true,
                setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                turnoutCount: thresholdProfile.releaseQuorum,
            }),
        ).toEqual({
            allowed: true,
            action: 'DeriveAggregateContribution',
        });
        expect(
            publicApi.deriveValidatedFirstComeOrder({
                requiredContextDigest: 'context',
                selectionPolicyDigest: 'policy',
                expectedSelectionPolicyDigest: 'policy',
                currentRecoveryEpochMap: {
                    participant: {
                        signerIdentity: 'participant',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                candidates: [
                    {
                        objectDigest: 'candidate',
                        objectType: 'TargetFinalityRecord',
                        boardSeq: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextDigest: 'context',
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }),
        ).toMatchObject({
            ok: true,
            orderedCandidates: [
                expect.objectContaining({ objectDigest: 'candidate' }),
            ],
        });
        expect(
            publicApi.verifyBoardConsistency({
                ceremonyId: 'ceremony',
                boardPolicyDigest: 'policy',
                expectedBoardPublicKeyDigest: 'board-key',
                signedBoardHeads: [],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });
});
