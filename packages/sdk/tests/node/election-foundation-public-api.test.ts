import { describe, expect, it } from 'vitest';

import * as publicApi from '../../dist/index.js';

const requiredPublicFunctions = [
    ['deriveValidatedFirstComeOrder', publicApi.deriveValidatedFirstComeOrder],
    ['deriveLifecycleLabels', publicApi.deriveLifecycleLabels],
    ['deriveThresholdProfile', publicApi.deriveThresholdProfile],
    ['evaluateActionCapability', publicApi.evaluateActionCapability],
    [
        'isActionCurrentForRecoveryEpoch',
        publicApi.isActionCurrentForRecoveryEpoch,
    ],
    ['isValidLifecycleTransition', publicApi.isValidLifecycleTransition],
    ['validatePollSpec', publicApi.validatePollSpec],
    ['verifyBoardConsistency', publicApi.verifyBoardConsistency],
    ['verifyCastReceiptShell', publicApi.verifyCastReceiptShell],
    ['verifyCloseRecordShell', publicApi.verifyCloseRecordShell],
    ['verifyFirstComePolicy', publicApi.verifyFirstComePolicy],
    ['verifyRecoveryEpochUpdate', publicApi.verifyRecoveryEpochUpdate],
    [
        'verifyRosterManifestTranscript',
        publicApi.verifyRosterManifestTranscript,
    ],
    ['verifyTargetFinality', publicApi.verifyTargetFinality],
    ['verifyTranscriptCoreFixture', publicApi.verifyTranscriptCoreFixture],
] as const;

const allowedRuntimeExports = requiredPublicFunctions
    .map(([publicFunctionName]) => publicFunctionName)
    .sort();

const forbiddenPublicKeys = [
    'getShare',
    'exportShare',
    'exportSecretKey',
    'importSecretKey',
    'setSecretKey',
    'thresholdDecrypt',
    'partialDecrypt',
    'partialDecryptWithoutTarget',
    'decryptToFile',
    'decryptToString',
    'rawHEAdd',
    'rawHEMul',
    'rawHERelin',
    'rawHERotate',
    'rawNTT',
    'rawRNSLimbAccess',
    'setNoiseFloodSigma',
    'setSmudgingDistribution',
    'bootstrap',
    'decryptAggregateShare',
    'decryptExactSum',
    'decryptRank',
    'decryptComparisonBit',
    'decryptIntermediateWire',
    'verifyEvaluationReplayAttestationShell',
    'verifyTargetAcceptedRecordShell',
    'verifyTopKDecryptionShareShell',
];

describe('election foundation public package API in Node', () => {
    it('exposes only the safe runtime functions and keeps forbidden operations absent', () => {
        expect(Object.keys(publicApi).sort()).toEqual(allowedRuntimeExports);
        for (const [
            publicFunctionName,
            publicFunction,
        ] of requiredPublicFunctions) {
            expect(typeof publicFunction, publicFunctionName).toBe('function');
        }
        for (const publicKey of forbiddenPublicKeys) {
            expect(publicKey in publicApi).toBe(false);
        }
    });

    it('derives threshold, poll, lifecycle, label, and capability decisions', () => {
        const thresholdProfile = publicApi.deriveThresholdProfile({
            rosterSize: 20,
        });

        expect(thresholdProfile.privacyCorruptionBound).toBe(6);
        expect(
            publicApi.validatePollSpec({
                pollId: 'poll',
                question: 'Question',
                options: ['A', 'B'],
                topOptionCount: 1,
            }),
        ).toMatchObject({ ok: true });
        expect(
            publicApi.isValidLifecycleTransition({
                from: 'VotingOpen',
                to: 'VotingClosed',
            }),
        ).toBe(true);
        const labels = publicApi.deriveLifecycleLabels({
            lifecycleState: 'ResultComputedAuditable',
            thresholdProfile,
            mheSecurityStage: 'ActiveMalicious',
            mobileClaimGatePassed: true,
        });

        expect(labels.resultClaimLabel).toBe('ResultComputedAuditable');
        expect(labels.modes).toEqual([]);
        expect(
            publicApi.evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'EvaluationReplayOpen',
                thresholdProfile,
                pollSpecValid: true,
                targetFinalityAccepted: true,
                replayAttestationCount: thresholdProfile.evaluationReplayQuorum,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
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
    });
});
