import { describe, expect, it } from 'vitest';

import * as publicApi from '../../dist/index.js';

const requiredPublicFunctions = [
    ['deriveLifecycleLabels', publicApi.deriveLifecycleLabels],
    ['deriveThresholdProfile', publicApi.deriveThresholdProfile],
    ['evaluateActionCapability', publicApi.evaluateActionCapability],
    ['isValidLifecycleTransition', publicApi.isValidLifecycleTransition],
    ['validatePollSpec', publicApi.validatePollSpec],
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
];

describe('protocol-shell public package API in Node', () => {
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
    });
});
