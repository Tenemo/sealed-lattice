import { describe, expect, it } from 'vitest';

import * as publicApi from '../../dist/index.js';

const expectedPublicKeys = [
    'deriveLifecycleLabels',
    'deriveThresholdProfile',
    'evaluateActionCapability',
    'isValidLifecycleTransition',
    'validatePollSpec',
    'verifyTranscriptCoreFixture',
];

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
    it('exposes only the safe protocol-shell runtime shell and transcript-core verifier', () => {
        expect(Object.keys(publicApi).sort()).toEqual(expectedPublicKeys);
        for (const publicKey of forbiddenPublicKeys) {
            expect(publicKey in publicApi).toBe(false);
        }
    });

    it('derives threshold, poll, lifecycle, label, and capability decisions', () => {
        const thresholdProfile = publicApi.deriveThresholdProfile({ n: 20 });

        expect(thresholdProfile.cPriv).toBe(6);
        expect(
            publicApi.validatePollSpec({
                ceremonyId: 'ceremony',
                question: 'Question',
                options: ['A', 'B'],
                kTop: 1,
            }),
        ).toMatchObject({ ok: true });
        expect(
            publicApi.isValidLifecycleTransition({
                from: 'VotingOpen',
                to: 'VotingClosed',
            }),
        ).toBe(true);
        expect(
            publicApi.deriveLifecycleLabels({
                lifecycleState: 'ResultComputedAuditable',
                thresholdProfile,
                mheSecurityStage: 'ActiveMalicious',
            }).resultClaimLabel,
        ).toBe('ResultComputedAuditable');
        expect(
            publicApi.evaluateActionCapability('AcceptTarget', {
                lifecycleState: 'EvaluationReplayOpen',
                thresholdProfile,
                pollSpecValid: true,
                targetFinalityAccepted: true,
                replayAttestationCount: thresholdProfile.qEval,
            }),
        ).toEqual({ allowed: true, action: 'AcceptTarget' });
    });
});
