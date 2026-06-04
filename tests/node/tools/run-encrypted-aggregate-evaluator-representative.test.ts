import { describe, expect, it } from 'vitest';

import {
    buildRepresentativeRunBinding,
    canonicalCiphertextByteLength,
    canonicalJsonByteLength,
    summarizeEvaluations,
    summarizePublicArtifactMetrics,
    summarizeSetupKeyMetrics,
} from '#tools/ci/run-encrypted-aggregate-evaluator-representative';

describe('encrypted aggregate evaluator representative summary metrics', () => {
    it('extracts public byte-size and certificate metrics from sweep artifacts', () => {
        const setupPackage = {
            certificates: {
                evaluationKeySizeCertificate: {
                    keySwitchKeyByteEstimate: 300,
                    relinearizationKeyByteEstimate: 100,
                    rotationKeyByteEstimate: 200,
                    rotationKeyCount: 20,
                    totalEvaluationKeyByteEstimate: 300,
                },
                evaluationKeySizeProfileHash: 'profile-hash',
                setupParameterCertificate: {
                    finalSecurityStatus:
                        'acceptedForSetupBridgeEvaluatorTargetPending',
                    largestExposedModulusBits: 799,
                },
            },
        };
        const sweep = {
            evaluations: [
                {
                    appendixDPublicInputStatement: {
                        objectType: 'TopKEvaluationProofPublicInputStatement',
                    },
                    encryptedSparseTarget: {
                        targetIdCiphertext: {
                            canonicalBytesHex: 'aabbccdd',
                        },
                        targetOrderCiphertext: {
                            canonicalBytesHex: '001122',
                        },
                    },
                    evaluationNoiseCertificate: {
                        evaluationNoiseCertHash: 'noise-hash',
                        fullCiphertextByteEstimate: 8,
                        operationCounts: {
                            comparisonInputLevelDropCount: 16,
                            comparisonInputPolynomialCiphertextMultiplicationEstimate: 1060,
                        },
                    },
                    statusLabels: ['TopKEvaluationProposalGenerated'],
                    targetProposalHash: 'proposal-hash',
                    topKEvaluationRecord: {
                        targetCiphertextHash: 'target-hash',
                        topKCiphertextHash: 'top-k-hash',
                    },
                },
            ],
            sharedEncryptedRankBundle: {
                packedRankCiphertext: {
                    canonicalBytesHex: '0011223344',
                },
            },
            topCounts: [1],
        };
        const requestBase = {
            aggregateReadyRecord: {
                aggregateReadyRecordHash: 'ready-hash',
            },
            encryptedAggregateInputs: [{ bridgeEncryption: {} }],
            setupPackage,
        };

        expect(
            canonicalCiphertextByteLength({ canonicalBytesHex: 'abcd' }),
        ).toBe(2);
        expect(canonicalJsonByteLength({ b: 2, a: 1 })).toBeGreaterThan(0);
        expect(summarizeSetupKeyMetrics(setupPackage as never)).toMatchObject({
            acceptedHeSecurityStatus:
                'acceptedForSetupBridgeEvaluatorTargetPending',
            evaluationKeySizeProfileHash: 'profile-hash',
            largestExposedModulusBits: 799,
            rotationKeyCount: 20,
            totalEvaluationKeyByteEstimate: 300,
        });
        expect(
            summarizePublicArtifactMetrics({
                requestBase: requestBase as never,
                sweep: sweep as never,
            }),
        ).toMatchObject({
            sharedPackedRankCiphertextByteLength: 5,
        });
        expect(summarizeEvaluations(sweep as never)).toEqual([
            expect.objectContaining({
                comparisonInputLevelDropCount: 16,
                comparisonInputPolynomialCiphertextMultiplicationEstimate: 1060,
                evaluationNoiseCertHash: 'noise-hash',
                fullCiphertextByteEstimate: 8,
                targetIdCiphertextByteLength: 4,
                targetOrderCiphertextByteLength: 3,
                targetProposalHash: 'proposal-hash',
                topCount: 1,
                topKCiphertextHash: 'top-k-hash',
            }),
        ]);
        expect(
            buildRepresentativeRunBinding({
                requestBase: requestBase as never,
                runtime: {
                    dependencyArtifactHash: 'dependency-hash',
                    kernelHash: 'kernel-hash',
                    sourceFingerprint: 'source-fingerprint',
                },
                topCounts: [1, 10],
            }),
        ).toMatchObject({
            dependencyArtifactHash: 'dependency-hash',
            kernelHash: 'kernel-hash',
            objectType: 'EncryptedAggregateEvaluatorRepresentativeRunBinding',
            objectVersion: 1,
            runnerProfile: 'accepted-input-representative-evaluator-sweep-v1',
            sourceFingerprint: 'source-fingerprint',
            topCounts: [1, 10],
        });
    });
});
