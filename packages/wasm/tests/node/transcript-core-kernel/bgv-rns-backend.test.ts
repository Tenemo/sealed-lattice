import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '../../../src/index';

describe('BGV-RNS backend kernel commands', () => {
    it('reports the sealed-lattice M7 profile and operation boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const operationRegistry = kernel.describeBgvOperationRegistry() as {
            readonly statusLabels: readonly string[];
        };
        const backendReport = kernel.generateBgvBackendReport() as {
            readonly parameterCertificate: {
                readonly qDataBits: number;
                readonly qTargetBits: null;
                readonly qpPublicBits: number;
                readonly largestExposedModulusBits: null;
                readonly largestKnownExposedModulusBits: number;
                readonly exposedBasisClass: string;
                readonly publicRlweSamplesByBasis: {
                    readonly target: {
                        readonly modulusBits: null;
                    };
                };
                readonly secretDistributionCertificate: {
                    readonly status: string;
                };
                readonly errorDistributionCertificate: {
                    readonly status: string;
                };
                readonly estimatorRows: readonly unknown[];
                readonly referenceOracleBoundary: {
                    readonly lattigoRuntimeDependency: boolean;
                    readonly oracleVectorsAcceptedAsProtocolEvidence: boolean;
                };
            };
            readonly statusLabels: readonly string[];
        };

        expect(profile.profile).toMatchObject({
            profileId: 'sealed-lattice-bgv-rns-v1',
            polynomialDegree: 32_768,
            plaintextModulus: 65_537,
            dataPrimeBitLength: 47,
            dataLevels: 16,
            extendedLevels: 17,
        });
        expect(profile.profile.dataPrimes).toHaveLength(16);
        expect(profile.profileDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(profile.batchEncoderDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(profile.batchLayoutBindingDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(profile.batchLayoutBinding).toMatchObject({
            layoutKind: 'EncryptedAggregateInputEncodedScoreLayout-v1',
            coordinateOrder:
                'score-share-then-one-hot-score-buckets-per-option',
            oneHotBucketOrder: 'ascending-score-1-through-10',
            scoreBucketCount: 10,
            scalarOnlyAggregateLayout: false,
        });
        expect(profile.statusLabels).toContain('M7ImplementationEvidence');
        expect(profile.statusLabels).toContain(
            'M8PassiveSetupCommandAvailable',
        );
        expect(profile.nonClaims).toContain('M9BridgeProofNotImplemented');
        expect(operationRegistry.statusLabels).toContain(
            'GenericFheApiNotExported',
        );
        expect(
            backendReport.parameterCertificate.referenceOracleBoundary
                .lattigoRuntimeDependency,
        ).toBe(false);
        expect(
            backendReport.parameterCertificate.referenceOracleBoundary
                .oracleVectorsAcceptedAsProtocolEvidence,
        ).toBe(false);
        expect(backendReport.parameterCertificate).toMatchObject({
            qDataBits: 752,
            qTargetBits: null,
            qpPublicBits: 799,
            largestExposedModulusBits: null,
            largestKnownExposedModulusBits: 799,
            exposedBasisClass:
                'data-plus-special-public-estimator-input-target-pending',
            publicRlweSamplesByBasis: {
                target: {
                    modulusBits: null,
                },
            },
            secretDistributionCertificate: {
                status: 'available-in-M8-passive-setup-package',
            },
            errorDistributionCertificate: {
                status: 'available-in-M8-passive-setup-package',
            },
        });
        expect(backendReport.parameterCertificate.estimatorRows).toHaveLength(
            3,
        );
        expect(backendReport.statusLabels).toContain(
            'ParameterCertificateReportEmitted',
        );
        expect(backendReport).not.toHaveProperty(
            'parameterCertificateCanonicalBytesHash512',
        );
    });

    it('encodes aggregate-share EncryptedAggregateInput slots and validates roots byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const encoded = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: profile.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(encoded.validation.ok).toBe(true);
        expect(encoded.canonicalBytesHex).toMatch(/^[a-f0-9]+$/u);
        expect(encoded.plaintextRoot).toMatch(/^[a-f0-9]{128}$/u);
        expect(encoded.batchLayoutBindingDigest).toBe(
            profile.batchLayoutBindingDigest,
        );
        expect(encoded.statusLabels).toContain(
            'EncryptedAggregateInputLayoutBound',
        );
        expect(encoded.sampledSlots).toEqual(
            expect.arrayContaining([
                { position: 0, value: 0 },
                { position: 1, value: 1 },
                { position: 2, value: 65_536 },
            ]),
        );

        const validated = kernel.validateBgvPlaintextObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
            expectedPlaintextRoot: encoded.plaintextRoot,
        });
        const analyzed = kernel.analyzeBgvCanonicalObject({
            canonicalBytesHex: encoded.canonicalBytesHex ?? '',
        }) as {
            readonly objectKind: string;
            readonly coefficientCount: number;
        };

        expect(validated).toMatchObject({
            ok: true,
            objectKind: 'plaintext',
            plaintextRoot: encoded.plaintextRoot,
            canonicalBytesHash512: encoded.canonicalBytesHash512,
        });
        expect(analyzed).toMatchObject({
            objectKind: 'plaintext',
            coefficientCount: 32_768,
        });
        expect(() =>
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: encoded.canonicalBytesHex ?? '',
                expectedPlaintextRoot: '0'.repeat(128),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        const layoutDigestHex = Buffer.from(
            profile.encryptedAggregateInputLayoutDigest,
            'utf8',
        ).toString('hex');
        const wrongLayoutCanonicalBytesHex = (
            encoded.canonicalBytesHex ?? ''
        ).replace(
            layoutDigestHex,
            Buffer.from('0'.repeat(128), 'utf8').toString('hex'),
        );
        expect(() =>
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: wrongLayoutCanonicalBytesHex,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        const wrongLayoutBinding = {
            ...(profile.batchLayoutBinding as Record<string, unknown>),
            scalarOnlyAggregateLayout: true,
        };
        expect(() =>
            kernel.encodeBgvBatchPlaintext({
                slots: [1, 2, 3],
                level: 0,
                layoutBinding: wrongLayoutBinding,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('validates ciphertext convention fixtures without claiming encryption evidence', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixture = kernel.generateBgvCiphertextConventionFixture({
            leftSlots: [1, 2, 3],
            rightSlots: [4, 5, 6],
            includeCanonicalBytesHex: true,
        });

        expect(fixture.statusLabels).toContain('NotEncryptionEvidence');
        expect(fixture.validation).toMatchObject({
            ok: true,
            objectKind: 'ciphertext',
            ciphertextRoot: fixture.ciphertextRoot,
        });
        expect(
            kernel.validateBgvCiphertextObject({
                canonicalBytesHex: fixture.canonicalBytesHex ?? '',
                expectedCiphertextRoot: fixture.ciphertextRoot,
            }),
        ).toMatchObject({
            ok: true,
            objectKind: 'ciphertext',
            ciphertextRoot: fixture.ciphertextRoot,
        });
    });

    it('keeps base conversion and oracle material inside the M7 boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const baseConversion = kernel.generateBgvBaseConversionFixture({
            slots: [7, 8, 9, 65_536],
        });
        const oracleRejection = kernel.rejectBgvReferenceOracleArtifact({
            artifact: {
                artifactKind: 'lattigo-development-oracle-vector',
                protocolEvidence: false,
            },
        });

        expect(baseConversion).toMatchObject({
            convertedBasisId: 'sealed-lattice-bgv-rns-extended-basis-v1',
            convertedModulusCount: 2,
        });
        expect(baseConversion.statusLabels).toContain(
            'GenericKeySwitchSurfaceNotExported',
        );
        expect(oracleRejection).toMatchObject({
            ok: false,
            acceptedAsProtocolEvidence: false,
        });
        expect(oracleRejection.statusLabels).toEqual(
            expect.arrayContaining([
                'ReferenceOracleRejected',
                'LattigoSerializationRejected',
                'RuntimeOracleDependencyRejected',
            ]),
        );
    });
});
