import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

type BgvProfileRejected = {
    readonly ok: false;
    readonly unresolvedReason: 'BGVProfileRejected';
    readonly statusLabels: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: 'BGVProfileRejected';
        readonly reasonCode: string;
        readonly message: string;
    }[];
};

const expectBgvProfileRejected = (
    value: unknown,
    reasonCode?: string,
): BgvProfileRejected => {
    expect(value).toMatchObject({
        ok: false,
        unresolvedReason: 'BGVProfileRejected',
    });
    const rejection = value as BgvProfileRejected;
    expect(rejection.statusLabels).toContain('BGVProfileRejected');
    expect(
        rejection.refusedObjects.some(
            (refusedObject) => refusedObject.code === 'BGVProfileRejected',
        ),
    ).toBe(true);
    if (reasonCode !== undefined) {
        expect(rejection.refusedObjects[0]?.reasonCode).toBe(reasonCode);
    }

    return rejection;
};

const expectBigIntegerReferenceVectors = (value: unknown): void => {
    const fixture = value as {
        readonly vectors: readonly {
            readonly modulus: number;
            readonly samples: readonly {
                readonly left: number;
                readonly right: number;
                readonly addition: number;
                readonly subtraction: number;
                readonly multiplication: number;
            }[];
        }[];
    };

    expect(fixture.vectors).toHaveLength(17);
    for (const vector of fixture.vectors) {
        const modulus = BigInt(vector.modulus);
        for (const sample of vector.samples) {
            const left = BigInt(sample.left);
            const right = BigInt(sample.right);
            expect(BigInt(sample.addition)).toBe((left + right) % modulus);
            expect(BigInt(sample.subtraction)).toBe(
                (left + modulus - right) % modulus,
            );
            expect(BigInt(sample.multiplication)).toBe(
                (left * right) % modulus,
            );
        }
    }
};

const stableBgvDigestVectors = {
    profileDigest:
        'd875931773a704df5f3b5d3dad4ef526bbe671a66465b75c19b2c1190929f86326822cd3ede1233eba2905a4b3c086e0426af5a3f7150f537d76b8349f73b3c2',
    batchEncoderDigest:
        'dd8249296f1b3d5f13ab5229b9ae94b15f10ec68b1a65c1e578d1b4d144fe772d205ea2d715114188e6ffbff414b9af75487987862effdbb4fae42ad6b257fe4',
    batchLayoutBindingDigest:
        '14e66d0972e0a8afc5799add5cea3d09c3ae1f08c6850558d988e47b8f953dc847922c1fba7b372051a565e6b7e1ea5a2f6a864f31dc3b26607c933d9b462e8f',
    encodedAggregateLayoutDigest:
        '2e26e73278c79f9fdf8def4a68601500ddb86882a73ac43ffe25c90a7c0760c18ae72530a80d6f7b8f8aeff3abb31cbd35e7e59cb93edbedb4a4c455a13340e5',
    topKEvaluatorInputLayoutDigest:
        '648022bf9e49d1bfacb52bc4391b6a4dd1729236495de0f27975141fea91e52557b379fa25aecb6a5e07f122bbb3c4166b8028773c168063356be37676960915',
    canonicalCiphertextConventionDigest:
        '71822f4b2f96f38140609db8621bd0c55948dca126eead0c80bffe5e287772af901e2e9dc83f5cce3578781ec595cb846936d804d70a9c084c58c3439017ed31',
    allowedEvaluatorOpsDigest:
        'a9040aab3345f6a38f01a1d279c7cb15a3b845cf36f39a5221c99658c57e113613bd3dd95aaa933157cc46fd6d51a947fd9c45627753b35d5d402fd5c70e1156',
    securityEstimatorInputDigest:
        '4bce752346f1caf9652f456f27645da0a19ff8c9cf5376eef941d9cb4411e22fa4c2f8eaf8707df98b7a48318ef3987ba85e656143e71587d68e16edfdb2f428',
    bigIntegerReferenceVectorRoot:
        '83cb67a77a5c84bf3c3bd98ded3fdb93eef9ee9878df6434c680762d70aceaae6ea94874e3790fcd3caa2d4b1dd124d040b91cadaebf32b8376ef357969d40e6',
    parameterCertificateDigest:
        '1af357fdb1330b3d0c1c41a8eb97ecc150e847f9ce14eedf039e22b74a4b773d8f1d13d87fab48790289baa3bb0f6a7f2e52bfcec8d0a6849aab7d89e98d2ecd',
    encodedPlaintextRoot:
        '59a29e210357f4e860c4c7b44b541956fc2d2ca425eefcb344dbd303420ffa44419674197bf746a0ca4dee937832b925a34ac008194c411c96ad9c6f94285c75',
    encodedPlaintextHash:
        '73a193fc97dad594fe063c04e1b0184d57901441ac520e8355f0e176378c1e1877bc86be1ebf9d873c7007551024cdb08b4af32935e7b56993e233c5a1771b70',
    ciphertextRoot:
        'a5096b8c8f0d14bea7895d29254fb0aa1f50fa81bd8345cafdeb88ec36389ef01933478448e81f3ec0ce39bd07f69cfdc4f0022e223d769a6ab43160f5224622',
    ciphertextHash:
        'f961235b3d1c61e3a4fa70eecb752f940715e7d768a8b7cca0dc8d90649f9b0c813c543f94fa7768a4a3380e57e11397508797d78728c215cb6552aa913c264e',
    baseConversionSourceRoot:
        '2cd073e151a0f86fc2c7b504edb6c2ac39c97cd6a143da4bbb83df400cd25b8d9215c59dc1de6e7d28bf72c80ed5faa9ebe97cff538d07ab048780f1ee0fec7f',
    baseConversionConvertedRoot:
        '9eebccb784a8508da0d21089c3ed0e46c476bbee278785e693dcc0cc3e5e1efa51bb6442bc3da9f533947380bcfd16d701d04b3acc7f1e09fd4bdf77745c62a9',
} as const;

describe('BGV-RNS backend kernel commands', () => {
    it('reports the BGV-RNS profile and operation boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const operationRegistry = kernel.describeBgvOperationRegistry() as {
            readonly forbiddenOperationRejectionFixtures: readonly BgvProfileRejected[];
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
            readonly parameterCertificateDigest: string;
            readonly bgvProfileRejectionFixtures: readonly BgvProfileRejected[];
            readonly conventionDifferenceRegistry: readonly {
                readonly dimension: string;
                readonly swappedConventionRejection: BgvProfileRejected;
            }[];
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
        expect(profile.profileDigest).toBe(
            stableBgvDigestVectors.profileDigest,
        );
        expect(profile.batchEncoderDigest).toBe(
            stableBgvDigestVectors.batchEncoderDigest,
        );
        expect(profile.batchLayoutBindingDigest).toBe(
            stableBgvDigestVectors.batchLayoutBindingDigest,
        );
        expect(profile.encodedAggregateLayoutDigest).toBe(
            stableBgvDigestVectors.encodedAggregateLayoutDigest,
        );
        expect(profile.topKEvaluatorInputLayoutDigest).toBe(
            stableBgvDigestVectors.topKEvaluatorInputLayoutDigest,
        );
        expect(profile.canonicalCiphertextConventionDigest).toBe(
            stableBgvDigestVectors.canonicalCiphertextConventionDigest,
        );
        expect(profile.allowedEvaluatorOpsDigest).toBe(
            stableBgvDigestVectors.allowedEvaluatorOpsDigest,
        );
        expect(profile.securityEstimatorInputDigest).toBe(
            stableBgvDigestVectors.securityEstimatorInputDigest,
        );
        expect(profile.bigIntegerReferenceVectorRoot).toBe(
            stableBgvDigestVectors.bigIntegerReferenceVectorRoot,
        );
        expectBigIntegerReferenceVectors(profile.bigIntegerReferenceVectors);
        expect(profile.batchLayoutBinding).toMatchObject({
            layoutKind: 'EncryptedAggregateInputEncodedScoreLayout-v1',
            coordinateOrder:
                'score-share-then-one-hot-score-buckets-per-option',
            oneHotBucketOrder: 'ascending-score-1-through-10',
            scoreBucketCount: 10,
            scalarOnlyAggregateLayout: false,
        });
        expect(operationRegistry.statusLabels).toContain(
            'GenericFheApiNotExported',
        );
        expect(
            operationRegistry.forbiddenOperationRejectionFixtures.some(
                (fixture) =>
                    fixture.unresolvedReason === 'BGVProfileRejected' &&
                    fixture.refusedObjects.some(
                        (refusedObject) =>
                            refusedObject.reasonCode ===
                            'ForbiddenEvaluatorOperation',
                    ),
            ),
        ).toBe(true);
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
        });
        expect(
            backendReport.parameterCertificate.secretDistributionCertificate
                .status,
        ).toEqual(expect.any(String));
        expect(
            backendReport.parameterCertificate.errorDistributionCertificate
                .status,
        ).toEqual(expect.any(String));
        expect(backendReport.parameterCertificate.estimatorRows).toHaveLength(
            3,
        );
        expect(backendReport.statusLabels).toContain(
            'ParameterCertificateReportEmitted',
        );
        expect(backendReport.parameterCertificateDigest).toBe(
            stableBgvDigestVectors.parameterCertificateDigest,
        );
        expect(
            backendReport.bgvProfileRejectionFixtures.some(
                (fixture) =>
                    fixture.unresolvedReason === 'BGVProfileRejected' &&
                    fixture.refusedObjects.some(
                        (refusedObject) =>
                            refusedObject.reasonCode === 'MissingEstimatorRow',
                    ),
            ),
        ).toBe(true);
        expect(
            backendReport.conventionDifferenceRegistry.some(
                (fixture) =>
                    fixture.dimension === 'coefficientOrdering' &&
                    fixture.swappedConventionRejection.unresolvedReason ===
                        'BGVProfileRejected',
            ),
        ).toBe(true);
        expect(
            backendReport.conventionDifferenceRegistry.some(
                (fixture) => fixture.dimension === 'ciphertextComponentOrder',
            ),
        ).toBe(true);
        expect(backendReport).not.toHaveProperty(
            'parameterCertificateCanonicalBytesHash512',
        );
    });

    it('encodes aggregate-share EncryptedAggregateInput slots and validates roots byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeBgvRnsProfile();
        const encodedResult = kernel.encodeBgvBatchPlaintext({
            slots: [0, 1, 65_536, 17, 99],
            level: 0,
            layoutBinding: profile.batchLayoutBinding,
            includeCanonicalBytesHex: true,
        });

        expect(encodedResult).not.toMatchObject({ ok: false });
        const encoded = encodedResult as Exclude<
            typeof encodedResult,
            BgvProfileRejected
        >;
        expect(encoded.validation.ok).toBe(true);
        expect(encoded.canonicalBytesHex).toMatch(/^[a-f0-9]+$/u);
        expect(encoded.plaintextRoot).toBe(
            stableBgvDigestVectors.encodedPlaintextRoot,
        );
        expect(encoded.canonicalBytesHash512).toBe(
            stableBgvDigestVectors.encodedPlaintextHash,
        );
        expect(encoded.canonicalByteLength).toBe(90_441);
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
        expectBgvProfileRejected(
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: encoded.canonicalBytesHex ?? '',
                expectedPlaintextRoot: '0'.repeat(128),
            }),
            'ProfileMismatch',
        );
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
        expectBgvProfileRejected(
            kernel.validateBgvPlaintextObject({
                canonicalBytesHex: wrongLayoutCanonicalBytesHex,
            }),
            'ProfileMismatch',
        );

        const layoutMutations: readonly Record<string, unknown>[] = [
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                coordinateOrder: 'one-hot-score-buckets-then-score-share',
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                oneHotBucketOrder: 'descending-score-10-through-1',
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                scoreBucketCount: 9,
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                ballotScoreEncodingProfileDigest: '0'.repeat(128),
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                encodedAggregateLayoutDigest: '0'.repeat(128),
            },
            {
                ...(profile.batchLayoutBinding as Record<string, unknown>),
                scalarOnlyAggregateLayout: true,
            },
        ];
        for (const layoutBinding of layoutMutations) {
            expectBgvProfileRejected(
                kernel.encodeBgvBatchPlaintext({
                    slots: [1, 2, 3],
                    level: 0,
                    layoutBinding,
                }),
                'ProfileMismatch',
            );
        }
    });

    it('rejects evaluator operations outside the selected registry', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.validateBgvEvaluatorOperation({
                operation: 'homomorphicAggregateShareAddition',
            }),
        ).toMatchObject({
            ok: true,
            acceptedOperation: 'homomorphicAggregateShareAddition',
        });
        expectBgvProfileRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'scalarDegree360Comparator',
            }),
            'ForbiddenEvaluatorOperation',
        );
        expectBgvProfileRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'uncertifiedScoreBitDerivationOperation',
            }),
            'ForbiddenEvaluatorOperation',
        );
        expectBgvProfileRejected(
            kernel.validateBgvEvaluatorOperation({
                operation: 'adHocEncryptedComparator',
            }),
            'UncertifiedEvaluatorOperation',
        );
    });

    it('validates ciphertext convention fixtures without claiming encryption evidence', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixtureResult = kernel.generateBgvCiphertextConventionFixture({
            leftSlots: [1, 2, 3],
            rightSlots: [4, 5, 6],
            includeCanonicalBytesHex: true,
        });
        expect(fixtureResult).not.toMatchObject({ ok: false });
        const fixture = fixtureResult as Exclude<
            typeof fixtureResult,
            BgvProfileRejected
        >;

        expect(fixture.statusLabels).toContain('NotEncryptionEvidence');
        expect(fixture.ciphertextRoot).toBe(
            stableBgvDigestVectors.ciphertextRoot,
        );
        expect(fixture.canonicalBytesHash512).toBe(
            stableBgvDigestVectors.ciphertextHash,
        );
        expect(fixture.canonicalByteLength).toBe(180_781);
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

    it('keeps base conversion and oracle material inside the BGV boundary', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const baseConversionResult = kernel.generateBgvBaseConversionFixture({
            slots: [7, 8, 9, 65_536],
        });
        expect(baseConversionResult).not.toMatchObject({ ok: false });
        const baseConversion = baseConversionResult as Exclude<
            typeof baseConversionResult,
            BgvProfileRejected
        >;
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
        expect(baseConversion.sourcePlaintextRoot).toBe(
            stableBgvDigestVectors.baseConversionSourceRoot,
        );
        expect(baseConversion.convertedPlaintextRoot).toBe(
            stableBgvDigestVectors.baseConversionConvertedRoot,
        );
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
