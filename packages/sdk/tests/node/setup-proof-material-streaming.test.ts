import { beforeEach, describe, expect, it, vi } from 'vitest';

type JsonRecord = Record<string, unknown>;

const proofHash =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const alternateProofHash =
    'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
const setupProofProfileId = 'SealedLattice-SetupProof-v1';

type SetupProofMaterialTransportFieldName =
    | 'transportedSameSecretProofMaterial'
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportCase = Readonly<{
    readonly fieldName: SetupProofMaterialTransportFieldName;
    readonly materialSetObjectType:
        | 'SetupTransportedSameSecretProofMaterialSet'
        | 'SetupTransportedPublicKeyShareProofMaterialSet'
        | 'SetupTransportedEvaluationKeyShareProofMaterialSet';
    readonly materialObjectType:
        | 'SetupTransportedSameSecretProofMaterial'
        | 'SetupTransportedPublicKeyShareProofMaterial'
        | 'SetupTransportedEvaluationKeyShareProofMaterial';
    readonly proofFamily:
        | 'same-secret-linkage-anchor'
        | 'public-key-share'
        | 'trustee-evaluation-key';
}>;

const setupProofMaterialTransportCases = [
    {
        fieldName: 'transportedSameSecretProofMaterial',
        materialSetObjectType: 'SetupTransportedSameSecretProofMaterialSet',
        materialObjectType: 'SetupTransportedSameSecretProofMaterial',
        proofFamily: 'same-secret-linkage-anchor',
    },
    {
        fieldName: 'transportedPublicKeyShareProofMaterial',
        materialSetObjectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedPublicKeyShareProofMaterial',
        proofFamily: 'public-key-share',
    },
    {
        fieldName: 'transportedEvaluationKeyShareProofMaterial',
        materialSetObjectType:
            'SetupTransportedEvaluationKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedEvaluationKeyShareProofMaterial',
        proofFamily: 'trustee-evaluation-key',
    },
] as const satisfies readonly SetupProofMaterialTransportCase[];

let mockKernel: {
    readonly beginThresholdShareCommitmentsFromTransportStream: ReturnType<
        typeof vi.fn
    >;
    readonly absorbThresholdShareCommitmentsFromTransportStreamChunk: ReturnType<
        typeof vi.fn
    >;
    readonly finishThresholdShareCommitmentsFromTransportStream: ReturnType<
        typeof vi.fn
    >;
    readonly releaseVerifiedTransportedVssMaterial: ReturnType<typeof vi.fn>;
    readonly beginSetupProofMaterialTransportStream: ReturnType<typeof vi.fn>;
    readonly absorbSetupProofMaterialTransportStreamChunk: ReturnType<
        typeof vi.fn
    >;
    readonly finishSetupProofMaterialTransportStream: ReturnType<typeof vi.fn>;
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
};

vi.mock('../../dist/kernel.js', () => ({
    loadTranscriptCoreKernel: () => Promise.resolve(mockKernel),
}));

const publicPackage = await import('../../dist/index.js');

let streamedProofMaterialReferences: Map<string, JsonRecord>;
let streamedVssMaterialReferences: Map<string, JsonRecord>;

type VerifySetupPackageInput = Parameters<
    typeof publicPackage.verifySetupPackage
>[0];
type TransportedSameSecretProofMaterialSet = NonNullable<
    VerifySetupPackageInput['transportedSameSecretProofMaterial']
>;
type TransportedPublicKeyShareProofMaterialSet = NonNullable<
    VerifySetupPackageInput['transportedPublicKeyShareProofMaterial']
>;
type TransportedEvaluationKeyShareProofMaterialSet = NonNullable<
    VerifySetupPackageInput['transportedEvaluationKeyShareProofMaterial']
>;

const transportedSetupProofMaterialSet = (
    transportCase: SetupProofMaterialTransportCase,
) =>
    ({
        objectType: transportCase.materialSetObjectType,
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: transportCase.proofFamily,
        proofMaterials: [
            {
                objectType: transportCase.materialObjectType,
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: proofHash,
                chunkSizeBytes: 1_048_576,
                chunkCount: 1,
                totalByteLength: 2,
                fullObjectHash: proofHash,
                chunkHashes: [proofHash],
                chunkRoot: proofHash,
                chunks: [
                    {
                        chunkIndex: 0,
                        bytesHex: 'abcd',
                    },
                ],
            },
        ],
    }) as const;

const transportedSameSecretProofMaterialSet =
    (): TransportedSameSecretProofMaterialSet =>
        transportedSetupProofMaterialSet(
            setupProofMaterialTransportCases[0],
        ) as TransportedSameSecretProofMaterialSet;

const transportedPublicKeyShareProofMaterialSet =
    (): TransportedPublicKeyShareProofMaterialSet =>
        transportedSetupProofMaterialSet(
            setupProofMaterialTransportCases[1],
        ) as TransportedPublicKeyShareProofMaterialSet;

const transportedEvaluationKeyShareProofMaterialSet =
    (): TransportedEvaluationKeyShareProofMaterialSet =>
        transportedSetupProofMaterialSet(
            setupProofMaterialTransportCases[2],
        ) as TransportedEvaluationKeyShareProofMaterialSet;

const verifiedSetupProofMaterials = (
    transportCase: SetupProofMaterialTransportCase,
    proofFullObjectHash = proofHash,
) =>
    ({
        objectType: 'VerifiedSetupProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofMaterials: [
            {
                objectType: 'VerifiedSetupProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                verificationId: 'caller-supplied-handle',
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: proofHash,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofChunkSizeBytes: 1_048_576,
                proofChunkCount: 1,
                proofTotalByteLength: 2,
                proofFullObjectHash,
                proofChunkRoot: proofHash,
                proofChunkHashes: [proofHash],
            },
        ],
    }) as const;

describe('setup proof material streaming in the public package', () => {
    beforeEach(() => {
        streamedProofMaterialReferences = new Map();
        streamedVssMaterialReferences = new Map();
        mockKernel = {
            beginThresholdShareCommitmentsFromTransportStream: vi.fn(
                (input: {
                    readonly derivationId: string;
                    readonly transportedVssCoefficientCommitmentMaterial: JsonRecord;
                }) => {
                    streamedVssMaterialReferences.set(
                        input.derivationId,
                        input.transportedVssCoefficientCommitmentMaterial,
                    );

                    return {
                        ok: true,
                        operation:
                            'beginThresholdShareCommitmentsFromTransportStream',
                    };
                },
            ),
            absorbThresholdShareCommitmentsFromTransportStreamChunk: vi.fn(
                () => ({
                    ok: true,
                    operation:
                        'absorbThresholdShareCommitmentsFromTransportStreamChunk',
                }),
            ),
            finishThresholdShareCommitmentsFromTransportStream: vi.fn(
                (input: { readonly derivationId: string }) => {
                    const transportedMaterial =
                        streamedVssMaterialReferences.get(input.derivationId);

                    return {
                        ok: true,
                        operation:
                            'finishThresholdShareCommitmentsFromTransportStream',
                        derivationId: input.derivationId,
                        verifiedVssCoefficientCommitmentMaterial: {
                            objectType:
                                'VerifiedVssCoefficientCommitmentMaterial',
                            objectVersion: 1,
                            setupProfileId: 'CollectiveBgvSetup-v1',
                            verificationId: input.derivationId,
                            materialBinaryFormat:
                                transportedMaterial?.binaryFormat,
                            publicMatrixSeedHash: proofHash,
                            vssCoefficientCommitmentRoot: alternateProofHash,
                            vssCoefficientCommitmentMaterialRoot:
                                transportedMaterial?.fullObjectHash,
                            thresholdShareCommitmentRoot: proofHash,
                            transportProfileId:
                                'sealed-lattice-setup-binary-chunked-transport-v1',
                            transportChunkSizeBytes:
                                transportedMaterial?.chunkSizeBytes,
                            transportChunkCount:
                                transportedMaterial?.chunkCount,
                            transportTotalByteLength:
                                transportedMaterial?.totalByteLength,
                            transportFullObjectHash:
                                transportedMaterial?.fullObjectHash,
                            transportChunkRoot: transportedMaterial?.chunkRoot,
                            transportChunkHashes:
                                transportedMaterial?.chunkHashes,
                        },
                    };
                },
            ),
            releaseVerifiedTransportedVssMaterial: vi.fn(() => ({
                ok: true,
                operation: 'releaseVerifiedTransportedVssMaterial',
                released: true,
            })),
            beginSetupProofMaterialTransportStream: vi.fn(
                (input: {
                    readonly verificationId: string;
                    readonly transportedSetupProofMaterial: JsonRecord;
                }) => {
                    streamedProofMaterialReferences.set(
                        input.verificationId,
                        input.transportedSetupProofMaterial,
                    );

                    return {
                        ok: true,
                        operation: 'beginSetupProofMaterialTransportStream',
                    };
                },
            ),
            absorbSetupProofMaterialTransportStreamChunk: vi.fn(() => ({
                ok: true,
                operation: 'absorbSetupProofMaterialTransportStreamChunk',
            })),
            finishSetupProofMaterialTransportStream: vi.fn(
                (input: { readonly verificationId: string }) => ({
                    ...(() => {
                        const proofMaterial =
                            streamedProofMaterialReferences.get(
                                input.verificationId,
                            );

                        return {
                            ok: true,
                            operation:
                                'finishSetupProofMaterialTransportStream',
                            verifiedSetupProofMaterial: {
                                objectType: 'VerifiedSetupProofMaterial',
                                objectVersion: 1,
                                setupProfileId: 'CollectiveBgvSetup-v1',
                                setupProofProfileId,
                                verificationId: input.verificationId,
                                proofFamily: proofMaterial?.proofFamily,
                                proofMaterialRoot:
                                    proofMaterial?.proofMaterialRoot,
                                proofBytesEncoding:
                                    'binary-chunked-proof-bytes',
                                proofChunkSizeBytes:
                                    proofMaterial?.chunkSizeBytes,
                                proofChunkCount: proofMaterial?.chunkCount,
                                proofTotalByteLength:
                                    proofMaterial?.totalByteLength,
                                proofFullObjectHash:
                                    proofMaterial?.fullObjectHash,
                                proofChunkRoot: proofMaterial?.chunkRoot,
                                proofChunkHashes: proofMaterial?.chunkHashes,
                            },
                        };
                    })(),
                }),
            ),
            verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => ({
                ok: false,
                operation: 'verifyCollectiveBgvSetupPackage',
                verifierStatus: 'outsideProfile',
                observedInput: input,
            })),
        };
    });

    it('preserves accepted setup handoff returned by the kernel verifier', async () => {
        const acceptedSetupHandoffRoot = 'a'.repeat(128);
        const acceptedSetupHandoff = {
            objectType: 'CollectiveBgvAcceptedSetupHandoff',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            acceptedSetupHandoffRoot,
            directBallotEncryption: {
                collectivePublicKeyRoot: proofHash,
            },
            publicAggregation: {
                aggregateCiphertextProfileRoot: proofHash,
            },
            boundedEvaluatorReplay: {
                evaluatorProfileRoot: proofHash,
            },
            futureTargetDecryptionBoundary: {
                qTargetState: 'downstream-null',
            },
            certificateRoots: {
                heSecurityCertificateHash: proofHash,
            },
        };
        mockKernel = {
            ...mockKernel,
            verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => ({
                ok: true,
                operation: 'verifyCollectiveBgvSetupPackage',
                setupProfileId: 'CollectiveBgvSetup-v1',
                verifierStatus: 'accepted',
                currentPhase: 'setupPackageVerification',
                acceptedHashes: [acceptedSetupHandoffRoot],
                missingObjects: [],
                refusedObjects: [],
                acceptedSetupHandoff,
                observedInput: input,
            })),
        };

        const result = await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
            },
        });

        expect(result).toMatchObject({
            ok: true,
            operation: 'verifyCollectiveBgvSetupPackage',
            verifierStatus: 'accepted',
            acceptedSetupHandoff,
        });
        expect(result.acceptedSetupHandoff?.acceptedSetupHandoffRoot).toBe(
            acceptedSetupHandoffRoot,
        );
        expect(mockKernel.verifyCollectiveBgvSetup).toHaveBeenCalledWith({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
            },
        });
    });

    it.each(setupProofMaterialTransportCases)(
        'streams $proofFamily proof chunks and verifies with compact handles',
        async (transportCase) => {
            await publicPackage.verifySetupPackage({
                setupPackage: {
                    objectType: 'SetupPackage',
                    objectVersion: 1,
                },
                [transportCase.fieldName]:
                    transportedSetupProofMaterialSet(transportCase),
            });

            expect(
                mockKernel.beginSetupProofMaterialTransportStream,
            ).toHaveBeenCalledOnce();
            const beginInput = mockKernel.beginSetupProofMaterialTransportStream
                .mock.calls[0]?.[0] as JsonRecord | undefined;
            expect(beginInput?.transportedSetupProofMaterial).toMatchObject({
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: proofHash,
            });
            expect(
                beginInput?.transportedSetupProofMaterial,
            ).not.toHaveProperty('chunks');
            expect(
                mockKernel.absorbSetupProofMaterialTransportStreamChunk,
            ).toHaveBeenCalledWith(
                expect.objectContaining({
                    chunkIndex: 0,
                    bytesHex: 'abcd',
                }),
            );

            const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
                .calls[0]?.[0] as JsonRecord | undefined;
            const finalMaterialSet = finalVerifyInput?.[
                transportCase.fieldName
            ] as
                | Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>
                | undefined;
            expect(finalMaterialSet?.proofMaterials[0]).toMatchObject({
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: proofHash,
            });
            expect(finalMaterialSet?.proofMaterials[0]).not.toHaveProperty(
                'chunks',
            );
            expect(finalVerifyInput?.verifiedSetupProofMaterials).toMatchObject(
                {
                    objectType: 'VerifiedSetupProofMaterialSet',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofMaterials: [
                        expect.objectContaining({
                            objectType: 'VerifiedSetupProofMaterial',
                            proofFamily: transportCase.proofFamily,
                            proofMaterialRoot: proofHash,
                        }),
                    ],
                },
            );
        },
    );

    it('streams all setup proof material fields before final verification', async () => {
        await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
            },
            transportedSameSecretProofMaterial:
                transportedSameSecretProofMaterialSet(),
            transportedPublicKeyShareProofMaterial:
                transportedPublicKeyShareProofMaterialSet(),
            transportedEvaluationKeyShareProofMaterial:
                transportedEvaluationKeyShareProofMaterialSet(),
        });

        expect(
            mockKernel.beginSetupProofMaterialTransportStream,
        ).toHaveBeenCalledTimes(setupProofMaterialTransportCases.length);
        expect(
            mockKernel.absorbSetupProofMaterialTransportStreamChunk,
        ).toHaveBeenCalledTimes(setupProofMaterialTransportCases.length);

        const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord | undefined;
        for (const transportCase of setupProofMaterialTransportCases) {
            const finalMaterialSet = finalVerifyInput?.[
                transportCase.fieldName
            ] as
                | Readonly<{
                      readonly proofMaterials: readonly JsonRecord[];
                  }>
                | undefined;
            expect(finalMaterialSet?.proofMaterials[0]).toMatchObject({
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: proofHash,
            });
            expect(finalMaterialSet?.proofMaterials[0]).not.toHaveProperty(
                'chunks',
            );
        }
        const expectedVerifiedProofMaterials =
            setupProofMaterialTransportCases.map((transportCase): unknown => {
                const expectedVerifiedProofMaterial: unknown =
                    expect.objectContaining({
                        objectType: 'VerifiedSetupProofMaterial',
                        proofFamily: transportCase.proofFamily,
                        proofMaterialRoot: proofHash,
                    });

                return expectedVerifiedProofMaterial;
            });
        expect(finalVerifyInput?.verifiedSetupProofMaterials).toMatchObject({
            objectType: 'VerifiedSetupProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofMaterials: expectedVerifiedProofMaterials,
        });
    });

    it('streams VSS material before final setup verification and ignores caller-supplied VSS handles', async () => {
        const sourceTrusteeRecords = [
            {
                sourceTrusteeRosterPosition: 0,
                sourceTrusteeCoefficientCommitmentRoot: proofHash,
            },
        ];
        const transportedVssCoefficientCommitmentMaterial = {
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            binaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            chunkSizeBytes: 1_048_576,
            chunkCount: 2,
            totalByteLength: 4,
            fullObjectHash: proofHash,
            chunkHashes: [proofHash, alternateProofHash],
            chunkRoot: alternateProofHash,
            chunks: [
                {
                    chunkIndex: 0,
                    bytesHex: '0102',
                },
                {
                    chunkIndex: 1,
                    bytesHex: '0304',
                },
            ],
        } as const;
        const callerSuppliedVssHandle = {
            objectType: 'VerifiedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            verificationId: 'caller-supplied-vss-handle',
            vssCoefficientCommitmentMaterialRoot: alternateProofHash,
        } as const;

        await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
                objectVersion: 1,
                setupContext: {
                    manifestHash: proofHash,
                    rosterHash: alternateProofHash,
                },
                commonRandomness: {
                    publicMatrixSeedHash: proofHash,
                },
                vssCoefficientCommitments: {
                    vssCoefficientCommitmentRoot: alternateProofHash,
                    sourceTrusteeRecords,
                },
            },
            transportedVssCoefficientCommitmentMaterial,
            verifiedVssCoefficientCommitmentMaterial: callerSuppliedVssHandle,
        });

        expect(
            mockKernel.beginThresholdShareCommitmentsFromTransportStream,
        ).toHaveBeenCalledWith(
            expect.objectContaining({
                publicMatrixSeedHash: proofHash,
                transportedVssCoefficientCommitmentMaterial:
                    expect.objectContaining({
                        objectType:
                            'SetupTransportedVssCoefficientCommitmentMaterial',
                        fullObjectHash: proofHash,
                    }),
            }),
        );
        const beginInput = mockKernel
            .beginThresholdShareCommitmentsFromTransportStream.mock
            .calls[0]?.[0] as JsonRecord | undefined;
        expect(
            beginInput?.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');
        expect(
            mockKernel.absorbThresholdShareCommitmentsFromTransportStreamChunk,
        ).toHaveBeenCalledTimes(2);
        expect(
            mockKernel.absorbThresholdShareCommitmentsFromTransportStreamChunk,
        ).toHaveBeenNthCalledWith(
            1,
            expect.objectContaining({
                chunkIndex: 0,
                bytesHex: '0102',
            }),
        );
        expect(
            mockKernel.finishThresholdShareCommitmentsFromTransportStream,
        ).toHaveBeenCalledWith(
            expect.objectContaining({
                vssCoefficientCommitmentRoot: alternateProofHash,
                sourceTrusteeCoefficientCommitmentRecords: sourceTrusteeRecords,
            }),
        );

        const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord | undefined;
        const finalVerifiedVssMaterial =
            finalVerifyInput?.verifiedVssCoefficientCommitmentMaterial as
                | JsonRecord
                | undefined;
        expect(
            finalVerifyInput?.transportedVssCoefficientCommitmentMaterial,
        ).toMatchObject({
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            fullObjectHash: proofHash,
        });
        expect(
            finalVerifyInput?.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');
        expect(
            finalVerifyInput?.verifiedVssCoefficientCommitmentMaterial,
        ).toMatchObject({
            objectType: 'VerifiedVssCoefficientCommitmentMaterial',
            verificationId: expect.stringMatching(/^sdk-vss-material-/u),
            vssCoefficientCommitmentMaterialRoot: proofHash,
        });
        expect(
            finalVerifyInput?.verifiedVssCoefficientCommitmentMaterial,
        ).not.toBe(callerSuppliedVssHandle);
        expect(
            mockKernel.releaseVerifiedTransportedVssMaterial,
        ).toHaveBeenCalledWith(
            expect.objectContaining({
                verificationId: finalVerifiedVssMaterial?.verificationId,
            }),
        );
        expect(
            mockKernel.verifyCollectiveBgvSetup.mock.invocationCallOrder[0],
        ).toBeLessThan(
            mockKernel.releaseVerifiedTransportedVssMaterial.mock
                .invocationCallOrder[0] ?? 0,
        );
    });

    it.each(setupProofMaterialTransportCases)(
        'ignores caller-supplied $proofFamily proof handles and streams chunks',
        async (transportCase) => {
            const suppliedHandles = verifiedSetupProofMaterials(
                transportCase,
                alternateProofHash,
            );
            const inputWithCallerProofHandles = {
                setupPackage: {
                    objectType: 'SetupPackage',
                    objectVersion: 1,
                },
                [transportCase.fieldName]:
                    transportedSetupProofMaterialSet(transportCase),
                verifiedSetupProofMaterials: suppliedHandles,
            } as Parameters<typeof publicPackage.verifySetupPackage>[0] &
                Readonly<{
                    readonly verifiedSetupProofMaterials: typeof suppliedHandles;
                }>;

            await publicPackage.verifySetupPackage(inputWithCallerProofHandles);

            expect(
                mockKernel.beginSetupProofMaterialTransportStream,
            ).toHaveBeenCalledOnce();
            expect(
                mockKernel.absorbSetupProofMaterialTransportStreamChunk,
            ).toHaveBeenCalledWith(
                expect.objectContaining({
                    chunkIndex: 0,
                    bytesHex: 'abcd',
                }),
            );
            expect(
                mockKernel.finishSetupProofMaterialTransportStream,
            ).toHaveBeenCalledOnce();

            const finalVerifyInput = mockKernel.verifyCollectiveBgvSetup.mock
                .calls[0]?.[0] as JsonRecord | undefined;
            const finalMaterialSet = finalVerifyInput?.[
                transportCase.fieldName
            ] as
                | Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>
                | undefined;
            expect(finalMaterialSet?.proofMaterials[0]).not.toHaveProperty(
                'chunks',
            );
            expect(finalVerifyInput?.verifiedSetupProofMaterials).not.toBe(
                suppliedHandles,
            );
            expect(finalVerifyInput?.verifiedSetupProofMaterials).toMatchObject(
                {
                    proofMaterials: [
                        expect.objectContaining({
                            proofFamily: transportCase.proofFamily,
                            proofMaterialRoot: proofHash,
                            proofFullObjectHash: proofHash,
                        }),
                    ],
                },
            );
        },
    );
});
