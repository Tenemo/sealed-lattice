import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { verifySetupPackage } from '#packages/sdk/src/index.js';

type JsonRecord = Record<string, unknown>;

const proofHash =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const alternateProofHash =
    'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
const expectedManifestHash = '1'.repeat(128);
type SetupProofMaterialTransportFieldName =
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportCase = Readonly<{
    readonly fieldName: SetupProofMaterialTransportFieldName;
    readonly materialSetObjectType:
        | 'SetupTransportedPublicKeyShareProofMaterialSet'
        | 'SetupTransportedVssShareLinkageProofMaterialSet'
        | 'SetupTransportedSameSecretBridgeProofMaterialSet'
        | 'SetupTransportedEvaluationKeyShareProofMaterialSet';
    readonly materialObjectType:
        | 'SetupTransportedPublicKeyShareProofMaterial'
        | 'SetupTransportedVssShareLinkageProofMaterial'
        | 'SetupTransportedSameSecretBridgeProofMaterial'
        | 'SetupTransportedEvaluationKeyShareProofMaterial';
    readonly proofFamily:
        | 'public-key-share'
        | 'vss-share-linkage'
        | 'same-secret-bridge'
        | 'trustee-evaluation-key';
}>;

const setupProofMaterialTransportCases = [
    {
        fieldName: 'transportedPublicKeyShareProofMaterial',
        materialSetObjectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedPublicKeyShareProofMaterial',
        proofFamily: 'public-key-share',
    },
    {
        fieldName: 'transportedVssShareLinkageProofMaterial',
        materialSetObjectType:
            'SetupTransportedVssShareLinkageProofMaterialSet',
        materialObjectType: 'SetupTransportedVssShareLinkageProofMaterial',
        proofFamily: 'vss-share-linkage',
    },
    {
        fieldName: 'transportedSameSecretBridgeProofMaterial',
        materialSetObjectType:
            'SetupTransportedSameSecretBridgeProofMaterialSet',
        materialObjectType: 'SetupTransportedSameSecretBridgeProofMaterial',
        proofFamily: 'same-secret-bridge',
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

const publicPackage = (await import('../../dist/index.js')) as Readonly<{
    readonly verifySetupPackage: typeof verifySetupPackage;
}>;
const expectedRosterHash = '2'.repeat(128);
const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;

let streamedProofMaterialReferences: Map<string, JsonRecord>;

type VerifySetupPackageInput = Parameters<
    typeof publicPackage.verifySetupPackage
>[0];

const transportedSetupProofMaterialSet = (
    transportCase: SetupProofMaterialTransportCase,
) =>
    ({
        objectType: transportCase.materialSetObjectType,
        proofFamily: transportCase.proofFamily,
        proofMaterials: [
            {
                objectType: transportCase.materialObjectType,
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

const verifiedSetupProofMaterials = (
    transportCase: SetupProofMaterialTransportCase,
    proofFullObjectHash = proofHash,
) =>
    ({
        objectType: 'VerifiedSetupProofMaterialSet',
        proofMaterials: [
            {
                objectType: 'VerifiedSetupProofMaterial',
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
        mockKernel = {
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
                        operation: 'beginSetupProofMaterialTransportStream',
                    };
                },
            ),
            absorbSetupProofMaterialTransportStreamChunk: vi.fn(() => ({
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
                            operation:
                                'finishSetupProofMaterialTransportStream',
                            verifiedSetupProofMaterial: {
                                objectType: 'VerifiedSetupProofMaterial',
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
                isValid: false,
                operation: 'verifyCollectiveBgvSetupPackage',
                observedInput: input,
            })),
        };
    });

    it('preserves accepted setup handoff returned by the kernel verifier', async () => {
        const acceptedSetupHandoffRoot = 'a'.repeat(128);
        const acceptedSetupHandoff = {
            objectType: 'CollectiveBgvAcceptedSetupHandoff',
            acceptedSetupHandoffRoot,
            directBallotEncryption: {
                collectivePublicKeyRoot: proofHash,
            },
            publicAggregation: {
                aggregateCiphertextParametersRoot: proofHash,
            },
            boundedEvaluatorReplay: {
                evaluatorParametersRoot: proofHash,
            },
            futureTargetDecryptionBoundary: {
                qTargetState: 'downstream-null',
            },
            certificateRoots: {
                setupTransportCertificateHash: proofHash,
            },
        };
        mockKernel = {
            ...mockKernel,
            verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => ({
                isValid: true,
                operation: 'verifyCollectiveBgvSetupPackage',
                currentPhase: 'setupPackageVerification',
                missingObjects: [],
                refusedObjects: [],
                acceptedSetupHandoff,
                observedInput: input,
            })),
        };

        const result = await publicPackage.verifySetupPackage({
            setupPackage: {
                objectType: 'SetupPackage',
            },
            ...setupVerificationBindings,
        });

        expect(result).toMatchObject({
            isValid: true,
            operation: 'verifyCollectiveBgvSetupPackage',
            acceptedSetupHandoff,
        });
        expect(result.acceptedSetupHandoff?.acceptedSetupHandoffRoot).toBe(
            acceptedSetupHandoffRoot,
        );
        expect(mockKernel.verifyCollectiveBgvSetup).toHaveBeenCalledWith({
            setupPackage: {
                objectType: 'SetupPackage',
            },
            ...setupVerificationBindings,
        });
    });

    it('requires external manifest and roster hashes before calling the kernel verifier', async () => {
        const inputWithoutExternalBindings = {
            setupPackage: {
                objectType: 'SetupPackage',
            },
        } as unknown as VerifySetupPackageInput;

        await expect(
            publicPackage.verifySetupPackage(inputWithoutExternalBindings),
        ).rejects.toThrow(/expectedManifestHash/u);
        expect(mockKernel.verifyCollectiveBgvSetup).not.toHaveBeenCalled();
    });

    it.each(setupProofMaterialTransportCases)(
        'streams $proofFamily proof chunks and verifies with streamed handles',
        async (transportCase) => {
            await publicPackage.verifySetupPackage({
                setupPackage: {
                    objectType: 'SetupPackage',
                },
                ...setupVerificationBindings,
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
            expect(finalVerifyInput?.verifiedSetupProofMaterials).toMatchObject(
                {
                    objectType: 'VerifiedSetupProofMaterialSet',
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
            },
            ...setupVerificationBindings,
            ...Object.fromEntries(
                setupProofMaterialTransportCases.map((transportCase) => [
                    transportCase.fieldName,
                    transportedSetupProofMaterialSet(transportCase),
                ]),
            ),
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
            proofMaterials: expectedVerifiedProofMaterials,
        });
    });

    it.each(setupProofMaterialTransportCases)(
        'forwards caller-supplied $proofFamily proof handles without re-streaming chunks',
        async (transportCase) => {
            const suppliedHandles = verifiedSetupProofMaterials(
                transportCase,
                alternateProofHash,
            );

            await publicPackage.verifySetupPackage({
                setupPackage: {
                    objectType: 'SetupPackage',
                },
                ...setupVerificationBindings,
                [transportCase.fieldName]:
                    transportedSetupProofMaterialSet(transportCase),
                verifiedSetupProofMaterials: suppliedHandles,
            });

            expect(
                mockKernel.beginSetupProofMaterialTransportStream,
            ).not.toHaveBeenCalled();
            expect(
                mockKernel.absorbSetupProofMaterialTransportStreamChunk,
            ).not.toHaveBeenCalled();
            expect(
                mockKernel.finishSetupProofMaterialTransportStream,
            ).not.toHaveBeenCalled();

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
            expect(finalVerifyInput?.verifiedSetupProofMaterials).toBe(
                suppliedHandles,
            );
        },
    );
});
