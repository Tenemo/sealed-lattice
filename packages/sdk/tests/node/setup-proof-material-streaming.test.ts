import { beforeEach, describe, expect, it, vi } from 'vitest';

import type {
    verifyPrivateVssShare,
    verifySetupPackage,
} from '#packages/sdk/src/index.js';

type JsonRecord = Record<string, unknown>;

const proofMaterialRoot = '1'.repeat(128);
const alternateProofMaterialRoot = '2'.repeat(128);
const expectedManifestHash = '3'.repeat(128);
const expectedRosterHash = '4'.repeat(128);

const mockedBgvCanonicalStreamStage = vi.hoisted(() => vi.fn());

vi.mock(
    '../../dist/internal/transcript-core-bridge.js',
    async (importOriginal) => {
        const originalModule =
            await importOriginal<
                typeof import('../../dist/internal/transcript-core-bridge.js')
            >();

        return {
            ...originalModule,
            openBgvCanonicalStreamRuntime: () => ({
                stage: mockedBgvCanonicalStreamStage,
            }),
        };
    },
);

let mockKernel: {
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
    readonly verifyPrivateVssShareEnvelope: ReturnType<typeof vi.fn>;
};

vi.mock('../../dist/kernel.js', () => ({
    loadTranscriptCoreKernel: () => Promise.resolve(mockKernel),
}));

const publicPackage = (await import('../../dist/index.js')) as Readonly<{
    readonly verifyPrivateVssShare: typeof verifyPrivateVssShare;
    readonly verifySetupPackage: typeof verifySetupPackage;
}>;

type SetupProofMaterialTransportFieldName =
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportCase = Readonly<{
    readonly fieldName: SetupProofMaterialTransportFieldName;
    readonly materialSetObjectType: string;
    readonly materialObjectType: string;
    readonly proofFamily: string;
    readonly runtimeFamily: number;
}>;

const setupProofMaterialTransportCases = [
    {
        fieldName: 'transportedPublicKeyShareProofMaterial',
        materialSetObjectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedPublicKeyShareProofMaterial',
        proofFamily: 'public-key-share',
        runtimeFamily: 4,
    },
    {
        fieldName: 'transportedVssShareLinkageProofMaterial',
        materialSetObjectType:
            'SetupTransportedVssShareLinkageProofMaterialSet',
        materialObjectType: 'SetupTransportedVssShareLinkageProofMaterial',
        proofFamily: 'vss-share-linkage',
        runtimeFamily: 2,
    },
    {
        fieldName: 'transportedSameSecretBridgeProofMaterial',
        materialSetObjectType:
            'SetupTransportedSameSecretBridgeProofMaterialSet',
        materialObjectType: 'SetupTransportedSameSecretBridgeProofMaterial',
        proofFamily: 'same-secret-bridge',
        runtimeFamily: 3,
    },
    {
        fieldName: 'transportedEvaluationKeyShareProofMaterial',
        materialSetObjectType:
            'SetupTransportedEvaluationKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedEvaluationKeyShareProofMaterial',
        proofFamily: 'trustee-evaluation-key',
        runtimeFamily: 5,
    },
] as const satisfies readonly SetupProofMaterialTransportCase[];

const binaryChunk = (firstByte: number): ArrayBuffer =>
    Uint8Array.of(firstByte, firstByte + 1, firstByte + 2).buffer;

const transportedSetupProofMaterialSet = (
    transportCase: SetupProofMaterialTransportCase,
    root = proofMaterialRoot,
): JsonRecord => ({
    objectType: transportCase.materialSetObjectType,
    proofFamily: transportCase.proofFamily,
    proofMaterials: [
        {
            objectType: transportCase.materialObjectType,
            proofFamily: transportCase.proofFamily,
            proofMaterialRoot: root,
            chunks: [
                {
                    chunkIndex: 0,
                    bytes: binaryChunk(17),
                },
            ],
        },
    ],
});

const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;

describe('canonical setup material streaming in the public package', () => {
    beforeEach(() => {
        mockedBgvCanonicalStreamStage.mockReset();
        mockedBgvCanonicalStreamStage.mockReturnValue(Uint8Array.of(1));
        mockKernel = {
            verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => ({
                isValid: false,
                observedInput: input,
                operation: 'verifyCollectiveBgvSetupPackage',
            })),
            verifyPrivateVssShareEnvelope: vi.fn((input: JsonRecord) => ({
                isValid: false,
                observedInput: input,
                operation: 'verifyPrivateVssShareEnvelope',
            })),
        };
    });

    it.each(setupProofMaterialTransportCases)(
        'authenticates $proofFamily bytes and passes only the semantic reference to setup verification',
        async (transportCase) => {
            await publicPackage.verifySetupPackage({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                [transportCase.fieldName]:
                    transportedSetupProofMaterialSet(transportCase),
            });

            expect(
                mockedBgvCanonicalStreamStage,
            ).toHaveBeenCalledExactlyOnceWith({
                chunks: [expect.any(ArrayBuffer)],
                family: transportCase.runtimeFamily,
                materialRoot: proofMaterialRoot,
            });

            const kernelInput = mockKernel.verifyCollectiveBgvSetup.mock
                .calls[0]?.[0] as JsonRecord;
            const materialSet = kernelInput[
                transportCase.fieldName
            ] as Readonly<{ readonly proofMaterials: readonly JsonRecord[] }>;
            expect(materialSet.proofMaterials[0]).toEqual({
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot,
            });
        },
    );

    it('authenticates all four setup-package proof families before one terminal verification', async () => {
        await publicPackage.verifySetupPackage({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            ...Object.fromEntries(
                setupProofMaterialTransportCases.map((transportCase) => [
                    transportCase.fieldName,
                    transportedSetupProofMaterialSet(transportCase),
                ]),
            ),
        });

        expect(mockedBgvCanonicalStreamStage).toHaveBeenCalledTimes(
            setupProofMaterialTransportCases.length,
        );
        expect(mockKernel.verifyCollectiveBgvSetup).toHaveBeenCalledOnce();
    });

    it('authenticates private VSS proof bytes and removes chunks before verification', async () => {
        const transportCase = {
            fieldName: 'transportedPrivateVssShareProofMaterial',
            materialSetObjectType:
                'SetupTransportedPrivateVssShareProofMaterialSet',
            materialObjectType:
                'PrivateVssShareTransportedSuccinctProofMaterial',
            proofFamily: 'vss-opening-carry',
            runtimeFamily: 1,
        } as const;
        const transportedMaterial = transportedSetupProofMaterialSet(
            transportCase,
            alternateProofMaterialRoot,
        );

        await publicPackage.verifyPrivateVssShare({
            setupContext: {
                ceremonyId: 'ceremony',
                manifestHash: expectedManifestHash,
                rosterHash: expectedRosterHash,
                setupEpoch: 'epoch',
                setupParametersHash: proofMaterialRoot,
            },
            publicMatrixSeedHash: proofMaterialRoot,
            sourceTrusteeCoefficientCommitmentMaterialRecords: [],
            sourceTrusteeCoefficientCommitmentRecord: {},
            privateEnvelope: {},
            transportedPrivateVssShareProofMaterial: transportedMaterial,
        });

        expect(mockedBgvCanonicalStreamStage).toHaveBeenCalledWith({
            chunks: [expect.any(ArrayBuffer)],
            family: transportCase.runtimeFamily,
            materialRoot: alternateProofMaterialRoot,
        });
        const kernelInput = mockKernel.verifyPrivateVssShareEnvelope.mock
            .calls[0]?.[0] as JsonRecord;
        const materialSet =
            kernelInput.transportedPrivateVssShareProofMaterial as Readonly<{
                readonly proofMaterials: readonly JsonRecord[];
            }>;
        expect(materialSet.proofMaterials[0]).toEqual({
            objectType: transportCase.materialObjectType,
            proofFamily: transportCase.proofFamily,
            proofMaterialRoot: alternateProofMaterialRoot,
        });
    });

    it('authenticates relinearization and Galois component material by semantic root', async () => {
        const componentCases = [
            {
                proofFamily: 'relinearization-key-share',
                root: proofMaterialRoot,
                runtimeFamily: 6,
            },
            {
                proofFamily: 'galois-key-share',
                root: alternateProofMaterialRoot,
                runtimeFamily: 7,
            },
        ] as const;

        await publicPackage.verifySetupPackage({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedEvaluationKeyShareComponentMaterial: {
                objectType:
                    'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                componentMaterials: componentCases.map((componentCase) => ({
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterial',
                    proofFamily: componentCase.proofFamily,
                    keySwitchComponentMaterialRoot: componentCase.root,
                })),
            },
            evaluationKeyShareComponentMaterialChunkStreams: componentCases.map(
                (componentCase, componentIndex) => ({
                    keySwitchComponentMaterialRoot: componentCase.root,
                    proofFamily: componentCase.proofFamily,
                    chunks: [
                        {
                            chunkIndex: 0,
                            bytes: binaryChunk(31 + componentIndex),
                        },
                    ],
                }),
            ),
        });

        componentCases.forEach((componentCase) => {
            expect(mockedBgvCanonicalStreamStage).toHaveBeenCalledWith({
                chunks: [expect.any(ArrayBuffer)],
                family: componentCase.runtimeFamily,
                materialRoot: componentCase.root,
            });
        });
        const kernelInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord;
        expect(
            kernelInput.evaluationKeyShareComponentMaterialChunkStreams,
        ).toBeUndefined();
    });

    it('refuses a component stream whose family does not match its semantic reference', async () => {
        await expect(
            publicPackage.verifySetupPackage({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        {
                            proofFamily: 'relinearization-key-share',
                            keySwitchComponentMaterialRoot: proofMaterialRoot,
                        },
                    ],
                },
                evaluationKeyShareComponentMaterialChunkStreams: [
                    {
                        keySwitchComponentMaterialRoot: proofMaterialRoot,
                        proofFamily: 'galois-key-share',
                        chunks: [
                            {
                                chunkIndex: 0,
                                bytes: binaryChunk(47),
                            },
                        ],
                    },
                ],
            }),
        ).rejects.toThrow(/must match exactly one transported reference/u);
        expect(mockedBgvCanonicalStreamStage).not.toHaveBeenCalled();
        expect(mockKernel.verifyCollectiveBgvSetup).not.toHaveBeenCalled();
    });
});
