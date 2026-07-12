import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

import type {
    verifyPrivateVssShare,
    verifySetupPackage,
} from '#packages/sdk/src/index.js';

type JsonRecord = Record<string, unknown>;
type ChunkPullRequest = Readonly<{
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}>;
type TestProofMaterialSource = Readonly<{
    readonly proofMaterialRoot: string;
    readonly pullChunk: Mock<
        (input: ChunkPullRequest) => Promise<ArrayBuffer | undefined>
    >;
}>;
type CanonicalReadInput = Readonly<{
    readonly pullChunk: (
        input: ChunkPullRequest,
    ) => Promise<ArrayBuffer | undefined>;
}>;

const proofMaterialRoot = '1'.repeat(128);
const alternateProofMaterialRoot = '2'.repeat(128);
const expectedManifestHash = '3'.repeat(128);
const expectedRosterHash = '4'.repeat(128);

const mockedReadMaterial = vi.hoisted(() => vi.fn());

vi.mock(
    '../../dist/internal/transcript-core-bridge.js',
    async (importOriginal) => ({
        ...(await importOriginal<Record<string, unknown>>()),
        openBgvCanonicalStreamRuntime: () => ({
            readMaterial: mockedReadMaterial,
        }),
    }),
);

type MockKernel = {
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
    readonly verifyPrivateVssShareEnvelope: ReturnType<typeof vi.fn>;
};

let mockKernel: MockKernel;
let createFreshMockKernel: () => MockKernel;
let loadedFreshMockKernels: MockKernel[];

vi.mock('../../dist/kernel.js', () => ({
    loadFreshTranscriptCoreKernel: () =>
        Promise.resolve(createFreshMockKernel()),
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
    transportCase: Readonly<{
        readonly materialSetObjectType: string;
        readonly materialObjectType: string;
        readonly proofFamily: string;
        readonly runtimeFamily: number;
    }>,
    root = proofMaterialRoot,
): JsonRecord => ({
    objectType: transportCase.materialSetObjectType,
    proofFamily: transportCase.proofFamily,
    proofMaterials: [
        {
            objectType: transportCase.materialObjectType,
            proofFamily: transportCase.proofFamily,
            proofMaterialRoot: root,
            descriptorBytes: Uint8Array.of(transportCase.runtimeFamily),
        },
    ],
});

const proofMaterialSource = (
    root: string,
    firstByte: number,
): TestProofMaterialSource => {
    const chunk = binaryChunk(firstByte);
    return {
        proofMaterialRoot: root,
        pullChunk: vi.fn(
            ({ chunkIndex, expectedByteLength }: ChunkPullRequest) => {
                if (chunkIndex === 0) {
                    expect(expectedByteLength).toBe(chunk.byteLength);
                    return Promise.resolve(chunk.slice(0));
                }
                expect(expectedByteLength).toBe(0);
                return Promise.resolve(undefined);
            },
        ),
    };
};

const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;

const indexedMaterialRoot = (sourceIndex: number): string =>
    String(sourceIndex + 1).repeat(128);

describe('canonical setup material streaming in the public package', () => {
    beforeEach(() => {
        mockedReadMaterial.mockReset();
        mockedReadMaterial.mockImplementation(
            async (input: CanonicalReadInput): Promise<void> => {
                await input.pullChunk({ chunkIndex: 0, expectedByteLength: 3 });
                await input.pullChunk({ chunkIndex: 1, expectedByteLength: 0 });
            },
        );
        const newMockKernel = (): MockKernel => ({
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
        });
        loadedFreshMockKernels = [];
        createFreshMockKernel = () => {
            mockKernel = newMockKernel();
            loadedFreshMockKernels.push(mockKernel);

            return mockKernel;
        };
        mockKernel = newMockKernel();
    });

    it.each(setupProofMaterialTransportCases)(
        'authenticates $proofFamily bytes before setup verification',
        async (transportCase) => {
            const source = proofMaterialSource(proofMaterialRoot, 17);
            await publicPackage.verifySetupPackage({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                [transportCase.fieldName]:
                    transportedSetupProofMaterialSet(transportCase),
                setupProofMaterialChunkSources: [source],
            });

            expect(mockedReadMaterial).toHaveBeenCalledExactlyOnceWith({
                descriptorBytes: Uint8Array.of(transportCase.runtimeFamily),
                family: transportCase.runtimeFamily,
                materialRoot: proofMaterialRoot,
                pullChunk: source.pullChunk,
            });
            expect(
                source.pullChunk.mock.calls.map(([request]) => request),
            ).toEqual([
                { chunkIndex: 0, expectedByteLength: 3 },
                { chunkIndex: 1, expectedByteLength: 0 },
            ]);
            expect(mockKernel.verifyCollectiveBgvSetup).toHaveBeenCalledOnce();
        },
    );

    it('authenticates all four setup proof families before one terminal verification', async () => {
        await publicPackage.verifySetupPackage({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            ...Object.fromEntries(
                setupProofMaterialTransportCases.map(
                    (transportCase, transportIndex) => [
                        transportCase.fieldName,
                        transportedSetupProofMaterialSet(
                            transportCase,
                            indexedMaterialRoot(transportIndex),
                        ),
                    ],
                ),
            ),
            setupProofMaterialChunkSources:
                setupProofMaterialTransportCases.map(
                    (_transportCase, sourceIndex) =>
                        proofMaterialSource(
                            indexedMaterialRoot(sourceIndex),
                            20 + sourceIndex,
                        ),
                ),
        });

        expect(mockedReadMaterial).toHaveBeenCalledTimes(
            setupProofMaterialTransportCases.length,
        );
        expect(mockKernel.verifyCollectiveBgvSetup).toHaveBeenCalledOnce();
    });

    it('authenticates private VSS proof bytes before verification', async () => {
        const transportCase = {
            fieldName: 'transportedPrivateVssShareProofMaterial',
            materialSetObjectType:
                'SetupTransportedPrivateVssShareProofMaterialSet',
            materialObjectType:
                'PrivateVssShareTransportedSuccinctProofMaterial',
            proofFamily: 'vss-opening-carry',
            runtimeFamily: 1,
        } as const;
        const source = proofMaterialSource(alternateProofMaterialRoot, 29);

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
            transportedPrivateVssShareProofMaterial:
                transportedSetupProofMaterialSet(
                    transportCase,
                    alternateProofMaterialRoot,
                ),
            privateVssShareProofMaterialChunkSources: [source],
        });

        expect(mockedReadMaterial).toHaveBeenCalledWith({
            descriptorBytes: Uint8Array.of(transportCase.runtimeFamily),
            family: transportCase.runtimeFamily,
            materialRoot: alternateProofMaterialRoot,
            pullChunk: source.pullChunk,
        });
        expect(mockKernel.verifyPrivateVssShareEnvelope).toHaveBeenCalledOnce();
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
        const sources = componentCases.map((componentCase, componentIndex) => ({
            keySwitchComponentMaterialRoot: componentCase.root,
            proofFamily: componentCase.proofFamily,
            pullChunk: proofMaterialSource(
                componentCase.root,
                31 + componentIndex,
            ).pullChunk,
        }));

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
                    descriptorBytes: Uint8Array.of(componentCase.runtimeFamily),
                })),
            },
            evaluationKeyShareComponentMaterialChunkSources: sources,
        });

        componentCases.forEach((componentCase, componentIndex) => {
            expect(mockedReadMaterial).toHaveBeenNthCalledWith(
                componentIndex + 1,
                {
                    descriptorBytes: Uint8Array.of(componentCase.runtimeFamily),
                    family: componentCase.runtimeFamily,
                    materialRoot: componentCase.root,
                    pullChunk: sources[componentIndex].pullChunk,
                },
            );
        });
    });

    it('refuses a component source whose family does not match its semantic reference', async () => {
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
                            descriptorBytes: Uint8Array.of(6),
                        },
                    ],
                },
                evaluationKeyShareComponentMaterialChunkSources: [
                    {
                        keySwitchComponentMaterialRoot: proofMaterialRoot,
                        proofFamily: 'galois-key-share',
                        pullChunk: proofMaterialSource(proofMaterialRoot, 47)
                            .pullChunk,
                    },
                ],
            }),
        ).rejects.toThrow(/must match exactly one transported reference/u);
        expect(mockedReadMaterial).not.toHaveBeenCalled();
        expect(mockKernel.verifyCollectiveBgvSetup).not.toHaveBeenCalled();
    });

    it('discards a setup verification kernel after material staging fails', async () => {
        const verificationInput = {
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedPublicKeyShareProofMaterial: {
                objectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
                proofFamily: 'public-key-share',
                proofMaterials: [
                    {
                        objectType:
                            'SetupTransportedPublicKeyShareProofMaterial',
                        proofFamily: 'public-key-share',
                        proofMaterialRoot,
                        descriptorBytes: Uint8Array.of(4),
                    },
                ],
            },
            setupProofMaterialChunkSources: [
                proofMaterialSource(proofMaterialRoot, 53),
            ],
        } satisfies Parameters<typeof publicPackage.verifySetupPackage>[0];
        mockedReadMaterial.mockRejectedValueOnce(
            new Error('simulated material source failure'),
        );

        await expect(
            publicPackage.verifySetupPackage(verificationInput),
        ).rejects.toThrow('simulated material source failure');
        const failedKernel = loadedFreshMockKernels[0];
        expect(failedKernel?.verifyCollectiveBgvSetup).not.toHaveBeenCalled();

        await publicPackage.verifySetupPackage(verificationInput);
        const recoveryKernel = loadedFreshMockKernels[1];
        expect(recoveryKernel).not.toBe(failedKernel);
        expect(recoveryKernel?.verifyCollectiveBgvSetup).toHaveBeenCalledOnce();
    });

    it('discards a private VSS verification kernel after material staging fails', async () => {
        const transportCase = {
            materialSetObjectType:
                'SetupTransportedPrivateVssShareProofMaterialSet',
            materialObjectType:
                'PrivateVssShareTransportedSuccinctProofMaterial',
            proofFamily: 'vss-opening-carry',
            runtimeFamily: 1,
        } as const;
        const verificationInput = {
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
            transportedPrivateVssShareProofMaterial:
                transportedSetupProofMaterialSet(
                    transportCase,
                    alternateProofMaterialRoot,
                ),
            privateVssShareProofMaterialChunkSources: [
                proofMaterialSource(alternateProofMaterialRoot, 59),
            ],
        };
        mockedReadMaterial.mockRejectedValueOnce(
            new Error('simulated private material source failure'),
        );

        await expect(
            publicPackage.verifyPrivateVssShare(verificationInput),
        ).rejects.toThrow('simulated private material source failure');
        const failedKernel = loadedFreshMockKernels[0];
        expect(
            failedKernel?.verifyPrivateVssShareEnvelope,
        ).not.toHaveBeenCalled();

        await publicPackage.verifyPrivateVssShare(verificationInput);
        const recoveryKernel = loadedFreshMockKernels[1];
        expect(recoveryKernel).not.toBe(failedKernel);
        expect(
            recoveryKernel?.verifyPrivateVssShareEnvelope,
        ).toHaveBeenCalledOnce();
    });
});
