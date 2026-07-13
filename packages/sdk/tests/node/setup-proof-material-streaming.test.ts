import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

import type {
    verifyPrivateVssShare,
    verifySetupPackage,
} from '#packages/sdk/src/index.js';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

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
type ProofMaterialTransportCase = Readonly<{
    readonly fieldName: string;
    readonly materialSetObjectType: string;
    readonly materialObjectType: string;
    readonly proofFamily: string;
    readonly runtimeFamily: number;
}>;

const proofMaterialRoot = '1'.repeat(128);
const alternateProofMaterialRoot = '2'.repeat(128);
const expectedManifestHash = '3'.repeat(128);
const expectedRosterHash = '4'.repeat(128);
const publicKeyShareMaterialRoot = '5'.repeat(128);

const readMaterial = vi.hoisted(() => vi.fn());
const openCanonicalRuntime = vi.hoisted(() => vi.fn());

vi.mock('@sealed-lattice/wasm/published-sdk', async (importOriginal) => ({
    ...(await importOriginal<Record<string, unknown>>()),
    openBgvCanonicalStreamRuntime: openCanonicalRuntime,
}));

type MockAcceptedSetupSession = Readonly<{
    cancel: ReturnType<typeof vi.fn>;
    verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
}>;

type MockKernel = Readonly<{
    acceptedSetupSession: MockAcceptedSetupSession;
    beginAcceptedSetupSession: ReturnType<typeof vi.fn>;
    verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
    verifyPrivateVssShareEnvelope: ReturnType<typeof vi.fn>;
}>;

let createFreshMockKernel: () => MockKernel;
let loadedFreshMockKernels: MockKernel[];
let lifecycleEvents: string[];
let mockKernel: MockKernel;

vi.mock('../../src/kernel.js', () => ({
    loadFreshTranscriptCoreKernel: () =>
        Promise.resolve(createFreshMockKernel()),
    loadTranscriptCoreKernel: () => Promise.resolve(mockKernel),
}));

const publicPackage = (await import('../../src/index.js')) as Readonly<{
    readonly verifyPrivateVssShare: typeof verifyPrivateVssShare;
    readonly verifySetupPackage: typeof verifySetupPackage;
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
] as const;

const transportedProofMaterialSet = <
    const TransportCase extends ProofMaterialTransportCase,
>(
    transportCase: TransportCase,
    root = proofMaterialRoot,
): Readonly<{
    readonly objectType: TransportCase['materialSetObjectType'];
    readonly proofMaterials: readonly [
        Readonly<{
            readonly objectType: TransportCase['materialObjectType'];
            readonly proofMaterialRoot: string;
            readonly descriptorBytes: Uint8Array;
        }>,
    ];
}> => ({
    objectType: transportCase.materialSetObjectType,
    proofMaterials: [
        {
            objectType: transportCase.materialObjectType,
            proofMaterialRoot: root,
            descriptorBytes: canonicalStreamDescriptorFixture(
                3,
                transportCase.runtimeFamily,
            ),
        },
    ],
});

const proofMaterialSource = (
    root: string,
    firstByte: number,
): TestProofMaterialSource => {
    const chunk = Uint8Array.of(firstByte, firstByte + 1, firstByte + 2).buffer;

    return {
        proofMaterialRoot: root,
        pullChunk: vi.fn(({ chunkIndex, expectedByteLength }) => {
            if (chunkIndex === 0) {
                expect(expectedByteLength).toBe(chunk.byteLength);
                return Promise.resolve(chunk.slice(0));
            }
            expect(expectedByteLength).toBe(0);
            return Promise.resolve(undefined);
        }),
    };
};

const requiredPublicKeyShareMaterialSource = proofMaterialSource(
    publicKeyShareMaterialRoot,
    7,
);
const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
    transportedPublicKeyShareMaterial: {
        objectType: 'SetupTransportedPublicKeyShareMaterial',
        publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
        descriptorBytes: canonicalStreamDescriptorFixture(3, 8, 9),
    },
    publicKeyShareMaterialChunkSource: {
        publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
        pullChunk: requiredPublicKeyShareMaterialSource.pullChunk,
    },
    transportedPublicKeyShareProofMaterial: {
        objectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
        proofMaterials: [],
    },
    transportedVssShareLinkageProofMaterial: {
        objectType: 'SetupTransportedVssShareLinkageProofMaterialSet',
        proofMaterials: [],
    },
    transportedSameSecretBridgeProofMaterial: {
        objectType: 'SetupTransportedSameSecretBridgeProofMaterialSet',
        proofMaterials: [],
    },
    transportedEvaluationKeyShareProofMaterial: {
        objectType: 'SetupTransportedEvaluationKeyShareProofMaterialSet',
        proofMaterials: [],
    },
    transportedEvaluationKeyShareComponentMaterial: {
        objectType: 'SetupTransportedEvaluationKeyShareComponentMaterialSet',
        componentMaterials: [],
    },
} as const;

const setupPackageWithoutEvaluationKeyComponentReferences = {
    objectType: 'SetupPackage',
    relinearizationKeyShareRounds: {
        objectType: 'RelinearizationKeyShareRounds',
        roundOneRecords: [],
        roundTwoRecords: [],
    },
    galoisKeyShareBatches: [],
} as const;

describe('canonical setup material streaming in the public package', () => {
    beforeEach(() => {
        lifecycleEvents = [];
        readMaterial.mockReset();
        readMaterial.mockImplementation(
            async (
                input: Readonly<{
                    pullChunk: TestProofMaterialSource['pullChunk'];
                }>,
            ) => {
                lifecycleEvents.push('source-pull');
                await input.pullChunk({ chunkIndex: 0, expectedByteLength: 3 });
                await input.pullChunk({ chunkIndex: 1, expectedByteLength: 0 });
            },
        );
        openCanonicalRuntime.mockReset();
        openCanonicalRuntime.mockImplementation(() => {
            lifecycleEvents.push('runtime-open');
            return { readMaterial };
        });

        const newMockKernel = (): MockKernel => {
            const acceptedSetupSession: MockAcceptedSetupSession = {
                cancel: vi.fn(() => lifecycleEvents.push('cancel')),
                verifyCollectiveBgvSetup: vi.fn((input: JsonRecord) => {
                    lifecycleEvents.push('terminal');
                    return { isValid: false, observedInput: input };
                }),
            };

            return {
                acceptedSetupSession,
                beginAcceptedSetupSession: vi.fn(() => {
                    lifecycleEvents.push('begin');
                    return acceptedSetupSession;
                }),
                verifyCollectiveBgvSetup: vi.fn(),
                verifyPrivateVssShareEnvelope: vi.fn((input: JsonRecord) => ({
                    isValid: false,
                    observedInput: input,
                })),
            };
        };

        loadedFreshMockKernels = [];
        createFreshMockKernel = () => {
            mockKernel = newMockKernel();
            loadedFreshMockKernels.push(mockKernel);
            return mockKernel;
        };
        mockKernel = newMockKernel();
    });

    it.each(setupProofMaterialTransportCases)(
        'authenticates $proofFamily bytes before terminal verification',
        async (transportCase) => {
            const source = proofMaterialSource(proofMaterialRoot, 17);

            await publicPackage.verifySetupPackage({
                setupPackage:
                    setupPackageWithoutEvaluationKeyComponentReferences,
                ...setupVerificationBindings,
                [transportCase.fieldName]:
                    transportedProofMaterialSet(transportCase),
                setupProofMaterialChunkSources: [source],
            });

            expect(readMaterial).toHaveBeenNthCalledWith(2, {
                descriptorBytes: canonicalStreamDescriptorFixture(
                    3,
                    transportCase.runtimeFamily,
                ),
                family: transportCase.runtimeFamily,
                materialRoot: proofMaterialRoot,
                pullChunk: source.pullChunk,
            });
            expect(lifecycleEvents).toEqual([
                'begin',
                'runtime-open',
                'source-pull',
                'source-pull',
                'terminal',
            ]);
            expect(mockKernel.verifyCollectiveBgvSetup).not.toHaveBeenCalled();
        },
    );

    it('authenticates public-key share material before terminal verification', async () => {
        const source = proofMaterialSource(publicKeyShareMaterialRoot, 19);

        await publicPackage.verifySetupPackage({
            setupPackage: setupPackageWithoutEvaluationKeyComponentReferences,
            ...setupVerificationBindings,
            transportedPublicKeyShareMaterial: {
                objectType: 'SetupTransportedPublicKeyShareMaterial',
                publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
                descriptorBytes: canonicalStreamDescriptorFixture(3, 8, 9),
            },
            publicKeyShareMaterialChunkSource: {
                publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
                pullChunk: source.pullChunk,
            },
        });

        expect(readMaterial).toHaveBeenCalledExactlyOnceWith({
            descriptorBytes: canonicalStreamDescriptorFixture(3, 8, 9),
            family: 9,
            materialRoot: publicKeyShareMaterialRoot,
            pullChunk: source.pullChunk,
        });
        const kernelInput = mockKernel.acceptedSetupSession
            .verifyCollectiveBgvSetup.mock.calls[0]?.[0] as JsonRecord;
        expect(kernelInput.transportedPublicKeyShareMaterial).toMatchObject({
            publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
        });
    });

    it('authenticates private VSS proof bytes before verification', async () => {
        const privateVssTransportCase = {
            fieldName: 'transportedVssShareLinkageProofMaterial',
            materialSetObjectType:
                'SetupTransportedPrivateVssShareProofMaterialSet',
            materialObjectType: 'SetupTransportedPrivateVssShareProofMaterial',
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
                participantCount: 1,
            },
            publicMatrixSeedHash: proofMaterialRoot,
            sourceTrusteeCoefficientCommitmentMaterialRecords: [],
            sourceTrusteeCoefficientCommitmentRecord: {},
            privateEnvelope: {},
            transportedPrivateVssShareProofMaterial:
                transportedProofMaterialSet(
                    privateVssTransportCase,
                    alternateProofMaterialRoot,
                ),
            privateVssShareProofMaterialChunkSources: [source],
        });

        expect(readMaterial).toHaveBeenCalledExactlyOnceWith({
            descriptorBytes: canonicalStreamDescriptorFixture(3, 1),
            family: 1,
            materialRoot: alternateProofMaterialRoot,
            pullChunk: source.pullChunk,
        });
        expect(mockKernel.verifyPrivateVssShareEnvelope).toHaveBeenCalledOnce();
    });

    it('refuses a component root claimed by conflicting package record families', async () => {
        await expect(
            publicPackage.verifySetupPackage({
                setupPackage: {
                    objectType: 'SetupPackage',
                    relinearizationKeyShareRounds: {
                        objectType: 'RelinearizationKeyShareRounds',
                        roundOneRecords: [
                            {
                                objectType: 'RelinearizationKeyShareRoundOne',
                                keySwitchComponentMaterialRoot:
                                    proofMaterialRoot,
                            },
                        ],
                        roundTwoRecords: [],
                    },
                    galoisKeyShareBatches: [
                        {
                            objectType: 'GaloisKeyShareBatch',
                            galoisKeyShareMaterialRecords: [
                                {
                                    objectType: 'GaloisKeyShareMaterial',
                                    keySwitchComponentMaterialRoot:
                                        proofMaterialRoot,
                                },
                            ],
                        },
                    ],
                },
                ...setupVerificationBindings,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        {
                            objectType:
                                'SetupTransportedEvaluationKeyShareComponentMaterial',
                            keySwitchComponentMaterialRoot: proofMaterialRoot,
                            descriptorBytes: canonicalStreamDescriptorFixture(
                                3,
                                6,
                            ),
                        },
                    ],
                },
                evaluationKeyShareComponentMaterialChunkSources: [
                    {
                        keySwitchComponentMaterialRoot: proofMaterialRoot,
                        pullChunk: proofMaterialSource(proofMaterialRoot, 47)
                            .pullChunk,
                    },
                ],
            }),
        ).rejects.toThrow(/conflicting material root/u);
        expect(readMaterial).toHaveBeenCalledOnce();
    });

    it('rejects an oversized descriptor before copying or loading a kernel', async () => {
        const oversizedDescriptor = new Uint8Array(131_177);
        const callerSlice = vi.fn(() => new Uint8Array());
        Object.defineProperty(oversizedDescriptor, 'slice', {
            value: callerSlice,
        });

        await expect(
            publicPackage.verifySetupPackage({
                setupPackage:
                    setupPackageWithoutEvaluationKeyComponentReferences,
                ...setupVerificationBindings,
                transportedPublicKeyShareProofMaterial: {
                    objectType:
                        'SetupTransportedPublicKeyShareProofMaterialSet',
                    proofMaterials: [
                        {
                            objectType:
                                'SetupTransportedPublicKeyShareProofMaterial',
                            proofMaterialRoot,
                            descriptorBytes: oversizedDescriptor,
                        },
                    ],
                },
            }),
        ).rejects.toThrow(/canonical stream descriptor bound/u);
        expect(callerSlice).not.toHaveBeenCalled();
        expect(loadedFreshMockKernels).toHaveLength(0);
    });

    it('cancels a setup session after material staging fails and permits a retry', async () => {
        const transportCase = setupProofMaterialTransportCases[0];
        const verificationInput = {
            setupPackage: setupPackageWithoutEvaluationKeyComponentReferences,
            ...setupVerificationBindings,
            transportedPublicKeyShareProofMaterial:
                transportedProofMaterialSet(transportCase),
            setupProofMaterialChunkSources: [
                proofMaterialSource(proofMaterialRoot, 53),
            ],
        } satisfies Parameters<typeof publicPackage.verifySetupPackage>[0];
        readMaterial.mockRejectedValueOnce(
            new Error('simulated material source failure'),
        );

        await expect(
            publicPackage.verifySetupPackage(verificationInput),
        ).rejects.toThrow('simulated material source failure');
        expect(
            loadedFreshMockKernels[0]?.acceptedSetupSession.cancel,
        ).toHaveBeenCalledOnce();
        expect(
            loadedFreshMockKernels[0]?.acceptedSetupSession
                .verifyCollectiveBgvSetup,
        ).not.toHaveBeenCalled();

        await publicPackage.verifySetupPackage(verificationInput);
        expect(
            loadedFreshMockKernels[1]?.acceptedSetupSession
                .verifyCollectiveBgvSetup,
        ).toHaveBeenCalledOnce();
    });
});
