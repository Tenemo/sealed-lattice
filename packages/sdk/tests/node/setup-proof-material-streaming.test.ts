import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index.js';
import type {
    createSetupPackageVerificationInput,
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
type CanonicalReadInput = Readonly<{
    readonly pullChunk: (
        input: ChunkPullRequest,
    ) => Promise<ArrayBuffer | undefined>;
}>;

const proofMaterialRoot = '1'.repeat(128);
const alternateProofMaterialRoot = '2'.repeat(128);
const expectedManifestHash = '3'.repeat(128);
const expectedRosterHash = '4'.repeat(128);
const publicKeyShareMaterialRoot = '5'.repeat(128);

const mockedReadMaterial = vi.hoisted(() => vi.fn());

vi.mock('@sealed-lattice/wasm', async (importOriginal) => ({
    ...(await importOriginal<Record<string, unknown>>()),
    openBgvCanonicalStreamRuntime: () => ({
        readMaterial: mockedReadMaterial,
    }),
}));

type MockKernel = {
    readonly verifyCollectiveBgvSetup: ReturnType<typeof vi.fn>;
    readonly verifyPrivateVssShareEnvelope: ReturnType<typeof vi.fn>;
};

let mockKernel: MockKernel;
let createFreshMockKernel: () => MockKernel;
let loadedFreshMockKernels: MockKernel[];

vi.mock('../../src/kernel.js', () => ({
    loadFreshTranscriptCoreKernel: () =>
        Promise.resolve(createFreshMockKernel()),
    loadTranscriptCoreKernel: () => Promise.resolve(mockKernel),
}));

const publicPackage = (await import('../../src/index.js')) as Readonly<{
    readonly createSetupPackageVerificationInput: typeof createSetupPackageVerificationInput;
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

const privateVerificationInput = (
    privateEnvelope: unknown,
    sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[] = [],
): Parameters<typeof publicPackage.verifyPrivateVssShare>[0] => ({
    setupContext: {
        ceremonyId: 'ceremony',
        manifestHash: expectedManifestHash,
        rosterHash: expectedRosterHash,
        setupEpoch: 'epoch',
        setupParametersHash: proofMaterialRoot,
    },
    publicMatrixSeedHash: proofMaterialRoot,
    sourceTrusteeCoefficientCommitmentMaterialRecords,
    sourceTrusteeCoefficientCommitmentRecord: {},
    privateEnvelope,
});

const indexedMaterialRoot = (sourceIndex: number): string =>
    String(sourceIndex + 1).repeat(128);

const descriptorAccounting = (
    totalByteLength: number,
    chunkHashByte: number,
    fullObjectHashByte = 0x42,
): Readonly<{
    readonly totalByteLength: number;
    readonly fullObjectHash: string;
    readonly chunkRoot: string;
    readonly chunkHashes: readonly string[];
}> => {
    const chunkHashes = [
        chunkHashByte.toString(16).padStart(2, '0').repeat(64),
    ];
    const fullObjectHash = fullObjectHashByte
        .toString(16)
        .padStart(2, '0')
        .repeat(64);

    return {
        totalByteLength,
        fullObjectHash,
        chunkRoot: deriveCanonicalObjectHash({
            objectType: 'SetupTransportChunkManifest',
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        }),
        chunkHashes,
    };
};

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
                descriptorBytes: canonicalStreamDescriptorFixture(
                    3,
                    transportCase.runtimeFamily,
                ),
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
            const kernelInput = mockKernel.verifyCollectiveBgvSetup.mock
                .calls[0]?.[0] as JsonRecord;
            const normalizedMaterials = (
                kernelInput[transportCase.fieldName] as JsonRecord
            ).proofMaterials as readonly JsonRecord[];
            const accounting = descriptorAccounting(
                3,
                transportCase.runtimeFamily,
            );
            expect(normalizedMaterials[0]?.descriptorBytes).toBeUndefined();
            expect(normalizedMaterials[0]).toMatchObject(
                transportCase.fieldName ===
                    'transportedEvaluationKeyShareProofMaterial'
                    ? {
                          proofTotalByteLength: accounting.totalByteLength,
                          proofFullObjectHash: accounting.fullObjectHash,
                          proofChunkRoot: accounting.chunkRoot,
                          proofChunkHashes: accounting.chunkHashes,
                      }
                    : accounting,
            );
        },
    );

    it('authenticates public-key share material and forwards descriptor-derived accounting', async () => {
        const source = proofMaterialSource(publicKeyShareMaterialRoot, 19);
        await publicPackage.verifySetupPackage({
            setupPackage: { objectType: 'SetupPackage' },
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

        expect(mockedReadMaterial).toHaveBeenCalledExactlyOnceWith({
            descriptorBytes: canonicalStreamDescriptorFixture(3, 8, 9),
            family: 9,
            materialRoot: publicKeyShareMaterialRoot,
            pullChunk: source.pullChunk,
        });
        const kernelInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord;
        const normalizedMaterial =
            kernelInput.transportedPublicKeyShareMaterial as JsonRecord;
        expect(normalizedMaterial.descriptorBytes).toBeUndefined();
        expect(normalizedMaterial).toMatchObject({
            publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
            ...descriptorAccounting(3, 8, 9),
        });
    });

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

    it('verifies the public helper output with all seven descriptor classes and one call-time snapshot', async () => {
        const setupProofMaterialChunkSources =
            setupProofMaterialTransportCases.map(
                (_transportCase, sourceIndex) =>
                    proofMaterialSource(
                        indexedMaterialRoot(sourceIndex),
                        70 + sourceIndex,
                    ),
            );
        const evaluationKeyComponentMaterialRoot = '6'.repeat(128);
        const publicEvaluationKeyMaterialRoot = '7'.repeat(128);
        const evaluationKeyShareComponentMaterialChunkSources = [
            {
                keySwitchComponentMaterialRoot:
                    evaluationKeyComponentMaterialRoot,
                proofFamily: 'relinearization-key-share' as const,
                pullChunk: proofMaterialSource(
                    evaluationKeyComponentMaterialRoot,
                    80,
                ).pullChunk,
            },
        ];
        const publicEvaluationKeyMaterialChunkSources = [
            {
                publicEvaluationKeyMaterialRoot,
                pullChunk: proofMaterialSource(
                    publicEvaluationKeyMaterialRoot,
                    81,
                ).pullChunk,
            },
        ];
        const publicKeyShareMaterialChunkSource = {
            publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
            pullChunk: proofMaterialSource(publicKeyShareMaterialRoot, 82)
                .pullChunk,
        };
        const transportedProofMaterialSets = Object.fromEntries(
            setupProofMaterialTransportCases.map(
                (transportCase, transportIndex) => [
                    transportCase.fieldName,
                    transportedSetupProofMaterialSet(
                        transportCase,
                        indexedMaterialRoot(transportIndex),
                    ),
                ],
            ),
        );
        const transportedPublicKeyShareProofMaterial =
            transportedProofMaterialSets.transportedPublicKeyShareProofMaterial;
        const proofMaterials =
            transportedPublicKeyShareProofMaterial.proofMaterials as JsonRecord[];
        const proofDescriptor = proofMaterials[0]
            ?.descriptorBytes as Uint8Array;
        const authenticatedProofDescriptor = proofDescriptor.slice();

        const verificationInput =
            publicPackage.createSetupPackageVerificationInput({
                setupPackage: {
                    objectType: 'SetupPackage',
                },
                ...setupVerificationBindings,
                ...transportedProofMaterialSets,
                transportedPublicKeyShareMaterial: {
                    objectType: 'SetupTransportedPublicKeyShareMaterial',
                    publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
                    descriptorBytes: canonicalStreamDescriptorFixture(3, 9),
                },
                publicKeyShareMaterialChunkSource,
                setupProofMaterialChunkSources,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        {
                            objectType:
                                'SetupTransportedEvaluationKeyShareComponentMaterial',
                            proofFamily: 'relinearization-key-share',
                            keySwitchComponentMaterialRoot:
                                evaluationKeyComponentMaterialRoot,
                            descriptorBytes: canonicalStreamDescriptorFixture(
                                3,
                                6,
                            ),
                        },
                    ],
                },
                evaluationKeyShareComponentMaterialChunkSources,
                transportedPublicEvaluationKeyMaterial: {
                    objectType:
                        'SetupTransportedPublicEvaluationKeyMaterialSet',
                    materialEncoding:
                        'binary-chunked-public-evaluation-key-material',
                    publicEvaluationKeyMaterials: [
                        {
                            objectType:
                                'SetupTransportedPublicEvaluationKeyMaterial',
                            publicEvaluationKeyMaterialRoot,
                            descriptorBytes: canonicalStreamDescriptorFixture(
                                3,
                                10,
                            ),
                        },
                    ],
                },
                publicEvaluationKeyMaterialChunkSources,
            } as unknown as Parameters<
                typeof publicPackage.createSetupPackageVerificationInput
            >[0]);

        const verificationPromise =
            publicPackage.verifySetupPackage(verificationInput);
        proofDescriptor.fill(0xff);
        setupProofMaterialChunkSources.splice(
            0,
            setupProofMaterialChunkSources.length,
        );
        evaluationKeyShareComponentMaterialChunkSources.splice(
            0,
            evaluationKeyShareComponentMaterialChunkSources.length,
        );
        publicEvaluationKeyMaterialChunkSources.splice(
            0,
            publicEvaluationKeyMaterialChunkSources.length,
        );
        await verificationPromise;

        expect(mockedReadMaterial).toHaveBeenCalledTimes(7);
        expect(
            mockedReadMaterial.mock.calls.map(
                ([streamInput]) => (streamInput as JsonRecord).family,
            ),
        ).toEqual([9, 6, 10, 5, 4, 3, 2]);
        expect(
            mockedReadMaterial.mock.calls.some(
                ([streamInput]) =>
                    (streamInput as JsonRecord).descriptorBytes ===
                    authenticatedProofDescriptor,
            ),
        ).toBe(false);
        expect(
            mockedReadMaterial.mock.calls.map(
                ([streamInput]) => (streamInput as JsonRecord).descriptorBytes,
            ),
        ).toContainEqual(authenticatedProofDescriptor);
        expect(mockKernel.verifyCollectiveBgvSetup).toHaveBeenCalledOnce();
    });

    it('keeps the complete setup terminal input immutable across kernel loading and chunk callbacks', async () => {
        const transportCase = setupProofMaterialTransportCases[0];
        const setupPackage = {
            objectType: 'SetupPackage',
            nestedContext: {
                phase: 'original-phase',
                trusteeRecords: [{ trusteeIdentity: 'trustee-alpha' }],
            },
        };
        const source = proofMaterialSource(proofMaterialRoot, 83);
        const mutatingPullChunk = vi.fn(
            async (
                request: ChunkPullRequest,
            ): Promise<ArrayBuffer | undefined> => {
                setupPackage.nestedContext.phase = 'callback-phase';
                setupPackage.nestedContext.trusteeRecords.push({
                    trusteeIdentity: 'callback-trustee',
                });

                return source.pullChunk(request);
            },
        );
        const verificationPromise = publicPackage.verifySetupPackage({
            setupPackage,
            ...setupVerificationBindings,
            transportedPublicKeyShareProofMaterial:
                transportedSetupProofMaterialSet(transportCase),
            setupProofMaterialChunkSources: [
                {
                    proofMaterialRoot,
                    pullChunk: mutatingPullChunk,
                },
            ],
        } as unknown as Parameters<typeof publicPackage.verifySetupPackage>[0]);
        setupPackage.nestedContext.phase = 'kernel-load-phase';
        setupPackage.nestedContext.trusteeRecords[0].trusteeIdentity =
            'kernel-load-trustee';

        await verificationPromise;

        const kernelInput = mockKernel.verifyCollectiveBgvSetup.mock
            .calls[0]?.[0] as JsonRecord;
        expect(kernelInput.setupPackage).toEqual({
            objectType: 'SetupPackage',
            nestedContext: {
                phase: 'original-phase',
                trusteeRecords: [{ trusteeIdentity: 'trustee-alpha' }],
            },
        });
        expect(
            (mockedReadMaterial.mock.calls[0]?.[0] as CanonicalReadInput)
                .pullChunk,
        ).toBe(mutatingPullChunk);
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
            descriptorBytes: canonicalStreamDescriptorFixture(
                3,
                transportCase.runtimeFamily,
            ),
            family: transportCase.runtimeFamily,
            materialRoot: alternateProofMaterialRoot,
            pullChunk: source.pullChunk,
        });
        expect(mockKernel.verifyPrivateVssShareEnvelope).toHaveBeenCalledOnce();
    });

    it('uses one private VSS transport snapshot when a chunk callback mutates caller objects', async () => {
        const transportCase = {
            materialSetObjectType:
                'SetupTransportedPrivateVssShareProofMaterialSet',
            materialObjectType:
                'PrivateVssShareTransportedSuccinctProofMaterial',
            proofFamily: 'vss-opening-carry',
            runtimeFamily: 1,
        } as const;
        const transportedMaterialSet = transportedSetupProofMaterialSet(
            transportCase,
            alternateProofMaterialRoot,
        );
        const callerProofMaterials = transportedMaterialSet.proofMaterials as
            | JsonRecord[]
            | undefined;
        const callerProofMaterial = callerProofMaterials?.[0];
        if (
            callerProofMaterials === undefined ||
            callerProofMaterial === undefined
        ) {
            throw new Error('Missing private VSS proof material fixture.');
        }
        const callerDescriptor =
            callerProofMaterial.descriptorBytes as Uint8Array;
        const authenticatedDescriptor = callerDescriptor.slice();
        const source = proofMaterialSource(alternateProofMaterialRoot, 30);
        const mutatingPullChunk = vi.fn(
            async (
                request: ChunkPullRequest,
            ): Promise<ArrayBuffer | undefined> => {
                if (request.chunkIndex === 0) {
                    callerProofMaterial.objectType = 'MutatedProofMaterial';
                    callerProofMaterial.proofFamily = 'mutated-proof-family';
                    callerProofMaterial.proofMaterialRoot = proofMaterialRoot;
                    callerDescriptor.fill(0xff);
                    callerProofMaterials.push({
                        objectType: transportCase.materialObjectType,
                        proofFamily: transportCase.proofFamily,
                        proofMaterialRoot,
                        descriptorBytes: canonicalStreamDescriptorFixture(
                            3,
                            transportCase.runtimeFamily,
                        ),
                    });
                }

                return source.pullChunk(request);
            },
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
            transportedPrivateVssShareProofMaterial: transportedMaterialSet,
            privateVssShareProofMaterialChunkSources: [
                {
                    proofMaterialRoot: alternateProofMaterialRoot,
                    pullChunk: mutatingPullChunk,
                },
            ],
        });

        const streamedInput = mockedReadMaterial.mock.calls[0]?.[0] as
            | Readonly<{
                  readonly descriptorBytes: Uint8Array;
                  readonly family: number;
                  readonly materialRoot: string;
              }>
            | undefined;
        expect(streamedInput).toMatchObject({
            descriptorBytes: authenticatedDescriptor,
            family: transportCase.runtimeFamily,
            materialRoot: alternateProofMaterialRoot,
        });
        expect(streamedInput?.descriptorBytes).not.toBe(callerDescriptor);
        const kernelInput = mockKernel.verifyPrivateVssShareEnvelope.mock
            .calls[0]?.[0] as JsonRecord;
        const normalizedMaterialSet =
            kernelInput.transportedPrivateVssShareProofMaterial as JsonRecord;
        expect(normalizedMaterialSet.proofMaterials).toEqual([
            {
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: alternateProofMaterialRoot,
            },
        ]);
        expect(callerProofMaterials).toHaveLength(2);
        expect(callerDescriptor).toEqual(
            new Uint8Array(callerDescriptor.byteLength).fill(0xff),
        );
    });

    it('keeps the complete private VSS terminal input immutable across kernel loading and chunk callbacks', async () => {
        const transportCase = {
            materialSetObjectType:
                'SetupTransportedPrivateVssShareProofMaterialSet',
            materialObjectType:
                'PrivateVssShareTransportedSuccinctProofMaterial',
            proofFamily: 'vss-opening-carry',
            runtimeFamily: 1,
        } as const;
        const setupContext = {
            ceremonyId: 'ceremony',
            manifestHash: expectedManifestHash,
            rosterHash: expectedRosterHash,
            setupEpoch: 'epoch',
            setupParametersHash: proofMaterialRoot,
        };
        const sourceCommitmentRecord = {
            objectType: 'SourceCommitment',
            nested: { trusteeIdentity: 'trustee-alpha' },
        };
        const sourceCommitmentMaterialRecords = [
            { objectType: 'SourceMaterial', nested: { limbIndex: 0 } },
        ];
        const privateEnvelope = {
            objectType: 'PrivateEnvelope',
            nested: { recipientIdentity: 'trustee-beta' },
        };
        const source = proofMaterialSource(alternateProofMaterialRoot, 84);
        const mutatingPullChunk = vi.fn(
            async (
                request: ChunkPullRequest,
            ): Promise<ArrayBuffer | undefined> => {
                privateEnvelope.nested.recipientIdentity = 'callback-recipient';
                sourceCommitmentMaterialRecords.push({
                    objectType: 'CallbackMaterial',
                    nested: { limbIndex: 1 },
                });

                return source.pullChunk(request);
            },
        );
        const verificationPromise = publicPackage.verifyPrivateVssShare({
            setupContext,
            publicMatrixSeedHash: proofMaterialRoot,
            sourceTrusteeCoefficientCommitmentMaterialRecords:
                sourceCommitmentMaterialRecords,
            sourceTrusteeCoefficientCommitmentRecord: sourceCommitmentRecord,
            privateEnvelope,
            transportedPrivateVssShareProofMaterial:
                transportedSetupProofMaterialSet(
                    transportCase,
                    alternateProofMaterialRoot,
                ),
            privateVssShareProofMaterialChunkSources: [
                {
                    proofMaterialRoot: alternateProofMaterialRoot,
                    pullChunk: mutatingPullChunk,
                },
            ],
        });
        setupContext.ceremonyId = 'kernel-load-ceremony';
        sourceCommitmentRecord.nested.trusteeIdentity = 'kernel-load-trustee';

        await verificationPromise;

        const kernelInput = mockKernel.verifyPrivateVssShareEnvelope.mock
            .calls[0]?.[0] as JsonRecord;
        expect(kernelInput.setupContext).toEqual({
            ceremonyId: 'ceremony',
            manifestHash: expectedManifestHash,
            rosterHash: expectedRosterHash,
            setupEpoch: 'epoch',
            setupParametersHash: proofMaterialRoot,
        });
        expect(kernelInput.sourceTrusteeCoefficientCommitmentRecord).toEqual({
            objectType: 'SourceCommitment',
            nested: { trusteeIdentity: 'trustee-alpha' },
        });
        expect(
            kernelInput.sourceTrusteeCoefficientCommitmentMaterialRecords,
        ).toEqual([{ objectType: 'SourceMaterial', nested: { limbIndex: 0 } }]);
        expect(kernelInput.privateEnvelope).toEqual({
            objectType: 'PrivateEnvelope',
            nested: { recipientIdentity: 'trustee-beta' },
        });
        expect(
            (mockedReadMaterial.mock.calls[0]?.[0] as CanonicalReadInput)
                .pullChunk,
        ).toBe(mutatingPullChunk);
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
                    descriptorBytes: canonicalStreamDescriptorFixture(
                        3,
                        componentCase.runtimeFamily,
                    ),
                })),
            },
            evaluationKeyShareComponentMaterialChunkSources: sources,
        });

        componentCases.forEach((componentCase, componentIndex) => {
            expect(mockedReadMaterial).toHaveBeenNthCalledWith(
                componentIndex + 1,
                {
                    descriptorBytes: canonicalStreamDescriptorFixture(
                        3,
                        componentCase.runtimeFamily,
                    ),
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

    it('refuses terminal accessors without invoking them or loading a kernel', async () => {
        const setupAccessor = vi.fn(() => ({ phase: 'accessor' }));
        const setupPackage = { objectType: 'SetupPackage' } as JsonRecord;
        Object.defineProperty(setupPackage, 'nestedContext', {
            enumerable: true,
            get: setupAccessor,
        });
        await expect(
            publicPackage.verifySetupPackage({
                setupPackage,
                ...setupVerificationBindings,
            }),
        ).rejects.toThrow(
            'setupPackage.nestedContext cannot be an accessor property',
        );

        const privateAccessor = vi.fn(() => ({ phase: 'accessor' }));
        const privateEnvelope = { objectType: 'PrivateEnvelope' } as JsonRecord;
        Object.defineProperty(privateEnvelope, 'nestedContext', {
            enumerable: true,
            get: privateAccessor,
        });
        await expect(
            publicPackage.verifyPrivateVssShare(
                privateVerificationInput(privateEnvelope),
            ),
        ).rejects.toThrow(
            'privateEnvelope.nestedContext cannot be an accessor property',
        );

        const chunkCallbackAccessor = vi.fn(
            () => proofMaterialSource(proofMaterialRoot, 85).pullChunk,
        );
        const chunkSource = { proofMaterialRoot } as JsonRecord;
        Object.defineProperty(chunkSource, 'pullChunk', {
            enumerable: true,
            get: chunkCallbackAccessor,
        });
        const setupInputWithCallbackAccessor = {
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedPublicKeyShareProofMaterial:
                transportedSetupProofMaterialSet(
                    setupProofMaterialTransportCases[0],
                ),
            setupProofMaterialChunkSources: [chunkSource],
        } as unknown as Parameters<typeof publicPackage.verifySetupPackage>[0];
        await expect(
            publicPackage.verifySetupPackage(setupInputWithCallbackAccessor),
        ).rejects.toThrow(
            'setupProofMaterialChunkSources.0.pullChunk cannot be an accessor property',
        );

        expect(setupAccessor).not.toHaveBeenCalled();
        expect(privateAccessor).not.toHaveBeenCalled();
        expect(chunkCallbackAccessor).not.toHaveBeenCalled();
        expect(loadedFreshMockKernels).toHaveLength(0);
    });

    it('refuses cyclic terminal values before loading a kernel', async () => {
        const setupPackage = { objectType: 'SetupPackage' } as JsonRecord;
        setupPackage.self = setupPackage;
        await expect(
            publicPackage.verifySetupPackage({
                setupPackage,
                ...setupVerificationBindings,
            }),
        ).rejects.toThrow('setupPackage.self cannot contain a cyclic value');

        const privateEnvelope = {
            objectType: 'PrivateEnvelope',
        } as JsonRecord;
        privateEnvelope.self = privateEnvelope;
        await expect(
            publicPackage.verifyPrivateVssShare(
                privateVerificationInput(privateEnvelope),
            ),
        ).rejects.toThrow('privateEnvelope.self cannot contain a cyclic value');

        expect(loadedFreshMockKernels).toHaveLength(0);
    });

    it('refuses custom-prototype terminal values before loading a kernel', async () => {
        const setupPackage = Object.assign(
            Object.create({ inheritedAuthority: true }) as JsonRecord,
            { objectType: 'SetupPackage' },
        );
        await expect(
            publicPackage.verifySetupPackage({
                setupPackage,
                ...setupVerificationBindings,
            }),
        ).rejects.toThrow(
            'setupPackage must contain only plain objects and arrays',
        );

        const privateEnvelope = Object.assign(
            Object.create({ inheritedAuthority: true }) as JsonRecord,
            { objectType: 'PrivateEnvelope' },
        );
        await expect(
            publicPackage.verifyPrivateVssShare(
                privateVerificationInput(privateEnvelope),
            ),
        ).rejects.toThrow(
            'privateEnvelope must contain only plain objects and arrays',
        );

        expect(loadedFreshMockKernels).toHaveLength(0);
    });

    it('refuses a dense oversized terminal array before enumerating its descriptors', async () => {
        const denseOversizedArray = new Array<null>(1_000_001).fill(null);
        const ownKeys = vi.fn((): (string | symbol)[] => {
            throw new Error('descriptor enumeration must not run');
        });
        const guardedOversizedArray = new Proxy(denseOversizedArray, {
            ownKeys,
        });

        await expect(
            publicPackage.verifyPrivateVssShare(
                privateVerificationInput({}, guardedOversizedArray),
            ),
        ).rejects.toThrow(
            'sourceTrusteeCoefficientCommitmentMaterialRecords exceeds the accepted array length',
        );
        expect(ownKeys).not.toHaveBeenCalled();
        expect(loadedFreshMockKernels).toHaveLength(0);
    });

    it('refuses an oversized descriptor before invoking caller copy methods or loading a kernel', async () => {
        const oversizedDescriptor = new Uint8Array(131_177);
        const callerSlice = vi.fn(() => new Uint8Array());
        Object.defineProperty(oversizedDescriptor, 'slice', {
            value: callerSlice,
        });

        await expect(
            publicPackage.verifySetupPackage({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedPublicKeyShareProofMaterial: {
                    objectType:
                        'SetupTransportedPublicKeyShareProofMaterialSet',
                    proofFamily: 'public-key-share',
                    proofMaterials: [
                        {
                            objectType:
                                'SetupTransportedPublicKeyShareProofMaterial',
                            proofFamily: 'public-key-share',
                            proofMaterialRoot,
                            descriptorBytes: oversizedDescriptor,
                        },
                    ],
                },
            }),
        ).rejects.toThrow('exceeds the canonical stream descriptor bound');
        expect(callerSlice).not.toHaveBeenCalled();
        expect(loadedFreshMockKernels).toHaveLength(0);
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
                        descriptorBytes: canonicalStreamDescriptorFixture(3, 4),
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
