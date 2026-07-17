import { foundationProfile } from '@sealed-lattice/types';
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
    readonly pullChunk: Mock<
        (input: ChunkPullRequest) => Promise<ArrayBuffer | undefined>
    >;
}>;
type ProofMaterialTransportCase = Readonly<{
    readonly fieldName:
        | 'transportedPublicKeyShareProofMaterial'
        | 'transportedVssShareLinkageProofMaterial'
        | 'transportedSameSecretBridgeProofMaterial'
        | 'transportedEvaluationKeyShareProofMaterial';
    readonly proofFamily: string;
    readonly runtimeFamily: number;
}>;

const proofBytesHash = '1'.repeat(128);
const alternateProofBytesHash = '2'.repeat(128);
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
}));

const publicPackage = (await import('../../src/index.js')) as Readonly<{
    readonly verifyPrivateVssShare: typeof verifyPrivateVssShare;
    readonly verifySetupPackage: typeof verifySetupPackage;
}>;

const setupProofMaterialTransportCases = [
    {
        fieldName: 'transportedPublicKeyShareProofMaterial',
        proofFamily: 'public-key-share',
        runtimeFamily: 4,
    },
    {
        fieldName: 'transportedVssShareLinkageProofMaterial',
        proofFamily: 'vss-share-linkage',
        runtimeFamily: 2,
    },
    {
        fieldName: 'transportedSameSecretBridgeProofMaterial',
        proofFamily: 'same-secret-bridge',
        runtimeFamily: 3,
    },
    {
        fieldName: 'transportedEvaluationKeyShareProofMaterial',
        proofFamily: 'trustee-evaluation-key',
        runtimeFamily: 5,
    },
] as const;

const transportedProofMaterialSet = (
    transportCase: ProofMaterialTransportCase,
    source: TestProofMaterialSource,
): Readonly<{
    readonly proofMaterialStreams: readonly [
        Readonly<{
            readonly descriptorBytes: Uint8Array;
            readonly pullChunk: TestProofMaterialSource['pullChunk'];
        }>,
    ];
}> => ({
    proofMaterialStreams: [
        {
            descriptorBytes: canonicalStreamDescriptorFixture(
                3,
                transportCase.runtimeFamily,
            ),
            pullChunk: source.pullChunk,
        },
    ],
});

const proofMaterialSource = (firstByte: number): TestProofMaterialSource => {
    const chunk = Uint8Array.of(firstByte, firstByte + 1, firstByte + 2).buffer;

    return {
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

const requiredPublicKeyShareMaterialSource = proofMaterialSource(7);
const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
    publicKeyShareMaterialStream: {
        descriptorBytes: canonicalStreamDescriptorFixture(3, 8),
        pullChunk: requiredPublicKeyShareMaterialSource.pullChunk,
    },
    transportedPublicKeyShareProofMaterial: {
        proofMaterialStreams: [],
    },
    transportedVssShareLinkageProofMaterial: {
        proofMaterialStreams: [],
    },
    transportedSameSecretBridgeProofMaterial: {
        proofMaterialStreams: [],
    },
    transportedEvaluationKeyShareProofMaterial: {
        proofMaterialStreams: [],
    },
    evaluationKeyShareComponentMaterialStreams: [],
} as const;

const setupPackageWithoutEvaluationKeyComponentReferences = {
    objectType: 'SetupPackage',
    publicKeyShareMaterial: {
        objectType: 'PublicKeyShareMaterialSet',
        publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
    },
    publicKeyShareSuccinctProofs: {
        objectType: 'PublicKeyShareSuccinctProofSet',
        proofBytesHashes: [],
    },
    vssShareLinkageProofMaterialSet: {
        objectType: 'VssShareLinkageProofMaterialSet',
        proofRecords: [],
    },
    sameSecretBridgeProofMaterialSet: {
        objectType: 'VssSameSecretBridgeProofMaterialSet',
        proofBytesHashes: [],
    },
    trusteeEvaluationKeyProofs: {
        objectType: 'TrusteeEvaluationKeyProofSet',
        proofBytesHashes: [],
    },
    relinearizationKeyShareRounds: {
        objectType: 'RelinearizationKeyShareRounds',
        roundOneKeySwitchComponentMaterialRoots: [],
        roundTwoKeySwitchComponentMaterialRoots: [],
    },
    galoisKeyShareBatches: [],
} as const;

const setupPackageWithProofBytesHashes = (
    transportCase: ProofMaterialTransportCase,
    proofBytesHashes: readonly string[],
): JsonRecord => {
    if (transportCase.fieldName === 'transportedPublicKeyShareProofMaterial') {
        return {
            ...setupPackageWithoutEvaluationKeyComponentReferences,
            publicKeyShareSuccinctProofs: {
                objectType: 'PublicKeyShareSuccinctProofSet',
                proofBytesHashes,
            },
        };
    }
    if (transportCase.fieldName === 'transportedVssShareLinkageProofMaterial') {
        return {
            ...setupPackageWithoutEvaluationKeyComponentReferences,
            vssShareLinkageProofMaterialSet: {
                objectType: 'VssShareLinkageProofMaterialSet',
                proofRecords: proofBytesHashes.map((currentProofBytesHash) => ({
                    objectType: 'VssShareLinkageProofRecord',
                    proofBytesHash: currentProofBytesHash,
                })),
            },
        };
    }
    if (
        transportCase.fieldName === 'transportedSameSecretBridgeProofMaterial'
    ) {
        return {
            ...setupPackageWithoutEvaluationKeyComponentReferences,
            sameSecretBridgeProofMaterialSet: {
                objectType: 'VssSameSecretBridgeProofMaterialSet',
                proofBytesHashes,
            },
        };
    }

    return {
        ...setupPackageWithoutEvaluationKeyComponentReferences,
        trusteeEvaluationKeyProofs: {
            objectType: 'TrusteeEvaluationKeyProofSet',
            proofBytesHashes,
        },
    };
};

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
                verifyCollectiveBgvSetup: vi.fn((_input: JsonRecord) => {
                    lifecycleEvents.push('terminal');
                    return {
                        isValid: false,
                        refusalReason: 'invalidProof',
                    };
                }),
            };

            return {
                acceptedSetupSession,
                beginAcceptedSetupSession: vi.fn(() => {
                    lifecycleEvents.push('begin');
                    return acceptedSetupSession;
                }),
                verifyCollectiveBgvSetup: vi.fn(),
                verifyPrivateVssShareEnvelope: vi.fn((_input: JsonRecord) => ({
                    isValid: false,
                    refusalReason: 'invalidProof',
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
            const source = proofMaterialSource(17);

            const verification = await publicPackage.verifySetupPackage({
                setupPackage: setupPackageWithProofBytesHashes(transportCase, [
                    proofBytesHash,
                ]),
                ...setupVerificationBindings,
                [transportCase.fieldName]: transportedProofMaterialSet(
                    transportCase,
                    source,
                ),
            });

            expect(verification).toEqual({
                isValid: false,
                refusalReason: 'invalidProof',
            });

            expect(readMaterial).toHaveBeenNthCalledWith(2, {
                descriptorBytes: canonicalStreamDescriptorFixture(
                    3,
                    transportCase.runtimeFamily,
                ),
                family: transportCase.runtimeFamily,
                materialRoot: proofBytesHash,
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

    it.each(setupProofMaterialTransportCases)(
        'requires one $proofFamily stream per authoritative proof hash',
        async (transportCase) => {
            await expect(
                publicPackage.verifySetupPackage({
                    setupPackage: setupPackageWithProofBytesHashes(
                        transportCase,
                        [proofBytesHash],
                    ),
                    ...setupVerificationBindings,
                    [transportCase.fieldName]: {
                        proofMaterialStreams: [],
                    },
                }),
            ).rejects.toThrow(
                /one stream per authoritative setup-package proof hash/u,
            );
        },
    );

    it.each(setupProofMaterialTransportCases)(
        'rejects duplicate authoritative $proofFamily proof hashes',
        async (transportCase) => {
            const source = proofMaterialSource(23);
            const stream = transportedProofMaterialSet(transportCase, source)
                .proofMaterialStreams[0];

            await expect(
                publicPackage.verifySetupPackage({
                    setupPackage: setupPackageWithProofBytesHashes(
                        transportCase,
                        [proofBytesHash, proofBytesHash],
                    ),
                    ...setupVerificationBindings,
                    [transportCase.fieldName]: {
                        proofMaterialStreams: [stream, stream],
                    },
                }),
            ).rejects.toThrow(/must not contain duplicate hashes/u);
        },
    );

    it('returns a genuine verification result without a process-local capability', async () => {
        const kernel = createFreshMockKernel();
        kernel.acceptedSetupSession.verifyCollectiveBgvSetup.mockReturnValueOnce(
            {
                isValid: true,
                value: undefined,
            },
        );
        createFreshMockKernel = () => kernel;

        const verification = await publicPackage.verifySetupPackage({
            setupPackage: setupPackageWithoutEvaluationKeyComponentReferences,
            ...setupVerificationBindings,
            expectedSetupPackageHash: proofBytesHash,
        });

        expect(verification).toEqual({ isValid: true, value: undefined });
        expect(
            kernel.acceptedSetupSession.verifyCollectiveBgvSetup,
        ).toHaveBeenCalledWith(
            expect.objectContaining({
                expectedSetupPackageHash: proofBytesHash,
            }),
        );
    });

    it('authenticates public-key share material before terminal verification', async () => {
        const source = proofMaterialSource(19);

        await publicPackage.verifySetupPackage({
            setupPackage: setupPackageWithoutEvaluationKeyComponentReferences,
            ...setupVerificationBindings,
            publicKeyShareMaterialStream: {
                descriptorBytes: canonicalStreamDescriptorFixture(3, 8),
                pullChunk: source.pullChunk,
            },
        });

        expect(readMaterial).toHaveBeenCalledExactlyOnceWith({
            descriptorBytes: canonicalStreamDescriptorFixture(3, 8),
            family: 9,
            materialRoot: publicKeyShareMaterialRoot,
            pullChunk: source.pullChunk,
        });
    });

    it('authenticates private VSS proof bytes before verification', async () => {
        const privateVssTransportCase = {
            fieldName: 'transportedVssShareLinkageProofMaterial',
            proofFamily: 'vss-opening-carry',
            runtimeFamily: 1,
        } as const;
        const source = proofMaterialSource(29);

        const verification = await publicPackage.verifyPrivateVssShare({
            setupContext: {
                ceremonyId: 'ceremony',
                manifestHash: expectedManifestHash,
                rosterHash: expectedRosterHash,
                setupEpoch: 'epoch',
                setupParametersHash: proofBytesHash,
                participantCount: 3,
            },
            publicMatrixSeedHash: proofBytesHash,
            sourceTrusteeCoefficientCommitmentMaterialRecords: [],
            sourceTrusteeCoefficientCommitmentRecord: {},
            privateEnvelope: {
                objectType: 'PrivateVssShareEnvelope',
                rnsShareOpenings: [
                    {
                        objectType: 'PrivateVssShareLimbOpening',
                        privateVssShareProofBytesHash: alternateProofBytesHash,
                    },
                ],
            },
            transportedPrivateVssShareProofMaterial:
                transportedProofMaterialSet(privateVssTransportCase, source),
        });

        expect(verification).toEqual({
            isValid: false,
            refusalReason: 'invalidProof',
        });

        expect(readMaterial).toHaveBeenCalledExactlyOnceWith({
            descriptorBytes: canonicalStreamDescriptorFixture(3, 1),
            family: 1,
            materialRoot: alternateProofBytesHash,
            pullChunk: source.pullChunk,
        });
        expect(mockKernel.verifyPrivateVssShareEnvelope).toHaveBeenCalledOnce();
    });

    it('requires one private VSS stream per envelope proof hash', async () => {
        await expect(
            publicPackage.verifyPrivateVssShare({
                setupContext: {
                    ceremonyId: 'ceremony',
                    manifestHash: expectedManifestHash,
                    rosterHash: expectedRosterHash,
                    setupEpoch: 'epoch',
                    setupParametersHash: proofBytesHash,
                    participantCount: 3,
                },
                publicMatrixSeedHash: proofBytesHash,
                sourceTrusteeCoefficientCommitmentMaterialRecords: [],
                sourceTrusteeCoefficientCommitmentRecord: {},
                privateEnvelope: {
                    objectType: 'PrivateVssShareEnvelope',
                    rnsShareOpenings: [
                        {
                            objectType: 'PrivateVssShareLimbOpening',
                            privateVssShareProofBytesHash:
                                alternateProofBytesHash,
                        },
                    ],
                },
                transportedPrivateVssShareProofMaterial: {
                    proofMaterialStreams: [],
                },
            }),
        ).rejects.toThrow(/one stream per private-envelope proof hash/u);
    });

    it('refuses a component root claimed by conflicting package record families', async () => {
        await expect(
            publicPackage.verifySetupPackage({
                setupPackage: {
                    ...setupPackageWithoutEvaluationKeyComponentReferences,
                    relinearizationKeyShareRounds: {
                        objectType: 'RelinearizationKeyShareRounds',
                        roundOneKeySwitchComponentMaterialRoots: [
                            proofBytesHash,
                        ],
                        roundTwoKeySwitchComponentMaterialRoots: [],
                    },
                    galoisKeyShareBatches: [
                        {
                            objectType: 'GaloisKeyShareBatch',
                            keySwitchComponentMaterialRoots: [proofBytesHash],
                        },
                    ],
                },
                ...setupVerificationBindings,
                evaluationKeyShareComponentMaterialStreams: [
                    {
                        descriptorBytes: canonicalStreamDescriptorFixture(3, 6),
                        pullChunk: proofMaterialSource(47).pullChunk,
                    },
                ],
            }),
        ).rejects.toThrow(/duplicate material root/u);
        expect(readMaterial).toHaveBeenCalledOnce();
    });

    it('rejects an oversized descriptor before copying or loading a kernel', async () => {
        const maximumDescriptorByteLength = canonicalStreamDescriptorFixture(
            foundationProfile.maximumCanonicalStreamByteLength,
        ).byteLength;
        const oversizedDescriptor = new Uint8Array(
            maximumDescriptorByteLength + 1,
        );
        const callerSlice = vi.fn(() => new Uint8Array());
        Object.defineProperty(oversizedDescriptor, 'slice', {
            value: callerSlice,
        });

        await expect(
            publicPackage.verifySetupPackage({
                setupPackage: setupPackageWithProofBytesHashes(
                    setupProofMaterialTransportCases[0],
                    [proofBytesHash],
                ),
                ...setupVerificationBindings,
                transportedPublicKeyShareProofMaterial: {
                    proofMaterialStreams: [
                        {
                            descriptorBytes: oversizedDescriptor,
                            pullChunk: proofMaterialSource(41).pullChunk,
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
        const source = proofMaterialSource(53);
        const verificationInput = {
            setupPackage: setupPackageWithProofBytesHashes(transportCase, [
                proofBytesHash,
            ]),
            ...setupVerificationBindings,
            transportedPublicKeyShareProofMaterial: transportedProofMaterialSet(
                transportCase,
                source,
            ),
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

    it('preserves setup verification and cancellation failures together', async () => {
        const transportCase = setupProofMaterialTransportCases[0];
        const verificationFailure = new Error('material staging failed');
        const cancellationFailure = new Error('session cancellation failed');
        readMaterial.mockRejectedValueOnce(verificationFailure);
        createFreshMockKernel = () => {
            const kernel = mockKernel;
            kernel.acceptedSetupSession.cancel.mockImplementationOnce(() => {
                throw cancellationFailure;
            });
            loadedFreshMockKernels.push(kernel);
            return kernel;
        };

        const operation = publicPackage.verifySetupPackage({
            setupPackage: setupPackageWithProofBytesHashes(transportCase, [
                proofBytesHash,
            ]),
            ...setupVerificationBindings,
            transportedPublicKeyShareProofMaterial: transportedProofMaterialSet(
                transportCase,
                proofMaterialSource(59),
            ),
        });

        const error = await operation.catch((failure: unknown) => failure);
        expect(error).toMatchObject({
            name: 'SetupPackageVerificationCleanupError',
            operationFailure: verificationFailure,
            cleanupFailure: cancellationFailure,
        });
    });
});
