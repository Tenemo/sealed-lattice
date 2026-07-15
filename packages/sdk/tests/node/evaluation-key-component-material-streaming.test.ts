import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

import type {
    AcceptedSetupSession,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

type JsonRecord = Record<string, unknown>;
type ChunkPullRequest = Readonly<{
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}>;
type TestComponentMaterialSource = Readonly<{
    readonly pullChunk: Mock<
        (input: ChunkPullRequest) => Promise<ArrayBuffer | undefined>
    >;
}>;
type CanonicalReadInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly pullChunk: (
        input: ChunkPullRequest,
    ) => Promise<ArrayBuffer | undefined>;
}>;

const runtimeMocks = vi.hoisted(() => ({
    readMaterial: vi.fn(),
}));

vi.mock('@sealed-lattice/wasm/published-sdk', async (importOriginal) => ({
    ...(await importOriginal<
        typeof import('@sealed-lattice/wasm/published-sdk')
    >()),
    openBgvCanonicalStreamRuntime: () => ({
        readMaterial: runtimeMocks.readMaterial,
    }),
}));

const componentMaterialRoot = '4'.repeat(128);
const secondComponentMaterialRoot = '5'.repeat(128);
const publicKeyShareMaterialRoot = '6'.repeat(128);
const expectedManifestHash = '1'.repeat(128);
const expectedRosterHash = '2'.repeat(128);

const publicKeyShareMaterialSource = {
    pullChunk: vi.fn(({ chunkIndex, expectedByteLength }: ChunkPullRequest) => {
        if (chunkIndex === 0) {
            const chunk = Uint8Array.of(0xaa, 0xbb, 0xcc, 0xdd).buffer;
            if (chunk.byteLength !== expectedByteLength) {
                throw new Error('Unexpected public-key material chunk length.');
            }
            return Promise.resolve(chunk);
        }
        if (expectedByteLength !== 0) {
            throw new Error(
                'Unexpected terminal public-key material chunk length.',
            );
        }
        return Promise.resolve(undefined);
    }),
} as const;

const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
    publicKeyShareMaterialStream: {
        descriptorBytes: canonicalStreamDescriptorFixture(4, 8),
        pullChunk: publicKeyShareMaterialSource.pullChunk,
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
} as const;

const componentMaterial = () =>
    ({
        descriptorBytes: canonicalStreamDescriptorFixture(4, 0x53),
    }) as const;

const setupPackageWithComponentReferences = (
    input: Readonly<{
        readonly roundOneRoots?: readonly string[];
        readonly roundTwoRoots?: readonly string[];
        readonly galoisRoots?: readonly string[];
    }>,
): JsonRecord => ({
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
        roundOneKeySwitchComponentMaterialRoots: input.roundOneRoots ?? [],
        roundTwoKeySwitchComponentMaterialRoots: input.roundTwoRoots ?? [],
    },
    galoisKeyShareBatches:
        (input.galoisRoots?.length ?? 0) === 0
            ? []
            : [
                  {
                      objectType: 'GaloisKeyShareBatch',
                      keySwitchComponentMaterialRoots: input.galoisRoots ?? [],
                  },
              ],
});

const componentMaterialSource = (
    firstChunkBytes: readonly number[],
): TestComponentMaterialSource => {
    const chunks = [
        Uint8Array.from([...firstChunkBytes, 1, 2]).buffer,
    ] as const;

    return {
        pullChunk: vi.fn(
            ({ chunkIndex, expectedByteLength }: ChunkPullRequest) => {
                const chunk = chunks[chunkIndex];
                if (chunk === undefined) {
                    return Promise.resolve(undefined);
                }
                expect(chunk.byteLength).toBe(expectedByteLength);
                return Promise.resolve(chunk.slice(0));
            },
        ),
    } as const;
};

const {
    prepareSnapshottedSetupPackageVerificationInputForKernel,
    snapshotSetupPackageVerificationInput,
} = await import('#packages/sdk/src/setup-verification-input.js');
const { bgvCanonicalStreamFamilies } =
    await import('@sealed-lattice/wasm/published-sdk');

const prepare = async (input: JsonRecord): Promise<void> => {
    await prepareSnapshottedSetupPackageVerificationInputForKernel(
        {} as TranscriptCoreKernel,
        snapshotSetupPackageVerificationInput(input as never),
        {} as AcceptedSetupSession,
    );
};

describe('evaluation-key component material streaming before terminal verification', () => {
    beforeEach(() => {
        publicKeyShareMaterialSource.pullChunk.mockClear();
        runtimeMocks.readMaterial.mockReset();
        runtimeMocks.readMaterial.mockImplementation(
            async (input: CanonicalReadInput): Promise<void> => {
                await input.pullChunk({ chunkIndex: 0, expectedByteLength: 4 });
                await input.pullChunk({ chunkIndex: 1, expectedByteLength: 0 });
            },
        );
    });

    it('authenticates each component from its descriptor and bounded source', async () => {
        const firstSource = componentMaterialSource([0xaa, 0xbb]);
        const secondSource = componentMaterialSource([0xcc, 0xdd]);
        await prepare({
            setupPackage: setupPackageWithComponentReferences({
                roundOneRoots: [componentMaterialRoot],
                galoisRoots: [secondComponentMaterialRoot],
            }),
            ...setupVerificationBindings,
            evaluationKeyShareComponentMaterialStreams: [
                { ...componentMaterial(), pullChunk: firstSource.pullChunk },
                { ...componentMaterial(), pullChunk: secondSource.pullChunk },
            ],
        });

        expect(runtimeMocks.readMaterial).toHaveBeenCalledTimes(3);
        expect(runtimeMocks.readMaterial).toHaveBeenCalledWith(
            expect.objectContaining({
                materialRoot: componentMaterialRoot,
                family: bgvCanonicalStreamFamilies.relinearizationComponent,
                pullChunk: firstSource.pullChunk,
            }),
        );
        expect(runtimeMocks.readMaterial).toHaveBeenCalledWith(
            expect.objectContaining({
                materialRoot: secondComponentMaterialRoot,
                family: bgvCanonicalStreamFamilies.galoisComponent,
                pullChunk: secondSource.pullChunk,
            }),
        );
        expect(firstSource.pullChunk).toHaveBeenCalledTimes(2);
        expect(secondSource.pullChunk).toHaveBeenCalledTimes(2);
        expect(
            firstSource.pullChunk.mock.calls.map(([request]) => request),
        ).toEqual([
            { chunkIndex: 0, expectedByteLength: 4 },
            { chunkIndex: 1, expectedByteLength: 0 },
        ]);
    });

    it('uses one descriptor snapshot when a chunk callback mutates the caller buffer', async () => {
        const callerMaterial = componentMaterial();
        const authenticatedDescriptor = callerMaterial.descriptorBytes.slice();
        const source = componentMaterialSource([0xaa, 0xbb]);
        const mutatingPullChunk = vi.fn(
            async (
                request: ChunkPullRequest,
            ): Promise<ArrayBuffer | undefined> => {
                callerMaterial.descriptorBytes.fill(0xff);
                return source.pullChunk(request);
            },
        );
        await prepare({
            setupPackage: setupPackageWithComponentReferences({
                roundOneRoots: [componentMaterialRoot],
            }),
            ...setupVerificationBindings,
            evaluationKeyShareComponentMaterialStreams: [
                {
                    ...callerMaterial,
                    pullChunk: mutatingPullChunk,
                },
            ],
        });

        expect(callerMaterial.descriptorBytes).toEqual(
            new Uint8Array(callerMaterial.descriptorBytes.byteLength).fill(
                0xff,
            ),
        );
        expect(runtimeMocks.readMaterial).toHaveBeenNthCalledWith(
            2,
            expect.objectContaining({
                descriptorBytes: authenticatedDescriptor,
                materialRoot: componentMaterialRoot,
                pullChunk: mutatingPullChunk,
            }),
        );
        const streamedInput = runtimeMocks.readMaterial.mock.calls[1]?.[0] as
            | Readonly<{ readonly descriptorBytes: Uint8Array }>
            | undefined;
        expect(streamedInput?.descriptorBytes).not.toBe(
            callerMaterial.descriptorBytes,
        );
    });

    it('surfaces a canonical stream rejection instead of swallowing it', async () => {
        runtimeMocks.readMaterial
            .mockImplementationOnce(async (input: CanonicalReadInput) => {
                await input.pullChunk({
                    chunkIndex: 0,
                    expectedByteLength: 4,
                });
                await input.pullChunk({
                    chunkIndex: 1,
                    expectedByteLength: 0,
                });
            })
            .mockRejectedValueOnce(
                new Error('canonical component stream rejected'),
            );

        await expect(
            prepare({
                setupPackage: setupPackageWithComponentReferences({
                    roundOneRoots: [componentMaterialRoot],
                }),
                ...setupVerificationBindings,
                evaluationKeyShareComponentMaterialStreams: [
                    {
                        ...componentMaterial(),
                        ...componentMaterialSource([0xaa, 0xbb]),
                    },
                ],
            }),
        ).rejects.toThrow('canonical component stream rejected');
    });

    it('rejects streams beyond the authoritative component references', async () => {
        const stream = {
            ...componentMaterial(),
            ...componentMaterialSource([0xaa, 0xbb]),
        };
        await expect(
            prepare({
                setupPackage: setupPackageWithComponentReferences({
                    roundOneRoots: [componentMaterialRoot],
                }),
                ...setupVerificationBindings,
                evaluationKeyShareComponentMaterialStreams: [stream, stream],
            }),
        ).rejects.toThrow(/one stream per setup-package/u);
    });

    it('rejects duplicate authoritative component references', async () => {
        await expect(
            prepare({
                setupPackage: setupPackageWithComponentReferences({
                    roundOneRoots: [componentMaterialRoot],
                    roundTwoRoots: [componentMaterialRoot],
                }),
                ...setupVerificationBindings,
                evaluationKeyShareComponentMaterialStreams: [
                    {
                        ...componentMaterial(),
                        ...componentMaterialSource([0xaa, 0xbb]),
                    },
                ],
            }),
        ).rejects.toThrow(/duplicate material root/u);
    });

    it('rejects malformed authoritative component references', async () => {
        await expect(
            prepare({
                setupPackage: setupPackageWithComponentReferences({
                    roundOneRoots: ['not-a-protocol-hash'],
                }),
                ...setupVerificationBindings,
                evaluationKeyShareComponentMaterialStreams: [
                    {
                        ...componentMaterial(),
                        ...componentMaterialSource([0xaa, 0xbb]),
                    },
                ],
            }),
        ).rejects.toThrow(/must be a protocol hash/u);
    });

    it('rejects an authoritative reference without a component stream', async () => {
        await expect(
            prepare({
                setupPackage: setupPackageWithComponentReferences({
                    roundOneRoots: [
                        componentMaterialRoot,
                        secondComponentMaterialRoot,
                    ],
                }),
                ...setupVerificationBindings,
                evaluationKeyShareComponentMaterialStreams: [
                    {
                        ...componentMaterial(),
                        ...componentMaterialSource([0xaa, 0xbb]),
                    },
                ],
            }),
        ).rejects.toThrow(/one stream per setup-package/u);
    });
});
