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
    readonly keySwitchComponentMaterialRoot: string;
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
const expectedManifestHash = '1'.repeat(128);
const expectedRosterHash = '2'.repeat(128);

const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;

const componentMaterial = (keySwitchComponentMaterialRoot: string) =>
    ({
        objectType: 'SetupTransportedEvaluationKeyShareComponentMaterial',
        proofFamily: 'relinearization-key-share',
        keySwitchComponentMaterialRoot,
        descriptorBytes: canonicalStreamDescriptorFixture(4, 0x53, 0x4c),
    }) as const;

const componentMaterialSource = (
    keySwitchComponentMaterialRoot: string,
    firstChunkBytes: readonly number[],
): TestComponentMaterialSource => {
    const chunks = [
        Uint8Array.from([...firstChunkBytes, 1, 2]).buffer,
    ] as const;

    return {
        keySwitchComponentMaterialRoot,
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

const prepare = (input: JsonRecord): Promise<JsonRecord> =>
    prepareSnapshottedSetupPackageVerificationInputForKernel(
        {} as TranscriptCoreKernel,
        snapshotSetupPackageVerificationInput(input as never),
        {} as AcceptedSetupSession,
    );

describe('evaluation-key component material streaming before terminal verification', () => {
    beforeEach(() => {
        runtimeMocks.readMaterial.mockReset();
        runtimeMocks.readMaterial.mockImplementation(
            async (input: CanonicalReadInput): Promise<void> => {
                await input.pullChunk({ chunkIndex: 0, expectedByteLength: 4 });
                await input.pullChunk({ chunkIndex: 1, expectedByteLength: 0 });
            },
        );
    });

    it('authenticates each component from its descriptor and bounded source', async () => {
        const firstSource = componentMaterialSource(
            componentMaterialRoot,
            [0xaa, 0xbb],
        );
        const secondSource = componentMaterialSource(
            secondComponentMaterialRoot,
            [0xcc, 0xdd],
        );
        const verificationInput = await prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedEvaluationKeyShareComponentMaterial: {
                objectType:
                    'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                componentMaterials: [
                    componentMaterial(componentMaterialRoot),
                    componentMaterial(secondComponentMaterialRoot),
                ],
            },
            evaluationKeyShareComponentMaterialChunkSources: [
                firstSource,
                secondSource,
            ],
        });

        expect(runtimeMocks.readMaterial).toHaveBeenCalledTimes(2);
        expect(runtimeMocks.readMaterial).toHaveBeenCalledWith(
            expect.objectContaining({
                materialRoot: componentMaterialRoot,
                pullChunk: firstSource.pullChunk,
            }),
        );
        expect(runtimeMocks.readMaterial).toHaveBeenCalledWith(
            expect.objectContaining({
                materialRoot: secondComponentMaterialRoot,
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
        const normalizedComponentMaterials = (
            verificationInput.transportedEvaluationKeyShareComponentMaterial as JsonRecord
        ).componentMaterials as readonly JsonRecord[];
        expect(normalizedComponentMaterials).toHaveLength(2);
        expect(normalizedComponentMaterials[0]).toMatchObject({
            keySwitchComponentMaterialRoot: componentMaterialRoot,
        });
    });

    it('uses one descriptor snapshot when a chunk callback mutates the caller buffer', async () => {
        const callerMaterial = componentMaterial(componentMaterialRoot);
        const authenticatedDescriptor = callerMaterial.descriptorBytes.slice();
        const source = componentMaterialSource(
            componentMaterialRoot,
            [0xaa, 0xbb],
        );
        const mutatingPullChunk = vi.fn(
            async (
                request: ChunkPullRequest,
            ): Promise<ArrayBuffer | undefined> => {
                callerMaterial.descriptorBytes.fill(0xff);
                return source.pullChunk(request);
            },
        );
        const verificationInput = await prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedEvaluationKeyShareComponentMaterial: {
                objectType:
                    'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                componentMaterials: [callerMaterial],
            },
            evaluationKeyShareComponentMaterialChunkSources: [
                {
                    ...source,
                    pullChunk: mutatingPullChunk,
                },
            ],
        });

        expect(callerMaterial.descriptorBytes).toEqual(
            new Uint8Array(callerMaterial.descriptorBytes.byteLength).fill(
                0xff,
            ),
        );
        expect(runtimeMocks.readMaterial).toHaveBeenCalledExactlyOnceWith(
            expect.objectContaining({
                descriptorBytes: authenticatedDescriptor,
                materialRoot: componentMaterialRoot,
                pullChunk: mutatingPullChunk,
            }),
        );
        const streamedInput = runtimeMocks.readMaterial.mock.calls[0]?.[0] as
            | Readonly<{ readonly descriptorBytes: Uint8Array }>
            | undefined;
        expect(streamedInput?.descriptorBytes).not.toBe(
            callerMaterial.descriptorBytes,
        );
        const normalizedComponentMaterials = (
            verificationInput.transportedEvaluationKeyShareComponentMaterial as JsonRecord
        ).componentMaterials as readonly JsonRecord[];
        expect(normalizedComponentMaterials[0]).toMatchObject({
            keySwitchComponentMaterialRoot: componentMaterialRoot,
        });
    });

    it('surfaces a canonical stream rejection instead of swallowing it', async () => {
        runtimeMocks.readMaterial.mockRejectedValueOnce(
            new Error('canonical component stream rejected'),
        );

        await expect(
            prepare({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        componentMaterial(componentMaterialRoot),
                    ],
                },
                evaluationKeyShareComponentMaterialChunkSources: [
                    componentMaterialSource(
                        componentMaterialRoot,
                        [0xaa, 0xbb],
                    ),
                ],
            }),
        ).rejects.toThrow('canonical component stream rejected');
    });

    it('rejects a source for an unknown component material root', async () => {
        await expect(
            prepare({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedEvaluationKeyShareComponentMaterial: {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterialSet',
                    componentMaterials: [
                        componentMaterial(componentMaterialRoot),
                    ],
                },
                evaluationKeyShareComponentMaterialChunkSources: [
                    componentMaterialSource(
                        secondComponentMaterialRoot,
                        [0xaa, 0xbb],
                    ),
                ],
            }),
        ).rejects.toThrow(/must match exactly one transported reference/u);
    });
});
