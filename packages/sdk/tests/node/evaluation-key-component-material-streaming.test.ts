import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';

import {
    bgvCanonicalStreamFamilies,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

type JsonRecord = Record<string, unknown>;
type ChunkPullRequest = Readonly<{
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}>;
type TestComponentMaterialSource = Readonly<{
    readonly keySwitchComponentMaterialRoot: string;
    readonly proofFamily: 'relinearization-key-share';
    readonly pullChunk: Mock<
        (input: ChunkPullRequest) => Promise<ArrayBuffer | undefined>
    >;
}>;
type TestPublicEvaluationKeyMaterialSource = Readonly<{
    readonly publicEvaluationKeyMaterialRoot: string;
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

vi.mock('@sealed-lattice/wasm', async (importOriginal) => ({
    ...(await importOriginal<typeof import('@sealed-lattice/wasm')>()),
    openBgvCanonicalStreamRuntime: () => ({
        readMaterial: runtimeMocks.readMaterial,
    }),
}));

const componentMaterialRoot = '4'.repeat(128);
const secondComponentMaterialRoot = '5'.repeat(128);
const publicEvaluationKeyMaterialRoot = '7'.repeat(128);
const otherHash = '6'.repeat(128);
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
        keySwitchMaterialEncoding:
            'binary-chunked-key-switch-component-vectors',
        trusteeIdentity: 'trustee-alpha',
        trusteeRosterPosition: 0,
        keySwitchDomain: 'relinearization',
        keySwitchSeedHex: 'abcd',
        level: 0,
        ringDegree: 4,
        digitCount: 1,
        rnsLimbCount: 1,
        keySwitchComponentVectorRoot: otherHash,
        keySwitchComponentMaterialRoot,
        descriptorBytes: Uint8Array.of(0x53, 0x4c),
    }) as const;

const componentMaterialSource = (
    keySwitchComponentMaterialRoot: string,
    firstChunkBytes: readonly number[],
): TestComponentMaterialSource => {
    const chunks = [
        Uint8Array.from(firstChunkBytes).buffer,
        Uint8Array.of(1, 2).buffer,
    ] as const;

    return {
        keySwitchComponentMaterialRoot,
        proofFamily: 'relinearization-key-share',
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

const publicEvaluationKeyMaterial = {
    objectType: 'SetupTransportedPublicEvaluationKeyMaterial',
    materialEncoding: 'binary-chunked-public-evaluation-key-material',
    ceremonyId: 'ceremony-alpha',
    manifestHash: expectedManifestHash,
    rosterHash: expectedRosterHash,
    setupParametersHash: otherHash,
    setupEpoch: '0',
    evaluationKeySetHash: otherHash,
    publicEvaluationKeyMaterialRoot,
    descriptorBytes: Uint8Array.of(0x53, 0x4c, 0x45),
} as const;

const publicEvaluationKeyMaterialSource =
    (): TestPublicEvaluationKeyMaterialSource => {
        const chunks = [
            Uint8Array.of(0xaa, 0xbb).buffer,
            Uint8Array.of(0xcc, 0xdd).buffer,
        ] as const;

        return {
            publicEvaluationKeyMaterialRoot,
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

const { prepareSetupPackageVerificationInputForKernel } =
    await import('#packages/sdk/src/setup-verification-input.js');

const prepare = (input: JsonRecord): Promise<JsonRecord> =>
    prepareSetupPackageVerificationInputForKernel(
        {} as TranscriptCoreKernel,
        input as never,
    );

describe('evaluation-key component material streaming before terminal verification', () => {
    beforeEach(() => {
        runtimeMocks.readMaterial.mockReset();
        runtimeMocks.readMaterial.mockImplementation(
            async (input: CanonicalReadInput): Promise<void> => {
                await input.pullChunk({ chunkIndex: 0, expectedByteLength: 2 });
                await input.pullChunk({ chunkIndex: 1, expectedByteLength: 2 });
                await input.pullChunk({ chunkIndex: 2, expectedByteLength: 0 });
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
        await prepare({
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
        expect(firstSource.pullChunk).toHaveBeenCalledTimes(3);
        expect(secondSource.pullChunk).toHaveBeenCalledTimes(3);
        expect(
            firstSource.pullChunk.mock.calls.map(([request]) => request),
        ).toEqual([
            { chunkIndex: 0, expectedByteLength: 2 },
            { chunkIndex: 1, expectedByteLength: 2 },
            { chunkIndex: 2, expectedByteLength: 0 },
        ]);
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

    it('rejects a transported reference without its bounded source', async () => {
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
            }),
        ).rejects.toThrow(/must match exactly one transported reference/u);
    });

    it('rebuilds the public-only verify input from a bare package plus bindings', async () => {
        const verificationInput = await prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
        });

        expect(verificationInput).toEqual({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
        });
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

    it('authenticates public evaluation-key material from its separate bounded source', async () => {
        const source = publicEvaluationKeyMaterialSource();
        await prepare({
            setupPackage: { objectType: 'SetupPackage' },
            ...setupVerificationBindings,
            transportedPublicEvaluationKeyMaterial: {
                objectType: 'SetupTransportedPublicEvaluationKeyMaterialSet',
                materialEncoding:
                    'binary-chunked-public-evaluation-key-material',
                publicEvaluationKeyMaterials: [publicEvaluationKeyMaterial],
            },
            publicEvaluationKeyMaterialChunkSources: [source],
        });

        expect(runtimeMocks.readMaterial).toHaveBeenCalledWith(
            expect.objectContaining({
                descriptorBytes: publicEvaluationKeyMaterial.descriptorBytes,
                family: bgvCanonicalStreamFamilies.publicEvaluationKeyMaterial,
                materialRoot: publicEvaluationKeyMaterialRoot,
                pullChunk: source.pullChunk,
            }),
        );
        expect(source.pullChunk).toHaveBeenCalledTimes(3);
    });

    it('rejects public evaluation-key material without an exact source match', async () => {
        await expect(
            prepare({
                setupPackage: { objectType: 'SetupPackage' },
                ...setupVerificationBindings,
                transportedPublicEvaluationKeyMaterial: {
                    objectType:
                        'SetupTransportedPublicEvaluationKeyMaterialSet',
                    materialEncoding:
                        'binary-chunked-public-evaluation-key-material',
                    publicEvaluationKeyMaterials: [publicEvaluationKeyMaterial],
                },
            }),
        ).rejects.toThrow(/has no matching canonical chunk source/u);
    });
});
