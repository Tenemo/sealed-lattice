import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    hashItem,
    unsigned16Item,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableValue,
} from '../canonical-tuple-test-helpers';

import {
    createRuntimeAssetHashAccumulator,
    createRuntimeBuildManifestHashAccumulator,
    createSuiteArtifactHashAccumulator,
    createSuiteIdentifierAccumulator,
    decodeRuntimeBuildManifest,
    decodeSuiteArtifactReferences,
    proofMaskRandomnessPurposeClasses,
    proofRandomnessFamilyAssignments,
    runtimeBuildBytesToHex,
    runtimeBuildCanonicalLimits,
    type RuntimeAssetRole,
} from '#packages/wasm/src/runtime-build-canonical';
import {
    compileRuntimeBuildBootstrap,
    copyRuntimeBuildAuthorityBindingDescription,
    createRuntimeBuildKernelWorkerPreflight,
    RuntimeBuildPreflightError,
    type RuntimeBuildAuthorityBinding,
    type RuntimeBuildByteSource,
    type RuntimeBuildCache,
    type RuntimeBuildFetchResponse,
    type RuntimeBuildFetcher,
    type RuntimeBuildWorkerPreflight,
} from '#packages/wasm/src/runtime-build-preflight';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const origin = 'https://runtime.example';
const manifestPath = '/runtime-manifest.canonical';
const suiteRecordPath = '/suite.canonical';
const artifactPaths = Object.freeze(
    Array.from({ length: 6 }, (_, index) => `/artifact-${index + 1}.canonical`),
);
const textEncoder = new TextEncoder();

type PrivateRandomnessFamilyAssignmentVector = Readonly<{
    familyName: string;
    familySchemaIdentifier: number;
}>;

type PrivateRandomnessProofCoordinatesVector = Readonly<{
    privateProofSaltPurpose: number;
    maskPurposeClasses: Readonly<{
        trace: number;
        telescoping: number;
        opening: number;
    }>;
    families: readonly PrivateRandomnessFamilyAssignmentVector[];
}>;

const readPrivateRandomnessProofCoordinatesVector =
    async (): Promise<PrivateRandomnessProofCoordinatesVector> =>
        JSON.parse(
            await readFile(
                path.resolve(
                    'test-vectors',
                    'private-randomness-proof-coordinates.json',
                ),
                'utf8',
            ),
        ) as PrivateRandomnessProofCoordinatesVector;

const byteSource = (
    bytes: Uint8Array,
    chunkByteLength = 3,
): RuntimeBuildByteSource => ({
    [Symbol.asyncIterator]: (): AsyncIterator<Uint8Array> => {
        let offset = 0;
        return {
            next: (): Promise<IteratorResult<Uint8Array>> => {
                if (offset >= bytes.byteLength) {
                    return Promise.resolve({ done: true, value: undefined });
                }
                const chunk = bytes.slice(
                    offset,
                    Math.min(bytes.byteLength, offset + chunkByteLength),
                );
                offset += chunk.byteLength;
                return Promise.resolve({ done: false, value: chunk });
            },
        };
    },
});

const collectSource = async (
    source: RuntimeBuildByteSource,
): Promise<Uint8Array> => {
    const chunks: Uint8Array[] = [];
    let byteLength = 0;
    for await (const chunk of source) {
        chunks.push(chunk);
        byteLength += chunk.byteLength;
    }
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
};

const asciiListItem = (values: readonly string[]): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(0x02),
            unsigned32LittleEndian(values.length),
            ...values.map((value) => variableValue(textEncoder.encode(value))),
        ),
    );

const nestedTupleListItem = (values: readonly Uint8Array[]): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(0x09),
            unsigned32LittleEndian(values.length),
            ...values,
        ),
    );

const deriveHash = (
    accumulator: ReturnType<typeof createSuiteIdentifierAccumulator>,
    bytes: Uint8Array,
): Uint8Array => {
    accumulator.update(bytes);
    return accumulator.finish();
};

type AssetFixture = Readonly<{
    bytes: Uint8Array;
    canonicalPath: string;
    role: RuntimeAssetRole;
}>;

const assetReferenceTuple = (
    asset: AssetFixture,
    byteLength = asset.bytes.byteLength,
): Uint8Array => {
    const accumulator = createRuntimeAssetHashAccumulator({
        assetRole: asset.role,
        byteLength: BigInt(asset.bytes.byteLength),
        canonicalPath: asset.canonicalPath,
    });
    return canonicalTuple(
        0x1801,
        unsigned16Item(asset.role),
        asciiItem(asset.canonicalPath),
        unsigned64Item(BigInt(byteLength)),
        hashItem(deriveHash(accumulator, asset.bytes)),
    );
};

const suiteArtifactReferenceTuple = (
    artifactKind: number,
    bytes: Uint8Array,
    byteLength = bytes.byteLength,
): Uint8Array => {
    const accumulator = createSuiteArtifactHashAccumulator(
        artifactKind,
        BigInt(bytes.byteLength),
    );
    return canonicalTuple(
        0x0117,
        unsigned16Item(artifactKind),
        unsigned64Item(BigInt(byteLength)),
        hashItem(deriveHash(accumulator, bytes)),
    );
};

type FixtureOverrides = Readonly<{
    artifactReferenceByteLength?: number;
    artifactReferenceKind?: number;
    duplicateArtifactPath?: boolean;
    executableReferenceByteLength?: number;
    operationProfiles?: readonly Uint8Array[];
    reorderAssets?: boolean;
}>;

const operationProfileForRandomUse = (
    family: number,
    purpose: number,
): Uint8Array => {
    const randomUse = canonicalTuple(
        0x1806,
        unsigned16Item(family),
        unsigned16Item(purpose),
    );
    const boundary = canonicalTuple(
        0x1807,
        unsigned16Item(0x1610),
        nestedTupleListItem([randomUse]),
    );
    return canonicalTuple(
        0x1808,
        unsigned16Item(1),
        nestedTupleListItem([boundary]),
    );
};

const ballotAggregationCheckpointOperationProfile = (): Uint8Array => {
    const checkpointBoundary = canonicalTuple(
        0x1807,
        unsigned16Item(0x180a),
        nestedTupleListItem([]),
    );
    return canonicalTuple(
        0x1808,
        unsigned16Item(0x1404),
        nestedTupleListItem([checkpointBoundary]),
    );
};

const createFixture = (overrides: FixtureOverrides = {}) => {
    const assets: readonly AssetFixture[] = Object.freeze([
        {
            bytes: textEncoder.encode('export const application = 1;'),
            canonicalPath: '/application.js',
            role: 1,
        },
        {
            bytes: textEncoder.encode('self.onmessage = () => {};'),
            canonicalPath: '/worker.js',
            role: 2,
        },
        {
            bytes: Uint8Array.of(0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0),
            canonicalPath: '/kernel.wasm',
            role: 3,
        },
        {
            bytes: textEncoder.encode('body { color: black; }'),
            canonicalPath: '/style.css',
            role: 4,
        },
    ]);
    const artifacts = Object.freeze(
        Array.from({ length: 6 }, (_, index) =>
            textEncoder.encode(`artifact-${index + 1}`),
        ),
    );
    const artifactReferences = artifacts.map((bytes, index) =>
        suiteArtifactReferenceTuple(
            index + 1,
            bytes,
            index + 1 === (overrides.artifactReferenceKind ?? 1) &&
                overrides.artifactReferenceByteLength !== undefined
                ? overrides.artifactReferenceByteLength
                : bytes.byteLength,
        ),
    );
    const suiteRecordBytes = canonicalTuple(
        0x0118,
        unsigned16Item(2),
        ...Array.from({ length: 20 }, () => unsigned16Item(1)),
        nestedTupleListItem(artifactReferences),
    );
    const suiteIdentifier = deriveHash(
        createSuiteIdentifierAccumulator(BigInt(suiteRecordBytes.byteLength)),
        suiteRecordBytes,
    );
    const orderedAssets = overrides.reorderAssets
        ? [assets[1], assets[0], assets[2], assets[3]]
        : assets;
    const assetReferences = orderedAssets.map((asset) => {
        if (asset === undefined) {
            throw new Error('The test asset fixture is incomplete.');
        }
        return assetReferenceTuple(
            asset,
            asset.role === 1 &&
                overrides.executableReferenceByteLength !== undefined
                ? overrides.executableReferenceByteLength
                : asset.bytes.byteLength,
        );
    });
    const orderedArtifactPaths = overrides.duplicateArtifactPath
        ? [...artifactPaths.slice(0, 5), artifactPaths[0]]
        : artifactPaths;
    const manifestBytes = canonicalTuple(
        0x1802,
        unsigned16Item(1),
        asciiItem('release-1'),
        hashItem(suiteIdentifier),
        asciiItem(suiteRecordPath),
        asciiListItem(orderedArtifactPaths),
        nestedTupleListItem(assetReferences),
        nestedTupleListItem(overrides.operationProfiles ?? []),
    );
    const manifestHash = deriveHash(
        createRuntimeBuildManifestHashAccumulator(
            BigInt(manifestBytes.byteLength),
        ),
        manifestBytes,
    );
    const routes = new Map<string, Uint8Array>([
        [manifestPath, manifestBytes],
        [suiteRecordPath, suiteRecordBytes],
        ...assets.map((asset) => [asset.canonicalPath, asset.bytes] as const),
        ...artifacts.map(
            (artifactBytes, index) =>
                [artifactPaths[index], artifactBytes] as const,
        ),
    ]);
    return {
        assets,
        manifestBytes,
        manifestHash,
        manifestHashHex: runtimeBuildBytesToHex(manifestHash),
        routes,
        suiteIdentifier,
    };
};

class MemoryRuntimeBuildCache implements RuntimeBuildCache {
    readonly #namespaces = new Map<string, Map<string, Uint8Array>>();

    public deleteNamespace(namespace: string): Promise<void> {
        this.#namespaces.delete(namespace);
        return Promise.resolve();
    }

    public listPaths(namespace: string): Promise<readonly string[]> {
        return Promise.resolve(
            [...(this.#namespaces.get(namespace)?.keys() ?? [])].reverse(),
        );
    }

    public read(
        namespace: string,
        canonicalPath: string,
    ): Promise<RuntimeBuildByteSource> {
        const bytes = this.#namespaces.get(namespace)?.get(canonicalPath);
        if (bytes === undefined) {
            throw new Error(`Missing cached test path: ${canonicalPath}`);
        }
        return Promise.resolve(byteSource(bytes));
    }

    public async write(
        namespace: string,
        canonicalPath: string,
        byteLength: number,
        source: RuntimeBuildByteSource,
    ): Promise<void> {
        const bytes = await collectSource(source);
        if (bytes.byteLength !== byteLength) {
            throw new Error('The test cache observed the wrong byte length.');
        }
        let entries = this.#namespaces.get(namespace);
        if (entries === undefined) {
            entries = new Map();
            this.#namespaces.set(namespace, entries);
        }
        entries.set(canonicalPath, bytes);
    }

    public seed(
        namespace: string,
        canonicalPath: string,
        bytes: Uint8Array,
    ): void {
        this.#namespaces.set(
            namespace,
            new Map([[canonicalPath, bytes.slice()]]),
        );
    }
}

type FetchMutation = Readonly<{
    contentLength?: string;
    finalPath?: string;
    redirected?: boolean;
    substitutedBytes?: Uint8Array;
}>;

const createFetcher = (
    routes: ReadonlyMap<string, Uint8Array>,
    mutations: ReadonlyMap<string, FetchMutation> = new Map(),
): Readonly<{
    fetch: RuntimeBuildFetcher;
    fetchCounts: ReadonlyMap<string, number>;
}> => {
    const fetchCounts = new Map<string, number>();
    return {
        fetch: (exactUrl): Promise<RuntimeBuildFetchResponse> => {
            const canonicalPath = exactUrl.pathname;
            fetchCounts.set(
                canonicalPath,
                (fetchCounts.get(canonicalPath) ?? 0) + 1,
            );
            const bytes = routes.get(canonicalPath);
            if (bytes === undefined) {
                throw new Error(`Missing test route: ${canonicalPath}`);
            }
            const mutation = mutations.get(canonicalPath);
            const responseBytes = mutation?.substitutedBytes ?? bytes;
            return Promise.resolve({
                body: byteSource(responseBytes),
                contentLength:
                    mutation?.contentLength ?? String(responseBytes.byteLength),
                finalUrl: `${origin}${mutation?.finalPath ?? canonicalPath}`,
                ok: true,
                redirected: mutation?.redirected ?? false,
            });
        },
        fetchCounts,
    };
};

const createWorkerHarness = (consumeWasm = true) => {
    const observations = {
        artifactKinds: [] as number[],
        finished: 0,
        launched: 0,
        suiteRecords: 0,
        terminated: 0,
        wasmBytes: 0,
    };
    const launch = (): Promise<
        RuntimeBuildWorkerPreflight<Readonly<{ ready: true }>>
    > => {
        observations.launched += 1;
        return Promise.resolve({
            finish: (): Promise<Readonly<{ ready: true }>> => {
                observations.finished += 1;
                return Promise.resolve(Object.freeze({ ready: true }));
            },
            terminate: (): void => {
                observations.terminated += 1;
            },
            verifySuiteArtifact: async (input): Promise<void> => {
                const bytes = await collectSource(input.source);
                expect(bytes.byteLength).toBe(
                    Number(input.artifactReference.byteLength),
                );
                observations.artifactKinds.push(
                    input.artifactReference.artifactKind,
                );
            },
            verifySuiteRecord: (input): Promise<void> => {
                expect(input.artifactReferences).toHaveLength(6);
                expect(input.canonicalBytes.byteLength).toBeGreaterThan(0);
                expect(input.suiteIdentifier).toHaveLength(64);
                observations.suiteRecords += 1;
                return Promise.resolve();
            },
            verifyWasm: async (input): Promise<void> => {
                if (consumeWasm) {
                    observations.wasmBytes = (
                        await collectSource(input.source)
                    ).byteLength;
                }
            },
        });
    };
    return { launch, observations };
};

const createSemanticWorker = (input: {
    artifactStatus?: (artifactKind: number, bytes: Uint8Array) => number;
    suiteIdentifier: Uint8Array;
}) => {
    const observedArtifactKinds: number[] = [];
    let finished = 0;
    let terminated = 0;
    const worker = createRuntimeBuildKernelWorkerPreflight({
        instantiateVerifiedWasm: ({ canonicalBytes }) => {
            expect(canonicalBytes).toEqual(
                Uint8Array.of(0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0),
            );
            const memory = new WebAssembly.Memory({ initial: 1 });
            let nextPointer = 8;
            const allocate = (byteLength: number): number => {
                const pointer = nextPointer;
                nextPointer += byteLength;
                if (nextPointer > memory.buffer.byteLength) {
                    memory.grow(
                        Math.ceil(
                            (nextPointer - memory.buffer.byteLength) /
                                (64 * 1024),
                        ),
                    );
                }
                return pointer;
            };
            const deallocate = (): void => undefined;
            const kernel = {
                verifyFoundationSuiteRecord: () => ({
                    isValid: true as const,
                    value: {
                        suiteId: runtimeBuildBytesToHex(input.suiteIdentifier),
                    },
                }),
            } as unknown as TranscriptCoreKernel;
            const context = {
                allocate,
                deallocate,
                executeCommand: <Result>(): Result => {
                    throw new Error(
                        'The semantic preflight test uses no command.',
                    );
                },
                memory,
                runExclusive: <Result>(
                    _operationName: string,
                    operation: () => Result,
                ): Result => operation(),
                wasmExports: {
                    memory,
                    sealed_lattice_foundation_verify_suite_artifact: (
                        _suitePointer: number,
                        _suiteByteLength: number,
                        artifactKind: number,
                        artifactPointer: number,
                        artifactByteLength: number,
                    ): number => {
                        observedArtifactKinds.push(artifactKind);
                        return (
                            input.artifactStatus?.(
                                artifactKind,
                                new Uint8Array(
                                    memory.buffer,
                                    artifactPointer,
                                    artifactByteLength,
                                ).slice(),
                            ) ?? 0
                        );
                    },
                },
            } as unknown as TranscriptCoreKernelCommandRuntime;
            registerCommonProofKernelContext(kernel, context);
            return Promise.resolve({
                finish: (): Promise<Readonly<{ ready: true }>> => {
                    finished += 1;
                    return Promise.resolve(Object.freeze({ ready: true }));
                },
                kernel,
                terminate: (): void => {
                    terminated += 1;
                },
            });
        },
    });
    return {
        observations: {
            get finished(): number {
                return finished;
            },
            observedArtifactKinds,
            get terminated(): number {
                return terminated;
            },
        },
        worker,
    };
};

const prepareSemanticWorker = async (input: {
    artifactStatus?: (artifactKind: number, bytes: Uint8Array) => number;
    fixture: ReturnType<typeof createFixture>;
}) => {
    const harness = createSemanticWorker({
        artifactStatus: input.artifactStatus,
        suiteIdentifier: input.fixture.suiteIdentifier,
    });
    const manifest = decodeRuntimeBuildManifest(input.fixture.manifestBytes);
    const wasmReference = manifest.orderedAssets.find(
        (reference) => reference.assetRole === 3,
    );
    const wasmBytes = input.fixture.routes.get('/kernel.wasm');
    const suiteRecordBytes = input.fixture.routes.get(suiteRecordPath);
    if (
        wasmReference === undefined ||
        wasmBytes === undefined ||
        suiteRecordBytes === undefined
    ) {
        throw new Error('The semantic preflight fixture is incomplete.');
    }
    await harness.worker.verifyWasm({
        assetReference: wasmReference,
        source: byteSource(wasmBytes),
    });
    const artifactReferences = decodeSuiteArtifactReferences(suiteRecordBytes);
    await harness.worker.verifySuiteRecord({
        artifactReferences,
        canonicalBytes: suiteRecordBytes,
        suiteIdentifier: input.fixture.suiteIdentifier,
    });
    return { artifactReferences, harness };
};

const runFixture = async (input: {
    cache?: MemoryRuntimeBuildCache;
    fetcher?: ReturnType<typeof createFetcher>;
    fixture?: ReturnType<typeof createFixture>;
    workerHarness?: ReturnType<typeof createWorkerHarness>;
}) => {
    const fixture = input.fixture ?? createFixture();
    const fetcher = input.fetcher ?? createFetcher(fixture.routes);
    const cache = input.cache ?? new MemoryRuntimeBuildCache();
    const workerHarness = input.workerHarness ?? createWorkerHarness();
    const preflight = compileRuntimeBuildBootstrap({
        bootstrapOrigin: origin,
        canonicalManifestPath: manifestPath,
        runtimeBuildManifestHashHex: fixture.manifestHashHex,
    });
    const activation = await preflight({
        cache,
        fetch: fetcher.fetch,
        importVerifiedApplication: (applicationInput) => {
            expect(applicationInput.applicationBytes).toEqual(
                fixture.assets[0]?.bytes,
            );
            expect(applicationInput.localAssetBytes.get('/style.css')).toEqual(
                fixture.assets[3]?.bytes,
            );
            expect(workerHarness.observations.artifactKinds).toEqual([
                1, 2, 3, 4, 5, 6,
            ]);
            return Promise.resolve('application-imported' as const);
        },
        launchVerifiedWorker: workerHarness.launch,
    });
    return { activation, cache, fetcher, fixture, workerHarness };
};

describe('runtime build preflight', () => {
    it('semantically preflights all six suite artifacts before worker finish', async () => {
        const fixture = createFixture();
        const { artifactReferences, harness } = await prepareSemanticWorker({
            fixture,
        });
        for (const [index, artifactReference] of artifactReferences.entries()) {
            const canonicalPath = artifactPaths[index];
            const artifactBytes =
                canonicalPath === undefined
                    ? undefined
                    : fixture.routes.get(canonicalPath);
            if (canonicalPath === undefined || artifactBytes === undefined) {
                throw new Error('The suite-artifact fixture is incomplete.');
            }
            await harness.worker.verifySuiteArtifact({
                artifactReference,
                canonicalPath,
                source: byteSource(artifactBytes),
            });
        }

        await expect(harness.worker.finish()).resolves.toEqual({ ready: true });
        expect(harness.observations.observedArtifactKinds).toEqual([
            1, 2, 3, 4, 5, 6,
        ]);
        expect(harness.observations.finished).toBe(1);
        expect(harness.observations.terminated).toBe(0);
    });

    it('propagates semantic mutation refusal and keeps finish unavailable', async () => {
        const fixture = createFixture();
        const firstArtifactBytes = fixture.routes.get(artifactPaths[0] ?? '');
        if (firstArtifactBytes === undefined) {
            throw new Error('The first suite artifact is unavailable.');
        }
        const { artifactReferences, harness } = await prepareSemanticWorker({
            artifactStatus: (artifactKind, bytes) =>
                artifactKind === 1 && bytes[0] !== firstArtifactBytes[0]
                    ? 0x0006
                    : 0,
            fixture,
        });
        const mutated = firstArtifactBytes.slice();
        mutated[0] = (mutated[0] ?? 0) ^ 0xff;
        const firstReference = artifactReferences[0];
        if (firstReference === undefined) {
            throw new Error(
                'The first suite-artifact reference is unavailable.',
            );
        }
        await expect(
            harness.worker.verifySuiteArtifact({
                artifactReference: firstReference,
                canonicalPath: artifactPaths[0] ?? '',
                source: byteSource(mutated),
            }),
        ).rejects.toThrow('wrongHashOrRoot');
        await expect(harness.worker.finish()).rejects.toThrow(
            'before every suite artifact passes',
        );
        await harness.worker.terminate();
        expect(harness.observations.terminated).toBe(1);
    });

    it('parses the exact ballot aggregation checkpoint operation profile', () => {
        const fixture = createFixture({
            operationProfiles: [ballotAggregationCheckpointOperationProfile()],
        });
        const manifest = decodeRuntimeBuildManifest(fixture.manifestBytes);

        expect(manifest.operationProfiles).toHaveLength(1);
        const operationProfile = manifest.operationProfiles[0];
        expect(operationProfile?.operationKind).toBe(0x1404);
        expect(operationProfile?.safeBoundaries).toHaveLength(1);
        expect(operationProfile?.safeBoundaries[0]).toEqual({
            orderedRandomUses: [],
            stateSchemaIdentifier: 0x180a,
        });
    });

    it('matches the shared proof-family randomness coordinates', async () => {
        const vector = await readPrivateRandomnessProofCoordinatesVector();
        expect(vector.families.map((family) => family.familyName)).toEqual([
            'sameSecret',
            'publicKeyShare',
            'relinearizationRoundOne',
            'relinearizationRoundTwo',
            'galoisKeyShare',
            'ballotValidity',
            'targetShareProof',
            'vssShareLinkage',
            'aggregateThresholdShare',
        ]);
        expect(proofRandomnessFamilyAssignments).toEqual(
            vector.families.map(({ familySchemaIdentifier }) => ({
                familySchemaIdentifier,
            })),
        );
        expect(proofMaskRandomnessPurposeClasses).toEqual(
            vector.maskPurposeClasses,
        );

        for (const family of vector.families) {
            for (const purpose of [
                vector.maskPurposeClasses.trace,
                vector.maskPurposeClasses.telescoping,
                vector.maskPurposeClasses.opening,
                vector.privateProofSaltPurpose,
            ]) {
                const fixture = createFixture({
                    operationProfiles: [
                        operationProfileForRandomUse(
                            family.familySchemaIdentifier,
                            purpose,
                        ),
                    ],
                });
                expect(() =>
                    decodeRuntimeBuildManifest(fixture.manifestBytes),
                ).not.toThrow();
            }

            for (const purpose of [0, 4]) {
                const fixture = createFixture({
                    operationProfiles: [
                        operationProfileForRandomUse(
                            family.familySchemaIdentifier,
                            purpose,
                        ),
                    ],
                });
                expect(() =>
                    decodeRuntimeBuildManifest(fixture.manifestBytes),
                ).toThrow('A checkpoint random-use profile is unassigned.');
            }
        }

        for (const [family, purpose] of [
            [0x1213, 0xfffe],
            [0xffff, 1],
        ] as const) {
            const fixture = createFixture({
                operationProfiles: [
                    operationProfileForRandomUse(family, purpose),
                ],
            });
            expect(() =>
                decodeRuntimeBuildManifest(fixture.manifestBytes),
            ).toThrow('A checkpoint random-use profile is unassigned.');
        }
    });

    it('authenticates every inert fetch and cache reread before activation', async () => {
        const { activation, fetcher, fixture, workerHarness } =
            await runFixture({});

        expect(activation.application).toBe('application-imported');
        expect(activation.workerChannel).toEqual({ ready: true });
        const authorityBindingDescription =
            copyRuntimeBuildAuthorityBindingDescription(
                activation.runtimeBuildAuthorityBinding,
            );
        expect(authorityBindingDescription.runtimeBuildManifestHash).toEqual(
            fixture.manifestHash,
        );
        expect(authorityBindingDescription.suiteIdentifier).toEqual(
            fixture.suiteIdentifier,
        );
        authorityBindingDescription.runtimeBuildManifestHash.fill(0xff);
        authorityBindingDescription.suiteIdentifier.fill(0xff);
        const copiedAuthorityBindingDescription =
            copyRuntimeBuildAuthorityBindingDescription(
                activation.runtimeBuildAuthorityBinding,
            );
        expect(
            copiedAuthorityBindingDescription.runtimeBuildManifestHash,
        ).not.toEqual(authorityBindingDescription.runtimeBuildManifestHash);
        expect(copiedAuthorityBindingDescription.suiteIdentifier).not.toEqual(
            authorityBindingDescription.suiteIdentifier,
        );
        expect(() =>
            copyRuntimeBuildAuthorityBindingDescription(
                Object.freeze({}) as RuntimeBuildAuthorityBinding,
            ),
        ).toThrow(TypeError);
        expect(workerHarness.observations).toEqual({
            artifactKinds: [1, 2, 3, 4, 5, 6],
            finished: 1,
            launched: 1,
            suiteRecords: 1,
            terminated: 0,
            wasmBytes: 8,
        });
        expect([...fetcher.fetchCounts.values()]).toEqual(
            Array.from({ length: 12 }, () => 1),
        );
    });

    it('refuses a substituted asset before worker creation and clears it', async () => {
        const fixture = createFixture();
        const cache = new MemoryRuntimeBuildCache();
        const workerHarness = createWorkerHarness();
        const fetcher = createFetcher(
            fixture.routes,
            new Map([
                [
                    '/worker.js',
                    {
                        substitutedBytes: textEncoder.encode(
                            'self.onmessage = () => {0}',
                        ),
                    },
                ],
            ]),
        );

        await expect(
            runFixture({ cache, fetcher, fixture, workerHarness }),
        ).rejects.toThrow(RuntimeBuildPreflightError);
        expect(workerHarness.observations.launched).toBe(0);
        expect(await cache.listPaths(fixture.manifestHashHex)).toEqual([]);
    });

    it('refuses a stale namespace without fetching or launching', async () => {
        const fixture = createFixture();
        const cache = new MemoryRuntimeBuildCache();
        const fetcher = createFetcher(fixture.routes);
        const workerHarness = createWorkerHarness();
        cache.seed(fixture.manifestHashHex, '/stale.js', Uint8Array.of(1));

        await expect(
            runFixture({ cache, fetcher, fixture, workerHarness }),
        ).rejects.toThrow('namespace was not empty');
        expect(fetcher.fetchCounts.size).toBe(0);
        expect(workerHarness.observations.launched).toBe(0);
        expect(await cache.listPaths(fixture.manifestHashHex)).toEqual([]);
    });

    it('refuses redirects even when redirected bytes are authentic', async () => {
        const fixture = createFixture();
        const workerHarness = createWorkerHarness();
        const fetcher = createFetcher(
            fixture.routes,
            new Map([
                [
                    manifestPath,
                    { finalPath: '/mirror.canonical', redirected: true },
                ],
            ]),
        );

        await expect(
            runFixture({ fetcher, fixture, workerHarness }),
        ).rejects.toThrow('did not resolve exactly');
        expect(workerHarness.observations.launched).toBe(0);
    });

    it('terminates a worker that returns before consuming verified WASM', async () => {
        const fixture = createFixture();
        const workerHarness = createWorkerHarness(false);

        await expect(runFixture({ fixture, workerHarness })).rejects.toThrow(
            'did not consume all bytes',
        );
        expect(workerHarness.observations).toMatchObject({
            finished: 0,
            launched: 1,
            terminated: 1,
        });
    });

    it.each([
        ['reordered assets', { reorderAssets: true }],
        ['duplicate paths', { duplicateArtifactPath: true }],
    ] as const)(
        'refuses %s in a hash-pinned manifest',
        async (_, overrides) => {
            const fixture = createFixture(overrides);
            const workerHarness = createWorkerHarness();

            await expect(
                runFixture({ fixture, workerHarness }),
            ).rejects.toThrow(RuntimeBuildPreflightError);
            expect(workerHarness.observations.launched).toBe(0);
        },
    );

    it('checks small-record, executable, and artifact ceilings before allocation', async () => {
        expect(runtimeBuildCanonicalLimits).toMatchObject({
            maximumCopiedExecutableAssetByteLength: 8_388_608,
            maximumEvaluatorProgramSetArtifactByteLength: 67_108_864,
            maximumFoundationVariableValueByteLength: 8 * 1024 * 1024 - 4,
            maximumRuntimeBuildManifestByteLength: 65_536,
        });
        const ordinaryFixture = createFixture();
        const oversizedManifestFetcher = createFetcher(
            ordinaryFixture.routes,
            new Map([[manifestPath, { contentLength: '65537' }]]),
        );
        await expect(
            runFixture({
                fetcher: oversizedManifestFetcher,
                fixture: ordinaryFixture,
            }),
        ).rejects.toThrow('outside its accepted bound');

        const oversizedExecutableFixture = createFixture({
            executableReferenceByteLength: 8_388_609,
        });
        await expect(
            runFixture({ fixture: oversizedExecutableFixture }),
        ).rejects.toThrow('copied-buffer safety bound');

        const oversizedArtifactFixture = createFixture({
            artifactReferenceByteLength: 8 * 1024 * 1024 - 3,
        });
        const workerHarness = createWorkerHarness();
        await expect(
            runFixture({ fixture: oversizedArtifactFixture, workerHarness }),
        ).rejects.toThrow('outside its accepted kind or safety bounds');
        expect(workerHarness.observations.terminated).toBe(1);
    });

    it('admits the selected evaluator artifact with slack and rejects one byte beyond the safety bound', () => {
        const evaluatorProgramSetSafetyByteLength =
            runtimeBuildCanonicalLimits.maximumEvaluatorProgramSetArtifactByteLength;
        expect(() =>
            createSuiteArtifactHashAccumulator(5, 20_270_968n),
        ).not.toThrow();
        expect(() =>
            createSuiteArtifactHashAccumulator(
                5,
                BigInt(evaluatorProgramSetSafetyByteLength),
            ),
        ).not.toThrow();
        expect(() =>
            createSuiteArtifactHashAccumulator(
                5,
                BigInt(evaluatorProgramSetSafetyByteLength + 1),
            ),
        ).toThrow('canonical safety bound');
        const selectedEvaluatorFixture = createFixture({
            artifactReferenceByteLength: 20_270_968,
            artifactReferenceKind: 5,
        });

        const references = decodeSuiteArtifactReferences(
            selectedEvaluatorFixture.routes.get(suiteRecordPath) ??
                new Uint8Array(0),
        );
        expect(references[4]).toMatchObject({
            artifactKind: 5,
            byteLength: 20_270_968n,
        });

        const oversizedEvaluatorFixture = createFixture({
            artifactReferenceByteLength:
                evaluatorProgramSetSafetyByteLength + 1,
            artifactReferenceKind: 5,
        });
        expect(() =>
            decodeSuiteArtifactReferences(
                oversizedEvaluatorFixture.routes.get(suiteRecordPath) ??
                    new Uint8Array(0),
            ),
        ).toThrow('outside its accepted kind or safety bounds');
    });

    it('uses the evaluator artifact bound for streamed response admission', async () => {
        const evaluatorProgramSetSafetyByteLength =
            runtimeBuildCanonicalLimits.maximumEvaluatorProgramSetArtifactByteLength;
        const evaluatorArtifactPath = artifactPaths[4];
        if (evaluatorArtifactPath === undefined) {
            throw new Error('The evaluator artifact test path is unavailable.');
        }
        const fixture = createFixture();
        const acceptedBoundaryFetcher = createFetcher(
            fixture.routes,
            new Map([
                [
                    evaluatorArtifactPath,
                    {
                        contentLength: String(
                            evaluatorProgramSetSafetyByteLength,
                        ),
                    },
                ],
            ]),
        );
        await expect(
            runFixture({ fetcher: acceptedBoundaryFetcher, fixture }),
        ).rejects.toThrow('wrong declared length');

        const rejectedBoundaryFetcher = createFetcher(
            fixture.routes,
            new Map([
                [
                    evaluatorArtifactPath,
                    {
                        contentLength: String(
                            evaluatorProgramSetSafetyByteLength + 1,
                        ),
                    },
                ],
            ]),
        );
        await expect(
            runFixture({ fetcher: rejectedBoundaryFetcher, fixture }),
        ).rejects.toThrow('outside its accepted bound');
    });
});
