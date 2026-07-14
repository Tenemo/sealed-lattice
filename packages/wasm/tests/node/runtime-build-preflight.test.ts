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
    runtimeBuildBytesToHex,
    type RuntimeAssetRole,
} from '#packages/wasm/src/runtime-build-canonical';
import {
    compileRuntimeBuildBootstrap,
    RuntimeBuildPreflightError,
    type RuntimeBuildByteSource,
    type RuntimeBuildCache,
    type RuntimeBuildFetchResponse,
    type RuntimeBuildFetcher,
    type RuntimeBuildWorkerPreflight,
} from '#packages/wasm/src/runtime-build-preflight';

const origin = 'https://runtime.example';
const manifestPath = '/runtime-manifest.canonical';
const suiteRecordPath = '/suite.canonical';
const artifactPaths = Object.freeze(
    Array.from({ length: 6 }, (_, index) => `/artifact-${index + 1}.canonical`),
);
const textEncoder = new TextEncoder();

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
    duplicateArtifactPath?: boolean;
    executableReferenceByteLength?: number;
    reorderAssets?: boolean;
}>;

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
            index === 0 && overrides.artifactReferenceByteLength !== undefined
                ? overrides.artifactReferenceByteLength
                : bytes.byteLength,
        ),
    );
    const suiteRecordBytes = canonicalTuple(
        0x0118,
        ...Array.from({ length: 26 }, () => unsigned16Item(1)),
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
        nestedTupleListItem([]),
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
    it('authenticates every inert fetch and cache reread before activation', async () => {
        const { activation, fetcher, workerHarness } = await runFixture({});

        expect(activation.application).toBe('application-imported');
        expect(activation.workerChannel).toEqual({ ready: true });
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
            executableReferenceByteLength: 1_572_865,
        });
        await expect(
            runFixture({ fixture: oversizedExecutableFixture }),
        ).rejects.toThrow('copied-buffer ceiling');

        const oversizedArtifactFixture = createFixture({
            artifactReferenceByteLength: 8 * 1024 * 1024 - 3,
        });
        const workerHarness = createWorkerHarness();
        await expect(
            runFixture({ fixture: oversizedArtifactFixture, workerHarness }),
        ).rejects.toThrow('outside its accepted profile');
        expect(workerHarness.observations.terminated).toBe(1);
    });
});
