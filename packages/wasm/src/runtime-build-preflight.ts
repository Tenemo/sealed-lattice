import {
    createRuntimeAssetHashAccumulator,
    createRuntimeBuildManifestHashAccumulator,
    createSuiteArtifactHashAccumulator,
    createSuiteIdentifierAccumulator,
    decodeRuntimeBuildManifest,
    decodeSuiteArtifactReferences,
    maximumSuiteArtifactByteLengthForKind,
    requireCanonicalRuntimePath,
    runtimeBuildBytesEqual,
    runtimeBuildBytesToHex,
    runtimeBuildCanonicalLimits,
    runtimeBuildHexToBytes,
    type RuntimeAssetReference,
    type RuntimeBuildHashAccumulator,
    type RuntimeBuildManifest,
    type SuiteArtifactReference,
} from './runtime-build-canonical.js';

export class RuntimeBuildPreflightError extends Error {
    public readonly cause: unknown;

    public constructor(message: string, cause?: unknown) {
        super(message);
        this.cause = cause;
        this.name = 'RuntimeBuildPreflightError';
    }
}

export type RuntimeBuildByteSource = AsyncIterable<Uint8Array>;

export type RuntimeBuildCache = Readonly<{
    deleteNamespace(namespace: string): Promise<void>;
    listPaths(namespace: string): Promise<readonly string[]>;
    read(
        namespace: string,
        canonicalPath: string,
    ): Promise<RuntimeBuildByteSource>;
    write(
        namespace: string,
        canonicalPath: string,
        byteLength: number,
        source: RuntimeBuildByteSource,
    ): Promise<void>;
}>;

export type RuntimeBuildFetchResponse = Readonly<{
    body: RuntimeBuildByteSource;
    contentLength: string | null;
    finalUrl: string;
    ok: boolean;
    redirected: boolean;
}>;

export type RuntimeBuildFetcher = (
    exactUrl: URL,
) => Promise<RuntimeBuildFetchResponse>;

export type RuntimeBuildWorkerPreflight<WorkerChannel> = Readonly<{
    finish(): Promise<WorkerChannel>;
    terminate(): Promise<void> | void;
    verifySuiteArtifact(input: {
        artifactReference: SuiteArtifactReference;
        canonicalPath: string;
        source: RuntimeBuildByteSource;
    }): Promise<void>;
    verifySuiteRecord(input: {
        artifactReferences: readonly SuiteArtifactReference[];
        canonicalBytes: Uint8Array;
        suiteIdentifier: Uint8Array;
    }): Promise<void>;
    verifyWasm(input: {
        assetReference: RuntimeAssetReference;
        source: RuntimeBuildByteSource;
    }): Promise<void>;
}>;

declare const runtimeBuildAuthorityBindingBrand: unique symbol;

export type RuntimeBuildAuthorityBinding = Readonly<{
    readonly [runtimeBuildAuthorityBindingBrand]: true;
}>;

export type RuntimeBuildAuthorityBindingDescription = Readonly<{
    runtimeBuildManifestHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

const runtimeBuildAuthorityBindingDescriptions = new WeakMap<
    object,
    RuntimeBuildAuthorityBindingDescription
>();

const mintRuntimeBuildAuthorityBinding = (
    runtimeBuildManifestHash: Uint8Array,
    suiteIdentifier: Uint8Array,
): RuntimeBuildAuthorityBinding => {
    const binding = Object.freeze(
        Object.create(null) as object,
    ) as RuntimeBuildAuthorityBinding;
    runtimeBuildAuthorityBindingDescriptions.set(
        binding,
        Object.freeze({
            runtimeBuildManifestHash: runtimeBuildManifestHash.slice(),
            suiteIdentifier: suiteIdentifier.slice(),
        }),
    );
    return binding;
};

export const copyRuntimeBuildAuthorityBindingDescription = (
    binding: RuntimeBuildAuthorityBinding,
): RuntimeBuildAuthorityBindingDescription => {
    if (
        (typeof binding !== 'object' && typeof binding !== 'function') ||
        binding === null
    ) {
        throw new TypeError(
            'The runtime-build authority binding was not issued by a completed runtime preflight.',
        );
    }
    const description = runtimeBuildAuthorityBindingDescriptions.get(binding);
    if (description === undefined) {
        throw new TypeError(
            'The runtime-build authority binding was not issued by a completed runtime preflight.',
        );
    }
    return Object.freeze({
        runtimeBuildManifestHash: description.runtimeBuildManifestHash.slice(),
        suiteIdentifier: description.suiteIdentifier.slice(),
    });
};

export type RuntimeBuildActivation<WorkerChannel, Application> = Readonly<{
    application: Application;
    manifest: RuntimeBuildManifest;
    runtimeBuildAuthorityBinding: RuntimeBuildAuthorityBinding;
    workerChannel: WorkerChannel;
}>;

export type RuntimeBuildPreflightEnvironment<WorkerChannel, Application> =
    Readonly<{
        cache: RuntimeBuildCache;
        fetch: RuntimeBuildFetcher;
        importVerifiedApplication(input: {
            applicationBytes: Uint8Array;
            localAssetBytes: ReadonlyMap<string, Uint8Array>;
            manifest: RuntimeBuildManifest;
            workerChannel: WorkerChannel;
        }): Promise<Application>;
        launchVerifiedWorker(
            workerBytes: Uint8Array,
        ): Promise<RuntimeBuildWorkerPreflight<WorkerChannel>>;
    }>;

export type RuntimeBuildBootstrapPin = Readonly<{
    bootstrapOrigin: string;
    canonicalManifestPath: string;
    runtimeBuildManifestHashHex: string;
}>;

const fail = (message: string, cause?: unknown): never => {
    throw new RuntimeBuildPreflightError(message, cause);
};

const requireBootstrapOrigin = (value: string): string => {
    let parsed: URL;
    try {
        parsed = new URL(value);
    } catch (error) {
        return fail(
            'The runtime bootstrap origin is not an absolute URL.',
            error,
        );
    }
    if (
        parsed.origin === 'null' ||
        parsed.pathname !== '/' ||
        parsed.search !== '' ||
        parsed.hash !== '' ||
        parsed.username !== '' ||
        parsed.password !== ''
    ) {
        return fail('The runtime bootstrap origin is not canonical.');
    }
    return parsed.origin;
};

const parseContentLength = (
    value: string | null,
    maximumByteLength: number,
): number => {
    if (value === null || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
        return fail('A runtime response lacks a canonical Content-Length.');
    }
    const byteLength = Number(value);
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength <= 0 ||
        byteLength > maximumByteLength
    ) {
        return fail('A runtime response length is outside its accepted bound.');
    }
    return byteLength;
};

const requireExactResponse = (
    response: RuntimeBuildFetchResponse,
    expectedUrl: URL,
): void => {
    let finalUrl: URL;
    try {
        finalUrl = new URL(response.finalUrl);
    } catch (error) {
        return fail('A runtime response has an invalid final URL.', error);
    }
    if (
        !response.ok ||
        response.redirected ||
        finalUrl.origin !== expectedUrl.origin ||
        finalUrl.pathname !== expectedUrl.pathname ||
        finalUrl.search !== '' ||
        finalUrl.hash !== '' ||
        finalUrl.username !== '' ||
        finalUrl.password !== ''
    ) {
        return fail(
            `The runtime response did not resolve exactly to ${expectedUrl.pathname}.`,
        );
    }
};

const copyChunk = (chunk: Uint8Array): Uint8Array => {
    if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) {
        return fail('A runtime byte stream contains an invalid chunk.');
    }
    return chunk.slice();
};

const collectBoundedSource = async (
    source: RuntimeBuildByteSource,
    expectedByteLength: number,
): Promise<Uint8Array> => {
    const bytes = new Uint8Array(expectedByteLength);
    let offset = 0;
    for await (const untrustedChunk of source) {
        const chunk = copyChunk(untrustedChunk);
        if (chunk.byteLength > expectedByteLength - offset) {
            return fail('A runtime byte stream exceeds its declared length.');
        }
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    if (offset !== expectedByteLength) {
        return fail(
            'A runtime byte stream is shorter than its declared length.',
        );
    }
    return bytes;
};

const streamIntoCache = async (input: {
    accumulator: RuntimeBuildHashAccumulator;
    byteLength: number;
    cache: RuntimeBuildCache;
    canonicalPath: string;
    expectedHash: Uint8Array;
    namespace: string;
    source: RuntimeBuildByteSource;
}): Promise<void> => {
    let observedByteLength = 0;
    const authenticatedSource = (async function* (): RuntimeBuildByteSource {
        for await (const untrustedChunk of input.source) {
            const chunk = copyChunk(untrustedChunk);
            if (chunk.byteLength > input.byteLength - observedByteLength) {
                return fail(
                    `Runtime bytes for ${input.canonicalPath} exceed their declared length.`,
                );
            }
            observedByteLength += chunk.byteLength;
            input.accumulator.update(chunk);
            yield chunk;
        }
    })();
    await input.cache.write(
        input.namespace,
        input.canonicalPath,
        input.byteLength,
        authenticatedSource,
    );
    const observedHash = input.accumulator.finish();
    if (
        observedByteLength !== input.byteLength ||
        !runtimeBuildBytesEqual(observedHash, input.expectedHash)
    ) {
        return fail(
            `Runtime bytes for ${input.canonicalPath} do not match their authenticated reference.`,
        );
    }
};

const fetchIntoCache = async (input: {
    accumulator: RuntimeBuildHashAccumulator;
    cache: RuntimeBuildCache;
    canonicalPath: string;
    expectedByteLength: number;
    expectedHash: Uint8Array;
    fetch: RuntimeBuildFetcher;
    maximumByteLength: number;
    namespace: string;
    origin: string;
}): Promise<void> => {
    const expectedUrl = new URL(input.canonicalPath, input.origin);
    const response = await input.fetch(expectedUrl);
    requireExactResponse(response, expectedUrl);
    const declaredByteLength = parseContentLength(
        response.contentLength,
        input.maximumByteLength,
    );
    if (declaredByteLength !== input.expectedByteLength) {
        return fail(
            `Runtime bytes for ${input.canonicalPath} have the wrong declared length.`,
        );
    }
    await streamIntoCache({
        accumulator: input.accumulator,
        byteLength: declaredByteLength,
        cache: input.cache,
        canonicalPath: input.canonicalPath,
        expectedHash: input.expectedHash,
        namespace: input.namespace,
        source: response.body,
    });
};

const readAuthenticatedCache = async (input: {
    accumulator: RuntimeBuildHashAccumulator;
    byteLength: number;
    cache: RuntimeBuildCache;
    canonicalPath: string;
    expectedHash: Uint8Array;
    namespace: string;
}): Promise<Uint8Array> => {
    const source = await input.cache.read(input.namespace, input.canonicalPath);
    const bytes = await collectBoundedSource(source, input.byteLength);
    input.accumulator.update(bytes);
    if (
        !runtimeBuildBytesEqual(input.accumulator.finish(), input.expectedHash)
    ) {
        return fail(
            `Cached runtime bytes for ${input.canonicalPath} fail authentication.`,
        );
    }
    return bytes;
};

const createAuthenticatedCacheStream = async (input: {
    accumulator: RuntimeBuildHashAccumulator;
    byteLength: number;
    cache: RuntimeBuildCache;
    canonicalPath: string;
    expectedHash: Uint8Array;
    namespace: string;
}): Promise<
    Readonly<{
        assertConsumed(): void;
        source: RuntimeBuildByteSource;
    }>
> => {
    const cachedSource = await input.cache.read(
        input.namespace,
        input.canonicalPath,
    );
    let observedByteLength = 0;
    let consumed = false;
    const source = (async function* (): RuntimeBuildByteSource {
        for await (const untrustedChunk of cachedSource) {
            const chunk = copyChunk(untrustedChunk);
            if (chunk.byteLength > input.byteLength - observedByteLength) {
                return fail(
                    `Cached runtime bytes for ${input.canonicalPath} exceed their declared length.`,
                );
            }
            observedByteLength += chunk.byteLength;
            input.accumulator.update(chunk);
            yield chunk;
        }
        if (
            observedByteLength !== input.byteLength ||
            !runtimeBuildBytesEqual(
                input.accumulator.finish(),
                input.expectedHash,
            )
        ) {
            return fail(
                `Cached runtime bytes for ${input.canonicalPath} fail authentication.`,
            );
        }
        consumed = true;
    })();
    return Object.freeze({
        assertConsumed: (): void => {
            if (!consumed) {
                fail(
                    `The preflight worker did not consume all bytes for ${input.canonicalPath}.`,
                );
            }
        },
        source,
    });
};

const requireExactInventory = async (
    cache: RuntimeBuildCache,
    namespace: string,
    expectedPaths: readonly string[],
): Promise<void> => {
    const observedPaths = [...(await cache.listPaths(namespace))].sort();
    const canonicalExpectedPaths = [...expectedPaths].sort();
    if (
        observedPaths.length !== canonicalExpectedPaths.length ||
        observedPaths.some(
            (observedPath, index) =>
                observedPath !== canonicalExpectedPaths[index],
        )
    ) {
        return fail(
            'The runtime cache contains a missing, extra, stale, or mixed entry.',
        );
    }
};

const fetchSmallCanonicalRecord = async (input: {
    cache: RuntimeBuildCache;
    canonicalPath: string;
    fetch: RuntimeBuildFetcher;
    maximumByteLength: number;
    namespace: string;
    origin: string;
}): Promise<Uint8Array> => {
    const expectedUrl = new URL(input.canonicalPath, input.origin);
    const response = await input.fetch(expectedUrl);
    requireExactResponse(response, expectedUrl);
    const byteLength = parseContentLength(
        response.contentLength,
        input.maximumByteLength,
    );
    const bytes = await collectBoundedSource(response.body, byteLength);
    const singleChunkSource: RuntimeBuildByteSource = {
        [Symbol.asyncIterator]: (): AsyncIterator<Uint8Array> => {
            let consumed = false;
            return {
                next: (): Promise<IteratorResult<Uint8Array>> => {
                    if (consumed) {
                        return Promise.resolve({
                            done: true,
                            value: undefined,
                        });
                    }
                    consumed = true;
                    return Promise.resolve({ done: false, value: bytes });
                },
            };
        },
    };
    await input.cache.write(
        input.namespace,
        input.canonicalPath,
        byteLength,
        singleChunkSource,
    );
    return bytes;
};

const runtimeAssetByRole = (
    manifest: RuntimeBuildManifest,
    assetRole: RuntimeAssetReference['assetRole'],
): RuntimeAssetReference => {
    const asset = manifest.orderedAssets.find(
        (candidate) => candidate.assetRole === assetRole,
    );
    if (asset === undefined) {
        return fail(`The runtime manifest lacks asset role ${assetRole}.`);
    }
    return asset;
};

const cleanupAfterFailure = async (
    cache: RuntimeBuildCache,
    namespace: string,
    worker: RuntimeBuildWorkerPreflight<unknown> | undefined,
    originalError: unknown,
): Promise<never> => {
    const cleanupErrors: unknown[] = [];
    if (worker !== undefined) {
        try {
            await worker.terminate();
        } catch (error) {
            cleanupErrors.push(error);
        }
    }
    try {
        await cache.deleteNamespace(namespace);
    } catch (error) {
        cleanupErrors.push(error);
    }
    if (cleanupErrors.length > 0) {
        return fail(
            'Runtime preflight failed and deterministic cleanup also failed.',
            { cleanupErrors, originalError },
        );
    }
    if (originalError instanceof RuntimeBuildPreflightError) {
        throw originalError;
    }
    return fail(
        originalError instanceof Error
            ? `Runtime preflight failed: ${originalError.message}`
            : 'Runtime preflight failed.',
        originalError,
    );
};

export const compileRuntimeBuildBootstrap = (
    pin: RuntimeBuildBootstrapPin,
): (<WorkerChannel, Application>(
    environment: RuntimeBuildPreflightEnvironment<WorkerChannel, Application>,
) => Promise<RuntimeBuildActivation<WorkerChannel, Application>>) => {
    const origin = requireBootstrapOrigin(pin.bootstrapOrigin);
    const canonicalManifestPath = requireCanonicalRuntimePath(
        pin.canonicalManifestPath,
    );
    const expectedManifestHash = runtimeBuildHexToBytes(
        pin.runtimeBuildManifestHashHex,
        runtimeBuildCanonicalLimits.hashByteLength,
    );
    const namespace = runtimeBuildBytesToHex(expectedManifestHash);

    return async <WorkerChannel, Application>(
        environment: RuntimeBuildPreflightEnvironment<
            WorkerChannel,
            Application
        >,
    ): Promise<RuntimeBuildActivation<WorkerChannel, Application>> => {
        let worker: RuntimeBuildWorkerPreflight<WorkerChannel> | undefined;
        try {
            if ((await environment.cache.listPaths(namespace)).length !== 0) {
                return fail(
                    'The runtime cache namespace was not empty before preflight.',
                );
            }

            const manifestBytes = await fetchSmallCanonicalRecord({
                cache: environment.cache,
                canonicalPath: canonicalManifestPath,
                fetch: environment.fetch,
                maximumByteLength:
                    runtimeBuildCanonicalLimits.maximumRuntimeBuildManifestByteLength,
                namespace,
                origin,
            });
            const manifestHashAccumulator =
                createRuntimeBuildManifestHashAccumulator(
                    BigInt(manifestBytes.byteLength),
                );
            manifestHashAccumulator.update(manifestBytes);
            if (
                !runtimeBuildBytesEqual(
                    manifestHashAccumulator.finish(),
                    expectedManifestHash,
                )
            ) {
                return fail(
                    'The runtime manifest does not match the bootstrap trust root.',
                );
            }
            const manifest = decodeRuntimeBuildManifest(manifestBytes);

            for (const asset of manifest.orderedAssets) {
                await fetchIntoCache({
                    accumulator: createRuntimeAssetHashAccumulator(asset),
                    cache: environment.cache,
                    canonicalPath: asset.canonicalPath,
                    expectedByteLength: Number(asset.byteLength),
                    expectedHash: asset.assetHash,
                    fetch: environment.fetch,
                    maximumByteLength:
                        runtimeBuildCanonicalLimits.maximumFoundationVariableValueByteLength,
                    namespace,
                    origin,
                });
            }
            await requireExactInventory(environment.cache, namespace, [
                canonicalManifestPath,
                ...manifest.orderedAssets.map((asset) => asset.canonicalPath),
            ]);

            const workerAsset = runtimeAssetByRole(manifest, 2);
            const workerBytes = await readAuthenticatedCache({
                accumulator: createRuntimeAssetHashAccumulator(workerAsset),
                byteLength: Number(workerAsset.byteLength),
                cache: environment.cache,
                canonicalPath: workerAsset.canonicalPath,
                expectedHash: workerAsset.assetHash,
                namespace,
            });
            worker = await environment.launchVerifiedWorker(workerBytes);

            const wasmAsset = runtimeAssetByRole(manifest, 3);
            const wasmStream = await createAuthenticatedCacheStream({
                accumulator: createRuntimeAssetHashAccumulator(wasmAsset),
                byteLength: Number(wasmAsset.byteLength),
                cache: environment.cache,
                canonicalPath: wasmAsset.canonicalPath,
                expectedHash: wasmAsset.assetHash,
                namespace,
            });
            await worker.verifyWasm({
                assetReference: wasmAsset,
                source: wasmStream.source,
            });
            wasmStream.assertConsumed();

            const suiteRecordBytes = await fetchSmallCanonicalRecord({
                cache: environment.cache,
                canonicalPath: manifest.suiteRecordPath,
                fetch: environment.fetch,
                maximumByteLength:
                    runtimeBuildCanonicalLimits.maximumRuntimeBuildManifestByteLength,
                namespace,
                origin,
            });
            const suiteIdentifierAccumulator = createSuiteIdentifierAccumulator(
                BigInt(suiteRecordBytes.byteLength),
            );
            suiteIdentifierAccumulator.update(suiteRecordBytes);
            if (
                !runtimeBuildBytesEqual(
                    suiteIdentifierAccumulator.finish(),
                    manifest.suiteIdentifier,
                )
            ) {
                return fail(
                    'The suite record does not match the runtime manifest.',
                );
            }
            const artifactReferences =
                decodeSuiteArtifactReferences(suiteRecordBytes);
            await worker.verifySuiteRecord({
                artifactReferences,
                canonicalBytes: suiteRecordBytes,
                suiteIdentifier: manifest.suiteIdentifier,
            });

            for (const [
                artifactIndex,
                artifactReference,
            ] of artifactReferences.entries()) {
                const canonicalPath =
                    manifest.orderedSuiteArtifactPaths[artifactIndex];
                if (canonicalPath === undefined) {
                    return fail(
                        'The runtime manifest lacks a suite artifact path.',
                    );
                }
                await fetchIntoCache({
                    accumulator: createSuiteArtifactHashAccumulator(
                        artifactReference.artifactKind,
                        artifactReference.byteLength,
                    ),
                    cache: environment.cache,
                    canonicalPath,
                    expectedByteLength: Number(artifactReference.byteLength),
                    expectedHash: artifactReference.artifactHash,
                    fetch: environment.fetch,
                    maximumByteLength: maximumSuiteArtifactByteLengthForKind(
                        artifactReference.artifactKind,
                    ),
                    namespace,
                    origin,
                });
                const artifactStream = await createAuthenticatedCacheStream({
                    accumulator: createSuiteArtifactHashAccumulator(
                        artifactReference.artifactKind,
                        artifactReference.byteLength,
                    ),
                    byteLength: Number(artifactReference.byteLength),
                    cache: environment.cache,
                    canonicalPath,
                    expectedHash: artifactReference.artifactHash,
                    namespace,
                });
                await worker.verifySuiteArtifact({
                    artifactReference,
                    canonicalPath,
                    source: artifactStream.source,
                });
                artifactStream.assertConsumed();
            }

            await requireExactInventory(environment.cache, namespace, [
                canonicalManifestPath,
                manifest.suiteRecordPath,
                ...manifest.orderedSuiteArtifactPaths,
                ...manifest.orderedAssets.map((asset) => asset.canonicalPath),
            ]);

            const applicationAsset = runtimeAssetByRole(manifest, 1);
            const applicationBytes = await readAuthenticatedCache({
                accumulator:
                    createRuntimeAssetHashAccumulator(applicationAsset),
                byteLength: Number(applicationAsset.byteLength),
                cache: environment.cache,
                canonicalPath: applicationAsset.canonicalPath,
                expectedHash: applicationAsset.assetHash,
                namespace,
            });
            const localAssetBytes = new Map<string, Uint8Array>();
            for (const localAsset of manifest.orderedAssets.filter(
                (asset) => asset.assetRole === 4,
            )) {
                localAssetBytes.set(
                    localAsset.canonicalPath,
                    await readAuthenticatedCache({
                        accumulator:
                            createRuntimeAssetHashAccumulator(localAsset),
                        byteLength: Number(localAsset.byteLength),
                        cache: environment.cache,
                        canonicalPath: localAsset.canonicalPath,
                        expectedHash: localAsset.assetHash,
                        namespace,
                    }),
                );
            }
            const workerChannel = await worker.finish();
            const application = await environment.importVerifiedApplication({
                applicationBytes,
                localAssetBytes,
                manifest,
                workerChannel,
            });
            const runtimeBuildAuthorityBinding =
                mintRuntimeBuildAuthorityBinding(
                    expectedManifestHash,
                    manifest.suiteIdentifier,
                );
            return Object.freeze({
                application,
                manifest,
                runtimeBuildAuthorityBinding,
                workerChannel,
            });
        } catch (error) {
            return cleanupAfterFailure(
                environment.cache,
                namespace,
                worker,
                error,
            );
        }
    };
};

const responseBodySource = (response: Response): RuntimeBuildByteSource => {
    if (response.body === null) {
        return fail('A runtime response has no readable body.');
    }
    const reader = response.body.getReader();
    return (async function* (): RuntimeBuildByteSource {
        try {
            while (true) {
                const result = await reader.read();
                if (result.done) {
                    return;
                }
                yield result.value;
            }
        } finally {
            reader.releaseLock();
        }
    })();
};

export const createBrowserRuntimeBuildFetcher = (
    fetchImplementation: typeof fetch = globalThis.fetch,
): RuntimeBuildFetcher => {
    return async (exactUrl): Promise<RuntimeBuildFetchResponse> => {
        const response = await fetchImplementation(exactUrl, {
            cache: 'no-store',
            credentials: 'same-origin',
            redirect: 'error',
        });
        return Object.freeze({
            body: responseBodySource(response),
            contentLength: response.headers.get('Content-Length'),
            finalUrl: response.url,
            ok: response.ok,
            redirected: response.redirected,
        });
    };
};

const runtimeCacheName = (namespace: string): string =>
    `sealed-lattice-runtime-build-${namespace}`;

export const openBrowserRuntimeBuildCache = (input: {
    bootstrapOrigin: string;
    cacheStorage?: CacheStorage;
}): RuntimeBuildCache => {
    const origin = requireBootstrapOrigin(input.bootstrapOrigin);
    const cacheStorage = input.cacheStorage ?? globalThis.caches;
    return Object.freeze({
        deleteNamespace: async (namespace): Promise<void> => {
            await cacheStorage.delete(runtimeCacheName(namespace));
        },
        listPaths: async (namespace): Promise<readonly string[]> => {
            const cache = await cacheStorage.open(runtimeCacheName(namespace));
            const requests = await cache.keys();
            return Object.freeze(
                requests.map((request) => {
                    const url = new URL(request.url);
                    if (
                        url.origin !== origin ||
                        url.search !== '' ||
                        url.hash !== ''
                    ) {
                        return fail(
                            'The runtime cache contains an entry outside the bootstrap origin.',
                        );
                    }
                    return requireCanonicalRuntimePath(url.pathname);
                }),
            );
        },
        read: async (
            namespace,
            canonicalPath,
        ): Promise<RuntimeBuildByteSource> => {
            requireCanonicalRuntimePath(canonicalPath);
            const cache = await cacheStorage.open(runtimeCacheName(namespace));
            const response = await cache.match(new URL(canonicalPath, origin));
            if (response === undefined) {
                return fail(`The runtime cache lacks ${canonicalPath}.`);
            }
            return responseBodySource(response);
        },
        write: async (
            namespace,
            canonicalPath,
            byteLength,
            source,
        ): Promise<void> => {
            requireCanonicalRuntimePath(canonicalPath);
            const iterator = source[Symbol.asyncIterator]();
            const readableStream = new ReadableStream<Uint8Array>({
                cancel: async (): Promise<void> => {
                    await iterator.return?.();
                },
                pull: async (controller): Promise<void> => {
                    try {
                        const result = await iterator.next();
                        if (result.done) {
                            controller.close();
                        } else {
                            controller.enqueue(result.value);
                        }
                    } catch (error) {
                        controller.error(error);
                    }
                },
            });
            const cache = await cacheStorage.open(runtimeCacheName(namespace));
            await cache.put(
                new URL(canonicalPath, origin),
                new Response(readableStream, {
                    headers: { 'Content-Length': String(byteLength) },
                }),
            );
        },
    });
};
