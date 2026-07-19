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
} from '../canonical-tuple-test-helpers.js';

import {
    createRuntimeAssetHashAccumulator,
    createRuntimeBuildManifestHashAccumulator,
    createSuiteIdentifierAccumulator,
    runtimeBuildBytesToHex,
    type RuntimeAssetRole,
} from '#packages/wasm/src/runtime-build-canonical';
import {
    compileRuntimeBuildBootstrap,
    type RuntimeBuildActivation,
    type RuntimeBuildByteSource,
    type RuntimeBuildCache,
    type RuntimeBuildFetchResponse,
    type RuntimeBuildWorkerPreflight,
} from '#packages/wasm/src/runtime-build-preflight';
import { createCanonicalSuiteRecordFixture } from '#packages/wasm/tests/support/canonical-suite-record-fixture';

const fixtureOrigin = 'https://runtime-authority.example';
const fixtureManifestPath = '/runtime-manifest.canonical';
const fixtureSuiteRecordPath = '/suite.canonical';
const fixtureArtifactPaths = Object.freeze(
    Array.from(
        { length: 6 },
        (_unused, artifactIndex) =>
            `/artifact-${String(artifactIndex + 1)}.canonical`,
    ),
);
const textEncoder = new TextEncoder();

type RuntimeAssetFixture = Readonly<{
    bytes: Uint8Array;
    canonicalPath: string;
    role: RuntimeAssetRole;
}>;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

const byteSource = (bytes: Uint8Array): RuntimeBuildByteSource => ({
    [Symbol.asyncIterator]: (): AsyncIterator<Uint8Array> => {
        let byteOffset = 0;
        return {
            next: (): Promise<IteratorResult<Uint8Array>> => {
                if (byteOffset >= bytes.byteLength) {
                    return Promise.resolve({ done: true, value: undefined });
                }
                const chunk = bytes.slice(
                    byteOffset,
                    Math.min(byteOffset + 3, bytes.byteLength),
                );
                byteOffset += chunk.byteLength;
                return Promise.resolve({ done: false, value: chunk });
            },
        };
    },
});

const collectSource = async (
    source: RuntimeBuildByteSource,
): Promise<Uint8Array> => {
    const chunks: Uint8Array[] = [];
    let totalByteLength = 0;
    for await (const chunk of source) {
        chunks.push(chunk);
        totalByteLength += chunk.byteLength;
    }
    const bytes = new Uint8Array(totalByteLength);
    let byteOffset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, byteOffset);
        byteOffset += chunk.byteLength;
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

const runtimeAssetReferenceTuple = (asset: RuntimeAssetFixture): Uint8Array => {
    const accumulator = createRuntimeAssetHashAccumulator({
        assetRole: asset.role,
        byteLength: BigInt(asset.bytes.byteLength),
        canonicalPath: asset.canonicalPath,
    });
    return canonicalTuple(
        0x1801,
        unsigned16Item(asset.role),
        asciiItem(asset.canonicalPath),
        unsigned64Item(BigInt(asset.bytes.byteLength)),
        hashItem(deriveHash(accumulator, asset.bytes)),
    );
};

const createFixture = (suiteArtifactVariant: number) => {
    if (
        !Number.isSafeInteger(suiteArtifactVariant) ||
        suiteArtifactVariant < 0
    ) {
        throw new TypeError(
            'The suite artifact fixture variant must be a nonnegative safe integer.',
        );
    }
    const assets: readonly RuntimeAssetFixture[] = Object.freeze([
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
        Array.from({ length: 6 }, (_unused, artifactIndex) =>
            textEncoder.encode(
                `artifact-${String(artifactIndex + 1)}${
                    suiteArtifactVariant === 0
                        ? ''
                        : `-variant-${String(suiteArtifactVariant)}`
                }`,
            ),
        ),
    );
    const suiteRecordBytes = createCanonicalSuiteRecordFixture({
        artifactBytes: artifacts,
    });
    const suiteIdentifier = deriveHash(
        createSuiteIdentifierAccumulator(BigInt(suiteRecordBytes.byteLength)),
        suiteRecordBytes,
    );
    const manifestBytes = canonicalTuple(
        0x1802,
        unsigned16Item(1),
        asciiItem('authority-binding-fixture'),
        hashItem(suiteIdentifier),
        asciiItem(fixtureSuiteRecordPath),
        asciiListItem(fixtureArtifactPaths),
        nestedTupleListItem(assets.map(runtimeAssetReferenceTuple)),
        nestedTupleListItem([]),
    );
    const runtimeBuildManifestHash = deriveHash(
        createRuntimeBuildManifestHashAccumulator(
            BigInt(manifestBytes.byteLength),
        ),
        manifestBytes,
    );
    const routes = new Map<string, Uint8Array>([
        [fixtureManifestPath, manifestBytes],
        [fixtureSuiteRecordPath, suiteRecordBytes],
        ...assets.map((asset) => [asset.canonicalPath, asset.bytes] as const),
        ...artifacts.map(
            (artifactBytes, artifactIndex) =>
                [fixtureArtifactPaths[artifactIndex], artifactBytes] as const,
        ),
    ]);
    return Object.freeze({
        artifacts,
        assets,
        routes,
        runtimeBuildManifestHash,
        suiteIdentifier,
        suiteRecordBytes,
    });
};

class MemoryRuntimeBuildCache implements RuntimeBuildCache {
    readonly #namespaces = new Map<string, Map<string, Uint8Array>>();

    public deleteNamespace(namespace: string): Promise<void> {
        this.#namespaces.delete(namespace);
        return Promise.resolve();
    }

    public listPaths(namespace: string): Promise<readonly string[]> {
        return Promise.resolve([
            ...(this.#namespaces.get(namespace)?.keys() ?? []),
        ]);
    }

    public read(
        namespace: string,
        canonicalPath: string,
    ): Promise<RuntimeBuildByteSource> {
        const bytes = this.#namespaces.get(namespace)?.get(canonicalPath);
        if (bytes === undefined) {
            return Promise.reject(
                new Error(`Missing cached fixture path: ${canonicalPath}`),
            );
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
            throw new Error(
                'The fixture cache observed the wrong byte length.',
            );
        }
        let namespaceRecords = this.#namespaces.get(namespace);
        if (namespaceRecords === undefined) {
            namespaceRecords = new Map();
            this.#namespaces.set(namespace, namespaceRecords);
        }
        namespaceRecords.set(canonicalPath, bytes);
    }
}

export const activateRuntimeBuildAuthorityBindingFixture = async (
    fixtureInput: Readonly<{ suiteArtifactVariant?: number }> = {},
): Promise<
    Readonly<{
        activation: RuntimeBuildActivation<Readonly<{ ready: true }>, true>;
        canonicalSuiteRecordBytes: Uint8Array;
        runtimeBuildManifestHash: Uint8Array;
        suiteIdentifier: Uint8Array;
    }>
> => {
    const fixture = createFixture(fixtureInput.suiteArtifactVariant ?? 0);
    const preflight = compileRuntimeBuildBootstrap({
        bootstrapOrigin: fixtureOrigin,
        canonicalManifestPath: fixtureManifestPath,
        runtimeBuildManifestHashHex: runtimeBuildBytesToHex(
            fixture.runtimeBuildManifestHash,
        ),
    });
    const activation = await preflight({
        cache: new MemoryRuntimeBuildCache(),
        fetch: (exactUrl): Promise<RuntimeBuildFetchResponse> => {
            const bytes = fixture.routes.get(exactUrl.pathname);
            if (bytes === undefined) {
                return Promise.reject(
                    new Error(
                        `Missing runtime fixture path: ${exactUrl.pathname}`,
                    ),
                );
            }
            return Promise.resolve({
                body: byteSource(bytes),
                contentLength: String(bytes.byteLength),
                finalUrl: exactUrl.href,
                ok: true,
                redirected: false,
            });
        },
        importVerifiedApplication: (input): Promise<true> => {
            const applicationAsset = fixture.assets[0];
            const localAsset = fixture.assets[3];
            if (
                applicationAsset === undefined ||
                localAsset === undefined ||
                !bytesEqual(input.applicationBytes, applicationAsset.bytes) ||
                !bytesEqual(
                    input.localAssetBytes.get(localAsset.canonicalPath) ??
                        new Uint8Array(),
                    localAsset.bytes,
                )
            ) {
                throw new Error(
                    'The preflight did not deliver the exact authenticated application assets.',
                );
            }
            return Promise.resolve(true);
        },
        launchVerifiedWorker: (): Promise<
            RuntimeBuildWorkerPreflight<Readonly<{ ready: true }>>
        > =>
            Promise.resolve({
                finish: () =>
                    Promise.resolve(Object.freeze({ ready: true as const })),
                terminate: () => undefined,
                verifySuiteArtifact: async (input): Promise<void> => {
                    const bytes = await collectSource(input.source);
                    if (
                        bytes.byteLength !==
                        Number(input.artifactReference.byteLength)
                    ) {
                        throw new Error(
                            'The worker received a truncated suite artifact.',
                        );
                    }
                },
                verifySuiteRecord: (input): Promise<void> => {
                    if (
                        input.artifactReferences.length !== 6 ||
                        !bytesEqual(
                            input.canonicalBytes,
                            fixture.suiteRecordBytes,
                        ) ||
                        !bytesEqual(
                            input.suiteIdentifier,
                            fixture.suiteIdentifier,
                        )
                    ) {
                        return Promise.reject(
                            new Error(
                                'The worker received a substituted suite record.',
                            ),
                        );
                    }
                    return Promise.resolve();
                },
                verifyWasm: async (input): Promise<void> => {
                    const bytes = await collectSource(input.source);
                    if (
                        bytes.byteLength < 4 ||
                        bytes[0] !== 0 ||
                        bytes[1] !== 0x61 ||
                        bytes[2] !== 0x73 ||
                        bytes[3] !== 0x6d
                    ) {
                        throw new Error(
                            'The worker received a malformed WebAssembly module.',
                        );
                    }
                },
            }),
    });
    return Object.freeze({
        activation,
        canonicalSuiteRecordBytes: fixture.suiteRecordBytes.slice(),
        runtimeBuildManifestHash: fixture.runtimeBuildManifestHash.slice(),
        suiteIdentifier: fixture.suiteIdentifier.slice(),
    });
};
