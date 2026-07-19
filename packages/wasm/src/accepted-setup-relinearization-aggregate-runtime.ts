import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import {
    readAcceptedSetupPrepackageEvaluatorComponentExactRange,
    releaseUnretainedAcceptedSetupEvaluatorComponentBackings,
    requireAcceptedSetupEvaluatorComponentBackingsRetainable,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner,
    retainAcceptedSetupEvaluatorComponentBackings,
    type AcceptedSetupEvaluatorComponentBacking,
    type AcceptedSetupEvaluatorSourceCatalogSession,
} from './accepted-setup-assembly-runtime.js';
import {
    type GeneratedEvaluatorComponentDescription,
    type GeneratedEvaluatorComponentReadback,
    type GeneratedEvaluatorComponentStore,
    persistGeneratedEvaluatorComponents,
} from './accepted-setup-generated-evaluator-component-runtime.js';
import {
    requireAcceptedSetupPackageBuilderKernelOwner,
    type AcceptedSetupPackageBuilder,
} from './accepted-setup-package-builder-runtime.js';
import {
    resolveActionRandomnessKernelAuthorization,
    type ActionRandomnessSession,
} from './action-randomness-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    canonicalStreamDomains,
    CanonicalStreamCancellationError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import { yieldBrowserWorkerTurn } from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import {
    deriveGeneratedCommonProofDescriptor,
    trackCanonicalCommonProofOutputChunks,
} from './generated-common-proof-output-runtime.js';
import {
    resolveVerifiedStateReservationKernelAuthorization,
    type VerifiedStateReservation,
} from './state-verifier-runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const checkpointLineageIdentifierByteLength = 32;
const hashByteLength = 64;
const verifierCapabilityByteLength = 32;
const unsigned64ByteLength = BigUint64Array.BYTES_PER_ELEMENT;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const sourceReadRequired = 1;
const constructionComplete = 0;
const maximumConstructionReadCount =
    foundationProfile.participantCount *
    2 *
    Math.ceil(
        foundationProfile.maximumCanonicalStreamByteLength /
            foundationProfile.streamChunkByteLength,
    );

export type RelinearizationAggregateGenerationMode = 'fresh' | 'resumed';
type RelinearizationAggregateGenerationWorkerOptions = Omit<
    CommonProofGenerationWorkerOptions,
    'authenticatedSourceRangeReader'
>;
export type RelinearizationAggregateComponentStore =
    GeneratedEvaluatorComponentStore;
export type RelinearizationAggregateComponentDescription =
    GeneratedEvaluatorComponentDescription;

export type GeneratedRelinearizationAggregateProof = Readonly<{
    components: readonly RelinearizationAggregateComponentDescription[];
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

type AggregateKernel = Readonly<{
    absorbConstruction: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_construction_absorb']
    >;
    beginConstruction: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_construction_begin']
    >;
    commitGeneratedSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_commit_generated_source']
    >;
    componentCount: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_component_count']
    >;
    componentDescriptorByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_component_descriptor_byte_length']
    >;
    componentTotalByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_component_total_byte_length']
    >;
    copyComponentDescriptor: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_component_copy_descriptor']
    >;
    copyComponentMaterialRoot: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_component_copy_material_root']
    >;
    discard: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_discard']
    >;
    finishConstruction: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_construction_finish']
    >;
    nextConstructionRead: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_construction_next_read']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_prepare_generation']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_prepare_resumed_generation']
    >;
    readComponentChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_aggregate_component_read_chunk']
    >;
}>;

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The RKG aggregate generator failed internally.',
        unknownStatusMessage:
            'The RKG aggregate generator returned an unknown status code.',
    });

const requireLiveHandle = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(`${label} is invalid.`);
    }
    return value;
};

const requireKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): AggregateKernel => {
    const exports = context.wasmExports;
    const kernel: Partial<AggregateKernel> = {
        absorbConstruction:
            exports.sealed_lattice_relinearization_round_one_aggregate_construction_absorb,
        beginConstruction:
            exports.sealed_lattice_relinearization_round_one_aggregate_construction_begin,
        commitGeneratedSource:
            exports.sealed_lattice_relinearization_round_one_aggregate_commit_generated_source,
        componentCount:
            exports.sealed_lattice_relinearization_round_one_aggregate_component_count,
        componentDescriptorByteLength:
            exports.sealed_lattice_relinearization_round_one_aggregate_component_descriptor_byte_length,
        componentTotalByteLength:
            exports.sealed_lattice_relinearization_round_one_aggregate_component_total_byte_length,
        copyComponentDescriptor:
            exports.sealed_lattice_relinearization_round_one_aggregate_component_copy_descriptor,
        copyComponentMaterialRoot:
            exports.sealed_lattice_relinearization_round_one_aggregate_component_copy_material_root,
        discard:
            exports.sealed_lattice_relinearization_round_one_aggregate_discard,
        finishConstruction:
            exports.sealed_lattice_relinearization_round_one_aggregate_construction_finish,
        nextConstructionRead:
            exports.sealed_lattice_relinearization_round_one_aggregate_construction_next_read,
        prepareGeneration:
            exports.sealed_lattice_relinearization_round_one_aggregate_prepare_generation,
        prepareResumedGeneration:
            exports.sealed_lattice_relinearization_round_one_aggregate_prepare_resumed_generation,
        readComponentChunk:
            exports.sealed_lattice_relinearization_round_one_aggregate_component_read_chunk,
    };
    if (
        Object.values(kernel).some((boundary) => typeof boundary !== 'function')
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the RKG aggregate boundary.',
        );
    }
    return Object.freeze(kernel as AggregateKernel);
};

const createMemoryBoundary = (
    context: TranscriptCoreKernelCommandRuntime,
): WasmMemoryBoundary =>
    new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'RKG aggregate generation',
    });

const readUnsigned64 = (
    context: TranscriptCoreKernelCommandRuntime,
    pointer: number,
): bigint =>
    new DataView(
        context.memory.buffer,
        pointer,
        unsigned64ByteLength,
    ).getBigUint64(0, true);

const runConstruction = async (input: {
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: AggregateKernel;
    memoryBoundary: WasmMemoryBoundary;
    publicKernel: TranscriptCoreKernel;
    sessionHandle: number;
    signal?: AbortSignal;
    statusBoundary: WasmStatusBoundary;
    yieldControl(): Promise<void>;
}): Promise<void> => {
    for (
        let requestOrdinal = 0;
        requestOrdinal <= maximumConstructionReadCount;
        requestOrdinal += 1
    ) {
        if (input.signal?.aborted === true) {
            throw new CanonicalStreamCancellationError();
        }
        const request = input.context.runExclusive(
            'RKG aggregate source-read poll',
            () => {
                const rosterPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                const componentPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                const materialRootPointer =
                    input.memoryBoundary.allocate(hashByteLength);
                const streamDigestPointer =
                    input.memoryBoundary.allocate(hashByteLength);
                const totalByteLengthPointer =
                    input.memoryBoundary.allocate(unsigned64ByteLength);
                const streamByteOffsetPointer =
                    input.memoryBoundary.allocate(unsigned64ByteLength);
                const corpusByteOffsetPointer =
                    input.memoryBoundary.allocate(unsigned64ByteLength);
                const chunkIndexPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                const sourceByteLengthPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                const statusPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                try {
                    const poll = input.kernel.nextConstructionRead(
                        input.sessionHandle,
                        rosterPointer,
                        componentPointer,
                        materialRootPointer,
                        hashByteLength,
                        streamDigestPointer,
                        hashByteLength,
                        totalByteLengthPointer,
                        streamByteOffsetPointer,
                        corpusByteOffsetPointer,
                        chunkIndexPointer,
                        sourceByteLengthPointer,
                        statusPointer,
                    );
                    const [status] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(status);
                    if (poll === constructionComplete) {
                        return undefined;
                    }
                    if (poll !== sourceReadRequired) {
                        throw new CanonicalStreamInternalError(
                            'The RKG aggregate returned an unknown construction poll.',
                        );
                    }
                    return Object.freeze({
                        chunkIndex: input.memoryBoundary.readWords(
                            chunkIndexPointer,
                            1,
                        )[0],
                        componentOrdinal: input.memoryBoundary.readWords(
                            componentPointer,
                            1,
                        )[0],
                        corpusByteOffset: readUnsigned64(
                            input.context,
                            corpusByteOffsetPointer,
                        ),
                        materialRoot: new Uint8Array(
                            input.context.memory.buffer,
                            materialRootPointer,
                            hashByteLength,
                        ).slice(),
                        rosterPosition: input.memoryBoundary.readWords(
                            rosterPointer,
                            1,
                        )[0],
                        sourceByteLength: input.memoryBoundary.readWords(
                            sourceByteLengthPointer,
                            1,
                        )[0],
                        streamByteOffset: readUnsigned64(
                            input.context,
                            streamByteOffsetPointer,
                        ),
                        streamDigest: new Uint8Array(
                            input.context.memory.buffer,
                            streamDigestPointer,
                            hashByteLength,
                        ).slice(),
                        totalByteLength: readUnsigned64(
                            input.context,
                            totalByteLengthPointer,
                        ),
                    });
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        sourceByteLengthPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        chunkIndexPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        corpusByteOffsetPointer,
                        unsigned64ByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        streamByteOffsetPointer,
                        unsigned64ByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        totalByteLengthPointer,
                        unsigned64ByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        streamDigestPointer,
                        hashByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        materialRootPointer,
                        hashByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        componentPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        rosterPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        if (request === undefined) {
            const status = input.context.runExclusive(
                'RKG aggregate construction finish',
                () => input.kernel.finishConstruction(input.sessionHandle),
            );
            input.statusBoundary.throwIfError(status);
            return;
        }
        const sourceBytes =
            await readAcceptedSetupPrepackageEvaluatorComponentExactRange({
                authenticatedByteLength: request.totalByteLength,
                catalog: input.catalog,
                exactByteLength: request.sourceByteLength,
                fullObjectDigest: request.streamDigest,
                kernel: input.publicKernel,
                materialRoot: request.materialRoot,
                sourceByteOffset: request.streamByteOffset,
            });
        try {
            const status = input.context.runExclusive(
                'RKG aggregate source-read absorption',
                () => {
                    const materialRootPointer = input.memoryBoundary.copy(
                        request.materialRoot,
                    );
                    const streamDigestPointer = input.memoryBoundary.copy(
                        request.streamDigest,
                    );
                    const sourcePointer =
                        input.memoryBoundary.copy(sourceBytes);
                    try {
                        return input.kernel.absorbConstruction(
                            input.sessionHandle,
                            request.rosterPosition,
                            request.componentOrdinal,
                            materialRootPointer,
                            hashByteLength,
                            streamDigestPointer,
                            hashByteLength,
                            request.totalByteLength,
                            request.streamByteOffset,
                            request.corpusByteOffset,
                            request.chunkIndex,
                            sourcePointer,
                            sourceBytes.byteLength,
                        );
                    } finally {
                        input.memoryBoundary.zeroAndDeallocate(
                            sourcePointer,
                            sourceBytes.byteLength,
                        );
                        input.memoryBoundary.zeroAndDeallocate(
                            streamDigestPointer,
                            hashByteLength,
                        );
                        input.memoryBoundary.zeroAndDeallocate(
                            materialRootPointer,
                            hashByteLength,
                        );
                    }
                },
            );
            input.statusBoundary.throwIfError(status);
        } finally {
            sourceBytes.fill(0);
        }
        await input.yieldControl();
    }
    throw new CanonicalStreamInternalError(
        'The RKG aggregate exceeded the exact source-read ceiling.',
    );
};

const createComponentReadback = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    kernel: AggregateKernel;
    memoryBoundary: WasmMemoryBoundary;
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
}): GeneratedEvaluatorComponentReadback => {
    const readNumber = (
        name: string,
        read: (statusPointer: number) => number,
    ): number =>
        input.context.runExclusive(name, () => {
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            try {
                const value = read(statusPointer);
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return value;
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
            }
        });
    const copyBytes = (
        componentOrdinal: number,
        byteLength: number,
        copy: (
            sessionHandle: number,
            componentOrdinal: number,
            outputPointer: number,
            outputByteLength: number,
        ) => number,
    ): Uint8Array<ArrayBuffer> =>
        input.context.runExclusive('RKG aggregate component readback', () => {
            const outputPointer = input.memoryBoundary.allocate(byteLength);
            try {
                const status = copy(
                    input.sessionHandle,
                    componentOrdinal,
                    outputPointer,
                    byteLength,
                );
                input.statusBoundary.throwIfError(status);
                return new Uint8Array(
                    input.context.memory.buffer,
                    outputPointer,
                    byteLength,
                ).slice();
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    byteLength,
                );
            }
        });
    return Object.freeze({
        componentCount: () =>
            readNumber('RKG aggregate component count', (statusPointer) =>
                input.kernel.componentCount(input.sessionHandle, statusPointer),
            ),
        copyDescriptor: (componentOrdinal) => {
            const byteLength = readNumber(
                'RKG aggregate descriptor length',
                (statusPointer) =>
                    input.kernel.componentDescriptorByteLength(
                        input.sessionHandle,
                        componentOrdinal,
                        statusPointer,
                    ),
            );
            return copyBytes(
                componentOrdinal,
                byteLength,
                input.kernel.copyComponentDescriptor,
            );
        },
        copyMaterialRoot: (componentOrdinal) =>
            copyBytes(
                componentOrdinal,
                hashByteLength,
                input.kernel.copyComponentMaterialRoot,
            ),
        readChunk: (componentOrdinal, chunkIndex, chunkByteLength) =>
            input.context.runExclusive(
                'RKG aggregate component chunk readback',
                () => {
                    const outputPointer =
                        input.memoryBoundary.allocate(chunkByteLength);
                    try {
                        const status = input.kernel.readComponentChunk(
                            input.sessionHandle,
                            componentOrdinal,
                            chunkIndex,
                            outputPointer,
                            chunkByteLength,
                        );
                        input.statusBoundary.throwIfError(status);
                        return new Uint8Array(
                            input.context.memory.buffer,
                            outputPointer,
                            chunkByteLength,
                        ).slice();
                    } finally {
                        input.memoryBoundary.zeroAndDeallocate(
                            outputPointer,
                            chunkByteLength,
                        );
                    }
                },
            ),
        totalByteLength: (componentOrdinal) =>
            input.context.runExclusive(
                'RKG aggregate component byte length',
                () => {
                    const statusPointer =
                        input.memoryBoundary.allocateZeroedWords(1);
                    try {
                        const byteLength =
                            input.kernel.componentTotalByteLength(
                                input.sessionHandle,
                                componentOrdinal,
                                statusPointer,
                            );
                        const [status] = input.memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        input.statusBoundary.throwIfError(status);
                        return byteLength;
                    } finally {
                        input.memoryBoundary.zeroAndDeallocate(
                            statusPointer,
                            wasm32WordByteLength,
                        );
                    }
                },
            ),
    });
};

export type RelinearizationAggregateGenerationInput = Readonly<{
    actionRandomnessSession: ActionRandomnessSession;
    checkpointLineageIdentifier: Uint8Array;
    componentStores: readonly RelinearizationAggregateComponentStore[];
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    externalMemory: CommonProofExternalMemoryTransactionExecutor;
    generationMode: RelinearizationAggregateGenerationMode;
    kernel: TranscriptCoreKernel;
    options?: RelinearizationAggregateGenerationWorkerOptions;
    packageBuilder: AcceptedSetupPackageBuilder;
    proofOutputStore: CommonProofCanonicalOutputStore;
    signal?: AbortSignal;
    verifiedReservation: VerifiedStateReservation;
    yieldControl?(): Promise<void>;
}>;

export const generateRelinearizationRoundOneAggregateInClosedWorker = async (
    input: RelinearizationAggregateGenerationInput,
): Promise<GeneratedRelinearizationAggregateProof> => {
    if (
        typeof globalThis.document !== 'undefined' ||
        input.componentStores.length !== 2
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        (input.generationMode === 'resumed') !==
            (input.options?.resume !== undefined) ||
        !isUint8Array(input.checkpointLineageIdentifier) ||
        input.checkpointLineageIdentifier.byteLength !==
            checkpointLineageIdentifierByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireKernel(context);
    const packageBuilderOwner = requireAcceptedSetupPackageBuilderKernelOwner(
        input.packageBuilder,
        input.kernel,
        'collecting',
    );
    const memoryBoundary = createMemoryBoundary(context);
    const statusBoundary = createStatusBoundary();
    const catalog = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    const actionRandomness = resolveActionRandomnessKernelAuthorization(
        input.actionRandomnessSession,
        input.kernel,
    );
    const state = resolveVerifiedStateReservationKernelAuthorization(
        input.verifiedReservation,
        input.kernel,
    );
    if (
        actionRandomness.context.memory !== context.memory ||
        state.capabilityMemory !== context.memory ||
        state.capabilityPointer <= 0 ||
        state.capabilityPointer + verifierCapabilityByteLength >
            context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The RKG aggregate generation authorities do not belong to one WASM worker.',
        );
    }
    const checkpointLineageIdentifier =
        input.checkpointLineageIdentifier.slice();
    const yieldControl = input.yieldControl ?? yieldBrowserWorkerTurn;
    let sessionHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let unretainedBackings:
        | readonly AcceptedSetupEvaluatorComponentBacking[]
        | undefined;
    let componentStoresNeedRelease = true;
    let operationFailure: unknown;
    try {
        sessionHandle = context.runExclusive(
            'RKG aggregate construction begin',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = kernel.beginConstruction(
                        catalog.handle,
                        statusPointer,
                    );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The RKG aggregate session handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        await runConstruction({
            catalog: input.evaluatorSourceCatalog,
            context,
            kernel,
            memoryBoundary,
            publicKernel: input.kernel,
            sessionHandle,
            signal: input.signal,
            statusBoundary,
            yieldControl,
        });
        componentStoresNeedRelease = false;
        const persisted = await persistGeneratedEvaluatorComponents({
            expectedComponentCount: 2,
            kernel: input.kernel,
            readback: createComponentReadback({
                context,
                kernel,
                memoryBoundary,
                sessionHandle,
                statusBoundary,
            }),
            stores: input.componentStores,
        });
        unretainedBackings = persisted.backings;
        requireAcceptedSetupEvaluatorComponentBackingsRetainable({
            backings: unretainedBackings,
            catalog: input.evaluatorSourceCatalog,
            kernel: input.kernel,
        });
        const adapterHandle = context.runExclusive(
            'RKG aggregate proof preparation',
            () => {
                const checkpointPointer = memoryBoundary.copy(
                    checkpointLineageIdentifier,
                );
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const prepare =
                        input.generationMode === 'fresh'
                            ? kernel.prepareGeneration
                            : kernel.prepareResumedGeneration;
                    const handle = prepare(
                        sessionHandle,
                        actionRandomness.handle,
                        state.sessionHandle,
                        state.capabilityPointer,
                        verifierCapabilityByteLength,
                        state.reservationHandle,
                        checkpointPointer,
                        checkpointLineageIdentifier.byteLength,
                        statusPointer,
                    );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The RKG aggregate generation adapter handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        checkpointPointer,
                        checkpointLineageIdentifier.byteLength,
                    );
                }
            },
        );
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            adapterHandle,
        );
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const trackedProofOutput = trackCanonicalCommonProofOutputChunks(
            input.proofOutputStore,
        );
        generatedCapability =
            await runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability(
                adapterForRun,
                input.externalMemory,
                trackedProofOutput.outputStore,
                input.options,
            );
        const proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor(
            {
                kernel: input.kernel,
                outputChunkByteLengths:
                    trackedProofOutput.outputChunkByteLengths,
                outputStore: input.proofOutputStore,
                proofFamilyLabel: 'RKG round-one aggregate',
                streamDomain: canonicalStreamDomains.rkgRoundOneAggregateProof,
            },
        );
        const capabilityForCommit = generatedCapability;
        const commitStatus = applyClosedWorkerGeneratedCommonProofCapability(
            capabilityForCommit,
            context,
            (generatedProofHandle) => {
                const status = context.runExclusive(
                    'RKG aggregate catalog commit',
                    () =>
                        kernel.commitGeneratedSource(
                            packageBuilderOwner.handle,
                            catalog.handle,
                            generatedProofHandle,
                            sessionHandle,
                        ),
                );
                return Object.freeze({
                    consumed: status === 0,
                    result: status,
                });
            },
        );
        statusBoundary.throwIfError(commitStatus);
        generatedCapability = undefined;
        sessionHandle = 0;
        retainAcceptedSetupEvaluatorComponentBackings({
            backings: unretainedBackings,
            catalog: input.evaluatorSourceCatalog,
            kernel: input.kernel,
        });
        unretainedBackings = undefined;
        checkpointLineageIdentifier.fill(0);
        return Object.freeze({
            components: persisted.components,
            proofDescriptorBytes,
        });
    } catch (error) {
        operationFailure = error;
    }

    checkpointLineageIdentifier.fill(0);
    const cleanupFailures: unknown[] = [];
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
            );
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (generatedCapability !== undefined) {
        try {
            generatedCapability.release();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (sessionHandle !== 0) {
        try {
            const status = context.runExclusive(
                'RKG aggregate session discard',
                () => kernel.discard(sessionHandle),
            );
            if (status >>> 0 !== refusalReasonCodes.consumedState) {
                statusBoundary.throwIfError(status);
            }
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (unretainedBackings !== undefined) {
        try {
            releaseUnretainedAcceptedSetupEvaluatorComponentBackings(
                unretainedBackings,
                input.kernel,
            );
        } catch (error) {
            cleanupFailures.push(error);
        }
    } else if (componentStoresNeedRelease) {
        for (const store of input.componentStores) {
            try {
                store.release();
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'RKG aggregate generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};
