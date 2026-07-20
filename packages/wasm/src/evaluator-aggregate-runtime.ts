import {
    foundationProfile,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import {
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage,
    readAcceptedSetupPrepackageEvaluatorComponentExactRange,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner,
    requireAcceptedSetupVerificationAssemblyKernelOwner,
    type AcceptedSetupEvaluatorSourceCatalogSession,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import {
    requireAcceptedSetupPackageBuilderKernelOwner,
    type AcceptedSetupPackageBuilder,
} from './accepted-setup-package-builder-runtime.js';
import { isUint8Array } from './byte-array.js';
import {
    canonicalStreamDomains,
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import { yieldBrowserWorkerTurn } from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    applyClosedWorkerVerifiedCommonProofCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type AuthenticatedCommonProofInputStore,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofCanonicalOutputStore,
    type CommonProofGenerationExecutionOpener,
    type CommonProofVerificationWorkerOptions,
    type VerifiedCommonProofCapability,
} from './common-proof-worker-runtime/runtime.js';
import { deriveGeneratedCommonProofDescriptor } from './generated-common-proof-output-runtime.js';
import type { ClosedWorkerProductionOperationIdentifiers } from './local-storage-root-worker-kernel/authorities.js';
import { withClosedWorkerProductionOperationAuthority } from './local-storage-root-worker-kernel/worker-kernel.js';
import {
    copySelectedSuiteRecordSourceBytes,
    type SelectedSuiteRecordSource,
} from './selected-suite-record-source.js';
import { stateVerifierCapabilityByteLength } from './state-verifier-runtime/contracts.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const attemptIdentifierByteLength = 32;
const fixedHashByteLength = 64;
const storeDescriptionByteLength = 72;
const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const storePollSourceReadRequired = 1;
const storePollOutputChunkReady = 2;
const storePollConstructionComplete = 3;
const maximumPhysicalComponentCount = foundationProfile.optionCount * 2;
const maximumStoreChunkCount = Math.ceil(
    foundationProfile.maximumCanonicalStreamByteLength /
        foundationProfile.streamChunkByteLength,
);
const maximumStoreSourceRequestCount =
    maximumPhysicalComponentCount *
    foundationProfile.participantCount *
    maximumStoreChunkCount;

type EvaluatorAggregateExports = Required<
    Pick<
        TranscriptCoreKernelExports,
        | 'sealed_lattice_common_proof_release_suite'
        | 'sealed_lattice_common_proof_select_suite'
        | 'sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk'
        | 'sealed_lattice_evaluator_aggregate_absorb_store_material_chunk'
        | 'sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk'
        | 'sealed_lattice_evaluator_aggregate_application_statement_byte_length'
        | 'sealed_lattice_evaluator_aggregate_begin_runtime_component_tree'
        | 'sealed_lattice_evaluator_aggregate_begin_store_construction'
        | 'sealed_lattice_evaluator_aggregate_commit_generated_proof'
        | 'sealed_lattice_evaluator_aggregate_commit_verified_store'
        | 'sealed_lattice_evaluator_aggregate_contribute_package'
        | 'sealed_lattice_evaluator_aggregate_copy_application_statement'
        | 'sealed_lattice_evaluator_aggregate_copy_store_output_chunk'
        | 'sealed_lattice_evaluator_aggregate_copy_store_source_request'
        | 'sealed_lattice_evaluator_aggregate_describe_store'
        | 'sealed_lattice_evaluator_aggregate_discard_session'
        | 'sealed_lattice_evaluator_aggregate_finalize_statement'
        | 'sealed_lattice_evaluator_aggregate_finish_runtime_component_tree'
        | 'sealed_lattice_evaluator_aggregate_finish_store_construction'
        | 'sealed_lattice_evaluator_aggregate_finish_store_material'
        | 'sealed_lattice_evaluator_aggregate_finish_verification'
        | 'sealed_lattice_evaluator_aggregate_prepare_generation'
        | 'sealed_lattice_evaluator_aggregate_prepare_resumed_generation'
        | 'sealed_lattice_evaluator_aggregate_prepare_verification'
        | 'sealed_lattice_evaluator_aggregate_store_construction_poll'
        | 'sealed_lattice_evaluator_aggregate_store_source_request_byte_length'
        | 'sealed_lattice_evaluator_aggregate_supply_store_source_range'
        | 'sealed_lattice_evaluator_aggregate_take_package_statement_source'
    >
>;

type EvaluatorAggregateContext = TranscriptCoreKernelCommandRuntime & {
    readonly wasmExports: TranscriptCoreKernelCommandRuntime['wasmExports'] &
        EvaluatorAggregateExports;
};

export type EvaluatorAggregateGenerationMode = 'fresh' | 'resumed';

export type EvaluatorKeyStoreDescription = Readonly<{
    fullObjectDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: bigint;
}>;

export type EvaluatorAggregateConstructionOptions = Readonly<{
    signal?: AbortSignal;
    yieldControl?(): Promise<void>;
}>;

const evaluatorAggregateSessionBrand = Symbol(
    'evaluator aggregate worker session',
);

/** Opaque same-worker custody of the complete selected evaluator proof. */
export type EvaluatorAggregateSession = Readonly<{
    readonly [evaluatorAggregateSessionBrand]: true;
    cancel(): void;
    commitVerifiedStore(
        acceptedSetupVerification: AcceptedSetupVerificationSession,
    ): void;
    bindPackageStatement(
        acceptedSetupVerification: AcceptedSetupVerificationSession,
    ): void;
    contributeToPackage(builder: AcceptedSetupPackageBuilder): void;
    copyCanonicalApplicationStatement(): Uint8Array<ArrayBuffer>;
    describeStore(): EvaluatorKeyStoreDescription;
    generate(input: {
        checkpointLineageIdentifier: Uint8Array;
        generationMode: EvaluatorAggregateGenerationMode;
        openProofGenerationExecution: CommonProofGenerationExecutionOpener;
        productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
        workerKernel: BrowserActionStorageWorkerKernel;
    }): Promise<Uint8Array<ArrayBuffer>>;
    verify(input: {
        options?: CommonProofVerificationWorkerOptions;
        proofInputStore: AuthenticatedCommonProofInputStore;
    }): Promise<void>;
}>;

type EvaluatorAggregatePhase =
    | 'prepared'
    | 'generating'
    | 'generated'
    | 'packageContributed'
    | 'packageBound'
    | 'packageStatementRetained'
    | 'verifying'
    | 'verified'
    | 'storeCommitted';

type PhysicalComponentObservation = {
    maximumSourceOrdinal: number;
    sourceOrdinalMask: number;
    storeByteOffset: number;
    totalByteLength: number;
};

type StoreSourceRequest = Readonly<{
    byteLength: number;
    chunkIndex: number;
    encodedBytes: Uint8Array<ArrayBuffer>;
    physicalComponentOrdinal: number;
    sourceByteOffset: bigint;
    sourceMaterialRoot: Uint8Array<ArrayBuffer>;
    sourceOrdinal: number;
    sourceStreamDigest: Uint8Array<ArrayBuffer>;
    sourceTotalByteLength: bigint;
}>;

type EvaluatorAggregateSessionRecord = {
    readonly canonicalApplicationStatement: Uint8Array<ArrayBuffer>;
    readonly canonicalSuiteRecordBytes: Uint8Array<ArrayBuffer>;
    readonly catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    readonly context: EvaluatorAggregateContext;
    generatedProof: ClosedWorkerGeneratedCommonProofCapability | undefined;
    readonly kernel: TranscriptCoreKernel;
    phase: EvaluatorAggregatePhase;
    readonly sessionHandle: number;
    readonly storeDescription: EvaluatorKeyStoreDescription;
};

const sessionRecords = new WeakMap<
    EvaluatorAggregateSession,
    EvaluatorAggregateSessionRecord
>();

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The evaluator aggregate kernel session failed internally.',
        unknownStatusMessage:
            'The evaluator aggregate kernel returned an unknown status code.',
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

const requireEvaluatorAggregateContext = (
    kernel: TranscriptCoreKernel,
): EvaluatorAggregateContext => {
    const context = resolveCommonProofKernelContext(kernel);
    const exports = context?.wasmExports as
        | Partial<EvaluatorAggregateExports>
        | undefined;
    const requiredExportNames = [
        'sealed_lattice_common_proof_release_suite',
        'sealed_lattice_common_proof_select_suite',
        'sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk',
        'sealed_lattice_evaluator_aggregate_absorb_store_material_chunk',
        'sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk',
        'sealed_lattice_evaluator_aggregate_application_statement_byte_length',
        'sealed_lattice_evaluator_aggregate_begin_runtime_component_tree',
        'sealed_lattice_evaluator_aggregate_begin_store_construction',
        'sealed_lattice_evaluator_aggregate_commit_generated_proof',
        'sealed_lattice_evaluator_aggregate_commit_verified_store',
        'sealed_lattice_evaluator_aggregate_contribute_package',
        'sealed_lattice_evaluator_aggregate_copy_application_statement',
        'sealed_lattice_evaluator_aggregate_copy_store_output_chunk',
        'sealed_lattice_evaluator_aggregate_copy_store_source_request',
        'sealed_lattice_evaluator_aggregate_describe_store',
        'sealed_lattice_evaluator_aggregate_discard_session',
        'sealed_lattice_evaluator_aggregate_finalize_statement',
        'sealed_lattice_evaluator_aggregate_finish_runtime_component_tree',
        'sealed_lattice_evaluator_aggregate_finish_store_construction',
        'sealed_lattice_evaluator_aggregate_finish_store_material',
        'sealed_lattice_evaluator_aggregate_finish_verification',
        'sealed_lattice_evaluator_aggregate_prepare_generation',
        'sealed_lattice_evaluator_aggregate_prepare_resumed_generation',
        'sealed_lattice_evaluator_aggregate_prepare_verification',
        'sealed_lattice_evaluator_aggregate_store_construction_poll',
        'sealed_lattice_evaluator_aggregate_store_source_request_byte_length',
        'sealed_lattice_evaluator_aggregate_supply_store_source_range',
        'sealed_lattice_evaluator_aggregate_take_package_statement_source',
    ] as const;
    if (
        context === undefined ||
        exports === undefined ||
        requiredExportNames.some(
            (exportName) => typeof exports[exportName] !== 'function',
        )
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the evaluator aggregate boundary.',
        );
    }
    return context as EvaluatorAggregateContext;
};

const createMemoryBoundary = (
    context: EvaluatorAggregateContext,
): WasmMemoryBoundary =>
    new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'evaluator aggregate boundary',
    });

const requireSessionRecord = (
    session: EvaluatorAggregateSession,
): EvaluatorAggregateSessionRecord => {
    if (
        (typeof session !== 'object' && typeof session !== 'function') ||
        session === null
    ) {
        throw new TypeError(
            'The evaluator aggregate session was not issued by this WASM runtime.',
        );
    }
    const record = sessionRecords.get(session);
    if (record === undefined) {
        throw new TypeError(
            'The evaluator aggregate session is unavailable or already consumed.',
        );
    }
    return record;
};

const requirePhase = (
    record: EvaluatorAggregateSessionRecord,
    expectedPhase: EvaluatorAggregatePhase,
): void => {
    if (record.phase !== expectedPhase) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
};

const requireAttemptIdentifier = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== attemptIdentifierByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return Uint8Array.from(value);
};

const throwIfAborted = (signal: AbortSignal | undefined): void => {
    if (signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
};

const requireOwnedExactBytes = (
    value: unknown,
    exactByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteOffset !== 0 ||
        value.byteLength !== exactByteLength ||
        value.buffer.byteLength !== exactByteLength
    ) {
        if (isUint8Array(value)) {
            value.fill(0);
        }
        throw new CanonicalStreamInternalError(
            `${label} did not return one fresh owned exact byte range.`,
        );
    }
    return value as Uint8Array<ArrayBuffer>;
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: EvaluatorAggregateContext;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive('evaluator aggregate suite selection', () => {
        const suitePointer = input.memoryBoundary.copy(
            input.canonicalSuiteRecordBytes,
        );
        const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
        let selectedSuiteHandle = 0;
        try {
            selectedSuiteHandle =
                input.context.wasmExports.sealed_lattice_common_proof_select_suite(
                    suitePointer,
                    input.canonicalSuiteRecordBytes.byteLength,
                    statusPointer,
                );
            const [status] = input.memoryBoundary.readWords(statusPointer, 1);
            input.statusBoundary.throwIfError(status);
            return requireLiveHandle(
                selectedSuiteHandle,
                'The evaluator aggregate selected-suite handle',
            );
        } catch (error) {
            if (selectedSuiteHandle !== 0) {
                try {
                    input.statusBoundary.throwIfError(
                        input.context.wasmExports.sealed_lattice_common_proof_release_suite(
                            selectedSuiteHandle,
                        ),
                    );
                } catch (cleanupFailure) {
                    throw new CanonicalStreamInternalError(
                        'Evaluator aggregate suite selection failed and its returned handle could not be released.',
                        Object.freeze({ cleanupFailure, error }),
                    );
                }
            }
            throw error;
        } finally {
            input.memoryBoundary.zeroAndDeallocate(
                statusPointer,
                wasm32WordByteLength,
            );
            input.memoryBoundary.zeroAndDeallocate(
                suitePointer,
                input.canonicalSuiteRecordBytes.byteLength,
            );
        }
    });

const releaseSuite = (input: {
    context: EvaluatorAggregateContext;
    selectedSuiteHandle: number;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'evaluator aggregate selected-suite release',
        () =>
            input.context.wasmExports.sealed_lattice_common_proof_release_suite(
                input.selectedSuiteHandle,
            ),
    );
    input.statusBoundary.throwIfError(status);
};

const discardKernelSession = (
    record: EvaluatorAggregateSessionRecord,
): void => {
    const status = record.context.runExclusive(
        'evaluator aggregate session discard',
        () =>
            record.context.wasmExports.sealed_lattice_evaluator_aggregate_discard_session(
                record.sessionHandle,
            ),
    );
    createStatusBoundary().throwIfError(status);
};

const parseStoreSourceRequest = (
    encodedBytes: Uint8Array<ArrayBuffer>,
): StoreSourceRequest => {
    const view = new DataView(encodedBytes.buffer);
    const request: StoreSourceRequest = Object.freeze({
        byteLength: view.getUint32(156, true),
        chunkIndex: view.getUint32(152, true),
        encodedBytes,
        physicalComponentOrdinal: view.getUint32(0, true),
        sourceByteOffset: view.getBigUint64(144, true),
        sourceMaterialRoot: encodedBytes.slice(8, 72),
        sourceOrdinal: view.getUint32(4, true),
        sourceStreamDigest: encodedBytes.slice(72, 136),
        sourceTotalByteLength: view.getBigUint64(136, true),
    });
    const expectedByteOffset =
        BigInt(request.chunkIndex) *
        BigInt(foundationProfile.streamChunkByteLength);
    const remainingByteLength =
        request.sourceTotalByteLength - request.sourceByteOffset;
    const expectedByteLength = Number(
        remainingByteLength < BigInt(foundationProfile.streamChunkByteLength)
            ? remainingByteLength
            : BigInt(foundationProfile.streamChunkByteLength),
    );
    if (
        request.physicalComponentOrdinal >= maximumPhysicalComponentCount ||
        request.sourceOrdinal >= foundationProfile.participantCount ||
        request.sourceTotalByteLength <= 0n ||
        request.sourceTotalByteLength >
            BigInt(foundationProfile.maximumCanonicalStreamByteLength) ||
        request.sourceByteOffset !== expectedByteOffset ||
        remainingByteLength <= 0n ||
        request.byteLength !== expectedByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The evaluator store constructor exposed an invalid bounded source request.',
        );
    }
    return request;
};

const observePhysicalComponent = (input: {
    observations: PhysicalComponentObservation[];
    request: StoreSourceRequest;
}): void => {
    const totalByteLength = Number(input.request.sourceTotalByteLength);
    const existing = input.observations[input.request.physicalComponentOrdinal];
    if (existing === undefined) {
        if (
            input.request.physicalComponentOrdinal !==
                input.observations.length ||
            input.request.sourceOrdinal !== 0 ||
            input.request.chunkIndex !== 0
        ) {
            throw new CanonicalStreamInternalError(
                'The evaluator store constructor exposed a noncanonical physical-component sequence.',
            );
        }
        const previous = input.observations[input.observations.length - 1];
        input.observations.push({
            maximumSourceOrdinal: 0,
            sourceOrdinalMask: 1,
            storeByteOffset:
                previous === undefined
                    ? 0
                    : previous.storeByteOffset + previous.totalByteLength,
            totalByteLength,
        });
        return;
    }
    if (existing.totalByteLength !== totalByteLength) {
        throw new CanonicalStreamInternalError(
            'The evaluator store constructor changed a physical-component length.',
        );
    }
    existing.maximumSourceOrdinal = Math.max(
        existing.maximumSourceOrdinal,
        input.request.sourceOrdinal,
    );
    existing.sourceOrdinalMask |= 1 << input.request.sourceOrdinal;
};

const copyStoreSourceRequest = (input: {
    context: EvaluatorAggregateContext;
    memoryBoundary: WasmMemoryBoundary;
    requestByteLength: number;
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive(
        'evaluator aggregate store-source request copy',
        () => {
            const pointer = input.memoryBoundary.allocate(
                input.requestByteLength,
            );
            try {
                const status =
                    input.context.wasmExports.sealed_lattice_evaluator_aggregate_copy_store_source_request(
                        input.sessionHandle,
                        pointer,
                        input.requestByteLength,
                    );
                input.statusBoundary.throwIfError(status);
                return Uint8Array.from(
                    new Uint8Array(
                        input.context.memory.buffer,
                        pointer,
                        input.requestByteLength,
                    ),
                );
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    pointer,
                    input.requestByteLength,
                );
            }
        },
    );

const supplyStoreSourceRange = (input: {
    context: EvaluatorAggregateContext;
    memoryBoundary: WasmMemoryBoundary;
    request: StoreSourceRequest;
    sessionHandle: number;
    sourceBytes: Uint8Array<ArrayBuffer>;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'evaluator aggregate store-source ingestion',
        () => {
            const requestPointer = input.memoryBoundary.copy(
                input.request.encodedBytes,
            );
            const sourcePointer = input.memoryBoundary.copy(input.sourceBytes);
            try {
                return input.context.wasmExports.sealed_lattice_evaluator_aggregate_supply_store_source_range(
                    input.sessionHandle,
                    requestPointer,
                    input.request.encodedBytes.byteLength,
                    sourcePointer,
                    input.sourceBytes.byteLength,
                );
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    sourcePointer,
                    input.sourceBytes.byteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    requestPointer,
                    input.request.encodedBytes.byteLength,
                );
            }
        },
    );
    input.statusBoundary.throwIfError(status);
};

const copyStoreOutputChunk = (input: {
    byteLength: number;
    chunkIndex: number;
    context: EvaluatorAggregateContext;
    memoryBoundary: WasmMemoryBoundary;
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive('evaluator aggregate store-output copy', () => {
        const pointer = input.memoryBoundary.allocate(input.byteLength);
        try {
            const status =
                input.context.wasmExports.sealed_lattice_evaluator_aggregate_copy_store_output_chunk(
                    input.sessionHandle,
                    input.chunkIndex,
                    pointer,
                    input.byteLength,
                );
            input.statusBoundary.throwIfError(status);
            return Uint8Array.from(
                new Uint8Array(
                    input.context.memory.buffer,
                    pointer,
                    input.byteLength,
                ),
            );
        } finally {
            input.memoryBoundary.zeroAndDeallocate(pointer, input.byteLength);
        }
    });

const describeStore = (input: {
    context: EvaluatorAggregateContext;
    memoryBoundary: WasmMemoryBoundary;
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
}): EvaluatorKeyStoreDescription =>
    input.context.runExclusive('evaluator aggregate store description', () => {
        const pointer = input.memoryBoundary.allocate(
            storeDescriptionByteLength,
        );
        try {
            const status =
                input.context.wasmExports.sealed_lattice_evaluator_aggregate_describe_store(
                    input.sessionHandle,
                    pointer,
                    storeDescriptionByteLength,
                );
            input.statusBoundary.throwIfError(status);
            const bytes = Uint8Array.from(
                new Uint8Array(
                    input.context.memory.buffer,
                    pointer,
                    storeDescriptionByteLength,
                ),
            );
            return Object.freeze({
                fullObjectDigest: bytes.slice(8),
                totalByteLength: new DataView(bytes.buffer).getBigUint64(
                    0,
                    true,
                ),
            });
        } finally {
            input.memoryBoundary.zeroAndDeallocate(
                pointer,
                storeDescriptionByteLength,
            );
        }
    });

const readStoreChunk = async (input: {
    chunkByteLengths: readonly number[];
    chunkIndex: number;
    store: CommonProofCanonicalOutputStore;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const exactByteLength = input.chunkByteLengths[input.chunkIndex];
    if (exactByteLength === undefined) {
        throw new CanonicalStreamInternalError(
            'The evaluator store requested an uncommitted output chunk.',
        );
    }
    const returned = await input.store.readChunk(
        input.chunkIndex,
        exactByteLength,
    );
    return requireOwnedExactBytes(
        returned,
        exactByteLength,
        'The evaluator output store',
    );
};

const readStoreExactRange = async (input: {
    chunkByteLengths: readonly number[];
    exactByteLength: number;
    sourceByteOffset: number;
    store: CommonProofCanonicalOutputStore;
    totalByteLength: number;
}): Promise<Uint8Array<ArrayBuffer>> => {
    if (
        !Number.isSafeInteger(input.sourceByteOffset) ||
        !Number.isSafeInteger(input.exactByteLength) ||
        input.sourceByteOffset < 0 ||
        input.exactByteLength <= 0 ||
        input.exactByteLength > foundationProfile.streamChunkByteLength ||
        input.sourceByteOffset + input.exactByteLength > input.totalByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The evaluator runtime requested an invalid store range.',
        );
    }
    const result = new Uint8Array(input.exactByteLength);
    let copiedByteLength = 0;
    while (copiedByteLength < input.exactByteLength) {
        const absoluteByteOffset = input.sourceByteOffset + copiedByteLength;
        const chunkIndex = Math.floor(
            absoluteByteOffset / foundationProfile.streamChunkByteLength,
        );
        const chunkLocalOffset =
            absoluteByteOffset % foundationProfile.streamChunkByteLength;
        const chunk = await readStoreChunk({
            chunkByteLengths: input.chunkByteLengths,
            chunkIndex,
            store: input.store,
        });
        try {
            const copiedFromChunk = Math.min(
                chunk.byteLength - chunkLocalOffset,
                input.exactByteLength - copiedByteLength,
            );
            if (copiedFromChunk <= 0) {
                throw new CanonicalStreamInternalError(
                    'The evaluator output store range crosses an invalid chunk boundary.',
                );
            }
            result.set(
                chunk.subarray(
                    chunkLocalOffset,
                    chunkLocalOffset + copiedFromChunk,
                ),
                copiedByteLength,
            );
            copiedByteLength += copiedFromChunk;
        } finally {
            chunk.fill(0);
        }
    }
    return result;
};

const copyCanonicalApplicationStatement = (input: {
    context: EvaluatorAggregateContext;
    memoryBoundary: WasmMemoryBoundary;
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> => {
    const byteLength = input.context.runExclusive(
        'evaluator aggregate application-statement length',
        () => {
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            try {
                const result =
                    input.context.wasmExports.sealed_lattice_evaluator_aggregate_application_statement_byte_length(
                        input.sessionHandle,
                        statusPointer,
                    );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return result;
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
            }
        },
    );
    if (
        byteLength <= 0n ||
        byteLength > BigInt(foundationProfile.maximumCopiedBufferByteLength)
    ) {
        throw new CanonicalStreamResourceError(
            'The evaluator application statement exceeds the absolute copy bound.',
        );
    }
    const exactByteLength = Number(byteLength);
    return input.context.runExclusive(
        'evaluator aggregate application-statement copy',
        () => {
            const pointer = input.memoryBoundary.allocate(exactByteLength);
            try {
                const status =
                    input.context.wasmExports.sealed_lattice_evaluator_aggregate_copy_application_statement(
                        input.sessionHandle,
                        pointer,
                        exactByteLength,
                    );
                input.statusBoundary.throwIfError(status);
                return Uint8Array.from(
                    new Uint8Array(
                        input.context.memory.buffer,
                        pointer,
                        exactByteLength,
                    ),
                );
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    pointer,
                    exactByteLength,
                );
            }
        },
    );
};

const constructStore = async (input: {
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    context: EvaluatorAggregateContext;
    kernel: TranscriptCoreKernel;
    memoryBoundary: WasmMemoryBoundary;
    options: EvaluatorAggregateConstructionOptions;
    outputStore: CommonProofCanonicalOutputStore;
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
}): Promise<{
    chunkByteLengths: readonly number[];
    physicalComponents: readonly PhysicalComponentObservation[];
    storeDescription: EvaluatorKeyStoreDescription;
}> => {
    const requestByteLength = input.context.runExclusive(
        'evaluator aggregate source-request length',
        () =>
            input.context.wasmExports.sealed_lattice_evaluator_aggregate_store_source_request_byte_length(),
    );
    if (requestByteLength !== 160) {
        throw new CanonicalStreamInternalError(
            'The evaluator aggregate source-request codec has the wrong fixed byte length.',
        );
    }
    const yieldControl = input.options.yieldControl ?? yieldBrowserWorkerTurn;
    const chunkByteLengths: number[] = [];
    const observations: PhysicalComponentObservation[] = [];
    let sourceRequestCount = 0;
    let outputByteLength = 0;
    for (;;) {
        throwIfAborted(input.options.signal);
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            input.catalog,
            input.kernel,
            'collecting',
        );
        const poll = input.context.runExclusive(
            'evaluator aggregate store-construction poll',
            () => {
                const metadataPointer =
                    input.memoryBoundary.allocateZeroedWords(3);
                try {
                    const code =
                        input.context.wasmExports.sealed_lattice_evaluator_aggregate_store_construction_poll(
                            input.sessionHandle,
                            metadataPointer,
                            metadataPointer + wasm32WordByteLength,
                            metadataPointer + wasm32WordByteLength * 2,
                        );
                    const [firstValue, secondValue, status] =
                        input.memoryBoundary.readWords(metadataPointer, 3);
                    input.statusBoundary.throwIfError(status);
                    return Object.freeze({
                        code,
                        firstValue,
                        secondValue,
                    });
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        wasm32WordByteLength * 3,
                    );
                }
            },
        );
        if (poll.code === storePollSourceReadRequired) {
            sourceRequestCount += 1;
            if (sourceRequestCount > maximumStoreSourceRequestCount) {
                throw new CanonicalStreamResourceError(
                    'The evaluator store construction exceeded the absolute source-request bound.',
                );
            }
            const request = parseStoreSourceRequest(
                copyStoreSourceRequest({
                    context: input.context,
                    memoryBoundary: input.memoryBoundary,
                    requestByteLength,
                    sessionHandle: input.sessionHandle,
                    statusBoundary: input.statusBoundary,
                }),
            );
            observePhysicalComponent({ observations, request });
            let sourceBytes: Uint8Array<ArrayBuffer> | undefined;
            try {
                sourceBytes = requireOwnedExactBytes(
                    await readAcceptedSetupPrepackageEvaluatorComponentExactRange(
                        {
                            authenticatedByteLength:
                                request.sourceTotalByteLength,
                            catalog: input.catalog,
                            exactByteLength: request.byteLength,
                            fullObjectDigest: request.sourceStreamDigest,
                            kernel: input.kernel,
                            materialRoot: request.sourceMaterialRoot,
                            sourceByteOffset: request.sourceByteOffset,
                        },
                    ),
                    request.byteLength,
                    'The authenticated evaluator component source',
                );
                requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                    input.catalog,
                    input.kernel,
                    'collecting',
                );
                supplyStoreSourceRange({
                    context: input.context,
                    memoryBoundary: input.memoryBoundary,
                    request,
                    sessionHandle: input.sessionHandle,
                    sourceBytes,
                    statusBoundary: input.statusBoundary,
                });
            } finally {
                sourceBytes?.fill(0);
                request.encodedBytes.fill(0);
                request.sourceMaterialRoot.fill(0);
                request.sourceStreamDigest.fill(0);
            }
            await yieldControl();
            continue;
        }
        if (poll.code === storePollOutputChunkReady) {
            const previousChunkByteLength =
                chunkByteLengths[chunkByteLengths.length - 1];
            if (
                poll.firstValue !== chunkByteLengths.length ||
                poll.secondValue <= 0 ||
                poll.secondValue > foundationProfile.streamChunkByteLength ||
                chunkByteLengths.length >= maximumStoreChunkCount ||
                (previousChunkByteLength !== undefined &&
                    previousChunkByteLength <
                        foundationProfile.streamChunkByteLength) ||
                outputByteLength + poll.secondValue >
                    foundationProfile.maximumCanonicalStreamByteLength
            ) {
                throw new CanonicalStreamInternalError(
                    'The evaluator store constructor exposed a noncanonical output chunk.',
                );
            }
            const outputBytes = copyStoreOutputChunk({
                byteLength: poll.secondValue,
                chunkIndex: poll.firstValue,
                context: input.context,
                memoryBoundary: input.memoryBoundary,
                sessionHandle: input.sessionHandle,
                statusBoundary: input.statusBoundary,
            });
            try {
                await input.outputStore.commitChunk(
                    poll.firstValue,
                    outputBytes,
                );
                requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                    input.catalog,
                    input.kernel,
                    'collecting',
                );
                const status = input.context.runExclusive(
                    'evaluator aggregate store-output acknowledgement',
                    () =>
                        input.context.wasmExports.sealed_lattice_evaluator_aggregate_acknowledge_store_output_chunk(
                            input.sessionHandle,
                            poll.firstValue,
                        ),
                );
                input.statusBoundary.throwIfError(status);
                chunkByteLengths.push(poll.secondValue);
                outputByteLength += poll.secondValue;
            } finally {
                outputBytes.fill(0);
            }
            await yieldControl();
            continue;
        }
        if (poll.code === storePollConstructionComplete) {
            break;
        }
        throw new CanonicalStreamInternalError(
            'The evaluator store constructor returned an unknown poll code.',
        );
    }
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.catalog,
        input.kernel,
        'collecting',
    );
    const finishStatus = input.context.runExclusive(
        'evaluator aggregate store-construction finish',
        () =>
            input.context.wasmExports.sealed_lattice_evaluator_aggregate_finish_store_construction(
                input.sessionHandle,
            ),
    );
    input.statusBoundary.throwIfError(finishStatus);
    const storeDescription = describeStore({
        context: input.context,
        memoryBoundary: input.memoryBoundary,
        sessionHandle: input.sessionHandle,
        statusBoundary: input.statusBoundary,
    });
    const physicalByteLength = observations.reduce(
        (total, observation) => total + observation.totalByteLength,
        0,
    );
    if (
        observations.length === 0 ||
        outputByteLength === 0 ||
        BigInt(outputByteLength) !== storeDescription.totalByteLength ||
        physicalByteLength !== outputByteLength ||
        storeDescription.fullObjectDigest.byteLength !== fixedHashByteLength ||
        observations.some(
            (observation) =>
                (observation.maximumSourceOrdinal === 0 &&
                    observation.sourceOrdinalMask !== 1) ||
                (observation.maximumSourceOrdinal ===
                    foundationProfile.participantCount - 1 &&
                    observation.sourceOrdinalMask !==
                        (1 << foundationProfile.participantCount) - 1) ||
                (observation.maximumSourceOrdinal !== 0 &&
                    observation.maximumSourceOrdinal !==
                        foundationProfile.participantCount - 1),
        )
    ) {
        throw new CanonicalStreamInternalError(
            'The evaluator store construction completed with inconsistent production-derived accounting.',
        );
    }
    return Object.freeze({
        chunkByteLengths: Object.freeze([...chunkByteLengths]),
        physicalComponents: Object.freeze(
            observations.map((observation) =>
                Object.freeze({ ...observation }),
            ),
        ),
        storeDescription,
    });
};

const bindRuntimeTreesAndStoreMaterial = async (input: {
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    canonicalSuiteRecordBytes: Uint8Array;
    chunkByteLengths: readonly number[];
    context: EvaluatorAggregateContext;
    kernel: TranscriptCoreKernel;
    memoryBoundary: WasmMemoryBoundary;
    options: EvaluatorAggregateConstructionOptions;
    physicalComponents: readonly PhysicalComponentObservation[];
    sessionHandle: number;
    statusBoundary: WasmStatusBoundary;
    store: CommonProofCanonicalOutputStore;
    totalStoreByteLength: number;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const yieldControl = input.options.yieldControl ?? yieldBrowserWorkerTurn;
    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context: input.context,
        memoryBoundary: input.memoryBoundary,
        statusBoundary: input.statusBoundary,
    });
    let unretainedCanonicalApplicationStatement:
        | Uint8Array<ArrayBuffer>
        | undefined;
    try {
        const runtimeComponents = input.physicalComponents.filter(
            (component) =>
                component.maximumSourceOrdinal ===
                foundationProfile.participantCount - 1,
        );
        if (
            runtimeComponents.length === 0 ||
            runtimeComponents.length > foundationProfile.optionCount
        ) {
            throw new CanonicalStreamInternalError(
                'The evaluator store exposed an invalid runtime-component inventory.',
            );
        }
        for (
            let logicalComponentOrdinal = 0;
            logicalComponentOrdinal < runtimeComponents.length;
            logicalComponentOrdinal += 1
        ) {
            requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                input.catalog,
                input.kernel,
                'collecting',
            );
            const component = runtimeComponents[logicalComponentOrdinal];
            if (component === undefined) {
                throw new CanonicalStreamInternalError(
                    'The evaluator runtime-component inventory changed during ingestion.',
                );
            }
            const beginStatus = input.context.runExclusive(
                'evaluator aggregate runtime-component begin',
                () =>
                    input.context.wasmExports.sealed_lattice_evaluator_aggregate_begin_runtime_component_tree(
                        input.sessionHandle,
                        selectedSuiteHandle,
                        logicalComponentOrdinal,
                    ),
            );
            input.statusBoundary.throwIfError(beginStatus);
            const chunkCount = Math.ceil(
                component.totalByteLength /
                    foundationProfile.streamChunkByteLength,
            );
            for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
                throwIfAborted(input.options.signal);
                const exactByteLength = Math.min(
                    foundationProfile.streamChunkByteLength,
                    component.totalByteLength -
                        chunkIndex * foundationProfile.streamChunkByteLength,
                );
                const chunkBytes = await readStoreExactRange({
                    chunkByteLengths: input.chunkByteLengths,
                    exactByteLength,
                    sourceByteOffset:
                        component.storeByteOffset +
                        chunkIndex * foundationProfile.streamChunkByteLength,
                    store: input.store,
                    totalByteLength: input.totalStoreByteLength,
                });
                try {
                    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                        input.catalog,
                        input.kernel,
                        'collecting',
                    );
                    const status = input.context.runExclusive(
                        'evaluator aggregate runtime-component ingestion',
                        () => {
                            const chunkPointer =
                                input.memoryBoundary.copy(chunkBytes);
                            try {
                                return input.context.wasmExports.sealed_lattice_evaluator_aggregate_absorb_runtime_component_chunk(
                                    input.sessionHandle,
                                    logicalComponentOrdinal,
                                    chunkIndex,
                                    chunkPointer,
                                    chunkBytes.byteLength,
                                );
                            } finally {
                                input.memoryBoundary.zeroAndDeallocate(
                                    chunkPointer,
                                    chunkBytes.byteLength,
                                );
                            }
                        },
                    );
                    input.statusBoundary.throwIfError(status);
                } finally {
                    chunkBytes.fill(0);
                }
                await yieldControl();
            }
            requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                input.catalog,
                input.kernel,
                'collecting',
            );
            const finishStatus = input.context.runExclusive(
                'evaluator aggregate runtime-component finish',
                () =>
                    input.context.wasmExports.sealed_lattice_evaluator_aggregate_finish_runtime_component_tree(
                        input.sessionHandle,
                        logicalComponentOrdinal,
                    ),
            );
            input.statusBoundary.throwIfError(finishStatus);
        }
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            input.catalog,
            input.kernel,
            'collecting',
        );
        const statementStatus = input.context.runExclusive(
            'evaluator aggregate statement finalization',
            () =>
                input.context.wasmExports.sealed_lattice_evaluator_aggregate_finalize_statement(
                    input.sessionHandle,
                    selectedSuiteHandle,
                ),
        );
        input.statusBoundary.throwIfError(statementStatus);
        unretainedCanonicalApplicationStatement =
            copyCanonicalApplicationStatement({
                context: input.context,
                memoryBoundary: input.memoryBoundary,
                sessionHandle: input.sessionHandle,
                statusBoundary: input.statusBoundary,
            });
        for (
            let chunkIndex = 0;
            chunkIndex < input.chunkByteLengths.length;
            chunkIndex += 1
        ) {
            throwIfAborted(input.options.signal);
            const chunkBytes = await readStoreChunk({
                chunkByteLengths: input.chunkByteLengths,
                chunkIndex,
                store: input.store,
            });
            try {
                requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
                    input.catalog,
                    input.kernel,
                    'collecting',
                );
                const status = input.context.runExclusive(
                    'evaluator aggregate store-material ingestion',
                    () => {
                        const chunkPointer =
                            input.memoryBoundary.copy(chunkBytes);
                        try {
                            return input.context.wasmExports.sealed_lattice_evaluator_aggregate_absorb_store_material_chunk(
                                input.sessionHandle,
                                chunkIndex,
                                chunkPointer,
                                chunkBytes.byteLength,
                            );
                        } finally {
                            input.memoryBoundary.zeroAndDeallocate(
                                chunkPointer,
                                chunkBytes.byteLength,
                            );
                        }
                    },
                );
                input.statusBoundary.throwIfError(status);
            } finally {
                chunkBytes.fill(0);
            }
            await yieldControl();
        }
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            input.catalog,
            input.kernel,
            'collecting',
        );
        const finishStoreStatus = input.context.runExclusive(
            'evaluator aggregate store-material finish',
            () =>
                input.context.wasmExports.sealed_lattice_evaluator_aggregate_finish_store_material(
                    input.sessionHandle,
                ),
        );
        input.statusBoundary.throwIfError(finishStoreStatus);
        releaseSuite({
            context: input.context,
            selectedSuiteHandle,
            statusBoundary: input.statusBoundary,
        });
        selectedSuiteHandle = 0;
        const canonicalApplicationStatement =
            unretainedCanonicalApplicationStatement;
        unretainedCanonicalApplicationStatement = undefined;
        return canonicalApplicationStatement;
    } finally {
        unretainedCanonicalApplicationStatement?.fill(0);
        if (selectedSuiteHandle !== 0) {
            releaseSuite({
                context: input.context,
                selectedSuiteHandle,
                statusBoundary: input.statusBoundary,
            });
        }
    }
};

const destroyRecordBytes = (record: EvaluatorAggregateSessionRecord): void => {
    record.canonicalApplicationStatement.fill(0);
    record.canonicalSuiteRecordBytes.fill(0);
    record.storeDescription.fullObjectDigest.fill(0);
};

const cancelSession = (session: EvaluatorAggregateSession): void => {
    const record = requireSessionRecord(session);
    let operationFailure: unknown;
    try {
        record.generatedProof?.release();
        record.generatedProof = undefined;
    } catch (error) {
        operationFailure = error;
    }
    try {
        discardKernelSession(record);
        sessionRecords.delete(session);
        destroyRecordBytes(record);
    } catch (cleanupFailure) {
        throw operationFailure === undefined
            ? cleanupFailure
            : new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    if (operationFailure !== undefined) {
        throw operationFailure instanceof Error
            ? operationFailure
            : new CanonicalStreamInternalError(
                  'The evaluator aggregate generated-proof release failed.',
                  operationFailure,
              );
    }
};

const generate = async (
    session: EvaluatorAggregateSession,
    input: Parameters<EvaluatorAggregateSession['generate']>[0],
): Promise<Uint8Array<ArrayBuffer>> => {
    const record = requireSessionRecord(session);
    requirePhase(record, 'prepared');
    if (
        input.generationMode !== 'fresh' &&
        input.generationMode !== 'resumed'
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        record.catalog,
        record.kernel,
        'collecting',
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    const statusBoundary = createStatusBoundary();
    const checkpointLineageIdentifier = requireAttemptIdentifier(
        input.checkpointLineageIdentifier,
    );
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let operationFailure: unknown;
    record.phase = 'generating';
    try {
        let adapterHandle: number | undefined;
        await withClosedWorkerProductionOperationAuthority(
            input.workerKernel,
            input.productionOperationIdentifiers,
            (productionOperationAuthority) =>
                productionOperationAuthority.withExactKernelAuthorization(
                    (authorization) => {
                        if (
                            authorization.kernel !== record.kernel ||
                            authorization.actionRandomnessContext.memory !==
                                record.context.memory ||
                            authorization.stateReservationCapabilityMemory !==
                                record.context.memory ||
                            authorization.stateReservationCapabilityPointer <=
                                0 ||
                            authorization.stateReservationCapabilityPointer +
                                stateVerifierCapabilityByteLength >
                                record.context.memory.buffer.byteLength
                        ) {
                            throw new CanonicalStreamRefusalError(
                                'wrongContext',
                            );
                        }
                        adapterHandle = record.context.runExclusive(
                            'evaluator aggregate generation preparation',
                            () => {
                                const checkpointPointer = memoryBoundary.copy(
                                    checkpointLineageIdentifier,
                                );
                                const statusPointer =
                                    memoryBoundary.allocateZeroedWords(1);
                                try {
                                    const prepare =
                                        input.generationMode === 'fresh'
                                            ? record.context.wasmExports
                                                  .sealed_lattice_evaluator_aggregate_prepare_generation
                                            : record.context.wasmExports
                                                  .sealed_lattice_evaluator_aggregate_prepare_resumed_generation;
                                    const handle = prepare(
                                        record.sessionHandle,
                                        authorization.actionRandomnessHandle,
                                        authorization.stateVerifierSessionHandle,
                                        authorization.stateReservationCapabilityPointer,
                                        stateVerifierCapabilityByteLength,
                                        authorization.stateReservationHandle,
                                        checkpointPointer,
                                        checkpointLineageIdentifier.byteLength,
                                        statusPointer,
                                    );
                                    const [status] = memoryBoundary.readWords(
                                        statusPointer,
                                        1,
                                    );
                                    statusBoundary.throwIfError(status);
                                    return requireLiveHandle(
                                        handle,
                                        'The evaluator aggregate generation adapter handle',
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
                    },
                ),
        );
        if (adapterHandle === undefined) {
            throw new CanonicalStreamInternalError(
                'The production operation completed without an evaluator aggregate adapter.',
            );
        }
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            record.context,
            adapterHandle,
        );
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const execution =
            await runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener(
                adapterForRun,
                input.openProofGenerationExecution,
            );
        generatedCapability = execution.generatedCapability;
        const proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor(
            {
                kernel: record.kernel,
                outputChunkByteLengths: execution.outputChunkByteLengths,
                outputStore: execution.outputStore,
                proofFamilyLabel: 'evaluator aggregate',
                streamDomain: canonicalStreamDomains.evaluatorKeyAggregateProof,
            },
        );
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            record.catalog,
            record.kernel,
            'collecting',
        );
        const status = applyClosedWorkerGeneratedCommonProofCapability(
            generatedCapability,
            record.context,
            (generatedCommonProofHandle) => {
                const commitStatus = record.context.runExclusive(
                    'evaluator aggregate generated-proof commit',
                    () =>
                        record.context.wasmExports.sealed_lattice_evaluator_aggregate_commit_generated_proof(
                            record.sessionHandle,
                            generatedCommonProofHandle,
                        ),
                );
                return Object.freeze({
                    consumed: false,
                    result: commitStatus,
                });
            },
        );
        if (status !== 0) {
            generatedCapability.release();
            generatedCapability = undefined;
            statusBoundary.throwIfError(status);
        }
        record.generatedProof = generatedCapability;
        generatedCapability = undefined;
        record.phase = 'generated';
        return proofDescriptorBytes;
    } catch (error) {
        operationFailure = error;
    } finally {
        checkpointLineageIdentifier.fill(0);
    }
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
    try {
        discardKernelSession(record);
        sessionRecords.delete(session);
        destroyRecordBytes(record);
    } catch (error) {
        cleanupFailures.push(error);
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Evaluator aggregate generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};

const contributeToPackage = (
    session: EvaluatorAggregateSession,
    builder: AcceptedSetupPackageBuilder,
): void => {
    const record = requireSessionRecord(session);
    requirePhase(record, 'generated');
    const generatedProof = record.generatedProof;
    if (generatedProof === undefined) {
        throw new CanonicalStreamInternalError(
            'The evaluator aggregate generated proof is unavailable.',
        );
    }
    const builderOwner = requireAcceptedSetupPackageBuilderKernelOwner(
        builder,
        record.kernel,
        'collecting',
    );
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        record.catalog,
        record.kernel,
        'collecting',
    );
    const memoryBoundary = createMemoryBoundary(record.context);
    let statementPointer = 0;
    try {
        statementPointer = memoryBoundary.copy(
            record.canonicalApplicationStatement,
        );
        const status = applyClosedWorkerGeneratedCommonProofCapability(
            generatedProof,
            record.context,
            (generatedProofHandle) =>
                Object.freeze({
                    consumed: false,
                    result: record.context.runExclusive(
                        'evaluator aggregate package contribution',
                        () =>
                            record.context.wasmExports.sealed_lattice_evaluator_aggregate_contribute_package(
                                record.sessionHandle,
                                builderOwner.handle,
                                generatedProofHandle,
                                statementPointer,
                                record.canonicalApplicationStatement.byteLength,
                            ),
                    ),
                }),
        );
        createStatusBoundary().throwIfError(status);
        record.phase = 'packageContributed';
    } finally {
        memoryBoundary.zeroAndDeallocate(
            statementPointer,
            record.canonicalApplicationStatement.byteLength,
        );
    }
};

const bindPackageStatement = (
    session: EvaluatorAggregateSession,
    acceptedSetupVerification: AcceptedSetupVerificationSession,
): void => {
    const record = requireSessionRecord(session);
    if (record.phase === 'packageContributed') {
        const generatedProof = record.generatedProof;
        if (generatedProof === undefined) {
            throw new CanonicalStreamInternalError(
                'The evaluator aggregate generated proof is unavailable.',
            );
        }
        requireAcceptedSetupVerificationAssemblyKernelOwner(
            acceptedSetupVerification,
            record.kernel,
            'collecting',
        );
        applyClosedWorkerGeneratedCommonProofCapability(
            generatedProof,
            record.context,
            () => {
                bindAcceptedSetupEvaluatorGeneratedProofsToPackage({
                    acceptedSetupVerification,
                    catalog: record.catalog,
                    kernel: record.kernel,
                });
                return Object.freeze({ consumed: true, result: undefined });
            },
        );
        record.generatedProof = undefined;
        record.phase = 'packageBound';
    }
    requirePhase(record, 'packageBound');
    const status = record.context.runExclusive(
        'evaluator aggregate package-statement handoff',
        () =>
            record.context.wasmExports.sealed_lattice_evaluator_aggregate_take_package_statement_source(
                record.sessionHandle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    record.phase = 'packageStatementRetained';
};

const verify = async (
    session: EvaluatorAggregateSession,
    input: Parameters<EvaluatorAggregateSession['verify']>[0],
): Promise<void> => {
    const record = requireSessionRecord(session);
    requirePhase(record, 'packageStatementRetained');
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        record.catalog,
        record.kernel,
        'complete',
    );
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = createMemoryBoundary(record.context);
    let selectedSuiteHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let verifiedCapability: VerifiedCommonProofCapability | undefined;
    let operationFailure: unknown;
    record.phase = 'verifying';
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: record.canonicalSuiteRecordBytes,
            context: record.context,
            memoryBoundary,
            statusBoundary,
        });
        const adapterHandle = record.context.runExclusive(
            'evaluator aggregate verification preparation',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle =
                        record.context.wasmExports.sealed_lattice_evaluator_aggregate_prepare_verification(
                            selectedSuiteHandle,
                            record.sessionHandle,
                            statusPointer,
                        );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The evaluator aggregate verification adapter handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            record.context,
            adapterHandle,
        );
        releaseSuite({
            context: record.context,
            selectedSuiteHandle,
            statusBoundary,
        });
        selectedSuiteHandle = 0;
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        verifiedCapability =
            await runClosedWorkerCommonProofVerificationFamilyAdapter(
                adapterForRun,
                input.proofInputStore,
                input.options,
            );
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            record.catalog,
            record.kernel,
            'complete',
        );
        const status = applyClosedWorkerVerifiedCommonProofCapability(
            verifiedCapability,
            record.context,
            (verifiedCommonProofHandle) => {
                const finishStatus = record.context.runExclusive(
                    'evaluator aggregate verification finish',
                    () =>
                        record.context.wasmExports.sealed_lattice_evaluator_aggregate_finish_verification(
                            record.sessionHandle,
                            verifiedCommonProofHandle,
                        ),
                );
                return Object.freeze({
                    consumed: finishStatus === 0,
                    result: finishStatus,
                });
            },
        );
        if (status !== 0) {
            verifiedCapability.release();
            verifiedCapability = undefined;
            statusBoundary.throwIfError(status);
        }
        verifiedCapability = undefined;
        record.phase = 'verified';
        return;
    } catch (error) {
        operationFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSuite({
                context: record.context,
                selectedSuiteHandle,
                statusBoundary,
            });
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofVerificationFamilyAdapter(
                familyAdapter,
            );
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (verifiedCapability !== undefined) {
        try {
            verifiedCapability.release();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    try {
        discardKernelSession(record);
        sessionRecords.delete(session);
        destroyRecordBytes(record);
    } catch (error) {
        cleanupFailures.push(error);
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Evaluator aggregate verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};

const commitVerifiedStore = (
    session: EvaluatorAggregateSession,
    acceptedSetupVerification: AcceptedSetupVerificationSession,
): void => {
    const record = requireSessionRecord(session);
    if (record.phase === 'storeCommitted') {
        discardKernelSession(record);
        sessionRecords.delete(session);
        destroyRecordBytes(record);
        return;
    }
    requirePhase(record, 'verified');
    const acceptedSetupOwner =
        requireAcceptedSetupVerificationAssemblyKernelOwner(
            acceptedSetupVerification,
            record.kernel,
            'collecting',
        );
    const status = record.context.runExclusive(
        'evaluator aggregate verified-store commit',
        () =>
            record.context.wasmExports.sealed_lattice_evaluator_aggregate_commit_verified_store(
                record.sessionHandle,
                acceptedSetupOwner.handle,
            ),
    );
    createStatusBoundary().throwIfError(status);
    record.phase = 'storeCommitted';
    discardKernelSession(record);
    sessionRecords.delete(session);
    destroyRecordBytes(record);
};

const createSession = (
    record: EvaluatorAggregateSessionRecord,
): EvaluatorAggregateSession => {
    const session: EvaluatorAggregateSession = Object.freeze({
        [evaluatorAggregateSessionBrand]: true as const,
        bindPackageStatement: (acceptedSetupVerification): void =>
            bindPackageStatement(session, acceptedSetupVerification),
        cancel: (): void => cancelSession(session),
        commitVerifiedStore: (acceptedSetupVerification): void =>
            commitVerifiedStore(session, acceptedSetupVerification),
        copyCanonicalApplicationStatement: (): Uint8Array<ArrayBuffer> =>
            Uint8Array.from(
                requireSessionRecord(session).canonicalApplicationStatement,
            ),
        describeStore: (): EvaluatorKeyStoreDescription => {
            const description = requireSessionRecord(session).storeDescription;
            return Object.freeze({
                fullObjectDigest: Uint8Array.from(description.fullObjectDigest),
                totalByteLength: description.totalByteLength,
            });
        },
        generate: (input): Promise<Uint8Array<ArrayBuffer>> =>
            generate(session, input),
        contributeToPackage: (builder): void =>
            contributeToPackage(session, builder),
        verify: (input): Promise<void> => verify(session, input),
    });
    sessionRecords.set(session, record);
    return session;
};

/**
 * Constructs the exact selected evaluator store, recomputes every runtime
 * component tree from committed store bytes, and retains the Rust-owned
 * statement for fresh or resumed common-proof generation.
 */
export const constructEvaluatorAggregateInClosedWorker = async (input: {
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    kernel: TranscriptCoreKernel;
    options?: EvaluatorAggregateConstructionOptions;
    selectedSuiteRecordSource: SelectedSuiteRecordSource;
    store: CommonProofCanonicalOutputStore;
}): Promise<EvaluatorAggregateSession> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Evaluator aggregate construction may only run inside the dedicated WASM worker.',
        );
    }
    const context = requireEvaluatorAggregateContext(input.kernel);
    const catalogOwner = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    const memoryBoundary = createMemoryBoundary(context);
    const statusBoundary = createStatusBoundary();
    const canonicalSuiteRecordBytes = copySelectedSuiteRecordSourceBytes({
        kernel: input.kernel,
        source: input.selectedSuiteRecordSource,
    });
    let sessionHandle = 0;
    let unretainedCanonicalApplicationStatement:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let operationFailure: unknown;
    try {
        sessionHandle = context.runExclusive(
            'evaluator aggregate store-construction begin',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle =
                        context.wasmExports.sealed_lattice_evaluator_aggregate_begin_store_construction(
                            catalogOwner.handle,
                            statusPointer,
                        );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The evaluator aggregate session handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        const construction = await constructStore({
            catalog: input.evaluatorSourceCatalog,
            context,
            kernel: input.kernel,
            memoryBoundary,
            options: input.options ?? {},
            outputStore: input.store,
            sessionHandle,
            statusBoundary,
        });
        unretainedCanonicalApplicationStatement =
            await bindRuntimeTreesAndStoreMaterial({
                catalog: input.evaluatorSourceCatalog,
                canonicalSuiteRecordBytes,
                chunkByteLengths: construction.chunkByteLengths,
                context,
                kernel: input.kernel,
                memoryBoundary,
                options: input.options ?? {},
                physicalComponents: construction.physicalComponents,
                sessionHandle,
                statusBoundary,
                store: input.store,
                totalStoreByteLength: Number(
                    construction.storeDescription.totalByteLength,
                ),
            });
        const session = createSession({
            canonicalApplicationStatement:
                unretainedCanonicalApplicationStatement,
            canonicalSuiteRecordBytes,
            catalog: input.evaluatorSourceCatalog,
            context,
            generatedProof: undefined,
            kernel: input.kernel,
            phase: 'prepared',
            sessionHandle,
            storeDescription: construction.storeDescription,
        });
        unretainedCanonicalApplicationStatement = undefined;
        sessionHandle = 0;
        return session;
    } catch (error) {
        operationFailure = error;
    }
    let cleanupFailure: unknown;
    if (sessionHandle !== 0) {
        try {
            const status = context.runExclusive(
                'unwrapped evaluator aggregate session discard',
                () =>
                    context.wasmExports.sealed_lattice_evaluator_aggregate_discard_session(
                        sessionHandle,
                    ),
            );
            statusBoundary.throwIfError(status);
        } catch (error) {
            cleanupFailure = error;
        }
    }
    unretainedCanonicalApplicationStatement?.fill(0);
    canonicalSuiteRecordBytes.fill(0);
    if (cleanupFailure !== undefined) {
        throw new CanonicalStreamCleanupError(operationFailure, cleanupFailure);
    }
    throw operationFailure;
};
