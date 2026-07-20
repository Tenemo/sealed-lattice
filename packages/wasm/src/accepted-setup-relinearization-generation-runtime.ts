import {
    foundationProfile,
    refusalReasonCodes,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

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
import { isUint8Array } from './byte-array.js';
import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamDomains,
    CanonicalStreamCancellationError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    yieldBrowserWorkerTurn,
    type CommonProofAuthenticatedSourceRangeRequest,
} from './common-proof-worker-runtime/kernel-boundaries.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofGenerationExecutionOpener,
} from './common-proof-worker-runtime/runtime.js';
import { deriveGeneratedCommonProofDescriptor } from './generated-common-proof-output-runtime.js';
import type { ClosedWorkerProductionOperationIdentifiers } from './local-storage-root-worker-kernel/authorities.js';
import { withClosedWorkerProductionOperationAuthority } from './local-storage-root-worker-kernel/worker-kernel.js';
import {
    resolveSetupGenerationAuthorityKernelAuthorization,
    type BrowserOwnedSetupGenerationAuthority,
} from './setup-generation-recipient-payload.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type {
    TranscriptCoreKernel,
    TranscriptCoreKernelExports,
} from './transcript-core-bridge/kernel-types.js';
import { resolveOrderedVerifiedBoardObjectAuthorization } from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const checkpointLineageIdentifierByteLength = 32;
const materialRootByteLength = 64;
const unsigned64ByteLength = BigUint64Array.BYTES_PER_ELEMENT;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const sourceReadRequired = 1;
const activationComplete = 0;
const maximumActivationReadCount =
    2 *
    Math.ceil(
        foundationProfile.maximumCanonicalStreamByteLength /
            foundationProfile.streamChunkByteLength,
    );
const maximumCanonicalStreamByteLength = BigInt(
    foundationProfile.maximumCanonicalStreamByteLength,
);

const abortSignalIsAborted = (signal: AbortSignal | undefined): boolean =>
    signal?.aborted === true;

type RelinearizationParticipantRound = 'roundOne' | 'roundTwo';
export type RelinearizationGenerationMode = 'fresh' | 'resumed';
export type RelinearizationComponentStore = GeneratedEvaluatorComponentStore;
export type RelinearizationComponentDescription =
    GeneratedEvaluatorComponentDescription;

export type GeneratedRelinearizationParticipantProof = Readonly<{
    components: readonly RelinearizationComponentDescription[];
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

type ParticipantKernel = Readonly<{
    absorbRoundTwoActivationSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_activation_absorb_source']
    >;
    beginRoundTwoActivation: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_activation_begin']
    >;
    discardRoundTwoActivation: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_activation_discard']
    >;
    finishRoundTwoActivation: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_activation_finish']
    >;
    nextRoundTwoActivationSourceRead: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_activation_next_source_read']
    >;
    commitGeneratedSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_source_commit']
    >;
    componentCount: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_component_count']
    >;
    componentDescriptorByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_component_descriptor_byte_length']
    >;
    componentTotalByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_component_total_byte_length']
    >;
    copyComponentDescriptor: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_component_copy_descriptor']
    >;
    copyComponentMaterialRoot: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_component_copy_material_root']
    >;
    discardGenerationSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_source_discard']
    >;
    prepareRoundOne: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_prepare_generation']
    >;
    prepareResumedRoundOne: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_one_prepare_resumed_generation']
    >;
    prepareRoundTwo: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_prepare_generation']
    >;
    prepareResumedRoundTwo: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_round_two_prepare_resumed_generation']
    >;
    readComponentChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_relinearization_generation_component_read_chunk']
    >;
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_select_suite']
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
            'The RKG participant generator failed internally.',
        unknownStatusMessage:
            'The RKG participant generator returned an unknown status code.',
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

const requireFixedOwnedBytes = (
    value: Uint8Array,
    expectedByteLength: number,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireParticipantKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): ParticipantKernel => {
    const exports = context.wasmExports;
    const kernel: Partial<ParticipantKernel> = {
        absorbRoundTwoActivationSource:
            exports.sealed_lattice_relinearization_round_two_activation_absorb_source,
        beginRoundTwoActivation:
            exports.sealed_lattice_relinearization_round_two_activation_begin,
        discardRoundTwoActivation:
            exports.sealed_lattice_relinearization_round_two_activation_discard,
        finishRoundTwoActivation:
            exports.sealed_lattice_relinearization_round_two_activation_finish,
        nextRoundTwoActivationSourceRead:
            exports.sealed_lattice_relinearization_round_two_activation_next_source_read,
        commitGeneratedSource:
            exports.sealed_lattice_relinearization_generation_source_commit,
        componentCount:
            exports.sealed_lattice_relinearization_generation_component_count,
        componentDescriptorByteLength:
            exports.sealed_lattice_relinearization_generation_component_descriptor_byte_length,
        componentTotalByteLength:
            exports.sealed_lattice_relinearization_generation_component_total_byte_length,
        copyComponentDescriptor:
            exports.sealed_lattice_relinearization_generation_component_copy_descriptor,
        copyComponentMaterialRoot:
            exports.sealed_lattice_relinearization_generation_component_copy_material_root,
        discardGenerationSource:
            exports.sealed_lattice_relinearization_generation_source_discard,
        prepareRoundOne:
            exports.sealed_lattice_relinearization_round_one_prepare_generation,
        prepareResumedRoundOne:
            exports.sealed_lattice_relinearization_round_one_prepare_resumed_generation,
        prepareRoundTwo:
            exports.sealed_lattice_relinearization_round_two_prepare_generation,
        prepareResumedRoundTwo:
            exports.sealed_lattice_relinearization_round_two_prepare_resumed_generation,
        readComponentChunk:
            exports.sealed_lattice_relinearization_generation_component_read_chunk,
        releaseSelectedSuite: exports.sealed_lattice_common_proof_release_suite,
        selectSuite: exports.sealed_lattice_common_proof_select_suite,
    };
    if (
        Object.values(kernel).some((boundary) => typeof boundary !== 'function')
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the RKG participant generation boundary.',
        );
    }
    return Object.freeze(kernel as ParticipantKernel);
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
        label: 'RKG participant generation',
    });

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: ParticipantKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number => {
    if (
        !isUint8Array(input.canonicalSuiteRecordBytes) ||
        input.canonicalSuiteRecordBytes.byteLength === 0
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return input.context.runExclusive('RKG selected-suite intake', () => {
        const suitePointer = input.memoryBoundary.copy(
            input.canonicalSuiteRecordBytes,
        );
        const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
        try {
            const handle = input.kernel.selectSuite(
                suitePointer,
                input.canonicalSuiteRecordBytes.byteLength,
                statusPointer,
            );
            const [status] = input.memoryBoundary.readWords(statusPointer, 1);
            input.statusBoundary.throwIfError(status);
            return requireLiveHandle(handle, 'The selected-suite handle');
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
};

const releaseSelectedSuite = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: ParticipantKernel;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'RKG selected-suite release',
        () => input.kernel.releaseSelectedSuite(input.handle),
    );
    input.statusBoundary.throwIfError(status);
};

const copyComponentBytes = (input: {
    componentOrdinal: number;
    context: TranscriptCoreKernelCommandRuntime;
    copy(
        generationSourceHandle: number,
        componentOrdinal: number,
        outputPointer: number,
        outputByteLength: number,
    ): number;
    generationSourceHandle: number;
    outputByteLength: number;
    memoryBoundary: WasmMemoryBoundary;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive(input.operationName, () => {
        const outputPointer = input.memoryBoundary.allocate(
            input.outputByteLength,
        );
        try {
            const status = input.copy(
                input.generationSourceHandle,
                input.componentOrdinal,
                outputPointer,
                input.outputByteLength,
            );
            input.statusBoundary.throwIfError(status);
            return new Uint8Array(
                input.context.memory.buffer,
                outputPointer,
                input.outputByteLength,
            ).slice();
        } finally {
            input.memoryBoundary.zeroAndDeallocate(
                outputPointer,
                input.outputByteLength,
            );
        }
    });

const createComponentReadback = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    generationSourceHandle: number;
    kernel: ParticipantKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): GeneratedEvaluatorComponentReadback => {
    const readNumber = (
        operationName: string,
        read: (statusPointer: number) => number,
    ): number =>
        input.context.runExclusive(operationName, () => {
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
    return Object.freeze({
        componentCount: () =>
            readNumber('RKG component-count readback', (statusPointer) =>
                input.kernel.componentCount(
                    input.generationSourceHandle,
                    statusPointer,
                ),
            ),
        copyDescriptor: (componentOrdinal) => {
            const byteLength = readNumber(
                'RKG component descriptor-length readback',
                (statusPointer) =>
                    input.kernel.componentDescriptorByteLength(
                        input.generationSourceHandle,
                        componentOrdinal,
                        statusPointer,
                    ),
            );
            return copyComponentBytes({
                componentOrdinal,
                context: input.context,
                copy: input.kernel.copyComponentDescriptor,
                generationSourceHandle: input.generationSourceHandle,
                memoryBoundary: input.memoryBoundary,
                operationName: 'RKG component descriptor readback',
                outputByteLength: byteLength,
                statusBoundary: input.statusBoundary,
            });
        },
        copyMaterialRoot: (componentOrdinal) =>
            copyComponentBytes({
                componentOrdinal,
                context: input.context,
                copy: input.kernel.copyComponentMaterialRoot,
                generationSourceHandle: input.generationSourceHandle,
                memoryBoundary: input.memoryBoundary,
                operationName: 'RKG component material-root readback',
                outputByteLength: materialRootByteLength,
                statusBoundary: input.statusBoundary,
            }),
        readChunk: (componentOrdinal, chunkIndex, chunkByteLength) =>
            input.context.runExclusive('RKG component chunk readback', () => {
                const outputPointer =
                    input.memoryBoundary.allocate(chunkByteLength);
                const statusPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                try {
                    const readStatus = input.kernel.readComponentChunk(
                        input.generationSourceHandle,
                        componentOrdinal,
                        chunkIndex,
                        outputPointer,
                        chunkByteLength,
                        statusPointer,
                    );
                    input.statusBoundary.throwIfError(readStatus);
                    const [status] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(status);
                    return new Uint8Array(
                        input.context.memory.buffer,
                        outputPointer,
                        chunkByteLength,
                    ).slice();
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        chunkByteLength,
                    );
                }
            }),
        totalByteLength: (componentOrdinal) =>
            input.context.runExclusive('RKG component length readback', () => {
                const statusPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                try {
                    const byteLength = input.kernel.componentTotalByteLength(
                        input.generationSourceHandle,
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
            }),
    });
};

export type RelinearizationParticipantGenerationInput = Readonly<{
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    componentStores: readonly RelinearizationComponentStore[];
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    generationMode: RelinearizationGenerationMode;
    kernel: TranscriptCoreKernel;
    openProofGenerationExecution: CommonProofGenerationExecutionOpener;
    packageBuilder: AcceptedSetupPackageBuilder;
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    workerKernel: BrowserActionStorageWorkerKernel;
}>;

const generateParticipantProof = async (
    round: RelinearizationParticipantRound,
    input: RelinearizationParticipantGenerationInput,
): Promise<GeneratedRelinearizationParticipantProof> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'RKG generation may only run inside the dedicated WASM worker.',
        );
    }
    const expectedComponentCount = round === 'roundOne' ? 2 : 1;
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        typeof input.openProofGenerationExecution !== 'function' ||
        input.componentStores.length !== expectedComponentCount
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireParticipantKernel(context);
    const packageBuilderOwner = requireAcceptedSetupPackageBuilderKernelOwner(
        input.packageBuilder,
        input.kernel,
        'collecting',
    );
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = createMemoryBoundary(context);
    const checkpointLineageIdentifier = requireFixedOwnedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const setupGeneration = resolveSetupGenerationAuthorityKernelAuthorization(
        input.setupGenerationAuthority,
        context,
    );
    const setupIntent = resolveOrderedVerifiedBoardObjectAuthorization({
        context,
        expectedObjectCount: 1,
        kernel: input.kernel,
        objects: [input.setupIntentObject],
    });
    const catalog = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    if (setupIntent.handleBytes.byteLength !== wasm32WordByteLength) {
        throw new CanonicalStreamInternalError(
            'The RKG generation authorities do not belong to one WASM worker.',
        );
    }

    let selectedSuiteHandle = 0;
    let generationSourceHandle = 0;
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
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        let prepared:
            | Readonly<{
                  adapterHandle: number;
                  sourceHandle: number;
              }>
            | undefined;
        await withClosedWorkerProductionOperationAuthority(
            input.workerKernel,
            input.productionOperationIdentifiers,
            (productionOperationAuthority) =>
                productionOperationAuthority.withExactKernelAuthorization(
                    (authorization) => {
                        if (
                            authorization.kernel !== input.kernel ||
                            authorization.actionRandomnessContext.memory !==
                                context.memory ||
                            authorization.stateReservationCapabilityMemory !==
                                context.memory ||
                            authorization.stateReservationCapabilityPointer <=
                                0 ||
                            authorization.stateReservationCapabilityPointer +
                                verifierCapabilityByteLength >
                                context.memory.buffer.byteLength
                        ) {
                            throw new CanonicalStreamInternalError(
                                'The RKG generation authorities do not belong to one WASM worker.',
                            );
                        }
                        prepared = context.runExclusive(
                            'RKG proof preparation',
                            () => {
                                const checkpointPointer = memoryBoundary.copy(
                                    checkpointLineageIdentifier,
                                );
                                const metadataPointer =
                                    memoryBoundary.allocateZeroedWords(2);
                                try {
                                    const prepare =
                                        round === 'roundOne'
                                            ? input.generationMode === 'fresh'
                                                ? kernel.prepareRoundOne
                                                : kernel.prepareResumedRoundOne
                                            : input.generationMode === 'fresh'
                                              ? kernel.prepareRoundTwo
                                              : kernel.prepareResumedRoundTwo;
                                    const adapterHandle = prepare(
                                        selectedSuiteHandle,
                                        setupGeneration.handle,
                                        round === 'roundOne'
                                            ? 0
                                            : catalog.handle,
                                        authorization.actionRandomnessHandle,
                                        authorization.stateVerifierSessionHandle,
                                        authorization.stateReservationCapabilityPointer,
                                        verifierCapabilityByteLength,
                                        authorization.stateReservationHandle,
                                        setupIntent.sessionHandle,
                                        setupIntent.capabilityPointer,
                                        verifierCapabilityByteLength,
                                        new DataView(
                                            setupIntent.handleBytes.buffer,
                                            setupIntent.handleBytes.byteOffset,
                                            setupIntent.handleBytes.byteLength,
                                        ).getUint32(0, true),
                                        checkpointPointer,
                                        checkpointLineageIdentifier.byteLength,
                                        metadataPointer,
                                        metadataPointer + wasm32WordByteLength,
                                    );
                                    const [sourceHandle, status] =
                                        memoryBoundary.readWords(
                                            metadataPointer,
                                            2,
                                        );
                                    statusBoundary.throwIfError(status);
                                    return Object.freeze({
                                        adapterHandle: requireLiveHandle(
                                            adapterHandle,
                                            'The RKG generation adapter handle',
                                        ),
                                        sourceHandle: requireLiveHandle(
                                            sourceHandle,
                                            'The RKG generation source handle',
                                        ),
                                    });
                                } finally {
                                    memoryBoundary.zeroAndDeallocate(
                                        metadataPointer,
                                        wasm32WordByteLength * 2,
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
        if (prepared === undefined) {
            throw new CanonicalStreamInternalError(
                'The production operation completed without an RKG adapter.',
            );
        }
        generationSourceHandle = prepared.sourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            statusBoundary,
        });
        selectedSuiteHandle = 0;

        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const execution =
            await runClosedWorkerCommonProofGenerationFamilyAdapterWithExecutionOpener(
                adapterForRun,
                async (description) => {
                    const opened =
                        await input.openProofGenerationExecution(description);
                    if (round === 'roundOne') {
                        return opened;
                    }
                    return Object.freeze({
                        ...opened,
                        options: Object.freeze({
                            ...opened.options,
                            authenticatedSourceRangeReader: Object.freeze({
                                readExactRange: (
                                    request: CommonProofAuthenticatedSourceRangeRequest,
                                ) =>
                                    readAcceptedSetupPrepackageEvaluatorComponentExactRange(
                                        {
                                            authenticatedByteLength:
                                                request.sourceStreamTotalByteLength,
                                            catalog:
                                                input.evaluatorSourceCatalog,
                                            exactByteLength:
                                                request.exactByteLength,
                                            fullObjectDigest:
                                                request.sourceStreamDigest,
                                            kernel: input.kernel,
                                            materialRoot:
                                                request.sourceMaterialRoot,
                                            sourceByteOffset:
                                                request.sourceStreamByteOffset,
                                        },
                                    ),
                            }),
                        }),
                    });
                },
            );
        generatedCapability = execution.generatedCapability;
        const proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor(
            {
                kernel: input.kernel,
                outputChunkByteLengths: execution.outputChunkByteLengths,
                outputStore: execution.outputStore,
                proofFamilyLabel:
                    round === 'roundOne' ? 'RKG round one' : 'RKG round two',
                streamDomain:
                    round === 'roundOne'
                        ? canonicalStreamDomains.rkgRoundOneProof
                        : canonicalStreamDomains.rkgRoundTwoProof,
            },
        );
        componentStoresNeedRelease = false;
        const persisted = await persistGeneratedEvaluatorComponents({
            expectedComponentCount,
            kernel: input.kernel,
            readback: createComponentReadback({
                context,
                generationSourceHandle,
                kernel,
                memoryBoundary,
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
        const capabilityForCommit = generatedCapability;
        const commitStatus = applyClosedWorkerGeneratedCommonProofCapability(
            capabilityForCommit,
            context,
            (generatedProofHandle) => {
                const status = context.runExclusive(
                    'RKG generated-source catalog commit',
                    () =>
                        kernel.commitGeneratedSource(
                            packageBuilderOwner.handle,
                            catalog.handle,
                            generatedProofHandle,
                            generationSourceHandle,
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
        generationSourceHandle = 0;
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
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                statusBoundary,
            });
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
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
    if (generationSourceHandle !== 0) {
        try {
            const status = context.runExclusive(
                'RKG generation-source discard',
                () => kernel.discardGenerationSource(generationSourceHandle),
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
            'RKG generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};

export const generateRelinearizationRoundOneInClosedWorker = (
    input: RelinearizationParticipantGenerationInput,
): Promise<GeneratedRelinearizationParticipantProof> =>
    generateParticipantProof('roundOne', input);

export const generateRelinearizationRoundTwoInClosedWorker = (
    input: RelinearizationParticipantGenerationInput,
): Promise<GeneratedRelinearizationParticipantProof> =>
    generateParticipantProof('roundTwo', input);

/**
 * Streams the catalog-owned aggregate through Rust authentication and freezes
 * the exact round-two witness before its proof attempt is prepared.
 */
export type RelinearizationRoundTwoActivationInput = Readonly<{
    canonicalSuiteRecordBytes: Uint8Array;
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    kernel: TranscriptCoreKernel;
    signal?: AbortSignal;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    yieldControl?: () => Promise<void>;
}>;

type RelinearizationRoundTwoActivationReadRequest = Readonly<{
    chunkIndex: number;
    componentOrdinal: number;
    materialRoot: Uint8Array<ArrayBuffer>;
    sourceByteLength: number;
    streamByteOffset: bigint;
    streamDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: bigint;
}>;

const readUnsigned64 = (
    context: TranscriptCoreKernelCommandRuntime,
    pointer: number,
): bigint =>
    new DataView(
        context.memory.buffer,
        pointer,
        unsigned64ByteLength,
    ).getBigUint64(0, true);

const pollRelinearizationRoundTwoActivationRead = (input: {
    activationHandle: number;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: ParticipantKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): RelinearizationRoundTwoActivationReadRequest | undefined =>
    input.context.runExclusive(
        'RKG round-two activation source-read poll',
        () => {
            const componentPointer =
                input.memoryBoundary.allocateZeroedWords(1);
            const materialRootPointer = input.memoryBoundary.allocate(
                materialRootByteLength,
            );
            const streamDigestPointer = input.memoryBoundary.allocate(
                materialRootByteLength,
            );
            const totalByteLengthPointer =
                input.memoryBoundary.allocate(unsigned64ByteLength);
            const streamByteOffsetPointer =
                input.memoryBoundary.allocate(unsigned64ByteLength);
            const chunkIndexPointer =
                input.memoryBoundary.allocateZeroedWords(1);
            const sourceByteLengthPointer =
                input.memoryBoundary.allocateZeroedWords(1);
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            try {
                const poll = input.kernel.nextRoundTwoActivationSourceRead(
                    input.activationHandle,
                    componentPointer,
                    materialRootPointer,
                    materialRootByteLength,
                    streamDigestPointer,
                    materialRootByteLength,
                    totalByteLengthPointer,
                    streamByteOffsetPointer,
                    chunkIndexPointer,
                    sourceByteLengthPointer,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                if (poll === activationComplete) {
                    return undefined;
                }
                if (poll !== sourceReadRequired) {
                    throw new CanonicalStreamInternalError(
                        'The RKG round-two activation returned an unknown source-read poll.',
                    );
                }
                const [componentOrdinal] = input.memoryBoundary.readWords(
                    componentPointer,
                    1,
                );
                const [chunkIndex] = input.memoryBoundary.readWords(
                    chunkIndexPointer,
                    1,
                );
                const [sourceByteLength] = input.memoryBoundary.readWords(
                    sourceByteLengthPointer,
                    1,
                );
                const totalByteLength = readUnsigned64(
                    input.context,
                    totalByteLengthPointer,
                );
                const streamByteOffset = readUnsigned64(
                    input.context,
                    streamByteOffsetPointer,
                );
                const expectedStreamByteOffset =
                    BigInt(chunkIndex) *
                    BigInt(foundationProfile.streamChunkByteLength);
                const expectedSourceByteLength = Number(
                    [
                        totalByteLength - expectedStreamByteOffset,
                        BigInt(foundationProfile.streamChunkByteLength),
                    ].reduce((minimum, value) =>
                        value < minimum ? value : minimum,
                    ),
                );
                if (
                    componentOrdinal > 1 ||
                    sourceByteLength <= 0 ||
                    sourceByteLength >
                        foundationProfile.streamChunkByteLength ||
                    totalByteLength <= 0n ||
                    totalByteLength > maximumCanonicalStreamByteLength ||
                    streamByteOffset !== expectedStreamByteOffset ||
                    sourceByteLength !== expectedSourceByteLength
                ) {
                    throw new CanonicalStreamInternalError(
                        'The RKG round-two activation exposed an inconsistent source range.',
                    );
                }
                return Object.freeze({
                    chunkIndex,
                    componentOrdinal,
                    materialRoot: new Uint8Array(
                        input.context.memory.buffer,
                        materialRootPointer,
                        materialRootByteLength,
                    ).slice(),
                    sourceByteLength,
                    streamByteOffset,
                    streamDigest: new Uint8Array(
                        input.context.memory.buffer,
                        streamDigestPointer,
                        materialRootByteLength,
                    ).slice(),
                    totalByteLength,
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
                    streamByteOffsetPointer,
                    unsigned64ByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    totalByteLengthPointer,
                    unsigned64ByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    streamDigestPointer,
                    materialRootByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    materialRootPointer,
                    materialRootByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    componentPointer,
                    wasm32WordByteLength,
                );
            }
        },
    );

const runRelinearizationRoundTwoActivationReads = async (input: {
    activationHandle: number;
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: ParticipantKernel;
    memoryBoundary: WasmMemoryBoundary;
    publicKernel: TranscriptCoreKernel;
    signal?: AbortSignal;
    statusBoundary: WasmStatusBoundary;
    yieldControl(): Promise<void>;
}): Promise<void> => {
    for (
        let requestOrdinal = 0;
        requestOrdinal <= maximumActivationReadCount;
        requestOrdinal += 1
    ) {
        if (abortSignalIsAborted(input.signal)) {
            throw new CanonicalStreamCancellationError();
        }
        const request = pollRelinearizationRoundTwoActivationRead(input);
        if (request === undefined) {
            return;
        }
        if (requestOrdinal === maximumActivationReadCount) {
            throw new CanonicalStreamInternalError(
                'The RKG round-two activation exceeded the exact source-read ceiling.',
            );
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
            if (abortSignalIsAborted(input.signal)) {
                throw new CanonicalStreamCancellationError();
            }
            const status = input.context.runExclusive(
                'RKG round-two activation source absorption',
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
                        return input.kernel.absorbRoundTwoActivationSource(
                            input.activationHandle,
                            request.componentOrdinal,
                            materialRootPointer,
                            materialRootByteLength,
                            streamDigestPointer,
                            materialRootByteLength,
                            request.totalByteLength,
                            request.streamByteOffset,
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
                            materialRootByteLength,
                        );
                        input.memoryBoundary.zeroAndDeallocate(
                            materialRootPointer,
                            materialRootByteLength,
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
        'The RKG round-two activation did not reach its terminal poll.',
    );
};

export const activateRelinearizationRoundTwoInClosedWorker = async (
    input: RelinearizationRoundTwoActivationInput,
): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'RKG round-two activation may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireParticipantKernel(context);
    const memoryBoundary = createMemoryBoundary(context);
    const statusBoundary = createStatusBoundary();
    const setupGeneration = resolveSetupGenerationAuthorityKernelAuthorization(
        input.setupGenerationAuthority,
        context,
    );
    const catalog = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    let selectedSuiteHandle = 0;
    let activationHandle = 0;
    let operationFailure: unknown;
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        activationHandle = context.runExclusive(
            'RKG round-two activation begin',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = kernel.beginRoundTwoActivation(
                        selectedSuiteHandle,
                        setupGeneration.handle,
                        catalog.handle,
                        statusPointer,
                    );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The RKG round-two activation handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            statusBoundary,
        });
        selectedSuiteHandle = 0;
        await runRelinearizationRoundTwoActivationReads({
            activationHandle,
            catalog: input.evaluatorSourceCatalog,
            context,
            kernel,
            memoryBoundary,
            publicKernel: input.kernel,
            signal: input.signal,
            statusBoundary,
            yieldControl: input.yieldControl ?? yieldBrowserWorkerTurn,
        });
        const finishStatus = context.runExclusive(
            'RKG round-two activation finish',
            () => kernel.finishRoundTwoActivation(activationHandle),
        );
        statusBoundary.throwIfError(finishStatus);
        activationHandle = 0;
        return;
    } catch (error) {
        operationFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    if (activationHandle !== 0) {
        try {
            const status = context.runExclusive(
                'RKG round-two activation discard',
                () => kernel.discardRoundTwoActivation(activationHandle),
            );
            if (status >>> 0 !== refusalReasonCodes.consumedState) {
                statusBoundary.throwIfError(status);
            }
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                statusBoundary,
            });
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'RKG round-two activation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};
