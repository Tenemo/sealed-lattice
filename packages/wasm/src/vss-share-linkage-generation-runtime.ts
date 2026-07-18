import { refusalReasonCodes } from '@sealed-lattice/types';

import {
    resolveActionRandomnessKernelAuthorization,
    type ActionRandomnessSession,
} from './action-randomness-runtime.js';
import { isUint8Array } from './byte-array.js';
import { type VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamDomains,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
import {
    applyClosedWorkerGeneratedCommonProofCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationWorkerOptions,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
} from './common-proof-worker-runtime/runtime.js';
import {
    deriveGeneratedCommonProofDescriptor,
    trackCanonicalCommonProofOutputChunks,
} from './generated-common-proof-output-runtime.js';
import {
    resolveSetupGenerationAuthorityKernelAuthorization,
    type BrowserOwnedSetupGenerationAuthority,
} from './setup-generation-recipient-payload.js';
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
import {
    resolveOrderedVerifiedBoardObjectAuthorization,
    type OrderedVerifiedBoardObjectAuthorization,
} from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const attemptIdentifierByteLength = 32;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

export type VssShareLinkageGenerationMode = 'fresh' | 'resumed';

export type VerifiedVssShareLinkageBoardCatalog = Readonly<{
    dealerRecordObject: VerifiedTranscriptObject;
    orderedCommitmentObjects: readonly VerifiedTranscriptObject[];
    orderedRevealObjects: readonly VerifiedTranscriptObject[];
    orderedSetupIntentObjects: readonly VerifiedTranscriptObject[];
}>;

type VssGenerationKernel = Readonly<{
    bindGeneratedProofToBoard: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_vss_share_linkage_bind_generated_proof_to_board']
    >;
    boardObjectHandleCatalogByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_vss_share_linkage_board_object_handle_catalog_byte_length']
    >;
    discardBoardBindingSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_vss_share_linkage_discard_generation_board_binding_source']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_vss_share_linkage_prepare_generation']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_vss_share_linkage_prepare_resumed_generation']
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
            'The VSS generation kernel session failed internally.',
        unknownStatusMessage:
            'The VSS generation kernel returned an unknown status code.',
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

const requireFixedBytes = (
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

const requireCanonicalSuiteRecordBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireVssGenerationKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): VssGenerationKernel => {
    const {
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
        sealed_lattice_vss_share_linkage_bind_generated_proof_to_board:
            bindGeneratedProofToBoard,
        sealed_lattice_vss_share_linkage_board_object_handle_catalog_byte_length:
            boardObjectHandleCatalogByteLength,
        sealed_lattice_vss_share_linkage_discard_generation_board_binding_source:
            discardBoardBindingSource,
        sealed_lattice_vss_share_linkage_prepare_generation: prepareGeneration,
        sealed_lattice_vss_share_linkage_prepare_resumed_generation:
            prepareResumedGeneration,
    } = context.wasmExports;
    if (
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function' ||
        typeof bindGeneratedProofToBoard !== 'function' ||
        typeof boardObjectHandleCatalogByteLength !== 'function' ||
        typeof discardBoardBindingSource !== 'function' ||
        typeof prepareGeneration !== 'function' ||
        typeof prepareResumedGeneration !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the VSS generation boundary.',
        );
    }
    return Object.freeze({
        bindGeneratedProofToBoard,
        boardObjectHandleCatalogByteLength,
        discardBoardBindingSource,
        prepareGeneration,
        prepareResumedGeneration,
        releaseSelectedSuite,
        selectSuite,
    });
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: VssGenerationKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive(
        'VSS generation selected-suite acquisition',
        () => {
            const suiteBytes = requireCanonicalSuiteRecordBytes(
                input.canonicalSuiteRecordBytes,
            );
            const suitePointer = input.memoryBoundary.copy(suiteBytes);
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            let selectedSuiteHandle = 0;
            try {
                selectedSuiteHandle = input.kernel.selectSuite(
                    suitePointer,
                    suiteBytes.byteLength,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return requireLiveHandle(
                    selectedSuiteHandle,
                    'The selected-suite handle',
                );
            } catch (error) {
                if (selectedSuiteHandle !== 0) {
                    input.kernel.releaseSelectedSuite(selectedSuiteHandle);
                }
                throw error;
            } finally {
                suiteBytes.fill(0);
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    suitePointer,
                    suiteBytes.byteLength,
                );
            }
        },
    );

const releaseSelectedSuite = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: VssGenerationKernel;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.kernel.releaseSelectedSuite(input.handle),
    );
    input.statusBoundary.throwIfError(status);
};

const discardBoardBindingSource = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: VssGenerationKernel;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(
        'VSS generation board-binding source discard',
        () => input.kernel.discardBoardBindingSource(input.handle),
    );
    if (status >>> 0 === refusalReasonCodes.consumedState) {
        return;
    }
    input.statusBoundary.throwIfError(status);
};

const requireSameWorkerAuthorization = (input: {
    capabilityMemory: WebAssembly.Memory;
    capabilityPointer: number;
    context: TranscriptCoreKernelCommandRuntime;
    label: string;
}): void => {
    if (
        input.capabilityMemory !== input.context.memory ||
        input.capabilityPointer <= 0 ||
        input.capabilityPointer + verifierCapabilityByteLength >
            input.context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamInternalError(
            `${input.label} does not belong to the common-proof WASM worker.`,
        );
    }
};

const resolveVerifiedBoardCatalogAuthorization = (input: {
    catalog: VerifiedVssShareLinkageBoardCatalog;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: TranscriptCoreKernel;
}): OrderedVerifiedBoardObjectAuthorization =>
    resolveOrderedVerifiedBoardObjectAuthorization({
        context: input.context,
        expectedObjectCount:
            input.catalog.orderedSetupIntentObjects.length +
            input.catalog.orderedCommitmentObjects.length +
            input.catalog.orderedRevealObjects.length +
            1,
        kernel: input.kernel,
        objects: [
            ...input.catalog.orderedSetupIntentObjects,
            ...input.catalog.orderedCommitmentObjects,
            ...input.catalog.orderedRevealObjects,
            input.catalog.dealerRecordObject,
        ],
    });

/**
 * Generates one exact selected VSS proof and consumes its Rust-owned
 * generation authority only after the complete verified board catalog binds
 * the generated descriptor and statement. The callback runs after proof
 * bytes are complete so the caller can seal custody, construct the dealer
 * record, and verify that record in the same worker.
 */
export const generateVssShareLinkageInClosedWorker = async (input: {
    actionRandomnessSession: ActionRandomnessSession;
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    externalMemory: CommonProofExternalMemoryTransactionExecutor;
    generationMode: VssShareLinkageGenerationMode;
    kernel: TranscriptCoreKernel;
    options?: CommonProofGenerationWorkerOptions;
    outputStore: CommonProofCanonicalOutputStore;
    resolveVerifiedBoardCatalog(input: {
        proofDescriptorBytes: Uint8Array<ArrayBuffer>;
    }): Promise<VerifiedVssShareLinkageBoardCatalog>;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    verifiedReservation: VerifiedStateReservation;
}): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'VSS proof generation may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireVssGenerationKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'VSS generation boundary',
    });
    const checkpointLineageIdentifier = requireFixedBytes(
        input.checkpointLineageIdentifier,
        attemptIdentifierByteLength,
    );
    const actionRandomnessAuthorization =
        resolveActionRandomnessKernelAuthorization(
            input.actionRandomnessSession,
            input.kernel,
        );
    const setupGenerationAuthorization =
        resolveSetupGenerationAuthorityKernelAuthorization(
            input.setupGenerationAuthority,
            context,
        );
    const stateAuthorization =
        resolveVerifiedStateReservationKernelAuthorization(
            input.verifiedReservation,
            input.kernel,
        );
    const setupIntentAuthorization =
        resolveOrderedVerifiedBoardObjectAuthorization({
            context,
            expectedObjectCount: 1,
            kernel: input.kernel,
            objects: [input.setupIntentObject],
        });
    requireSameWorkerAuthorization({
        capabilityMemory: stateAuthorization.capabilityMemory,
        capabilityPointer: stateAuthorization.capabilityPointer,
        context,
        label: 'The state-verifier reservation authority',
    });
    if (actionRandomnessAuthorization.context.memory !== context.memory) {
        throw new CanonicalStreamInternalError(
            'The action-randomness session belongs to another WASM worker.',
        );
    }

    let boardBindingSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context,
        kernel,
        memoryBoundary,
        statusBoundary,
    });
    let operationFailed = false;
    let operationFailure: unknown;
    try {
        const prepared = context.runExclusive(
            'VSS generation preparation',
            () => {
                const checkpointPointer = memoryBoundary.copy(
                    checkpointLineageIdentifier,
                );
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const prepare =
                        input.generationMode === 'fresh'
                            ? kernel.prepareGeneration
                            : kernel.prepareResumedGeneration;
                    const adapterHandle = prepare(
                        selectedSuiteHandle,
                        setupGenerationAuthorization.handle,
                        actionRandomnessAuthorization.handle,
                        stateAuthorization.sessionHandle,
                        stateAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        stateAuthorization.reservationHandle,
                        setupIntentAuthorization.sessionHandle,
                        setupIntentAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        new DataView(
                            setupIntentAuthorization.handleBytes.buffer,
                            setupIntentAuthorization.handleBytes.byteOffset,
                            setupIntentAuthorization.handleBytes.byteLength,
                        ).getUint32(0, true),
                        checkpointPointer,
                        checkpointLineageIdentifier.byteLength,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const [sourceHandle, status] = memoryBoundary.readWords(
                        metadataPointer,
                        2,
                    );
                    statusBoundary.throwIfError(status);
                    return Object.freeze({
                        adapterHandle: requireLiveHandle(
                            adapterHandle,
                            'The VSS generation family-adapter handle',
                        ),
                        boardBindingSourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The VSS generation board-binding source handle',
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
        boardBindingSourceHandle = prepared.boardBindingSourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName: 'VSS generation selected-suite release',
            statusBoundary,
        });
        selectedSuiteHandle = 0;

        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const trackedOutput = trackCanonicalCommonProofOutputChunks(
            input.outputStore,
        );
        generatedCapability =
            await runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability(
                adapterForRun,
                input.externalMemory,
                trackedOutput.outputStore,
                input.options,
            );
        const proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor(
            {
                kernel: input.kernel,
                outputChunkByteLengths: trackedOutput.outputChunkByteLengths,
                outputStore: input.outputStore,
                proofFamilyLabel: 'VSS share-linkage',
                streamDomain: canonicalStreamDomains.dealerVssShareLinkageProof,
            },
        );
        const catalog = await input.resolveVerifiedBoardCatalog({
            proofDescriptorBytes,
        });
        const catalogAuthorization = resolveVerifiedBoardCatalogAuthorization({
            catalog,
            context,
            kernel: input.kernel,
        });
        const expectedCatalogByteLength = context.runExclusive(
            'VSS generation board-object catalog length',
            () => kernel.boardObjectHandleCatalogByteLength(),
        );
        if (
            expectedCatalogByteLength !==
            catalogAuthorization.handleBytes.byteLength
        ) {
            throw new CanonicalStreamInternalError(
                'The VSS generator and browser adapter disagree on the exact board-object catalog length.',
            );
        }
        const catalogPointer = memoryBoundary.copy(
            catalogAuthorization.handleBytes,
        );
        try {
            const capabilityForBinding = generatedCapability;
            applyClosedWorkerGeneratedCommonProofCapability(
                capabilityForBinding,
                context,
                (generatedCommonProofHandle) => {
                    const status = context.runExclusive(
                        'VSS generated-proof board binding',
                        () =>
                            kernel.bindGeneratedProofToBoard(
                                generatedCommonProofHandle,
                                boardBindingSourceHandle,
                                catalogAuthorization.sessionHandle,
                                catalogAuthorization.capabilityPointer,
                                verifierCapabilityByteLength,
                                catalogPointer,
                                catalogAuthorization.handleBytes.byteLength,
                            ),
                    );
                    statusBoundary.throwIfError(status);
                    return Object.freeze({
                        consumed: true,
                        result: undefined,
                    });
                },
            );
            generatedCapability = undefined;
            boardBindingSourceHandle = 0;
        } finally {
            memoryBoundary.zeroAndDeallocate(
                catalogPointer,
                catalogAuthorization.handleBytes.byteLength,
            );
        }
    } catch (error) {
        operationFailed = true;
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
                operationName: 'VSS generation selected-suite failure release',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (generatedCapability !== undefined) {
        try {
            generatedCapability.release();
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (boardBindingSourceHandle !== 0) {
        try {
            discardBoardBindingSource({
                context,
                handle: boardBindingSourceHandle,
                kernel,
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'VSS generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
};
