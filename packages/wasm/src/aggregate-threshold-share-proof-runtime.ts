import {
    foundationProfile,
    refusalReasonCodes,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import {
    requireAggregateThresholdShareRecipientAuthorityKernelOwner,
    type AggregateThresholdShareRecipientAuthority,
} from './aggregate-threshold-share-authenticated-recipient.js';
import { isUint8Array } from './byte-array.js';
import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamDomains,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from './canonical-stream-runtime.js';
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
    type CommonProofGenerationExecutionOpener,
    type CommonProofVerificationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import { deriveGeneratedCommonProofDescriptor } from './generated-common-proof-output-runtime.js';
import type { ClosedWorkerProductionOperationIdentifiers } from './local-storage-root-worker-kernel/authorities.js';
import { withClosedWorkerProductionOperationAuthority } from './local-storage-root-worker-kernel/worker-kernel.js';
import { mlDsa65SignatureByteLength } from './state-verifier-runtime/contracts.js';
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
const checkpointLineageIdentifierByteLength = 32;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const foundationHashByteLength = 64;

export type AggregateThresholdShareGenerationMode = 'fresh' | 'resumed';

export type PrivateShareAcceptanceSignatureOperation = Readonly<{
    signPrivateShareAcceptanceMessage(
        signatureMessageHash: Uint8Array<ArrayBuffer>,
    ): Uint8Array;
}>;

type PreparedAggregateThresholdShareGeneration = Readonly<{
    adapterHandle: number;
    boardBindingSourceHandle: number;
}>;

type AggregateThresholdShareProofKernel = Readonly<{
    bindGeneratedProofToBoard: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_bind_generated_proof_to_board']
    >;
    cancelPrivateShareAcceptanceCarrier: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_cancel_private_share_acceptance_carrier']
    >;
    discardBoardBindingSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_discard_generation_board_binding_source']
    >;
    discardVerificationTerminalSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_discard_verification_terminal_source']
    >;
    finishVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_finish_verification']
    >;
    finishPrivateShareAcceptanceCarrier: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_finish_private_share_acceptance_carrier']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_prepare_generation']
    >;
    preparePrivateShareAcceptanceCarrier: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_prepare_private_share_acceptance_carrier']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_prepare_resumed_generation']
    >;
    prepareVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_aggregate_threshold_share_prepare_verification']
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
            'The aggregate-threshold-share proof kernel session failed internally.',
        unknownStatusMessage:
            'The aggregate-threshold-share proof kernel returned an unknown status code.',
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

const requireBoundedCanonicalBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength === 0
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    if (
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        value.byteLength > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamRefusalError('outsideSupportedProfile');
    }
    return value.slice();
};

const requireAggregateThresholdShareProofKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): AggregateThresholdShareProofKernel => {
    const {
        sealed_lattice_aggregate_threshold_share_bind_generated_proof_to_board:
            bindGeneratedProofToBoard,
        sealed_lattice_aggregate_threshold_share_cancel_private_share_acceptance_carrier:
            cancelPrivateShareAcceptanceCarrier,
        sealed_lattice_aggregate_threshold_share_discard_generation_board_binding_source:
            discardBoardBindingSource,
        sealed_lattice_aggregate_threshold_share_discard_verification_terminal_source:
            discardVerificationTerminalSource,
        sealed_lattice_aggregate_threshold_share_finish_verification:
            finishVerification,
        sealed_lattice_aggregate_threshold_share_finish_private_share_acceptance_carrier:
            finishPrivateShareAcceptanceCarrier,
        sealed_lattice_aggregate_threshold_share_prepare_generation:
            prepareGeneration,
        sealed_lattice_aggregate_threshold_share_prepare_private_share_acceptance_carrier:
            preparePrivateShareAcceptanceCarrier,
        sealed_lattice_aggregate_threshold_share_prepare_resumed_generation:
            prepareResumedGeneration,
        sealed_lattice_aggregate_threshold_share_prepare_verification:
            prepareVerification,
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
    } = context.wasmExports;
    if (
        typeof bindGeneratedProofToBoard !== 'function' ||
        typeof cancelPrivateShareAcceptanceCarrier !== 'function' ||
        typeof discardBoardBindingSource !== 'function' ||
        typeof discardVerificationTerminalSource !== 'function' ||
        typeof finishPrivateShareAcceptanceCarrier !== 'function' ||
        typeof finishVerification !== 'function' ||
        typeof prepareGeneration !== 'function' ||
        typeof preparePrivateShareAcceptanceCarrier !== 'function' ||
        typeof prepareResumedGeneration !== 'function' ||
        typeof prepareVerification !== 'function' ||
        typeof releaseSelectedSuite !== 'function' ||
        typeof selectSuite !== 'function'
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the aggregate-threshold-share proof boundary.',
        );
    }
    return Object.freeze({
        bindGeneratedProofToBoard,
        cancelPrivateShareAcceptanceCarrier,
        discardBoardBindingSource,
        discardVerificationTerminalSource,
        finishPrivateShareAcceptanceCarrier,
        finishVerification,
        prepareGeneration,
        preparePrivateShareAcceptanceCarrier,
        prepareResumedGeneration,
        prepareVerification,
        releaseSelectedSuite,
        selectSuite,
    });
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: AggregateThresholdShareProofKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive(
        'aggregate-threshold-share selected-suite acquisition',
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
    kernel: AggregateThresholdShareProofKernel;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.kernel.releaseSelectedSuite(input.handle),
    );
    input.statusBoundary.throwIfError(status);
};

const discardHandle = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    discard(handle: number): number;
    handle: number;
    operationName: string;
    statusBoundary: WasmStatusBoundary;
}): void => {
    const status = input.context.runExclusive(input.operationName, () =>
        input.discard(input.handle),
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

const resolveSingleBoardObjectAuthorization = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    kernel: TranscriptCoreKernel;
    object: VerifiedTranscriptObject;
}): Readonly<{
    authorization: OrderedVerifiedBoardObjectAuthorization;
    objectHandle: number;
}> => {
    const authorization = resolveOrderedVerifiedBoardObjectAuthorization({
        context: input.context,
        expectedObjectCount: 1,
        kernel: input.kernel,
        objects: [input.object],
    });
    return Object.freeze({
        authorization,
        objectHandle: requireLiveHandle(
            new DataView(
                authorization.handleBytes.buffer,
                authorization.handleBytes.byteOffset,
                authorization.handleBytes.byteLength,
            ).getUint32(0, true),
            'The canonical-board object handle',
        ),
    });
};

const produceCanonicalPrivateShareAcceptanceCarrier = (input: {
    boardBindingSourceHandle: number;
    canonicalRosterBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    generatedCommonProofHandle: number;
    kernel: AggregateThresholdShareProofKernel;
    memoryBoundary: WasmMemoryBoundary;
    signatureOperation: PrivateShareAcceptanceSignatureOperation;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> => {
    let signPrivateShareAcceptanceMessage: (
        signatureMessageHash: Uint8Array<ArrayBuffer>,
    ) => Uint8Array;
    try {
        if (
            typeof input.signatureOperation !== 'object' ||
            input.signatureOperation === null
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        signPrivateShareAcceptanceMessage =
            input.signatureOperation.signPrivateShareAcceptanceMessage;
        if (typeof signPrivateShareAcceptanceMessage !== 'function') {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
    } catch (error) {
        if (error instanceof CanonicalStreamRefusalError) {
            throw error;
        }
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }

    const canonicalRosterBytes = requireBoundedCanonicalBytes(
        input.canonicalRosterBytes,
    );
    let preparedCarrierHandle = 0;
    let signatureMessage: Uint8Array<ArrayBuffer> | undefined;
    let signature: Uint8Array<ArrayBuffer> | undefined;
    try {
        const preparation = input.context.runExclusive(
            'private-share acceptance carrier preparation',
            () => {
                let canonicalRosterPointer = 0;
                let canonicalCarrierByteLengthPointer = 0;
                let signatureMessagePointer = 0;
                let statusPointer = 0;
                try {
                    canonicalRosterPointer =
                        input.memoryBoundary.copy(canonicalRosterBytes);
                    canonicalCarrierByteLengthPointer =
                        input.memoryBoundary.allocateZeroedWords(1);
                    signatureMessagePointer = input.memoryBoundary.allocate(
                        foundationHashByteLength,
                    );
                    statusPointer = input.memoryBoundary.allocateZeroedWords(1);
                    const handle =
                        input.kernel.preparePrivateShareAcceptanceCarrier(
                            input.generatedCommonProofHandle,
                            input.boardBindingSourceHandle,
                            canonicalRosterPointer,
                            canonicalRosterBytes.byteLength,
                            canonicalCarrierByteLengthPointer,
                            signatureMessagePointer,
                            foundationHashByteLength,
                            statusPointer,
                        );
                    if (handle !== 0) {
                        preparedCarrierHandle = requireLiveHandle(
                            handle,
                            'The prepared private-share acceptance carrier handle',
                        );
                    }
                    const [canonicalCarrierByteLength] =
                        input.memoryBoundary.readWords(
                            canonicalCarrierByteLengthPointer,
                            1,
                        );
                    const [status] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(status);
                    input.memoryBoundary.validateAllocationByteLength(
                        canonicalCarrierByteLength,
                    );
                    return Object.freeze({
                        canonicalCarrierByteLength,
                        handle: requireLiveHandle(
                            preparedCarrierHandle,
                            'The prepared private-share acceptance carrier handle',
                        ),
                        signatureMessage: new Uint8Array(
                            input.context.memory.buffer,
                            signatureMessagePointer,
                            foundationHashByteLength,
                        ).slice(),
                    });
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        signatureMessagePointer,
                        foundationHashByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        canonicalCarrierByteLengthPointer,
                        wasm32WordByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        canonicalRosterPointer,
                        canonicalRosterBytes.byteLength,
                    );
                }
            },
        );
        preparedCarrierHandle = preparation.handle;
        signatureMessage = preparation.signatureMessage;
        signature = requireFixedBytes(
            signPrivateShareAcceptanceMessage.call(
                input.signatureOperation,
                signatureMessage,
            ),
            mlDsa65SignatureByteLength,
        );
        const exactSignature = signature;
        return input.context.runExclusive(
            'private-share acceptance carrier completion',
            () => {
                let signaturePointer = 0;
                let outputPointer = 0;
                try {
                    signaturePointer =
                        input.memoryBoundary.copy(exactSignature);
                    outputPointer = input.memoryBoundary.allocate(
                        preparation.canonicalCarrierByteLength,
                    );
                    const status =
                        input.kernel.finishPrivateShareAcceptanceCarrier(
                            input.boardBindingSourceHandle,
                            preparedCarrierHandle,
                            signaturePointer,
                            exactSignature.byteLength,
                            outputPointer,
                            preparation.canonicalCarrierByteLength,
                        );
                    preparedCarrierHandle = 0;
                    input.statusBoundary.throwIfError(status);
                    return new Uint8Array(
                        input.context.memory.buffer,
                        outputPointer,
                        preparation.canonicalCarrierByteLength,
                    ).slice();
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        preparation.canonicalCarrierByteLength,
                    );
                    input.memoryBoundary.zeroAndDeallocate(
                        signaturePointer,
                        exactSignature.byteLength,
                    );
                }
            },
        );
    } catch (operationFailure) {
        if (preparedCarrierHandle !== 0) {
            try {
                const cancellationStatus = input.context.runExclusive(
                    'private-share acceptance carrier cancellation',
                    () =>
                        input.kernel.cancelPrivateShareAcceptanceCarrier(
                            input.boardBindingSourceHandle,
                            preparedCarrierHandle,
                        ),
                );
                input.statusBoundary.throwIfError(cancellationStatus);
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'Private-share acceptance carrier production and cancellation both failed.',
                    Object.freeze({ cleanupFailure, operationFailure }),
                );
            }
        }
        throw operationFailure;
    } finally {
        canonicalRosterBytes.fill(0);
        signatureMessage?.fill(0);
        signature?.fill(0);
    }
};

export const generateAggregateThresholdShareInClosedWorker = async (input: {
    canonicalRosterBytes: Uint8Array;
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    generationMode: AggregateThresholdShareGenerationMode;
    kernel: TranscriptCoreKernel;
    openProofGenerationExecution: CommonProofGenerationExecutionOpener;
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    recipientAuthority: AggregateThresholdShareRecipientAuthority;
    resolveVerifiedPrivateShareAcceptance(input: {
        canonicalPrivateShareAcceptanceCarrier: Uint8Array<ArrayBuffer>;
        proofDescriptorBytes: Uint8Array<ArrayBuffer>;
    }): Promise<VerifiedTranscriptObject>;
    signatureOperation: PrivateShareAcceptanceSignatureOperation;
    setupIntentObject: VerifiedTranscriptObject;
    workerKernel: BrowserActionStorageWorkerKernel;
}): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Aggregate-threshold-share proof generation may only run inside the dedicated WASM worker.',
        );
    }
    if (
        input.generationMode !== 'fresh' &&
        input.generationMode !== 'resumed'
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireAggregateThresholdShareProofKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'aggregate-threshold-share generation boundary',
    });
    const checkpointLineageIdentifier = requireFixedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const recipientAuthority =
        requireAggregateThresholdShareRecipientAuthorityKernelOwner(
            input.recipientAuthority,
            input.kernel,
        );
    const setupIntent = resolveSingleBoardObjectAuthorization({
        context,
        kernel: input.kernel,
        object: input.setupIntentObject,
    });

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
        let preparedGeneration:
            | PreparedAggregateThresholdShareGeneration
            | undefined;
        await withClosedWorkerProductionOperationAuthority(
            input.workerKernel,
            input.productionOperationIdentifiers,
            (productionOperationAuthority) =>
                productionOperationAuthority.withExactKernelAuthorization(
                    (authorization) => {
                        if (authorization.kernel !== input.kernel) {
                            throw new CanonicalStreamInternalError(
                                'The production operation belongs to another WASM worker.',
                            );
                        }
                        requireSameWorkerAuthorization({
                            capabilityMemory:
                                authorization.stateReservationCapabilityMemory,
                            capabilityPointer:
                                authorization.stateReservationCapabilityPointer,
                            context,
                            label: 'The state-verifier reservation authority',
                        });
                        if (
                            authorization.actionRandomnessContext.memory !==
                            context.memory
                        ) {
                            throw new CanonicalStreamInternalError(
                                'The action-randomness authority belongs to another WASM worker.',
                            );
                        }
                        preparedGeneration = context.runExclusive(
                            'aggregate-threshold-share generation preparation',
                            () => {
                                const checkpointPointer = memoryBoundary.copy(
                                    checkpointLineageIdentifier,
                                );
                                const metadataPointer =
                                    memoryBoundary.allocateZeroedWords(2);
                                try {
                                    const prepare =
                                        input.generationMode === 'fresh'
                                            ? kernel.prepareGeneration
                                            : kernel.prepareResumedGeneration;
                                    const adapterHandle = prepare(
                                        selectedSuiteHandle,
                                        recipientAuthority.handle,
                                        authorization.actionRandomnessHandle,
                                        authorization.stateVerifierSessionHandle,
                                        authorization.stateReservationCapabilityPointer,
                                        verifierCapabilityByteLength,
                                        authorization.stateReservationHandle,
                                        setupIntent.authorization.sessionHandle,
                                        setupIntent.authorization
                                            .capabilityPointer,
                                        verifierCapabilityByteLength,
                                        setupIntent.objectHandle,
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
                                            'The aggregate-threshold-share generation family-adapter handle',
                                        ),
                                        boardBindingSourceHandle:
                                            requireLiveHandle(
                                                sourceHandle,
                                                'The aggregate-threshold-share generation board-binding source handle',
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
        const prepared = preparedGeneration;
        if (prepared === undefined) {
            throw new CanonicalStreamInternalError(
                'The production operation completed without a proof-family adapter.',
            );
        }
        boardBindingSourceHandle = prepared.boardBindingSourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName:
                'aggregate-threshold-share generation selected-suite release',
            statusBoundary,
        });
        selectedSuiteHandle = 0;

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
                kernel: input.kernel,
                outputChunkByteLengths: execution.outputChunkByteLengths,
                outputStore: execution.outputStore,
                proofFamilyLabel: 'aggregate-threshold-share',
                streamDomain:
                    canonicalStreamDomains.recipientAggregateThresholdShareProof,
            },
        );
        let canonicalPrivateShareAcceptanceCarrier:
            | Uint8Array<ArrayBuffer>
            | undefined;
        let privateShareAcceptanceObject: VerifiedTranscriptObject;
        try {
            canonicalPrivateShareAcceptanceCarrier =
                applyClosedWorkerGeneratedCommonProofCapability(
                    generatedCapability,
                    context,
                    (generatedCommonProofHandle) =>
                        Object.freeze({
                            consumed: false,
                            result: produceCanonicalPrivateShareAcceptanceCarrier(
                                {
                                    boardBindingSourceHandle,
                                    canonicalRosterBytes:
                                        input.canonicalRosterBytes,
                                    context,
                                    generatedCommonProofHandle,
                                    kernel,
                                    memoryBoundary,
                                    signatureOperation:
                                        input.signatureOperation,
                                    statusBoundary,
                                },
                            ),
                        }),
                );
            privateShareAcceptanceObject =
                await input.resolveVerifiedPrivateShareAcceptance({
                    canonicalPrivateShareAcceptanceCarrier,
                    proofDescriptorBytes,
                });
        } finally {
            canonicalPrivateShareAcceptanceCarrier?.fill(0);
        }
        const acceptance = resolveSingleBoardObjectAuthorization({
            context,
            kernel: input.kernel,
            object: privateShareAcceptanceObject,
        });
        const capabilityForBinding = generatedCapability;
        applyClosedWorkerGeneratedCommonProofCapability(
            capabilityForBinding,
            context,
            (generatedCommonProofHandle) => {
                const status = context.runExclusive(
                    'aggregate-threshold-share generated-proof board binding',
                    () =>
                        kernel.bindGeneratedProofToBoard(
                            generatedCommonProofHandle,
                            boardBindingSourceHandle,
                            acceptance.authorization.sessionHandle,
                            acceptance.authorization.capabilityPointer,
                            verifierCapabilityByteLength,
                            acceptance.objectHandle,
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
                operationName:
                    'aggregate-threshold-share generation selected-suite failure release',
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
            discardHandle({
                context,
                discard: kernel.discardBoardBindingSource,
                handle: boardBindingSourceHandle,
                operationName:
                    'aggregate-threshold-share generation board-binding source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Aggregate-threshold-share generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
};

export const verifyAggregateThresholdShareInClosedWorker = async (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    inputStore: AuthenticatedCommonProofInputStore;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
    privateShareAcceptanceObject: VerifiedTranscriptObject;
    recipientAuthority: AggregateThresholdShareRecipientAuthority;
}): Promise<boolean> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Aggregate-threshold-share proof verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireAggregateThresholdShareProofKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'aggregate-threshold-share verification boundary',
    });
    const recipientAuthority =
        requireAggregateThresholdShareRecipientAuthorityKernelOwner(
            input.recipientAuthority,
            input.kernel,
        );
    const acceptance = resolveSingleBoardObjectAuthorization({
        context,
        kernel: input.kernel,
        object: input.privateShareAcceptanceObject,
    });

    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let terminalSourceHandle = 0;
    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context,
        kernel,
        memoryBoundary,
        statusBoundary,
    });
    let operationFailed = false;
    let operationFailure: unknown;
    let qualificationComplete: boolean | undefined;
    try {
        const prepared = context.runExclusive(
            'aggregate-threshold-share verification preparation',
            () => {
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const adapterHandle = kernel.prepareVerification(
                        selectedSuiteHandle,
                        recipientAuthority.handle,
                        acceptance.authorization.sessionHandle,
                        acceptance.authorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        acceptance.objectHandle,
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
                            'The aggregate-threshold-share verification family-adapter handle',
                        ),
                        terminalSourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The aggregate-threshold-share verification terminal-source handle',
                        ),
                    });
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    );
                }
            },
        );
        terminalSourceHandle = prepared.terminalSourceHandle;
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName:
                'aggregate-threshold-share verification selected-suite release',
            statusBoundary,
        });
        selectedSuiteHandle = 0;

        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const verifiedCommonProof =
            await runClosedWorkerCommonProofVerificationFamilyAdapter(
                adapterForRun,
                input.inputStore,
                input.options,
            );
        const verificationFinish = (() => {
            try {
                return applyClosedWorkerVerifiedCommonProofCapability(
                    verifiedCommonProof,
                    context,
                    (verifiedCommonProofHandle) =>
                        context.runExclusive(
                            'aggregate-threshold-share verification finish',
                            () => {
                                const statusPointer =
                                    memoryBoundary.allocateZeroedWords(1);
                                try {
                                    const completed = kernel.finishVerification(
                                        verifiedCommonProofHandle,
                                        terminalSourceHandle,
                                        statusPointer,
                                    );
                                    const [status] = memoryBoundary.readWords(
                                        statusPointer,
                                        1,
                                    );
                                    return Object.freeze({
                                        consumed: status === 0,
                                        result: Object.freeze({
                                            completed,
                                            status,
                                        }),
                                    });
                                } finally {
                                    memoryBoundary.zeroAndDeallocate(
                                        statusPointer,
                                        wasm32WordByteLength,
                                    );
                                }
                            },
                        ),
                );
            } catch (handoffFailure) {
                try {
                    verifiedCommonProof.release();
                } catch (cleanupFailure) {
                    throw new CanonicalStreamInternalError(
                        'The failed aggregate-threshold-share proof handoff could not release its generic verifier authority.',
                        Object.freeze({ cleanupFailure, handoffFailure }),
                    );
                }
                throw handoffFailure;
            }
        })();
        if (verificationFinish.status !== 0) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The refused aggregate-threshold-share proof handoff could not release its generic verifier authority.',
                    Object.freeze({
                        cleanupFailure,
                        status: verificationFinish.status,
                    }),
                );
            }
            statusBoundary.throwIfError(verificationFinish.status);
        }
        if (
            verificationFinish.completed !== 0 &&
            verificationFinish.completed !== 1
        ) {
            throw new CanonicalStreamInternalError(
                'The aggregate-threshold-share verifier returned a malformed completion flag.',
            );
        }
        terminalSourceHandle = 0;
        qualificationComplete = verificationFinish.completed === 1;
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                operationName:
                    'aggregate-threshold-share verification selected-suite failure release',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (familyAdapter !== undefined) {
        try {
            releaseClosedWorkerCommonProofVerificationFamilyAdapter(
                familyAdapter,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (terminalSourceHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardVerificationTerminalSource,
                handle: terminalSourceHandle,
                operationName:
                    'aggregate-threshold-share verification terminal-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Aggregate-threshold-share verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (qualificationComplete === undefined) {
        throw new CanonicalStreamInternalError(
            'Aggregate-threshold-share verification completed without a completion result.',
        );
    }
    return qualificationComplete;
};
