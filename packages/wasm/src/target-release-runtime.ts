import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import {
    requireVerifiedAcceptedSetupAuthorityKernelOwner,
    type VerifiedAcceptedSetupAuthority,
} from './accepted-setup-verification-runtime.js';
import {
    resolveActionRandomnessKernelAuthorization,
    type ActionRandomnessSession,
} from './action-randomness-runtime.js';
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
    applyClosedWorkerGeneratedCommonProofCapability,
    applyClosedWorkerVerifiedCommonProofCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    type AuthenticatedCommonProofInputStore,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofVerificationFamilyAdapter,
    type ClosedWorkerGeneratedCommonProofCapability,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationWorkerOptions,
    type CommonProofVerificationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import {
    resolveVerifiedFinalityKernelAuthorization,
    type VerifiedFinality,
} from './finality-verifier-runtime.js';
import {
    deriveGeneratedCommonProofDescriptor,
    trackCanonicalCommonProofOutputChunks,
} from './generated-common-proof-output-runtime.js';
import {
    requireSelectedSuiteRecordSourceKernelOwner,
    type SelectedSuiteRecordSource,
} from './selected-suite-record-source.js';
import {
    mlDsa65SignatureByteLength,
    type StateObjectSignatureOperation,
} from './state-verifier-runtime/contracts.js';
import {
    resolveVerifiedStateOutputKernelAuthorization,
    resolveVerifiedStateReservationKernelAuthorization,
    type VerifiedStateOutput,
    type VerifiedStateReservation,
} from './state-verifier-runtime.js';
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
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const foundationHashByteLength = 64;
const targetReleasePartialRoleCount = 2;
const targetReleaseReconstructionThreshold =
    foundationProfile.reconstructionThreshold;

export type TargetReleaseGenerationMode = 'fresh' | 'resumed';
export type TargetReleasePartialRole = 'targetIdentifier' | 'targetOrder';

export type TargetReleasePartialOutputStoreResolver = Readonly<{
    resolveOutputStore(input: {
        canonicalDescriptorBytes: Uint8Array<ArrayBuffer>;
        role: TargetReleasePartialRole;
        totalByteLength: number;
    }): Promise<CommonProofCanonicalOutputStore>;
}>;

/** Canonical signed carrier and descriptors for one bound paired target release. */
export type GeneratedTargetReleaseTransport = Readonly<{
    canonicalTargetShareCarrier: Uint8Array<ArrayBuffer>;
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
    targetIdentifierPartialDescriptorBytes: Uint8Array<ArrayBuffer>;
    targetOrderPartialDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

const verifiedTargetReleaseShareBrand: unique symbol = Symbol(
    'sealed-lattice/verified-target-release-share',
);

/** Positive paired-share result retained by the exact Rust/WASM worker. */
export type VerifiedTargetReleaseShare = Readonly<{
    readonly [verifiedTargetReleaseShareBrand]: true;
    release(): void;
}>;

/** Canonical one-based option identifiers in increasing result rank. */
export type ReconstructedTargetRelease = Readonly<{
    orderedOptionIdentifiers: Uint32Array<ArrayBuffer>;
}>;

type VerifiedTargetReleaseShareRecord = Readonly<{
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const verifiedTargetReleaseShareRecords = new WeakMap<
    VerifiedTargetReleaseShare,
    VerifiedTargetReleaseShareRecord
>();

type TargetReleaseKernel = Readonly<{
    bindGeneratedProof: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_bind_generated_proof']
    >;
    cancelOutputCarrier: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_cancel_output_carrier']
    >;
    copyPartialDescriptor: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_copy_partial_descriptor']
    >;
    discardGenerationSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_discard_generation_source']
    >;
    discardVerificationTerminalSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_discard_verification_terminal_source']
    >;
    discardVerifiedShare: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_discard_verified_share']
    >;
    reconstructVerifiedShares: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_reconstruct_verified_shares']
    >;
    reconstructedSelectedOptionCount: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_reconstructed_selected_option_count']
    >;
    copyReconstructedOptionIdentifiers: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_copy_reconstructed_option_identifiers']
    >;
    finishReconstruction: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_finish_reconstruction']
    >;
    finishOutputCarrier: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_finish_output_carrier']
    >;
    discardReconstruction: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_discard_reconstruction']
    >;
    finishVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_finish_verification']
    >;
    partialDescriptorByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_partial_descriptor_byte_length']
    >;
    partialTotalByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_partial_total_byte_length']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_prepare_generation']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_prepare_resumed_generation']
    >;
    prepareOutputCarrier: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_prepare_output_carrier']
    >;
    prepareVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_prepare_verification']
    >;
    readPartialChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_target_release_read_partial_chunk']
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
            'The target-release kernel session failed internally.',
        unknownStatusMessage:
            'The target-release kernel returned an unknown status code.',
    });

const requireTargetReleaseKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): TargetReleaseKernel => {
    const wasmExports = context.wasmExports;
    const requiredExports = {
        bindGeneratedProof:
            wasmExports.sealed_lattice_target_release_bind_generated_proof,
        cancelOutputCarrier:
            wasmExports.sealed_lattice_target_release_cancel_output_carrier,
        copyPartialDescriptor:
            wasmExports.sealed_lattice_target_release_copy_partial_descriptor,
        discardGenerationSource:
            wasmExports.sealed_lattice_target_release_discard_generation_source,
        discardVerificationTerminalSource:
            wasmExports.sealed_lattice_target_release_discard_verification_terminal_source,
        discardVerifiedShare:
            wasmExports.sealed_lattice_target_release_discard_verified_share,
        reconstructVerifiedShares:
            wasmExports.sealed_lattice_target_release_reconstruct_verified_shares,
        reconstructedSelectedOptionCount:
            wasmExports.sealed_lattice_target_release_reconstructed_selected_option_count,
        copyReconstructedOptionIdentifiers:
            wasmExports.sealed_lattice_target_release_copy_reconstructed_option_identifiers,
        finishReconstruction:
            wasmExports.sealed_lattice_target_release_finish_reconstruction,
        finishOutputCarrier:
            wasmExports.sealed_lattice_target_release_finish_output_carrier,
        discardReconstruction:
            wasmExports.sealed_lattice_target_release_discard_reconstruction,
        finishVerification:
            wasmExports.sealed_lattice_target_release_finish_verification,
        partialDescriptorByteLength:
            wasmExports.sealed_lattice_target_release_partial_descriptor_byte_length,
        partialTotalByteLength:
            wasmExports.sealed_lattice_target_release_partial_total_byte_length,
        prepareGeneration:
            wasmExports.sealed_lattice_target_release_prepare_generation,
        prepareResumedGeneration:
            wasmExports.sealed_lattice_target_release_prepare_resumed_generation,
        prepareOutputCarrier:
            wasmExports.sealed_lattice_target_release_prepare_output_carrier,
        prepareVerification:
            wasmExports.sealed_lattice_target_release_prepare_verification,
        readPartialChunk:
            wasmExports.sealed_lattice_target_release_read_partial_chunk,
    };
    if (
        Object.values(requiredExports).some(
            (exportedFunction) => typeof exportedFunction !== 'function',
        )
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the target-release boundary.',
        );
    }
    return Object.freeze(requiredExports) as TargetReleaseKernel;
};

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

const requireOwnedBytes = (
    value: Uint8Array,
    expectedByteLength?: number,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength === 0 ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        (expectedByteLength !== undefined &&
            value.byteLength !== expectedByteLength)
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireSameWorkerCapability = (input: {
    capabilityMemory: WebAssembly.Memory;
    capabilityPointer: number;
    context: TranscriptCoreKernelCommandRuntime;
    label: string;
}): void => {
    if (
        input.capabilityMemory !== input.context.memory ||
        !Number.isSafeInteger(input.capabilityPointer) ||
        input.capabilityPointer <= 0 ||
        input.capabilityPointer + verifierCapabilityByteLength >
            input.context.memory.buffer.byteLength
    ) {
        throw new CanonicalStreamInternalError(
            `${input.label} does not belong to the target-release WASM worker.`,
        );
    }
};

const throwIfAborted = (signal: AbortSignal | undefined): void => {
    if (signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
};

const readSingleObjectHandle = (
    handleBytes: Uint8Array<ArrayBuffer>,
): number => {
    if (handleBytes.byteLength !== wasm32WordByteLength) {
        throw new CanonicalStreamInternalError(
            'The target-release board authorization did not contain one exact object handle.',
        );
    }
    return requireLiveHandle(
        new DataView(
            handleBytes.buffer,
            handleBytes.byteOffset,
            handleBytes.byteLength,
        ).getUint32(0, true),
        'The target-release board object handle',
    );
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

const partialRoles = Object.freeze([
    Object.freeze({ ordinal: 0, role: 'targetIdentifier' as const }),
    Object.freeze({ ordinal: 1, role: 'targetOrder' as const }),
]);

const copyPartialStreamToStore = async (input: {
    context: TranscriptCoreKernelCommandRuntime;
    generationSourceHandle: number;
    kernel: TargetReleaseKernel;
    memoryBoundary: WasmMemoryBoundary;
    options: CommonProofGenerationWorkerOptions | undefined;
    outputStores: TargetReleasePartialOutputStoreResolver;
    role: TargetReleasePartialRole;
    roleOrdinal: number;
    statusBoundary: WasmStatusBoundary;
}): Promise<Uint8Array<ArrayBuffer>> => {
    let canonicalDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let statusPointer = 0;
    try {
        const descriptorByteLength = input.context.runExclusive(
            'target-release partial descriptor length',
            () => {
                statusPointer = input.memoryBoundary.allocateZeroedWords(1);
                const byteLength = input.kernel.partialDescriptorByteLength(
                    input.generationSourceHandle,
                    input.roleOrdinal,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return byteLength;
            },
        );
        input.memoryBoundary.validateAllocationByteLength(descriptorByteLength);
        canonicalDescriptorBytes = input.context.runExclusive(
            'target-release partial descriptor copy',
            () => {
                const outputPointer =
                    input.memoryBoundary.allocate(descriptorByteLength);
                try {
                    const status = input.kernel.copyPartialDescriptor(
                        input.generationSourceHandle,
                        input.roleOrdinal,
                        outputPointer,
                        descriptorByteLength,
                        statusPointer,
                    );
                    input.statusBoundary.throwIfError(status);
                    const [writtenStatus] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(writtenStatus);
                    return Uint8Array.from(
                        new Uint8Array(
                            input.context.memory.buffer,
                            outputPointer,
                            descriptorByteLength,
                        ),
                    );
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        outputPointer,
                        descriptorByteLength,
                    );
                }
            },
        );
        const totalByteLengthValue = input.context.runExclusive(
            'target-release partial stream length',
            () => {
                const byteLength = input.kernel.partialTotalByteLength(
                    input.generationSourceHandle,
                    input.roleOrdinal,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return byteLength;
            },
        );
        if (
            typeof totalByteLengthValue !== 'bigint' ||
            totalByteLengthValue <= 0n ||
            totalByteLengthValue >
                BigInt(foundationProfile.maximumCanonicalStreamByteLength) ||
            totalByteLengthValue > BigInt(Number.MAX_SAFE_INTEGER)
        ) {
            throw new CanonicalStreamResourceError(
                'The target-release partial stream exceeds the absolute canonical-stream bound.',
            );
        }
        const totalByteLength = Number(totalByteLengthValue);
        const outputStore = await input.outputStores.resolveOutputStore({
            canonicalDescriptorBytes: canonicalDescriptorBytes.slice(),
            role: input.role,
            totalByteLength,
        });
        const chunkCount = Math.ceil(
            totalByteLength / foundationProfile.streamChunkByteLength,
        );
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            throwIfAborted(input.options?.signal);
            const chunkByteOffset =
                chunkIndex * foundationProfile.streamChunkByteLength;
            const chunkByteLength = Math.min(
                foundationProfile.streamChunkByteLength,
                totalByteLength - chunkByteOffset,
            );
            let chunkBytes: Uint8Array<ArrayBuffer> | undefined;
            input.context.runExclusive(
                'target-release partial stream chunk readback',
                () => {
                    const outputPointer =
                        input.memoryBoundary.allocate(chunkByteLength);
                    try {
                        const status = input.kernel.readPartialChunk(
                            input.generationSourceHandle,
                            input.roleOrdinal,
                            chunkIndex,
                            outputPointer,
                            chunkByteLength,
                            statusPointer,
                        );
                        input.statusBoundary.throwIfError(status);
                        const [writtenStatus] = input.memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        input.statusBoundary.throwIfError(writtenStatus);
                        chunkBytes = Uint8Array.from(
                            new Uint8Array(
                                input.context.memory.buffer,
                                outputPointer,
                                chunkByteLength,
                            ),
                        );
                    } finally {
                        input.memoryBoundary.zeroAndDeallocate(
                            outputPointer,
                            chunkByteLength,
                        );
                    }
                },
            );
            if (chunkBytes === undefined) {
                throw new CanonicalStreamInternalError(
                    'The target-release partial readback produced no chunk.',
                );
            }
            try {
                await outputStore.commitChunk(chunkIndex, chunkBytes);
            } finally {
                chunkBytes.fill(0);
            }
            await input.options?.yieldControl?.();
        }
        return canonicalDescriptorBytes;
    } catch (error) {
        canonicalDescriptorBytes?.fill(0);
        throw error;
    } finally {
        if (statusPointer !== 0) {
            input.memoryBoundary.zeroAndDeallocate(
                statusPointer,
                wasm32WordByteLength,
            );
        }
    }
};

const produceCanonicalTargetShareCarrier = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    generationSourceHandle: number;
    kernel: TargetReleaseKernel;
    memoryBoundary: WasmMemoryBoundary;
    proofDescriptorBytes: Uint8Array;
    signatureOperation: StateObjectSignatureOperation;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> => {
    if (
        typeof input.signatureOperation !== 'object' ||
        input.signatureOperation === null ||
        typeof input.signatureOperation.signStateObjectMessage !== 'function'
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const proofDescriptorBytes = requireOwnedBytes(input.proofDescriptorBytes);
    let preparedCarrierHandle = 0;
    let signatureMessage: Uint8Array<ArrayBuffer> | undefined;
    let signature: Uint8Array<ArrayBuffer> | undefined;
    try {
        const preparation = input.context.runExclusive(
            'target-share carrier preparation',
            () => {
                let proofDescriptorPointer = 0;
                let canonicalCarrierByteLengthPointer = 0;
                let signatureMessagePointer = 0;
                let statusPointer = 0;
                try {
                    proofDescriptorPointer =
                        input.memoryBoundary.copy(proofDescriptorBytes);
                    canonicalCarrierByteLengthPointer =
                        input.memoryBoundary.allocateZeroedWords(1);
                    signatureMessagePointer = input.memoryBoundary.allocate(
                        foundationHashByteLength,
                    );
                    statusPointer = input.memoryBoundary.allocateZeroedWords(1);
                    const handle = input.kernel.prepareOutputCarrier(
                        input.generationSourceHandle,
                        proofDescriptorPointer,
                        proofDescriptorBytes.byteLength,
                        canonicalCarrierByteLengthPointer,
                        signatureMessagePointer,
                        foundationHashByteLength,
                        statusPointer,
                    );
                    if (handle !== 0) {
                        preparedCarrierHandle = requireLiveHandle(
                            handle,
                            'The prepared target-share carrier handle',
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
                            'The prepared target-share carrier handle',
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
                        proofDescriptorPointer,
                        proofDescriptorBytes.byteLength,
                    );
                }
            },
        );
        preparedCarrierHandle = preparation.handle;
        signatureMessage = preparation.signatureMessage;
        signature = requireOwnedBytes(
            input.signatureOperation.signStateObjectMessage(signatureMessage),
            mlDsa65SignatureByteLength,
        );
        const exactSignature = signature;
        const canonicalCarrier = input.context.runExclusive(
            'target-share carrier completion',
            () => {
                let signaturePointer = 0;
                let outputPointer = 0;
                try {
                    signaturePointer =
                        input.memoryBoundary.copy(exactSignature);
                    outputPointer = input.memoryBoundary.allocate(
                        preparation.canonicalCarrierByteLength,
                    );
                    const status = input.kernel.finishOutputCarrier(
                        preparedCarrierHandle,
                        signaturePointer,
                        exactSignature.byteLength,
                        outputPointer,
                        preparation.canonicalCarrierByteLength,
                    );
                    input.statusBoundary.throwIfError(status);
                    preparedCarrierHandle = 0;
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
        if (
            canonicalCarrier.byteLength !==
            preparation.canonicalCarrierByteLength
        ) {
            canonicalCarrier.fill(0);
            throw new CanonicalStreamInternalError(
                'The target-share carrier has the wrong canonical length.',
            );
        }
        return canonicalCarrier;
    } catch (error) {
        if (preparedCarrierHandle !== 0) {
            try {
                discardHandle({
                    context: input.context,
                    discard: input.kernel.cancelOutputCarrier,
                    handle: preparedCarrierHandle,
                    operationName: 'target-share carrier cancellation',
                    statusBoundary: input.statusBoundary,
                });
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'Target-share carrier production and cancellation both failed.',
                    Object.freeze({ cleanupFailure, error }),
                );
            }
        }
        throw error;
    } finally {
        proofDescriptorBytes.fill(0);
        signatureMessage?.fill(0);
        signature?.fill(0);
    }
};

const releaseVerifiedShare = (share: VerifiedTargetReleaseShare): void => {
    const record = verifiedTargetReleaseShareRecords.get(share);
    if (record === undefined) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    verifiedTargetReleaseShareRecords.delete(share);
    const kernel = requireTargetReleaseKernel(record.context);
    discardHandle({
        context: record.context,
        discard: kernel.discardVerifiedShare,
        handle: record.handle,
        operationName: 'target-release verified-share discard',
        statusBoundary: createStatusBoundary(),
    });
};

const createVerifiedShare = (
    record: VerifiedTargetReleaseShareRecord,
): VerifiedTargetReleaseShare => {
    const share: VerifiedTargetReleaseShare = Object.freeze({
        [verifiedTargetReleaseShareBrand]: true as const,
        release: () => releaseVerifiedShare(share),
    });
    verifiedTargetReleaseShareRecords.set(share, record);
    return share;
};

/**
 * Generates the exact paired factor-four target release and retires its proof
 * authority only after a verifier-minted state output and board carrier bind
 * both partial streams and the common proof.
 */
export const generateTargetReleaseInClosedWorker = async (input: {
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    actionRandomnessSession: ActionRandomnessSession;
    checkpointLineageIdentifier: Uint8Array;
    externalMemory: CommonProofExternalMemoryTransactionExecutor;
    finalizedTargetIdentifierBytes: Uint8Array;
    finalizedTargetOrderBytes: Uint8Array;
    generationMode: TargetReleaseGenerationMode;
    kernel: TranscriptCoreKernel;
    options?: CommonProofGenerationWorkerOptions;
    outputStore: CommonProofCanonicalOutputStore;
    partialOutputStores: TargetReleasePartialOutputStoreResolver;
    reservationIntentObject: VerifiedTranscriptObject;
    resolveVerifiedTargetShare(
        input: GeneratedTargetReleaseTransport,
    ): Promise<{
        targetShareObject: VerifiedTranscriptObject;
        verifiedOutput: VerifiedStateOutput;
    }>;
    selectedSuiteRecordSource: SelectedSuiteRecordSource;
    signatureOperation: StateObjectSignatureOperation;
    verifiedFinality: VerifiedFinality;
    verifiedReservation: VerifiedStateReservation;
}): Promise<GeneratedTargetReleaseTransport> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Target-release generation may only run inside the dedicated WASM worker.',
        );
    }
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        (input.generationMode === 'resumed') !==
            (input.options?.resume !== undefined)
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireTargetReleaseKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'target-release generation boundary',
    });
    const selectedSuiteOwner = requireSelectedSuiteRecordSourceKernelOwner({
        kernel: input.kernel,
        source: input.selectedSuiteRecordSource,
    });
    const acceptedSetupOwner = requireVerifiedAcceptedSetupAuthorityKernelOwner(
        input.acceptedSetupAuthority,
        input.kernel,
    );
    const actionRandomnessAuthorization =
        resolveActionRandomnessKernelAuthorization(
            input.actionRandomnessSession,
            input.kernel,
        );
    const stateAuthorization =
        resolveVerifiedStateReservationKernelAuthorization(
            input.verifiedReservation,
            input.kernel,
        );
    const finalityAuthorization = resolveVerifiedFinalityKernelAuthorization(
        input.verifiedFinality,
        input.kernel,
    );
    const reservationIntentAuthorization =
        resolveOrderedVerifiedBoardObjectAuthorization({
            context,
            expectedObjectCount: 1,
            kernel: input.kernel,
            objects: [input.reservationIntentObject],
        });
    if (
        selectedSuiteOwner.kernel !== input.kernel ||
        acceptedSetupOwner.kernel !== input.kernel ||
        actionRandomnessAuthorization.context.memory !== context.memory
    ) {
        throw new CanonicalStreamInternalError(
            'The target-release generation authorities do not belong to one WASM worker.',
        );
    }
    requireSameWorkerCapability({
        capabilityMemory: stateAuthorization.capabilityMemory,
        capabilityPointer: stateAuthorization.capabilityPointer,
        context,
        label: 'The state reservation',
    });
    requireSameWorkerCapability({
        capabilityMemory: finalityAuthorization.capabilityMemory,
        capabilityPointer: finalityAuthorization.capabilityPointer,
        context,
        label: 'The verified finality',
    });
    const checkpointLineageIdentifier = requireOwnedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const finalizedTargetIdentifierBytes = requireOwnedBytes(
        input.finalizedTargetIdentifierBytes,
    );
    const finalizedTargetOrderBytes = requireOwnedBytes(
        input.finalizedTargetOrderBytes,
    );

    let generationSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let proofDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let targetIdentifierPartialDescriptorBytes:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let targetOrderPartialDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let canonicalTargetShareCarrier: Uint8Array<ArrayBuffer> | undefined;
    let result: GeneratedTargetReleaseTransport | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        const prepared = context.runExclusive(
            'target-release generation preparation',
            () => {
                let targetIdentifierPointer = 0;
                let targetOrderPointer = 0;
                let checkpointPointer = 0;
                let metadataPointer = 0;
                try {
                    targetIdentifierPointer = memoryBoundary.copy(
                        finalizedTargetIdentifierBytes,
                    );
                    targetOrderPointer = memoryBoundary.copy(
                        finalizedTargetOrderBytes,
                    );
                    checkpointPointer = memoryBoundary.copy(
                        checkpointLineageIdentifier,
                    );
                    metadataPointer = memoryBoundary.allocateZeroedWords(2);
                    const prepare =
                        input.generationMode === 'fresh'
                            ? kernel.prepareGeneration
                            : kernel.prepareResumedGeneration;
                    const adapterHandle = prepare(
                        selectedSuiteOwner.handle,
                        acceptedSetupOwner.handle,
                        actionRandomnessAuthorization.handle,
                        stateAuthorization.sessionHandle,
                        stateAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        stateAuthorization.reservationHandle,
                        finalityAuthorization.sessionHandle,
                        finalityAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        finalityAuthorization.finalityHandle,
                        reservationIntentAuthorization.sessionHandle,
                        reservationIntentAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        readSingleObjectHandle(
                            reservationIntentAuthorization.handleBytes,
                        ),
                        targetIdentifierPointer,
                        finalizedTargetIdentifierBytes.byteLength,
                        targetOrderPointer,
                        finalizedTargetOrderBytes.byteLength,
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
                            'The target-release generation adapter handle',
                        ),
                        sourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The target-release generation source handle',
                        ),
                    });
                } finally {
                    if (metadataPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            metadataPointer,
                            wasm32WordByteLength * 2,
                        );
                    }
                    if (checkpointPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            checkpointPointer,
                            checkpointLineageIdentifier.byteLength,
                        );
                    }
                    if (targetOrderPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetOrderPointer,
                            finalizedTargetOrderBytes.byteLength,
                        );
                    }
                    if (targetIdentifierPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetIdentifierPointer,
                            finalizedTargetIdentifierBytes.byteLength,
                        );
                    }
                }
            },
        );
        generationSourceHandle = prepared.sourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
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
        proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor({
            kernel: input.kernel,
            outputChunkByteLengths: trackedOutput.outputChunkByteLengths,
            outputStore: input.outputStore,
            proofFamilyLabel: 'target release',
            streamDomain: canonicalStreamDomains.maliciousTargetShareProof,
        });
        const partialDescriptors: Uint8Array<ArrayBuffer>[] = [];
        for (const partialRole of partialRoles) {
            partialDescriptors.push(
                await copyPartialStreamToStore({
                    context,
                    generationSourceHandle,
                    kernel,
                    memoryBoundary,
                    options: input.options,
                    outputStores: input.partialOutputStores,
                    role: partialRole.role,
                    roleOrdinal: partialRole.ordinal,
                    statusBoundary,
                }),
            );
        }
        const targetIdentifierDescriptor = partialDescriptors[0];
        const targetOrderDescriptor = partialDescriptors[1];
        if (
            partialDescriptors.length !== targetReleasePartialRoleCount ||
            targetIdentifierDescriptor === undefined ||
            targetOrderDescriptor === undefined
        ) {
            throw new CanonicalStreamInternalError(
                'The target-release generator did not produce both fixed partial streams.',
            );
        }
        targetIdentifierPartialDescriptorBytes = targetIdentifierDescriptor;
        targetOrderPartialDescriptorBytes = targetOrderDescriptor;
        throwIfAborted(input.options?.signal);
        canonicalTargetShareCarrier = produceCanonicalTargetShareCarrier({
            context,
            generationSourceHandle,
            kernel,
            memoryBoundary,
            proofDescriptorBytes,
            signatureOperation: input.signatureOperation,
            statusBoundary,
        });
        throwIfAborted(input.options?.signal);
        const transport: GeneratedTargetReleaseTransport = Object.freeze({
            canonicalTargetShareCarrier,
            proofDescriptorBytes,
            targetIdentifierPartialDescriptorBytes,
            targetOrderPartialDescriptorBytes,
        });
        const resolverTransport: GeneratedTargetReleaseTransport =
            Object.freeze({
                canonicalTargetShareCarrier:
                    transport.canonicalTargetShareCarrier.slice(),
                proofDescriptorBytes: transport.proofDescriptorBytes.slice(),
                targetIdentifierPartialDescriptorBytes:
                    transport.targetIdentifierPartialDescriptorBytes.slice(),
                targetOrderPartialDescriptorBytes:
                    transport.targetOrderPartialDescriptorBytes.slice(),
            });
        let verifiedTargetShare: {
            targetShareObject: VerifiedTranscriptObject;
            verifiedOutput: VerifiedStateOutput;
        };
        try {
            verifiedTargetShare =
                await input.resolveVerifiedTargetShare(resolverTransport);
        } finally {
            resolverTransport.canonicalTargetShareCarrier.fill(0);
            resolverTransport.proofDescriptorBytes.fill(0);
            resolverTransport.targetIdentifierPartialDescriptorBytes.fill(0);
            resolverTransport.targetOrderPartialDescriptorBytes.fill(0);
        }
        throwIfAborted(input.options?.signal);
        const outputAuthorization =
            resolveVerifiedStateOutputKernelAuthorization(
                verifiedTargetShare.verifiedOutput,
                input.kernel,
            );
        requireSameWorkerCapability({
            capabilityMemory: outputAuthorization.capabilityMemory,
            capabilityPointer: outputAuthorization.capabilityPointer,
            context,
            label: 'The verified target-share state output',
        });
        if (
            outputAuthorization.sessionHandle !==
                stateAuthorization.sessionHandle ||
            outputAuthorization.capabilityPointer !==
                stateAuthorization.capabilityPointer
        ) {
            throw new CanonicalStreamRefusalError('wrongContext');
        }
        const targetShareAuthorization =
            resolveOrderedVerifiedBoardObjectAuthorization({
                context,
                expectedObjectCount: 1,
                kernel: input.kernel,
                objects: [verifiedTargetShare.targetShareObject],
            });
        const capabilityForBinding = generatedCapability;
        const bindStatus = applyClosedWorkerGeneratedCommonProofCapability(
            capabilityForBinding,
            context,
            (generatedCommonProofHandle) => {
                const status = context.runExclusive(
                    'target-release generated-proof binding',
                    () =>
                        kernel.bindGeneratedProof(
                            generatedCommonProofHandle,
                            generationSourceHandle,
                            outputAuthorization.outputHandle,
                            readSingleObjectHandle(
                                targetShareAuthorization.handleBytes,
                            ),
                        ),
                );
                return Object.freeze({
                    consumed: status === 0,
                    result: status,
                });
            },
        );
        statusBoundary.throwIfError(bindStatus);
        generatedCapability = undefined;
        generationSourceHandle = 0;
        result = transport;
        canonicalTargetShareCarrier = undefined;
        proofDescriptorBytes = undefined;
        targetIdentifierPartialDescriptorBytes = undefined;
        targetOrderPartialDescriptorBytes = undefined;
    } catch (error) {
        operationFailure = error;
        operationFailed = true;
    } finally {
        checkpointLineageIdentifier.fill(0);
        finalizedTargetIdentifierBytes.fill(0);
        finalizedTargetOrderBytes.fill(0);
    }

    const cleanupFailures: unknown[] = [];
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
    if (generationSourceHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardGenerationSource,
                handle: generationSourceHandle,
                operationName: 'target-release generation source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (result === undefined) {
        canonicalTargetShareCarrier?.fill(0);
        proofDescriptorBytes?.fill(0);
        targetIdentifierPartialDescriptorBytes?.fill(0);
        targetOrderPartialDescriptorBytes?.fill(0);
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Target-release generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'Target-release generation completed without a bound paired transport.',
        );
    }
    return result;
};

/**
 * Positively verifies the common proof and its exact paired partial streams,
 * then returns only the Rust-owned share needed by bounded reconstruction.
 */
export const verifyTargetReleaseInClosedWorker = async (input: {
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    finalizedTargetIdentifierBytes: Uint8Array;
    finalizedTargetOrderBytes: Uint8Array;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
    proofInputStore: AuthenticatedCommonProofInputStore;
    selectedSuiteRecordSource: SelectedSuiteRecordSource;
    targetIdentifierPartialBytes: Uint8Array;
    targetOrderPartialBytes: Uint8Array;
    targetShareObject: VerifiedTranscriptObject;
    verifiedFinality: VerifiedFinality;
    verifiedOutput: VerifiedStateOutput;
    verifiedReservation: VerifiedStateReservation;
}): Promise<VerifiedTargetReleaseShare> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Target-release verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireTargetReleaseKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'target-release verification boundary',
    });
    const selectedSuiteOwner = requireSelectedSuiteRecordSourceKernelOwner({
        kernel: input.kernel,
        source: input.selectedSuiteRecordSource,
    });
    const acceptedSetupOwner = requireVerifiedAcceptedSetupAuthorityKernelOwner(
        input.acceptedSetupAuthority,
        input.kernel,
    );
    const stateReservationAuthorization =
        resolveVerifiedStateReservationKernelAuthorization(
            input.verifiedReservation,
            input.kernel,
        );
    const stateOutputAuthorization =
        resolveVerifiedStateOutputKernelAuthorization(
            input.verifiedOutput,
            input.kernel,
        );
    const finalityAuthorization = resolveVerifiedFinalityKernelAuthorization(
        input.verifiedFinality,
        input.kernel,
    );
    const targetShareAuthorization =
        resolveOrderedVerifiedBoardObjectAuthorization({
            context,
            expectedObjectCount: 1,
            kernel: input.kernel,
            objects: [input.targetShareObject],
        });
    if (
        selectedSuiteOwner.kernel !== input.kernel ||
        acceptedSetupOwner.kernel !== input.kernel
    ) {
        throw new CanonicalStreamInternalError(
            'The target-release verification authorities do not belong to one WASM worker.',
        );
    }
    requireSameWorkerCapability({
        capabilityMemory: stateReservationAuthorization.capabilityMemory,
        capabilityPointer: stateReservationAuthorization.capabilityPointer,
        context,
        label: 'The state reservation',
    });
    requireSameWorkerCapability({
        capabilityMemory: stateOutputAuthorization.capabilityMemory,
        capabilityPointer: stateOutputAuthorization.capabilityPointer,
        context,
        label: 'The verified state output',
    });
    requireSameWorkerCapability({
        capabilityMemory: finalityAuthorization.capabilityMemory,
        capabilityPointer: finalityAuthorization.capabilityPointer,
        context,
        label: 'The verified finality',
    });
    if (
        stateReservationAuthorization.sessionHandle !==
            stateOutputAuthorization.sessionHandle ||
        stateReservationAuthorization.capabilityPointer !==
            stateOutputAuthorization.capabilityPointer
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const finalizedTargetIdentifierBytes = requireOwnedBytes(
        input.finalizedTargetIdentifierBytes,
    );
    const finalizedTargetOrderBytes = requireOwnedBytes(
        input.finalizedTargetOrderBytes,
    );
    const targetIdentifierPartialBytes = requireOwnedBytes(
        input.targetIdentifierPartialBytes,
    );
    const targetOrderPartialBytes = requireOwnedBytes(
        input.targetOrderPartialBytes,
    );

    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let terminalSourceHandle = 0;
    let verifiedShare: VerifiedTargetReleaseShare | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        const prepared = context.runExclusive(
            'target-release verification preparation',
            () => {
                let targetIdentifierPointer = 0;
                let targetOrderPointer = 0;
                let targetIdentifierPartialPointer = 0;
                let targetOrderPartialPointer = 0;
                let metadataPointer = 0;
                try {
                    targetIdentifierPointer = memoryBoundary.copy(
                        finalizedTargetIdentifierBytes,
                    );
                    targetOrderPointer = memoryBoundary.copy(
                        finalizedTargetOrderBytes,
                    );
                    targetIdentifierPartialPointer = memoryBoundary.copy(
                        targetIdentifierPartialBytes,
                    );
                    targetOrderPartialPointer = memoryBoundary.copy(
                        targetOrderPartialBytes,
                    );
                    metadataPointer = memoryBoundary.allocateZeroedWords(2);
                    const adapterHandle = kernel.prepareVerification(
                        selectedSuiteOwner.handle,
                        acceptedSetupOwner.handle,
                        stateReservationAuthorization.sessionHandle,
                        stateReservationAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        stateReservationAuthorization.reservationHandle,
                        stateOutputAuthorization.outputHandle,
                        finalityAuthorization.sessionHandle,
                        finalityAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        finalityAuthorization.finalityHandle,
                        targetShareAuthorization.sessionHandle,
                        targetShareAuthorization.capabilityPointer,
                        verifierCapabilityByteLength,
                        readSingleObjectHandle(
                            targetShareAuthorization.handleBytes,
                        ),
                        targetIdentifierPointer,
                        finalizedTargetIdentifierBytes.byteLength,
                        targetOrderPointer,
                        finalizedTargetOrderBytes.byteLength,
                        targetIdentifierPartialPointer,
                        targetIdentifierPartialBytes.byteLength,
                        targetOrderPartialPointer,
                        targetOrderPartialBytes.byteLength,
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
                            'The target-release verification adapter handle',
                        ),
                        sourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The target-release verification terminal-source handle',
                        ),
                    });
                } finally {
                    if (metadataPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            metadataPointer,
                            wasm32WordByteLength * 2,
                        );
                    }
                    if (targetOrderPartialPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetOrderPartialPointer,
                            targetOrderPartialBytes.byteLength,
                        );
                    }
                    if (targetIdentifierPartialPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetIdentifierPartialPointer,
                            targetIdentifierPartialBytes.byteLength,
                        );
                    }
                    if (targetOrderPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetOrderPointer,
                            finalizedTargetOrderBytes.byteLength,
                        );
                    }
                    if (targetIdentifierPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetIdentifierPointer,
                            finalizedTargetIdentifierBytes.byteLength,
                        );
                    }
                }
            },
        );
        terminalSourceHandle = prepared.sourceHandle;
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        const adapterForRun = familyAdapter;
        familyAdapter = undefined;
        const verifiedCommonProof =
            await runClosedWorkerCommonProofVerificationFamilyAdapter(
                adapterForRun,
                input.proofInputStore,
                input.options,
            );
        const verificationFinish = (() => {
            try {
                return applyClosedWorkerVerifiedCommonProofCapability(
                    verifiedCommonProof,
                    context,
                    (verifiedCommonProofHandle) =>
                        context.runExclusive(
                            'target-release verification finish',
                            () => {
                                const statusPointer =
                                    memoryBoundary.allocateZeroedWords(1);
                                try {
                                    const handle = kernel.finishVerification(
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
                                            handle,
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
                        'The failed target-release proof handoff could not release its generic verifier authority.',
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
                    'The refused target-release proof handoff could not release its generic verifier authority.',
                    Object.freeze({
                        cleanupFailure,
                        status: verificationFinish.status,
                    }),
                );
            }
            statusBoundary.throwIfError(verificationFinish.status);
        }
        const verifiedShareHandle = requireLiveHandle(
            verificationFinish.handle,
            'The verified target-release share handle',
        );
        terminalSourceHandle = 0;
        try {
            verifiedShare = createVerifiedShare({
                context,
                handle: verifiedShareHandle,
                kernel: input.kernel,
            });
        } catch (adoptionFailure) {
            try {
                discardHandle({
                    context,
                    discard: kernel.discardVerifiedShare,
                    handle: verifiedShareHandle,
                    operationName:
                        'target-release failed verified-share adoption discard',
                    statusBoundary,
                });
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The verified target-release share could not be adopted or retired.',
                    Object.freeze({ adoptionFailure, cleanupFailure }),
                );
            }
            throw adoptionFailure;
        }
    } catch (error) {
        operationFailure = error;
        operationFailed = true;
    } finally {
        finalizedTargetIdentifierBytes.fill(0);
        finalizedTargetOrderBytes.fill(0);
        targetIdentifierPartialBytes.fill(0);
        targetOrderPartialBytes.fill(0);
    }

    const cleanupFailures: unknown[] = [];
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
                    'target-release verification terminal-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Target-release verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (verifiedShare === undefined) {
        throw new CanonicalStreamInternalError(
            'Target-release verification completed without a verified share.',
        );
    }
    return verifiedShare;
};

const copyReconstructedOptionIdentifiers = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    kernel: TargetReleaseKernel;
    memoryBoundary: WasmMemoryBoundary;
    reconstructedTargetResultHandle: number;
    resultByteLength: number;
    optionCount: number;
    statusBoundary: WasmStatusBoundary;
    statusPointer: number;
}): Uint32Array<ArrayBuffer> => {
    const outputPointer = input.memoryBoundary.allocate(input.resultByteLength);
    try {
        const returnedStatus = input.kernel.copyReconstructedOptionIdentifiers(
            input.reconstructedTargetResultHandle,
            outputPointer,
            input.resultByteLength,
            input.statusPointer,
        );
        input.statusBoundary.throwIfError(returnedStatus);
        const [writtenStatus] = input.memoryBoundary.readWords(
            input.statusPointer,
            1,
        );
        input.statusBoundary.throwIfError(writtenStatus);
        const encodedOptionIdentifiers = new DataView(
            input.context.memory.buffer,
            outputPointer,
            input.resultByteLength,
        );
        const orderedOptionIdentifiers = new Uint32Array(input.optionCount);
        for (
            let optionIndex = 0;
            optionIndex < input.optionCount;
            optionIndex += 1
        ) {
            orderedOptionIdentifiers[optionIndex] =
                encodedOptionIdentifiers.getUint32(
                    optionIndex * wasm32WordByteLength,
                    true,
                );
        }
        return orderedOptionIdentifiers;
    } finally {
        input.memoryBoundary.zeroAndDeallocate(
            outputPointer,
            input.resultByteLength,
        );
    }
};

/**
 * Consumes four through ten distinct Rust-owned paired shares, deterministically
 * selects the four lowest verified roster positions, and reconstructs the exact
 * finalized target as canonical one-based option identifiers in result order.
 * Constructing and certifying the subsequent state-output carrier remains a
 * separate protocol orchestration step.
 */
export const reconstructTargetReleaseInClosedWorker = (input: {
    finalizedTargetIdentifierBytes: Uint8Array;
    finalizedTargetOrderBytes: Uint8Array;
    kernel: TranscriptCoreKernel;
    verifiedFinality: VerifiedFinality;
    verifiedShares: readonly VerifiedTargetReleaseShare[];
}): ReconstructedTargetRelease => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Target-release reconstruction may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireTargetReleaseKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'target-release reconstruction boundary',
    });
    const finalityAuthorization = resolveVerifiedFinalityKernelAuthorization(
        input.verifiedFinality,
        input.kernel,
    );
    requireSameWorkerCapability({
        capabilityMemory: finalityAuthorization.capabilityMemory,
        capabilityPointer: finalityAuthorization.capabilityPointer,
        context,
        label: 'The verified finality',
    });
    const verifiedShareInput = input.verifiedShares;
    const untrustedVerifiedShareInput: unknown = verifiedShareInput;
    if (
        !Array.isArray(untrustedVerifiedShareInput) ||
        untrustedVerifiedShareInput.length <
            targetReleaseReconstructionThreshold ||
        untrustedVerifiedShareInput.length > foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const verifiedShares = verifiedShareInput.slice();
    const verifiedShareRecords = verifiedShares.map((share) => {
        const record = verifiedTargetReleaseShareRecords.get(share);
        if (record === undefined) {
            throw new CanonicalStreamRefusalError('consumedState');
        }
        if (record.context !== context || record.kernel !== input.kernel) {
            throw new CanonicalStreamInternalError(
                'The target-release reconstruction shares do not belong to one WASM worker.',
            );
        }
        return record;
    });
    if (
        new Set(verifiedShareRecords.map((record) => record.handle)).size !==
        verifiedShareRecords.length
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }

    let finalizedTargetIdentifierBytes: Uint8Array<ArrayBuffer> | undefined;
    let finalizedTargetOrderBytes: Uint8Array<ArrayBuffer> | undefined;
    let verifiedShareHandleBytes: Uint8Array<ArrayBuffer> | undefined;
    let reconstructedTargetResultHandle = 0;
    let shareOwnershipTransferred = false;
    let sharesConsumedByReconstruction = false;
    let reconstructedTargetRelease: ReconstructedTargetRelease | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        const ownedTargetIdentifierBytes = requireOwnedBytes(
            input.finalizedTargetIdentifierBytes,
        );
        const ownedTargetOrderBytes = requireOwnedBytes(
            input.finalizedTargetOrderBytes,
        );
        const encodedVerifiedShareHandles = new Uint8Array(
            verifiedShareRecords.length * wasm32WordByteLength,
        );
        finalizedTargetIdentifierBytes = ownedTargetIdentifierBytes;
        finalizedTargetOrderBytes = ownedTargetOrderBytes;
        verifiedShareHandleBytes = encodedVerifiedShareHandles;
        const handleView = new DataView(encodedVerifiedShareHandles.buffer);
        verifiedShareRecords.forEach((record, shareIndex) => {
            handleView.setUint32(
                shareIndex * wasm32WordByteLength,
                record.handle,
                true,
            );
        });

        shareOwnershipTransferred = true;
        verifiedShares.forEach((share) => {
            verifiedTargetReleaseShareRecords.delete(share);
        });

        reconstructedTargetRelease = context.runExclusive(
            'target-release reconstruction',
            () => {
                let targetIdentifierPointer = 0;
                let targetOrderPointer = 0;
                let shareHandlesPointer = 0;
                let statusPointer = 0;
                let orderedOptionIdentifiers:
                    | Uint32Array<ArrayBuffer>
                    | undefined;
                try {
                    targetIdentifierPointer = memoryBoundary.copy(
                        ownedTargetIdentifierBytes,
                    );
                    targetOrderPointer = memoryBoundary.copy(
                        ownedTargetOrderBytes,
                    );
                    shareHandlesPointer = memoryBoundary.copy(
                        encodedVerifiedShareHandles,
                    );
                    statusPointer = memoryBoundary.allocateZeroedWords(1);
                    const returnedHandle =
                        kernel.reconstructVerifiedShares(
                            finalityAuthorization.sessionHandle,
                            finalityAuthorization.capabilityPointer,
                            verifierCapabilityByteLength,
                            finalityAuthorization.finalityHandle,
                            targetIdentifierPointer,
                            ownedTargetIdentifierBytes.byteLength,
                            targetOrderPointer,
                            ownedTargetOrderBytes.byteLength,
                            shareHandlesPointer,
                            encodedVerifiedShareHandles.byteLength,
                            statusPointer,
                        ) >>> 0;
                    if (returnedHandle !== 0) {
                        reconstructedTargetResultHandle = returnedHandle;
                    }
                    const [reconstructionStatus] = memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    statusBoundary.throwIfError(reconstructionStatus);
                    reconstructedTargetResultHandle = requireLiveHandle(
                        returnedHandle,
                        'The reconstructed target-result handle',
                    );
                    sharesConsumedByReconstruction = true;

                    const selectedOptionCount =
                        kernel.reconstructedSelectedOptionCount(
                            reconstructedTargetResultHandle,
                            statusPointer,
                        );
                    const [selectedOptionCountStatus] =
                        memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(selectedOptionCountStatus);
                    if (
                        !Number.isSafeInteger(selectedOptionCount) ||
                        selectedOptionCount <= 0 ||
                        selectedOptionCount > foundationProfile.optionCount
                    ) {
                        throw new CanonicalStreamInternalError(
                            'The reconstructed target result has an invalid option count.',
                        );
                    }
                    const resultByteLength =
                        selectedOptionCount * wasm32WordByteLength;
                    memoryBoundary.validateAllocationByteLength(
                        resultByteLength,
                    );
                    const copiedOrderedOptionIdentifiers =
                        copyReconstructedOptionIdentifiers({
                            context,
                            kernel,
                            memoryBoundary,
                            reconstructedTargetResultHandle,
                            resultByteLength,
                            optionCount: selectedOptionCount,
                            statusBoundary,
                            statusPointer,
                        });
                    orderedOptionIdentifiers = copiedOrderedOptionIdentifiers;
                    statusBoundary.throwIfError(
                        kernel.finishReconstruction(
                            reconstructedTargetResultHandle,
                        ),
                    );
                    reconstructedTargetResultHandle = 0;
                    return Object.freeze({
                        orderedOptionIdentifiers:
                            copiedOrderedOptionIdentifiers,
                    });
                } catch (error) {
                    orderedOptionIdentifiers?.fill(0);
                    throw error;
                } finally {
                    if (statusPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            statusPointer,
                            wasm32WordByteLength,
                        );
                    }
                    if (shareHandlesPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            shareHandlesPointer,
                            encodedVerifiedShareHandles.byteLength,
                        );
                    }
                    if (targetOrderPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetOrderPointer,
                            ownedTargetOrderBytes.byteLength,
                        );
                    }
                    if (targetIdentifierPointer !== 0) {
                        memoryBoundary.zeroAndDeallocate(
                            targetIdentifierPointer,
                            ownedTargetIdentifierBytes.byteLength,
                        );
                    }
                }
            },
        );
    } catch (error) {
        operationFailure = error;
        operationFailed = true;
    } finally {
        finalizedTargetIdentifierBytes?.fill(0);
        finalizedTargetOrderBytes?.fill(0);
        verifiedShareHandleBytes?.fill(0);
    }

    const cleanupFailures: unknown[] = [];
    if (reconstructedTargetResultHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardReconstruction,
                handle: reconstructedTargetResultHandle,
                operationName: 'target-release reconstruction discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (
        shareOwnershipTransferred &&
        !sharesConsumedByReconstruction &&
        reconstructedTargetRelease === undefined
    ) {
        for (const record of verifiedShareRecords) {
            try {
                discardHandle({
                    context,
                    discard: kernel.discardVerifiedShare,
                    handle: record.handle,
                    operationName:
                        'target-release reconstruction share cleanup',
                    statusBoundary,
                });
            } catch (cleanupFailure) {
                cleanupFailures.push(cleanupFailure);
            }
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Target-release reconstruction failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (reconstructedTargetRelease === undefined) {
        throw new CanonicalStreamInternalError(
            'Target-release reconstruction completed without a canonical result.',
        );
    }
    return reconstructedTargetRelease;
};
