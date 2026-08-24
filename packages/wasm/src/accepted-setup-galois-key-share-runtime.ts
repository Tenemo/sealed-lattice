import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
    foundationProfile,
    refusalReasonCodes,
    type BrowserActionStorageWorkerKernel,
} from '@sealed-lattice/types';

import {
    createAcceptedSetupEvaluatorComponentBacking,
    readAcceptedSetupPrepackageEvaluatorComponentExactRange,
    releaseUnretainedAcceptedSetupEvaluatorComponentBackings,
    requireAcceptedSetupEvaluatorComponentBackingsRetainable,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner,
    retainAcceptedSetupEvaluatorComponentBackings,
    type AcceptedSetupEvaluatorComponentBacking,
    type AcceptedSetupEvaluatorSourceCatalogSession,
} from './accepted-setup-assembly-runtime.js';
import {
    requireAcceptedSetupPackageBuilderKernelOwner,
    type AcceptedSetupPackageBuilder,
} from './accepted-setup-package-builder-runtime.js';
import { isUint8Array } from './byte-array.js';
import type { VerifiedTranscriptObject } from './canonical-board-runtime.js';
import {
    canonicalStreamDomains,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    deriveCanonicalStreamChunkCount,
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
    type CommonProofCanonicalOutputStore,
    type CommonProofGenerationExecutionOpener,
    type CommonProofVerificationWorkerOptions,
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
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const maximumRosterPosition = 0xffff;

export type GaloisKeyShareBatchGenerationMode = 'fresh' | 'resumed';

/** Browser-owned durable storage for one exact generated public component. */
export type GaloisKeyShareComponentStore = CommonProofCanonicalOutputStore &
    Readonly<{
        release(): void;
    }>;

/** Canonical public bindings needed to replay one component into verification. */
export type GaloisKeyShareComponentDescription = Readonly<{
    materialRoot: Uint8Array<ArrayBuffer>;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

/** Public output after the generated proof and its components enter catalog custody. */
export type GeneratedGaloisKeyShareBatch = Readonly<{
    components: readonly GaloisKeyShareComponentDescription[];
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

type GaloisKeyShareKernel = Readonly<{
    absorbComponentChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_absorb_chunk']
    >;
    beginComponent: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_begin']
    >;
    beginVerificationIngress: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_verification_ingress_begin']
    >;
    cancelComponentReadback: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_cancel']
    >;
    commitGeneratedSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_commit_generated_source']
    >;
    componentCount: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_component_count']
    >;
    componentDescriptorByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_descriptor_byte_length']
    >;
    componentTotalByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_total_byte_length']
    >;
    copyComponentDescriptor: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_copy_descriptor']
    >;
    copyComponentMaterialRoot: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_copy_material_root']
    >;
    discardGenerationSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_discard_generation_source']
    >;
    discardVerificationIngress: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_discard_verification_ingress']
    >;
    discardVerificationTerminalSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_discard_verification_terminal_source']
    >;
    finishComponent: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_finish']
    >;
    finishComponentReadback: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_finish']
    >;
    finishVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_finish_verification']
    >;
    openComponentReadback: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_open']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_prepare_generation']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_prepare_resumed_generation']
    >;
    prepareVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_prepare_verification']
    >;
    readComponentChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_read_chunk']
    >;
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_select_suite']
    >;
}>;

type DecodedComponentDescription = Readonly<{
    chunkByteLengths: readonly number[];
    fullObjectDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: number;
}>;

const createStatusBoundary = (): WasmStatusBoundary =>
    new WasmStatusBoundary({
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createRefusalError: (refusalReason) =>
            new CanonicalStreamRefusalError(refusalReason),
        createResourceError: () => new CanonicalStreamResourceError(),
        internalFailureMessage:
            'The Galois key-share batch runtime failed internally.',
        unknownStatusMessage:
            'The Galois key-share batch runtime returned an unknown status code.',
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

const requireCanonicalSuiteRecordBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
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

const requireGaloisKeyShareKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): GaloisKeyShareKernel => {
    const wasmExports = context.wasmExports;
    const kernel: GaloisKeyShareKernel = {
        absorbComponentChunk:
            wasmExports.sealed_lattice_galois_key_share_component_absorb_chunk!,
        beginComponent:
            wasmExports.sealed_lattice_galois_key_share_component_begin!,
        beginVerificationIngress:
            wasmExports.sealed_lattice_galois_key_share_verification_ingress_begin!,
        cancelComponentReadback:
            wasmExports.sealed_lattice_galois_key_share_component_readback_cancel!,
        commitGeneratedSource:
            wasmExports.sealed_lattice_galois_key_share_commit_generated_source!,
        componentCount:
            wasmExports.sealed_lattice_galois_key_share_component_readback_component_count!,
        componentDescriptorByteLength:
            wasmExports.sealed_lattice_galois_key_share_component_readback_descriptor_byte_length!,
        componentTotalByteLength:
            wasmExports.sealed_lattice_galois_key_share_component_readback_total_byte_length!,
        copyComponentDescriptor:
            wasmExports.sealed_lattice_galois_key_share_component_readback_copy_descriptor!,
        copyComponentMaterialRoot:
            wasmExports.sealed_lattice_galois_key_share_component_readback_copy_material_root!,
        discardGenerationSource:
            wasmExports.sealed_lattice_galois_key_share_discard_generation_source!,
        discardVerificationIngress:
            wasmExports.sealed_lattice_galois_key_share_discard_verification_ingress!,
        discardVerificationTerminalSource:
            wasmExports.sealed_lattice_galois_key_share_discard_verification_terminal_source!,
        finishComponent:
            wasmExports.sealed_lattice_galois_key_share_component_finish!,
        finishComponentReadback:
            wasmExports.sealed_lattice_galois_key_share_component_readback_finish!,
        finishVerification:
            wasmExports.sealed_lattice_galois_key_share_finish_verification!,
        openComponentReadback:
            wasmExports.sealed_lattice_galois_key_share_component_readback_open!,
        prepareGeneration:
            wasmExports.sealed_lattice_galois_key_share_prepare_generation!,
        prepareResumedGeneration:
            wasmExports.sealed_lattice_galois_key_share_prepare_resumed_generation!,
        prepareVerification:
            wasmExports.sealed_lattice_galois_key_share_prepare_verification!,
        readComponentChunk:
            wasmExports.sealed_lattice_galois_key_share_component_readback_read_chunk!,
        releaseSelectedSuite:
            wasmExports.sealed_lattice_common_proof_release_suite!,
        selectSuite: wasmExports.sealed_lattice_common_proof_select_suite!,
    };
    if (
        Object.values(kernel).some((boundary) => typeof boundary !== 'function')
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the Galois key-share batch boundary.',
        );
    }
    return Object.freeze(kernel);
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive('Galois selected-suite acquisition', () => {
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
            const [status] = input.memoryBoundary.readWords(statusPointer, 1);
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
    });

const releaseSelectedSuite = (input: {
    context: TranscriptCoreKernelCommandRuntime;
    handle: number;
    kernel: GaloisKeyShareKernel;
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

const decodeComponentDescription = (input: {
    malformedDescriptorIsInternal: boolean;
    kernel: TranscriptCoreKernel;
    streamDescriptorBytes: Uint8Array;
}): DecodedComponentDescription => {
    let decoded;
    try {
        decoded = input.kernel.decodeStreamDescriptor({
            canonicalBytesHex: bytesToHex(input.streamDescriptorBytes),
        }).value;
    } catch (error) {
        if (!input.malformedDescriptorIsInternal) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
        throw new CanonicalStreamInternalError(
            'Rust returned a malformed Galois component stream descriptor.',
            { cause: error },
        );
    }
    const totalByteLength = Number(decoded.totalByteLength);
    if (
        !Number.isSafeInteger(totalByteLength) ||
        totalByteLength <= 0 ||
        totalByteLength > foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The Galois component stream length is outside the canonical runtime bounds.',
        );
    }
    const chunkCount = deriveCanonicalStreamChunkCount(totalByteLength);
    if (decoded.orderedChunkDigests.length !== chunkCount) {
        throw new CanonicalStreamInternalError(
            'The Galois component descriptor has the wrong canonical chunk count.',
        );
    }
    const fullObjectDigest = Uint8Array.from(
        hexToBytes(decoded.fullObjectDigest),
    );
    if (fullObjectDigest.byteLength !== materialRootByteLength) {
        throw new CanonicalStreamInternalError(
            'The Galois component descriptor has the wrong stream-digest length.',
        );
    }
    const chunkByteLengths = Array.from({ length: chunkCount }, (_, index) =>
        Math.min(
            foundationProfile.streamChunkByteLength,
            totalByteLength - index * foundationProfile.streamChunkByteLength,
        ),
    );
    return Object.freeze({
        chunkByteLengths: Object.freeze(chunkByteLengths),
        fullObjectDigest,
        totalByteLength,
    });
};

const readExactComponentStoreRange = async (input: {
    chunkByteLengths: readonly number[];
    exactByteLength: number;
    sourceByteOffset: bigint;
    store: GaloisKeyShareComponentStore;
    totalByteLength: number;
}): Promise<Uint8Array<ArrayBuffer>> => {
    if (
        typeof input.sourceByteOffset !== 'bigint' ||
        input.sourceByteOffset < 0n ||
        !Number.isSafeInteger(input.exactByteLength) ||
        input.exactByteLength <= 0 ||
        input.sourceByteOffset + BigInt(input.exactByteLength) >
            BigInt(input.totalByteLength)
    ) {
        throw new CanonicalStreamInternalError(
            'The evaluator-source catalog requested an invalid Galois component range.',
        );
    }
    const numericOffset = Number(input.sourceByteOffset);
    if (!Number.isSafeInteger(numericOffset)) {
        throw new CanonicalStreamResourceError(
            'The Galois component range exceeds JavaScript indexing bounds.',
        );
    }
    const output = new Uint8Array(input.exactByteLength);
    const lastExclusiveOffset = numericOffset + input.exactByteLength;
    let outputOffset = 0;
    let chunkIndex = Math.floor(
        numericOffset / foundationProfile.streamChunkByteLength,
    );
    while (numericOffset + outputOffset < lastExclusiveOffset) {
        const chunkByteLength = input.chunkByteLengths[chunkIndex];
        if (chunkByteLength === undefined) {
            throw new CanonicalStreamInternalError(
                'The Galois component store lacks a required canonical chunk.',
            );
        }
        const chunk = await input.store.readChunk(chunkIndex, chunkByteLength);
        if (!isUint8Array(chunk) || chunk.byteLength !== chunkByteLength) {
            throw new CanonicalStreamInternalError(
                'The Galois component store returned a malformed canonical chunk.',
            );
        }
        const chunkStartOffset =
            chunkIndex * foundationProfile.streamChunkByteLength;
        const copyStart = Math.max(numericOffset - chunkStartOffset, 0);
        const copyEnd = Math.min(
            lastExclusiveOffset - chunkStartOffset,
            chunkByteLength,
        );
        output.set(chunk.subarray(copyStart, copyEnd), outputOffset);
        outputOffset += copyEnd - copyStart;
        chunk.fill(0);
        chunkIndex += 1;
    }
    return output;
};

const copyReadbackDescriptor = (input: {
    componentOrdinal: number;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    readbackHandle: number;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive('Galois component descriptor readback', () => {
        const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
        let outputPointer = 0;
        let outputByteLength = 0;
        try {
            outputByteLength = input.kernel.componentDescriptorByteLength(
                input.readbackHandle,
                input.componentOrdinal,
                statusPointer,
            );
            const [lengthStatus] = input.memoryBoundary.readWords(
                statusPointer,
                1,
            );
            input.statusBoundary.throwIfError(lengthStatus);
            input.memoryBoundary.validateAllocationByteLength(outputByteLength);
            outputPointer = input.memoryBoundary.allocate(outputByteLength);
            const copyStatus = input.kernel.copyComponentDescriptor(
                input.readbackHandle,
                input.componentOrdinal,
                outputPointer,
                outputByteLength,
                statusPointer,
            );
            input.statusBoundary.throwIfError(copyStatus);
            const [status] = input.memoryBoundary.readWords(statusPointer, 1);
            input.statusBoundary.throwIfError(status);
            return new Uint8Array(
                input.context.memory.buffer,
                outputPointer,
                outputByteLength,
            ).slice();
        } finally {
            input.memoryBoundary.zeroAndDeallocate(
                outputPointer,
                outputByteLength,
            );
            input.memoryBoundary.zeroAndDeallocate(
                statusPointer,
                wasm32WordByteLength,
            );
        }
    });

const copyReadbackMaterialRoot = (input: {
    componentOrdinal: number;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    readbackHandle: number;
    statusBoundary: WasmStatusBoundary;
}): Uint8Array<ArrayBuffer> =>
    input.context.runExclusive(
        'Galois component material-root readback',
        () => {
            const outputPointer = input.memoryBoundary.allocate(
                materialRootByteLength,
            );
            try {
                const status = input.kernel.copyComponentMaterialRoot(
                    input.readbackHandle,
                    input.componentOrdinal,
                    outputPointer,
                    materialRootByteLength,
                );
                input.statusBoundary.throwIfError(status);
                return new Uint8Array(
                    input.context.memory.buffer,
                    outputPointer,
                    materialRootByteLength,
                ).slice();
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    materialRootByteLength,
                );
            }
        },
    );

const readGeneratedComponents = async (input: {
    componentStores: readonly GaloisKeyShareComponentStore[];
    context: TranscriptCoreKernelCommandRuntime;
    generationSourceHandle: number;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    publicKernel: TranscriptCoreKernel;
    statusBoundary: WasmStatusBoundary;
}): Promise<
    Readonly<{
        backings: readonly AcceptedSetupEvaluatorComponentBacking[];
        components: readonly GaloisKeyShareComponentDescription[];
    }>
> => {
    let preparedReadback:
        | Readonly<{ componentCount: number; readbackHandle: number }>
        | undefined;
    try {
        preparedReadback = input.context.runExclusive(
            'Galois component readback open',
            () => {
                const statusPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                let readbackHandle = 0;
                try {
                    readbackHandle = input.kernel.openComponentReadback(
                        input.generationSourceHandle,
                        statusPointer,
                    );
                    const [openStatus] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(openStatus);
                    readbackHandle = requireLiveHandle(
                        readbackHandle,
                        'The Galois component readback handle',
                    );
                    const componentCount = input.kernel.componentCount(
                        readbackHandle,
                        statusPointer,
                    );
                    const [countStatus] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(countStatus);
                    if (
                        !Number.isSafeInteger(componentCount) ||
                        componentCount <= 0 ||
                        componentCount !== input.componentStores.length
                    ) {
                        throw new CanonicalStreamRefusalError(
                            'wrongTypeOrLength',
                        );
                    }
                    return Object.freeze({ componentCount, readbackHandle });
                } catch (error) {
                    if (readbackHandle !== 0) {
                        input.kernel.cancelComponentReadback(
                            input.generationSourceHandle,
                            readbackHandle,
                        );
                    }
                    throw error;
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
    } catch (operationFailure) {
        const cleanupFailures: unknown[] = [];
        for (const store of input.componentStores) {
            try {
                store.release();
            } catch (cleanupFailure) {
                cleanupFailures.push(cleanupFailure);
            }
        }
        if (cleanupFailures.length > 0) {
            throw new CanonicalStreamInternalError(
                'Galois readback preparation failed to release its component stores.',
                Object.freeze({ cleanupFailures, operationFailure }),
            );
        }
        throw operationFailure;
    }
    let readbackHandle = preparedReadback.readbackHandle;
    const backings: AcceptedSetupEvaluatorComponentBacking[] = [];
    const components: GaloisKeyShareComponentDescription[] = [];
    const adoptedStoreOrdinals = new Set<number>();
    let operationFailure: unknown;
    try {
        for (
            let componentOrdinal = 0;
            componentOrdinal < preparedReadback.componentCount;
            componentOrdinal += 1
        ) {
            const store = input.componentStores[componentOrdinal];
            if (
                typeof store.commitChunk !== 'function' ||
                typeof store.readChunk !== 'function' ||
                typeof store.release !== 'function'
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            const streamDescriptorBytes = copyReadbackDescriptor({
                componentOrdinal,
                context: input.context,
                kernel: input.kernel,
                memoryBoundary: input.memoryBoundary,
                readbackHandle,
                statusBoundary: input.statusBoundary,
            });
            const materialRoot = copyReadbackMaterialRoot({
                componentOrdinal,
                context: input.context,
                kernel: input.kernel,
                memoryBoundary: input.memoryBoundary,
                readbackHandle,
                statusBoundary: input.statusBoundary,
            });
            const decodedDescription = decodeComponentDescription({
                kernel: input.publicKernel,
                malformedDescriptorIsInternal: true,
                streamDescriptorBytes,
            });
            const reportedTotalByteLength = input.context.runExclusive(
                'Galois component length readback',
                () => {
                    const statusPointer =
                        input.memoryBoundary.allocateZeroedWords(1);
                    try {
                        const totalByteLength =
                            input.kernel.componentTotalByteLength(
                                readbackHandle,
                                componentOrdinal,
                                statusPointer,
                            );
                        const [status] = input.memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        input.statusBoundary.throwIfError(status);
                        return totalByteLength;
                    } finally {
                        input.memoryBoundary.zeroAndDeallocate(
                            statusPointer,
                            wasm32WordByteLength,
                        );
                    }
                },
            );
            if (
                reportedTotalByteLength !==
                BigInt(decodedDescription.totalByteLength)
            ) {
                throw new CanonicalStreamInternalError(
                    'The Galois component readback length does not match its Rust-minted descriptor.',
                );
            }
            for (
                let chunkIndex = 0;
                chunkIndex < decodedDescription.chunkByteLengths.length;
                chunkIndex += 1
            ) {
                const chunkByteLength =
                    decodedDescription.chunkByteLengths[chunkIndex];
                const chunkBytes = input.context.runExclusive(
                    'Galois component chunk readback',
                    () => {
                        const outputPointer =
                            input.memoryBoundary.allocate(chunkByteLength);
                        const statusPointer =
                            input.memoryBoundary.allocateZeroedWords(1);
                        try {
                            const readStatus = input.kernel.readComponentChunk(
                                readbackHandle,
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
                    },
                );
                try {
                    await store.commitChunk(chunkIndex, chunkBytes);
                } finally {
                    chunkBytes.fill(0);
                }
            }
            const backing = createAcceptedSetupEvaluatorComponentBacking({
                authenticatedByteLength: BigInt(
                    decodedDescription.totalByteLength,
                ),
                fullObjectDigest: decodedDescription.fullObjectDigest,
                kernel: input.publicKernel,
                materialRoot,
                readExactRange: (sourceByteOffset, exactByteLength) =>
                    readExactComponentStoreRange({
                        chunkByteLengths: decodedDescription.chunkByteLengths,
                        exactByteLength,
                        sourceByteOffset,
                        store,
                        totalByteLength: decodedDescription.totalByteLength,
                    }),
                release: () => store.release(),
            });
            adoptedStoreOrdinals.add(componentOrdinal);
            backings.push(backing);
            components.push(
                Object.freeze({
                    materialRoot,
                    streamDescriptorBytes,
                }),
            );
        }
        const finishStatus = input.context.runExclusive(
            'Galois component readback finish',
            () =>
                input.kernel.finishComponentReadback(
                    input.generationSourceHandle,
                    readbackHandle,
                ),
        );
        input.statusBoundary.throwIfError(finishStatus);
        readbackHandle = 0;
        return Object.freeze({
            backings: Object.freeze(backings),
            components: Object.freeze(components),
        });
    } catch (error) {
        operationFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    if (readbackHandle !== 0) {
        try {
            const status = input.context.runExclusive(
                'Galois component readback cancellation',
                () =>
                    input.kernel.cancelComponentReadback(
                        input.generationSourceHandle,
                        readbackHandle,
                    ),
            );
            input.statusBoundary.throwIfError(status);
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (backings.length > 0) {
        try {
            releaseUnretainedAcceptedSetupEvaluatorComponentBackings(
                backings,
                input.publicKernel,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    input.componentStores.forEach((store, componentOrdinal) => {
        if (!adoptedStoreOrdinals.has(componentOrdinal)) {
            try {
                store.release();
            } catch (cleanupFailure) {
                cleanupFailures.push(cleanupFailure);
            }
        }
    });
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Galois component readback failed to retire all browser-owned storage.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};

/**
 * Generates the exact selected participant batch, persists every Rust-owned
 * public component, and transfers the generated proof/source into the
 * collecting evaluator-source catalog.
 */
export const generateGaloisKeyShareBatchInClosedWorker = async (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    componentStores: readonly GaloisKeyShareComponentStore[];
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    generationMode: GaloisKeyShareBatchGenerationMode;
    kernel: TranscriptCoreKernel;
    openProofGenerationExecution: CommonProofGenerationExecutionOpener;
    packageBuilder: AcceptedSetupPackageBuilder;
    productionOperationIdentifiers: ClosedWorkerProductionOperationIdentifiers;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    workerKernel: BrowserActionStorageWorkerKernel;
}): Promise<GeneratedGaloisKeyShareBatch> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Galois key-share generation may only run inside the dedicated WASM worker.',
        );
    }
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        input.componentStores.length === 0
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireGaloisKeyShareKernel(context);
    const packageBuilderOwner = requireAcceptedSetupPackageBuilderKernelOwner(
        input.packageBuilder,
        input.kernel,
        'collecting',
    );
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'Galois key-share generation',
    });
    const checkpointLineageIdentifier = requireFixedOwnedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );
    const setupGenerationAuthorization =
        resolveSetupGenerationAuthorityKernelAuthorization(
            input.setupGenerationAuthority,
            context,
        );
    const setupIntentAuthorization =
        resolveOrderedVerifiedBoardObjectAuthorization({
            context,
            expectedObjectCount: 1,
            kernel: input.kernel,
            objects: [input.setupIntentObject],
        });
    const catalogOwner = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    if (
        setupIntentAuthorization.handleBytes.byteLength !== wasm32WordByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'The Galois key-share generation authorities do not belong to one WASM worker.',
        );
    }

    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context,
        kernel,
        memoryBoundary,
        statusBoundary,
    });
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let generationSourceHandle = 0;
    let unretainedBackings:
        | readonly AcceptedSetupEvaluatorComponentBacking[]
        | undefined;
    let operationFailure: unknown;
    try {
        let prepared:
            | Readonly<{
                  adapterHandle: number;
                  generationSourceHandle: number;
              }>
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
                        if (
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
                                'The Galois key-share generation authorities do not belong to one WASM worker.',
                            );
                        }
                        prepared = context.runExclusive(
                            'Galois key-share generation preparation',
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
                                        setupGenerationAuthorization.handle,
                                        authorization.actionRandomnessHandle,
                                        authorization.stateVerifierSessionHandle,
                                        authorization.stateReservationCapabilityPointer,
                                        verifierCapabilityByteLength,
                                        authorization.stateReservationHandle,
                                        setupIntentAuthorization.sessionHandle,
                                        setupIntentAuthorization.capabilityPointer,
                                        verifierCapabilityByteLength,
                                        new DataView(
                                            setupIntentAuthorization.handleBytes
                                                .buffer,
                                            setupIntentAuthorization.handleBytes
                                                .byteOffset,
                                            setupIntentAuthorization.handleBytes
                                                .byteLength,
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
                                            'The Galois generation family-adapter handle',
                                        ),
                                        generationSourceHandle:
                                            requireLiveHandle(
                                                sourceHandle,
                                                'The Galois generation source handle',
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
                'The production operation completed without a proof-family adapter.',
            );
        }
        generationSourceHandle = prepared.generationSourceHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName: 'Galois generation selected-suite release',
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
                proofFamilyLabel: 'Galois key-share batch',
                streamDomain: canonicalStreamDomains.galoisShareProof,
            },
        );
        const generatedComponents = await readGeneratedComponents({
            componentStores: input.componentStores,
            context,
            generationSourceHandle,
            kernel,
            memoryBoundary,
            publicKernel: input.kernel,
            statusBoundary,
        });
        unretainedBackings = generatedComponents.backings;
        requireAcceptedSetupEvaluatorComponentBackingsRetainable({
            backings: unretainedBackings,
            catalog: input.evaluatorSourceCatalog,
            kernel: input.kernel,
        });
        const capabilityForCommit = generatedCapability;
        const commitStatus = applyClosedWorkerGeneratedCommonProofCapability(
            capabilityForCommit,
            context,
            (generatedCommonProofHandle) => {
                const status = context.runExclusive(
                    'Galois generated-source catalog commit',
                    () =>
                        kernel.commitGeneratedSource(
                            packageBuilderOwner.handle,
                            catalogOwner.handle,
                            generatedCommonProofHandle,
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
            components: generatedComponents.components,
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
                operationName:
                    'Galois generation selected-suite failure release',
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
    if (generationSourceHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardGenerationSource,
                handle: generationSourceHandle,
                operationName: 'Galois generation-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (unretainedBackings !== undefined) {
        try {
            releaseUnretainedAcceptedSetupEvaluatorComponentBackings(
                unretainedBackings,
                input.kernel,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Galois generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};

const requireVerificationComponent = (input: {
    component: GaloisKeyShareComponentDescription;
    kernel: TranscriptCoreKernel;
}): Readonly<{
    decoded: DecodedComponentDescription;
    materialRoot: Uint8Array<ArrayBuffer>;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}> => {
    const streamDescriptorBytes =
        isUint8Array(input.component.streamDescriptorBytes) &&
        input.component.streamDescriptorBytes.byteLength > 0
            ? input.component.streamDescriptorBytes.slice()
            : undefined;
    if (streamDescriptorBytes === undefined) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const materialRoot = requireFixedOwnedBytes(
        input.component.materialRoot,
        materialRootByteLength,
    );
    return Object.freeze({
        decoded: decodeComponentDescription({
            kernel: input.kernel,
            malformedDescriptorIsInternal: false,
            streamDescriptorBytes,
        }),
        materialRoot,
        streamDescriptorBytes,
    });
};

/**
 * Replays every catalog-owned public component, verifies the exact proof, and
 * commits only the positive Rust family terminal back into catalog custody.
 */
export const verifyGaloisKeyShareBatchInClosedWorker = async (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    components: readonly GaloisKeyShareComponentDescription[];
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    inputStore: AuthenticatedCommonProofInputStore;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
    rosterPosition: number;
}): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Galois key-share verification may only run inside the dedicated WASM worker.',
        );
    }
    if (
        !Number.isSafeInteger(input.rosterPosition) ||
        input.rosterPosition < 0 ||
        input.rosterPosition > maximumRosterPosition ||
        input.components.length === 0
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireGaloisKeyShareKernel(context);
    const catalogOwner = requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
        input.evaluatorSourceCatalog,
        input.kernel,
        'collecting',
    );
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'Galois key-share verification',
    });
    const components = input.components.map((component) =>
        requireVerificationComponent({ component, kernel: input.kernel }),
    );
    let selectedSuiteHandle = selectSuite({
        canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
        context,
        kernel,
        memoryBoundary,
        statusBoundary,
    });
    let ingressHandle = 0;
    let terminalSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let operationFailure: unknown;
    try {
        ingressHandle = context.runExclusive(
            'Galois verification ingress begin',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = kernel.beginVerificationIngress(
                        selectedSuiteHandle,
                        catalogOwner.handle,
                        input.rosterPosition,
                        statusPointer,
                    );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The Galois verification ingress handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        for (
            let componentOrdinal = 0;
            componentOrdinal < components.length;
            componentOrdinal += 1
        ) {
            const component = components[componentOrdinal];
            const descriptorPointer = memoryBoundary.copy(
                component.streamDescriptorBytes,
            );
            try {
                const beginStatus = context.runExclusive(
                    'Galois verification component begin',
                    () =>
                        kernel.beginComponent(
                            ingressHandle,
                            componentOrdinal,
                            descriptorPointer,
                            component.streamDescriptorBytes.byteLength,
                        ),
                );
                statusBoundary.throwIfError(beginStatus);
            } finally {
                memoryBoundary.zeroAndDeallocate(
                    descriptorPointer,
                    component.streamDescriptorBytes.byteLength,
                );
            }
            let sourceByteOffset = 0n;
            for (
                let chunkIndex = 0;
                chunkIndex < component.decoded.chunkByteLengths.length;
                chunkIndex += 1
            ) {
                const chunkByteLength =
                    component.decoded.chunkByteLengths[chunkIndex];
                const chunk =
                    await readAcceptedSetupPrepackageEvaluatorComponentExactRange(
                        {
                            authenticatedByteLength: BigInt(
                                component.decoded.totalByteLength,
                            ),
                            catalog: input.evaluatorSourceCatalog,
                            exactByteLength: chunkByteLength,
                            fullObjectDigest:
                                component.decoded.fullObjectDigest,
                            kernel: input.kernel,
                            materialRoot: component.materialRoot,
                            sourceByteOffset,
                        },
                    );
                const chunkPointer = memoryBoundary.copy(chunk);
                try {
                    const absorbStatus = context.runExclusive(
                        'Galois verification component chunk absorb',
                        () =>
                            kernel.absorbComponentChunk(
                                ingressHandle,
                                componentOrdinal,
                                chunkIndex,
                                chunkPointer,
                                chunk.byteLength,
                            ),
                    );
                    statusBoundary.throwIfError(absorbStatus);
                } finally {
                    chunk.fill(0);
                    memoryBoundary.zeroAndDeallocate(
                        chunkPointer,
                        chunkByteLength,
                    );
                }
                sourceByteOffset += BigInt(chunkByteLength);
            }
            const finishStatus = context.runExclusive(
                'Galois verification component finish',
                () => kernel.finishComponent(ingressHandle, componentOrdinal),
            );
            statusBoundary.throwIfError(finishStatus);
        }
        const prepared = context.runExclusive(
            'Galois common-proof verification preparation',
            () => {
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const adapterHandle = kernel.prepareVerification(
                        selectedSuiteHandle,
                        ingressHandle,
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
                            'The Galois verification family-adapter handle',
                        ),
                        terminalSourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The Galois verification terminal-source handle',
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
        ingressHandle = 0;
        terminalSourceHandle = prepared.terminalSourceHandle;
        familyAdapter = openClosedWorkerCommonProofVerificationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName: 'Galois verification selected-suite release',
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
        let finishStatus: number;
        try {
            finishStatus = applyClosedWorkerVerifiedCommonProofCapability(
                verifiedCommonProof,
                context,
                (verifiedCommonProofHandle) => {
                    const status = context.runExclusive(
                        'Galois verification finish',
                        () =>
                            kernel.finishVerification(
                                verifiedCommonProofHandle,
                                terminalSourceHandle,
                            ),
                    );
                    return Object.freeze({
                        consumed: status === 0,
                        result: status,
                    });
                },
            );
        } catch (handoffFailure) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The failed Galois proof handoff could not release its generic verifier authority.',
                    Object.freeze({ cleanupFailure, handoffFailure }),
                );
            }
            throw handoffFailure;
        }
        if (finishStatus !== 0) {
            try {
                verifiedCommonProof.release();
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The refused Galois proof handoff could not release its generic verifier authority.',
                    Object.freeze({ cleanupFailure, finishStatus }),
                );
            }
            statusBoundary.throwIfError(finishStatus);
        }
        terminalSourceHandle = 0;
        for (const component of components) {
            component.decoded.fullObjectDigest.fill(0);
            component.materialRoot.fill(0);
            component.streamDescriptorBytes.fill(0);
        }
        return;
    } catch (error) {
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
                    'Galois verification selected-suite failure release',
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
    if (ingressHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardVerificationIngress,
                handle: ingressHandle,
                operationName: 'Galois verification ingress discard',
                statusBoundary,
            });
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
                operationName: 'Galois verification terminal-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    for (const component of components) {
        component.decoded.fullObjectDigest.fill(0);
        component.materialRoot.fill(0);
        component.streamDescriptorBytes.fill(0);
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Galois verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};
