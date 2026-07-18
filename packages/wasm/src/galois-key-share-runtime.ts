import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import {
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage,
    createAcceptedSetupEvaluatorComponentBacking,
    readAcceptedSetupPrepackageEvaluatorComponentExactRange,
    releaseUnretainedAcceptedSetupEvaluatorComponentBackings,
    requireAcceptedSetupEvaluatorComponentBackingsRetainable,
    requireAcceptedSetupEvaluatorSourceCatalogKernelOwner,
    retainAcceptedSetupEvaluatorComponentBackings,
    type AcceptedSetupEvaluatorComponentBacking,
    type AcceptedSetupEvaluatorSourceCatalogSession,
    type AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
import {
    resolveActionRandomnessKernelAuthorization,
    type ActionRandomnessSession,
} from './action-randomness-runtime.js';
import { byteArraysEqual, isUint8Array } from './byte-array.js';
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
} from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const verifierCapabilityByteLength = 32;
const checkpointLineageIdentifierByteLength = 32;
const hashByteLength = 64;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const selectedGaloisComponentCount = 4;

const throwIfAborted = (signal: AbortSignal | undefined): void => {
    if (signal?.aborted === true) {
        throw new CanonicalStreamCancellationError();
    }
};

export type GaloisKeyShareGenerationMode = 'fresh' | 'resumed';

/** Canonical public carrier minted from the exact generated Galois source. */
export type GeneratedGaloisKeyShareComponentTransport = Readonly<{
    canonicalDescriptorBytes: Uint8Array<ArrayBuffer>;
    materialRoot: Uint8Array<ArrayBuffer>;
}>;

/** Public transport needed to assemble and later verify one Galois batch. */
export type GeneratedGaloisKeyShareTransport = Readonly<{
    orderedComponents: readonly GeneratedGaloisKeyShareComponentTransport[];
    proofDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

export type GaloisKeyShareComponentOutputStoreResolver = Readonly<{
    resolveOutputStore(input: {
        canonicalDescriptorBytes: Uint8Array<ArrayBuffer>;
        componentOrdinal: number;
        materialRoot: Uint8Array<ArrayBuffer>;
        totalByteLength: number;
    }): Promise<CommonProofCanonicalOutputStore>;
}>;

type GaloisKeyShareKernel = Readonly<{
    commitGeneratedSource: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_commit_generated_source']
    >;
    componentAbsorbChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_absorb_chunk']
    >;
    componentBegin: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_begin']
    >;
    componentFinish: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_finish']
    >;
    componentReadbackCancel: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_cancel']
    >;
    componentReadbackComponentCount: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_component_count']
    >;
    componentReadbackCopyDescriptor: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_copy_descriptor']
    >;
    componentReadbackCopyMaterialRoot: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_copy_material_root']
    >;
    componentReadbackDescriptorByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_descriptor_byte_length']
    >;
    componentReadbackFinish: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_finish']
    >;
    componentReadbackOpen: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_open']
    >;
    componentReadbackReadChunk: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_read_chunk']
    >;
    componentReadbackTotalByteLength: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_component_readback_total_byte_length']
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
    finishVerification: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_finish_verification']
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
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_common_proof_select_suite']
    >;
    verificationIngressBegin: NonNullable<
        TranscriptCoreKernelExports['sealed_lattice_galois_key_share_verification_ingress_begin']
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
            'The Galois key-share kernel session failed internally.',
        unknownStatusMessage:
            'The Galois key-share kernel returned an unknown status code.',
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

const requireNonEmptyOwnedBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');

const fixedHashBytesFromHex = (value: string): Uint8Array<ArrayBuffer> => {
    if (!/^[0-9a-f]{128}$/u.test(value)) {
        throw new CanonicalStreamRefusalError('malformedEncoding');
    }
    const bytes = new Uint8Array(hashByteLength);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const requireGaloisKeyShareKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): GaloisKeyShareKernel => {
    const wasmExports = context.wasmExports;
    const requiredExports = {
        commitGeneratedSource:
            wasmExports.sealed_lattice_galois_key_share_commit_generated_source,
        componentAbsorbChunk:
            wasmExports.sealed_lattice_galois_key_share_component_absorb_chunk,
        componentBegin:
            wasmExports.sealed_lattice_galois_key_share_component_begin,
        componentFinish:
            wasmExports.sealed_lattice_galois_key_share_component_finish,
        componentReadbackCancel:
            wasmExports.sealed_lattice_galois_key_share_component_readback_cancel,
        componentReadbackComponentCount:
            wasmExports.sealed_lattice_galois_key_share_component_readback_component_count,
        componentReadbackCopyDescriptor:
            wasmExports.sealed_lattice_galois_key_share_component_readback_copy_descriptor,
        componentReadbackCopyMaterialRoot:
            wasmExports.sealed_lattice_galois_key_share_component_readback_copy_material_root,
        componentReadbackDescriptorByteLength:
            wasmExports.sealed_lattice_galois_key_share_component_readback_descriptor_byte_length,
        componentReadbackFinish:
            wasmExports.sealed_lattice_galois_key_share_component_readback_finish,
        componentReadbackOpen:
            wasmExports.sealed_lattice_galois_key_share_component_readback_open,
        componentReadbackReadChunk:
            wasmExports.sealed_lattice_galois_key_share_component_readback_read_chunk,
        componentReadbackTotalByteLength:
            wasmExports.sealed_lattice_galois_key_share_component_readback_total_byte_length,
        discardGenerationSource:
            wasmExports.sealed_lattice_galois_key_share_discard_generation_source,
        discardVerificationIngress:
            wasmExports.sealed_lattice_galois_key_share_discard_verification_ingress,
        discardVerificationTerminalSource:
            wasmExports.sealed_lattice_galois_key_share_discard_verification_terminal_source,
        finishVerification:
            wasmExports.sealed_lattice_galois_key_share_finish_verification,
        prepareGeneration:
            wasmExports.sealed_lattice_galois_key_share_prepare_generation,
        prepareResumedGeneration:
            wasmExports.sealed_lattice_galois_key_share_prepare_resumed_generation,
        prepareVerification:
            wasmExports.sealed_lattice_galois_key_share_prepare_verification,
        releaseSelectedSuite:
            wasmExports.sealed_lattice_common_proof_release_suite,
        selectSuite: wasmExports.sealed_lattice_common_proof_select_suite,
        verificationIngressBegin:
            wasmExports.sealed_lattice_galois_key_share_verification_ingress_begin,
    };
    if (
        Object.values(requiredExports).some(
            (requiredExport) => typeof requiredExport !== 'function',
        )
    ) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the Galois key-share boundary.',
        );
    }
    return Object.freeze(requiredExports as GaloisKeyShareKernel);
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive('Galois selected-suite acquisition', () => {
        const suiteBytes = requireNonEmptyOwnedBytes(
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

const requireMatchingReturnedStatus = (
    returnedStatus: number,
    writtenStatus: number,
    label: string,
): void => {
    if ((returnedStatus >>> 0) !== (writtenStatus >>> 0)) {
        throw new CanonicalStreamInternalError(
            `${label} returned inconsistent status values.`,
        );
    }
};

const requireDecodedComponentDescriptor = (input: {
    canonicalDescriptorBytes: Uint8Array<ArrayBuffer>;
    kernel: TranscriptCoreKernel;
    totalByteLength: number;
}): Readonly<{
    chunkCount: number;
    fullObjectDigest: Uint8Array<ArrayBuffer>;
}> => {
    const decoded = input.kernel.decodeStreamDescriptor({
        canonicalBytesHex: bytesToHex(input.canonicalDescriptorBytes),
    }).value;
    let decodedTotalByteLength: bigint;
    try {
        decodedTotalByteLength = BigInt(decoded.totalByteLength);
    } catch {
        throw new CanonicalStreamRefusalError('malformedEncoding');
    }
    if (decodedTotalByteLength !== BigInt(input.totalByteLength)) {
        throw new CanonicalStreamRefusalError('wrongHashOrRoot');
    }
    const chunkCount = Math.ceil(
        input.totalByteLength / foundationProfile.streamChunkByteLength,
    );
    if (decoded.orderedChunkDigests.length !== chunkCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return Object.freeze({
        chunkCount,
        fullObjectDigest: fixedHashBytesFromHex(decoded.fullObjectDigest),
    });
};

const createComponentExactRangeReader = (input: {
    outputStore: CommonProofCanonicalOutputStore;
    totalByteLength: number;
}): Readonly<{
    readExactRange(
        sourceByteOffset: bigint,
        exactByteLength: number,
    ): Promise<Uint8Array<ArrayBuffer>>;
    release(): void;
}> => {
    let live = true;
    return Object.freeze({
        readExactRange: async (
            sourceByteOffset,
            exactByteLength,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            if (!live) {
                throw new CanonicalStreamRefusalError('consumedState');
            }
            if (
                sourceByteOffset < 0n ||
                !Number.isSafeInteger(exactByteLength) ||
                exactByteLength <= 0 ||
                exactByteLength >
                    foundationProfile.maximumCopiedBufferByteLength ||
                sourceByteOffset + BigInt(exactByteLength) >
                    BigInt(input.totalByteLength)
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            const sourceByteOffsetNumber = Number(sourceByteOffset);
            if (!Number.isSafeInteger(sourceByteOffsetNumber)) {
                throw new CanonicalStreamRefusalError(
                    'outsideSupportedProfile',
                );
            }
            const output = new Uint8Array(exactByteLength);
            let remainingByteLength = exactByteLength;
            let nextSourceByteOffset = sourceByteOffsetNumber;
            let outputByteOffset = 0;
            while (remainingByteLength > 0) {
                const chunkIndex = Math.floor(
                    nextSourceByteOffset /
                        foundationProfile.streamChunkByteLength,
                );
                const chunkSourceByteOffset =
                    chunkIndex * foundationProfile.streamChunkByteLength;
                const chunkByteLength = Math.min(
                    foundationProfile.streamChunkByteLength,
                    input.totalByteLength - chunkSourceByteOffset,
                );
                const chunkOffset =
                    nextSourceByteOffset - chunkSourceByteOffset;
                const copiedByteLength = Math.min(
                    remainingByteLength,
                    chunkByteLength - chunkOffset,
                );
                const returnedBytes = await input.outputStore.readChunk(
                    chunkIndex,
                    chunkByteLength,
                );
                try {
                    if (
                        !isUint8Array(returnedBytes) ||
                        !(returnedBytes.buffer instanceof ArrayBuffer) ||
                        returnedBytes.byteLength !== chunkByteLength
                    ) {
                        throw new CanonicalStreamRefusalError(
                            'wrongTypeOrLength',
                        );
                    }
                    output.set(
                        returnedBytes.subarray(
                            chunkOffset,
                            chunkOffset + copiedByteLength,
                        ),
                        outputByteOffset,
                    );
                } finally {
                    if (isUint8Array(returnedBytes)) {
                        returnedBytes.fill(0);
                    }
                }
                nextSourceByteOffset += copiedByteLength;
                outputByteOffset += copiedByteLength;
                remainingByteLength -= copiedByteLength;
            }
            return output;
        },
        release: (): void => {
            live = false;
        },
    });
};

const copyGeneratedComponentsToStores = async (input: {
    componentOutputStores: GaloisKeyShareComponentOutputStoreResolver;
    context: TranscriptCoreKernelCommandRuntime;
    generationSourceHandle: number;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    publicKernel: TranscriptCoreKernel;
    signal: AbortSignal | undefined;
    statusBoundary: WasmStatusBoundary;
}): Promise<Readonly<{
    backings: readonly AcceptedSetupEvaluatorComponentBacking[];
    transports: readonly GeneratedGaloisKeyShareComponentTransport[];
}>> => {
    let readbackHandle = 0;
    const backings: AcceptedSetupEvaluatorComponentBacking[] = [];
    const transports: GeneratedGaloisKeyShareComponentTransport[] = [];
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        readbackHandle = input.context.runExclusive(
            'Galois component readback begin',
            () => {
                const statusPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = input.kernel.componentReadbackOpen(
                        input.generationSourceHandle,
                        statusPointer,
                    );
                    const [status] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The Galois component readback handle',
                    );
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        const componentCount = input.context.runExclusive(
            'Galois component readback count',
            () => {
                const statusPointer =
                    input.memoryBoundary.allocateZeroedWords(1);
                try {
                    const count =
                        input.kernel.componentReadbackComponentCount(
                            readbackHandle,
                            statusPointer,
                        );
                    const [status] = input.memoryBoundary.readWords(
                        statusPointer,
                        1,
                    );
                    input.statusBoundary.throwIfError(status);
                    return count;
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        if (componentCount !== selectedGaloisComponentCount) {
            throw new CanonicalStreamInternalError(
                'The selected Galois batch returned an unexpected component count.',
            );
        }
        for (
            let componentOrdinal = 0;
            componentOrdinal < componentCount;
            componentOrdinal += 1
        ) {
            throwIfAborted(input.signal);
            const componentMetadata = input.context.runExclusive(
                'Galois component readback metadata',
                () => {
                    const statusPointer =
                        input.memoryBoundary.allocateZeroedWords(1);
                    let descriptorByteLength = 0;
                    let descriptorPointer = 0;
                    let materialRootPointer = 0;
                    try {
                        descriptorByteLength =
                            input.kernel.componentReadbackDescriptorByteLength(
                                readbackHandle,
                                componentOrdinal,
                                statusPointer,
                            );
                        let [status] = input.memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        input.statusBoundary.throwIfError(status);
                        if (
                            !Number.isSafeInteger(descriptorByteLength) ||
                            descriptorByteLength <= 0 ||
                            descriptorByteLength >
                                foundationProfile.maximumCopiedBufferByteLength
                        ) {
                            throw new CanonicalStreamInternalError(
                                'The Galois component descriptor has an invalid byte length.',
                            );
                        }
                        descriptorPointer =
                            input.memoryBoundary.allocate(descriptorByteLength);
                        const descriptorStatus =
                            input.kernel.componentReadbackCopyDescriptor(
                                readbackHandle,
                                componentOrdinal,
                                descriptorPointer,
                                descriptorByteLength,
                                statusPointer,
                            );
                        [status] = input.memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        requireMatchingReturnedStatus(
                            descriptorStatus,
                            status,
                            'The Galois component descriptor copy',
                        );
                        input.statusBoundary.throwIfError(status);
                        const canonicalDescriptorBytes = new Uint8Array(
                            input.context.memory.buffer,
                            descriptorPointer,
                            descriptorByteLength,
                        ).slice();

                        materialRootPointer =
                            input.memoryBoundary.allocate(hashByteLength);
                        const rootStatus =
                            input.kernel.componentReadbackCopyMaterialRoot(
                                readbackHandle,
                                componentOrdinal,
                                materialRootPointer,
                                hashByteLength,
                            );
                        input.statusBoundary.throwIfError(rootStatus);
                        const materialRoot = new Uint8Array(
                            input.context.memory.buffer,
                            materialRootPointer,
                            hashByteLength,
                        ).slice();

                        const totalByteLengthValue =
                            input.kernel.componentReadbackTotalByteLength(
                                readbackHandle,
                                componentOrdinal,
                                statusPointer,
                            );
                        [status] = input.memoryBoundary.readWords(
                            statusPointer,
                            1,
                        );
                        input.statusBoundary.throwIfError(status);
                        if (
                            totalByteLengthValue <= 0n ||
                            totalByteLengthValue >
                                BigInt(
                                    foundationProfile.maximumCanonicalStreamByteLength,
                                )
                        ) {
                            throw new CanonicalStreamResourceError(
                                'The Galois component exceeds the absolute canonical-stream bound.',
                            );
                        }
                        return Object.freeze({
                            canonicalDescriptorBytes,
                            materialRoot,
                            totalByteLength: Number(totalByteLengthValue),
                        });
                    } finally {
                        if (materialRootPointer !== 0) {
                            input.memoryBoundary.zeroAndDeallocate(
                                materialRootPointer,
                                hashByteLength,
                            );
                        }
                        if (descriptorPointer !== 0) {
                            input.memoryBoundary.zeroAndDeallocate(
                                descriptorPointer,
                                descriptorByteLength,
                            );
                        }
                        input.memoryBoundary.zeroAndDeallocate(
                            statusPointer,
                            wasm32WordByteLength,
                        );
                    }
                },
            );
            let componentAdopted = false;
            try {
                const decodedDescriptor = requireDecodedComponentDescriptor({
                    canonicalDescriptorBytes:
                        componentMetadata.canonicalDescriptorBytes,
                    kernel: input.publicKernel,
                    totalByteLength: componentMetadata.totalByteLength,
                });
                try {
                    const outputStore =
                        await input.componentOutputStores.resolveOutputStore({
                            canonicalDescriptorBytes:
                                componentMetadata.canonicalDescriptorBytes.slice(),
                            componentOrdinal,
                            materialRoot: componentMetadata.materialRoot.slice(),
                            totalByteLength: componentMetadata.totalByteLength,
                        });
                    if (
                        typeof outputStore?.commitChunk !== 'function' ||
                        typeof outputStore.readChunk !== 'function'
                    ) {
                        throw new CanonicalStreamInternalError(
                            'The Galois component output-store resolver returned an invalid store.',
                        );
                    }
                    for (
                        let chunkIndex = 0;
                        chunkIndex < decodedDescriptor.chunkCount;
                        chunkIndex += 1
                    ) {
                        throwIfAborted(input.signal);
                        const consumedByteLength =
                            chunkIndex *
                            foundationProfile.streamChunkByteLength;
                        const chunkByteLength = Math.min(
                            foundationProfile.streamChunkByteLength,
                            componentMetadata.totalByteLength -
                                consumedByteLength,
                        );
                        const chunkBytes = input.context.runExclusive(
                            'Galois component readback chunk',
                            () => {
                                const outputPointer =
                                    input.memoryBoundary.allocate(
                                        chunkByteLength,
                                    );
                                const statusPointer =
                                    input.memoryBoundary.allocateZeroedWords(1);
                                try {
                                    const returnedStatus =
                                        input.kernel.componentReadbackReadChunk(
                                            readbackHandle,
                                            componentOrdinal,
                                            chunkIndex,
                                            outputPointer,
                                            chunkByteLength,
                                            statusPointer,
                                        );
                                    const [status] =
                                        input.memoryBoundary.readWords(
                                            statusPointer,
                                            1,
                                        );
                                    requireMatchingReturnedStatus(
                                        returnedStatus,
                                        status,
                                        'The Galois component chunk readback',
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
                            await outputStore.commitChunk(
                                chunkIndex,
                                chunkBytes,
                            );
                            const storedBytes = await outputStore.readChunk(
                                chunkIndex,
                                chunkByteLength,
                            );
                            try {
                                if (
                                    !isUint8Array(storedBytes) ||
                                    !(
                                        storedBytes.buffer instanceof
                                        ArrayBuffer
                                    ) ||
                                    storedBytes.byteLength !==
                                        chunkByteLength ||
                                    !byteArraysEqual(storedBytes, chunkBytes)
                                ) {
                                    throw new CanonicalStreamRefusalError(
                                        'wrongHashOrRoot',
                                    );
                                }
                            } finally {
                                if (isUint8Array(storedBytes)) {
                                    storedBytes.fill(0);
                                }
                            }
                        } finally {
                            chunkBytes.fill(0);
                        }
                    }
                    const rangeReader = createComponentExactRangeReader({
                        outputStore,
                        totalByteLength: componentMetadata.totalByteLength,
                    });
                    try {
                        const backing =
                            createAcceptedSetupEvaluatorComponentBacking({
                                authenticatedByteLength: BigInt(
                                    componentMetadata.totalByteLength,
                                ),
                                fullObjectDigest:
                                    decodedDescriptor.fullObjectDigest,
                                kernel: input.publicKernel,
                                materialRoot: componentMetadata.materialRoot,
                                readExactRange: rangeReader.readExactRange,
                                release: rangeReader.release,
                            });
                        backings.push(backing);
                        transports.push(
                            Object.freeze({
                                canonicalDescriptorBytes:
                                    componentMetadata.canonicalDescriptorBytes,
                                materialRoot: componentMetadata.materialRoot,
                            }),
                        );
                        componentAdopted = true;
                    } catch (error) {
                        rangeReader.release();
                        throw error;
                    }
                } finally {
                    decodedDescriptor.fullObjectDigest.fill(0);
                }
            } finally {
                if (!componentAdopted) {
                    componentMetadata.canonicalDescriptorBytes.fill(0);
                    componentMetadata.materialRoot.fill(0);
                }
            }
        }
        const finishStatus = input.context.runExclusive(
            'Galois component readback finish',
            () =>
                input.kernel.componentReadbackFinish(
                    input.generationSourceHandle,
                    readbackHandle,
                ),
        );
        input.statusBoundary.throwIfError(finishStatus);
        readbackHandle = 0;
        return Object.freeze({
            backings: Object.freeze(backings),
            transports: Object.freeze(transports),
        });
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (readbackHandle !== 0) {
        try {
            discardHandle({
                context: input.context,
                discard: (handle) =>
                    input.kernel.componentReadbackCancel(
                        input.generationSourceHandle,
                        handle,
                    ),
                handle: readbackHandle,
                operationName: 'Galois component readback cancellation',
                statusBoundary: input.statusBoundary,
            });
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
    for (const transport of transports) {
        transport.canonicalDescriptorBytes.fill(0);
        transport.materialRoot.fill(0);
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Galois component readback failed to retire all worker-owned custody.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    throw new CanonicalStreamInternalError(
        'Galois component readback ended without a transport or a failure.',
    );
};

/**
 * Generates one suite-fixed Galois batch, persists every canonical public
 * component, and atomically transfers the proof source into the exact
 * evaluator catalog.
 */
export const generateGaloisKeyShareInClosedWorker = async (input: {
    actionRandomnessSession: ActionRandomnessSession;
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    componentOutputStores: GaloisKeyShareComponentOutputStoreResolver;
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    externalMemory: CommonProofExternalMemoryTransactionExecutor;
    generationMode: GaloisKeyShareGenerationMode;
    kernel: TranscriptCoreKernel;
    options?: CommonProofGenerationWorkerOptions;
    outputStore: CommonProofCanonicalOutputStore;
    setupGenerationAuthority: BrowserOwnedSetupGenerationAuthority;
    setupIntentObject: VerifiedTranscriptObject;
    verifiedReservation: VerifiedStateReservation;
}): Promise<GeneratedGaloisKeyShareTransport> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Galois proof generation may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireGaloisKeyShareKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'Galois generation boundary',
    });
    if (
        (input.generationMode !== 'fresh' &&
            input.generationMode !== 'resumed') ||
        (input.generationMode === 'resumed') !==
            (input.options?.resume !== undefined)
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
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
    const catalogOwner =
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            input.evaluatorSourceCatalog,
            input.kernel,
            'collecting',
        );
    if (
        actionRandomnessAuthorization.context.memory !== context.memory ||
        stateAuthorization.capabilityMemory !== context.memory ||
        setupIntentAuthorization.capabilityPointer <= 0
    ) {
        throw new CanonicalStreamInternalError(
            'The Galois generation authorities do not belong to one WASM worker.',
        );
    }
    const checkpointLineageIdentifier = requireFixedOwnedBytes(
        input.checkpointLineageIdentifier,
        checkpointLineageIdentifierByteLength,
    );

    let selectedSuiteHandle = 0;
    let generationSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let componentResult:
        | Readonly<{
              backings: readonly AcceptedSetupEvaluatorComponentBacking[];
              transports: readonly GeneratedGaloisKeyShareComponentTransport[];
          }>
        | undefined;
    let proofDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let result: GeneratedGaloisKeyShareTransport | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        const prepared = context.runExclusive(
            'Galois generation preparation',
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
                            'The Galois generation family-adapter handle',
                        ),
                        sourceHandle: requireLiveHandle(
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
        generationSourceHandle = prepared.sourceHandle;
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
            proofFamilyLabel: 'Galois key-share',
            streamDomain: canonicalStreamDomains.galoisShareProof,
        });
        componentResult = await copyGeneratedComponentsToStores({
            componentOutputStores: input.componentOutputStores,
            context,
            generationSourceHandle,
            kernel,
            memoryBoundary,
            publicKernel: input.kernel,
            signal: input.options?.signal,
            statusBoundary,
        });
        requireAcceptedSetupEvaluatorComponentBackingsRetainable({
            backings: componentResult.backings,
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
                            catalogOwner.handle,
                            generatedCommonProofHandle,
                            generationSourceHandle,
                        ),
                );
                return Object.freeze({ consumed: status === 0, result: status });
            },
        );
        statusBoundary.throwIfError(commitStatus);
        generatedCapability = undefined;
        generationSourceHandle = 0;
        retainAcceptedSetupEvaluatorComponentBackings({
            backings: componentResult.backings,
            catalog: input.evaluatorSourceCatalog,
            kernel: input.kernel,
        });
        result = Object.freeze({
            orderedComponents: componentResult.transports,
            proofDescriptorBytes,
        });
        componentResult = undefined;
        proofDescriptorBytes = undefined;
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    } finally {
        checkpointLineageIdentifier.fill(0);
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                operationName: 'Galois selected-suite failure release',
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
                operationName: 'Galois generation source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (componentResult !== undefined) {
        try {
            releaseUnretainedAcceptedSetupEvaluatorComponentBackings(
                componentResult.backings,
                input.kernel,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
        for (const transport of componentResult.transports) {
            transport.canonicalDescriptorBytes.fill(0);
            transport.materialRoot.fill(0);
        }
    }
    proofDescriptorBytes?.fill(0);
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Galois generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'Galois generation completed without a catalog-bound transport.',
        );
    }
    return result;
};

const requireRosterPosition = (value: number): number => {
    if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value >= foundationProfile.participantCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value;
};

const absorbVerifiedComponent = async (input: {
    catalog: AcceptedSetupEvaluatorSourceCatalogSession;
    component: GeneratedGaloisKeyShareComponentTransport;
    componentOrdinal: number;
    context: TranscriptCoreKernelCommandRuntime;
    ingressHandle: number;
    kernel: GaloisKeyShareKernel;
    memoryBoundary: WasmMemoryBoundary;
    publicKernel: TranscriptCoreKernel;
    signal: AbortSignal | undefined;
    statusBoundary: WasmStatusBoundary;
}): Promise<void> => {
    const canonicalDescriptorBytes = requireNonEmptyOwnedBytes(
        input.component.canonicalDescriptorBytes,
    );
    const materialRoot = requireFixedOwnedBytes(
        input.component.materialRoot,
        hashByteLength,
    );
    let fullObjectDigest: Uint8Array<ArrayBuffer> | undefined;
    try {
        const decoded = input.publicKernel.decodeStreamDescriptor({
            canonicalBytesHex: bytesToHex(canonicalDescriptorBytes),
        }).value;
        let totalByteLengthValue: bigint;
        try {
            totalByteLengthValue = BigInt(decoded.totalByteLength);
        } catch {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
        if (
            totalByteLengthValue <= 0n ||
            totalByteLengthValue >
                BigInt(foundationProfile.maximumCanonicalStreamByteLength)
        ) {
            throw new CanonicalStreamResourceError(
                'The Galois component exceeds the absolute canonical-stream bound.',
            );
        }
        const totalByteLength = Number(totalByteLengthValue);
        const chunkCount = Math.ceil(
            totalByteLength / foundationProfile.streamChunkByteLength,
        );
        if (decoded.orderedChunkDigests.length !== chunkCount) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const authenticatedFullObjectDigest = fixedHashBytesFromHex(
            decoded.fullObjectDigest,
        );
        fullObjectDigest = authenticatedFullObjectDigest;
        const beginStatus = input.context.runExclusive(
            'Galois component verification begin',
            () => {
                const descriptorPointer = input.memoryBoundary.copy(
                    canonicalDescriptorBytes,
                );
                try {
                    return input.kernel.componentBegin(
                        input.ingressHandle,
                        input.componentOrdinal,
                        descriptorPointer,
                        canonicalDescriptorBytes.byteLength,
                    );
                } finally {
                    input.memoryBoundary.zeroAndDeallocate(
                        descriptorPointer,
                        canonicalDescriptorBytes.byteLength,
                    );
                }
            },
        );
        input.statusBoundary.throwIfError(beginStatus);
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            throwIfAborted(input.signal);
            const sourceByteOffset =
                chunkIndex * foundationProfile.streamChunkByteLength;
            const chunkByteLength = Math.min(
                foundationProfile.streamChunkByteLength,
                totalByteLength - sourceByteOffset,
            );
            const returnedBytes =
                await readAcceptedSetupPrepackageEvaluatorComponentExactRange({
                    authenticatedByteLength: totalByteLengthValue,
                    catalog: input.catalog,
                    exactByteLength: chunkByteLength,
                    fullObjectDigest: authenticatedFullObjectDigest,
                    kernel: input.publicKernel,
                    materialRoot,
                    sourceByteOffset: BigInt(sourceByteOffset),
                });
            try {
                if (
                    !isUint8Array(returnedBytes) ||
                    !(returnedBytes.buffer instanceof ArrayBuffer) ||
                    returnedBytes.byteLength !== chunkByteLength
                ) {
                    throw new CanonicalStreamRefusalError(
                        'wrongTypeOrLength',
                    );
                }
                const absorbStatus = input.context.runExclusive(
                    'Galois component verification chunk',
                    () => {
                        const chunkPointer =
                            input.memoryBoundary.copy(returnedBytes);
                        try {
                            return input.kernel.componentAbsorbChunk(
                                input.ingressHandle,
                                input.componentOrdinal,
                                chunkIndex,
                                chunkPointer,
                                returnedBytes.byteLength,
                            );
                        } finally {
                            input.memoryBoundary.zeroAndDeallocate(
                                chunkPointer,
                                returnedBytes.byteLength,
                            );
                        }
                    },
                );
                input.statusBoundary.throwIfError(absorbStatus);
            } finally {
                if (isUint8Array(returnedBytes)) {
                    returnedBytes.fill(0);
                }
            }
        }
        const finishStatus = input.context.runExclusive(
            'Galois component verification finish',
            () =>
                input.kernel.componentFinish(
                    input.ingressHandle,
                    input.componentOrdinal,
                ),
        );
        input.statusBoundary.throwIfError(finishStatus);
    } finally {
        canonicalDescriptorBytes.fill(0);
        materialRoot.fill(0);
        fullObjectDigest?.fill(0);
    }
};

/**
 * Verifies one package-bound Galois proof and commits only its positive family
 * terminal into the exact evaluator catalog.
 */
export const verifyGaloisKeyShareInClosedWorker = async (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
    orderedComponents: readonly GeneratedGaloisKeyShareComponentTransport[];
    proofInputStore: AuthenticatedCommonProofInputStore;
    rosterPosition: number;
}): Promise<void> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Galois proof verification may only run inside the dedicated WASM worker.',
        );
    }
    if (input.orderedComponents.length !== selectedGaloisComponentCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const rosterPosition = requireRosterPosition(input.rosterPosition);
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireGaloisKeyShareKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'Galois verification boundary',
    });
    const catalogOwner =
        requireAcceptedSetupEvaluatorSourceCatalogKernelOwner(
            input.evaluatorSourceCatalog,
            input.kernel,
            'collecting',
        );

    let selectedSuiteHandle = 0;
    let ingressHandle = 0;
    let terminalSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        ingressHandle = context.runExclusive(
            'Galois verification ingress begin',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = kernel.verificationIngressBegin(
                        selectedSuiteHandle,
                        catalogOwner.handle,
                        rosterPosition,
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
            componentOrdinal < input.orderedComponents.length;
            componentOrdinal += 1
        ) {
            await absorbVerifiedComponent({
                catalog: input.evaluatorSourceCatalog,
                component: input.orderedComponents[componentOrdinal]!,
                componentOrdinal,
                context,
                ingressHandle,
                kernel,
                memoryBoundary,
                publicKernel: input.kernel,
                signal: input.options?.signal,
                statusBoundary,
            });
        }
        const prepared = context.runExclusive(
            'Galois verification preparation',
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
                input.proofInputStore,
                input.options,
            );
        const finishStatus = (() => {
            try {
                return applyClosedWorkerVerifiedCommonProofCapability(
                    verifiedCommonProof,
                    context,
                    (verifiedCommonProofHandle) => {
                        const status = context.runExclusive(
                            'Galois verification terminal commit',
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
        })();
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
                    'Galois verification selected-suite failure release',
                statusBoundary,
            });
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
                    'Galois verification terminal-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Galois verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
};

/** Binds the complete generated evaluator-proof set to one canonical package. */
export const bindGeneratedEvaluatorSourceProofsToAcceptedSetupPackage = (
    input: {
        acceptedSetupVerification: AcceptedSetupVerificationSession;
        evaluatorSourceCatalog: AcceptedSetupEvaluatorSourceCatalogSession;
        kernel: TranscriptCoreKernel;
    },
): void =>
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage({
        acceptedSetupVerification: input.acceptedSetupVerification,
        catalog: input.evaluatorSourceCatalog,
        kernel: input.kernel,
    });
