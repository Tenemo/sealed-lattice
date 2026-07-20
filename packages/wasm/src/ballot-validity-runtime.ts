import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import {
    requireVerifiedAcceptedSetupAuthorityKernelOwner,
    type VerifiedAcceptedSetupAuthority,
} from './accepted-setup-verification-runtime.js';
import {
    resolveActionRandomnessKernelAuthorization,
    type ActionRandomnessSession,
} from './action-randomness-runtime.js';
import { byteArraysEqual, isUint8Array } from './byte-array.js';
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
    type CommonProofCanonicalOutputStore,
    type CommonProofGenerationExecutionOpener,
    type CommonProofVerificationWorkerOptions,
} from './common-proof-worker-runtime/runtime.js';
import { deriveGeneratedCommonProofDescriptor } from './generated-common-proof-output-runtime.js';
import { resolveCommonProofKernelContext } from './transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import { bytesToHex } from './transcript-core-bridge/kernel-wasm-hash.js';
import { resolveOrderedVerifiedBoardObjectAuthorization } from './vss-share-linkage-verification-runtime.js';
import { WasmMemoryBoundary } from './wasm-memory-boundary.js';
import { WasmStatusBoundary } from './wasm-status-boundary.js';

const maximumWasm32UnsignedInteger = 0xffff_ffff;
const wasm32WordByteLength = Uint32Array.BYTES_PER_ELEMENT;
const fixedAttemptIdentifierByteLength = 32;
const boardVerifierCapabilityByteLength = 32;
const ballotScoreByteLength = BigUint64Array.BYTES_PER_ELEMENT;

export type BallotValidityGenerationMode = 'fresh' | 'resumed';

type BallotValidityKernel = Readonly<{
    absorbCiphertextChunk: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_absorb_ciphertext_chunk']
    >;
    beginVerification: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_begin_verification']
    >;
    bindGeneratedProofToBoard: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_bind_generated_proof_to_board']
    >;
    ciphertextDescriptorByteLength: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_ciphertext_descriptor_byte_length']
    >;
    copyCiphertextDescriptor: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_copy_ciphertext_descriptor']
    >;
    discardCiphertextReadback: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_discard_ciphertext_readback']
    >;
    discardVerificationPreparation: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_discard_verification_preparation']
    >;
    discardVerificationTerminalSource: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_discard_verification_terminal_source']
    >;
    discardVerifiedOutput: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_discard_verified_output']
    >;
    finishCiphertextReadback: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_finish_ciphertext_readback']
    >;
    finishVerification: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_finish_verification']
    >;
    finishVerificationPreparation: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_finish_verification_preparation']
    >;
    prepareGeneration: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_prepare_generation']
    >;
    prepareResumedGeneration: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_prepare_resumed_generation']
    >;
    readCiphertextChunk: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_ballot_validity_read_ciphertext_chunk']
    >;
    releaseSelectedSuite: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_common_proof_release_suite']
    >;
    selectSuite: NonNullable<
        TranscriptCoreKernelCommandRuntime['wasmExports']['sealed_lattice_common_proof_select_suite']
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
            'The ballot-validity kernel session failed internally.',
        unknownStatusMessage:
            'The ballot-validity kernel returned an unknown status code.',
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

const requireBallotValidityKernel = (
    context: TranscriptCoreKernelCommandRuntime,
): BallotValidityKernel => {
    const {
        sealed_lattice_ballot_validity_absorb_ciphertext_chunk:
            absorbCiphertextChunk,
        sealed_lattice_ballot_validity_begin_verification: beginVerification,
        sealed_lattice_ballot_validity_bind_generated_proof_to_board:
            bindGeneratedProofToBoard,
        sealed_lattice_ballot_validity_ciphertext_descriptor_byte_length:
            ciphertextDescriptorByteLength,
        sealed_lattice_ballot_validity_copy_ciphertext_descriptor:
            copyCiphertextDescriptor,
        sealed_lattice_ballot_validity_discard_ciphertext_readback:
            discardCiphertextReadback,
        sealed_lattice_ballot_validity_discard_verification_preparation:
            discardVerificationPreparation,
        sealed_lattice_ballot_validity_discard_verification_terminal_source:
            discardVerificationTerminalSource,
        sealed_lattice_ballot_validity_discard_verified_output:
            discardVerifiedOutput,
        sealed_lattice_ballot_validity_finish_ciphertext_readback:
            finishCiphertextReadback,
        sealed_lattice_ballot_validity_finish_verification: finishVerification,
        sealed_lattice_ballot_validity_finish_verification_preparation:
            finishVerificationPreparation,
        sealed_lattice_ballot_validity_prepare_generation: prepareGeneration,
        sealed_lattice_ballot_validity_prepare_resumed_generation:
            prepareResumedGeneration,
        sealed_lattice_ballot_validity_read_ciphertext_chunk:
            readCiphertextChunk,
        sealed_lattice_common_proof_release_suite: releaseSelectedSuite,
        sealed_lattice_common_proof_select_suite: selectSuite,
    } = context.wasmExports;
    const functions = [
        absorbCiphertextChunk,
        beginVerification,
        bindGeneratedProofToBoard,
        ciphertextDescriptorByteLength,
        copyCiphertextDescriptor,
        discardCiphertextReadback,
        discardVerificationPreparation,
        discardVerificationTerminalSource,
        discardVerifiedOutput,
        finishCiphertextReadback,
        finishVerification,
        finishVerificationPreparation,
        prepareGeneration,
        prepareResumedGeneration,
        readCiphertextChunk,
        releaseSelectedSuite,
        selectSuite,
    ];
    if (functions.some((value) => typeof value !== 'function')) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel lacks the ballot-validity boundary.',
        );
    }
    return Object.freeze({
        absorbCiphertextChunk,
        beginVerification,
        bindGeneratedProofToBoard,
        ciphertextDescriptorByteLength,
        copyCiphertextDescriptor,
        discardCiphertextReadback,
        discardVerificationPreparation,
        discardVerificationTerminalSource,
        discardVerifiedOutput,
        finishCiphertextReadback,
        finishVerification,
        finishVerificationPreparation,
        prepareGeneration,
        prepareResumedGeneration,
        readCiphertextChunk,
        releaseSelectedSuite,
        selectSuite,
    } as BallotValidityKernel);
};

const requireFixedBytes = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const owned = value.slice();
    if (owned.byteLength !== expectedByteLength) {
        throw new CanonicalStreamInternalError(`${label} could not be copied.`);
    }
    return owned;
};

const requireCanonicalSuiteRecordBytes = (
    value: Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (
        !isUint8Array(value) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteLength === 0
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    return value.slice();
};

const requireUnsigned64 = (value: bigint): bigint => {
    if (
        typeof value !== 'bigint' ||
        value < 0n ||
        value > 0xffff_ffff_ffff_ffffn
    ) {
        throw new CanonicalStreamRefusalError('outsideSupportedProfile');
    }
    return value;
};

const encodeBallotScores = (
    scores: readonly bigint[],
): Uint8Array<ArrayBuffer> => {
    if (scores.length !== foundationProfile.optionCount) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const encoded = new Uint8Array(scores.length * ballotScoreByteLength);
    const view = new DataView(encoded.buffer);
    scores.forEach((score, scoreIndex) => {
        view.setBigUint64(
            scoreIndex * ballotScoreByteLength,
            requireUnsigned64(score),
            true,
        );
    });
    return encoded;
};

const copyBallotGenerationSecrets = (input: {
    checkpointLineageIdentifier: Uint8Array;
    encryptionAttemptIdentifier: Uint8Array;
    proofAttemptNonce: Uint8Array;
    scores: readonly bigint[];
}): Readonly<{
    checkpointLineageIdentifier: Uint8Array<ArrayBuffer>;
    encryptionAttemptIdentifier: Uint8Array<ArrayBuffer>;
    proofAttemptNonce: Uint8Array<ArrayBuffer>;
    scoreBytes: Uint8Array<ArrayBuffer>;
}> => {
    let scoreBytes: Uint8Array<ArrayBuffer> | undefined;
    let encryptionAttemptIdentifier: Uint8Array<ArrayBuffer> | undefined;
    let proofAttemptNonce: Uint8Array<ArrayBuffer> | undefined;
    let checkpointLineageIdentifier: Uint8Array<ArrayBuffer> | undefined;
    try {
        scoreBytes = encodeBallotScores(input.scores);
        encryptionAttemptIdentifier = requireFixedBytes(
            input.encryptionAttemptIdentifier,
            fixedAttemptIdentifierByteLength,
            'The ballot encryption attempt identifier',
        );
        proofAttemptNonce = requireFixedBytes(
            input.proofAttemptNonce,
            fixedAttemptIdentifierByteLength,
            'The ballot proof attempt nonce',
        );
        checkpointLineageIdentifier = requireFixedBytes(
            input.checkpointLineageIdentifier,
            fixedAttemptIdentifierByteLength,
            'The ballot proof checkpoint lineage identifier',
        );
        return Object.freeze({
            checkpointLineageIdentifier,
            encryptionAttemptIdentifier,
            proofAttemptNonce,
            scoreBytes,
        });
    } catch (error) {
        scoreBytes?.fill(0);
        encryptionAttemptIdentifier?.fill(0);
        proofAttemptNonce?.fill(0);
        checkpointLineageIdentifier?.fill(0);
        throw error;
    }
};

const selectSuite = (input: {
    canonicalSuiteRecordBytes: Uint8Array;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: BallotValidityKernel;
    memoryBoundary: WasmMemoryBoundary;
    statusBoundary: WasmStatusBoundary;
}): number =>
    input.context.runExclusive(
        'ballot-validity selected-suite acquisition',
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
                    try {
                        input.statusBoundary.throwIfError(
                            input.kernel.releaseSelectedSuite(
                                selectedSuiteHandle,
                            ),
                        );
                    } catch (cleanupFailure) {
                        throw new CanonicalStreamInternalError(
                            'Ballot-validity suite acquisition failed and its returned handle could not be released.',
                            Object.freeze({ cleanupFailure, error }),
                        );
                    }
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
    kernel: BallotValidityKernel;
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
    readonly discard: (handle: number) => number;
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

const throwIfAborted = (signal: AbortSignal | undefined): void => {
    signal?.throwIfAborted();
};

const verifiedBallotOutputBrand: unique symbol = Symbol(
    'sealed-lattice/verified-ballot-output',
);

/** One positive ballot-validity output retained by the exact WASM worker. */
export type VerifiedBallotOutput = Readonly<{
    readonly [verifiedBallotOutputBrand]: true;
    release(): void;
}>;

type VerifiedBallotOutputRecord = {
    readonly handle: number;
    readonly kernel: TranscriptCoreKernel;
    readonly releaseKernelOutput: (handle: number) => void;
    readonly reservation: BallotOutputReservation;
    retired: boolean;
};

const verifiedBallotOutputRecords = new WeakMap<
    VerifiedBallotOutput,
    VerifiedBallotOutputRecord
>();

type BallotOutputReservation = Readonly<{ reservationIdentifier: symbol }>;
let activeBallotOutputReservation: BallotOutputReservation | undefined;

const reserveBallotOutputSlot = (): BallotOutputReservation => {
    if (activeBallotOutputReservation !== undefined) {
        throw new CanonicalStreamResourceError(
            'The browser worker already owns a ballot verification output or an active ballot verification.',
        );
    }
    const reservation = Object.freeze({ reservationIdentifier: Symbol() });
    activeBallotOutputReservation = reservation;
    return reservation;
};

const releaseBallotOutputReservation = (
    reservation: BallotOutputReservation,
): void => {
    if (activeBallotOutputReservation !== reservation) {
        throw new CanonicalStreamInternalError(
            'The ballot-output reservation is unavailable.',
        );
    }
    activeBallotOutputReservation = undefined;
};

export type VerifiedBallotOutputKernelAuthority = Readonly<{
    handle: number;
    kernel: TranscriptCoreKernel;
}>;

const requireLiveRecord = (
    output: VerifiedBallotOutput,
): VerifiedBallotOutputRecord => {
    if (
        (typeof output !== 'object' && typeof output !== 'function') ||
        output === null
    ) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    const record = verifiedBallotOutputRecords.get(output);
    if (record === undefined || record.retired) {
        throw new CanonicalStreamRefusalError('consumedState');
    }
    return record;
};

const mintVerifiedBallotOutputKernelAuthority = (
    input: {
        handle: number;
        kernel: TranscriptCoreKernel;
        readonly releaseKernelOutput: (handle: number) => void;
    },
    reservation: BallotOutputReservation,
): VerifiedBallotOutput => {
    if (activeBallotOutputReservation !== reservation) {
        throw new CanonicalStreamInternalError(
            'The verified ballot output lacks its browser-worker reservation.',
        );
    }
    const output: VerifiedBallotOutput = Object.freeze({
        [verifiedBallotOutputBrand]: true as const,
        release: (): void => {
            const record = requireLiveRecord(output);
            record.retired = true;
            verifiedBallotOutputRecords.delete(output);
            releaseBallotOutputReservation(record.reservation);
            record.releaseKernelOutput(record.handle);
        },
    });
    verifiedBallotOutputRecords.set(output, {
        handle: input.handle,
        kernel: input.kernel,
        releaseKernelOutput: input.releaseKernelOutput,
        reservation,
        retired: false,
    });
    return output;
};

/** Internal mint called only for the nonzero Rust verification output handle. */
export const createVerifiedBallotOutputKernelAuthority = (input: {
    handle: number;
    kernel: TranscriptCoreKernel;
    readonly releaseKernelOutput: (handle: number) => void;
}): VerifiedBallotOutput => {
    if (
        !Number.isSafeInteger(input.handle) ||
        input.handle <= 0 ||
        input.handle > maximumWasm32UnsignedInteger
    ) {
        throw new CanonicalStreamInternalError(
            'The WASM kernel returned an invalid verified ballot-output handle.',
        );
    }
    const reservation = reserveBallotOutputSlot();
    try {
        return mintVerifiedBallotOutputKernelAuthority(input, reservation);
    } catch (error) {
        releaseBallotOutputReservation(reservation);
        throw error;
    }
};

/** Borrow-only same-worker resolution for aggregation preflight. */
export const requireVerifiedBallotOutputKernelAuthority = (
    output: VerifiedBallotOutput,
    kernel: TranscriptCoreKernel,
): VerifiedBallotOutputKernelAuthority => {
    const record = requireLiveRecord(output);
    if (record.kernel !== kernel) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    return Object.freeze({ handle: record.handle, kernel: record.kernel });
};

/**
 * Retires browser custody after Rust reports successful aggregation. The
 * aggregation runtime must call this only after its borrowed preflight and
 * consume/commit FFI returns zero.
 */
export const markVerifiedBallotOutputConsumedAfterKernelSuccess = (
    output: VerifiedBallotOutput,
    kernel: TranscriptCoreKernel,
): void => {
    const record = requireLiveRecord(output);
    if (record.kernel !== kernel) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    record.retired = true;
    verifiedBallotOutputRecords.delete(output);
    releaseBallotOutputReservation(record.reservation);
};

export type GeneratedBallotValidityTransport = Readonly<{
    ballotPackageObject: VerifiedTranscriptObject;
    ciphertextByteLength: number;
    ciphertextChunkByteLengths: readonly number[];
    proofByteLength: number;
    proofChunkByteLengths: readonly number[];
}>;

const copyGeneratedCiphertextToStore = async (input: {
    ciphertextReadbackHandle: number;
    ciphertextStore: CommonProofCanonicalOutputStore;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: BallotValidityKernel;
    publicKernel: TranscriptCoreKernel;
    memoryBoundary: WasmMemoryBoundary;
    signal: AbortSignal | undefined;
    statusBoundary: WasmStatusBoundary;
}): Promise<
    Readonly<{
        ciphertextByteLength: number;
        ciphertextChunkByteLengths: readonly number[];
        ciphertextDescriptorBytes: Uint8Array<ArrayBuffer>;
    }>
> => {
    throwIfAborted(input.signal);
    const descriptorByteLength = input.context.runExclusive(
        'ballot ciphertext descriptor length',
        () => {
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            try {
                const byteLength = input.kernel.ciphertextDescriptorByteLength(
                    input.ciphertextReadbackHandle,
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
    );
    if (
        !Number.isSafeInteger(descriptorByteLength) ||
        descriptorByteLength <= 0
    ) {
        throw new CanonicalStreamInternalError(
            'The ballot ciphertext descriptor has an invalid byte length.',
        );
    }
    const ciphertextDescriptorBytes = input.context.runExclusive(
        'ballot ciphertext descriptor copy',
        () => {
            const outputPointer =
                input.memoryBoundary.allocate(descriptorByteLength);
            const statusPointer = input.memoryBoundary.allocateZeroedWords(1);
            try {
                input.kernel.copyCiphertextDescriptor(
                    input.ciphertextReadbackHandle,
                    outputPointer,
                    descriptorByteLength,
                    statusPointer,
                );
                const [status] = input.memoryBoundary.readWords(
                    statusPointer,
                    1,
                );
                input.statusBoundary.throwIfError(status);
                return new Uint8Array(
                    input.context.memory.buffer,
                    outputPointer,
                    descriptorByteLength,
                ).slice();
            } finally {
                input.memoryBoundary.zeroAndDeallocate(
                    statusPointer,
                    wasm32WordByteLength,
                );
                input.memoryBoundary.zeroAndDeallocate(
                    outputPointer,
                    descriptorByteLength,
                );
            }
        },
    );
    const decodedDescriptor = input.publicKernel.decodeStreamDescriptor({
        canonicalBytesHex: bytesToHex(ciphertextDescriptorBytes),
    }).value;
    let ciphertextByteLength: number;
    try {
        const parsedByteLength = BigInt(decodedDescriptor.totalByteLength);
        if (
            parsedByteLength <= 0n ||
            parsedByteLength > BigInt(Number.MAX_SAFE_INTEGER) ||
            parsedByteLength >
                BigInt(foundationProfile.maximumCanonicalStreamByteLength)
        ) {
            throw new Error('outside the browser profile');
        }
        ciphertextByteLength = Number(parsedByteLength);
    } catch {
        ciphertextDescriptorBytes.fill(0);
        throw new CanonicalStreamRefusalError('outsideSupportedProfile');
    }
    const ciphertextChunkByteLengths: number[] = [];
    const chunkCount = Math.ceil(
        ciphertextByteLength / foundationProfile.streamChunkByteLength,
    );
    if (decodedDescriptor.orderedChunkDigests.length !== chunkCount) {
        ciphertextDescriptorBytes.fill(0);
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    try {
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            throwIfAborted(input.signal);
            const chunkByteLength = Math.min(
                foundationProfile.streamChunkByteLength,
                ciphertextByteLength -
                    chunkIndex * foundationProfile.streamChunkByteLength,
            );
            const chunkBytes = input.context.runExclusive(
                'ballot ciphertext chunk readback',
                () => {
                    const outputPointer =
                        input.memoryBoundary.allocate(chunkByteLength);
                    const statusPointer =
                        input.memoryBoundary.allocateZeroedWords(1);
                    try {
                        input.kernel.readCiphertextChunk(
                            input.ciphertextReadbackHandle,
                            chunkIndex,
                            outputPointer,
                            chunkByteLength,
                            statusPointer,
                        );
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
                await input.ciphertextStore.commitChunk(chunkIndex, chunkBytes);
                throwIfAborted(input.signal);
                const storedBytes = await input.ciphertextStore.readChunk(
                    chunkIndex,
                    chunkByteLength,
                );
                try {
                    if (
                        !isUint8Array(storedBytes) ||
                        !(storedBytes.buffer instanceof ArrayBuffer) ||
                        storedBytes.byteLength !== chunkByteLength ||
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
                throwIfAborted(input.signal);
                ciphertextChunkByteLengths.push(chunkByteLength);
            } finally {
                chunkBytes.fill(0);
            }
        }
        const finishStatus = input.context.runExclusive(
            'ballot ciphertext readback finish',
            () =>
                input.kernel.finishCiphertextReadback(
                    input.ciphertextReadbackHandle,
                ),
        );
        input.statusBoundary.throwIfError(finishStatus);
        return Object.freeze({
            ciphertextByteLength,
            ciphertextChunkByteLengths: Object.freeze(
                ciphertextChunkByteLengths,
            ),
            ciphertextDescriptorBytes,
        });
    } catch (error) {
        ciphertextDescriptorBytes.fill(0);
        throw error;
    }
};

const totalChunkByteLength = (
    chunkByteLengths: readonly number[],
    label: string,
): number =>
    chunkByteLengths.reduce((total, byteLength) => {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength <= 0 ||
            !Number.isSafeInteger(total + byteLength)
        ) {
            throw new CanonicalStreamInternalError(
                `${label} has invalid canonical chunk accounting.`,
            );
        }
        return total + byteLength;
    }, 0);

/**
 * Generates, persists, and binds one exact ballot-validity proof and its
 * encrypted ballot package inside the dedicated browser worker.
 */
export const generateBallotValidityInClosedWorker = async (input: {
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    actionRandomnessSession: ActionRandomnessSession;
    canonicalSuiteRecordBytes: Uint8Array;
    checkpointLineageIdentifier: Uint8Array;
    ciphertextStore: CommonProofCanonicalOutputStore;
    encryptionAttemptIdentifier: Uint8Array;
    generationMode: BallotValidityGenerationMode;
    kernel: TranscriptCoreKernel;
    openProofGenerationExecution: CommonProofGenerationExecutionOpener;
    producerSequence: bigint;
    proofAttemptNonce: Uint8Array;
    resolveVerifiedBallotPackage(input: {
        ciphertextDescriptorBytes: Uint8Array<ArrayBuffer>;
        proofDescriptorBytes: Uint8Array<ArrayBuffer>;
    }): Promise<VerifiedTranscriptObject>;
    scores: readonly bigint[];
}): Promise<GeneratedBallotValidityTransport> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Ballot-validity proof generation may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireBallotValidityKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'ballot-validity generation boundary',
    });
    const acceptedSetupAuthorization =
        requireVerifiedAcceptedSetupAuthorityKernelOwner(
            input.acceptedSetupAuthority,
            input.kernel,
        );
    const actionRandomnessAuthorization =
        resolveActionRandomnessKernelAuthorization(
            input.actionRandomnessSession,
            input.kernel,
        );
    if (actionRandomnessAuthorization.context.memory !== context.memory) {
        throw new CanonicalStreamInternalError(
            'The action-randomness session belongs to another WASM worker.',
        );
    }
    if (
        input.generationMode !== 'fresh' &&
        input.generationMode !== 'resumed'
    ) {
        throw new CanonicalStreamRefusalError('wrongContext');
    }
    const producerSequence = requireUnsigned64(input.producerSequence);
    const {
        checkpointLineageIdentifier,
        encryptionAttemptIdentifier,
        proofAttemptNonce,
        scoreBytes,
    } = copyBallotGenerationSecrets({
        checkpointLineageIdentifier: input.checkpointLineageIdentifier,
        encryptionAttemptIdentifier: input.encryptionAttemptIdentifier,
        proofAttemptNonce: input.proofAttemptNonce,
        scores: input.scores,
    });
    let selectedSuiteHandle = 0;
    let ciphertextReadbackHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofGenerationFamilyAdapter
        | undefined;
    let generatedCapability:
        | ClosedWorkerGeneratedCommonProofCapability
        | undefined;
    let operationFailure: unknown;
    let operationFailed = false;
    let result: GeneratedBallotValidityTransport | undefined;
    let ciphertextDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    let proofDescriptorBytes: Uint8Array<ArrayBuffer> | undefined;
    try {
        selectedSuiteHandle = selectSuite({
            canonicalSuiteRecordBytes: input.canonicalSuiteRecordBytes,
            context,
            kernel,
            memoryBoundary,
            statusBoundary,
        });
        const prepared = context.runExclusive(
            'ballot-validity generation preparation',
            () => {
                const scorePointer = memoryBoundary.copy(scoreBytes);
                const encryptionAttemptPointer = memoryBoundary.copy(
                    encryptionAttemptIdentifier,
                );
                const proofAttemptPointer =
                    memoryBoundary.copy(proofAttemptNonce);
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
                        actionRandomnessAuthorization.handle,
                        acceptedSetupAuthorization.handle,
                        producerSequence,
                        scorePointer,
                        scoreBytes.byteLength,
                        encryptionAttemptPointer,
                        proofAttemptPointer,
                        checkpointPointer,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const [readbackHandle, status] = memoryBoundary.readWords(
                        metadataPointer,
                        2,
                    );
                    statusBoundary.throwIfError(status);
                    return Object.freeze({
                        adapterHandle: requireLiveHandle(
                            adapterHandle,
                            'The ballot-validity generation family-adapter handle',
                        ),
                        ciphertextReadbackHandle: requireLiveHandle(
                            readbackHandle,
                            'The ballot ciphertext readback handle',
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
                    memoryBoundary.zeroAndDeallocate(
                        proofAttemptPointer,
                        proofAttemptNonce.byteLength,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        encryptionAttemptPointer,
                        encryptionAttemptIdentifier.byteLength,
                    );
                    memoryBoundary.zeroAndDeallocate(
                        scorePointer,
                        scoreBytes.byteLength,
                    );
                }
            },
        );
        ciphertextReadbackHandle = prepared.ciphertextReadbackHandle;
        familyAdapter = openClosedWorkerCommonProofGenerationFamilyAdapter(
            context,
            prepared.adapterHandle,
        );
        releaseSelectedSuite({
            context,
            handle: selectedSuiteHandle,
            kernel,
            operationName: 'ballot-validity selected-suite release',
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
        proofDescriptorBytes = await deriveGeneratedCommonProofDescriptor({
            kernel: input.kernel,
            outputChunkByteLengths: execution.outputChunkByteLengths,
            outputStore: execution.outputStore,
            proofFamilyLabel: 'ballot-validity',
            streamDomain: canonicalStreamDomains.ballotValidityProof,
        });
        const ciphertextTransport = await copyGeneratedCiphertextToStore({
            ciphertextReadbackHandle,
            ciphertextStore: input.ciphertextStore,
            context,
            kernel,
            memoryBoundary,
            publicKernel: input.kernel,
            signal: execution.options?.signal,
            statusBoundary,
        });
        ciphertextDescriptorBytes =
            ciphertextTransport.ciphertextDescriptorBytes;
        throwIfAborted(execution.options?.signal);
        const ballotPackageObject = await input.resolveVerifiedBallotPackage({
            ciphertextDescriptorBytes: ciphertextDescriptorBytes.slice(),
            proofDescriptorBytes: proofDescriptorBytes.slice(),
        });
        throwIfAborted(execution.options?.signal);
        const boardAuthorization =
            resolveOrderedVerifiedBoardObjectAuthorization({
                context,
                expectedObjectCount: 1,
                kernel: input.kernel,
                objects: [ballotPackageObject],
            });
        const ballotPackageObjectHandle = new DataView(
            boardAuthorization.handleBytes.buffer,
            boardAuthorization.handleBytes.byteOffset,
            boardAuthorization.handleBytes.byteLength,
        ).getUint32(0, true);
        const capabilityForBinding = generatedCapability;
        applyClosedWorkerGeneratedCommonProofCapability(
            capabilityForBinding,
            context,
            (generatedCommonProofHandle) => {
                const status = context.runExclusive(
                    'ballot-validity generated-proof board binding',
                    () =>
                        kernel.bindGeneratedProofToBoard(
                            generatedCommonProofHandle,
                            ciphertextReadbackHandle,
                            boardAuthorization.sessionHandle,
                            boardAuthorization.capabilityPointer,
                            boardVerifierCapabilityByteLength,
                            ballotPackageObjectHandle,
                        ),
                );
                statusBoundary.throwIfError(status);
                return Object.freeze({ consumed: true, result: undefined });
            },
        );
        generatedCapability = undefined;
        ciphertextReadbackHandle = 0;
        result = Object.freeze({
            ballotPackageObject,
            ciphertextByteLength: ciphertextTransport.ciphertextByteLength,
            ciphertextChunkByteLengths:
                ciphertextTransport.ciphertextChunkByteLengths,
            proofByteLength: totalChunkByteLength(
                execution.outputChunkByteLengths,
                'The ballot-validity proof',
            ),
            proofChunkByteLengths: Object.freeze([
                ...execution.outputChunkByteLengths,
            ]),
        });
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    } finally {
        scoreBytes.fill(0);
        encryptionAttemptIdentifier.fill(0);
        proofAttemptNonce.fill(0);
        checkpointLineageIdentifier.fill(0);
        ciphertextDescriptorBytes?.fill(0);
        proofDescriptorBytes?.fill(0);
    }

    const cleanupFailures: unknown[] = [];
    if (selectedSuiteHandle !== 0) {
        try {
            releaseSelectedSuite({
                context,
                handle: selectedSuiteHandle,
                kernel,
                operationName: 'ballot-validity selected-suite failure release',
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
    if (ciphertextReadbackHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardCiphertextReadback,
                handle: ciphertextReadbackHandle,
                operationName:
                    'ballot-validity ciphertext readback failure discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Ballot-validity generation failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (result === undefined) {
        throw new CanonicalStreamInternalError(
            'Ballot-validity generation completed without a bound transport.',
        );
    }
    return result;
};

const readAndAbsorbCiphertext = async (input: {
    ciphertextInputStore: AuthenticatedCommonProofInputStore;
    context: TranscriptCoreKernelCommandRuntime;
    kernel: BallotValidityKernel;
    memoryBoundary: WasmMemoryBoundary;
    preparationHandle: number;
    signal: AbortSignal | undefined;
    statusBoundary: WasmStatusBoundary;
}): Promise<void> => {
    const declaredByteLength = input.ciphertextInputStore.declaredByteLength;
    if (
        !Number.isSafeInteger(declaredByteLength) ||
        declaredByteLength <= 0 ||
        declaredByteLength > foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new CanonicalStreamRefusalError('outsideSupportedProfile');
    }
    const chunkCount = Math.ceil(
        declaredByteLength / foundationProfile.streamChunkByteLength,
    );
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        throwIfAborted(input.signal);
        const exactByteLength = Math.min(
            foundationProfile.streamChunkByteLength,
            declaredByteLength -
                chunkIndex * foundationProfile.streamChunkByteLength,
        );
        const untrustedReturnedBytes: unknown =
            await input.ciphertextInputStore.readCommittedChunk(
                chunkIndex,
                exactByteLength,
            );
        throwIfAborted(input.signal);
        if (
            !isUint8Array(untrustedReturnedBytes) ||
            !(untrustedReturnedBytes.buffer instanceof ArrayBuffer) ||
            untrustedReturnedBytes.byteLength !== exactByteLength
        ) {
            if (isUint8Array(untrustedReturnedBytes)) {
                untrustedReturnedBytes.fill(0);
            }
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const returnedBytes = untrustedReturnedBytes;
        const ownedBytes = Uint8Array.from(returnedBytes);
        try {
            const status = input.context.runExclusive(
                'ballot ciphertext verification ingestion',
                () => {
                    const chunkPointer = input.memoryBoundary.copy(ownedBytes);
                    try {
                        return input.kernel.absorbCiphertextChunk(
                            input.preparationHandle,
                            chunkIndex,
                            chunkPointer,
                            ownedBytes.byteLength,
                        );
                    } finally {
                        input.memoryBoundary.zeroAndDeallocate(
                            chunkPointer,
                            ownedBytes.byteLength,
                        );
                    }
                },
            );
            input.statusBoundary.throwIfError(status);
        } finally {
            ownedBytes.fill(0);
            returnedBytes.fill(0);
        }
    }
};

/**
 * Verifies the board-bound ciphertext and proof, then mints the sole opaque
 * ballot output that evaluator aggregation can consume.
 */
export const verifyBallotValidityInClosedWorker = async (input: {
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    ballotPackageObject: VerifiedTranscriptObject;
    canonicalSuiteRecordBytes: Uint8Array;
    ciphertextInputStore: AuthenticatedCommonProofInputStore;
    kernel: TranscriptCoreKernel;
    options?: CommonProofVerificationWorkerOptions;
    proofInputStore: AuthenticatedCommonProofInputStore;
}): Promise<VerifiedBallotOutput> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new CanonicalStreamInternalError(
            'Ballot-validity proof verification may only run inside the dedicated WASM worker.',
        );
    }
    const context = resolveCommonProofKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The loaded WASM kernel has no common-proof worker context.',
        );
    }
    const kernel = requireBallotValidityKernel(context);
    const statusBoundary = createStatusBoundary();
    const memoryBoundary = new WasmMemoryBoundary({
        context,
        createInternalError: (message) =>
            new CanonicalStreamInternalError(message),
        createResourceError: (message) =>
            new CanonicalStreamResourceError(message),
        label: 'ballot-validity verification boundary',
    });
    const acceptedSetupAuthorization =
        requireVerifiedAcceptedSetupAuthorityKernelOwner(
            input.acceptedSetupAuthority,
            input.kernel,
        );
    const boardAuthorization = resolveOrderedVerifiedBoardObjectAuthorization({
        context,
        expectedObjectCount: 1,
        kernel: input.kernel,
        objects: [input.ballotPackageObject],
    });
    const ballotPackageObjectHandle = new DataView(
        boardAuthorization.handleBytes.buffer,
        boardAuthorization.handleBytes.byteOffset,
        boardAuthorization.handleBytes.byteLength,
    ).getUint32(0, true);
    const ballotOutputReservation = reserveBallotOutputSlot();
    let reservationOwnedByVerification = true;
    let selectedSuiteHandle = 0;
    let preparationHandle = 0;
    let terminalSourceHandle = 0;
    let familyAdapter:
        | ClosedWorkerCommonProofVerificationFamilyAdapter
        | undefined;
    let verifiedOutput: VerifiedBallotOutput | undefined;
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
        preparationHandle = context.runExclusive(
            'ballot-validity verification begin',
            () => {
                const statusPointer = memoryBoundary.allocateZeroedWords(1);
                try {
                    const handle = kernel.beginVerification(
                        selectedSuiteHandle,
                        acceptedSetupAuthorization.handle,
                        boardAuthorization.sessionHandle,
                        boardAuthorization.capabilityPointer,
                        boardVerifierCapabilityByteLength,
                        ballotPackageObjectHandle,
                        statusPointer,
                    );
                    const [status] = memoryBoundary.readWords(statusPointer, 1);
                    statusBoundary.throwIfError(status);
                    return requireLiveHandle(
                        handle,
                        'The ballot-validity verification preparation handle',
                    );
                } finally {
                    memoryBoundary.zeroAndDeallocate(
                        statusPointer,
                        wasm32WordByteLength,
                    );
                }
            },
        );
        await readAndAbsorbCiphertext({
            ciphertextInputStore: input.ciphertextInputStore,
            context,
            kernel,
            memoryBoundary,
            preparationHandle,
            signal: input.options?.signal,
            statusBoundary,
        });
        const prepared = context.runExclusive(
            'ballot-validity verification preparation finish',
            () => {
                const metadataPointer = memoryBoundary.allocateZeroedWords(2);
                try {
                    const adapterHandle = kernel.finishVerificationPreparation(
                        preparationHandle,
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
                            'The ballot-validity verification family-adapter handle',
                        ),
                        terminalSourceHandle: requireLiveHandle(
                            sourceHandle,
                            'The ballot-validity verification terminal-source handle',
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
        preparationHandle = 0;
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
                'ballot-validity verification selected-suite release',
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
        const verificationFinish = (() => {
            try {
                return applyClosedWorkerVerifiedCommonProofCapability(
                    verifiedCommonProof,
                    context,
                    (verifiedCommonProofHandle) =>
                        context.runExclusive(
                            'ballot-validity verification finish',
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
                        'The failed ballot proof handoff could not release its generic verifier authority.',
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
                    'The refused ballot proof handoff could not release its generic verifier authority.',
                    Object.freeze({
                        cleanupFailure,
                        status: verificationFinish.status,
                    }),
                );
            }
            statusBoundary.throwIfError(verificationFinish.status);
        }
        const outputHandle = requireLiveHandle(
            verificationFinish.handle,
            'The verified ballot-output handle',
        );
        terminalSourceHandle = 0;
        try {
            verifiedOutput = mintVerifiedBallotOutputKernelAuthority(
                {
                    handle: outputHandle,
                    kernel: input.kernel,
                    releaseKernelOutput: (handle): void =>
                        discardHandle({
                            context,
                            discard: kernel.discardVerifiedOutput,
                            handle,
                            operationName: 'verified ballot-output release',
                            statusBoundary,
                        }),
                },
                ballotOutputReservation,
            );
            reservationOwnedByVerification = false;
        } catch (adoptionFailure) {
            try {
                discardHandle({
                    context,
                    discard: kernel.discardVerifiedOutput,
                    handle: outputHandle,
                    operationName:
                        'verified ballot-output adoption failure discard',
                    statusBoundary,
                });
            } catch (cleanupFailure) {
                throw new CanonicalStreamInternalError(
                    'The verified ballot output could not be adopted or retired.',
                    Object.freeze({ cleanupFailure, adoptionFailure }),
                );
            }
            throw adoptionFailure;
        }
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
                    'ballot-validity verification selected-suite failure release',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (preparationHandle !== 0) {
        try {
            discardHandle({
                context,
                discard: kernel.discardVerificationPreparation,
                handle: preparationHandle,
                operationName:
                    'ballot-validity verification preparation discard',
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
                    'ballot-validity verification terminal-source discard',
                statusBoundary,
            });
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (reservationOwnedByVerification) {
        try {
            releaseBallotOutputReservation(ballotOutputReservation);
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Ballot-validity verification failed to retire all worker-owned authority.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    if (operationFailed) {
        throw operationFailure;
    }
    if (verifiedOutput === undefined) {
        throw new CanonicalStreamInternalError(
            'Ballot-validity verification completed without an output.',
        );
    }
    return verifiedOutput;
};
