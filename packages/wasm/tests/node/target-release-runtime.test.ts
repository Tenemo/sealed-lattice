import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    mlDsa65SignatureByteLength,
    type StateObjectSignatureOperation,
} from '#packages/wasm/src/state-verifier-runtime/contracts';
import {
    generateTargetReleaseInClosedWorker,
    reconstructTargetReleaseInClosedWorker,
    type VerifiedTargetReleaseShare,
    verifyTargetReleaseInClosedWorker,
} from '#packages/wasm/src/target-release-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

const foundationHashByteLength = 64;
const validTargetShareSignatureByte = 0x5a;

const boundaryMocks = vi.hoisted(() => {
    const activeContext: {
        value: TranscriptCoreKernelCommandRuntime | undefined;
    } = { value: undefined };
    const generatedCapabilityRelease = vi.fn();
    const verifiedCapabilityRelease = vi.fn();
    return {
        activeContext,
        applyGeneratedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: unknown }>,
            ) => apply(301).result,
        ),
        applyVerifiedCapability: vi.fn(
            (
                _capability: unknown,
                _context: unknown,
                apply: (
                    handle: number,
                ) => Readonly<{ consumed: boolean; result: unknown }>,
            ) => apply(401).result,
        ),
        deriveProofDescriptor: vi.fn(() =>
            Promise.resolve(Uint8Array.of(0xd1, 0xd2)),
        ),
        generatedCapabilityRelease,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        openVerificationAdapter: vi.fn(() => Object.freeze({})),
        releaseGenerationAdapter: vi.fn(),
        releaseVerificationAdapter: vi.fn(),
        runGeneration: vi.fn(() =>
            Promise.resolve(
                Object.freeze({ release: generatedCapabilityRelease }),
            ),
        ),
        runVerification: vi.fn(() =>
            Promise.resolve(
                Object.freeze({ release: verifiedCapabilityRelease }),
            ),
        ),
        trackOutput: vi.fn((outputStore: unknown) =>
            Object.freeze({
                outputChunkByteLengths: Object.freeze([2]),
                outputStore,
            }),
        ),
        verifiedCapabilityRelease,
    };
});

vi.mock('#packages/wasm/src/accepted-setup-verification-runtime', () => ({
    requireVerifiedAcceptedSetupAuthorityKernelOwner: (
        _authority: unknown,
        kernel: TranscriptCoreKernel,
    ) => Object.freeze({ handle: 12, kernel }),
}));

vi.mock('#packages/wasm/src/action-randomness-runtime', () => ({
    resolveActionRandomnessKernelAuthorization: () => ({
        context: boundaryMocks.activeContext.value,
        handle: 13,
    }),
}));

vi.mock('#packages/wasm/src/finality-verifier-runtime', () => ({
    resolveVerifiedFinalityKernelAuthorization: () => ({
        capabilityMemory: boundaryMocks.activeContext.value?.memory,
        capabilityPointer: 192,
        finalityHandle: 16,
        sessionHandle: 17,
    }),
}));

vi.mock('#packages/wasm/src/selected-suite-record-source', () => ({
    requireSelectedSuiteRecordSourceKernelOwner: (input: {
        kernel: TranscriptCoreKernel;
    }) => Object.freeze({ handle: 11, kernel: input.kernel }),
}));

vi.mock('#packages/wasm/src/state-verifier-runtime', () => ({
    resolveVerifiedStateOutputKernelAuthorization: () => ({
        capabilityMemory: boundaryMocks.activeContext.value?.memory,
        capabilityPointer: 128,
        outputHandle: 21,
        sessionHandle: 14,
    }),
    resolveVerifiedStateReservationKernelAuthorization: () => ({
        capabilityMemory: boundaryMocks.activeContext.value?.memory,
        capabilityPointer: 128,
        reservationHandle: 15,
        sessionHandle: 14,
    }),
}));

vi.mock('#packages/wasm/src/vss-share-linkage-verification-runtime', () => ({
    resolveOrderedVerifiedBoardObjectAuthorization: (input: {
        objects: readonly Readonly<{ testKind?: string }>[];
    }) => {
        const handleBytes = new Uint8Array(4);
        const handle =
            input.objects[0]?.testKind === 'reservation-intent' ? 18 : 19;
        new DataView(handleBytes.buffer).setUint32(0, handle, true);
        return Object.freeze({
            capabilityPointer: 256,
            handleBytes,
            sessionHandle: 20,
        });
    },
}));

vi.mock('#packages/wasm/src/generated-common-proof-output-runtime', () => ({
    deriveGeneratedCommonProofDescriptor: boundaryMocks.deriveProofDescriptor,
    trackCanonicalCommonProofOutputChunks: boundaryMocks.trackOutput,
}));

vi.mock('#packages/wasm/src/common-proof-worker-runtime/runtime', () => ({
    applyClosedWorkerGeneratedCommonProofCapability:
        boundaryMocks.applyGeneratedCapability,
    applyClosedWorkerVerifiedCommonProofCapability:
        boundaryMocks.applyVerifiedCapability,
    openClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.openGenerationAdapter,
    openClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.openVerificationAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter:
        boundaryMocks.releaseGenerationAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.releaseVerificationAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapterRetainingGeneratedCapability:
        boundaryMocks.runGeneration,
    runClosedWorkerCommonProofVerificationFamilyAdapter:
        boundaryMocks.runVerification,
}));

type FakeTargetReleaseRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    bindCalls: number[][];
    bindStatus: { value: number };
    canonicalTargetShareCarrierByteLength: { value: number };
    generationModes: Array<'fresh' | 'resumed'>;
    generationPreparationArguments: number[][];
    generationSourceDiscards: number[];
    kernel: TranscriptCoreKernel;
    partialReadCalls: Array<
        Readonly<{ chunkIndex: number; roleOrdinal: number }>
    >;
    reconstructedResultCopyCalls: number[];
    reconstructedResultCopyRefusal: { status: number };
    targetShareCarrierCancellations: number[];
    targetShareCarrierFinishCalls: Array<
        Readonly<{
            canonicalCarrierByteLength: number;
            handle: number;
            signatureBytes: number[];
        }>
    >;
    targetShareCarrierFinishStatus: { value: number };
    targetShareCarrierPreparationCalls: Array<
        Readonly<{
            generationSourceHandle: number;
            proofDescriptorBytes: number[];
        }>
    >;
    targetShareCarrierPreparationStatus: { value: number };
    reconstructionCalls: Array<
        Readonly<{
            finalityHandle: number;
            finalitySessionHandle: number;
            targetIdentifierBytes: number[];
            targetOrderBytes: number[];
            verifiedShareHandles: number[];
        }>
    >;
    reconstructionDiscards: number[];
    reconstructionFinishes: number[];
    reconstructionStatus: { value: number };
    verifiedShareDiscards: number[];
    verificationFinishCalls: number[][];
    verificationFinishStatus: { value: number };
    verificationPreparationArguments: number[][];
    verificationTerminalSourceDiscards: number[];
}>;

const writeWord = (
    memory: WebAssembly.Memory,
    pointer: number,
    value: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, value, true);
};

const createFakeTargetReleaseRuntime = (): FakeTargetReleaseRuntime => {
    const memory = new WebAssembly.Memory({ initial: 32 });
    const allocations = new Map<number, number>();
    const bindCalls: number[][] = [];
    const bindStatus = { value: 0 };
    const canonicalTargetShareCarrierByteLength = { value: 7 };
    const generationModes: Array<'fresh' | 'resumed'> = [];
    const generationPreparationArguments: number[][] = [];
    const generationSourceDiscards: number[] = [];
    const partialReadCalls: Array<
        Readonly<{ chunkIndex: number; roleOrdinal: number }>
    > = [];
    const reconstructedResultCopyCalls: number[] = [];
    const reconstructedResultCopyRefusal = { status: 0 };
    const targetShareCarrierCancellations: number[] = [];
    const targetShareCarrierFinishCalls: Array<
        Readonly<{
            canonicalCarrierByteLength: number;
            handle: number;
            signatureBytes: number[];
        }>
    > = [];
    const targetShareCarrierFinishStatus = { value: 0 };
    const targetShareCarrierPreparationCalls: Array<
        Readonly<{
            generationSourceHandle: number;
            proofDescriptorBytes: number[];
        }>
    > = [];
    const targetShareCarrierPreparationStatus = { value: 0 };
    const reconstructionCalls: Array<
        Readonly<{
            finalityHandle: number;
            finalitySessionHandle: number;
            targetIdentifierBytes: number[];
            targetOrderBytes: number[];
            verifiedShareHandles: number[];
        }>
    > = [];
    const reconstructionDiscards: number[] = [];
    const reconstructionFinishes: number[] = [];
    const reconstructionStatus = { value: 0 };
    const verifiedShareDiscards: number[] = [];
    const verificationFinishCalls: number[][] = [];
    const verificationFinishStatus = { value: 0 };
    const verificationPreparationArguments: number[][] = [];
    const verificationTerminalSourceDiscards: number[] = [];
    const activeReconstructionHandles = new Set<number>();
    const activeTargetShareCarrierHandles = new Set<number>();
    const activeVerifiedShareHandles = new Set<number>();
    const copiedReconstructionResults = new Set<number>();
    let nextReconstructedTargetResultHandle = 60;
    let nextVerifiedShareHandle = 46;
    let nextTargetShareCarrierHandle = 70;
    let nextPointer = 1_024;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        if (nextPointer > memory.buffer.byteLength) {
            throw new Error(
                'The fake target-release WASM memory is exhausted.',
            );
        }
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The fake target-release allocation was released with the wrong length.',
            );
        }
        allocations.delete(pointer);
    };
    const prepareGeneration = (
        mode: 'fresh' | 'resumed',
        argumentsList: number[],
    ): number => {
        generationModes.push(mode);
        generationPreparationArguments.push(argumentsList.slice(0, 15));
        writeWord(memory, argumentsList[21] ?? 0, 34);
        writeWord(memory, argumentsList[22] ?? 0, 0);
        return 33;
    };

    const wasmExports = {
        sealed_lattice_target_release_cancel_output_carrier: (
            handle: number,
        ) => {
            targetShareCarrierCancellations.push(handle);
            return activeTargetShareCarrierHandles.delete(handle)
                ? 0
                : refusalReasonCodes.consumedState;
        },
        sealed_lattice_target_release_bind_generated_proof: (
            ...argumentsList: number[]
        ) => {
            bindCalls.push(argumentsList);
            return bindStatus.value;
        },
        sealed_lattice_target_release_copy_partial_descriptor: (
            _sourceHandle: number,
            roleOrdinal: number,
            outputPointer: number,
            outputByteLength: number,
            statusPointer: number,
        ) => {
            const output = new Uint8Array(
                memory.buffer,
                outputPointer,
                outputByteLength,
            );
            output.set([0xa0 + roleOrdinal, 0xb0 + roleOrdinal]);
            writeWord(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_target_release_discard_generation_source: (
            handle: number,
        ) => {
            generationSourceDiscards.push(handle);
            return 0;
        },
        sealed_lattice_target_release_discard_verification_terminal_source: (
            handle: number,
        ) => {
            verificationTerminalSourceDiscards.push(handle);
            return 0;
        },
        sealed_lattice_target_release_discard_verified_share: (
            handle: number,
        ) => {
            verifiedShareDiscards.push(handle);
            if (!activeVerifiedShareHandles.delete(handle)) {
                return refusalReasonCodes.consumedState;
            }
            return 0;
        },
        sealed_lattice_target_release_reconstruct_verified_shares: (
            finalitySessionHandle: number,
            _finalityCapabilityPointer: number,
            _finalityCapabilityByteLength: number,
            finalityHandle: number,
            targetIdentifierPointer: number,
            targetIdentifierByteLength: number,
            targetOrderPointer: number,
            targetOrderByteLength: number,
            verifiedShareHandlesPointer: number,
            verifiedShareHandlesByteLength: number,
            statusPointer: number,
        ) => {
            const handleView = new DataView(
                memory.buffer,
                verifiedShareHandlesPointer,
                verifiedShareHandlesByteLength,
            );
            const verifiedShareHandles = Array.from(
                {
                    length:
                        verifiedShareHandlesByteLength /
                        Uint32Array.BYTES_PER_ELEMENT,
                },
                (_, handleIndex) =>
                    handleView.getUint32(
                        handleIndex * Uint32Array.BYTES_PER_ELEMENT,
                        true,
                    ),
            );
            reconstructionCalls.push(
                Object.freeze({
                    finalityHandle,
                    finalitySessionHandle,
                    targetIdentifierBytes: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            targetIdentifierPointer,
                            targetIdentifierByteLength,
                        ),
                    ),
                    targetOrderBytes: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            targetOrderPointer,
                            targetOrderByteLength,
                        ),
                    ),
                    verifiedShareHandles,
                }),
            );
            if (reconstructionStatus.value !== 0) {
                writeWord(memory, statusPointer, reconstructionStatus.value);
                return 0;
            }
            if (
                verifiedShareHandles.length < 4 ||
                verifiedShareHandles.length >
                    foundationProfile.participantCount ||
                new Set(verifiedShareHandles).size !==
                    verifiedShareHandles.length ||
                !verifiedShareHandles.every((handle) =>
                    activeVerifiedShareHandles.has(handle),
                )
            ) {
                writeWord(
                    memory,
                    statusPointer,
                    refusalReasonCodes.consumedState,
                );
                return 0;
            }
            verifiedShareHandles.forEach((handle) => {
                activeVerifiedShareHandles.delete(handle);
            });
            const reconstructedTargetResultHandle =
                nextReconstructedTargetResultHandle;
            nextReconstructedTargetResultHandle += 1;
            activeReconstructionHandles.add(reconstructedTargetResultHandle);
            writeWord(memory, statusPointer, 0);
            return reconstructedTargetResultHandle;
        },
        sealed_lattice_target_release_reconstructed_selected_option_count: (
            reconstructedTargetResultHandle: number,
            statusPointer: number,
        ) => {
            const status = activeReconstructionHandles.has(
                reconstructedTargetResultHandle,
            )
                ? 0
                : refusalReasonCodes.consumedState;
            writeWord(memory, statusPointer, status);
            return status === 0 ? 4 : 0;
        },
        sealed_lattice_target_release_copy_reconstructed_option_identifiers: (
            reconstructedTargetResultHandle: number,
            outputPointer: number,
            outputByteLength: number,
            statusPointer: number,
        ) => {
            reconstructedResultCopyCalls.push(reconstructedTargetResultHandle);
            let status = activeReconstructionHandles.has(
                reconstructedTargetResultHandle,
            )
                ? 0
                : refusalReasonCodes.consumedState;
            if (status === 0 && reconstructedResultCopyRefusal.status !== 0) {
                status = reconstructedResultCopyRefusal.status;
            }
            if (status !== 0) {
                writeWord(memory, statusPointer, status);
                return status;
            }
            const orderedOptionIdentifiers = [5, 20, 2, 10];
            if (
                outputByteLength !==
                orderedOptionIdentifiers.length * Uint32Array.BYTES_PER_ELEMENT
            ) {
                writeWord(
                    memory,
                    statusPointer,
                    refusalReasonCodes.wrongTypeOrLength,
                );
                return refusalReasonCodes.wrongTypeOrLength;
            }
            const outputView = new DataView(
                memory.buffer,
                outputPointer,
                outputByteLength,
            );
            orderedOptionIdentifiers.forEach(
                (optionIdentifier, optionIndex) => {
                    outputView.setUint32(
                        optionIndex * Uint32Array.BYTES_PER_ELEMENT,
                        optionIdentifier,
                        true,
                    );
                },
            );
            copiedReconstructionResults.add(reconstructedTargetResultHandle);
            writeWord(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_target_release_finish_reconstruction: (
            reconstructedTargetResultHandle: number,
        ) => {
            reconstructionFinishes.push(reconstructedTargetResultHandle);
            if (
                !activeReconstructionHandles.has(
                    reconstructedTargetResultHandle,
                ) ||
                !copiedReconstructionResults.has(
                    reconstructedTargetResultHandle,
                )
            ) {
                return refusalReasonCodes.consumedState;
            }
            activeReconstructionHandles.delete(reconstructedTargetResultHandle);
            copiedReconstructionResults.delete(reconstructedTargetResultHandle);
            return 0;
        },
        sealed_lattice_target_release_discard_reconstruction: (
            reconstructedTargetResultHandle: number,
        ) => {
            reconstructionDiscards.push(reconstructedTargetResultHandle);
            if (
                !activeReconstructionHandles.delete(
                    reconstructedTargetResultHandle,
                )
            ) {
                return refusalReasonCodes.consumedState;
            }
            copiedReconstructionResults.delete(reconstructedTargetResultHandle);
            return 0;
        },
        sealed_lattice_target_release_finish_output_carrier: (
            handle: number,
            signaturePointer: number,
            signatureByteLength: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            const signatureBytes = Array.from(
                new Uint8Array(
                    memory.buffer,
                    signaturePointer,
                    signatureByteLength,
                ),
            );
            targetShareCarrierFinishCalls.push(
                Object.freeze({
                    canonicalCarrierByteLength: outputByteLength,
                    handle,
                    signatureBytes,
                }),
            );
            if (targetShareCarrierFinishStatus.value !== 0) {
                if (
                    targetShareCarrierFinishStatus.value ===
                    refusalReasonCodes.consumedState
                ) {
                    activeTargetShareCarrierHandles.delete(handle);
                }
                return targetShareCarrierFinishStatus.value;
            }
            if (!activeTargetShareCarrierHandles.has(handle)) {
                return refusalReasonCodes.consumedState;
            }
            if (
                signatureByteLength !== mlDsa65SignatureByteLength ||
                signatureBytes.some(
                    (signatureByte) =>
                        signatureByte !== validTargetShareSignatureByte,
                )
            ) {
                activeTargetShareCarrierHandles.delete(handle);
                return refusalReasonCodes.invalidSignature;
            }
            if (
                outputByteLength !== canonicalTargetShareCarrierByteLength.value
            ) {
                return refusalReasonCodes.wrongTypeOrLength;
            }
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).fill(
                0xc1,
            );
            activeTargetShareCarrierHandles.delete(handle);
            return 0;
        },
        sealed_lattice_target_release_finish_verification: (
            verifiedProofHandle: number,
            terminalSourceHandle: number,
            statusPointer: number,
        ) => {
            verificationFinishCalls.push([
                verifiedProofHandle,
                terminalSourceHandle,
            ]);
            writeWord(memory, statusPointer, verificationFinishStatus.value);
            if (verificationFinishStatus.value !== 0) {
                return 0;
            }
            const verifiedShareHandle = nextVerifiedShareHandle;
            nextVerifiedShareHandle += 1;
            activeVerifiedShareHandles.add(verifiedShareHandle);
            return verifiedShareHandle;
        },
        sealed_lattice_target_release_partial_descriptor_byte_length: (
            _sourceHandle: number,
            _roleOrdinal: number,
            statusPointer: number,
        ) => {
            writeWord(memory, statusPointer, 0);
            return 2;
        },
        sealed_lattice_target_release_partial_total_byte_length: (
            _sourceHandle: number,
            roleOrdinal: number,
            statusPointer: number,
        ) => {
            writeWord(memory, statusPointer, 0);
            return roleOrdinal === 0
                ? BigInt(foundationProfile.streamChunkByteLength + 3)
                : 5n;
        },
        sealed_lattice_target_release_prepare_generation: (
            ...argumentsList: number[]
        ) => prepareGeneration('fresh', argumentsList),
        sealed_lattice_target_release_prepare_resumed_generation: (
            ...argumentsList: number[]
        ) => prepareGeneration('resumed', argumentsList),
        sealed_lattice_target_release_prepare_output_carrier: (
            generationSourceHandle: number,
            proofDescriptorPointer: number,
            proofDescriptorByteLength: number,
            canonicalCarrierByteLengthOutputPointer: number,
            signatureMessageOutputPointer: number,
            signatureMessageOutputByteLength: number,
            statusPointer: number,
        ) => {
            targetShareCarrierPreparationCalls.push(
                Object.freeze({
                    generationSourceHandle,
                    proofDescriptorBytes: Array.from(
                        new Uint8Array(
                            memory.buffer,
                            proofDescriptorPointer,
                            proofDescriptorByteLength,
                        ),
                    ),
                }),
            );
            if (targetShareCarrierPreparationStatus.value !== 0) {
                writeWord(
                    memory,
                    statusPointer,
                    targetShareCarrierPreparationStatus.value,
                );
                return 0;
            }
            if (signatureMessageOutputByteLength !== foundationHashByteLength) {
                writeWord(
                    memory,
                    statusPointer,
                    refusalReasonCodes.wrongTypeOrLength,
                );
                return 0;
            }
            writeWord(
                memory,
                canonicalCarrierByteLengthOutputPointer,
                canonicalTargetShareCarrierByteLength.value,
            );
            new Uint8Array(
                memory.buffer,
                signatureMessageOutputPointer,
                signatureMessageOutputByteLength,
            ).fill(0x91);
            writeWord(memory, statusPointer, 0);
            const handle = nextTargetShareCarrierHandle;
            nextTargetShareCarrierHandle += 1;
            activeTargetShareCarrierHandles.add(handle);
            return handle;
        },
        sealed_lattice_target_release_prepare_verification: (
            ...argumentsList: number[]
        ) => {
            verificationPreparationArguments.push(argumentsList.slice(0, 15));
            writeWord(memory, argumentsList[23] ?? 0, 45);
            writeWord(memory, argumentsList[24] ?? 0, 0);
            return 44;
        },
        sealed_lattice_target_release_read_partial_chunk: (
            _sourceHandle: number,
            roleOrdinal: number,
            chunkIndex: number,
            outputPointer: number,
            outputByteLength: number,
            statusPointer: number,
        ) => {
            partialReadCalls.push({ chunkIndex, roleOrdinal });
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).fill(
                1 + roleOrdinal * 16 + chunkIndex,
            );
            writeWord(memory, statusPointer, 0);
            return 0;
        },
    };
    const kernel = Object.freeze({}) as TranscriptCoreKernel;
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The target-release test does not use commands.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports,
    } as unknown as TranscriptCoreKernelCommandRuntime;
    registerCommonProofKernelContext(kernel, context);
    boundaryMocks.activeContext.value = context;

    return Object.freeze({
        allocations,
        bindCalls,
        bindStatus,
        canonicalTargetShareCarrierByteLength,
        generationModes,
        generationPreparationArguments,
        generationSourceDiscards,
        kernel,
        partialReadCalls,
        reconstructedResultCopyCalls,
        reconstructedResultCopyRefusal,
        targetShareCarrierCancellations,
        targetShareCarrierFinishCalls,
        targetShareCarrierFinishStatus,
        targetShareCarrierPreparationCalls,
        targetShareCarrierPreparationStatus,
        reconstructionCalls,
        reconstructionDiscards,
        reconstructionFinishes,
        reconstructionStatus,
        verifiedShareDiscards,
        verificationFinishCalls,
        verificationFinishStatus,
        verificationPreparationArguments,
        verificationTerminalSourceDiscards,
    });
};

const createOutputStore = (input?: {
    failAtChunkIndex?: number;
    observations?: Array<Readonly<{ byteLength: number; firstByte: number }>>;
}) => {
    const chunks = new Map<number, Uint8Array<ArrayBuffer>>();
    return Object.freeze({
        commitChunk: (
            chunkIndex: number,
            chunkBytes: Uint8Array<ArrayBuffer>,
        ): Promise<void> => {
            if (input?.failAtChunkIndex === chunkIndex) {
                return Promise.reject(
                    new Error('The test output store rejected the chunk.'),
                );
            }
            input?.observations?.push(
                Object.freeze({
                    byteLength: chunkBytes.byteLength,
                    firstByte: chunkBytes[0] ?? 0,
                }),
            );
            chunks.set(chunkIndex, chunkBytes.slice());
            return Promise.resolve();
        },
        readChunk: (
            chunkIndex: number,
            exactByteLength: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            const bytes = chunks.get(chunkIndex);
            if (bytes === undefined || bytes.byteLength !== exactByteLength) {
                return Promise.reject(
                    new Error('The requested target-release chunk is absent.'),
                );
            }
            return Promise.resolve(bytes.slice());
        },
    });
};

const reservationIntentObject = Object.freeze({
    testKind: 'reservation-intent',
});
const targetShareObject = Object.freeze({ testKind: 'target-share' });
const verifiedOutput = Object.freeze({ testKind: 'output' });

const createTargetShareSignatureOperation = (input?: {
    observedMessages?: Uint8Array<ArrayBuffer>[];
    signatureByte?: number;
    signatureByteLength?: number;
}): StateObjectSignatureOperation =>
    Object.freeze({
        signStateObjectMessage: (
            signatureMessageHash: Uint8Array,
        ): Uint8Array => {
            input?.observedMessages?.push(signatureMessageHash.slice());
            return new Uint8Array(
                input?.signatureByteLength ?? mlDsa65SignatureByteLength,
            ).fill(input?.signatureByte ?? validTargetShareSignatureByte);
        },
    });

const mintVerifiedTargetReleaseShares = async (
    runtime: FakeTargetReleaseRuntime,
    shareCount = 4,
): Promise<VerifiedTargetReleaseShare[]> => {
    const shares: VerifiedTargetReleaseShare[] = [];
    for (let shareIndex = 0; shareIndex < shareCount; shareIndex += 1) {
        shares.push(
            await verifyTargetReleaseInClosedWorker({
                acceptedSetupAuthority: Object.freeze({}) as never,
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                kernel: runtime.kernel,
                proofInputStore: Object.freeze({}) as never,
                selectedSuiteRecordSource: Object.freeze({}) as never,
                targetIdentifierPartialBytes: Uint8Array.of(0x61 + shareIndex),
                targetOrderPartialBytes: Uint8Array.of(0x71 + shareIndex),
                targetShareObject: targetShareObject as never,
                verifiedFinality: Object.freeze({}) as never,
                verifiedOutput: verifiedOutput as never,
                verifiedReservation: Object.freeze({}) as never,
            }),
        );
    }
    return shares;
};

type TargetReleaseGenerationInput = Parameters<
    typeof generateTargetReleaseInClosedWorker
>[0];

const createTargetReleaseGenerationInput = (
    runtime: FakeTargetReleaseRuntime,
    overrides: Partial<TargetReleaseGenerationInput> = {},
): TargetReleaseGenerationInput => ({
    acceptedSetupAuthority: Object.freeze({}) as never,
    actionRandomnessSession: Object.freeze({}) as never,
    checkpointLineageIdentifier: new Uint8Array(32).fill(0x31),
    externalMemory: Object.freeze({}) as never,
    finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
    finalizedTargetOrderBytes: Uint8Array.of(0x51),
    generationMode: 'fresh',
    kernel: runtime.kernel,
    outputStore: createOutputStore(),
    partialOutputStores: {
        resolveOutputStore: () => Promise.resolve(createOutputStore()),
    },
    reservationIntentObject: reservationIntentObject as never,
    resolveVerifiedTargetShare: () =>
        Promise.resolve({
            targetShareObject: targetShareObject as never,
            verifiedOutput: verifiedOutput as never,
        }),
    selectedSuiteRecordSource: Object.freeze({}) as never,
    signatureOperation: createTargetShareSignatureOperation(),
    verifiedFinality: Object.freeze({}) as never,
    verifiedReservation: Object.freeze({}) as never,
    ...overrides,
});

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.activeContext.value = undefined;
});

describe('target-release closed-worker lifecycle', () => {
    it('streams both fixed roles in canonical order before one-shot binding', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const observedSignatureMessages: Uint8Array<ArrayBuffer>[] = [];
        let resolverTransport:
            | Readonly<{
                  canonicalTargetShareCarrier: Uint8Array<ArrayBuffer>;
                  proofDescriptorBytes: Uint8Array<ArrayBuffer>;
                  targetIdentifierPartialDescriptorBytes: Uint8Array<ArrayBuffer>;
                  targetOrderPartialDescriptorBytes: Uint8Array<ArrayBuffer>;
              }>
            | undefined;
        const targetIdentifierObservations: Array<
            Readonly<{ byteLength: number; firstByte: number }>
        > = [];
        const targetOrderObservations: Array<
            Readonly<{ byteLength: number; firstByte: number }>
        > = [];
        const result = await generateTargetReleaseInClosedWorker({
            acceptedSetupAuthority: Object.freeze({}) as never,
            actionRandomnessSession: Object.freeze({}) as never,
            checkpointLineageIdentifier: new Uint8Array(32).fill(0x31),
            externalMemory: Object.freeze({}) as never,
            finalizedTargetIdentifierBytes: Uint8Array.of(0x41, 0x42),
            finalizedTargetOrderBytes: Uint8Array.of(0x51, 0x52),
            generationMode: 'fresh',
            kernel: runtime.kernel,
            outputStore: createOutputStore(),
            partialOutputStores: {
                resolveOutputStore: ({ role }) =>
                    Promise.resolve(
                        role === 'targetIdentifier'
                            ? createOutputStore({
                                  observations: targetIdentifierObservations,
                              })
                            : createOutputStore({
                                  observations: targetOrderObservations,
                              }),
                    ),
            },
            reservationIntentObject: reservationIntentObject as never,
            resolveVerifiedTargetShare: (transport) => {
                resolverTransport = transport;
                expect(
                    Array.from(transport.canonicalTargetShareCarrier),
                ).toEqual(new Array(7).fill(0xc1));
                return Promise.resolve({
                    targetShareObject: targetShareObject as never,
                    verifiedOutput: verifiedOutput as never,
                });
            },
            selectedSuiteRecordSource: Object.freeze({}) as never,
            signatureOperation: createTargetShareSignatureOperation({
                observedMessages: observedSignatureMessages,
            }),
            verifiedFinality: Object.freeze({}) as never,
            verifiedReservation: Object.freeze({}) as never,
        });

        expect(runtime.generationModes).toEqual(['fresh']);
        expect(runtime.generationPreparationArguments).toEqual([
            [11, 12, 13, 14, 128, 32, 15, 17, 192, 32, 16, 20, 256, 32, 18],
        ]);
        expect(runtime.partialReadCalls).toEqual([
            { chunkIndex: 0, roleOrdinal: 0 },
            { chunkIndex: 1, roleOrdinal: 0 },
            { chunkIndex: 0, roleOrdinal: 1 },
        ]);
        expect(targetIdentifierObservations).toEqual([
            {
                byteLength: foundationProfile.streamChunkByteLength,
                firstByte: 1,
            },
            { byteLength: 3, firstByte: 2 },
        ]);
        expect(targetOrderObservations).toEqual([
            { byteLength: 5, firstByte: 17 },
        ]);
        expect(runtime.bindCalls).toEqual([[301, 34, 21, 19]]);
        expect(runtime.targetShareCarrierPreparationCalls).toEqual([
            {
                generationSourceHandle: 34,
                proofDescriptorBytes: [0xd1, 0xd2],
            },
        ]);
        expect(observedSignatureMessages).toHaveLength(1);
        expect(observedSignatureMessages[0]).toEqual(
            new Uint8Array(foundationHashByteLength).fill(0x91),
        );
        expect(runtime.targetShareCarrierFinishCalls).toHaveLength(1);
        expect(runtime.targetShareCarrierFinishCalls[0]).toMatchObject({
            canonicalCarrierByteLength: 7,
            handle: 70,
        });
        expect(
            runtime.targetShareCarrierFinishCalls[0]?.signatureBytes,
        ).toEqual(
            new Array(mlDsa65SignatureByteLength).fill(
                validTargetShareSignatureByte,
            ),
        );
        expect(runtime.targetShareCarrierCancellations).toEqual([]);
        expect(runtime.generationSourceDiscards).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
        expect(Array.from(result.proofDescriptorBytes)).toEqual([0xd1, 0xd2]);
        expect(Array.from(result.canonicalTargetShareCarrier)).toEqual(
            new Array(7).fill(0xc1),
        );
        expect(
            Array.from(result.targetIdentifierPartialDescriptorBytes),
        ).toEqual([0xa0, 0xb0]);
        expect(Array.from(result.targetOrderPartialDescriptorBytes)).toEqual([
            0xa1, 0xb1,
        ]);
        expect(resolverTransport).toBeDefined();
        expect(
            Array.from(resolverTransport?.canonicalTargetShareCarrier ?? []),
        ).toEqual(new Array(7).fill(0));
        expect(
            Array.from(resolverTransport?.proofDescriptorBytes ?? []),
        ).toEqual([0, 0]);
        expect(
            Array.from(
                resolverTransport?.targetIdentifierPartialDescriptorBytes ?? [],
            ),
        ).toEqual([0, 0]);
        expect(
            Array.from(
                resolverTransport?.targetOrderPartialDescriptorBytes ?? [],
            ),
        ).toEqual([0, 0]);
        expect(runtime.allocations.size).toBe(0);
    });

    it.each([
        ['a wrong live roster binding', 'wrongContext'],
        ['a wrong authority hash', 'wrongHashOrRoot'],
        ['a malformed proof descriptor', 'malformedEncoding'],
    ] as const)(
        'refuses %s before signing or resolving the target-share carrier',
        async (_caseLabel, refusalReason) => {
            const runtime = createFakeTargetReleaseRuntime();
            runtime.targetShareCarrierPreparationStatus.value =
                refusalReasonCodes[refusalReason];
            const resolveVerifiedTargetShare = vi.fn();

            await expect(
                generateTargetReleaseInClosedWorker(
                    createTargetReleaseGenerationInput(runtime, {
                        resolveVerifiedTargetShare,
                    }),
                ),
            ).rejects.toMatchObject({ refusalReason });

            expect(runtime.targetShareCarrierPreparationCalls).toEqual([
                {
                    generationSourceHandle: 34,
                    proofDescriptorBytes: [0xd1, 0xd2],
                },
            ]);
            expect(runtime.targetShareCarrierFinishCalls).toEqual([]);
            expect(runtime.targetShareCarrierCancellations).toEqual([]);
            expect(resolveVerifiedTargetShare).not.toHaveBeenCalled();
            expect(runtime.bindCalls).toEqual([]);
            expect(
                boundaryMocks.generatedCapabilityRelease,
            ).toHaveBeenCalledTimes(1);
            expect(runtime.generationSourceDiscards).toEqual([34]);
            expect(runtime.allocations.size).toBe(0);
        },
    );

    it('cancels the prepared carrier when Rust reports an invalid canonical length', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        runtime.canonicalTargetShareCarrierByteLength.value = 0;

        await expect(
            generateTargetReleaseInClosedWorker(
                createTargetReleaseGenerationInput(runtime),
            ),
        ).rejects.toThrow();

        expect(runtime.targetShareCarrierFinishCalls).toEqual([]);
        expect(runtime.targetShareCarrierCancellations).toEqual([70]);
        expect(runtime.bindCalls).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels the prepared carrier when the signer returns the wrong signature length', async () => {
        const runtime = createFakeTargetReleaseRuntime();

        await expect(
            generateTargetReleaseInClosedWorker(
                createTargetReleaseGenerationInput(runtime, {
                    signatureOperation: createTargetShareSignatureOperation({
                        signatureByteLength: mlDsa65SignatureByteLength - 1,
                    }),
                }),
            ),
        ).rejects.toMatchObject({ refusalReason: 'wrongTypeOrLength' });

        expect(runtime.targetShareCarrierFinishCalls).toEqual([]);
        expect(runtime.targetShareCarrierCancellations).toEqual([70]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('cancels the prepared carrier after an invalid signature refusal', async () => {
        const runtime = createFakeTargetReleaseRuntime();

        await expect(
            generateTargetReleaseInClosedWorker(
                createTargetReleaseGenerationInput(runtime, {
                    signatureOperation: createTargetShareSignatureOperation({
                        signatureByte: validTargetShareSignatureByte ^ 0xff,
                    }),
                }),
            ),
        ).rejects.toMatchObject({ refusalReason: 'invalidSignature' });

        expect(runtime.targetShareCarrierFinishCalls).toHaveLength(1);
        expect(runtime.targetShareCarrierCancellations).toEqual([70]);
        expect(runtime.bindCalls).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('preserves a consumed-state replay refusal while retiring remaining generation custody', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        runtime.targetShareCarrierFinishStatus.value =
            refusalReasonCodes.consumedState;

        await expect(
            generateTargetReleaseInClosedWorker(
                createTargetReleaseGenerationInput(runtime),
            ),
        ).rejects.toMatchObject({ refusalReason: 'consumedState' });

        expect(runtime.targetShareCarrierFinishCalls).toHaveLength(1);
        expect(runtime.targetShareCarrierCancellations).toEqual([70]);
        expect(runtime.bindCalls).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('zeroes resolver copies and retires proof and source custody after cancellation', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const cancellation = new AbortController();
        let resolverTransport:
            | Parameters<
                  TargetReleaseGenerationInput['resolveVerifiedTargetShare']
              >[0]
            | undefined;

        await expect(
            generateTargetReleaseInClosedWorker(
                createTargetReleaseGenerationInput(runtime, {
                    options: Object.freeze({ signal: cancellation.signal }),
                    resolveVerifiedTargetShare: (transport) => {
                        resolverTransport = transport;
                        cancellation.abort();
                        return Promise.resolve({
                            targetShareObject: targetShareObject as never,
                            verifiedOutput: verifiedOutput as never,
                        });
                    },
                }),
            ),
        ).rejects.toThrow('cancelled');

        expect(runtime.targetShareCarrierFinishCalls).toHaveLength(1);
        expect(runtime.targetShareCarrierCancellations).toEqual([]);
        expect(runtime.bindCalls).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(
            Array.from(resolverTransport?.canonicalTargetShareCarrier ?? []),
        ).toEqual(new Array(7).fill(0));
        expect(runtime.allocations.size).toBe(0);
    });

    it('uses the resumed adapter and retires proof and source custody after storage failure', async () => {
        const runtime = createFakeTargetReleaseRuntime();

        await expect(
            generateTargetReleaseInClosedWorker({
                acceptedSetupAuthority: Object.freeze({}) as never,
                actionRandomnessSession: Object.freeze({}) as never,
                checkpointLineageIdentifier: new Uint8Array(32).fill(0x31),
                externalMemory: Object.freeze({}) as never,
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                generationMode: 'resumed',
                kernel: runtime.kernel,
                options: Object.freeze({ resume: Object.freeze({}) }) as never,
                outputStore: createOutputStore(),
                partialOutputStores: {
                    resolveOutputStore: ({ role }) =>
                        Promise.resolve(
                            role === 'targetOrder'
                                ? createOutputStore({ failAtChunkIndex: 0 })
                                : createOutputStore(),
                        ),
                },
                reservationIntentObject: reservationIntentObject as never,
                resolveVerifiedTargetShare: () =>
                    Promise.resolve({
                        targetShareObject: targetShareObject as never,
                        verifiedOutput: verifiedOutput as never,
                    }),
                selectedSuiteRecordSource: Object.freeze({}) as never,
                signatureOperation: createTargetShareSignatureOperation(),
                verifiedFinality: Object.freeze({}) as never,
                verifiedReservation: Object.freeze({}) as never,
            }),
        ).rejects.toThrow('The test output store rejected the chunk.');

        expect(runtime.generationModes).toEqual(['resumed']);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(runtime.bindCalls).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('retires generated proof and paired-stream authority after a refused state-and-board binding', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        runtime.bindStatus.value = refusalReasonCodes.wrongHashOrRoot;

        await expect(
            generateTargetReleaseInClosedWorker({
                acceptedSetupAuthority: Object.freeze({}) as never,
                actionRandomnessSession: Object.freeze({}) as never,
                checkpointLineageIdentifier: new Uint8Array(32).fill(0x31),
                externalMemory: Object.freeze({}) as never,
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                generationMode: 'fresh',
                kernel: runtime.kernel,
                outputStore: createOutputStore(),
                partialOutputStores: {
                    resolveOutputStore: () =>
                        Promise.resolve(createOutputStore()),
                },
                reservationIntentObject: reservationIntentObject as never,
                resolveVerifiedTargetShare: () =>
                    Promise.resolve({
                        targetShareObject: targetShareObject as never,
                        verifiedOutput: verifiedOutput as never,
                    }),
                selectedSuiteRecordSource: Object.freeze({}) as never,
                signatureOperation: createTargetShareSignatureOperation(),
                verifiedFinality: Object.freeze({}) as never,
                verifiedReservation: Object.freeze({}) as never,
            }),
        ).rejects.toMatchObject({ refusalReason: 'wrongHashOrRoot' });

        expect(runtime.bindCalls).toEqual([[301, 34, 21, 19]]);
        expect(boundaryMocks.generatedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.generationSourceDiscards).toEqual([34]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('mints and explicitly retires one positively verified paired share', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const share = await verifyTargetReleaseInClosedWorker({
            acceptedSetupAuthority: Object.freeze({}) as never,
            finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
            finalizedTargetOrderBytes: Uint8Array.of(0x51),
            kernel: runtime.kernel,
            proofInputStore: Object.freeze({}) as never,
            selectedSuiteRecordSource: Object.freeze({}) as never,
            targetIdentifierPartialBytes: Uint8Array.of(0x61, 0x62),
            targetOrderPartialBytes: Uint8Array.of(0x71, 0x72),
            targetShareObject: targetShareObject as never,
            verifiedFinality: Object.freeze({}) as never,
            verifiedOutput: verifiedOutput as never,
            verifiedReservation: Object.freeze({}) as never,
        });

        expect(runtime.verificationPreparationArguments).toEqual([
            [11, 12, 14, 128, 32, 15, 21, 17, 192, 32, 16, 20, 256, 32, 19],
        ]);
        expect(runtime.verificationFinishCalls).toEqual([[401, 45]]);
        expect(runtime.verificationTerminalSourceDiscards).toEqual([]);
        expect(boundaryMocks.verifiedCapabilityRelease).not.toHaveBeenCalled();

        share.release();
        expect(runtime.verifiedShareDiscards).toEqual([46]);
        expect(() => share.release()).toThrow('consumedState');
        expect(runtime.allocations.size).toBe(0);
    });

    it('releases generic proof authority and terminal source after a refused share handoff', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        runtime.verificationFinishStatus.value =
            refusalReasonCodes.wrongHashOrRoot;

        await expect(
            verifyTargetReleaseInClosedWorker({
                acceptedSetupAuthority: Object.freeze({}) as never,
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                kernel: runtime.kernel,
                proofInputStore: Object.freeze({}) as never,
                selectedSuiteRecordSource: Object.freeze({}) as never,
                targetIdentifierPartialBytes: Uint8Array.of(0x61),
                targetOrderPartialBytes: Uint8Array.of(0x71),
                targetShareObject: targetShareObject as never,
                verifiedFinality: Object.freeze({}) as never,
                verifiedOutput: verifiedOutput as never,
                verifiedReservation: Object.freeze({}) as never,
            }),
        ).rejects.toMatchObject({ refusalReason: 'wrongHashOrRoot' });

        expect(boundaryMocks.verifiedCapabilityRelease).toHaveBeenCalledTimes(
            1,
        );
        expect(runtime.verificationTerminalSourceDiscards).toEqual([45]);
        expect(runtime.verifiedShareDiscards).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('consumes distinct shares and returns only canonical identifiers in rank order', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime, 7);

        const result = reconstructTargetReleaseInClosedWorker({
            finalizedTargetIdentifierBytes: Uint8Array.of(0x41, 0x42),
            finalizedTargetOrderBytes: Uint8Array.of(0x51, 0x52),
            kernel: runtime.kernel,
            verifiedFinality: Object.freeze({}) as never,
            verifiedShares: shares,
        });

        expect(runtime.reconstructionCalls).toEqual([
            {
                finalityHandle: 16,
                finalitySessionHandle: 17,
                targetIdentifierBytes: [0x41, 0x42],
                targetOrderBytes: [0x51, 0x52],
                verifiedShareHandles: [46, 47, 48, 49, 50, 51, 52],
            },
        ]);
        expect(runtime.reconstructedResultCopyCalls).toEqual([60]);
        expect(Array.from(result.orderedOptionIdentifiers)).toEqual([
            5, 20, 2, 10,
        ]);
        expect(runtime.reconstructionFinishes).toEqual([60]);
        expect(runtime.reconstructionDiscards).toEqual([]);
        expect(runtime.verifiedShareDiscards).toEqual([]);
        for (const share of shares) {
            expect(() => share.release()).toThrow('consumedState');
        }
        expect(runtime.allocations.size).toBe(0);
    });

    it('accepts all ten verified shares without letting relay order change the result', async () => {
        const firstRuntime = createFakeTargetReleaseRuntime();
        const firstShares = await mintVerifiedTargetReleaseShares(
            firstRuntime,
            foundationProfile.participantCount,
        );
        const firstRelayOrder = [
            firstShares[9],
            firstShares[1],
            firstShares[7],
            firstShares[3],
            firstShares[5],
            firstShares[0],
            firstShares[8],
            firstShares[2],
            firstShares[6],
            firstShares[4],
        ];
        const firstResult = reconstructTargetReleaseInClosedWorker({
            finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
            finalizedTargetOrderBytes: Uint8Array.of(0x51),
            kernel: firstRuntime.kernel,
            verifiedFinality: Object.freeze({}) as never,
            verifiedShares: firstRelayOrder,
        });
        expect(
            firstRuntime.reconstructionCalls[0]?.verifiedShareHandles,
        ).toEqual([55, 47, 53, 49, 51, 46, 54, 48, 52, 50]);

        const secondRuntime = createFakeTargetReleaseRuntime();
        const secondShares = await mintVerifiedTargetReleaseShares(
            secondRuntime,
            foundationProfile.participantCount,
        );
        const secondResult = reconstructTargetReleaseInClosedWorker({
            finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
            finalizedTargetOrderBytes: Uint8Array.of(0x51),
            kernel: secondRuntime.kernel,
            verifiedFinality: Object.freeze({}) as never,
            verifiedShares: secondShares,
        });
        expect(Array.from(firstResult.orderedOptionIdentifiers)).toEqual(
            Array.from(secondResult.orderedOptionIdentifiers),
        );
        expect(firstRuntime.allocations.size).toBe(0);
        expect(secondRuntime.allocations.size).toBe(0);
    });

    it('rejects incomplete and repeated share selections before transferring ownership', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime);
        const reconstructionInput = {
            finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
            finalizedTargetOrderBytes: Uint8Array.of(0x51),
            kernel: runtime.kernel,
            verifiedFinality: Object.freeze({}) as never,
        };

        let incompleteSelectionFailure: unknown;
        try {
            reconstructTargetReleaseInClosedWorker({
                ...reconstructionInput,
                verifiedShares: shares.slice(0, 3),
            });
        } catch (error) {
            incompleteSelectionFailure = error;
        }
        expect(incompleteSelectionFailure).toMatchObject({
            refusalReason: 'wrongTypeOrLength',
        });

        let repeatedSelectionFailure: unknown;
        try {
            reconstructTargetReleaseInClosedWorker({
                ...reconstructionInput,
                verifiedShares: [shares[0], shares[1], shares[2], shares[2]],
            });
        } catch (error) {
            repeatedSelectionFailure = error;
        }
        expect(repeatedSelectionFailure).toMatchObject({
            refusalReason: 'wrongContext',
        });
        expect(runtime.reconstructionCalls).toEqual([]);

        for (const share of shares) {
            share.release();
        }
        expect(runtime.verifiedShareDiscards).toEqual([46, 47, 48, 49]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('rejects more verified shares than the fixed roster before transferring ownership', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(
            runtime,
            foundationProfile.participantCount + 1,
        );

        expect(() =>
            reconstructTargetReleaseInClosedWorker({
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                kernel: runtime.kernel,
                verifiedFinality: Object.freeze({}) as never,
                verifiedShares: shares,
            }),
        ).toThrow('wrongTypeOrLength');
        expect(runtime.reconstructionCalls).toEqual([]);

        for (const share of shares) {
            share.release();
        }
        expect(runtime.verifiedShareDiscards).toEqual([
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
        ]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('retires every poisoned share after reconstruction refusal', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime);
        runtime.reconstructionStatus.value = refusalReasonCodes.wrongHashOrRoot;

        let reconstructionFailure: unknown;
        try {
            reconstructTargetReleaseInClosedWorker({
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                kernel: runtime.kernel,
                verifiedFinality: Object.freeze({}) as never,
                verifiedShares: shares,
            });
        } catch (error) {
            reconstructionFailure = error;
        }

        expect(reconstructionFailure).toMatchObject({
            refusalReason: 'wrongHashOrRoot',
        });
        expect(runtime.reconstructionDiscards).toEqual([]);
        expect(runtime.verifiedShareDiscards).toEqual([46, 47, 48, 49]);
        for (const share of shares) {
            expect(() => share.release()).toThrow('consumedState');
        }
        expect(runtime.allocations.size).toBe(0);
    });

    it('discards the reconstructed result when its canonical identifiers cannot be copied', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime);
        runtime.reconstructedResultCopyRefusal.status =
            refusalReasonCodes.wrongHashOrRoot;

        let copyFailure: unknown;
        try {
            reconstructTargetReleaseInClosedWorker({
                finalizedTargetIdentifierBytes: Uint8Array.of(0x41),
                finalizedTargetOrderBytes: Uint8Array.of(0x51),
                kernel: runtime.kernel,
                verifiedFinality: Object.freeze({}) as never,
                verifiedShares: shares,
            });
        } catch (error) {
            copyFailure = error;
        }

        expect(copyFailure).toMatchObject({
            refusalReason: 'wrongHashOrRoot',
        });
        expect(runtime.reconstructedResultCopyCalls).toEqual([60]);
        expect(runtime.reconstructionFinishes).toEqual([]);
        expect(runtime.reconstructionDiscards).toEqual([60]);
        expect(runtime.verifiedShareDiscards).toEqual([]);
        for (const share of shares) {
            expect(() => share.release()).toThrow('consumedState');
        }
        expect(runtime.allocations.size).toBe(0);
    });
});
