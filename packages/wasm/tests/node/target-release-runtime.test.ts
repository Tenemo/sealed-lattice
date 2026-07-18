import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateTargetReleaseInClosedWorker,
    reconstructTargetReleaseInClosedWorker,
    type VerifiedTargetReleaseShare,
    verifyTargetReleaseInClosedWorker,
} from '#packages/wasm/src/target-release-runtime';
import { registerCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';
import type { TranscriptCoreKernel } from '#packages/wasm/src/transcript-core-bridge/kernel-types';

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
        deriveProofDescriptor: vi.fn(async () => Uint8Array.of(0xd1, 0xd2)),
        generatedCapabilityRelease,
        openGenerationAdapter: vi.fn(() => Object.freeze({})),
        openVerificationAdapter: vi.fn(() => Object.freeze({})),
        releaseGenerationAdapter: vi.fn(),
        releaseVerificationAdapter: vi.fn(),
        runGeneration: vi.fn(async () =>
            Object.freeze({ release: generatedCapabilityRelease }),
        ),
        runVerification: vi.fn(async () =>
            Object.freeze({ release: verifiedCapabilityRelease }),
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
    generationModes: Array<'fresh' | 'resumed'>;
    generationPreparationArguments: number[][];
    generationSourceDiscards: number[];
    kernel: TranscriptCoreKernel;
    partialReadCalls: Array<
        Readonly<{ chunkIndex: number; roleOrdinal: number }>
    >;
    reconstructedRoleCopyCalls: Array<
        Readonly<{ handle: number; roleOrdinal: number }>
    >;
    reconstructedRoleCopyRefusal: {
        roleOrdinal: number | undefined;
        status: number;
    };
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
    const generationModes: Array<'fresh' | 'resumed'> = [];
    const generationPreparationArguments: number[][] = [];
    const generationSourceDiscards: number[] = [];
    const partialReadCalls: Array<
        Readonly<{ chunkIndex: number; roleOrdinal: number }>
    > = [];
    const reconstructedRoleCopyCalls: Array<
        Readonly<{ handle: number; roleOrdinal: number }>
    > = [];
    const reconstructedRoleCopyRefusal: {
        roleOrdinal: number | undefined;
        status: number;
    } = { roleOrdinal: undefined, status: 0 };
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
    const activeVerifiedShareHandles = new Set<number>();
    const copiedReconstructionRoles = new Map<number, number[]>();
    let nextReconstructedTargetPairHandle = 60;
    let nextVerifiedShareHandle = 46;
    let nextPointer = 1_024;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        if (nextPointer > memory.buffer.byteLength) {
            throw new Error('The fake target-release WASM memory is exhausted.');
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
                verifiedShareHandles.length !== 4 ||
                new Set(verifiedShareHandles).size !== 4 ||
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
            const reconstructedTargetPairHandle =
                nextReconstructedTargetPairHandle;
            nextReconstructedTargetPairHandle += 1;
            activeReconstructionHandles.add(reconstructedTargetPairHandle);
            copiedReconstructionRoles.set(reconstructedTargetPairHandle, []);
            writeWord(memory, statusPointer, 0);
            return reconstructedTargetPairHandle;
        },
        sealed_lattice_target_release_reconstructed_slot_count: (
            reconstructedTargetPairHandle: number,
            statusPointer: number,
        ) => {
            const status = activeReconstructionHandles.has(
                reconstructedTargetPairHandle,
            )
                ? 0
                : refusalReasonCodes.consumedState;
            writeWord(memory, statusPointer, status);
            return status === 0 ? 3 : 0;
        },
        sealed_lattice_target_release_copy_reconstructed_role: (
            reconstructedTargetPairHandle: number,
            roleOrdinal: number,
            outputPointer: number,
            outputByteLength: number,
            statusPointer: number,
        ) => {
            reconstructedRoleCopyCalls.push(
                Object.freeze({
                    handle: reconstructedTargetPairHandle,
                    roleOrdinal,
                }),
            );
            let status = activeReconstructionHandles.has(
                reconstructedTargetPairHandle,
            )
                ? 0
                : refusalReasonCodes.consumedState;
            if (
                status === 0 &&
                reconstructedRoleCopyRefusal.roleOrdinal === roleOrdinal
            ) {
                status = reconstructedRoleCopyRefusal.status;
            }
            if (status !== 0) {
                writeWord(memory, statusPointer, status);
                return status;
            }
            const slots =
                roleOrdinal === 0 ? [101, 202, 303] : [7, 8, 9];
            if (
                outputByteLength !==
                slots.length * Uint32Array.BYTES_PER_ELEMENT
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
            slots.forEach((slot, slotIndex) => {
                outputView.setUint32(
                    slotIndex * Uint32Array.BYTES_PER_ELEMENT,
                    slot,
                    true,
                );
            });
            copiedReconstructionRoles
                .get(reconstructedTargetPairHandle)
                ?.push(roleOrdinal);
            writeWord(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_target_release_finish_reconstruction: (
            reconstructedTargetPairHandle: number,
        ) => {
            reconstructionFinishes.push(reconstructedTargetPairHandle);
            if (
                !activeReconstructionHandles.has(
                    reconstructedTargetPairHandle,
                ) ||
                copiedReconstructionRoles
                    .get(reconstructedTargetPairHandle)
                    ?.join(',') !== '0,1'
            ) {
                return refusalReasonCodes.consumedState;
            }
            activeReconstructionHandles.delete(
                reconstructedTargetPairHandle,
            );
            copiedReconstructionRoles.delete(reconstructedTargetPairHandle);
            return 0;
        },
        sealed_lattice_target_release_discard_reconstruction: (
            reconstructedTargetPairHandle: number,
        ) => {
            reconstructionDiscards.push(reconstructedTargetPairHandle);
            if (
                !activeReconstructionHandles.delete(
                    reconstructedTargetPairHandle,
                )
            ) {
                return refusalReasonCodes.consumedState;
            }
            copiedReconstructionRoles.delete(reconstructedTargetPairHandle);
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
            new Uint8Array(
                memory.buffer,
                outputPointer,
                outputByteLength,
            ).fill(1 + roleOrdinal * 16 + chunkIndex);
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
        generationModes,
        generationPreparationArguments,
        generationSourceDiscards,
        kernel,
        partialReadCalls,
        reconstructedRoleCopyCalls,
        reconstructedRoleCopyRefusal,
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
        commitChunk: async (
            chunkIndex: number,
            chunkBytes: Uint8Array<ArrayBuffer>,
        ): Promise<void> => {
            if (input?.failAtChunkIndex === chunkIndex) {
                throw new Error('The test output store rejected the chunk.');
            }
            input?.observations?.push(
                Object.freeze({
                    byteLength: chunkBytes.byteLength,
                    firstByte: chunkBytes[0] ?? 0,
                }),
            );
            chunks.set(chunkIndex, chunkBytes.slice());
        },
        readChunk: async (
            chunkIndex: number,
            exactByteLength: number,
        ): Promise<Uint8Array<ArrayBuffer>> => {
            const bytes = chunks.get(chunkIndex);
            if (bytes === undefined || bytes.byteLength !== exactByteLength) {
                throw new Error('The requested target-release chunk is absent.');
            }
            return bytes.slice();
        },
    });
};

const reservationIntentObject = Object.freeze({
    testKind: 'reservation-intent',
});
const targetShareObject = Object.freeze({ testKind: 'target-share' });
const verifiedOutput = Object.freeze({ testKind: 'output' });

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
                targetIdentifierPartialBytes: Uint8Array.of(
                    0x61 + shareIndex,
                ),
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

beforeEach(() => {
    vi.clearAllMocks();
    boundaryMocks.activeContext.value = undefined;
});

describe('target-release closed-worker lifecycle', () => {
    it('streams both fixed roles in canonical order before one-shot binding', async () => {
        const runtime = createFakeTargetReleaseRuntime();
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
                resolveOutputStore: async ({ role }) =>
                    role === 'targetIdentifier'
                        ? createOutputStore({
                              observations: targetIdentifierObservations,
                          })
                        : createOutputStore({
                              observations: targetOrderObservations,
                          }),
            },
            reservationIntentObject: reservationIntentObject as never,
            resolveVerifiedTargetShare: async () => ({
                targetShareObject: targetShareObject as never,
                verifiedOutput: verifiedOutput as never,
            }),
            selectedSuiteRecordSource: Object.freeze({}) as never,
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
        expect(runtime.generationSourceDiscards).toEqual([]);
        expect(boundaryMocks.generatedCapabilityRelease).not.toHaveBeenCalled();
        expect(Array.from(result.proofDescriptorBytes)).toEqual([0xd1, 0xd2]);
        expect(
            Array.from(result.targetIdentifierPartialDescriptorBytes),
        ).toEqual([0xa0, 0xb0]);
        expect(Array.from(result.targetOrderPartialDescriptorBytes)).toEqual([
            0xa1, 0xb1,
        ]);
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
                    resolveOutputStore: async ({ role }) =>
                        role === 'targetOrder'
                            ? createOutputStore({ failAtChunkIndex: 0 })
                            : createOutputStore(),
                },
                reservationIntentObject: reservationIntentObject as never,
                resolveVerifiedTargetShare: async () => ({
                    targetShareObject: targetShareObject as never,
                    verifiedOutput: verifiedOutput as never,
                }),
                selectedSuiteRecordSource: Object.freeze({}) as never,
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
                    resolveOutputStore: async () => createOutputStore(),
                },
                reservationIntentObject: reservationIntentObject as never,
                resolveVerifiedTargetShare: async () => ({
                    targetShareObject: targetShareObject as never,
                    verifiedOutput: verifiedOutput as never,
                }),
                selectedSuiteRecordSource: Object.freeze({}) as never,
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
        expect(
            runtime.verificationTerminalSourceDiscards,
        ).toEqual([]);
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

    it('consumes four distinct shares and copies the paired logical slots in fixed order', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime);

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
                verifiedShareHandles: [46, 47, 48, 49],
            },
        ]);
        expect(runtime.reconstructedRoleCopyCalls).toEqual([
            { handle: 60, roleOrdinal: 0 },
            { handle: 60, roleOrdinal: 1 },
        ]);
        expect(Array.from(result.targetIdentifierSlots)).toEqual([
            101, 202, 303,
        ]);
        expect(Array.from(result.targetOrderSlots)).toEqual([7, 8, 9]);
        expect(runtime.reconstructionFinishes).toEqual([60]);
        expect(runtime.reconstructionDiscards).toEqual([]);
        expect(runtime.verifiedShareDiscards).toEqual([]);
        for (const share of shares) {
            expect(() => share.release()).toThrow('consumedState');
        }
        expect(runtime.allocations.size).toBe(0);
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
                verifiedShares: [
                    shares[0]!,
                    shares[1]!,
                    shares[2]!,
                    shares[2]!,
                ],
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

    it('retires every poisoned share after reconstruction refusal', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime);
        runtime.reconstructionStatus.value =
            refusalReasonCodes.wrongHashOrRoot;

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

    it('discards the paired result when the second fixed role cannot be copied', async () => {
        const runtime = createFakeTargetReleaseRuntime();
        const shares = await mintVerifiedTargetReleaseShares(runtime);
        runtime.reconstructedRoleCopyRefusal.roleOrdinal = 1;
        runtime.reconstructedRoleCopyRefusal.status =
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
        expect(runtime.reconstructedRoleCopyCalls).toEqual([
            { handle: 60, roleOrdinal: 0 },
            { handle: 60, roleOrdinal: 1 },
        ]);
        expect(runtime.reconstructionFinishes).toEqual([]);
        expect(runtime.reconstructionDiscards).toEqual([60]);
        expect(runtime.verifiedShareDiscards).toEqual([46, 47, 48, 49]);
        for (const share of shares) {
            expect(() => share.release()).toThrow('consumedState');
        }
        expect(runtime.allocations.size).toBe(0);
    });
});
