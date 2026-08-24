import { describe, expect, it } from 'vitest';

import { CompactPublicKeyGenerationKernelBoundary } from '#packages/wasm/src/common-proof-worker-runtime/kernel-boundaries';
import type { TranscriptCoreKernelCommandRuntime } from '#packages/wasm/src/transcript-core-bridge/kernel-runtime';

const canonicalChunkByteLength = 1_048_576;

type PollOutcome = Readonly<{
    checkpointReady: number;
    completedWorkUnitCount: number;
    firstOrdinal: number;
    pollCode: number;
    stage: number;
    status?: number;
}>;

type FakeCompactGenerationBoundaryRuntime = Readonly<{
    allocations: ReadonlyMap<number, number>;
    cancelledHandles: number[];
    context: TranscriptCoreKernelCommandRuntime;
    copiedProofRanges: Array<Readonly<{ byteLength: number; offset: number }>>;
    copiedPublicInputRanges: Array<
        Readonly<{ byteLength: number; offset: number }>
    >;
    pendingStorageOwnerCode: { value: number };
    pollOutcomes: PollOutcome[];
    releasedCompletedHandles: number[];
    storageRequestBytes: Uint8Array<ArrayBuffer>;
    suppliedStorageResponses: Array<
        Readonly<{
            bytes: number[];
            operationHandle: number;
            storageOwnerCode: number;
        }>
    >;
}>;

const writeUnsigned32 = (
    memory: WebAssembly.Memory,
    pointer: number,
    value: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, value, true);
};

const createFakeRuntime = (input?: {
    proofByteLength?: number;
    publicInputByteLength?: number;
}): FakeCompactGenerationBoundaryRuntime => {
    const memory = new WebAssembly.Memory({ initial: 64 });
    const allocations = new Map<number, number>();
    const pollOutcomes: PollOutcome[] = [];
    const cancelledHandles: number[] = [];
    const releasedCompletedHandles: number[] = [];
    const copiedProofRanges: Array<
        Readonly<{ byteLength: number; offset: number }>
    > = [];
    const copiedPublicInputRanges: Array<
        Readonly<{ byteLength: number; offset: number }>
    > = [];
    const suppliedStorageResponses: Array<
        Readonly<{
            bytes: number[];
            operationHandle: number;
            storageOwnerCode: number;
        }>
    > = [];
    const pendingStorageOwnerCode = { value: 1 };
    const storageRequestBytes = new Uint8Array(156).fill(0x51);
    const transportBindingBytes = Uint8Array.from(
        { length: 256 },
        (_unused, byteIndex) => Math.floor(byteIndex / 64) + 1,
    );
    const publicInputByteLength =
        input?.publicInputByteLength ?? canonicalChunkByteLength + 17;
    const proofByteLength = input?.proofByteLength ?? 19;
    let nextPointer = 1_024;

    const allocate = (byteLength: number): number => {
        const pointer = Math.ceil(nextPointer / 8) * 8;
        nextPointer = pointer + byteLength;
        if (nextPointer > memory.buffer.byteLength) {
            throw new Error('The focused boundary test exhausted fake memory.');
        }
        allocations.set(pointer, byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        if (allocations.get(pointer) !== byteLength) {
            throw new Error(
                'The focused boundary test received a mismatched deallocation.',
            );
        }
        allocations.delete(pointer);
    };
    const copyPattern = (
        destinationPointer: number,
        sourceOffset: number,
        byteLength: number,
        multiplier: number,
    ): void => {
        const destination = new Uint8Array(
            memory.buffer,
            destinationPointer,
            byteLength,
        );
        for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
            destination[byteIndex] =
                ((sourceOffset + byteIndex) * multiplier) % 251;
        }
    };

    const wasmExports = {
        sealed_lattice_compact_public_key_generation_cancel: (
            operationHandle: number,
        ) => {
            cancelledHandles.push(operationHandle);
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_external_memory_usage:
            (
                _operationHandle: number,
                outputPointer: number,
                outputWordCount: number,
            ) => {
                const view = new DataView(memory.buffer, outputPointer);
                for (
                    let wordIndex = 0;
                    wordIndex < outputWordCount;
                    wordIndex += 1
                ) {
                    view.setBigUint64(
                        wordIndex * BigUint64Array.BYTES_PER_ELEMENT,
                        BigInt(100 + wordIndex),
                        true,
                    );
                }
                return 0;
            },
        sealed_lattice_compact_public_key_generation_copy_proof: (
            _operationHandle: number,
            sourceOffset: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            copiedProofRanges.push({
                byteLength: outputByteLength,
                offset: sourceOffset,
            });
            copyPattern(outputPointer, sourceOffset, outputByteLength, 3);
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_public_input: (
            _operationHandle: number,
            sourceOffset: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            copiedPublicInputRanges.push({
                byteLength: outputByteLength,
                offset: sourceOffset,
            });
            copyPattern(outputPointer, sourceOffset, outputByteLength, 1);
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_storage_request: (
            _operationHandle: number,
            _storageOwnerCode: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                storageRequestBytes,
            );
            return 0;
        },
        sealed_lattice_compact_public_key_generation_copy_transport_bindings: (
            _operationHandle: number,
            outputPointer: number,
            outputByteLength: number,
        ) => {
            new Uint8Array(memory.buffer, outputPointer, outputByteLength).set(
                transportBindingBytes,
            );
            return 0;
        },
        sealed_lattice_compact_public_key_generation_external_memory_usage_word_count:
            () => 10,
        sealed_lattice_compact_public_key_generation_pending_storage_request_byte_length:
            (
                _operationHandle: number,
                storageOwnerOutputPointer: number,
                statusPointer: number,
            ) => {
                writeUnsigned32(
                    memory,
                    storageOwnerOutputPointer,
                    pendingStorageOwnerCode.value,
                );
                writeUnsigned32(memory, statusPointer, 0);
                return storageRequestBytes.byteLength;
            },
        sealed_lattice_compact_public_key_generation_poll: (
            _operationHandle: number,
            _maximumWorkUnitCount: number,
            stageOutputPointer: number,
            firstOrdinalOutputPointer: number,
            completedWorkUnitCountOutputPointer: number,
            checkpointReadyOutputPointer: number,
            statusPointer: number,
        ) => {
            const outcome = pollOutcomes.shift();
            if (outcome === undefined) {
                throw new Error(
                    'The focused boundary test exhausted compact poll outcomes.',
                );
            }
            writeUnsigned32(memory, stageOutputPointer, outcome.stage);
            writeUnsigned32(
                memory,
                firstOrdinalOutputPointer,
                outcome.firstOrdinal,
            );
            writeUnsigned32(
                memory,
                completedWorkUnitCountOutputPointer,
                outcome.completedWorkUnitCount,
            );
            writeUnsigned32(
                memory,
                checkpointReadyOutputPointer,
                outcome.checkpointReady,
            );
            writeUnsigned32(memory, statusPointer, outcome.status ?? 0);
            return outcome.pollCode;
        },
        sealed_lattice_compact_public_key_generation_proof_byte_length: (
            _operationHandle: number,
            statusPointer: number,
        ) => {
            writeUnsigned32(memory, statusPointer, 0);
            return proofByteLength;
        },
        sealed_lattice_compact_public_key_generation_public_input_byte_length: (
            _operationHandle: number,
            statusPointer: number,
        ) => {
            writeUnsigned32(memory, statusPointer, 0);
            return publicInputByteLength;
        },
        sealed_lattice_compact_public_key_generation_release_completed: (
            operationHandle: number,
        ) => {
            releasedCompletedHandles.push(operationHandle);
            return 0;
        },
        sealed_lattice_compact_public_key_generation_supply_storage_response: (
            operationHandle: number,
            storageOwnerCode: number,
            responsePointer: number,
            responseByteLength: number,
        ) => {
            suppliedStorageResponses.push({
                bytes: Array.from(
                    new Uint8Array(
                        memory.buffer,
                        responsePointer,
                        responseByteLength,
                    ),
                ),
                operationHandle,
                storageOwnerCode,
            });
            return 0;
        },
        sealed_lattice_compact_public_key_transport_bindings_byte_length: () =>
            transportBindingBytes.byteLength,
    };
    const context = {
        allocate,
        deallocate,
        executeCommand: () => {
            throw new Error('The focused boundary test does not use commands.');
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => operation(),
        wasmExports,
    } as unknown as TranscriptCoreKernelCommandRuntime;
    return Object.freeze({
        allocations,
        cancelledHandles,
        context,
        copiedProofRanges,
        copiedPublicInputRanges,
        pendingStorageOwnerCode,
        pollOutcomes,
        releasedCompletedHandles,
        storageRequestBytes,
        suppliedStorageResponses,
    });
};

describe('Compact public-key generation kernel boundary', () => {
    it('copies bounded outputs and preserves terminal accounting', () => {
        const runtime = createFakeRuntime();
        runtime.pollOutcomes.push(
            {
                checkpointReady: 1,
                completedWorkUnitCount: 0,
                firstOrdinal: 0,
                pollCode: 1,
                stage: 5,
            },
            {
                checkpointReady: 0,
                completedWorkUnitCount: 0,
                firstOrdinal: 1,
                pollCode: 2,
                stage: 0,
            },
            {
                checkpointReady: 0,
                completedWorkUnitCount: 17,
                firstOrdinal: 3,
                pollCode: 1,
                stage: 6,
            },
            {
                checkpointReady: 0,
                completedWorkUnitCount: 0,
                firstOrdinal: 0,
                pollCode: 5,
                stage: 17,
            },
        );
        const boundary = new CompactPublicKeyGenerationKernelBoundary(
            runtime.context,
        );

        expect(boundary.poll(41, 4_096)).toEqual({
            checkpointSafeBoundaryOrdinal: 0,
            completedWorkUnitCount: 0,
            firstOrdinal: 0,
            kind: 'progress',
            stage: 5,
        });
        expect(boundary.poll(41, 4_096)).toEqual({
            kind: 'storage-request-ready',
            storageOwner: 'responseTrees',
        });
        expect(boundary.copyStorageRequest(41, 'responseTrees')).toEqual(
            runtime.storageRequestBytes,
        );
        boundary.supplyStorageResponse(
            41,
            'responseTrees',
            Uint8Array.of(9, 8, 7),
        );
        expect(runtime.suppliedStorageResponses).toEqual([
            {
                bytes: [9, 8, 7],
                operationHandle: 41,
                storageOwnerCode: 1,
            },
        ]);
        expect(boundary.poll(41, 4_096)).toEqual({
            completedWorkUnitCount: 17,
            firstOrdinal: 3,
            kind: 'progress',
            stage: 6,
        });
        expect(boundary.poll(41, 4_096)).toEqual({ kind: 'complete' });

        const publicInput = boundary.copyCanonicalPublicInput(41);
        expect(publicInput.byteLength).toBe(canonicalChunkByteLength + 17);
        expect([
            publicInput[0],
            publicInput[canonicalChunkByteLength - 1],
            publicInput[canonicalChunkByteLength],
            publicInput[publicInput.byteLength - 1],
        ]).toEqual([
            0,
            (canonicalChunkByteLength - 1) % 251,
            canonicalChunkByteLength % 251,
            (canonicalChunkByteLength + 16) % 251,
        ]);
        expect(runtime.copiedPublicInputRanges).toEqual([
            { byteLength: canonicalChunkByteLength, offset: 0 },
            { byteLength: 17, offset: canonicalChunkByteLength },
        ]);

        const proof = boundary.copyCanonicalProof(41);
        expect(Array.from(proof)).toEqual(
            Array.from({ length: 19 }, (_, byteIndex) => (byteIndex * 3) % 251),
        );
        expect(runtime.copiedProofRanges).toEqual([
            { byteLength: 19, offset: 0 },
        ]);
        expect(boundary.copyTransportBindings(41)).toEqual({
            applicationStatementHash: new Uint8Array(64).fill(2),
            manifestHash: new Uint8Array(64).fill(3),
            relationPlanHash: new Uint8Array(64).fill(4),
            suiteIdentifier: new Uint8Array(64).fill(1),
        });
        expect(boundary.externalMemoryUsage(41)).toEqual({
            cfw: {
                deletedObjectLifecycleCount: 109n,
                peakStoredByteLength: 107n,
                totalReadByteLength: 106n,
                totalWrittenByteLength: 105n,
                transactionCount: 108n,
            },
            responseTrees: {
                deletedObjectLifecycleCount: 104n,
                peakStoredByteLength: 102n,
                totalReadByteLength: 101n,
                totalWrittenByteLength: 100n,
                transactionCount: 103n,
            },
        });
        boundary.releaseCompleted(41);
        expect(runtime.releasedCompletedHandles).toEqual([41]);
        expect(runtime.cancelledHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });

    it('rejects malformed poll metadata and inconsistent storage ownership', () => {
        const runtime = createFakeRuntime({
            proofByteLength: 3,
            publicInputByteLength: 3,
        });
        const boundary = new CompactPublicKeyGenerationKernelBoundary(
            runtime.context,
        );
        runtime.pollOutcomes.push({
            checkpointReady: 0,
            completedWorkUnitCount: 1,
            firstOrdinal: 0,
            pollCode: 1,
            stage: 17,
        });
        expect(() => boundary.poll(51, 1)).toThrowError(
            expect.objectContaining({ code: 'KernelFailure' }),
        );

        runtime.pendingStorageOwnerCode.value = 2;
        expect(() =>
            boundary.copyStorageRequest(51, 'responseTrees'),
        ).toThrowError(expect.objectContaining({ code: 'KernelFailure' }));
        expect(() => boundary.poll(51, 0)).toThrowError(
            expect.objectContaining({ code: 'ResourceLimit' }),
        );
        boundary.cancel(51);
        expect(runtime.cancelledHandles).toEqual([51]);
        expect(runtime.releasedCompletedHandles).toEqual([]);
        expect(runtime.allocations.size).toBe(0);
    });
});
