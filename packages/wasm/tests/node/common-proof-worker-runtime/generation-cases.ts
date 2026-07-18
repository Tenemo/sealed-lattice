import { describe, expect, it } from 'vitest';

import {
    decodeCommonProofExternalMemoryRequest,
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runPreparedCommonProofGenerationWorker,
    type CommonProofCanonicalOutputStore,
    type CommonProofExternalMemoryTransactionExecutor,
    type CommonProofGenerationCheckpoint,
    type CommonProofGenerationWorkerOptions,
} from '../../../src/common-proof-worker-runtime.js';
import type { TranscriptCoreKernelCommandRuntime } from '../../../src/transcript-core-bridge/kernel-runtime.js';

import {
    createCheckpointGenerationKernelFixture,
    createMockKernelRuntime,
    memoryBytes,
    noSecondPollValue,
    writeGenerationPoll,
    writeUnsigned32,
} from './kernel-fixtures.js';
import {
    encodeRequest,
    fourByteReadRequest,
    hashByteLength,
    readResult,
    runtimeBinding,
} from './wire-fixtures.js';

const authenticatedSourceRequestByteLength = 160;

const encodeAuthenticatedSourceReadRequest = (input: {
    authenticationChunkIndex: number;
    exactByteLength: number;
    sourceMaterialRootByte: number;
    sourceStreamByteOffset: bigint;
    sourceStreamDigestByte: number;
    sourceStreamTotalByteLength: bigint;
    storageByteOffset: bigint;
}): Uint8Array<ArrayBuffer> => {
    const encodedRequest = new Uint8Array(authenticatedSourceRequestByteLength);
    encodedRequest.fill(input.sourceMaterialRootByte, 0, hashByteLength);
    encodedRequest.fill(
        input.sourceStreamDigestByte,
        hashByteLength,
        2 * hashByteLength,
    );
    const view = new DataView(encodedRequest.buffer);
    view.setBigUint64(128, input.sourceStreamTotalByteLength, true);
    view.setBigUint64(136, input.sourceStreamByteOffset, true);
    view.setBigUint64(144, input.storageByteOffset, true);
    view.setUint32(152, input.exactByteLength, true);
    view.setUint32(156, input.authenticationChunkIndex, true);
    return encodedRequest;
};

describe('common-proof generation runtime', () => {
    it('drives storage, commit, exact readback, and opaque generation authority in order', async () => {
        class SliceObservingBytes extends Uint8Array {
            public sliceCount = 0;

            public override slice(
                start?: number,
                end?: number,
            ): Uint8Array<ArrayBuffer> {
                this.sliceCount += 1;
                return super.slice(start, end);
            }
        }

        const binding = runtimeBinding(0x41);
        const request = fourByteReadRequest(binding, 1n);
        const outputBytes = Uint8Array.from([7, 3, 9, 1, 4]);
        let phase = 0;
        let releasedCapabilityCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(41);
                writeUnsigned32(memory, statusPointer, 0);
                return 51;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(51);
                if (phase === 0) {
                    phase = 1;
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        1,
                        1,
                        0,
                    );
                }
                if (phase === 1) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        request.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 2) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        3,
                        0,
                        outputBytes.byteLength,
                    );
                }
                if (phase === 3) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        4,
                        0,
                        noSecondPollValue,
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    5,
                    0,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(phase).toBe(1);
                expect(outputLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(request);
                return 0;
            },
            sealed_lattice_common_proof_generation_supply_storage_response: (
                operationHandle,
                responsePointer,
                responseLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(phase).toBe(1);
                const response = memoryBytes(
                    memory,
                    responsePointer,
                    responseLength,
                );
                expect(
                    new DataView(
                        response.buffer,
                        response.byteOffset,
                    ).getUint16(2, true),
                ).toBe(2);
                phase = 2;
                return 0;
            },
            sealed_lattice_common_proof_generation_copy_output_chunk: (
                operationHandle,
                expectedChunkIndex,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(expectedChunkIndex).toBe(0);
                expect(phase).toBe(2);
                expect(outputLength).toBe(outputBytes.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(
                    outputBytes,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
                operationHandle,
                expectedChunkIndex,
            ) => {
                expect(operationHandle).toBe(51);
                expect(expectedChunkIndex).toBe(0);
                expect(phase).toBe(2);
                phase = 3;
                return 0;
            },
            sealed_lattice_common_proof_generation_confirm_output_readback: (
                operationHandle,
                chunkIndex,
                readbackPointer,
                readbackLength,
            ) => {
                expect(operationHandle).toBe(51);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(3);
                expect([
                    ...memoryBytes(memory, readbackPointer, readbackLength),
                ]).toEqual([...outputBytes]);
                phase = 4;
                return 0;
            },
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(51);
                expect(phase).toBe(4);
                writeUnsigned32(memory, statusPointer, 0);
                phase = 5;
                return 61;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(61);
                expect(phase).toBe(5);
                releasedCapabilityCount += 1;
                return 0;
            },
        }));
        const transferredReadBytes = new SliceObservingBytes([5, 8, 13, 21]);
        const transferredReadResult = {
            bytes: transferredReadBytes,
            objectOrdinal: 7,
            offset: 3n,
            operationIndex: 0,
        };
        const externalMemory: CommonProofExternalMemoryTransactionExecutor = {
            executeTransaction: (decodedRequest) => {
                expect(decodedRequest.requestSequence).toBe(1n);
                return Promise.resolve([transferredReadResult]);
            },
        };
        let committedArgument: Uint8Array<ArrayBuffer> | undefined;
        let committedOutput: Uint8Array<ArrayBuffer> | undefined;
        let transferredOutputReadback: SliceObservingBytes | undefined;
        const outputStore: CommonProofCanonicalOutputStore = {
            commitChunk: (chunkIndex, chunkBytes) => {
                expect(chunkIndex).toBe(0);
                committedArgument = chunkBytes;
                committedOutput = chunkBytes.slice();
                return Promise.resolve();
            },
            readChunk: (chunkIndex, exactByteLength) => {
                expect(chunkIndex).toBe(0);
                expect(exactByteLength).toBe(outputBytes.byteLength);
                transferredOutputReadback = new SliceObservingBytes(
                    committedOutput ?? new Uint8Array(),
                );
                return Promise.resolve(transferredOutputReadback);
            },
        };
        let yieldCount = 0;

        const capability = await runPreparedCommonProofGenerationWorker(
            runtime,
            41,
            externalMemory,
            outputStore,
            {
                yieldControl: () => {
                    yieldCount += 1;
                    return Promise.resolve();
                },
            },
        );

        expect(yieldCount).toBe(1);
        expect([...(committedOutput ?? [])]).toEqual([...outputBytes]);
        expect([...(committedArgument ?? [])]).toEqual(
            Array(outputBytes.byteLength).fill(0),
        );
        expect(transferredReadBytes.sliceCount).toBe(0);
        expect([...transferredReadResult.bytes]).toEqual([0, 0, 0, 0]);
        expect(transferredOutputReadback?.sliceCount).toBe(0);
        expect([...(transferredOutputReadback ?? [])]).toEqual(
            Array(outputBytes.byteLength).fill(0),
        );
        capability.release();
        expect(releasedCapabilityCount).toBe(1);
        expect(() => capability.release()).toThrowError(
            expect.objectContaining({ code: 'KernelFailure' }),
        );
    });

    it('services one exact Rust-authenticated source range and clears every transferred view', async () => {
        const exactSourceBytes = Uint8Array.from([2, 3, 5, 7, 11]);
        const encodedSourceRequest = encodeAuthenticatedSourceReadRequest({
            authenticationChunkIndex: 3,
            exactByteLength: exactSourceBytes.byteLength,
            sourceMaterialRootByte: 0x31,
            sourceStreamByteOffset: 1024n,
            sourceStreamDigestByte: 0x42,
            sourceStreamTotalByteLength: 4096n,
            storageByteOffset: 8192n,
        });
        let phase = 0;
        let releasedCapabilityCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(42);
                writeUnsigned32(memory, statusPointer, 0);
                return 52;
            },
            sealed_lattice_common_proof_generation_authenticated_source_request_byte_length:
                () => authenticatedSourceRequestByteLength,
            sealed_lattice_common_proof_generation_copy_authenticated_source_request:
                (operationHandle, outputPointer, outputByteLength) => {
                    expect(operationHandle).toBe(52);
                    expect(outputByteLength).toBe(
                        authenticatedSourceRequestByteLength,
                    );
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        encodedSourceRequest,
                    );
                    return 0;
                },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(52);
                return phase === 0
                    ? writeGenerationPoll(
                          memory,
                          pollKindPointer,
                          primaryValuePointer,
                          secondaryValuePointer,
                          8,
                          exactSourceBytes.byteLength,
                          3,
                      )
                    : writeGenerationPoll(
                          memory,
                          pollKindPointer,
                          primaryValuePointer,
                          secondaryValuePointer,
                          5,
                          0,
                          noSecondPollValue,
                      );
            },
            sealed_lattice_common_proof_generation_supply_authenticated_source_range:
                (operationHandle, sourcePointer, sourceByteLength) => {
                    expect(operationHandle).toBe(52);
                    expect(phase).toBe(0);
                    expect([
                        ...memoryBytes(memory, sourcePointer, sourceByteLength),
                    ]).toEqual([...exactSourceBytes]);
                    phase = 1;
                    return 0;
                },
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(52);
                expect(phase).toBe(1);
                writeUnsigned32(memory, statusPointer, 0);
                return 62;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(62);
                releasedCapabilityCount += 1;
                return 0;
            },
        }));
        let transferredSourceBytes: Uint8Array<ArrayBuffer> | undefined;
        let retainedSourceMaterialRoot: Uint8Array<ArrayBuffer> | undefined;
        let retainedSourceStreamDigest: Uint8Array<ArrayBuffer> | undefined;

        const capability = await runPreparedCommonProofGenerationWorker(
            runtime,
            42,
            {
                executeTransaction: () =>
                    Promise.reject(
                        new Error(
                            'Authenticated-source generation must not use external scratch in this fixture.',
                        ),
                    ),
            },
            {
                commitChunk: () =>
                    Promise.reject(
                        new Error(
                            'Authenticated-source generation emitted an unexpected proof chunk.',
                        ),
                    ),
                readChunk: () =>
                    Promise.reject(
                        new Error(
                            'Authenticated-source generation requested unexpected proof readback.',
                        ),
                    ),
            },
            {
                authenticatedSourceRangeReader: Object.freeze({
                    readExactRange: (request) => {
                        expect(request).toMatchObject({
                            authenticationChunkIndex: 3,
                            exactByteLength: exactSourceBytes.byteLength,
                            sourceStreamByteOffset: 1024n,
                            sourceStreamTotalByteLength: 4096n,
                            storageByteOffset: 8192n,
                        });
                        expect([...request.sourceMaterialRoot]).toEqual(
                            Array(hashByteLength).fill(0x31),
                        );
                        expect([...request.sourceStreamDigest]).toEqual(
                            Array(hashByteLength).fill(0x42),
                        );
                        retainedSourceMaterialRoot = request.sourceMaterialRoot;
                        retainedSourceStreamDigest = request.sourceStreamDigest;
                        transferredSourceBytes = exactSourceBytes.slice();
                        return Promise.resolve(transferredSourceBytes);
                    },
                }),
            },
        );

        expect([...(transferredSourceBytes ?? [])]).toEqual(
            Array(exactSourceBytes.byteLength).fill(0),
        );
        expect([...(retainedSourceMaterialRoot ?? [])]).toEqual(
            Array(hashByteLength).fill(0),
        );
        expect([...(retainedSourceStreamDigest ?? [])]).toEqual(
            Array(hashByteLength).fill(0),
        );
        capability.release();
        expect(releasedCapabilityCount).toBe(1);
    });

    it('retires generation before reading an inconsistent authenticated-source request', async () => {
        const encodedSourceRequest = encodeAuthenticatedSourceReadRequest({
            authenticationChunkIndex: 4,
            exactByteLength: 4,
            sourceMaterialRootByte: 0x51,
            sourceStreamByteOffset: 256n,
            sourceStreamDigestByte: 0x62,
            sourceStreamTotalByteLength: 1024n,
            storageByteOffset: 2048n,
        });
        let readAttemptCount = 0;
        let retirementCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(43);
                writeUnsigned32(memory, statusPointer, 0);
                return 53;
            },
            sealed_lattice_common_proof_generation_authenticated_source_request_byte_length:
                () => authenticatedSourceRequestByteLength,
            sealed_lattice_common_proof_generation_copy_authenticated_source_request:
                (operationHandle, outputPointer, outputByteLength) => {
                    expect(operationHandle).toBe(53);
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        encodedSourceRequest,
                    );
                    return 0;
                },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(53);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    8,
                    5,
                    4,
                );
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(53);
                retirementCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                43,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    authenticatedSourceRangeReader: Object.freeze({
                        readExactRange: () => {
                            readAttemptCount += 1;
                            return Promise.resolve(new Uint8Array(5));
                        },
                    }),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(readAttemptCount).toBe(0);
        expect(retirementCount).toBe(1);
    });

    it('clears and rejects a non-owned authenticated-source range before Rust ingestion', async () => {
        const exactByteLength = 5;
        const encodedSourceRequest = encodeAuthenticatedSourceReadRequest({
            authenticationChunkIndex: 5,
            exactByteLength,
            sourceMaterialRootByte: 0x71,
            sourceStreamByteOffset: 64n,
            sourceStreamDigestByte: 0x72,
            sourceStreamTotalByteLength: 512n,
            storageByteOffset: 1024n,
        });
        const backingBytes = new Uint8Array(exactByteLength + 2).fill(0x83);
        const nonOwnedSourceRange = backingBytes.subarray(
            1,
            1 + exactByteLength,
        );
        let ingestionCount = 0;
        let retirementCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(44);
                writeUnsigned32(memory, statusPointer, 0);
                return 54;
            },
            sealed_lattice_common_proof_generation_authenticated_source_request_byte_length:
                () => authenticatedSourceRequestByteLength,
            sealed_lattice_common_proof_generation_copy_authenticated_source_request:
                (_operationHandle, outputPointer, outputByteLength) => {
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        encodedSourceRequest,
                    );
                    return 0;
                },
            sealed_lattice_common_proof_generation_poll: (
                _operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) =>
                writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    8,
                    exactByteLength,
                    5,
                ),
            sealed_lattice_common_proof_generation_supply_authenticated_source_range:
                () => {
                    ingestionCount += 1;
                    return 0;
                },
            sealed_lattice_common_proof_generation_retire_failed: () => {
                retirementCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                44,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    authenticatedSourceRangeReader: Object.freeze({
                        readExactRange: () =>
                            Promise.resolve(nonOwnedSourceRange),
                    }),
                },
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            permanentRetirementRequired: true,
        });
        expect([...nonOwnedSourceRange]).toEqual(
            Array(exactByteLength).fill(0),
        );
        expect(backingBytes[0]).toBe(0x83);
        expect(backingBytes[backingBytes.byteLength - 1]).toBe(0x83);
        expect(ingestionCount).toBe(0);
        expect(retirementCount).toBe(1);
    });

    it('rejects a hostile read length before copying and clears the transferred buffer', async () => {
        class CopyDetectingBytes extends Uint8Array {
            public copyAttempted = false;

            public override slice(
                start?: number,
                end?: number,
            ): Uint8Array<ArrayBuffer> {
                this.copyAttempted = true;
                return super.slice(start, end);
            }
        }

        const binding = runtimeBinding(0x47);
        const request = fourByteReadRequest(binding, 1n);
        let retiredOperationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(43);
                writeUnsigned32(memory, statusPointer, 0);
                return 53;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(53);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    request.byteLength,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(53);
                expect(outputByteLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    request,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(53);
                retiredOperationCount += 1;
                return 0;
            },
        }));
        const transferredBytes = new CopyDetectingBytes(5).fill(0xa7);

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                43,
                {
                    executeTransaction: () =>
                        Promise.resolve([
                            {
                                bytes: transferredBytes,
                                objectOrdinal: 7,
                                offset: 3n,
                                operationIndex: 0,
                            },
                        ]),
                },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'WrongStorageResult',
            permanentRetirementRequired: true,
        });
        expect(transferredBytes.copyAttempted).toBe(false);
        expect([...transferredBytes]).toEqual([0, 0, 0, 0, 0]);
        expect(retiredOperationCount).toBe(1);
    });

    it('retires a noncanonical generated-output chunk sequence before storage commit', async () => {
        let retiredOperationCount = 0;
        let outputCommitCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(44);
                writeUnsigned32(memory, statusPointer, 0);
                return 54;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(54);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    3,
                    1,
                    1,
                );
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(54);
                retiredOperationCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                44,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => {
                        outputCommitCount += 1;
                        return Promise.resolve();
                    },
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(outputCommitCount).toBe(0);
        expect(retiredOperationCount).toBe(1);
    });

    it('retires generation before committing a chunk after a short terminal chunk', async () => {
        let nextChunkIndex = 0;
        let retiredOperationCount = 0;
        const committedChunkIndices: number[] = [];
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(45);
                writeUnsigned32(memory, statusPointer, 0);
                return 55;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(55);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    3,
                    nextChunkIndex,
                    1,
                );
            },
            sealed_lattice_common_proof_generation_copy_output_chunk: (
                operationHandle,
                chunkIndex,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(55);
                expect(chunkIndex).toBe(nextChunkIndex);
                expect(outputByteLength).toBe(1);
                memoryBytes(memory, outputPointer, outputByteLength)[0] =
                    chunkIndex;
                return 0;
            },
            sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
                operationHandle,
                chunkIndex,
            ) => {
                expect(operationHandle).toBe(55);
                expect(chunkIndex).toBe(nextChunkIndex);
                nextChunkIndex += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(55);
                expect(nextChunkIndex).toBe(1);
                retiredOperationCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                45,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: (chunkIndex, chunkBytes) => {
                        expect([...chunkBytes]).toEqual([chunkIndex]);
                        committedChunkIndices.push(chunkIndex);
                        return Promise.resolve();
                    },
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(committedChunkIndices).toEqual([0]);
        expect(retiredOperationCount).toBe(1);
    });

    it('publishes and acknowledges a complete checkpoint before continuing', async () => {
        const fixture = createCheckpointGenerationKernelFixture();
        let publishedCheckpoint: CommonProofGenerationCheckpoint | undefined;
        let committedStateBytes: Uint8Array<ArrayBuffer> | undefined;
        let committedCursorBytes: Uint8Array<ArrayBuffer> | undefined;
        let committedStableAttemptBindingHash:
            | Uint8Array<ArrayBuffer>
            | undefined;
        const capability = await runPreparedCommonProofGenerationWorker(
            fixture.runtime,
            81,
            {
                executeTransaction: () =>
                    Promise.reject(
                        new Error(
                            'A checkpoint-only fixture has no storage request.',
                        ),
                    ),
            },
            {
                commitChunk: () =>
                    Promise.reject(
                        new Error(
                            'A checkpoint boundary emits no proof output.',
                        ),
                    ),
                readChunk: () =>
                    Promise.reject(
                        new Error(
                            'A checkpoint boundary reads no proof output.',
                        ),
                    ),
            },
            {
                checkpointCustody: {
                    publishAuthenticatedCheckpoint: (checkpoint) => {
                        publishedCheckpoint = checkpoint;
                        expect(checkpoint.safeBoundaryOrdinal).toBe(4);
                        committedStateBytes =
                            checkpoint.canonicalStateBytes.slice();
                        committedCursorBytes =
                            checkpoint.privateRandomCursorManifestBytes.slice();
                        committedStableAttemptBindingHash =
                            checkpoint.stableAttemptBindingHash.slice();
                        return Promise.resolve();
                    },
                    restoreAuthenticatedCheckpointState: () =>
                        Promise.reject(
                            new Error(
                                'Fresh generation does not restore state.',
                            ),
                        ),
                },
                yieldControl: () => Promise.resolve(),
            },
        );

        expect(fixture.observations.acknowledgedCheckpointCount).toBe(1);
        expect(fixture.observations.discardedCheckpointCount).toBe(0);
        expect(fixture.observations.retiredOperationCount).toBe(0);
        expect([...(committedStateBytes ?? [])]).toEqual([
            ...fixture.canonicalStateBytes,
        ]);
        expect([...(committedCursorBytes ?? [])]).toEqual([
            ...fixture.cursorManifestBytes,
        ]);
        expect([...(committedStableAttemptBindingHash ?? [])]).toEqual([
            ...fixture.stableAttemptBindingHash,
        ]);
        expect(publishedCheckpoint).toBeDefined();
        if (publishedCheckpoint === undefined) {
            throw new Error('The checkpoint was not published.');
        }
        expect([...publishedCheckpoint.canonicalStateBytes]).toEqual(
            Array(fixture.canonicalStateBytes.byteLength).fill(0),
        );
        expect([
            ...publishedCheckpoint.privateRandomCursorManifestBytes,
        ]).toEqual(Array(fixture.cursorManifestBytes.byteLength).fill(0));
        expect([...publishedCheckpoint.stableAttemptBindingHash]).toEqual(
            Array(hashByteLength).fill(0),
        );
        capability.release();
    });

    it('explicitly discards a ready checkpoint when custody is absent', async () => {
        const fixture = createCheckpointGenerationKernelFixture();
        const capability = await runPreparedCommonProofGenerationWorker(
            fixture.runtime,
            81,
            {
                executeTransaction: () => Promise.resolve([]),
            },
            {
                commitChunk: () => Promise.resolve(),
                readChunk: () => Promise.resolve(new Uint8Array()),
            },
            { yieldControl: () => Promise.resolve() },
        );

        expect(fixture.observations.acknowledgedCheckpointCount).toBe(0);
        expect(fixture.observations.discardedCheckpointCount).toBe(1);
        expect(fixture.observations.retiredOperationCount).toBe(0);
        capability.release();
    });

    it('permanently retires an ambiguous checkpoint publication and wipes the snapshot', async () => {
        const fixture = createCheckpointGenerationKernelFixture();
        const publicationError = new Error(
            'IndexedDB committed but its response was lost',
        );
        let attemptedCheckpoint: CommonProofGenerationCheckpoint | undefined;

        await expect(
            runPreparedCommonProofGenerationWorker(
                fixture.runtime,
                81,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: (checkpoint) => {
                            attemptedCheckpoint = checkpoint;
                            return Promise.reject(publicationError);
                        },
                        restoreAuthenticatedCheckpointState: () =>
                            Promise.reject(
                                new Error(
                                    'Fresh generation does not restore state.',
                                ),
                            ),
                    },
                    yieldControl: () => Promise.resolve(),
                },
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            failureCause: publicationError,
            permanentRetirementRequired: true,
        });
        expect(fixture.observations.acknowledgedCheckpointCount).toBe(0);
        expect(fixture.observations.discardedCheckpointCount).toBe(0);
        expect(fixture.observations.retiredOperationCount).toBe(1);
        expect(attemptedCheckpoint).toBeDefined();
        if (attemptedCheckpoint === undefined) {
            throw new Error('The checkpoint publication was not attempted.');
        }
        expect([...attemptedCheckpoint.canonicalStateBytes]).toEqual(
            Array(fixture.canonicalStateBytes.byteLength).fill(0),
        );
        expect([...attemptedCheckpoint.stableAttemptBindingHash]).toEqual(
            Array(hashByteLength).fill(0),
        );
    });

    it('retires a checkpoint whose cursor corpus exceeds the aggregate worker bound', async () => {
        const fixture = createCheckpointGenerationKernelFixture(
            new Uint8Array(1_048_577).fill(0x31),
        );
        let publicationAttempted = false;

        await expect(
            runPreparedCommonProofGenerationWorker(
                fixture.runtime,
                81,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: () => {
                            publicationAttempted = true;
                            return Promise.resolve();
                        },
                        restoreAuthenticatedCheckpointState: () =>
                            Promise.reject(
                                new Error('A fresh operation cannot restore.'),
                            ),
                    },
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(publicationAttempted).toBe(false);
        expect(fixture.observations.acknowledgedCheckpointCount).toBe(0);
        expect(fixture.observations.retiredOperationCount).toBe(1);
    });

    it('replays a lost-response transaction exactly once before resumed output', async () => {
        const binding = runtimeBinding(0x57);
        const replayRequest = encodeRequest({
            maximumPayloadByteLength: 2n,
            operations: [
                {
                    kind: 2,
                    objectOrdinal: 12,
                    payload: Uint8Array.from([4, 2]),
                    payloadByteLength: 2n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 1n,
            runtimeBindingHash: binding,
        });
        const liveRequest = fourByteReadRequest(binding, 2n);
        const authenticatedCheckpointState = Uint8Array.from([
            11, 7, 5, 3, 2, 13, 17, 19,
        ]);
        const expectedOutputBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
        let phase = 0;
        let releasedCapabilityCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(72);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).set(binding);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x58);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x59);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_prepare_generation_family_adapter: (
                adapterHandle,
                checkpointPointer,
                checkpointByteLength,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(72);
                expect([
                    ...memoryBytes(
                        memory,
                        checkpointPointer,
                        checkpointByteLength,
                    ),
                ]).toEqual([...authenticatedCheckpointState]);
                writeUnsigned32(memory, statusPointer, 0);
                return 82;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: () =>
                0,
            sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
                () => authenticatedCheckpointState.byteLength,
            sealed_lattice_common_proof_begin_generation: () => {
                throw new Error('Resume must not open a fresh operation.');
            },
            sealed_lattice_common_proof_resume_generation: (
                preparedGenerationHandle,
                checkpointPointer,
                checkpointByteLength,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(82);
                expect([
                    ...memoryBytes(
                        memory,
                        checkpointPointer,
                        checkpointByteLength,
                    ),
                ]).toEqual([...authenticatedCheckpointState]);
                writeUnsigned32(memory, statusPointer, 0);
                return 92;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(92);
                if (phase === 0) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        replayRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 1) {
                    phase = 2;
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        7,
                        4,
                        noSecondPollValue,
                    );
                }
                if (phase === 2) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        liveRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 3) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        3,
                        0,
                        expectedOutputBytes.byteLength,
                    );
                }
                if (phase === 4) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        4,
                        0,
                        noSecondPollValue,
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    5,
                    0,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(92);
                const request = phase === 0 ? replayRequest : liveRequest;
                expect(outputByteLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    request,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_supply_storage_response: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(92);
                expect([0, 2]).toContain(phase);
                phase += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_copy_output_chunk: (
                operationHandle,
                chunkIndex,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(92);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(3);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    expectedOutputBytes,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
                operationHandle,
                chunkIndex,
            ) => {
                expect(operationHandle).toBe(92);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(3);
                phase = 4;
                return 0;
            },
            sealed_lattice_common_proof_generation_confirm_output_readback: (
                operationHandle,
                chunkIndex,
                readbackPointer,
                readbackByteLength,
            ) => {
                expect(operationHandle).toBe(92);
                expect(chunkIndex).toBe(0);
                expect(phase).toBe(4);
                expect([
                    ...memoryBytes(memory, readbackPointer, readbackByteLength),
                ]).toEqual([...expectedOutputBytes]);
                phase = 5;
                return 0;
            },
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(92);
                expect(phase).toBe(5);
                writeUnsigned32(memory, statusPointer, 0);
                return 102;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(102);
                releasedCapabilityCount += 1;
                return 0;
            },
        }));
        const committedReplayRequest = decodeCommonProofExternalMemoryRequest(
            replayRequest.slice(),
        );
        const underlyingWriteCount = 1;
        let prefixReplayCount = 0;
        let liveTransactionCount = 0;
        let committedOutputBytes: Uint8Array<ArrayBuffer> | undefined;
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 72);
        await runClosedWorkerCommonProofGenerationFamilyAdapter(
            familyAdapter,
            {
                executeTransaction: (request) => {
                    liveTransactionCount += 1;
                    expect(request.requestSequence).toBe(2n);
                    return Promise.resolve([
                        readResult(0, 7, 3n, [1, 1, 2, 3]),
                    ]);
                },
            },
            {
                commitChunk: (chunkIndex, chunkBytes) => {
                    expect(chunkIndex).toBe(0);
                    committedOutputBytes = chunkBytes.slice();
                    return Promise.resolve();
                },
                readChunk: (_chunkIndex, exactByteLength) => {
                    expect(exactByteLength).toBe(
                        expectedOutputBytes.byteLength,
                    );
                    return Promise.resolve(
                        committedOutputBytes?.slice() ?? new Uint8Array(),
                    );
                },
            },
            {
                resume: {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: () =>
                            Promise.reject(
                                new Error(
                                    'The fixture emits no later checkpoint.',
                                ),
                            ),
                        restoreAuthenticatedCheckpointState: () =>
                            Promise.resolve(
                                authenticatedCheckpointState.slice(),
                            ),
                    },
                    prefixReplayExternalMemory: {
                        executeDeterministicPrefixReplayTransaction: (
                            request,
                        ) => {
                            prefixReplayCount += 1;
                            expect(request.requestSequence).toBe(1n);
                            expect([...request.requestDigest]).toEqual([
                                ...committedReplayRequest.requestDigest,
                            ]);
                            return Promise.resolve([]);
                        },
                    },
                },
                yieldControl: () => Promise.resolve(),
            },
        );

        expect(underlyingWriteCount).toBe(1);
        expect(prefixReplayCount).toBe(1);
        expect(liveTransactionCount).toBe(1);
        expect([...(committedOutputBytes ?? [])]).toEqual([
            ...expectedOutputBytes,
        ]);
        expect(releasedCapabilityCount).toBe(1);
    });

    it('authenticates checkpoint custody before preparing resumed family generation', async () => {
        const restorationError = new Error('Encrypted checkpoint is missing');
        let adapterDiscardCount = 0;
        let preparationCount = 0;
        let resumeCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(73);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(73);
                adapterDiscardCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
                () => 37,
            sealed_lattice_common_proof_prepare_generation_family_adapter:
                () => {
                    preparationCount += 1;
                    return 83;
                },
            sealed_lattice_common_proof_resume_generation: (
                _preparedGenerationHandle,
                _checkpointPointer,
                _checkpointByteLength,
                _statusPointer,
            ) => {
                resumeCount += 1;
                return 0;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 73);

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                {
                    resume: {
                        checkpointCustody: {
                            publishAuthenticatedCheckpoint: () =>
                                Promise.resolve(),
                            restoreAuthenticatedCheckpointState: () =>
                                Promise.reject(restorationError),
                        },
                        prefixReplayExternalMemory: {
                            executeDeterministicPrefixReplayTransaction: () =>
                                Promise.resolve([]),
                        },
                    },
                },
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            failureCause: restorationError,
            permanentRetirementRequired: true,
        });
        expect(adapterDiscardCount).toBe(1);
        expect(preparationCount).toBe(0);
        expect(resumeCount).toBe(0);
    });

    it('discards generation family authority when preparation fails before the FFI call', async () => {
        let adapterDiscardCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(74);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(74);
                adapterDiscardCount += 1;
                return 0;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 74);

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            message:
                'Common-proof generation preparation consumed its exact deferred family authority and permanently retired the attempt.',
            permanentRetirementRequired: true,
        });
        expect(adapterDiscardCount).toBe(1);
    });

    it('permanently retires a generation adapter when its resume accessor throws', async () => {
        const optionError = new Error('Injected resume option accessor.');
        let adapterDiscardCount = 0;
        let preparationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(77);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(77);
                adapterDiscardCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_prepare_generation_family_adapter:
                () => {
                    preparationCount += 1;
                    return 0;
                },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 77);
        const options = Object.create(null, {
            resume: {
                get: () => {
                    throw optionError;
                },
            },
        }) as CommonProofGenerationWorkerOptions;

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
                options,
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            message:
                'The common-proof generation adapter could not adopt its worker options and was permanently retired.',
            permanentRetirementRequired: true,
        });
        expect(adapterDiscardCount).toBe(1);
        expect(preparationCount).toBe(0);
    });

    it('discards transferred family authority when adoption fails before description', () => {
        const firstUnsafeWasmMemoryByteLength = 671_088_641;
        let adapterDescriptionCount = 0;
        let adapterDiscardCount = 0;
        const runtime = createMockKernelRuntime((_memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                _adapterHandle,
                _runtimeBindingHashOutputPointer,
                _verificationBindingHashOutputPointer,
                _proofAttemptLineageIdentifierOutputPointer,
                _statusPointer,
            ) => {
                adapterDescriptionCount += 1;
                return 0;
            },
            sealed_lattice_common_proof_discard_generation_family_adapter: (
                adapterHandle,
            ) => {
                expect(adapterHandle).toBe(75);
                adapterDiscardCount += 1;
                return 0;
            },
        }));
        const unsafeMemoryContext = {
            ...runtime,
            memory: {
                buffer: { byteLength: firstUnsafeWasmMemoryByteLength },
            } as WebAssembly.Memory,
        } as TranscriptCoreKernelCommandRuntime;

        expect(() =>
            openClosedWorkerCommonProofGenerationFamilyAdapter(
                unsafeMemoryContext,
                75,
            ),
        ).toThrowError(expect.objectContaining({ code: 'ResourceLimit' }));
        expect(adapterDescriptionCount).toBe(0);
        expect(adapterDiscardCount).toBe(1);
    });

    it('requires permanent retirement when generated capability release fails', async () => {
        let generatedCapabilityReleaseCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_describe_generation_family_adapter: (
                adapterHandle,
                runtimeBindingHashOutputPointer,
                verificationBindingHashOutputPointer,
                proofAttemptLineageIdentifierOutputPointer,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(76);
                memoryBytes(
                    memory,
                    runtimeBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x11);
                memoryBytes(
                    memory,
                    verificationBindingHashOutputPointer,
                    hashByteLength,
                ).fill(0x22);
                memoryBytes(
                    memory,
                    proofAttemptLineageIdentifierOutputPointer,
                    32,
                ).fill(0x33);
                writeUnsigned32(memory, statusPointer, 0);
                return 0;
            },
            sealed_lattice_common_proof_prepare_generation_family_adapter: (
                adapterHandle,
                checkpointPointer,
                checkpointByteLength,
                statusPointer,
            ) => {
                expect(adapterHandle).toBe(76);
                expect(checkpointPointer).toBe(0);
                expect(checkpointByteLength).toBe(0);
                writeUnsigned32(memory, statusPointer, 0);
                return 86;
            },
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(86);
                writeUnsigned32(memory, statusPointer, 0);
                return 96;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(96);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    5,
                    0,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_finish: (
                operationHandle,
                statusPointer,
            ) => {
                expect(operationHandle).toBe(96);
                writeUnsigned32(memory, statusPointer, 0);
                return 106;
            },
            sealed_lattice_common_proof_release_generated_proof: (
                capabilityHandle,
            ) => {
                expect(capabilityHandle).toBe(106);
                generatedCapabilityReleaseCount += 1;
                return 0x0001_0001;
            },
        }));
        const familyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(runtime, 76);

        await expect(
            runClosedWorkerCommonProofGenerationFamilyAdapter(
                familyAdapter,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(generatedCapabilityReleaseCount).toBe(1);
    });

    it('retires generation authority and preserves the browser storage failure', async () => {
        const binding = runtimeBinding(0x43);
        const request = fourByteReadRequest(binding, 1n);
        const storageError = new Error('IndexedDB transaction aborted');
        let retirementCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(43);
                writeUnsigned32(memory, statusPointer, 0);
                return 53;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(53);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    request.byteLength,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(53);
                expect(outputLength).toBe(request.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(request);
                return 0;
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(53);
                retirementCount += 1;
                return retirementCount === 1 ? 0 : 1;
            },
            sealed_lattice_common_proof_generation_request_cancellation: () => {
                throw new Error(
                    'A failed browser transaction cannot enter graceful cancellation.',
                );
            },
        }));
        const externalMemory: CommonProofExternalMemoryTransactionExecutor = {
            executeTransaction: () => Promise.reject(storageError),
        };
        const unusedOutputStore: CommonProofCanonicalOutputStore = {
            commitChunk: () =>
                Promise.reject(
                    new Error('A failed transaction emits no output.'),
                ),
            readChunk: () =>
                Promise.reject(
                    new Error('A failed transaction has no output.'),
                ),
        };

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                43,
                externalMemory,
                unusedOutputStore,
            ),
        ).rejects.toMatchObject({
            code: 'StorageFailure',
            failureCause: storageError,
            permanentRetirementRequired: true,
        });
        expect(retirementCount).toBe(1);
    });

    it('retires generation authority when finish fails before Rust consumes the operation', async () => {
        let retirementCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(44);
                writeUnsigned32(memory, statusPointer, 0);
                return 54;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(54);
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    5,
                    0,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_retire_failed: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(54);
                retirementCount += 1;
                return 0;
            },
        }));

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                44,
                { executeTransaction: () => Promise.resolve([]) },
                {
                    commitChunk: () => Promise.resolve(),
                    readChunk: () => Promise.resolve(new Uint8Array()),
                },
            ),
        ).rejects.toMatchObject({
            code: 'KernelFailure',
            permanentRetirementRequired: true,
        });
        expect(retirementCount).toBe(1);
    });

    it('finishes an issued transaction and drives cleanup after cancellation', async () => {
        const binding = runtimeBinding(0x42);
        const generationRequest = fourByteReadRequest(binding, 1n);
        const cleanupRequest = encodeRequest({
            maximumPayloadByteLength: 1n,
            operations: [
                {
                    kind: 5,
                    objectOrdinal: 7,
                    payloadByteLength: 0n,
                    position: 0n,
                    protection: 0,
                },
            ],
            requestSequence: 2n,
            runtimeBindingHash: binding,
        });
        let phase = 0;
        let cancellationRequested = false;
        let cleanupRequestObservedAfterCancellation = false;
        let cancelledOperationReleased = false;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_begin_generation: (
                preparedGenerationHandle,
                statusPointer,
            ) => {
                expect(preparedGenerationHandle).toBe(42);
                writeUnsigned32(memory, statusPointer, 0);
                return 52;
            },
            sealed_lattice_common_proof_generation_poll: (
                operationHandle,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
            ) => {
                expect(operationHandle).toBe(52);
                if (phase === 0) {
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        generationRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                if (phase === 1) {
                    cleanupRequestObservedAfterCancellation =
                        cancellationRequested;
                    return writeGenerationPoll(
                        memory,
                        pollKindPointer,
                        primaryValuePointer,
                        secondaryValuePointer,
                        2,
                        cleanupRequest.byteLength,
                        noSecondPollValue,
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    6,
                    0,
                    noSecondPollValue,
                );
            },
            sealed_lattice_common_proof_generation_copy_storage_request: (
                operationHandle,
                outputPointer,
                outputLength,
            ) => {
                expect(operationHandle).toBe(52);
                const currentRequest =
                    phase === 0 ? generationRequest : cleanupRequest;
                expect(outputLength).toBe(currentRequest.byteLength);
                memoryBytes(memory, outputPointer, outputLength).set(
                    currentRequest,
                );
                return 0;
            },
            sealed_lattice_common_proof_generation_supply_storage_response: (
                operationHandle,
                _responsePointer,
                _responseLength,
            ) => {
                expect(operationHandle).toBe(52);
                phase += 1;
                return 0;
            },
            sealed_lattice_common_proof_generation_request_cancellation: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(52);
                expect(phase).toBe(1);
                cancellationRequested = true;
                return 0;
            },
            sealed_lattice_common_proof_generation_release_cancelled: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(52);
                expect(phase).toBe(2);
                cancelledOperationReleased = true;
                return 0;
            },
        }));
        const controller = new AbortController();
        let transactionCount = 0;
        const observedRequestSequences: bigint[] = [];
        const externalMemory: CommonProofExternalMemoryTransactionExecutor = {
            executeTransaction: (requestValue) => {
                transactionCount += 1;
                observedRequestSequences.push(requestValue.requestSequence);
                if (requestValue.requestSequence === 1n) {
                    controller.abort('participant cancelled');
                    return Promise.resolve([
                        readResult(0, 7, 3n, [1, 2, 3, 4]),
                    ]);
                }
                return Promise.resolve([]);
            },
        };
        const unusedOutputStore: CommonProofCanonicalOutputStore = {
            commitChunk: () =>
                Promise.reject(new Error('Cancellation must not emit output.')),
            readChunk: () =>
                Promise.reject(new Error('Cancellation must not read output.')),
        };

        await expect(
            runPreparedCommonProofGenerationWorker(
                runtime,
                42,
                externalMemory,
                unusedOutputStore,
                { signal: controller.signal },
            ),
        ).rejects.toMatchObject({ code: 'Cancelled' });
        expect(transactionCount).toBe(2);
        expect(observedRequestSequences).toEqual([1n, 2n]);
        expect(cancellationRequested).toBe(true);
        expect(cleanupRequestObservedAfterCancellation).toBe(true);
        expect(cancelledOperationReleased).toBe(true);
    });
});
