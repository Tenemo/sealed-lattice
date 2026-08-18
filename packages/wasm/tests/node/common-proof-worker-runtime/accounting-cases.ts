import { describe, expect, it } from 'vitest';

import {
    CommonProofGenerationKernelBoundary,
    CommonProofVerificationKernelBoundary,
} from '../../../src/common-proof-worker-runtime/kernel-boundaries.js';
import { verifyCompactPublicKeyAlgebraicallyInClosedWorker } from '../../../src/common-proof-worker-runtime/runtime.js';

import {
    createMockKernelRuntime,
    memoryBytes,
    writeUnsigned32,
} from './kernel-fixtures.js';

const encodeUnsigned64Words = (
    values: readonly bigint[],
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(values.length * 8);
    const view = new DataView(bytes.buffer);
    for (const [wordIndex, value] of values.entries()) {
        view.setBigUint64(wordIndex * 8, value, true);
    }
    return bytes;
};

const generationAccountingWords = Object.freeze([
    12n,
    1_048_576n,
    1_048_576n,
    4n,
    6n,
    1_000n,
    2_000n,
    3_000n,
    40n,
    2_000n,
    2_500n,
    900n,
    35n,
    6n,
    1n,
    800n,
    1_100n,
    700n,
    16n,
    2n,
]);

const generationAccountingWordsWith = (
    wordIndex: number,
    value: bigint,
): readonly bigint[] =>
    generationAccountingWords.map((word, index) =>
        index === wordIndex ? value : word,
    );

const freshGenerationAccountingWords = generationAccountingWords.map(
    (word, wordIndex) => (wordIndex >= 14 ? 0n : word),
);

describe('Common-proof manual accounting boundaries', () => {
    it('decodes compiled, terminal, and resumed-prefix generation usage exactly', () => {
        const encoded = encodeUnsigned64Words(generationAccountingWords);
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_generation_external_memory_accounting_byte_length:
                () => encoded.byteLength,
            sealed_lattice_common_proof_generation_copy_external_memory_accounting:
                (operationHandle, outputPointer, outputByteLength) => {
                    expect(operationHandle).toBe(71);
                    expect(outputByteLength).toBe(encoded.byteLength);
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        encoded,
                    );
                    return 0;
                },
        }));

        expect(
            new CommonProofGenerationKernelBoundary(
                runtime,
            ).externalMemoryAccounting(71),
        ).toEqual({
            actualUsage: {
                deletedObjectLifecycleCount: 6n,
                peakStoredByteLength: 900n,
                totalReadByteLength: 2_500n,
                totalWrittenByteLength: 2_000n,
                transactionCount: 35n,
            },
            compiledRequirement: {
                maximumChunkByteLength: 1_048_576,
                maximumTransactionPayloadByteLength: 1_048_576n,
                distinctPhysicalObjectCount: 4,
                objectLifecycleCount: 6,
                peakStoredByteLength: 1_000n,
                stepCount: 12,
                totalReadByteLength: 3_000n,
                totalWrittenByteLength: 2_000n,
                transactionCount: 40n,
            },
            deterministicPrefixReplayUsage: {
                deletedObjectLifecycleCount: 2n,
                peakStoredByteLength: 700n,
                totalReadByteLength: 1_100n,
                totalWrittenByteLength: 800n,
                transactionCount: 16n,
            },
        });
    });

    it('keeps fresh generation distinct from a resumed zero-traffic prefix', () => {
        const encoded = encodeUnsigned64Words(freshGenerationAccountingWords);
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_generation_external_memory_accounting_byte_length:
                () => encoded.byteLength,
            sealed_lattice_common_proof_generation_copy_external_memory_accounting:
                (_operationHandle, outputPointer, outputByteLength) => {
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        encoded,
                    );
                    return 0;
                },
        }));

        expect(
            new CommonProofGenerationKernelBoundary(
                runtime,
            ).externalMemoryAccounting(71).deterministicPrefixReplayUsage,
        ).toBeUndefined();
    });

    it.each([
        { words: generationAccountingWordsWith(13, 3n) },
        { words: generationAccountingWordsWith(15, 2_001n) },
        { words: generationAccountingWordsWith(14, 0n) },
        { words: generationAccountingWordsWith(5, 1_073_741_825n) },
    ])('rejects inconsistent or over-bound generation usage', ({ words }) => {
        const encoded = encodeUnsigned64Words(words);
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_generation_external_memory_accounting_byte_length:
                () => encoded.byteLength,
            sealed_lattice_common_proof_generation_copy_external_memory_accounting:
                (_operationHandle, outputPointer, outputByteLength) => {
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        encoded,
                    );
                    return 0;
                },
        }));

        expect(() =>
            new CommonProofGenerationKernelBoundary(
                runtime,
            ).externalMemoryAccounting(71),
        ).toThrow(/external-memory (?:accounting|usage)/u);
    });

    it('preserves unsigned 64-bit verifier traversal counters without number coercion', () => {
        const encoded = encodeUnsigned64Words([
            91n,
            9_007_199_254_740_999n,
            143n,
            9_007_199_254_741_777n,
        ]);
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_common_proof_verification_readback_accounting_byte_length:
                () => encoded.byteLength,
            sealed_lattice_common_proof_verification_copy_readback_accounting: (
                operationHandle,
                outputPointer,
                outputByteLength,
            ) => {
                expect(operationHandle).toBe(81);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    encoded,
                );
                return 0;
            },
        }));

        expect(
            new CommonProofVerificationKernelBoundary(
                runtime,
            ).readbackAccounting(81),
        ).toEqual({
            logicalRequiredByteLength: 9_007_199_254_740_999n,
            logicalRequiredRangeCount: 91n,
            suppliedFullChunkByteLength: 9_007_199_254_741_777n,
            suppliedFullChunkCount: 143n,
        });
    });

    it('rejects diagnostic records with a non-exact kernel length', () => {
        const runtime = createMockKernelRuntime(() => ({
            sealed_lattice_common_proof_verification_readback_accounting_byte_length:
                () => 31,
        }));

        expect(() =>
            new CommonProofVerificationKernelBoundary(
                runtime,
            ).readbackAccounting(81),
        ).toThrow(/malformed verification readback accounting length/u);
    });
});

describe('Compact public-key transport boundary', () => {
    const bindings = Object.freeze({
        suiteIdentifier: new Uint8Array(64).fill(0x11),
        applicationStatementHash: new Uint8Array(64).fill(0x22),
        manifestHash: new Uint8Array(64).fill(0x33),
        relationPlanHash: new Uint8Array(64).fill(0x44),
    });

    it('passes the exact binding order and transported bytes to the release export', () => {
        const proofBytes = Uint8Array.of(0x51, 0x52, 0x53);
        const publicInputBytes = Uint8Array.of(0x61, 0x62);
        const releasedRanges: Array<
            Readonly<{ byteLength: number; pointer: number }>
        > = [];
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_validate_transport: (
                bindingsPointer,
                bindingsByteLength,
                proofPointer,
                proofByteLength,
                publicInputPointer,
                publicInputByteLength,
            ) => {
                expect(bindingsByteLength).toBe(256);
                expect(
                    memoryBytes(memory, bindingsPointer, bindingsByteLength),
                ).toEqual(
                    new Uint8Array([
                        ...bindings.suiteIdentifier,
                        ...bindings.applicationStatementHash,
                        ...bindings.manifestHash,
                        ...bindings.relationPlanHash,
                    ]),
                );
                expect(
                    memoryBytes(memory, proofPointer, proofByteLength),
                ).toEqual(proofBytes);
                expect(
                    memoryBytes(
                        memory,
                        publicInputPointer,
                        publicInputByteLength,
                    ),
                ).toEqual(publicInputBytes);
                releasedRanges.push(
                    {
                        pointer: bindingsPointer,
                        byteLength: bindingsByteLength,
                    },
                    { pointer: proofPointer, byteLength: proofByteLength },
                    {
                        pointer: publicInputPointer,
                        byteLength: publicInputByteLength,
                    },
                );
                return 0;
            },
        }));

        new CommonProofVerificationKernelBoundary(
            runtime,
        ).validateCompactPublicKeyTransport(
            bindings,
            proofBytes,
            publicInputBytes,
        );

        for (const range of releasedRanges) {
            expect(
                memoryBytes(runtime.memory, range.pointer, range.byteLength),
            ).toEqual(new Uint8Array(range.byteLength));
        }
    });

    it('rejects malformed binding widths before invoking the kernel', () => {
        let invocationCount = 0;
        const runtime = createMockKernelRuntime(() => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_validate_transport: () => {
                invocationCount += 1;
                return 0;
            },
        }));

        expect(() =>
            new CommonProofVerificationKernelBoundary(
                runtime,
            ).validateCompactPublicKeyTransport(
                {
                    ...bindings,
                    manifestHash: new Uint8Array(63),
                },
                Uint8Array.of(1),
                Uint8Array.of(2),
            ),
        ).toThrow(/exactly 64 bytes/u);
        expect(invocationCount).toBe(0);
    });

    it.each([
        ['proof', new Uint8Array(), Uint8Array.of(2)],
        ['public input', Uint8Array.of(1), new Uint8Array()],
    ])(
        'rejects an empty %s before invoking the kernel',
        (_label, proofBytes, publicInputBytes) => {
            let invocationCount = 0;
            const runtime = createMockKernelRuntime(() => ({
                sealed_lattice_compact_public_key_transport_bindings_byte_length:
                    () => 256,
                sealed_lattice_compact_public_key_validate_transport: () => {
                    invocationCount += 1;
                    return 0;
                },
            }));

            expect(() =>
                new CommonProofVerificationKernelBoundary(
                    runtime,
                ).validateCompactPublicKeyTransport(
                    bindings,
                    proofBytes,
                    publicInputBytes,
                ),
            ).toThrow(/must be nonempty/u);
            expect(invocationCount).toBe(0);
        },
    );

    it.each([255, 257])(
        'rejects a kernel binding geometry of %i bytes',
        (bindingByteLength) => {
            const runtime = createMockKernelRuntime(() => ({
                sealed_lattice_compact_public_key_transport_bindings_byte_length:
                    () => bindingByteLength,
            }));
            expect(() =>
                new CommonProofVerificationKernelBoundary(
                    runtime,
                ).validateCompactPublicKeyTransport(
                    bindings,
                    Uint8Array.of(1),
                    Uint8Array.of(2),
                ),
            ).toThrow(/binding geometry disagrees/u);
        },
    );

    it('propagates a typed kernel refusal without treating it as acceptance', () => {
        const runtime = createMockKernelRuntime(() => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_validate_transport: () => 0x0006,
        }));

        expect(() =>
            new CommonProofVerificationKernelBoundary(
                runtime,
            ).validateCompactPublicKeyTransport(
                bindings,
                Uint8Array.of(1),
                Uint8Array.of(2),
            ),
        ).toThrow(/status 6/u);
    });
});

describe('Compact public-key algebraic verification worker', () => {
    const bindings = Object.freeze({
        suiteIdentifier: new Uint8Array(64).fill(0x11),
        applicationStatementHash: new Uint8Array(64).fill(0x22),
        manifestHash: new Uint8Array(64).fill(0x33),
        relationPlanHash: new Uint8Array(64).fill(0x44),
    });
    const proofBytes = Uint8Array.of(0x51, 0x52, 0x53);
    const publicInputBytes = Uint8Array.of(0x61, 0x62);

    it('drives bounded progress to one typed positive result without cancellation', async () => {
        let pollCount = 0;
        let cancellationCount = 0;
        let yieldCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                bindingsPointer,
                bindingsByteLength,
                proofPointer,
                proofByteLength,
                publicInputPointer,
                publicInputByteLength,
                statusPointer,
            ) => {
                expect(bindingsByteLength).toBe(256);
                expect(
                    memoryBytes(memory, bindingsPointer, bindingsByteLength),
                ).toEqual(
                    new Uint8Array([
                        ...bindings.suiteIdentifier,
                        ...bindings.applicationStatementHash,
                        ...bindings.manifestHash,
                        ...bindings.relationPlanHash,
                    ]),
                );
                expect(
                    memoryBytes(memory, proofPointer, proofByteLength),
                ).toEqual(proofBytes);
                expect(
                    memoryBytes(
                        memory,
                        publicInputPointer,
                        publicInputByteLength,
                    ),
                ).toEqual(publicInputBytes);
                writeUnsigned32(memory, statusPointer, 0);
                return 91;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: (
                operationHandle,
                maximumWorkUnitCount,
                pollKindPointer,
                completedWorkUnitCountPointer,
            ) => {
                expect(operationHandle).toBe(91);
                expect(maximumWorkUnitCount).toBe(17);
                pollCount += 1;
                writeUnsigned32(
                    memory,
                    pollKindPointer,
                    pollCount === 1 ? 1 : 5,
                );
                writeUnsigned32(
                    memory,
                    completedWorkUnitCountPointer,
                    pollCount === 1 ? 17 : 0,
                );
                return 0;
            },
            sealed_lattice_compact_public_key_cancel_algebraic_verification:
                () => {
                    cancellationCount += 1;
                    return 0;
                },
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    maximumWorkUnitCountPerPoll: 17,
                    yieldControl: () => {
                        yieldCount += 1;
                        return Promise.resolve();
                    },
                },
            ),
        ).resolves.toEqual({ isValid: true, value: undefined });
        expect(pollCount).toBe(2);
        expect(yieldCount).toBe(1);
        expect(cancellationCount).toBe(0);
    });

    it('publishes the exact source-bound cursor after live bounded progress', async () => {
        const canonicalCheckpointBytes = new Uint8Array(400).fill(0x71);
        let copiedCheckpointCount = 0;
        let publishedCheckpointBytes: Uint8Array | undefined;
        let pollCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length:
                () => canonicalCheckpointBytes.byteLength,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                statusPointer,
            ) => {
                writeUnsigned32(memory, statusPointer, 0);
                return 95;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: (
                operationHandle,
                _maximumWorkUnitCount,
                pollKindPointer,
                completedWorkUnitCountPointer,
            ) => {
                expect(operationHandle).toBe(95);
                pollCount += 1;
                writeUnsigned32(
                    memory,
                    pollKindPointer,
                    pollCount === 1 ? 1 : 5,
                );
                writeUnsigned32(
                    memory,
                    completedWorkUnitCountPointer,
                    pollCount === 1 ? 9 : 0,
                );
                return 0;
            },
            sealed_lattice_compact_public_key_copy_algebraic_verification_checkpoint:
                (
                    operationHandle: number,
                    outputPointer: number,
                    outputByteLength: number,
                ) => {
                    expect(operationHandle).toBe(95);
                    expect(outputByteLength).toBe(400);
                    copiedCheckpointCount += 1;
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        canonicalCheckpointBytes,
                    );
                    return 0;
                },
            sealed_lattice_compact_public_key_cancel_algebraic_verification:
                () => 0,
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: (
                            checkpointBytes: Uint8Array<ArrayBuffer>,
                        ) => {
                            publishedCheckpointBytes = checkpointBytes.slice();
                            return Promise.resolve();
                        },
                        restoreAuthenticatedCheckpoint: () => {
                            throw new Error(
                                'Fresh verification must not restore.',
                            );
                        },
                    },
                    maximumWorkUnitCountPerPoll: 9,
                },
            ),
        ).resolves.toEqual({ isValid: true, value: undefined });
        expect(copiedCheckpointCount).toBe(1);
        expect(publishedCheckpointBytes).toEqual(canonicalCheckpointBytes);
    });

    it('restores at genesis, replays without publishing, and resumes live checkpointing', async () => {
        const restoredCheckpointBytes = new Uint8Array(400).fill(0x72);
        const nextCheckpointBytes = new Uint8Array(400).fill(0x73);
        let beginCount = 0;
        let copiedCheckpointCount = 0;
        let pollCount = 0;
        let publishedCheckpointBytes: Uint8Array | undefined;
        let yieldCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length:
                () => 400,
            sealed_lattice_compact_public_key_begin_algebraic_verification:
                () => {
                    beginCount += 1;
                    return 0;
                },
            sealed_lattice_compact_public_key_resume_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                checkpointPointer: number,
                checkpointByteLength: number,
                statusPointer: number,
            ) => {
                expect(checkpointByteLength).toBe(400);
                expect(
                    memoryBytes(
                        memory,
                        checkpointPointer,
                        checkpointByteLength,
                    ),
                ).toEqual(restoredCheckpointBytes);
                writeUnsigned32(memory, statusPointer, 0);
                return 96;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: (
                operationHandle,
                maximumWorkUnitCount,
                pollKindPointer,
                completedWorkUnitCountPointer,
            ) => {
                expect(operationHandle).toBe(96);
                expect(maximumWorkUnitCount).toBe(5);
                pollCount += 1;
                const pollKind = [1, 7, 1, 5][pollCount - 1];
                const completedWorkUnitCount = [5, 3, 2, 0][pollCount - 1];
                writeUnsigned32(memory, pollKindPointer, pollKind);
                writeUnsigned32(
                    memory,
                    completedWorkUnitCountPointer,
                    completedWorkUnitCount,
                );
                return 0;
            },
            sealed_lattice_compact_public_key_copy_algebraic_verification_checkpoint:
                (
                    operationHandle: number,
                    outputPointer: number,
                    outputByteLength: number,
                ) => {
                    expect(operationHandle).toBe(96);
                    copiedCheckpointCount += 1;
                    memoryBytes(memory, outputPointer, outputByteLength).set(
                        nextCheckpointBytes,
                    );
                    return 0;
                },
            sealed_lattice_compact_public_key_cancel_algebraic_verification:
                () => 0,
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    maximumWorkUnitCountPerPoll: 5,
                    resume: {
                        checkpointCustody: {
                            publishAuthenticatedCheckpoint: (
                                checkpointBytes: Uint8Array<ArrayBuffer>,
                            ) => {
                                publishedCheckpointBytes =
                                    checkpointBytes.slice();
                                return Promise.resolve();
                            },
                            restoreAuthenticatedCheckpoint: () =>
                                Promise.resolve(restoredCheckpointBytes),
                        },
                    },
                    yieldControl: () => {
                        yieldCount += 1;
                        return Promise.resolve();
                    },
                },
            ),
        ).resolves.toEqual({ isValid: true, value: undefined });
        expect(beginCount).toBe(0);
        expect(copiedCheckpointCount).toBe(1);
        expect(pollCount).toBe(4);
        expect(publishedCheckpointBytes).toEqual(nextCheckpointBytes);
        expect(restoredCheckpointBytes.byteLength).toBe(0);
        expect(yieldCount).toBe(3);
    });

    it('refuses a restored checkpoint that is not one exact owned canonical buffer', async () => {
        const oversizedBackingBuffer = new ArrayBuffer(401);
        const restoredCheckpointBytes = new Uint8Array(
            oversizedBackingBuffer,
            1,
            400,
        ).fill(0x74);
        const runtime = createMockKernelRuntime(() => ({
            sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length:
                () => 400,
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    resume: {
                        checkpointCustody: {
                            publishAuthenticatedCheckpoint: () =>
                                Promise.resolve(),
                            restoreAuthenticatedCheckpoint: () =>
                                Promise.resolve(restoredCheckpointBytes),
                        },
                    },
                },
            ),
        ).rejects.toMatchObject({ code: 'WrongStorageResult' });
        expect(restoredCheckpointBytes).toEqual(new Uint8Array(400));
    });

    it('returns a checkpoint-binding refusal as a typed verification result', async () => {
        const restoredCheckpointBytes = new Uint8Array(400).fill(0x74);
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length:
                () => 400,
            sealed_lattice_compact_public_key_resume_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                _checkpointPointer,
                _checkpointByteLength,
                statusPointer: number,
            ) => {
                writeUnsigned32(memory, statusPointer, 0x0004);
                return 0;
            },
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    resume: {
                        checkpointCustody: {
                            publishAuthenticatedCheckpoint: () =>
                                Promise.resolve(),
                            restoreAuthenticatedCheckpoint: () =>
                                Promise.resolve(restoredCheckpointBytes),
                        },
                    },
                },
            ),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'wrongContext',
        });
        expect(restoredCheckpointBytes.byteLength).toBe(0);
    });

    it('retires the live verifier when authenticated checkpoint publication fails', async () => {
        let cancellationCount = 0;
        let publishedInput: Uint8Array | undefined;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_algebraic_verification_checkpoint_byte_length:
                () => 400,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                statusPointer,
            ) => {
                writeUnsigned32(memory, statusPointer, 0);
                return 97;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: (
                _operationHandle,
                _maximumWorkUnitCount,
                pollKindPointer,
                completedWorkUnitCountPointer,
            ) => {
                writeUnsigned32(memory, pollKindPointer, 1);
                writeUnsigned32(memory, completedWorkUnitCountPointer, 1);
                return 0;
            },
            sealed_lattice_compact_public_key_copy_algebraic_verification_checkpoint:
                (
                    _operationHandle: number,
                    outputPointer: number,
                    outputByteLength: number,
                ) => {
                    memoryBytes(memory, outputPointer, outputByteLength).fill(
                        0x75,
                    );
                    return 0;
                },
            sealed_lattice_compact_public_key_cancel_algebraic_verification: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(97);
                cancellationCount += 1;
                return 0;
            },
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    checkpointCustody: {
                        publishAuthenticatedCheckpoint: (
                            checkpointBytes: Uint8Array<ArrayBuffer>,
                        ) => {
                            publishedInput = checkpointBytes;
                            return Promise.reject(
                                new Error('simulated publication failure'),
                            );
                        },
                        restoreAuthenticatedCheckpoint: () => {
                            throw new Error(
                                'Fresh verification must not restore.',
                            );
                        },
                    },
                    maximumWorkUnitCountPerPoll: 1,
                },
            ),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(cancellationCount).toBe(1);
        expect(publishedInput?.byteLength).toBe(0);
    });

    it('returns begin and poll refusals as typed verification results', async () => {
        const beginRefusalRuntime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                statusPointer,
            ) => {
                writeUnsigned32(memory, statusPointer, 0x000b);
                return 0;
            },
        }));
        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                beginRefusalRuntime,
                { bindings, proofBytes, publicInputBytes },
            ),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'invalidProof',
        });

        let cancellationCount = 0;
        const pollRefusalRuntime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                statusPointer,
            ) => {
                writeUnsigned32(memory, statusPointer, 0);
                return 92;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: () =>
                0x0006,
            sealed_lattice_compact_public_key_cancel_algebraic_verification:
                () => {
                    cancellationCount += 1;
                    return 0;
                },
        }));
        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                pollRefusalRuntime,
                { bindings, proofBytes, publicInputBytes },
            ),
        ).resolves.toEqual({
            isValid: false,
            refusalReason: 'wrongHashOrRoot',
        });
        expect(cancellationCount).toBe(0);
    });

    it('cancels the live Rust verifier after an abort between bounded polls', async () => {
        const abortController = new AbortController();
        let cancellationCount = 0;
        let pollCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                statusPointer,
            ) => {
                writeUnsigned32(memory, statusPointer, 0);
                return 93;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: (
                operationHandle,
                _maximumWorkUnitCount,
                pollKindPointer,
                completedWorkUnitCountPointer,
            ) => {
                expect(operationHandle).toBe(93);
                pollCount += 1;
                writeUnsigned32(memory, pollKindPointer, 1);
                writeUnsigned32(memory, completedWorkUnitCountPointer, 1);
                return 0;
            },
            sealed_lattice_compact_public_key_cancel_algebraic_verification: (
                operationHandle,
            ) => {
                expect(operationHandle).toBe(93);
                cancellationCount += 1;
                return 0;
            },
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                {
                    maximumWorkUnitCountPerPoll: 1,
                    signal: abortController.signal,
                    yieldControl: () => {
                        abortController.abort('test cancellation');
                        return Promise.resolve();
                    },
                },
            ),
        ).rejects.toMatchObject({ code: 'Cancelled' });
        expect(pollCount).toBe(1);
        expect(cancellationCount).toBe(1);
    });

    it('rejects malformed progress metadata and retires the live operation', async () => {
        let cancellationCount = 0;
        const runtime = createMockKernelRuntime((memory) => ({
            sealed_lattice_compact_public_key_transport_bindings_byte_length:
                () => 256,
            sealed_lattice_compact_public_key_begin_algebraic_verification: (
                _bindingsPointer,
                _bindingsByteLength,
                _proofPointer,
                _proofByteLength,
                _publicInputPointer,
                _publicInputByteLength,
                statusPointer,
            ) => {
                writeUnsigned32(memory, statusPointer, 0);
                return 94;
            },
            sealed_lattice_compact_public_key_algebraic_verification_poll: (
                _operationHandle,
                _maximumWorkUnitCount,
                pollKindPointer,
                completedWorkUnitCountPointer,
            ) => {
                writeUnsigned32(memory, pollKindPointer, 1);
                writeUnsigned32(memory, completedWorkUnitCountPointer, 2);
                return 0;
            },
            sealed_lattice_compact_public_key_cancel_algebraic_verification:
                () => {
                    cancellationCount += 1;
                    return 0;
                },
        }));

        await expect(
            verifyCompactPublicKeyAlgebraicallyInClosedWorker(
                runtime,
                { bindings, proofBytes, publicInputBytes },
                { maximumWorkUnitCountPerPoll: 1 },
            ),
        ).rejects.toThrow(/invalid bounded progress/u);
        expect(cancellationCount).toBe(1);
    });
});
