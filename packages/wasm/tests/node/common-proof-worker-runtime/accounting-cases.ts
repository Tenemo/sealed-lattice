import { describe, expect, it } from 'vitest';

import {
    CommonProofGenerationKernelBoundary,
    CommonProofVerificationKernelBoundary,
} from '../../../src/common-proof-worker-runtime/kernel-boundaries.js';

import { createMockKernelRuntime, memoryBytes } from './kernel-fixtures.js';

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
    49_152n,
    49_152n,
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
                maximumChunkByteLength: 49_152,
                maximumTransactionPayloadByteLength: 49_152n,
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
