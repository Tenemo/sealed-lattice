import { randomUUID } from 'node:crypto';
import { access } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type {
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryRequest,
} from '#packages/wasm/src/index';
import { openFileBackedCommonProofExternalMemory } from '#packages/wasm/tests/support/file-backed-common-proof-external-memory';

const maximumPayloadByteLength = 1_048_576n;
const maximumOperationCount = 4_096;

const request = (input: {
    operations: readonly CommonProofExternalMemoryOperation[];
    requestSequence: bigint;
    runtimeBindingHash: Uint8Array<ArrayBuffer>;
}): CommonProofExternalMemoryRequest =>
    Object.freeze({
        maximumOperationCount,
        maximumPayloadByteLength,
        operations: Object.freeze([...input.operations]),
        requestDigest: new Uint8Array(64).fill(0x41),
        requestSequence: input.requestSequence,
        runtimeBindingHash: input.runtimeBindingHash.slice(),
    });

const operation = <
    Operation extends Omit<
        CommonProofExternalMemoryOperation,
        'operationIndex'
    >,
>(
    operationIndex: number,
    value: Operation,
): CommonProofExternalMemoryOperation =>
    Object.freeze({
        ...value,
        operationIndex,
    }) as CommonProofExternalMemoryOperation;

describe('File-backed common-proof external memory', () => {
    it('preserves copy-on-write transactions, exact reads, ordinal reuse, and independent ledgers', async () => {
        const runtimeBindingHash = new Uint8Array(64).fill(0x31);
        const directoryPath = path.resolve(
            'temp',
            `file-backed-common-proof-external-memory-${randomUUID()}`,
        );
        const storage = await openFileBackedCommonProofExternalMemory({
            directoryPath,
            runtimeBindingHash,
        });
        try {
            await expect(
                storage.executeTransaction(
                    request({
                        operations: [
                            operation(0, {
                                exactByteLength: 8n,
                                objectOrdinal: 7,
                                operationKind: 'create',
                                protection: 'secret-authenticated-encryption',
                            }),
                            operation(1, {
                                bytes: Uint8Array.from([0, 1, 2, 3]),
                                expectedOffset: 0n,
                                objectOrdinal: 7,
                                operationKind: 'append',
                            }),
                        ],
                        requestSequence: 1n,
                        runtimeBindingHash,
                    }),
                ),
            ).resolves.toEqual([]);

            await expect(
                storage.executeTransaction(
                    request({
                        operations: [
                            operation(0, {
                                bytes: Uint8Array.from([9, 9]),
                                expectedOffset: 3n,
                                objectOrdinal: 7,
                                operationKind: 'append',
                            }),
                        ],
                        requestSequence: 2n,
                        runtimeBindingHash,
                    }),
                ),
            ).rejects.toThrow('invalid append boundary');

            const completedRead = await storage.executeTransaction(
                request({
                    operations: [
                        operation(0, {
                            bytes: Uint8Array.from([4, 5, 6, 7]),
                            expectedOffset: 4n,
                            objectOrdinal: 7,
                            operationKind: 'append',
                        }),
                        operation(1, {
                            objectOrdinal: 7,
                            operationKind: 'seal',
                        }),
                        operation(2, {
                            byteLength: 4,
                            objectOrdinal: 7,
                            offset: 2n,
                            operationKind: 'read',
                        }),
                    ],
                    requestSequence: 2n,
                    runtimeBindingHash,
                }),
            );
            expect(completedRead).toHaveLength(1);
            expect([...completedRead[0].bytes]).toEqual([2, 3, 4, 5]);
            completedRead[0].bytes.fill(0);

            const replacedRead = await storage.executeTransaction(
                request({
                    operations: [
                        operation(0, {
                            objectOrdinal: 7,
                            operationKind: 'delete',
                        }),
                        operation(1, {
                            exactByteLength: 3n,
                            objectOrdinal: 7,
                            operationKind: 'create',
                            protection: 'public-integrity',
                        }),
                        operation(2, {
                            bytes: Uint8Array.from([21, 22, 23]),
                            expectedOffset: 0n,
                            objectOrdinal: 7,
                            operationKind: 'append',
                        }),
                        operation(3, {
                            objectOrdinal: 7,
                            operationKind: 'seal',
                        }),
                        operation(4, {
                            byteLength: 3,
                            objectOrdinal: 7,
                            offset: 0n,
                            operationKind: 'read',
                        }),
                    ],
                    requestSequence: 3n,
                    runtimeBindingHash,
                }),
            );
            expect([...replacedRead[0].bytes]).toEqual([21, 22, 23]);
            replacedRead[0].bytes.fill(0);

            await expect(
                storage.executeTransaction(
                    request({
                        operations: [
                            operation(0, {
                                objectOrdinal: 7,
                                operationKind: 'delete',
                            }),
                        ],
                        requestSequence: 4n,
                        runtimeBindingHash,
                    }),
                ),
            ).resolves.toEqual([]);

            expect(storage.copyLogicalUsage()).toEqual({
                deletedObjectLifecycleCount: 2n,
                peakStoredByteLength: 8n,
                totalReadByteLength: 7n,
                totalWrittenByteLength: 11n,
                transactionCount: 4n,
            });
            expect(storage.copyPhysicalAccounting()).toMatchObject({
                copyOnWriteByteLength: 4n,
                copyOnWriteCount: 1n,
                currentDeclaredByteLength: 0n,
                liveObjectCount: 0,
                maximumDeclaredByteLength: 8n,
                physicalReadByteLength: 11n,
                physicalReadCount: 3n,
                physicalSealCount: 2n,
                physicalWriteByteLength: 15n,
                physicalWriteCount: 4n,
            });
        } finally {
            await storage.close();
        }
        await expect(access(directoryPath)).rejects.toThrow();
    });

    it('refuses wrong bindings, wrong sequences, noncanonical operations, and directories outside repository temp', async () => {
        const runtimeBindingHash = new Uint8Array(64).fill(0x51);
        const directoryPath = path.resolve(
            'temp',
            `file-backed-common-proof-hostile-${randomUUID()}`,
        );
        const storage = await openFileBackedCommonProofExternalMemory({
            directoryPath,
            runtimeBindingHash,
        });
        try {
            const validCreate = operation(0, {
                exactByteLength: 2n,
                objectOrdinal: 3,
                operationKind: 'create',
                protection: 'public-integrity',
            });
            await expect(
                storage.executeTransaction(
                    request({
                        operations: [validCreate],
                        requestSequence: 1n,
                        runtimeBindingHash: new Uint8Array(64).fill(0x52),
                    }),
                ),
            ).rejects.toThrow('wrong runtime-binding hash');
            await expect(
                storage.executeTransaction(
                    request({
                        operations: [validCreate],
                        requestSequence: 2n,
                        runtimeBindingHash,
                    }),
                ),
            ).rejects.toThrow('wrong request sequence');
            await expect(
                storage.executeTransaction(
                    request({
                        operations: [
                            operation(1, {
                                exactByteLength: 2n,
                                objectOrdinal: 3,
                                operationKind: 'create',
                                protection: 'public-integrity',
                            }),
                        ],
                        requestSequence: 1n,
                        runtimeBindingHash,
                    }),
                ),
            ).rejects.toThrow('noncanonical operation indices');
            expect(storage.copyLogicalUsage()).toEqual({
                deletedObjectLifecycleCount: 0n,
                peakStoredByteLength: 0n,
                totalReadByteLength: 0n,
                totalWrittenByteLength: 0n,
                transactionCount: 0n,
            });
        } finally {
            await storage.close();
        }

        await expect(
            openFileBackedCommonProofExternalMemory({
                directoryPath: path.resolve('logs', 'wrong-custody-root'),
                runtimeBindingHash,
            }),
        ).rejects.toThrow('descendant of the repository temp directory');
        await expect(
            openFileBackedCommonProofExternalMemory({
                directoryPath: path.resolve(
                    'temp',
                    `wrong-runtime-binding-${randomUUID()}`,
                ),
                runtimeBindingHash: new Uint8Array(63),
            }),
        ).rejects.toThrow('one exact runtime-binding hash');
    });
});
