import { describe, expect, it } from 'vitest';

import {
    DurableSignedCarrierCache,
    type SignedCarrierAuthenticator,
    type SignedCarrierCacheBinding,
} from '#packages/protocol/src/runtime/durable-signed-carrier-cache';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAtomicMutation,
    type UntrustedStorageRecoveryReport,
    type UntrustedStorageTransactionLimits,
    UntrustedStorageTransactionStore,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';

const bytesEqual = (
    left: Uint8Array | undefined,
    right: Uint8Array | undefined,
): boolean => {
    if (left === undefined || right === undefined) {
        return left === right;
    }
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }

    return true;
};

class DeterministicStorageAdapter implements UntrustedStorageAdapter {
    #values = new Map<string, Uint8Array>();
    public afterNextAtomicMutation: (() => void) | undefined;
    public failNextAtomicMutation = false;
    public failNextReadAfterAtomicMutation = false;
    #readFailurePending = false;

    public read(key: string): Promise<Uint8Array | undefined> {
        if (this.#readFailurePending) {
            this.#readFailurePending = false;
            return Promise.reject(
                new Error('injected post-publication read failure'),
            );
        }

        return Promise.resolve(this.#values.get(key)?.slice());
    }

    public write(key: string, value: Uint8Array): Promise<void> {
        this.#values.set(key, value.slice());
        return Promise.resolve();
    }

    public delete(key: string): Promise<void> {
        this.#values.delete(key);
        return Promise.resolve();
    }

    public listKeys(prefix: string): Promise<readonly string[]> {
        return Promise.resolve(
            [...this.#values.keys()]
                .filter((key) => key.startsWith(prefix))
                .sort(),
        );
    }

    public applyAtomicMutation(
        mutation: UntrustedStorageAtomicMutation,
    ): Promise<boolean> {
        if (this.failNextAtomicMutation) {
            this.failNextAtomicMutation = false;
            return Promise.reject(
                new Error('injected atomic mutation failure'),
            );
        }
        for (const expectedValue of mutation.expectedValues) {
            if (
                !bytesEqual(
                    this.#values.get(expectedValue.key),
                    expectedValue.value,
                )
            ) {
                return Promise.resolve(false);
            }
        }

        const nextValues = new Map<string, Uint8Array>(
            [...this.#values].map(
                ([key, value]) => [key, value.slice()] as const,
            ),
        );
        for (const key of mutation.deletes) {
            nextValues.delete(key);
        }
        for (const write of mutation.writes) {
            nextValues.set(write.key, write.value.slice());
        }
        this.#values = nextValues;

        const afterMutation = this.afterNextAtomicMutation;
        this.afterNextAtomicMutation = undefined;
        afterMutation?.();
        if (this.failNextReadAfterAtomicMutation) {
            this.failNextReadAfterAtomicMutation = false;
            this.#readFailurePending = true;
        }

        return Promise.resolve(true);
    }

    public objectKeys(namespace: string): readonly string[] {
        const prefix = `sealed-lattice-runtime-store/${namespace}/objects/`;
        return [...this.#values.keys()]
            .filter((key) => key.startsWith(prefix))
            .sort();
    }

    public overwrite(key: string, bytes: Uint8Array): void {
        if (!this.#values.has(key)) {
            throw new Error(`cannot overwrite missing key ${key}`);
        }
        this.#values.set(key, bytes.slice());
    }

    public readRaw(key: string): Uint8Array | undefined {
        return this.#values.get(key)?.slice();
    }
}

const transactionLimits: UntrustedStorageTransactionLimits = {
    maximumActiveTransactionCount: 8,
    maximumLeaseByteLength: 4_096,
    maximumLeaseCountPerTransaction: 4,
    maximumStoredValueByteLength: 64_000,
    maximumTransactionByteLength: 8_192,
    maximumTransactionLifetimeMilliseconds: 1_000,
};

const createIdentifierFactory = (
    factoryIdentifier: number,
): ((kind: 'lease' | 'transaction') => string) => {
    const issuedCounts = { lease: 0, transaction: 0 };

    return (kind) => {
        issuedCounts[kind] += 1;
        const kindByte = kind === 'transaction' ? '01' : '02';
        return `${kindByte}${factoryIdentifier
            .toString(16)
            .padStart(30, '0')}${issuedCounts[kind]
            .toString(16)
            .padStart(32, '0')}`;
    };
};

const namespace = 'signed-carrier-cache-test';

const openTestCache = async (input?: {
    adapter?: DeterministicStorageAdapter;
    factoryIdentifier?: number;
}): Promise<{
    adapter: DeterministicStorageAdapter;
    cache: DurableSignedCarrierCache;
    recoveryReport: UntrustedStorageRecoveryReport;
    store: UntrustedStorageTransactionStore;
}> => {
    const adapter = input?.adapter ?? new DeterministicStorageAdapter();
    const { recoveryReport, store } =
        await openUntrustedStorageTransactionStore({
            adapter,
            createIdentifier: createIdentifierFactory(
                input?.factoryIdentifier ?? 0,
            ),
            limits: transactionLimits,
            monotonicClockMilliseconds: () => 0,
            namespace,
        });

    return {
        adapter,
        cache: new DurableSignedCarrierCache({
            store,
            transactionLifetimeMilliseconds: 100,
        }),
        recoveryReport,
        store,
    };
};

const hashFilledWithByte = (byte: number): string =>
    byte.toString(16).padStart(2, '0').repeat(64);

const binding = (input?: {
    actionContextByte?: number;
    ceremonyContextByte?: number;
    producerSlotByte?: number;
    suiteByte?: number;
}): SignedCarrierCacheBinding => ({
    protocolVersion: 1,
    suiteId: hashFilledWithByte(input?.suiteByte ?? 0x11),
    ceremonyContextHash: hashFilledWithByte(input?.ceremonyContextByte ?? 0x22),
    actionContextHash: hashFilledWithByte(input?.actionContextByte ?? 0x33),
    producerSlotHash: hashFilledWithByte(input?.producerSlotByte ?? 0x44),
});

const firstHashByte = (hash: string): number =>
    Number.parseInt(hash.slice(0, 2), 16);

const createTestSignedCarrier = (input: {
    binding: SignedCarrierCacheBinding;
    objectByte: number;
    signatureHedgeByte: number;
}): Uint8Array => {
    const bytesWithoutChecksum = Uint8Array.of(
        0xa5,
        input.objectByte,
        firstHashByte(input.binding.suiteId),
        firstHashByte(input.binding.ceremonyContextHash),
        firstHashByte(input.binding.actionContextHash),
        firstHashByte(input.binding.producerSlotHash),
        input.signatureHedgeByte,
    );
    const checksum = bytesWithoutChecksum.reduce(
        (accumulatedChecksum, byte) => accumulatedChecksum ^ byte,
        0,
    );

    return Uint8Array.of(...bytesWithoutChecksum, checksum);
};

const authenticateTestSignedCarrier: SignedCarrierAuthenticator = ({
    canonicalSignedCarrierBytes,
    expectedBinding,
}) => {
    if (
        canonicalSignedCarrierBytes.byteLength !== 8 ||
        canonicalSignedCarrierBytes[0] !== 0xa5
    ) {
        throw new Error('malformed test signed carrier');
    }
    const expectedContextBytes = [
        firstHashByte(expectedBinding.suiteId),
        firstHashByte(expectedBinding.ceremonyContextHash),
        firstHashByte(expectedBinding.actionContextHash),
        firstHashByte(expectedBinding.producerSlotHash),
    ];
    for (
        let contextByteIndex = 0;
        contextByteIndex < expectedContextBytes.length;
        contextByteIndex += 1
    ) {
        if (
            canonicalSignedCarrierBytes[contextByteIndex + 2] !==
            expectedContextBytes[contextByteIndex]
        ) {
            throw new Error('test signed-carrier context mismatch');
        }
    }
    const expectedChecksum = canonicalSignedCarrierBytes
        .subarray(0, 7)
        .reduce((accumulatedChecksum, byte) => accumulatedChecksum ^ byte, 0);
    if (canonicalSignedCarrierBytes[7] !== expectedChecksum) {
        throw new Error('test signed-carrier authentication failed');
    }

    return hashFilledWithByte(canonicalSignedCarrierBytes[1] ?? 0);
};

describe('durable signed-carrier cache', () => {
    it('keeps one byte-identical carrier for exact and object-hash duplicates', async () => {
        const { adapter, cache } = await openTestCache();
        const cacheBinding = binding();
        const firstCarrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x51,
            signatureHedgeByte: 0x61,
        });
        const sameObjectWithDifferentSignature = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x51,
            signatureHedgeByte: 0x62,
        });

        const firstResult = await cache.cacheSignedCarrierForRetransmission({
            authenticate: authenticateTestSignedCarrier,
            binding: cacheBinding,
            canonicalSignedCarrierBytes: firstCarrier,
        });
        const exactDuplicateResult =
            await cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: firstCarrier,
            });
        const semanticDuplicateResult =
            await cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: sameObjectWithDifferentSignature,
            });

        expect(firstResult).toEqual(firstCarrier);
        expect(exactDuplicateResult).toEqual(firstCarrier);
        expect(semanticDuplicateResult).toEqual(firstCarrier);
        expect(semanticDuplicateResult).not.toEqual(
            sameObjectWithDifferentSignature,
        );
        expect(adapter.objectKeys(namespace)).toHaveLength(1);

        firstResult.fill(0);
        expect(
            await cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            }),
        ).toEqual(firstCarrier);
    });

    it('refuses a different authenticated object in the same slot as typed equivocation', async () => {
        const { cache } = await openTestCache();
        const cacheBinding = binding();
        const acceptedCarrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x71,
            signatureHedgeByte: 0x81,
        });
        const conflictingCarrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x72,
            signatureHedgeByte: 0x82,
        });
        await cache.cacheSignedCarrierForRetransmission({
            authenticate: authenticateTestSignedCarrier,
            binding: cacheBinding,
            canonicalSignedCarrierBytes: acceptedCarrier,
        });

        await expect(
            cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: conflictingCarrier,
            }),
        ).rejects.toMatchObject({
            name: 'SignedCarrierEquivocationError',
            refusalReason: 'equivocation',
        });
        expect(
            await cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            }),
        ).toEqual(acceptedCarrier);
    });

    it('separates stable protocol contexts and producer slots', async () => {
        const { adapter, cache } = await openTestCache();
        const bindings = [
            binding(),
            binding({ suiteByte: 0x12 }),
            binding({ ceremonyContextByte: 0x23 }),
            binding({ actionContextByte: 0x34 }),
            binding({ producerSlotByte: 0x45 }),
        ];
        const carriers = bindings.map((carrierBinding, bindingIndex) =>
            createTestSignedCarrier({
                binding: carrierBinding,
                objectByte: 0x20 + bindingIndex,
                signatureHedgeByte: 0x30 + bindingIndex,
            }),
        );

        await Promise.all(
            bindings.map((carrierBinding, bindingIndex) =>
                cache.cacheSignedCarrierForRetransmission({
                    authenticate: authenticateTestSignedCarrier,
                    binding: carrierBinding,
                    canonicalSignedCarrierBytes: carriers[bindingIndex],
                }),
            ),
        );

        await expect(
            Promise.all(
                bindings.map((carrierBinding) =>
                    cache.readSignedCarrierForRetransmission({
                        authenticate: authenticateTestSignedCarrier,
                        binding: carrierBinding,
                    }),
                ),
            ),
        ).resolves.toEqual(carriers);
        expect(adapter.objectKeys(namespace)).toHaveLength(bindings.length);
    });

    it('resolves concurrent duplicates to one carrier and concurrent conflicts to one refusal', async () => {
        const { cache } = await openTestCache();
        const duplicateBinding = binding({ producerSlotByte: 0x60 });
        const duplicateCandidates = [0x41, 0x42].map((signatureHedgeByte) =>
            createTestSignedCarrier({
                binding: duplicateBinding,
                objectByte: 0x31,
                signatureHedgeByte,
            }),
        );
        const duplicateResults = await Promise.all(
            duplicateCandidates.map((canonicalSignedCarrierBytes) =>
                cache.cacheSignedCarrierForRetransmission({
                    authenticate: authenticateTestSignedCarrier,
                    binding: duplicateBinding,
                    canonicalSignedCarrierBytes,
                }),
            ),
        );
        expect(duplicateResults[0]).toEqual(duplicateResults[1]);
        expect(
            duplicateCandidates.some((candidate) =>
                bytesEqual(candidate, duplicateResults[0]),
            ),
        ).toBe(true);

        const conflictBinding = binding({ producerSlotByte: 0x61 });
        const conflictCandidates = [0x51, 0x52].map((objectByte) =>
            createTestSignedCarrier({
                binding: conflictBinding,
                objectByte,
                signatureHedgeByte: objectByte + 0x10,
            }),
        );
        const conflictResults = await Promise.allSettled(
            conflictCandidates.map((canonicalSignedCarrierBytes) =>
                cache.cacheSignedCarrierForRetransmission({
                    authenticate: authenticateTestSignedCarrier,
                    binding: conflictBinding,
                    canonicalSignedCarrierBytes,
                }),
            ),
        );
        const acceptedResults = conflictResults.filter(
            (result) => result.status === 'fulfilled',
        );
        const refusedResults = conflictResults.filter(
            (result) => result.status === 'rejected',
        );
        expect(acceptedResults).toHaveLength(1);
        expect(refusedResults).toHaveLength(1);
        expect(refusedResults[0]).toMatchObject({
            reason: { refusalReason: 'equivocation' },
        });
    });

    it('recovers committed bytes across restart and never aliases caller buffers', async () => {
        const firstRuntime = await openTestCache();
        const cacheBinding = binding({ producerSlotByte: 0x70 });
        const carrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x63,
            signatureHedgeByte: 0x73,
        });
        const pendingCache =
            firstRuntime.cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: carrier,
            });
        carrier.fill(0);
        const selectedBytes = await pendingCache;
        const expectedCarrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x63,
            signatureHedgeByte: 0x73,
        });
        expect(selectedBytes).toEqual(expectedCarrier);

        const restartedRuntime = await openTestCache({
            adapter: firstRuntime.adapter,
            factoryIdentifier: 1,
        });
        expect(restartedRuntime.recoveryReport).toMatchObject({
            removedCorruptIndexCount: 0,
            removedUnreferencedObjectCount: 0,
            retainedObjectCount: 1,
        });
        const retransmissionBytes =
            await restartedRuntime.cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            });
        expect(retransmissionBytes).toEqual(expectedCarrier);
        retransmissionBytes?.fill(0xff);
        expect(
            await restartedRuntime.cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            }),
        ).toEqual(expectedCarrier);
    });

    it('removes an uncommitted staged carrier during crash recovery', async () => {
        const firstRuntime = await openTestCache();
        const cacheBinding = binding({ producerSlotByte: 0x80 });
        const carrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x64,
            signatureHedgeByte: 0x74,
        });
        firstRuntime.adapter.failNextAtomicMutation = true;

        await expect(
            firstRuntime.cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: carrier,
            }),
        ).rejects.toThrow('injected atomic mutation failure');
        expect(firstRuntime.adapter.objectKeys(namespace)).toHaveLength(1);

        const restartedRuntime = await openTestCache({
            adapter: firstRuntime.adapter,
            factoryIdentifier: 2,
        });
        expect(restartedRuntime.recoveryReport).toMatchObject({
            removedUnreferencedObjectCount: 1,
            retainedObjectCount: 0,
        });
        await expect(
            restartedRuntime.cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            }),
        ).resolves.toBeUndefined();
        await expect(
            restartedRuntime.cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: carrier,
            }),
        ).resolves.toEqual(carrier);
    });

    it('recovers a published carrier when the original runtime loses its completion reread', async () => {
        const firstRuntime = await openTestCache();
        const cacheBinding = binding({ producerSlotByte: 0x90 });
        const carrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x65,
            signatureHedgeByte: 0x75,
        });
        firstRuntime.adapter.failNextReadAfterAtomicMutation = true;

        await expect(
            firstRuntime.cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: carrier,
            }),
        ).rejects.toThrow('injected post-publication read failure');

        const restartedRuntime = await openTestCache({
            adapter: firstRuntime.adapter,
            factoryIdentifier: 3,
        });
        expect(restartedRuntime.recoveryReport).toMatchObject({
            removedUnreferencedObjectCount: 0,
            retainedObjectCount: 1,
        });
        await expect(
            restartedRuntime.cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            }),
        ).resolves.toEqual(carrier);
    });

    it('authenticates committed rereads and refuses storage tampering', async () => {
        const runtime = await openTestCache();
        const cacheBinding = binding({ producerSlotByte: 0xa0 });
        const carrier = createTestSignedCarrier({
            binding: cacheBinding,
            objectByte: 0x66,
            signatureHedgeByte: 0x76,
        });
        runtime.adapter.afterNextAtomicMutation = () => {
            const [objectKey] = runtime.adapter.objectKeys(namespace);
            if (objectKey === undefined) {
                throw new Error('expected a staged carrier object');
            }
            const tamperedBytes = runtime.adapter.readRaw(objectKey);
            if (tamperedBytes === undefined) {
                throw new Error('expected staged carrier bytes');
            }
            tamperedBytes[7] = (tamperedBytes[7] ?? 0) ^ 0xff;
            runtime.adapter.overwrite(objectKey, tamperedBytes);
        };

        await expect(
            runtime.cache.cacheSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
                canonicalSignedCarrierBytes: carrier,
            }),
        ).rejects.toMatchObject({
            code: 'AuthenticationFailed',
            failureCause: {
                message: 'test signed-carrier authentication failed',
            },
        });

        const restartedRuntime = await openTestCache({
            adapter: runtime.adapter,
            factoryIdentifier: 4,
        });
        await expect(
            restartedRuntime.cache.readSignedCarrierForRetransmission({
                authenticate: authenticateTestSignedCarrier,
                binding: cacheBinding,
            }),
        ).rejects.toMatchObject({
            code: 'AuthenticationFailed',
            failureCause: {
                message: 'test signed-carrier authentication failed',
            },
        });
    });
});
