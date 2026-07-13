import type { ProtocolHash, RefusalReason } from '@sealed-lattice/types';

import { UntrustedStorageTransactionStore } from './untrusted-storage-transaction-store.js';

const supportedProtocolVersion = 1;
const protocolHashPattern = /^[0-9a-f]{128}$/u;
const logicalRecordKeyPrefix = 'signed-carrier-cache/v1';

export type SignedCarrierCacheBinding = Readonly<{
    protocolVersion: 1;
    suiteId: ProtocolHash;
    ceremonyContextHash: ProtocolHash;
    actionContextHash: ProtocolHash;
    producerSlotHash: ProtocolHash;
}>;

export type SignedCarrierAuthenticationInput = Readonly<{
    canonicalSignedCarrierBytes: Uint8Array;
    expectedBinding: SignedCarrierCacheBinding;
}>;

/**
 * Authenticates one complete signed carrier against the expected context and
 * producer slot, then returns the object hash recomputed from its envelope.
 */
export type SignedCarrierAuthenticator = (
    input: SignedCarrierAuthenticationInput,
) => Promise<ProtocolHash> | ProtocolHash;

class SignedCarrierEquivocationError extends Error {
    public readonly refusalReason: Extract<RefusalReason, 'equivocation'> =
        'equivocation';

    public constructor() {
        super(
            'An authenticated signed carrier conflicts with the carrier already cached for this producer slot.',
        );
        this.name = 'SignedCarrierEquivocationError';
    }
}

class SignedCarrierCacheCleanupError extends Error {
    public readonly operationFailure: unknown;
    public readonly cleanupFailure: unknown;

    public constructor(operationFailure: unknown, cleanupFailure: unknown) {
        super(
            'The signed-carrier cache operation failed and its uncommitted transaction could not be cleaned up.',
        );
        this.name = 'SignedCarrierCacheCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailure = cleanupFailure;
    }
}

type AuthenticatedCachedCarrier = Readonly<{
    bytes: Uint8Array;
    objectHash: ProtocolHash;
}>;

type DurableSignedCarrierCacheConfiguration = Readonly<{
    store: UntrustedStorageTransactionStore;
    transactionLifetimeMilliseconds: number;
}>;

const assertProtocolHash = (
    value: ProtocolHash,
    fieldName: string,
): ProtocolHash => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must contain exactly 128 lowercase hexadecimal characters.`,
        );
    }

    return value;
};

const normalizeBinding = (
    binding: SignedCarrierCacheBinding,
): SignedCarrierCacheBinding => {
    if (binding.protocolVersion !== supportedProtocolVersion) {
        throw new TypeError('protocolVersion must be one.');
    }

    return Object.freeze({
        protocolVersion: supportedProtocolVersion,
        suiteId: assertProtocolHash(binding.suiteId, 'suiteId'),
        ceremonyContextHash: assertProtocolHash(
            binding.ceremonyContextHash,
            'ceremonyContextHash',
        ),
        actionContextHash: assertProtocolHash(
            binding.actionContextHash,
            'actionContextHash',
        ),
        producerSlotHash: assertProtocolHash(
            binding.producerSlotHash,
            'producerSlotHash',
        ),
    });
};

const logicalRecordKeyForBinding = (
    binding: SignedCarrierCacheBinding,
): string =>
    [
        logicalRecordKeyPrefix,
        binding.suiteId,
        binding.ceremonyContextHash,
        binding.actionContextHash,
        binding.producerSlotHash,
    ].join('/');

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
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

const isStorageConflict = (error: unknown): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'Conflict';

const assertTransactionLifetime = (
    transactionLifetimeMilliseconds: number,
): void => {
    if (
        !Number.isSafeInteger(transactionLifetimeMilliseconds) ||
        transactionLifetimeMilliseconds <= 0
    ) {
        throw new TypeError(
            'transactionLifetimeMilliseconds must be a positive safe integer.',
        );
    }
};

export class DurableSignedCarrierCache {
    readonly #store: UntrustedStorageTransactionStore;
    readonly #transactionLifetimeMilliseconds: number;

    public constructor(configuration: DurableSignedCarrierCacheConfiguration) {
        assertTransactionLifetime(
            configuration.transactionLifetimeMilliseconds,
        );
        this.#store = configuration.store;
        this.#transactionLifetimeMilliseconds =
            configuration.transactionLifetimeMilliseconds;
    }

    /**
     * Returns the authenticated bytes selected for a producer slot. Exact-byte
     * replay and a second valid signature over the same object are idempotent;
     * a different authenticated object hash is equivocation.
     */
    public async cacheSignedCarrierForRetransmission(input: {
        binding: SignedCarrierCacheBinding;
        canonicalSignedCarrierBytes: Uint8Array;
        authenticate: SignedCarrierAuthenticator;
    }): Promise<Uint8Array> {
        const binding = normalizeBinding(input.binding);
        if (!(input.canonicalSignedCarrierBytes instanceof Uint8Array)) {
            throw new TypeError(
                'canonicalSignedCarrierBytes must be a Uint8Array.',
            );
        }
        if (typeof input.authenticate !== 'function') {
            throw new TypeError('authenticate must be a function.');
        }

        const candidateBytes = input.canonicalSignedCarrierBytes.slice();
        const candidateObjectHash = await this.#authenticateCarrier(
            candidateBytes,
            binding,
            input.authenticate,
        );
        const logicalRecordKey = logicalRecordKeyForBinding(binding);
        const existingCarrier = await this.#readAuthenticatedCarrier(
            logicalRecordKey,
            binding,
            input.authenticate,
        );
        if (existingCarrier !== undefined) {
            return this.#selectCachedCarrier(
                existingCarrier,
                candidateBytes,
                candidateObjectHash,
            );
        }

        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#transactionLifetimeMilliseconds,
        });
        let commitStarted = false;
        try {
            const lease = await transaction.issueWriteLease({
                declaredByteLength: candidateBytes.byteLength,
                expectedCurrentValue: null,
                logicalRecordKey,
            });
            await lease.write(candidateBytes);
            await lease.seal(
                async ({ bytes, logicalRecordKey: observedKey }) => {
                    if (observedKey !== logicalRecordKey) {
                        throw new Error(
                            'The transaction store supplied a different signed-carrier cache key.',
                        );
                    }
                    const observedObjectHash = await this.#authenticateCarrier(
                        bytes,
                        binding,
                        input.authenticate,
                    );
                    if (observedObjectHash !== candidateObjectHash) {
                        throw new Error(
                            'Signed-carrier authentication changed for byte-identical staged bytes.',
                        );
                    }
                },
            );
            commitStarted = true;
            await transaction.commit();
        } catch (error) {
            if (!commitStarted || isStorageConflict(error)) {
                try {
                    await transaction.abort();
                } catch (cleanupFailure) {
                    throw new SignedCarrierCacheCleanupError(
                        error,
                        cleanupFailure,
                    );
                }
            }

            if (isStorageConflict(error)) {
                const concurrentCarrier = await this.#readAuthenticatedCarrier(
                    logicalRecordKey,
                    binding,
                    input.authenticate,
                );
                if (concurrentCarrier !== undefined) {
                    return this.#selectCachedCarrier(
                        concurrentCarrier,
                        candidateBytes,
                        candidateObjectHash,
                    );
                }
            }
            throw error;
        }

        const committedCarrier = await this.#readAuthenticatedCarrier(
            logicalRecordKey,
            binding,
            input.authenticate,
        );
        if (committedCarrier === undefined) {
            throw new Error(
                'The committed signed carrier was absent during authenticated reread.',
            );
        }
        if (
            committedCarrier.objectHash !== candidateObjectHash ||
            !bytesEqual(committedCarrier.bytes, candidateBytes)
        ) {
            throw new Error(
                'The committed signed carrier changed during authenticated reread.',
            );
        }

        return committedCarrier.bytes.slice();
    }

    /** Returns authenticated byte-identical retransmission bytes after restart. */
    public async readSignedCarrierForRetransmission(input: {
        binding: SignedCarrierCacheBinding;
        authenticate: SignedCarrierAuthenticator;
    }): Promise<Uint8Array | undefined> {
        const binding = normalizeBinding(input.binding);
        if (typeof input.authenticate !== 'function') {
            throw new TypeError('authenticate must be a function.');
        }
        const cachedCarrier = await this.#readAuthenticatedCarrier(
            logicalRecordKeyForBinding(binding),
            binding,
            input.authenticate,
        );

        return cachedCarrier?.bytes.slice();
    }

    async #authenticateCarrier(
        bytes: Uint8Array,
        binding: SignedCarrierCacheBinding,
        authenticate: SignedCarrierAuthenticator,
    ): Promise<ProtocolHash> {
        const objectHash = await authenticate({
            canonicalSignedCarrierBytes: bytes.slice(),
            expectedBinding: binding,
        });

        return assertProtocolHash(objectHash, 'authenticated object hash');
    }

    async #readAuthenticatedCarrier(
        logicalRecordKey: string,
        binding: SignedCarrierCacheBinding,
        authenticate: SignedCarrierAuthenticator,
    ): Promise<AuthenticatedCachedCarrier | undefined> {
        let authenticatedObjectHash: ProtocolHash | undefined;
        const bytes = await this.#store.readAuthenticated({
            logicalRecordKey,
            authenticate: async ({
                bytes: storedBytes,
                logicalRecordKey: observedKey,
            }) => {
                if (observedKey !== logicalRecordKey) {
                    throw new Error(
                        'The transaction store supplied a different signed-carrier cache key.',
                    );
                }
                authenticatedObjectHash = await this.#authenticateCarrier(
                    storedBytes,
                    binding,
                    authenticate,
                );
            },
        });
        if (bytes === undefined) {
            return undefined;
        }
        if (authenticatedObjectHash === undefined) {
            throw new Error(
                'The transaction store returned signed-carrier bytes without authenticating them.',
            );
        }

        return {
            bytes,
            objectHash: authenticatedObjectHash,
        };
    }

    #selectCachedCarrier(
        cachedCarrier: AuthenticatedCachedCarrier,
        candidateBytes: Uint8Array,
        candidateObjectHash: ProtocolHash,
    ): Uint8Array {
        if (
            bytesEqual(cachedCarrier.bytes, candidateBytes) ||
            cachedCarrier.objectHash === candidateObjectHash
        ) {
            return cachedCarrier.bytes.slice();
        }

        throw new SignedCarrierEquivocationError();
    }
}
