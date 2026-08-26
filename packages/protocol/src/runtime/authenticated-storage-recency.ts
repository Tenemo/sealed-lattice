import { bytesEqual, mapStorageError } from './authenticated-runtime-record.js';
import type { UntrustedStorageTransactionStore } from './untrusted-storage-transaction-store.js';

const recencyCoordinateVersion = 1;
const storageInstanceIdentityByteLength = 64;
const authenticatedHeadDigestByteLength = 64;
const unsigned64Maximum = 0xffff_ffff_ffff_ffffn;
export const authenticatedStorageRecencyCoordinateByteLength =
    1 +
    storageInstanceIdentityByteLength +
    8 +
    authenticatedHeadDigestByteLength;

export type AuthenticatedStorageRecencyAnchor = Readonly<{
    compareAndSet(input: {
        expectedBytes: Uint8Array | null;
        nextBytes: Uint8Array;
    }): Promise<boolean>;
    read(): Promise<Uint8Array | undefined>;
}>;

type AuthenticatedStorageRecencyErrorCode =
    | 'AnchorFailure'
    | 'Conflict'
    | 'InvalidInput'
    | 'InvalidState'
    | 'StorageFailure';

class AuthenticatedStorageRecencyError extends Error {
    public readonly code: AuthenticatedStorageRecencyErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: AuthenticatedStorageRecencyErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'AuthenticatedStorageRecencyError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

type AuthenticatedStorageRecencyCoordinate = Readonly<{
    authenticatedHeadDigest: Uint8Array;
    namespaceSequence: bigint;
    storageInstanceIdentity: Uint8Array;
}>;

type AuthenticatedStorageLocalCoordinate =
    AuthenticatedStorageRecencyCoordinate &
        Readonly<{
            predecessorAuthenticatedHeadDigest: Uint8Array | undefined;
        }>;

type ExternalRecencyCoordinate = Readonly<{
    bytes: Uint8Array;
    coordinate: AuthenticatedStorageRecencyCoordinate;
}>;

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const copyExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new AuthenticatedStorageRecencyError(
            'InvalidInput',
            `${label} must be exactly ${expectedByteLength} bytes.`,
        );
    }
    return value.slice();
};

const requireError = (failure: unknown, operation: string): Error => {
    if (failure instanceof Error) {
        return failure;
    }
    return new AuthenticatedStorageRecencyError(
        'StorageFailure',
        `${operation} rejected with a non-error value.`,
        failure,
    );
};

const destroyCoordinate = (
    coordinate: AuthenticatedStorageRecencyCoordinate | undefined,
): void => {
    coordinate?.authenticatedHeadDigest.fill(0);
    coordinate?.storageInstanceIdentity.fill(0);
};

const copyCoordinate = (
    coordinate: AuthenticatedStorageRecencyCoordinate,
): AuthenticatedStorageRecencyCoordinate => ({
    authenticatedHeadDigest: coordinate.authenticatedHeadDigest.slice(),
    namespaceSequence: coordinate.namespaceSequence,
    storageInstanceIdentity: coordinate.storageInstanceIdentity.slice(),
});

const coordinatesEqual = (
    left: AuthenticatedStorageRecencyCoordinate,
    right: AuthenticatedStorageRecencyCoordinate,
): boolean =>
    left.namespaceSequence === right.namespaceSequence &&
    bytesEqual(left.storageInstanceIdentity, right.storageInstanceIdentity) &&
    bytesEqual(left.authenticatedHeadDigest, right.authenticatedHeadDigest);

const encodeRecencyCoordinate = (
    coordinate: AuthenticatedStorageRecencyCoordinate,
): Uint8Array => {
    if (
        coordinate.namespaceSequence < 0n ||
        coordinate.namespaceSequence > unsigned64Maximum
    ) {
        throw new AuthenticatedStorageRecencyError(
            'InvalidInput',
            'Authenticated storage namespace sequence is outside the unsigned 64-bit range.',
        );
    }
    const storageInstanceIdentity = copyExactBytes(
        coordinate.storageInstanceIdentity,
        storageInstanceIdentityByteLength,
        'storage instance identity',
    );
    const authenticatedHeadDigest = copyExactBytes(
        coordinate.authenticatedHeadDigest,
        authenticatedHeadDigestByteLength,
        'authenticated head digest',
    );
    const bytes = new Uint8Array(
        authenticatedStorageRecencyCoordinateByteLength,
    );
    try {
        const view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );
        let offset = 0;
        view.setUint8(offset, recencyCoordinateVersion);
        offset += 1;
        bytes.set(storageInstanceIdentity, offset);
        offset += storageInstanceIdentity.byteLength;
        view.setBigUint64(offset, coordinate.namespaceSequence, true);
        offset += 8;
        bytes.set(authenticatedHeadDigest, offset);
        return bytes;
    } finally {
        storageInstanceIdentity.fill(0);
        authenticatedHeadDigest.fill(0);
    }
};

const decodeRecencyCoordinate = (
    value: unknown,
): AuthenticatedStorageRecencyCoordinate => {
    const bytes = copyExactBytes(
        value,
        authenticatedStorageRecencyCoordinateByteLength,
        'external recency coordinate',
    );
    try {
        const view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );
        let offset = 0;
        if (view.getUint8(offset) !== recencyCoordinateVersion) {
            throw new AuthenticatedStorageRecencyError(
                'Conflict',
                'External recency coordinate has an unsupported version.',
            );
        }
        offset += 1;
        const storageInstanceIdentity = bytes.slice(
            offset,
            offset + storageInstanceIdentityByteLength,
        );
        offset += storageInstanceIdentityByteLength;
        const namespaceSequence = view.getBigUint64(offset, true);
        offset += 8;
        const authenticatedHeadDigest = bytes.slice(
            offset,
            offset + authenticatedHeadDigestByteLength,
        );
        return {
            authenticatedHeadDigest,
            namespaceSequence,
            storageInstanceIdentity,
        };
    } finally {
        bytes.fill(0);
    }
};

/**
 * Serializes authenticated storage work against one external monotonic anchor.
 *
 * The external anchor stores opaque canonical bytes and supplies exact
 * compare-and-set semantics. A local head exactly one transition ahead can be
 * repaired only when its authenticated predecessor matches the anchored head,
 * with the authenticated zero sentinel for the first transition. Every older,
 * forked, wrong-instance, or multi-transition gap permanently retires this
 * coordinator.
 */
export class AuthenticatedStorageRecencyCoordinator {
    readonly #anchor: AuthenticatedStorageRecencyAnchor;
    readonly #store: UntrustedStorageTransactionStore;
    #operationTail: Promise<void> = Promise.resolve();
    #retirementFailure: AuthenticatedStorageRecencyError | undefined;

    public constructor(input: {
        anchor: AuthenticatedStorageRecencyAnchor;
        store: UntrustedStorageTransactionStore;
    }) {
        if (
            typeof input.anchor?.compareAndSet !== 'function' ||
            typeof input.anchor?.read !== 'function'
        ) {
            throw new AuthenticatedStorageRecencyError(
                'InvalidInput',
                'Authenticated storage recency requires a complete external anchor.',
            );
        }
        this.#anchor = input.anchor;
        this.#store = input.store;
    }

    public reconcile(): Promise<void> {
        return this.#runExclusive(async () => {
            const coordinate = await this.#reconcileInternal();
            destroyCoordinate(coordinate);
        });
    }

    public runRead<Result>(
        operation: (store: UntrustedStorageTransactionStore) => Promise<Result>,
    ): Promise<Result> {
        return this.#runExclusive(async () => {
            const before = await this.#reconcileInternal();
            let operationFailed = false;
            let operationFailure: unknown;
            let result: Result | undefined;
            try {
                result = await operation(this.#store);
            } catch (error) {
                operationFailed = true;
                operationFailure = error;
            }

            let after: AuthenticatedStorageLocalCoordinate | undefined;
            try {
                after = await this.#authenticateLocalCoordinate();
                if (!coordinatesEqual(before, after)) {
                    throw this.#retire(
                        'A read-only recency operation changed the authenticated local head.',
                    );
                }
                const reconciledAfter = await this.#reconcileInternal();
                try {
                    if (!coordinatesEqual(before, reconciledAfter)) {
                        throw this.#retire(
                            'The authenticated storage coordinate changed during a read-only operation.',
                        );
                    }
                } finally {
                    destroyCoordinate(reconciledAfter);
                }
            } catch (recencyFailure) {
                if (operationFailed) {
                    throw new AuthenticatedStorageRecencyError(
                        'StorageFailure',
                        'A read-only operation and its recency verification both failed.',
                        [operationFailure, recencyFailure],
                    );
                }
                throw recencyFailure;
            } finally {
                destroyCoordinate(before);
                destroyCoordinate(after);
            }

            if (operationFailed) {
                throw requireError(operationFailure, 'Read-only operation');
            }
            return result as Result;
        });
    }

    public runMutation<Result>(
        operation: (store: UntrustedStorageTransactionStore) => Promise<Result>,
    ): Promise<Result> {
        return this.#runExclusive(async () => {
            const before = await this.#reconcileInternal();
            let operationFailed = false;
            let operationFailure: unknown;
            let result: Result | undefined;
            try {
                result = await operation(this.#store);
            } catch (error) {
                operationFailed = true;
                operationFailure = error;
            }

            let after: AuthenticatedStorageLocalCoordinate | undefined;
            try {
                after = await this.#authenticateLocalCoordinate();
                if (coordinatesEqual(before, after)) {
                    if (!operationFailed) {
                        throw new AuthenticatedStorageRecencyError(
                            'InvalidState',
                            'A successful recency mutation did not advance the authenticated local head.',
                        );
                    }
                } else {
                    this.#requireSingleSuccessor(before, after);
                    await this.#advanceExternalAnchor(before, after);
                }
            } catch (recencyFailure) {
                if (operationFailed) {
                    throw new AuthenticatedStorageRecencyError(
                        'StorageFailure',
                        'A storage mutation and its recency reconciliation both failed.',
                        [operationFailure, recencyFailure],
                    );
                }
                throw recencyFailure;
            } finally {
                destroyCoordinate(before);
                destroyCoordinate(after);
            }

            if (operationFailed) {
                throw requireError(operationFailure, 'Storage mutation');
            }
            return result as Result;
        });
    }

    #runExclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        const scheduled = this.#operationTail.then(async () => {
            this.#assertActive();
            return operation();
        });
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    #assertActive(): void {
        if (this.#retirementFailure !== undefined) {
            throw this.#retirementFailure;
        }
    }

    #retire(
        message: string,
        failureCause?: unknown,
    ): AuthenticatedStorageRecencyError {
        if (this.#retirementFailure === undefined) {
            this.#retirementFailure = new AuthenticatedStorageRecencyError(
                'Conflict',
                message,
                failureCause,
            );
        }
        return this.#retirementFailure;
    }

    async #authenticateLocalCoordinate(): Promise<AuthenticatedStorageLocalCoordinate> {
        try {
            const snapshot = await this.#store.authenticateCurrentHead();
            if (
                typeof snapshot.namespaceSequence !== 'bigint' ||
                snapshot.namespaceSequence < 0n ||
                snapshot.namespaceSequence > unsigned64Maximum
            ) {
                throw this.#retire(
                    'Authenticated local storage returned an invalid namespace sequence.',
                );
            }
            if (
                (snapshot.namespaceSequence === 0n) !==
                (snapshot.predecessorAuthenticatedHeadDigest === undefined)
            ) {
                throw this.#retire(
                    'Authenticated local storage returned an inconsistent predecessor coordinate.',
                );
            }
            return {
                authenticatedHeadDigest: copyExactBytes(
                    snapshot.authenticatedHeadDigest,
                    authenticatedHeadDigestByteLength,
                    'authenticated local head digest',
                ),
                namespaceSequence: snapshot.namespaceSequence,
                predecessorAuthenticatedHeadDigest:
                    snapshot.predecessorAuthenticatedHeadDigest === undefined
                        ? undefined
                        : copyExactBytes(
                              snapshot.predecessorAuthenticatedHeadDigest,
                              authenticatedHeadDigestByteLength,
                              'authenticated local predecessor head digest',
                          ),
                storageInstanceIdentity: copyExactBytes(
                    snapshot.storageInstanceIdentity,
                    storageInstanceIdentityByteLength,
                    'local storage instance identity',
                ),
            };
        } catch (error) {
            if (error instanceof AuthenticatedStorageRecencyError) {
                if (error.code === 'Conflict') {
                    throw error;
                }
                throw this.#retire(
                    'Authenticated local storage returned a malformed coordinate.',
                    error,
                );
            }
            const mapped = mapStorageError(error);
            if (
                mapped.code === 'AuthenticationFailed' ||
                mapped.code === 'Conflict'
            ) {
                throw this.#retire(
                    'Authenticated local storage no longer matches its retained head.',
                    mapped,
                );
            }
            throw new AuthenticatedStorageRecencyError(
                'StorageFailure',
                'Authenticated local storage head could not be read.',
                mapped,
            );
        }
    }

    async #readExternalCoordinate(): Promise<
        ExternalRecencyCoordinate | undefined
    > {
        let value: unknown;
        try {
            value = await this.#anchor.read();
        } catch (error) {
            throw new AuthenticatedStorageRecencyError(
                'AnchorFailure',
                'External recency anchor could not be read.',
                error,
            );
        }
        if (value === undefined) {
            return undefined;
        }
        if (!isUint8Array(value)) {
            throw this.#retire(
                'External recency anchor returned a malformed value.',
            );
        }
        const untrustedBytes = value.slice();
        try {
            let coordinate: AuthenticatedStorageRecencyCoordinate;
            try {
                coordinate = decodeRecencyCoordinate(untrustedBytes);
            } catch (error) {
                if (
                    error instanceof AuthenticatedStorageRecencyError &&
                    error.code === 'Conflict'
                ) {
                    throw this.#retire(error.message, error);
                }
                throw this.#retire(
                    'External recency anchor returned noncanonical bytes.',
                    error,
                );
            }
            return {
                bytes: untrustedBytes.slice(),
                coordinate,
            };
        } finally {
            untrustedBytes.fill(0);
        }
    }

    async #compareAndSetExternalAnchor(
        expectedBytes: Uint8Array | null,
        nextBytes: Uint8Array,
    ): Promise<boolean> {
        const expectedCopy = expectedBytes?.slice() ?? null;
        const nextCopy = nextBytes.slice();
        try {
            let result: unknown;
            try {
                result = await this.#anchor.compareAndSet({
                    expectedBytes: expectedCopy,
                    nextBytes: nextCopy,
                });
            } catch (error) {
                throw new AuthenticatedStorageRecencyError(
                    'AnchorFailure',
                    'External recency compare-and-set failed.',
                    error,
                );
            }
            if (typeof result !== 'boolean') {
                throw new AuthenticatedStorageRecencyError(
                    'AnchorFailure',
                    'External recency compare-and-set returned a malformed result.',
                );
            }
            return result;
        } finally {
            expectedCopy?.fill(0);
            nextCopy.fill(0);
        }
    }

    async #reconcileInternal(): Promise<AuthenticatedStorageRecencyCoordinate> {
        this.#assertActive();
        const local = await this.#authenticateLocalCoordinate();
        let external: ExternalRecencyCoordinate | undefined;
        try {
            external = await this.#readExternalCoordinate();
            if (external === undefined) {
                if (local.namespaceSequence !== 0n) {
                    throw this.#retire(
                        'A nonempty authenticated local store has no external recency anchor.',
                    );
                }
                const localBytes = encodeRecencyCoordinate(local);
                try {
                    if (
                        await this.#compareAndSetExternalAnchor(
                            null,
                            localBytes,
                        )
                    ) {
                        return copyCoordinate(local);
                    }
                } finally {
                    localBytes.fill(0);
                }
                external = await this.#readExternalCoordinate();
                if (
                    external !== undefined &&
                    coordinatesEqual(local, external.coordinate)
                ) {
                    return copyCoordinate(local);
                }
                throw this.#retire(
                    'External recency initialization selected a different storage coordinate.',
                );
            }

            if (
                !bytesEqual(
                    local.storageInstanceIdentity,
                    external.coordinate.storageInstanceIdentity,
                )
            ) {
                throw this.#retire(
                    'External recency anchor belongs to a different storage instance.',
                );
            }
            if (coordinatesEqual(local, external.coordinate)) {
                return copyCoordinate(local);
            }
            this.#requireSingleSuccessor(external.coordinate, local);
            await this.#advanceExternalAnchor(external.coordinate, local);
            return copyCoordinate(local);
        } finally {
            destroyCoordinate(local);
            external?.bytes.fill(0);
            destroyCoordinate(external?.coordinate);
        }
    }

    #requireSingleSuccessor(
        predecessor: AuthenticatedStorageRecencyCoordinate,
        successor: AuthenticatedStorageLocalCoordinate,
    ): void {
        const predecessorDigestMatches =
            successor.predecessorAuthenticatedHeadDigest !== undefined &&
            (predecessor.namespaceSequence === 0n
                ? successor.predecessorAuthenticatedHeadDigest.every(
                      (byte) => byte === 0,
                  )
                : bytesEqual(
                      predecessor.authenticatedHeadDigest,
                      successor.predecessorAuthenticatedHeadDigest,
                  ));
        if (
            !bytesEqual(
                predecessor.storageInstanceIdentity,
                successor.storageInstanceIdentity,
            ) ||
            predecessor.namespaceSequence === unsigned64Maximum ||
            successor.namespaceSequence !==
                predecessor.namespaceSequence + 1n ||
            !predecessorDigestMatches
        ) {
            throw this.#retire(
                'Authenticated local storage is not one exact successor of the external recency coordinate.',
            );
        }
    }

    async #advanceExternalAnchor(
        predecessor: AuthenticatedStorageRecencyCoordinate,
        successor: AuthenticatedStorageLocalCoordinate,
    ): Promise<void> {
        this.#requireSingleSuccessor(predecessor, successor);
        const predecessorBytes = encodeRecencyCoordinate(predecessor);
        const successorBytes = encodeRecencyCoordinate(successor);
        let observed: ExternalRecencyCoordinate | undefined;
        try {
            if (
                await this.#compareAndSetExternalAnchor(
                    predecessorBytes,
                    successorBytes,
                )
            ) {
                return;
            }
            observed = await this.#readExternalCoordinate();
            if (
                observed !== undefined &&
                coordinatesEqual(observed.coordinate, successor)
            ) {
                return;
            }
            throw this.#retire(
                'External recency anchor selected a conflicting transition.',
            );
        } finally {
            predecessorBytes.fill(0);
            successorBytes.fill(0);
            observed?.bytes.fill(0);
            destroyCoordinate(observed?.coordinate);
        }
    }
}
