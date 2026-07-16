import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';
import {
    openCanonicalBoardVerifierSession,
    type CanonicalBoardContextInput,
    type CanonicalBoardVerifierSession,
    type TranscriptCoreKernel,
    type UntrustedCanonicalBoardCarrier,
    type VerifiedTranscriptObject,
    type VerifiedTranscriptObjectDescription,
} from '@sealed-lattice/wasm';

const hashByteLength = 64;

declare const verifiedCanonicalBoardSnapshotBrand: unique symbol;

/**
 * A process-local view containing only foundation-validated transcript objects.
 * Owning operation relations require their separate verifier capabilities.
 */
export type VerifiedCanonicalBoardSnapshot = Readonly<{
    readonly [verifiedCanonicalBoardSnapshotBrand]: true;
}>;

export type CanonicalBoardRuntimeState = 'active' | 'closed';

export type CanonicalBoardRuntime = Readonly<{
    close(): void;
    copyCanonicalCarrierSet(
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): VerificationResult<readonly UntrustedCanonicalBoardCarrier[]>;
    copyCachedCarrier(
        snapshot: VerifiedCanonicalBoardSnapshot,
        objectHash: Uint8Array,
    ): VerificationResult<Uint8Array>;
    copyContextInput(): CanonicalBoardContextInput;
    findObject(
        snapshot: VerifiedCanonicalBoardSnapshot,
        objectHash: Uint8Array,
    ): VerificationResult<VerifiedTranscriptObject>;
    ingestUnordered(
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): VerificationResult<VerifiedCanonicalBoardSnapshot>;
    objects(
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): VerificationResult<readonly VerifiedTranscriptObject[]>;
    state(): CanonicalBoardRuntimeState;
}>;

export type TransferableCanonicalBoardRuntime = CanonicalBoardRuntime &
    Readonly<{
        claimExclusiveOwner(): CanonicalBoardRuntime;
    }>;

export type CanonicalBoardRuntimeInput = Readonly<{
    contextInput: CanonicalBoardContextInput;
    kernel: TranscriptCoreKernel;
}>;

type RetainedObject = Readonly<{
    description: VerifiedTranscriptObjectDescription;
    object: VerifiedTranscriptObject;
}>;

type SnapshotRecord = Readonly<{
    objectsByHash: ReadonlyMap<string, RetainedObject>;
    runtime: CanonicalBoardRuntimeImplementation;
}>;

const snapshotRecords = new WeakMap<object, SnapshotRecord>();

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const bytesToKey = (bytes: Uint8Array): string => {
    let key = '';
    for (let index = 0; index < hashByteLength; index += 1) {
        key += bytes[index].toString(16).padStart(2, '0');
    }
    return key;
};

const isHash = (value: unknown): value is Uint8Array => {
    try {
        return (
            ArrayBuffer.isView(value) &&
            Object.prototype.toString.call(value) === '[object Uint8Array]' &&
            value.byteLength === hashByteLength
        );
    } catch {
        return false;
    }
};

const descriptionsEqual = (
    left: VerifiedTranscriptObjectDescription,
    right: VerifiedTranscriptObjectDescription,
): boolean => {
    if (left.objectType !== right.objectType) {
        return false;
    }
    for (let index = 0; index < hashByteLength; index += 1) {
        if (left.objectHash[index] !== right.objectHash[index]) {
            return false;
        }
    }
    return true;
};

const copyDescription = (
    description: VerifiedTranscriptObjectDescription,
): VerifiedTranscriptObjectDescription => {
    if (!isHash(description.objectHash)) {
        throw new Error(
            'The canonical-board verifier returned a malformed object hash.',
        );
    }
    const objectHash = new Uint8Array(hashByteLength);
    objectHash.set(description.objectHash);
    return Object.freeze({
        objectHash,
        objectType: description.objectType,
    });
};

class CanonicalBoardRuntimeImplementation implements CanonicalBoardRuntime {
    readonly #contextInput: CanonicalBoardContextInput;
    readonly #objectsByHash = new Map<string, RetainedObject>();
    readonly #verifierSession: CanonicalBoardVerifierSession;
    #state: CanonicalBoardRuntimeState = 'active';

    public constructor(
        verifierSession: CanonicalBoardVerifierSession,
        contextInput: CanonicalBoardContextInput,
    ) {
        this.#verifierSession = verifierSession;
        this.#contextInput = copyContextInput(contextInput);
    }

    public copyContextInput(): CanonicalBoardContextInput {
        return copyContextInput(this.#contextInput);
    }

    public state(): CanonicalBoardRuntimeState {
        return this.#state;
    }

    public ingestUnordered(
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): VerificationResult<VerifiedCanonicalBoardSnapshot> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        const verification =
            this.#verifierSession.verifyUnorderedCarriers(carriers);
        if (!verification.isValid) {
            return verification;
        }

        const described: RetainedObject[] = [];
        for (const object of verification.value) {
            const description = this.#verifierSession.describe(object);
            if (!description.isValid) {
                throw new Error(
                    `A newly verified transcript capability could not be described: ${description.refusalReason}.`,
                );
            }
            described.push(
                Object.freeze({
                    description: copyDescription(description.value),
                    object,
                }),
            );
        }

        for (const retained of described) {
            const key = bytesToKey(retained.description.objectHash);
            const previous = this.#objectsByHash.get(key);
            if (
                previous !== undefined &&
                !descriptionsEqual(previous.description, retained.description)
            ) {
                throw new Error(
                    'The canonical-board verifier reused an object hash for a different typed object.',
                );
            }
        }
        for (const retained of described) {
            const key = bytesToKey(retained.description.objectHash);
            if (!this.#objectsByHash.has(key)) {
                this.#objectsByHash.set(key, retained);
            }
        }
        return valid(this.#createSnapshot());
    }

    public objects(
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): VerificationResult<readonly VerifiedTranscriptObject[]> {
        const resolved = this.#resolveSnapshot(snapshot);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        return valid(
            Object.freeze(
                [...resolved.record.objectsByHash.values()].map(
                    (retained) => retained.object,
                ),
            ),
        );
    }

    public findObject(
        snapshot: VerifiedCanonicalBoardSnapshot,
        objectHash: Uint8Array,
    ): VerificationResult<VerifiedTranscriptObject> {
        const resolved = this.#resolveObject(snapshot, objectHash);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        return valid(resolved.retained.object);
    }

    public copyCachedCarrier(
        snapshot: VerifiedCanonicalBoardSnapshot,
        objectHash: Uint8Array,
    ): VerificationResult<Uint8Array> {
        const resolved = this.#resolveObject(snapshot, objectHash);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        return this.#verifierSession.copyCachedCarrier(
            resolved.retained.object,
        );
    }

    public copyCanonicalCarrierSet(
        snapshot: VerifiedCanonicalBoardSnapshot,
    ): VerificationResult<readonly UntrustedCanonicalBoardCarrier[]> {
        const resolved = this.#resolveSnapshot(snapshot);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        const carriers: UntrustedCanonicalBoardCarrier[] = [];
        for (const retained of resolved.record.objectsByHash.values()) {
            const copied = this.#verifierSession.copyCachedCarrier(
                retained.object,
            );
            if (!copied.isValid) {
                throw new Error(
                    `A retained transcript capability could not copy its canonical carrier: ${copied.refusalReason}.`,
                );
            }
            carriers.push(Object.freeze({ canonicalCarrier: copied.value }));
        }
        return valid(Object.freeze(carriers));
    }

    public close(): void {
        if (this.#state === 'closed') {
            return;
        }
        try {
            this.#verifierSession.close();
        } finally {
            if (this.#verifierSession.state() === 'closed') {
                this.#objectsByHash.clear();
                this.#state = 'closed';
            }
        }
    }

    #createSnapshot(): VerifiedCanonicalBoardSnapshot {
        const sortedObjects = [...this.#objectsByHash.entries()].sort(
            ([left], [right]) => (left < right ? -1 : left > right ? 1 : 0),
        );
        const snapshot = Object.freeze(
            Object.create(null) as object,
        ) as VerifiedCanonicalBoardSnapshot;
        snapshotRecords.set(snapshot, {
            objectsByHash: new Map(sortedObjects),
            runtime: this,
        });
        return snapshot;
    }

    #resolveSnapshot(
        snapshot: VerifiedCanonicalBoardSnapshot,
    ):
        | Readonly<{ record: SnapshotRecord }>
        | Readonly<{ refusalReason: RefusalReason }> {
        if (this.#state !== 'active') {
            return { refusalReason: 'consumedState' };
        }
        if (
            (typeof snapshot !== 'object' && typeof snapshot !== 'function') ||
            snapshot === null
        ) {
            return { refusalReason: 'wrongTypeOrLength' };
        }
        const record = snapshotRecords.get(snapshot);
        if (record === undefined || record.runtime !== this) {
            return { refusalReason: 'wrongContext' };
        }
        return { record };
    }

    #resolveObject(
        snapshot: VerifiedCanonicalBoardSnapshot,
        objectHash: Uint8Array,
    ):
        | Readonly<{ retained: RetainedObject }>
        | Readonly<{ refusalReason: RefusalReason }> {
        const resolvedSnapshot = this.#resolveSnapshot(snapshot);
        if ('refusalReason' in resolvedSnapshot) {
            return resolvedSnapshot;
        }
        if (!isHash(objectHash)) {
            return { refusalReason: 'wrongTypeOrLength' };
        }
        const retained = resolvedSnapshot.record.objectsByHash.get(
            bytesToKey(objectHash),
        );
        if (retained === undefined) {
            return { refusalReason: 'missingPrerequisite' };
        }
        return { retained };
    }
}

export const openCanonicalBoardRuntime = (
    input: CanonicalBoardRuntimeInput,
): VerificationResult<TransferableCanonicalBoardRuntime> => {
    let contextInput: CanonicalBoardContextInput;
    try {
        contextInput = copyContextInput(input.contextInput);
    } catch {
        return refused('wrongTypeOrLength');
    }
    const opened = openCanonicalBoardVerifierSession({
        contextInput,
        kernel: input.kernel,
    });
    if (!opened.isValid) {
        return opened;
    }
    return valid(
        makeTransferableCanonicalBoardRuntime(
            new CanonicalBoardRuntimeImplementation(opened.value, contextInput),
        ),
    );
};

const makeTransferableCanonicalBoardRuntime = (
    runtime: CanonicalBoardRuntime,
): TransferableCanonicalBoardRuntime => {
    let currentOwner: object = Object.freeze({});
    let ownershipClaimed = false;
    let closed = false;
    const assertOwner = (owner: object): void => {
        if (owner !== currentOwner) {
            throw new TypeError(
                'This canonical-board runtime wrapper is stale because ownership was transferred.',
            );
        }
    };
    const assertOpen = (owner: object): void => {
        assertOwner(owner);
        if (closed) {
            throw new TypeError('The canonical-board runtime is closed.');
        }
    };
    const createOwnedRuntime = (owner: object): CanonicalBoardRuntime =>
        Object.freeze({
            close: () => {
                assertOwner(owner);
                if (closed) {
                    return;
                }
                closed = true;
                runtime.close();
            },
            copyCachedCarrier: (snapshot, objectHash) => {
                assertOwner(owner);
                return runtime.copyCachedCarrier(snapshot, objectHash);
            },
            copyCanonicalCarrierSet: (snapshot) => {
                assertOwner(owner);
                return runtime.copyCanonicalCarrierSet(snapshot);
            },
            copyContextInput: () => {
                assertOwner(owner);
                return runtime.copyContextInput();
            },
            findObject: (snapshot, objectHash) => {
                assertOwner(owner);
                return runtime.findObject(snapshot, objectHash);
            },
            ingestUnordered: (carriers) => {
                assertOwner(owner);
                return runtime.ingestUnordered(carriers);
            },
            objects: (snapshot) => {
                assertOwner(owner);
                return runtime.objects(snapshot);
            },
            state: () => {
                assertOwner(owner);
                return closed ? 'closed' : runtime.state();
            },
        });
    const initialOwner = currentOwner;
    const initialRuntime = createOwnedRuntime(initialOwner);
    return Object.freeze({
        ...initialRuntime,
        claimExclusiveOwner: () => {
            assertOpen(initialOwner);
            if (ownershipClaimed) {
                throw new TypeError(
                    'Exclusive ownership of the canonical-board runtime was already claimed.',
                );
            }
            ownershipClaimed = true;
            currentOwner = Object.freeze({});
            return createOwnedRuntime(currentOwner);
        },
    });
};

const copyContextInput = (
    contextInput: CanonicalBoardContextInput,
): CanonicalBoardContextInput =>
    Object.freeze({
        actionIdentifier: contextInput.actionIdentifier,
        canonicalActionDefinitionBytes:
            contextInput.canonicalActionDefinitionBytes.slice(),
        canonicalBoardPolicyBytes:
            contextInput.canonicalBoardPolicyBytes.slice(),
        canonicalManifestBytes: contextInput.canonicalManifestBytes.slice(),
        canonicalRosterBytes: contextInput.canonicalRosterBytes.slice(),
        canonicalSuiteRecordBytes:
            contextInput.canonicalSuiteRecordBytes.slice(),
        ceremonyIdentifier: contextInput.ceremonyIdentifier,
        expectedActionContextHash:
            contextInput.expectedActionContextHash.slice(),
        expectedCeremonyContextHash:
            contextInput.expectedCeremonyContextHash.slice(),
        expectedSuiteIdentifier: contextInput.expectedSuiteIdentifier.slice(),
    });
