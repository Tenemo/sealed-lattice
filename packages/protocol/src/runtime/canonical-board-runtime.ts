import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';
import {
    openCanonicalBoardVerifierSession,
    type CanonicalBoardVerifierConfiguration,
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
    copyConfiguration(): CanonicalBoardVerifierConfiguration;
    copyCachedCarrier(
        snapshot: VerifiedCanonicalBoardSnapshot,
        objectHash: Uint8Array,
    ): VerificationResult<Uint8Array>;
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

export type CanonicalBoardRuntimeInput = Readonly<{
    configuration: CanonicalBoardVerifierConfiguration;
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
    readonly #configuration: CanonicalBoardVerifierConfiguration;
    readonly #objectsByHash = new Map<string, RetainedObject>();
    readonly #verifierSession: CanonicalBoardVerifierSession;
    #state: CanonicalBoardRuntimeState = 'active';

    public constructor(
        verifierSession: CanonicalBoardVerifierSession,
        configuration: CanonicalBoardVerifierConfiguration,
    ) {
        this.#verifierSession = verifierSession;
        this.#configuration = copyConfiguration(configuration);
    }

    public copyConfiguration(): CanonicalBoardVerifierConfiguration {
        return copyConfiguration(this.#configuration);
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
): VerificationResult<CanonicalBoardRuntime> => {
    let configuration: CanonicalBoardVerifierConfiguration;
    try {
        configuration = copyConfiguration(input.configuration);
    } catch {
        return refused('wrongTypeOrLength');
    }
    const opened = openCanonicalBoardVerifierSession({
        configuration,
        kernel: input.kernel,
    });
    if (!opened.isValid) {
        return opened;
    }
    return valid(
        Object.freeze(
            new CanonicalBoardRuntimeImplementation(
                opened.value,
                configuration,
            ),
        ),
    );
};

const copyConfiguration = (
    configuration: CanonicalBoardVerifierConfiguration,
): CanonicalBoardVerifierConfiguration =>
    Object.freeze({
        actionContextHash: configuration.actionContextHash.slice(),
        canonicalRosterBytes: configuration.canonicalRosterBytes.slice(),
        ceremonyContextHash: configuration.ceremonyContextHash.slice(),
        maximumBallotAttemptsPerParticipant:
            configuration.maximumBallotAttemptsPerParticipant,
        maximumRetainedCanonicalCarrierByteLength:
            configuration.maximumRetainedCanonicalCarrierByteLength,
        maximumRetainedTranscriptObjects:
            configuration.maximumRetainedTranscriptObjects,
        maximumUnorderedCarriersPerBatch:
            configuration.maximumUnorderedCarriersPerBatch,
        suiteIdentifier: configuration.suiteIdentifier.slice(),
    });
