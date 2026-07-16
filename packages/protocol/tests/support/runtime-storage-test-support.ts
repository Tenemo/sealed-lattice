import { createRuntimeRecordAuthenticatedRepairProtection } from '#packages/protocol/src/runtime/authenticated-runtime-record';
import type { RuntimeStorageAuthorityContext } from '#packages/protocol/src/runtime/durable-state-witness-service';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAuthenticatedRepairProtection,
    type UntrustedStorageAtomicMutation,
    type UntrustedStorageRepairReport,
    type UntrustedStorageTransactionLimits,
    type UntrustedStorageTransactionStore,
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

export class InMemoryRuntimeStorageAdapter implements UntrustedStorageAdapter {
    readonly #failedAtomicMutationNumbers = new Set<number>();
    #values = new Map<string, Uint8Array>();
    public afterNextAtomicMutation:
        | ((mutation: UntrustedStorageAtomicMutation) => void)
        | undefined;
    public atomicMutationCount = 0;
    public failNextDeleteCount = 0;
    public forceNextAtomicConflict = false;

    public read(key: string): Promise<Uint8Array | undefined> {
        return Promise.resolve(this.#values.get(key)?.slice());
    }

    public write(key: string, value: Uint8Array): Promise<void> {
        this.#values.set(key, value.slice());
        return Promise.resolve();
    }

    public delete(key: string): Promise<void> {
        if (this.failNextDeleteCount > 0) {
            this.failNextDeleteCount -= 1;
            return Promise.reject(new Error('injected delete failure'));
        }
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

    public deleteUnreferencedObjects(input: {
        indexPrefix: string;
        objectKeys: readonly string[];
    }): Promise<boolean> {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        const referencedObjectKeys = new Set(
            [...this.#values.entries()]
                .filter(([key]) => key.startsWith(input.indexPrefix))
                .map(([, value]) => decoder.decode(value)),
        );
        if (
            input.objectKeys.some((objectKey) =>
                referencedObjectKeys.has(objectKey),
            )
        ) {
            return Promise.resolve(false);
        }
        for (const objectKey of input.objectKeys) {
            this.#values.delete(objectKey);
        }
        return Promise.resolve(true);
    }

    public applyAtomicMutation(
        mutation: UntrustedStorageAtomicMutation,
    ): Promise<boolean> {
        this.atomicMutationCount += 1;
        if (
            this.#failedAtomicMutationNumbers.delete(this.atomicMutationCount)
        ) {
            return Promise.reject(
                new Error('injected atomic mutation failure'),
            );
        }
        if (this.forceNextAtomicConflict) {
            this.forceNextAtomicConflict = false;
            return Promise.resolve(false);
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
        const nextValues = new Map(
            [...this.#values.entries()].map(
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
        afterMutation?.(mutation);
        return Promise.resolve(true);
    }

    public failAtomicMutationAfter(additionalMutationCount: number): void {
        if (
            !Number.isSafeInteger(additionalMutationCount) ||
            additionalMutationCount <= 0
        ) {
            throw new Error('additionalMutationCount must be positive');
        }
        this.#failedAtomicMutationNumbers.add(
            this.atomicMutationCount + additionalMutationCount,
        );
    }

    public keys(): readonly string[] {
        return [...this.#values.keys()].sort();
    }

    public rawDelete(key: string): void {
        this.#values.delete(key);
    }

    public rawRead(key: string): Uint8Array | undefined {
        return this.#values.get(key)?.slice();
    }

    public rawWrite(key: string, value: Uint8Array): void {
        this.#values.set(key, value.slice());
    }
}

const defaultLimits: UntrustedStorageTransactionLimits = {
    maximumActiveTransactionCount: 8,
    maximumLeaseByteLength: 2 * 1_024 * 1_024,
    maximumLeaseCountPerTransaction: 8,
    maximumOwnedRecordCount: 256,
    maximumStoredValueByteLength: 32 * 1_024 * 1_024,
    maximumTransactionByteLength: 4 * 1_024 * 1_024,
    maximumTransactionLifetimeMilliseconds: 10_000,
};

const createIdentifierFactory = (): ((
    kind: 'lease' | 'transaction',
) => string) => {
    const counts = { lease: 0, transaction: 0 };
    return (kind) => {
        counts[kind] += 1;
        const kindByte = kind === 'transaction' ? '01' : '02';
        return `${kindByte}${counts[kind].toString(16).padStart(62, '0')}`;
    };
};

const authenticatedRepairProtections = new WeakMap<
    InMemoryRuntimeStorageAdapter,
    Promise<UntrustedStorageAuthenticatedRepairProtection>
>();

const authenticatedRepairProtectionFor = (
    adapter: InMemoryRuntimeStorageAdapter,
): Promise<UntrustedStorageAuthenticatedRepairProtection> => {
    let protection = authenticatedRepairProtections.get(adapter);
    if (protection === undefined) {
        protection = generateRuntimeStorageEncryptionKey().then(
            (encryptionKey) =>
                createRuntimeRecordAuthenticatedRepairProtection({
                    authorityContext: runtimeAuthorityContext(),
                    encryptionKey,
                    maximumRecordSealingCount: 0x1_0000_0000,
                }),
        );
        authenticatedRepairProtections.set(adapter, protection);
    }
    return protection;
};

export const openRuntimeTestStore = async (input?: {
    adapter?: InMemoryRuntimeStorageAdapter;
    limits?: Partial<UntrustedStorageTransactionLimits>;
    namespace?: string;
}): Promise<{
    adapter: InMemoryRuntimeStorageAdapter;
    repairReport: UntrustedStorageRepairReport;
    store: UntrustedStorageTransactionStore;
}> => {
    const adapter = input?.adapter ?? new InMemoryRuntimeStorageAdapter();
    const opened = await openUntrustedStorageTransactionStore({
        adapter,
        authenticatedRepairProtection:
            await authenticatedRepairProtectionFor(adapter),
        createIdentifier: createIdentifierFactory(),
        limits: { ...defaultLimits, ...input?.limits },
        monotonicClockMilliseconds: () => 0,
        namespace: input?.namespace ?? 'runtime-service-test',
    });
    return { adapter, ...opened };
};

export const generateRuntimeStorageEncryptionKey =
    async (): Promise<CryptoKey> =>
        globalThis.crypto.subtle.generateKey(
            { length: 256, name: 'AES-GCM' },
            false,
            ['decrypt', 'encrypt'],
        );

export const hashFilledWith = (byte: number): Uint8Array =>
    new Uint8Array(64).fill(byte);

export const runtimeAuthorityContext = (
    overrides: Partial<RuntimeStorageAuthorityContext> = {},
): RuntimeStorageAuthorityContext => ({
    actionContextHash: hashFilledWith(0x33),
    ceremonyContextHash: hashFilledWith(0x22),
    ownerParticipantIdentity: hashFilledWith(0x44),
    runtimeBuildManifestHash: hashFilledWith(0x55),
    suiteIdentifier: hashFilledWith(0x11),
    ...overrides,
});
