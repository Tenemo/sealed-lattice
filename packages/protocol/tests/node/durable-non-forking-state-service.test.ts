import { hash512Hex } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    deriveStateRecoveryProducerSequence,
    deriveStateWitnessVoteProducerSequence,
    DurableNonForkingStateError,
    DurableNonForkingStateService,
    type DurableExactOutputScope,
    type DurableExactOutputInspector,
    type DurableExactOutputRecordContext,
    type DurableStateCryptography,
    type DurableStateWitnessVoteSigningInput,
    type ResolvedDurableStateIntent,
    type ResolvedDurableStateWitnessVote,
} from '#packages/protocol/src/runtime/durable-non-forking-state-service';
import {
    openUntrustedStorageTransactionStore,
    type UntrustedStorageAdapter,
    type UntrustedStorageAtomicMutation,
    type UntrustedStorageTransactionLimits,
    type UntrustedStorageTransactionStore,
} from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';

const textEncoder = new TextEncoder();
const storageNamespace = 'durable-state-tests';
const authenticationTagByteLength = 64;
let openedStoreCount = 0;

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

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array =>
    Uint8Array.from({ length: hex.length / 2 }, (_, byteIndex) =>
        Number.parseInt(hex.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
    );

const hash = (seed: number): Uint8Array => new Uint8Array(64).fill(seed);

const copyIntent = (
    intent: ResolvedDurableStateIntent,
): ResolvedDurableStateIntent => {
    const base = {
        actionContextHash: intent.actionContextHash.slice(),
        intentObjectHash: intent.intentObjectHash.slice(),
        stateKey: intent.stateKey.slice(),
        subjectEpoch: intent.subjectEpoch,
        subjectParticipantIdentity: intent.subjectParticipantIdentity.slice(),
    };
    if (intent.voteKind === 'reservation') {
        return { ...base, voteKind: 'reservation' };
    }
    if (intent.voteKind === 'output') {
        return {
            ...base,
            exactOutputHash: intent.exactOutputHash.slice(),
            reservationIntentObjectHash:
                intent.reservationIntentObjectHash.slice(),
            voteKind: 'output',
        };
    }

    return {
        ...base,
        ...(intent.preservedOutputIntentObjectHash === undefined
            ? {}
            : {
                  preservedOutputIntentObjectHash:
                      intent.preservedOutputIntentObjectHash.slice(),
              }),
        ...(intent.preservedReservationIntentObjectHash === undefined
            ? {}
            : {
                  preservedReservationIntentObjectHash:
                      intent.preservedReservationIntentObjectHash.slice(),
              }),
        voteKind: 'recovery',
    };
};

const copyVote = (
    vote: ResolvedDurableStateWitnessVote,
): ResolvedDurableStateWitnessVote => ({
    actionContextHash: vote.actionContextHash.slice(),
    intentObjectHash: vote.intentObjectHash.slice(),
    producerSequence: vote.producerSequence,
    stateKey: vote.stateKey.slice(),
    subjectParticipantIdentity: vote.subjectParticipantIdentity.slice(),
    witnessParticipantIdentity: vote.witnessParticipantIdentity.slice(),
});

class InMemoryStorageAdapter implements UntrustedStorageAdapter {
    #values = new Map<string, Uint8Array>();
    public afterSuccessfulAtomicMutation:
        | ((mutationAttemptCount: number) => void)
        | undefined;
    public atomicMutationAttemptCount = 0;
    public readonly conflictMutationAttempts = new Set<number>();
    public deleteFailure: Error | undefined;

    public read(key: string): Promise<Uint8Array | undefined> {
        return Promise.resolve(this.#values.get(key)?.slice());
    }

    public write(key: string, value: Uint8Array): Promise<void> {
        this.#values.set(key, value.slice());
        return Promise.resolve();
    }

    public delete(key: string): Promise<void> {
        if (this.deleteFailure !== undefined) {
            const failure = this.deleteFailure;
            this.deleteFailure = undefined;
            return Promise.reject(failure);
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

    public applyAtomicMutation(
        mutation: UntrustedStorageAtomicMutation,
    ): Promise<boolean> {
        this.atomicMutationAttemptCount += 1;
        if (
            this.conflictMutationAttempts.delete(
                this.atomicMutationAttemptCount,
            )
        ) {
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
        this.afterSuccessfulAtomicMutation?.(this.atomicMutationAttemptCount);

        return Promise.resolve(true);
    }

    public deleteLogicalRecord(logicalRecordKey: string): void {
        const indexKey = this.#indexKey(logicalRecordKey);
        const objectKeyBytes = this.#values.get(indexKey);
        if (objectKeyBytes !== undefined) {
            const objectKey = new TextDecoder().decode(objectKeyBytes);
            this.#values.delete(objectKey);
            this.#values.delete(indexKey);
        }
    }

    public overwriteLogicalRecord(
        logicalRecordKey: string,
        bytes: Uint8Array,
    ): void {
        const objectKeyBytes = this.#values.get(
            this.#indexKey(logicalRecordKey),
        );
        if (objectKeyBytes === undefined) {
            throw new Error('logical record is absent');
        }
        this.#values.set(
            new TextDecoder().decode(objectKeyBytes),
            bytes.slice(),
        );
    }

    public logicalRecordKeys(): readonly string[] {
        const indexPrefix = `sealed-lattice-runtime-store/${storageNamespace}/indices/`;
        return [...this.#values.keys()]
            .filter((key) => key.startsWith(indexPrefix))
            .map((key) => {
                const hex = key.slice(indexPrefix.length);
                return new TextDecoder().decode(
                    Uint8Array.from(
                        { length: hex.length / 2 },
                        (_, byteIndex) =>
                            Number.parseInt(
                                hex.slice(byteIndex * 2, byteIndex * 2 + 2),
                                16,
                            ),
                    ),
                );
            })
            .sort();
    }

    #indexKey(logicalRecordKey: string): string {
        return `sealed-lattice-runtime-store/${storageNamespace}/indices/${bytesToHex(
            textEncoder.encode(logicalRecordKey),
        )}`;
    }
}

class TestStateWorld {
    readonly intentBindings = new Map<string, ResolvedDurableStateIntent>();
    readonly voteBindings = new Map<string, ResolvedDurableStateWitnessVote>();
    #carrierNumber = 0;
    #voteNumber = 0;

    public registerIntent(intent: ResolvedDurableStateIntent): Uint8Array {
        this.#carrierNumber += 1;
        const bytes = new Uint8Array(8);
        bytes[0] = 0x49;
        new DataView(bytes.buffer).setUint32(1, this.#carrierNumber, true);
        bytes[5] =
            intent.voteKind === 'reservation'
                ? 1
                : intent.voteKind === 'output'
                  ? 2
                  : 3;
        bytes[6] = intent.intentObjectHash[0] ?? 0;
        bytes[7] = intent.stateKey[0] ?? 0;
        this.intentBindings.set(bytesToHex(bytes), copyIntent(intent));

        return bytes;
    }

    public registerVote(
        signingInput: DurableStateWitnessVoteSigningInput,
    ): Uint8Array {
        this.#voteNumber += 1;
        const bytes = new Uint8Array(8);
        bytes[0] = 0x56;
        new DataView(bytes.buffer).setUint32(1, this.#voteNumber, true);
        bytes[5] = signingInput.intentObjectHash[0] ?? 0;
        bytes[6] = Number(signingInput.producerSequence & 0xffn);
        bytes[7] = signingInput.witnessParticipantIdentity[0] ?? 0;
        this.voteBindings.set(bytesToHex(bytes), {
            actionContextHash: signingInput.actionContextHash.slice(),
            intentObjectHash: signingInput.intentObjectHash.slice(),
            producerSequence: signingInput.producerSequence,
            stateKey: signingInput.stateKey.slice(),
            subjectParticipantIdentity:
                signingInput.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                signingInput.witnessParticipantIdentity.slice(),
        });

        return bytes;
    }
}

class TestStateCryptography implements DurableStateCryptography {
    readonly #world: TestStateWorld;
    public failNextSigning = false;
    public failVoteResolutionInvocation: number | undefined;
    public signingCount = 0;
    public voteResolutionCount = 0;

    public constructor(world: TestStateWorld) {
        this.#world = world;
    }

    public readonly resolveStateIntent = (input: {
        canonicalIntentCarrier: Uint8Array;
    }): ResolvedDurableStateIntent => {
        const intent = this.#world.intentBindings.get(
            bytesToHex(input.canonicalIntentCarrier),
        );
        if (intent === undefined) {
            throw new Error('intent signature or canonical bytes are invalid');
        }

        return copyIntent(intent);
    };

    public readonly signStateWitnessVote = (
        input: DurableStateWitnessVoteSigningInput,
    ): Uint8Array => {
        this.signingCount += 1;
        if (this.failNextSigning) {
            this.failNextSigning = false;
            throw new Error('injected signing interruption');
        }

        return this.#world.registerVote(input);
    };

    public readonly resolveSignedStateWitnessVote = (input: {
        canonicalSignedStateWitnessVoteCarrier: Uint8Array;
    }): ResolvedDurableStateWitnessVote => {
        this.voteResolutionCount += 1;
        if (this.voteResolutionCount === this.failVoteResolutionInvocation) {
            this.failVoteResolutionInvocation = undefined;
            throw new Error('injected signed-carrier reread interruption');
        }
        const vote = this.#world.voteBindings.get(
            bytesToHex(input.canonicalSignedStateWitnessVoteCarrier),
        );
        if (vote === undefined) {
            throw new Error('vote signature or canonical bytes are invalid');
        }

        return copyVote(vote);
    };
}

class TestExactOutputCryptography {
    public failOpenInvocation: number | undefined;
    public readonly generationReservationIdentifiers: Uint8Array[] = [];
    public readonly generationReservationSourceBuffers: Uint8Array[] = [];
    public openCount = 0;
    public readonly openedGenerationReservationBuffers: Uint8Array[] = [];

    public readonly seal = (input: {
        context: DurableExactOutputRecordContext;
        plaintext: Uint8Array;
    }): Uint8Array => {
        if (
            input.context.logicalRecordKey.endsWith('/generation-reservation')
        ) {
            this.generationReservationIdentifiers.push(input.plaintext.slice());
            this.generationReservationSourceBuffers.push(input.plaintext);
        }
        const tag = this.#tag(input.context, input.plaintext);
        const sealed = new Uint8Array(
            tag.byteLength + input.plaintext.byteLength,
        );
        sealed.set(tag);
        sealed.set(input.plaintext, tag.byteLength);

        return sealed;
    };

    public readonly open = (input: {
        context: DurableExactOutputRecordContext;
        sealedBytes: Uint8Array;
    }): Uint8Array => {
        this.openCount += 1;
        if (this.openCount === this.failOpenInvocation) {
            this.failOpenInvocation = undefined;
            throw new Error('injected exact-output reread interruption');
        }
        if (input.sealedBytes.byteLength <= authenticationTagByteLength) {
            throw new Error('sealed exact output is truncated');
        }
        const tag = input.sealedBytes.slice(0, authenticationTagByteLength);
        const plaintext = input.sealedBytes.slice(authenticationTagByteLength);
        if (
            input.context.logicalRecordKey.endsWith('/generation-reservation')
        ) {
            this.openedGenerationReservationBuffers.push(plaintext);
        }
        if (!bytesEqual(tag, this.#tag(input.context, plaintext))) {
            throw new Error('sealed exact output authentication failed');
        }

        return plaintext;
    };

    #tag(
        context: DurableExactOutputRecordContext,
        plaintext: Uint8Array,
    ): Uint8Array {
        return hexToBytes(
            hash512Hex('sealed-lattice/test/durable-exact-output/v1', [
                textEncoder.encode(context.logicalRecordKey),
                context.stateKey,
                context.reservationIntentObjectHash,
                plaintext,
            ]),
        );
    }
}

class TestGenerationReservationCryptoProvider implements Pick<
    Crypto,
    'getRandomValues'
> {
    #identifierNumber = 0;

    public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        if (!(array instanceof Uint8Array)) {
            throw new Error('test randomness requires a Uint8Array');
        }
        this.#identifierNumber += 1;
        array.fill(0xa5);
        new DataView(
            array.buffer,
            array.byteOffset,
            array.byteLength,
        ).setUint32(0, this.#identifierNumber, true);

        return array;
    }
}

class FailingGenerationReservationCryptoProvider implements Pick<
    Crypto,
    'getRandomValues'
> {
    public getRandomValues<T extends ArrayBufferView | null>(_array: T): T {
        throw new Error('injected generation reservation entropy failure');
    }
}

class ZeroGenerationReservationCryptoProvider implements Pick<
    Crypto,
    'getRandomValues'
> {
    public getRandomValues<T extends ArrayBufferView | null>(array: T): T {
        return array;
    }
}

const sharedGenerationReservationCryptoProvider =
    new TestGenerationReservationCryptoProvider();

const storageLimits: UntrustedStorageTransactionLimits = {
    maximumActiveTransactionCount: 16,
    maximumLeaseByteLength: 4_096,
    maximumLeaseCountPerTransaction: 8,
    maximumStoredValueByteLength: 262_144,
    maximumTransactionByteLength: 16_384,
    maximumTransactionLifetimeMilliseconds: 5_000,
};

const stateLimits = {
    maximumCanonicalCarrierByteLength: 1_024,
    maximumConflictRetryCount: 8,
    maximumExactOutputByteLength: 128,
    maximumSealedExactOutputByteLength: 256,
    maximumStateCertificateByteLength: 2_048,
    transactionLifetimeMilliseconds: 1_000,
} as const;

const createIdentifierFactory = (
    storeIdentifier: number,
): ((kind: 'lease' | 'transaction') => string) => {
    const counts = { lease: 0, transaction: 0 };

    return (kind) => {
        counts[kind] += 1;
        return `${kind}-${storeIdentifier
            .toString()
            .padStart(8, '0')}-${counts[kind].toString().padStart(8, '0')}`;
    };
};

const openStorage = async (
    adapter = new InMemoryStorageAdapter(),
): Promise<{
    adapter: InMemoryStorageAdapter;
    store: UntrustedStorageTransactionStore;
}> => {
    openedStoreCount += 1;
    const opened = await openUntrustedStorageTransactionStore({
        adapter,
        createIdentifier: createIdentifierFactory(openedStoreCount),
        limits: storageLimits,
        monotonicClockMilliseconds: () => 0,
        namespace: storageNamespace,
    });

    return { adapter, store: opened.store };
};

const createService = (
    store: UntrustedStorageTransactionStore,
    cryptography: TestStateCryptography,
    exactOutputCryptography = new TestExactOutputCryptography(),
    generationReservationCryptoProvider: Pick<
        Crypto,
        'getRandomValues'
    > = sharedGenerationReservationCryptoProvider,
): DurableNonForkingStateService =>
    new DurableNonForkingStateService({
        cryptography,
        generationReservationCryptoProvider,
        limits: stateLimits,
        openExactOutput: exactOutputCryptography.open,
        sealExactOutput: exactOutputCryptography.seal,
        store,
        witnessParticipantIdentity: hash(240),
    });

const reservationIntent = (input: {
    actionSeed?: number;
    epoch?: bigint;
    intentSeed: number;
    stateSeed: number;
    subjectSeed?: number;
}): ResolvedDurableStateIntent => ({
    actionContextHash: hash(input.actionSeed ?? 10),
    intentObjectHash: hash(input.intentSeed),
    stateKey: hash(input.stateSeed),
    subjectEpoch: input.epoch ?? 0n,
    subjectParticipantIdentity: hash(input.subjectSeed ?? 20),
    voteKind: 'reservation',
});

const outputIntent = (input: {
    exactOutputHash: Uint8Array;
    intentSeed: number;
    reservationIntentObjectHash: Uint8Array;
    stateSeed: number;
}): ResolvedDurableStateIntent => ({
    actionContextHash: hash(10),
    exactOutputHash: input.exactOutputHash.slice(),
    intentObjectHash: hash(input.intentSeed),
    reservationIntentObjectHash: input.reservationIntentObjectHash.slice(),
    stateKey: hash(input.stateSeed),
    subjectEpoch: 0n,
    subjectParticipantIdentity: hash(20),
    voteKind: 'output',
});

const recoveryIntent = (input: {
    intentSeed: number;
    preservedOutputHash?: Uint8Array;
    preservedReservationHash?: Uint8Array;
    stateSeed: number;
}): ResolvedDurableStateIntent => ({
    actionContextHash: hash(10),
    intentObjectHash: hash(input.intentSeed),
    ...(input.preservedOutputHash === undefined
        ? {}
        : {
              preservedOutputIntentObjectHash:
                  input.preservedOutputHash.slice(),
          }),
    ...(input.preservedReservationHash === undefined
        ? {}
        : {
              preservedReservationIntentObjectHash:
                  input.preservedReservationHash.slice(),
          }),
    stateKey: hash(input.stateSeed),
    subjectEpoch: 1n,
    subjectParticipantIdentity: hash(20),
    voteKind: 'recovery',
});

const inspectExactOutput: DurableExactOutputInspector = (input) => ({
    exactOutputHash: hexToBytes(
        hash512Hex('sealed-lattice/test/state-exact-output/v1', [
            input.stateKey,
            input.reservationIntentObjectHash,
            input.exactOutputBytes,
        ]),
    ),
});

const exactOutputScope = (
    stateSeed: number,
    reservationSeed: number,
): DurableExactOutputScope => ({
    reservationIntentObjectHash: hash(reservationSeed),
    stateKey: hash(stateSeed),
});

describe('durable non-forking state service', () => {
    it('derives every canonical producer sequence and refuses u64 overflow', () => {
        expect(deriveStateWitnessVoteProducerSequence('reservation', 0n)).toBe(
            1n,
        );
        expect(deriveStateWitnessVoteProducerSequence('output', 0n)).toBe(2n);
        expect(deriveStateWitnessVoteProducerSequence('recovery', 1n)).toBe(3n);

        const maximumUnsigned64 = (1n << 64n) - 1n;
        const largestReservationEpoch = (maximumUnsigned64 - 1n) / 3n;
        const largestOutputEpoch = (maximumUnsigned64 - 2n) / 3n;
        const largestRecoveryEpoch = maximumUnsigned64 / 3n;
        expect(
            deriveStateWitnessVoteProducerSequence(
                'reservation',
                largestReservationEpoch,
            ),
        ).toBe(largestReservationEpoch * 3n + 1n);
        expect(
            deriveStateWitnessVoteProducerSequence(
                'output',
                largestOutputEpoch,
            ),
        ).toBe(largestOutputEpoch * 3n + 2n);
        expect(
            deriveStateWitnessVoteProducerSequence(
                'recovery',
                largestRecoveryEpoch,
            ),
        ).toBe(largestRecoveryEpoch * 3n);
        expect(() =>
            deriveStateWitnessVoteProducerSequence(
                'reservation',
                largestReservationEpoch + 1n,
            ),
        ).toThrow(expect.objectContaining({ code: 'OutsideSupportedProfile' }));
        expect(() =>
            deriveStateWitnessVoteProducerSequence(
                'output',
                largestOutputEpoch + 1n,
            ),
        ).toThrow(expect.objectContaining({ code: 'OutsideSupportedProfile' }));
        expect(() =>
            deriveStateWitnessVoteProducerSequence(
                'recovery',
                largestRecoveryEpoch + 1n,
            ),
        ).toThrow(expect.objectContaining({ code: 'OutsideSupportedProfile' }));
        expect(() =>
            deriveStateWitnessVoteProducerSequence('recovery', 0n),
        ).toThrow(expect.objectContaining({ code: 'InvalidInput' }));
        expect(
            deriveStateRecoveryProducerSequence(maximumUnsigned64 - 1n),
        ).toBe(maximumUnsigned64);
        expect(() =>
            deriveStateRecoveryProducerSequence(maximumUnsigned64),
        ).toThrow(expect.objectContaining({ code: 'OutsideSupportedProfile' }));
    });

    it('durably locks before signing and returns the first cached carrier on replay', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const cryptography = new TestStateCryptography(world);
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 31, stateSeed: 41 }),
        );
        const service = createService(store, cryptography);

        const first = await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: carrier,
        });
        carrier.fill(0xff);
        const replayCarrier = world.registerIntent(
            reservationIntent({ intentSeed: 31, stateSeed: 41 }),
        );
        const replay = await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: replayCarrier,
        });

        expect(replay).toEqual(first);
        expect(cryptography.signingCount).toBe(1);
        expect(adapter.atomicMutationAttemptCount).toBe(2);
        expect(adapter.logicalRecordKeys()).toHaveLength(3);
    });

    it('persists the lock across a signing interruption and resumes only that intent', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const cryptography = new TestStateCryptography(world);
        cryptography.failNextSigning = true;
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 32, stateSeed: 42 }),
        );
        const conflict = world.registerIntent(
            reservationIntent({ intentSeed: 33, stateSeed: 42 }),
        );
        const service = createService(store, cryptography);

        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).rejects.toMatchObject({ code: 'SigningFailed' });
        expect(adapter.atomicMutationAttemptCount).toBe(1);
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: conflict,
            }),
        ).rejects.toMatchObject({ code: 'Equivocation' });
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).resolves.toBeInstanceOf(Uint8Array);
        expect(adapter.atomicMutationAttemptCount).toBe(2);
    });

    it('recovers the committed carrier after an interruption before its explicit reread', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const interruptedCryptography = new TestStateCryptography(world);
        interruptedCryptography.failVoteResolutionInvocation = 5;
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 34, stateSeed: 43 }),
        );

        await expect(
            createService(
                store,
                interruptedCryptography,
            ).obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(adapter.atomicMutationAttemptCount).toBe(2);

        const recoveredCryptography = new TestStateCryptography(world);
        const recovered = await createService(
            store,
            recoveredCryptography,
        ).obtainSignedWitnessVote({ canonicalIntentCarrier: carrier });
        expect(recovered).toBeInstanceOf(Uint8Array);
        expect(recoveredCryptography.signingCount).toBe(0);
        expect(adapter.atomicMutationAttemptCount).toBe(2);
    });

    it('retries a known uncommitted cache conflict without losing the durable lock', async () => {
        const { adapter, store } = await openStorage();
        adapter.conflictMutationAttempts.add(2);
        const world = new TestStateWorld();
        const cryptography = new TestStateCryptography(world);
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 35, stateSeed: 44 }),
        );

        const result = await createService(
            store,
            cryptography,
        ).obtainSignedWitnessVote({ canonicalIntentCarrier: carrier });
        expect(result).toBeInstanceOf(Uint8Array);
        expect(adapter.atomicMutationAttemptCount).toBe(3);
        expect(cryptography.signingCount).toBe(2);
    });

    it('bounds sustained compare-and-lock contention and leaves no live transaction behind', async () => {
        const { adapter, store } = await openStorage();
        for (
            let mutationAttempt = 1;
            mutationAttempt <= 20;
            mutationAttempt += 1
        ) {
            adapter.conflictMutationAttempts.add(mutationAttempt);
        }
        const world = new TestStateWorld();
        const cryptography = new TestStateCryptography(world);
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 39, stateSeed: 47 }),
        );
        const service = createService(store, cryptography);

        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).rejects.toMatchObject({ code: 'ConflictExhausted' });
        expect(adapter.atomicMutationAttemptCount).toBe(9);
        adapter.conflictMutationAttempts.clear();
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).resolves.toBeInstanceOf(Uint8Array);
    });

    it('allows one concurrent reservation and refuses the conflicting caller', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const first = world.registerIntent(
            reservationIntent({ intentSeed: 36, stateSeed: 45 }),
        );
        const second = world.registerIntent(
            reservationIntent({ intentSeed: 37, stateSeed: 45 }),
        );
        const firstService = createService(
            store,
            new TestStateCryptography(world),
        );
        const secondService = createService(
            store,
            new TestStateCryptography(world),
        );

        const outcomes = await Promise.allSettled([
            firstService.obtainSignedWitnessVote({
                canonicalIntentCarrier: first,
            }),
            secondService.obtainSignedWitnessVote({
                canonicalIntentCarrier: second,
            }),
        ]);
        expect(
            outcomes.filter((outcome) => outcome.status === 'fulfilled'),
        ).toHaveLength(1);
        const rejection = outcomes.find(
            (outcome) => outcome.status === 'rejected',
        )!;
        expect(rejection.reason).toMatchObject({ code: 'Equivocation' });
    });

    it('makes concurrent identical callers converge on one exact signed carrier', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 38, stateSeed: 46 }),
        );
        const services = Array.from({ length: 6 }, () =>
            createService(store, new TestStateCryptography(world)),
        );

        const carriers = await Promise.all(
            services.map((service) =>
                service.obtainSignedWitnessVote({
                    canonicalIntentCarrier: carrier,
                }),
            ),
        );
        for (const observed of carriers) {
            expect(observed).toEqual(carriers[0]);
        }
    });

    it('requires the matching reservation before locking an output and refuses a second output', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const reservation = reservationIntent({
            intentSeed: 40,
            stateSeed: 50,
        });
        const reservationCarrier = world.registerIntent(reservation);
        const firstOutputCarrier = world.registerIntent(
            outputIntent({
                exactOutputHash: hash(90),
                intentSeed: 41,
                reservationIntentObjectHash: reservation.intentObjectHash,
                stateSeed: 50,
            }),
        );

        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: firstOutputCarrier,
            }),
        ).rejects.toMatchObject({ code: 'MissingPrerequisite' });
        await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: reservationCarrier,
        });
        await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: firstOutputCarrier,
        });
        const conflictingOutput = world.registerIntent(
            outputIntent({
                exactOutputHash: hash(91),
                intentSeed: 42,
                reservationIntentObjectHash: reservation.intentObjectHash,
                stateSeed: 50,
            }),
        );
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: conflictingOutput,
            }),
        ).rejects.toMatchObject({ code: 'Equivocation' });
    });

    it('materializes recovery preservation and prevents a recovery that omits a local lock', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const reservation = reservationIntent({
            intentSeed: 50,
            stateSeed: 60,
        });
        const reservationCarrier = world.registerIntent(reservation);
        const output = outputIntent({
            exactOutputHash: hash(100),
            intentSeed: 51,
            reservationIntentObjectHash: reservation.intentObjectHash,
            stateSeed: 60,
        });
        const outputCarrier = world.registerIntent(output);
        const recoveryCarrier = world.registerIntent(
            recoveryIntent({
                intentSeed: 52,
                preservedOutputHash: output.intentObjectHash,
                preservedReservationHash: reservation.intentObjectHash,
                stateSeed: 60,
            }),
        );

        await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: recoveryCarrier,
            canonicalPreservedOutputIntentCarrier: outputCarrier,
            canonicalPreservedReservationIntentCarrier: reservationCarrier,
        });
        const omission = world.registerIntent(
            recoveryIntent({ intentSeed: 53, stateSeed: 60 }),
        );
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: omission,
            }),
        ).rejects.toMatchObject({ code: 'Equivocation' });
        const conflictingReservation = world.registerIntent(
            reservationIntent({ intentSeed: 54, stateSeed: 60 }),
        );
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: conflictingReservation,
            }),
        ).rejects.toMatchObject({ code: 'Equivocation' });
    });

    it('authenticates durable locks and cached carriers before replay', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 60, stateSeed: 70 }),
        );
        const service = createService(store, new TestStateCryptography(world));
        await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: carrier,
        });
        const voteKey = adapter
            .logicalRecordKeys()
            .find((key) => key.startsWith('non-forking-state/votes/'))!;
        adapter.overwriteLogicalRecord(voteKey, new Uint8Array([0xff]));
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
    });

    it('refuses a cached carrier whose durable producer lock was lost', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const carrier = world.registerIntent(
            reservationIntent({ intentSeed: 61, stateSeed: 71 }),
        );
        const service = createService(store, new TestStateCryptography(world));
        await service.obtainSignedWitnessVote({
            canonicalIntentCarrier: carrier,
        });
        const intentKey = adapter
            .logicalRecordKeys()
            .find((key) => key.startsWith('non-forking-state/vote-intents/'))!;
        adapter.deleteLogicalRecord(intentKey);
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: carrier,
            }),
        ).rejects.toMatchObject({ code: 'CorruptRecord' });
    });

    it('caches exact output bytes once and never invokes a replacement producer', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const scope = exactOutputScope(80, 81);
        const source = new Uint8Array([1, 2, 3, 4, 5]);
        const first = await service.obtainExactOutput({
            createExactOutput: () => source,
            inspectExactOutput,
            scope,
        });
        source.fill(0xff);
        const replay = await service.obtainExactOutput({
            createExactOutput: () => {
                throw new Error('replacement producer must not run');
            },
            inspectExactOutput,
            scope,
        });
        expect(replay.exactOutputBytes).toEqual(
            new Uint8Array([1, 2, 3, 4, 5]),
        );
        expect(replay.exactOutputHash).toEqual(first.exactOutputHash);
    });

    it('requires fresh nonzero injected entropy before every new generation', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const exactOutputCryptography = new TestExactOutputCryptography();
        const service = createService(
            store,
            new TestStateCryptography(world),
            exactOutputCryptography,
        );
        await service.obtainExactOutput({
            createExactOutput: () => new Uint8Array([1, 2, 3]),
            inspectExactOutput,
            scope: exactOutputScope(120, 121),
        });
        await service.obtainExactOutput({
            createExactOutput: () => new Uint8Array([4, 5, 6]),
            inspectExactOutput,
            scope: exactOutputScope(122, 123),
        });

        expect(
            exactOutputCryptography.generationReservationIdentifiers,
        ).toHaveLength(2);
        const [firstIdentifier, secondIdentifier] =
            exactOutputCryptography.generationReservationIdentifiers;
        expect(firstIdentifier).toHaveLength(32);
        expect(secondIdentifier).toHaveLength(32);
        expect(firstIdentifier?.some((byte) => byte !== 0)).toBe(true);
        expect(secondIdentifier?.some((byte) => byte !== 0)).toBe(true);
        expect(firstIdentifier).not.toEqual(secondIdentifier);
        expect(
            exactOutputCryptography.generationReservationSourceBuffers.every(
                (identifier) => identifier.every((byte) => byte === 0),
            ),
        ).toBe(true);
        const openedReservationBuffersRetainBytes =
            exactOutputCryptography.openedGenerationReservationBuffers.map(
                (identifier) => identifier.some((byte) => byte !== 0),
            );
        expect(openedReservationBuffersRetainBytes).toEqual(
            new Array<boolean>(openedReservationBuffersRetainBytes.length).fill(
                false,
            ),
        );
        expect(
            adapter
                .logicalRecordKeys()
                .filter((key) => key.endsWith('/generation-reservation')),
        ).toHaveLength(2);
    });

    it('fails before producer entry when injected generation entropy fails', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        let producerInvoked = false;
        let entropyFailure: unknown;
        try {
            await createService(
                store,
                new TestStateCryptography(world),
                new TestExactOutputCryptography(),
                new FailingGenerationReservationCryptoProvider(),
            ).obtainExactOutput({
                createExactOutput: () => {
                    producerInvoked = true;

                    return new Uint8Array([7, 8, 9]);
                },
                inspectExactOutput,
                scope: exactOutputScope(124, 125),
            });
            entropyFailure = new Error(
                'entropy failure unexpectedly succeeded',
            );
        } catch (error) {
            entropyFailure = error;
        }
        expect(entropyFailure).toMatchObject({
            code: 'RandomnessUnavailable',
        });
        expect(
            (entropyFailure as DurableNonForkingStateError).failureCause,
        ).toMatchObject({
            message: 'injected generation reservation entropy failure',
        });
        expect(producerInvoked).toBe(false);
        expect(adapter.logicalRecordKeys()).toEqual([]);

        await expect(
            createService(
                store,
                new TestStateCryptography(world),
                new TestExactOutputCryptography(),
                new ZeroGenerationReservationCryptoProvider(),
            ).obtainExactOutput({
                createExactOutput: () => new Uint8Array([1]),
                inspectExactOutput,
                scope: exactOutputScope(126, 127),
            }),
        ).rejects.toMatchObject({ code: 'RandomnessUnavailable' });
        expect(adapter.logicalRecordKeys()).toEqual([]);
    });

    it('allows only the durable reservation owner to generate under concurrency', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const scope = exactOutputScope(82, 83);
        const services = Array.from({ length: 5 }, () =>
            createService(store, new TestStateCryptography(world)),
        );
        let signalWinningProducerEntered: (() => void) | undefined;
        const winningProducerEntered = new Promise<void>((resolve) => {
            signalWinningProducerEntered = resolve;
        });
        let releaseWinningProducer: (() => void) | undefined;
        const winningProducerRelease = new Promise<void>((resolve) => {
            releaseWinningProducer = resolve;
        });
        let winningProducerInvocationCount = 0;
        const winningOutputPromise = services[0].obtainExactOutput({
            createExactOutput: async () => {
                winningProducerInvocationCount += 1;
                signalWinningProducerEntered?.();
                await winningProducerRelease;

                return new Uint8Array([1, 9, 8, 7]);
            },
            inspectExactOutput,
            scope,
        });
        await winningProducerEntered;

        const losingProducerInvocationCounts = [0, 0, 0, 0];
        const losingAttempts = services.slice(1).map((service, serviceIndex) =>
            service.obtainExactOutput({
                createExactOutput: () => {
                    losingProducerInvocationCounts[serviceIndex] =
                        (losingProducerInvocationCounts[serviceIndex] ?? 0) + 1;

                    return new Uint8Array([serviceIndex + 2, 9, 8, 7]);
                },
                inspectExactOutput,
                scope,
            }),
        );
        const losingResults = await Promise.allSettled(losingAttempts);
        const losingFailures = losingResults.map((result) => {
            if (result.status === 'fulfilled') {
                throw new Error(
                    'a non-owning exact-output generation unexpectedly succeeded',
                );
            }

            const failure: unknown = result.reason;
            return failure;
        });
        for (const result of losingResults) {
            expect(result.status).toBe('rejected');
        }
        for (const losingFailure of losingFailures) {
            expect(losingFailure).toMatchObject({
                code: 'ExactOutputUnavailable',
            });
        }
        expect(losingProducerInvocationCounts).toEqual([0, 0, 0, 0]);

        releaseWinningProducer?.();
        const winningOutput = await winningOutputPromise;
        expect(winningProducerInvocationCount).toBe(1);
        const replayedOutputs = await Promise.all(
            services.slice(1).map((service) =>
                service.obtainExactOutput({
                    createExactOutput: () => {
                        throw new Error(
                            'cached output must suppress generation',
                        );
                    },
                    inspectExactOutput,
                    scope,
                }),
            ),
        );
        for (const replayedOutput of replayedOutputs) {
            expect(replayedOutput.exactOutputBytes).toEqual(
                winningOutput.exactOutputBytes,
            );
            expect(replayedOutput.exactOutputHash).toEqual(
                winningOutput.exactOutputHash,
            );
        }
    });

    it('reuses one generation only across same-call storage conflict retries', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const scope = exactOutputScope(86, 87);
        adapter.conflictMutationAttempts.add(2);
        let producerInvocationCount = 0;

        const output = await service.obtainExactOutput({
            createExactOutput: () => {
                producerInvocationCount += 1;

                return new Uint8Array([6, 7, 8, 9]);
            },
            inspectExactOutput,
            scope,
        });

        expect(output.exactOutputBytes).toEqual(new Uint8Array([6, 7, 8, 9]));
        expect(producerInvocationCount).toBe(1);
        expect(adapter.atomicMutationAttemptCount).toBe(3);
    });

    it('never regenerates after a consumed generation reservation survives a crash', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const scope = exactOutputScope(88, 89);
        let producerInvocationCount = 0;
        await expect(
            createService(
                store,
                new TestStateCryptography(world),
            ).obtainExactOutput({
                createExactOutput: () => {
                    producerInvocationCount += 1;
                    throw new Error('injected process interruption');
                },
                inspectExactOutput,
                scope,
            }),
        ).rejects.toMatchObject({ code: 'StorageFailure' });
        expect(producerInvocationCount).toBe(1);
        const generationReservationKey = adapter
            .logicalRecordKeys()
            .find((key) => key.endsWith('/generation-reservation'));
        expect(generationReservationKey).toBeDefined();

        await expect(
            createService(
                store,
                new TestStateCryptography(world),
            ).obtainExactOutput({
                createExactOutput: () => {
                    producerInvocationCount += 1;

                    return new Uint8Array([1, 1, 1, 1]);
                },
                inspectExactOutput,
                scope,
            }),
        ).rejects.toMatchObject({ code: 'ExactOutputUnavailable' });
        expect(producerInvocationCount).toBe(1);

        adapter.overwriteLogicalRecord(
            generationReservationKey!,
            new Uint8Array([0xff]),
        );
        await expect(
            createService(
                store,
                new TestStateCryptography(world),
            ).obtainExactOutput({
                createExactOutput: () => {
                    producerInvocationCount += 1;

                    return new Uint8Array([2, 2, 2, 2]);
                },
                inspectExactOutput,
                scope,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(producerInvocationCount).toBe(1);
    });

    it('surfaces both state mutation and transaction abort failures', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const exactOutputCryptography = new TestExactOutputCryptography();
        exactOutputCryptography.failOpenInvocation = 2;
        adapter.deleteFailure = new Error('injected abort cleanup failure');

        let observedFailure: unknown;
        try {
            await createService(
                store,
                new TestStateCryptography(world),
                exactOutputCryptography,
            ).obtainExactOutput({
                createExactOutput: () => new Uint8Array([3, 5, 7, 9]),
                inspectExactOutput,
                scope: exactOutputScope(112, 113),
            });
        } catch (error) {
            observedFailure = error;
        }

        expect(observedFailure).toMatchObject({
            code: 'StorageFailure',
            failureCause: {
                cleanupFailure: {
                    code: 'CleanupFailed',
                },
                name: 'DurableStateTransactionCleanupError',
                originalFailure: {
                    code: 'AuthenticationFailed',
                },
            },
            name: 'DurableNonForkingStateError',
        });
    });

    it('recovers an exact output committed before its explicit authenticated reread', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const interruptedOutputCryptography = new TestExactOutputCryptography();
        adapter.afterSuccessfulAtomicMutation = (mutationAttemptCount) => {
            if (mutationAttemptCount === 2) {
                interruptedOutputCryptography.failOpenInvocation =
                    interruptedOutputCryptography.openCount + 1;
            }
        };
        const scope = exactOutputScope(84, 85);
        await expect(
            createService(
                store,
                new TestStateCryptography(world),
                interruptedOutputCryptography,
            ).obtainExactOutput({
                createExactOutput: () => new Uint8Array([4, 3, 2, 1]),
                inspectExactOutput,
                scope,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(adapter.atomicMutationAttemptCount).toBe(2);

        const recovered = await createService(
            store,
            new TestStateCryptography(world),
        ).obtainExactOutput({
            createExactOutput: () => {
                throw new Error(
                    'committed bytes must recover without recreation',
                );
            },
            inspectExactOutput,
            scope,
        });
        expect(recovered.exactOutputBytes).toEqual(
            new Uint8Array([4, 3, 2, 1]),
        );
    });

    it('resolves an output certificate only against the cached exact bytes', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const scope = exactOutputScope(90, 91);
        const exactOutput = await service.obtainExactOutput({
            createExactOutput: () => new Uint8Array([7, 6, 5, 4]),
            inspectExactOutput,
            scope,
        });
        const outputCarrier = world.registerIntent(
            outputIntent({
                exactOutputHash: exactOutput.exactOutputHash,
                intentSeed: 92,
                reservationIntentObjectHash: scope.reservationIntentObjectHash,
                stateSeed: 90,
            }),
        );
        const certificate = new Uint8Array([1, 2, 3]);
        const resolution = await service.resolveStateCertificate({
            canonicalIntentCarrier: outputCarrier,
            canonicalStateCertificate: certificate,
            exactOutput: { inspectExactOutput, scope },
            verifyCertificate: (input) => {
                expect(input.canonicalStateCertificate).toEqual(certificate);
                expect(input.exactOutputBytes).toEqual(
                    exactOutput.exactOutputBytes,
                );

                return { kind: 'verified-output-capability' } as const;
            },
        });
        expect(resolution.verifiedCapability).toEqual({
            kind: 'verified-output-capability',
        });
        expect(resolution.exactOutputBytes).toEqual(
            exactOutput.exactOutputBytes,
        );
    });

    it('refuses an output intent that names different bytes before certificate resolution', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const scope = exactOutputScope(93, 94);
        await service.obtainExactOutput({
            createExactOutput: () => new Uint8Array([1, 3, 5, 7]),
            inspectExactOutput,
            scope,
        });
        const outputCarrier = world.registerIntent(
            outputIntent({
                exactOutputHash: hash(255),
                intentSeed: 95,
                reservationIntentObjectHash: scope.reservationIntentObjectHash,
                stateSeed: 93,
            }),
        );
        let certificateVerifierCalled = false;
        await expect(
            service.resolveStateCertificate({
                canonicalIntentCarrier: outputCarrier,
                canonicalStateCertificate: new Uint8Array([1]),
                exactOutput: { inspectExactOutput, scope },
                verifyCertificate: () => {
                    certificateVerifierCalled = true;
                    return {};
                },
            }),
        ).rejects.toMatchObject({ code: 'Equivocation' });
        expect(certificateVerifierCalled).toBe(false);
    });

    it('resolves reservation certificates without operation-specific state policy', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const reservationCarrier = world.registerIntent(
            reservationIntent({ intentSeed: 96, stateSeed: 97 }),
        );
        const resolution = await service.resolveStateCertificate({
            canonicalIntentCarrier: reservationCarrier,
            canonicalStateCertificate: new Uint8Array([9, 8, 7]),
            verifyCertificate: () =>
                ({ kind: 'verified-reservation' }) as const,
        });
        expect(resolution).toEqual({
            verifiedCapability: { kind: 'verified-reservation' },
        });
    });

    it('fails closed for missing exact output, corrupt sealed bytes, and self-witnessing', async () => {
        const { adapter, store } = await openStorage();
        const world = new TestStateWorld();
        const service = createService(store, new TestStateCryptography(world));
        const scope = exactOutputScope(100, 101);
        const missingOutputCarrier = world.registerIntent(
            outputIntent({
                exactOutputHash: hash(102),
                intentSeed: 103,
                reservationIntentObjectHash: scope.reservationIntentObjectHash,
                stateSeed: 100,
            }),
        );
        await expect(
            service.resolveStateCertificate({
                canonicalIntentCarrier: missingOutputCarrier,
                canonicalStateCertificate: new Uint8Array([1]),
                exactOutput: { inspectExactOutput, scope },
                verifyCertificate: () => ({}),
            }),
        ).rejects.toMatchObject({ code: 'ExactOutputUnavailable' });

        await service.obtainExactOutput({
            createExactOutput: () => new Uint8Array([2, 4, 6, 8]),
            inspectExactOutput,
            scope,
        });
        const exactOutputKey = adapter
            .logicalRecordKeys()
            .find(
                (key) =>
                    key.startsWith('non-forking-state/exact-outputs/') &&
                    !key.endsWith('/generation-reservation'),
            )!;
        adapter.overwriteLogicalRecord(exactOutputKey, new Uint8Array([0xff]));
        await expect(
            service.obtainExactOutput({
                createExactOutput: () => new Uint8Array([1]),
                inspectExactOutput,
                scope,
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });

        const selfIntent = world.registerIntent({
            ...reservationIntent({ intentSeed: 104, stateSeed: 105 }),
            subjectParticipantIdentity: hash(240),
        });
        await expect(
            service.obtainSignedWitnessVote({
                canonicalIntentCarrier: selfIntent,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });

    it('exhaustively explores bounded restart traces across reservation, output, and recovery branches', async () => {
        type ScheduleOperation =
            | 'canonicalOutput'
            | 'canonicalRecovery'
            | 'canonicalReservation'
            | 'conflictingOutput'
            | 'conflictingRecovery'
            | 'conflictingReservation';
        type WitnessVoteInput = Parameters<
            DurableNonForkingStateService['obtainSignedWitnessVote']
        >[0];

        const operations: readonly ScheduleOperation[] = [
            'canonicalReservation',
            'canonicalOutput',
            'canonicalRecovery',
            'conflictingReservation',
            'conflictingOutput',
            'conflictingRecovery',
        ];
        const canonicalBranch: readonly ScheduleOperation[] = [
            'canonicalReservation',
            'canonicalOutput',
            'canonicalRecovery',
        ];
        const conflictingBranch: readonly ScheduleOperation[] = [
            'conflictingReservation',
            'conflictingOutput',
            'conflictingRecovery',
        ];
        let exploredTraceCount = 0;

        for (const firstOperation of operations) {
            for (const secondOperation of operations) {
                for (const interruptedOperationIndex of [-1, 0, 1]) {
                    exploredTraceCount += 1;
                    const { store } = await openStorage();
                    const world = new TestStateWorld();
                    const canonicalReservation = reservationIntent({
                        intentSeed: 121,
                        stateSeed: 120,
                    });
                    const conflictingReservation = reservationIntent({
                        intentSeed: 122,
                        stateSeed: 120,
                    });
                    const canonicalOutput = outputIntent({
                        exactOutputHash: hash(123),
                        intentSeed: 124,
                        reservationIntentObjectHash:
                            canonicalReservation.intentObjectHash,
                        stateSeed: 120,
                    });
                    const conflictingOutput = outputIntent({
                        exactOutputHash: hash(125),
                        intentSeed: 126,
                        reservationIntentObjectHash:
                            conflictingReservation.intentObjectHash,
                        stateSeed: 120,
                    });
                    const canonicalReservationCarrier =
                        world.registerIntent(canonicalReservation);
                    const conflictingReservationCarrier = world.registerIntent(
                        conflictingReservation,
                    );
                    const canonicalOutputCarrier =
                        world.registerIntent(canonicalOutput);
                    const conflictingOutputCarrier =
                        world.registerIntent(conflictingOutput);
                    const canonicalRecoveryCarrier = world.registerIntent(
                        recoveryIntent({
                            intentSeed: 127,
                            preservedOutputHash:
                                canonicalOutput.intentObjectHash,
                            preservedReservationHash:
                                canonicalReservation.intentObjectHash,
                            stateSeed: 120,
                        }),
                    );
                    const conflictingRecoveryCarrier = world.registerIntent(
                        recoveryIntent({
                            intentSeed: 128,
                            preservedOutputHash:
                                conflictingOutput.intentObjectHash,
                            preservedReservationHash:
                                conflictingReservation.intentObjectHash,
                            stateSeed: 120,
                        }),
                    );
                    const inputByOperation: Record<
                        ScheduleOperation,
                        WitnessVoteInput
                    > = {
                        canonicalOutput: {
                            canonicalIntentCarrier: canonicalOutputCarrier,
                        },
                        canonicalRecovery: {
                            canonicalIntentCarrier: canonicalRecoveryCarrier,
                            canonicalPreservedOutputIntentCarrier:
                                canonicalOutputCarrier,
                            canonicalPreservedReservationIntentCarrier:
                                canonicalReservationCarrier,
                        },
                        canonicalReservation: {
                            canonicalIntentCarrier: canonicalReservationCarrier,
                        },
                        conflictingOutput: {
                            canonicalIntentCarrier: conflictingOutputCarrier,
                        },
                        conflictingRecovery: {
                            canonicalIntentCarrier: conflictingRecoveryCarrier,
                            canonicalPreservedOutputIntentCarrier:
                                conflictingOutputCarrier,
                            canonicalPreservedReservationIntentCarrier:
                                conflictingReservationCarrier,
                        },
                        conflictingReservation: {
                            canonicalIntentCarrier:
                                conflictingReservationCarrier,
                        },
                    };

                    const runOperation = async (
                        operation: ScheduleOperation,
                        interruptSigning: boolean,
                    ): Promise<Uint8Array | undefined> => {
                        const cryptography = new TestStateCryptography(world);
                        cryptography.failNextSigning = interruptSigning;
                        try {
                            return await createService(
                                store,
                                cryptography,
                            ).obtainSignedWitnessVote(
                                inputByOperation[operation],
                            );
                        } catch (error) {
                            if (
                                !(error instanceof DurableNonForkingStateError)
                            ) {
                                throw error;
                            }
                            if (
                                error.code !== 'Equivocation' &&
                                error.code !== 'MissingPrerequisite' &&
                                error.code !== 'SigningFailed'
                            ) {
                                throw error;
                            }
                            return undefined;
                        }
                    };
                    const runBranch = async (
                        branch: readonly ScheduleOperation[],
                    ): Promise<readonly (Uint8Array | undefined)[]> => {
                        const results: (Uint8Array | undefined)[] = [];
                        for (const operation of branch) {
                            results.push(await runOperation(operation, false));
                        }
                        return results;
                    };

                    await runOperation(
                        firstOperation,
                        interruptedOperationIndex === 0,
                    );
                    await runOperation(
                        secondOperation,
                        interruptedOperationIndex === 1,
                    );

                    const canonicalResults = await runBranch(canonicalBranch);
                    const conflictingResults =
                        await runBranch(conflictingBranch);
                    const canonicalWon = canonicalResults.every(
                        (result) => result !== undefined,
                    );
                    const conflictingWon = conflictingResults.every(
                        (result) => result !== undefined,
                    );
                    expect(Number(canonicalWon) + Number(conflictingWon)).toBe(
                        1,
                    );
                    const winningBranch = canonicalWon
                        ? canonicalBranch
                        : conflictingBranch;
                    const winningResults = canonicalWon
                        ? canonicalResults
                        : conflictingResults;
                    const losingResults = canonicalWon
                        ? conflictingResults
                        : canonicalResults;
                    expect(
                        losingResults.every((result) => result === undefined),
                    ).toBe(true);

                    const replayResults = await runBranch(winningBranch);
                    expect(replayResults).toEqual(winningResults);
                }
            }
        }

        expect(exploredTraceCount).toBe(108);
    });

    it('validates bounds before storage or cryptographic work', async () => {
        const { store } = await openStorage();
        const world = new TestStateWorld();
        const cryptography = new TestStateCryptography(world);
        expect(
            () =>
                new DurableNonForkingStateService({
                    cryptography,
                    generationReservationCryptoProvider:
                        sharedGenerationReservationCryptoProvider,
                    limits: {
                        ...stateLimits,
                        maximumConflictRetryCount: 33,
                    },
                    openExactOutput: new TestExactOutputCryptography().open,
                    sealExactOutput: new TestExactOutputCryptography().seal,
                    store,
                    witnessParticipantIdentity: hash(240),
                }),
        ).toThrow(expect.objectContaining({ code: 'InvalidConfiguration' }));

        const service = createService(store, cryptography);
        await expect(
            service.obtainExactOutput({
                createExactOutput: () => new Uint8Array(129),
                inspectExactOutput,
                scope: exactOutputScope(110, 111),
            }),
        ).rejects.toMatchObject({ code: 'BoundsExceeded' });
        expect(DurableNonForkingStateError).toBeTypeOf('function');
    });
});
