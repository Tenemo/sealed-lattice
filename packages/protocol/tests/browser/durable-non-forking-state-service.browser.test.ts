import { hash512Hex } from '@sealed-lattice/crypto';
import { afterEach, describe, expect, it } from 'vitest';

import {
    DurableNonForkingStateService,
    type DurableExactOutputInspector,
    type DurableExactOutputRecordContext,
    type DurableStateCryptography,
    type DurableStateWitnessVoteSigningInput,
    type ResolvedDurableStateIntent,
    type ResolvedDurableStateWitnessVote,
} from '#packages/protocol/src/runtime/durable-non-forking-state-service';
import {
    openWebLockOwnedStorageTransactionStore,
    type WebLockOwnedStorageTransactionStore,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { webLocksAvailable } from '#tests/support/browser-capabilities';

const textEncoder = new TextEncoder();
const authenticationTagByteLength = 64;
const openedHandles: WebLockOwnedStorageTransactionStore[] = [];
const databaseNames = new Set<string>();
const storageLimits = {
    maximumActiveTransactionCount: 16,
    maximumLeaseByteLength: 4_096,
    maximumLeaseCountPerTransaction: 8,
    maximumStoredValueByteLength: 262_144,
    maximumTransactionByteLength: 16_384,
    maximumTransactionLifetimeMilliseconds: 5_000,
} as const;

const stateLimits = {
    maximumCanonicalCarrierByteLength: 1_024,
    maximumConflictRetryCount: 8,
    maximumExactOutputByteLength: 128,
    maximumSealedExactOutputByteLength: 256,
    maximumStateCertificateByteLength: 2_048,
    transactionLifetimeMilliseconds: 5_000,
} as const;

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

class BrowserStateWorld {
    readonly intentBindings = new Map<string, ResolvedDurableStateIntent>();
    readonly voteBindings = new Map<string, ResolvedDurableStateWitnessVote>();
    #intentNumber = 0;
    #voteNumber = 0;

    public registerIntent(intent: ResolvedDurableStateIntent): Uint8Array {
        this.#intentNumber += 1;
        const carrier = new Uint8Array([0x49, this.#intentNumber, 0, 0]);
        this.intentBindings.set(bytesToHex(carrier), copyIntent(intent));

        return carrier;
    }

    public registerVote(
        input: DurableStateWitnessVoteSigningInput,
    ): Uint8Array {
        this.#voteNumber += 1;
        const carrier = new Uint8Array([0x56, this.#voteNumber, 0, 0]);
        this.voteBindings.set(bytesToHex(carrier), {
            actionContextHash: input.actionContextHash.slice(),
            intentObjectHash: input.intentObjectHash.slice(),
            producerSequence: input.producerSequence,
            stateKey: input.stateKey.slice(),
            subjectParticipantIdentity:
                input.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                input.witnessParticipantIdentity.slice(),
        });

        return carrier;
    }
}

class BrowserStateCryptography implements DurableStateCryptography {
    readonly #world: BrowserStateWorld;
    public failNextSigning = false;
    public failVoteResolutionInvocation: number | undefined;
    public signingCount = 0;
    #voteResolutionCount = 0;

    public constructor(world: BrowserStateWorld) {
        this.#world = world;
    }

    public readonly resolveStateIntent = (input: {
        canonicalIntentCarrier: Uint8Array;
    }): ResolvedDurableStateIntent => {
        const binding = this.#world.intentBindings.get(
            bytesToHex(input.canonicalIntentCarrier),
        );
        if (binding === undefined) {
            throw new Error('invalid browser intent carrier');
        }

        return copyIntent(binding);
    };

    public readonly signStateWitnessVote = (
        input: DurableStateWitnessVoteSigningInput,
    ): Uint8Array => {
        this.signingCount += 1;
        if (this.failNextSigning) {
            this.failNextSigning = false;
            throw new Error('injected browser signing interruption');
        }

        return this.#world.registerVote(input);
    };

    public readonly resolveSignedStateWitnessVote = (input: {
        canonicalSignedStateWitnessVoteCarrier: Uint8Array;
    }): ResolvedDurableStateWitnessVote => {
        this.#voteResolutionCount += 1;
        if (this.#voteResolutionCount === this.failVoteResolutionInvocation) {
            this.failVoteResolutionInvocation = undefined;
            throw new Error('injected browser cache reread interruption');
        }
        const binding = this.#world.voteBindings.get(
            bytesToHex(input.canonicalSignedStateWitnessVoteCarrier),
        );
        if (binding === undefined) {
            throw new Error('invalid browser witness vote carrier');
        }

        return {
            actionContextHash: binding.actionContextHash.slice(),
            intentObjectHash: binding.intentObjectHash.slice(),
            producerSequence: binding.producerSequence,
            stateKey: binding.stateKey.slice(),
            subjectParticipantIdentity:
                binding.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                binding.witnessParticipantIdentity.slice(),
        };
    };
}

class BrowserExactOutputCryptography {
    public readonly seal = (input: {
        context: DurableExactOutputRecordContext;
        plaintext: Uint8Array;
    }): Uint8Array => {
        const tag = this.#tag(input.context, input.plaintext);
        const sealedBytes = new Uint8Array(
            tag.byteLength + input.plaintext.byteLength,
        );
        sealedBytes.set(tag);
        sealedBytes.set(input.plaintext, tag.byteLength);

        return sealedBytes;
    };

    public readonly open = (input: {
        context: DurableExactOutputRecordContext;
        sealedBytes: Uint8Array;
    }): Uint8Array => {
        if (input.sealedBytes.byteLength <= authenticationTagByteLength) {
            throw new Error('sealed browser exact output is truncated');
        }
        const tag = input.sealedBytes.slice(0, authenticationTagByteLength);
        const plaintext = input.sealedBytes.slice(authenticationTagByteLength);
        if (!bytesEqual(tag, this.#tag(input.context, plaintext))) {
            throw new Error('browser exact output authentication failed');
        }

        return plaintext;
    };

    #tag(
        context: DurableExactOutputRecordContext,
        plaintext: Uint8Array,
    ): Uint8Array {
        return hexToBytes(
            hash512Hex('sealed-lattice/test/browser-state-output/v1', [
                textEncoder.encode(context.logicalRecordKey),
                context.stateKey,
                context.reservationIntentObjectHash,
                plaintext,
            ]),
        );
    }
}

const inspectExactOutput: DurableExactOutputInspector = (input) => ({
    exactOutputHash: hexToBytes(
        hash512Hex('sealed-lattice/test/browser-state-output-hash/v1', [
            input.stateKey,
            input.reservationIntentObjectHash,
            input.exactOutputBytes,
        ]),
    ),
});

const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);

    return `sealed-lattice-state-browser-test-${bytesToHex(randomBytes)}`;
};

const openOwnedStore = async (
    databaseName: string,
): Promise<WebLockOwnedStorageTransactionStore> => {
    databaseNames.add(databaseName);
    const handle = await openWebLockOwnedStorageTransactionStore({
        databaseName,
        limits: storageLimits,
        namespace: 'durable-non-forking-state',
    });
    openedHandles.push(handle);

    return handle;
};

const createService = (
    handle: WebLockOwnedStorageTransactionStore,
    cryptography: BrowserStateCryptography,
): DurableNonForkingStateService => {
    const exactOutputCryptography = new BrowserExactOutputCryptography();

    return new DurableNonForkingStateService({
        cryptography,
        generationReservationCryptoProvider: crypto,
        limits: stateLimits,
        openExactOutput: exactOutputCryptography.open,
        sealExactOutput: exactOutputCryptography.seal,
        store: handle.store,
        witnessParticipantIdentity: hash(240),
    });
};

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ?? new Error('state test deletion failed'),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () => reject(new Error('state test database deletion was blocked')),
            { once: true },
        );
    });

afterEach(async () => {
    for (const handle of openedHandles.splice(0).reverse()) {
        try {
            await handle.close();
        } catch {
            // A failed owned handle has already closed its adapter.
        }
    }
    for (const databaseName of databaseNames) {
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe.skipIf(!webLocksAvailable)(
    'Durable non-forking state service in browsers',
    () => {
        it('recovers signed-carrier and exact-output caches after IndexedDB reopen', async () => {
            const databaseName = createDatabaseName();
            const world = new BrowserStateWorld();
            const reservationBinding: ResolvedDurableStateIntent = {
                actionContextHash: hash(1),
                intentObjectHash: hash(2),
                stateKey: hash(3),
                subjectEpoch: 0n,
                subjectParticipantIdentity: hash(4),
                voteKind: 'reservation',
            };
            const reservationCarrier = world.registerIntent(reservationBinding);
            const scope = {
                reservationIntentObjectHash:
                    reservationBinding.intentObjectHash,
                stateKey: reservationBinding.stateKey,
            };
            const firstHandle = await openOwnedStore(databaseName);
            const firstService = createService(
                firstHandle,
                new BrowserStateCryptography(world),
            );
            const firstVote = await firstService.obtainSignedWitnessVote({
                canonicalIntentCarrier: reservationCarrier,
            });
            const firstOutput = await firstService.obtainExactOutput({
                createExactOutput: () => new Uint8Array([9, 7, 5, 3, 1]),
                inspectExactOutput,
                scope,
            });
            await firstHandle.close();

            const secondHandle = await openOwnedStore(databaseName);
            const recoveredCryptography = new BrowserStateCryptography(world);
            const secondService = createService(
                secondHandle,
                recoveredCryptography,
            );
            expect(
                await secondService.obtainSignedWitnessVote({
                    canonicalIntentCarrier: reservationCarrier,
                }),
            ).toEqual(firstVote);
            expect(recoveredCryptography.signingCount).toBe(0);
            const recoveredOutput = await secondService.obtainExactOutput({
                createExactOutput: () => {
                    throw new Error('browser cache must suppress regeneration');
                },
                inspectExactOutput,
                scope,
            });
            expect(recoveredOutput.exactOutputBytes).toEqual(
                firstOutput.exactOutputBytes,
            );

            const outputCarrier = world.registerIntent({
                actionContextHash: hash(1),
                exactOutputHash: firstOutput.exactOutputHash,
                intentObjectHash: hash(5),
                reservationIntentObjectHash:
                    reservationBinding.intentObjectHash,
                stateKey: reservationBinding.stateKey,
                subjectEpoch: 0n,
                subjectParticipantIdentity: hash(4),
                voteKind: 'output',
            });
            const resolution = await secondService.resolveStateCertificate({
                canonicalIntentCarrier: outputCarrier,
                canonicalStateCertificate: new Uint8Array([1, 2, 3]),
                exactOutput: { inspectExactOutput, scope },
                verifyCertificate: ({ exactOutputBytes }) => {
                    expect(exactOutputBytes).toEqual(
                        firstOutput.exactOutputBytes,
                    );

                    return { kind: 'browser-verified-output' } as const;
                },
            });
            expect(resolution.verifiedCapability).toEqual({
                kind: 'browser-verified-output',
            });
        });

        it('refuses exact-output regeneration after an interrupted browser generation', async () => {
            const databaseName = createDatabaseName();
            const world = new BrowserStateWorld();
            const scope = {
                reservationIntentObjectHash: hash(31),
                stateKey: hash(32),
            };
            let producerInvocationCount = 0;
            const firstHandle = await openOwnedStore(databaseName);
            await expect(
                createService(
                    firstHandle,
                    new BrowserStateCryptography(world),
                ).obtainExactOutput({
                    createExactOutput: () => {
                        producerInvocationCount += 1;
                        throw new Error('injected browser interruption');
                    },
                    inspectExactOutput,
                    scope,
                }),
            ).rejects.toMatchObject({ code: 'StorageFailure' });
            await firstHandle.close();

            const secondHandle = await openOwnedStore(databaseName);
            await expect(
                createService(
                    secondHandle,
                    new BrowserStateCryptography(world),
                ).obtainExactOutput({
                    createExactOutput: () => {
                        producerInvocationCount += 1;

                        return new Uint8Array([9, 9, 9, 9]);
                    },
                    inspectExactOutput,
                    scope,
                }),
            ).rejects.toMatchObject({ code: 'ExactOutputUnavailable' });
            expect(producerInvocationCount).toBe(1);
        });

        it('permits only one browser service to enter a concurrent exact-output producer', async () => {
            const databaseName = createDatabaseName();
            const world = new BrowserStateWorld();
            const handle = await openOwnedStore(databaseName);
            const firstService = createService(
                handle,
                new BrowserStateCryptography(world),
            );
            const secondService = createService(
                handle,
                new BrowserStateCryptography(world),
            );
            const scope = {
                reservationIntentObjectHash: hash(33),
                stateKey: hash(34),
            };
            let signalProducerEntered: (() => void) | undefined;
            const producerEntered = new Promise<void>((resolve) => {
                signalProducerEntered = resolve;
            });
            let releaseProducer: (() => void) | undefined;
            const producerRelease = new Promise<void>((resolve) => {
                releaseProducer = resolve;
            });
            const winningOutput = firstService.obtainExactOutput({
                createExactOutput: async () => {
                    signalProducerEntered?.();
                    await producerRelease;

                    return new Uint8Array([1, 3, 5, 7]);
                },
                inspectExactOutput,
                scope,
            });
            await producerEntered;
            let losingProducerInvoked = false;

            await expect(
                secondService.obtainExactOutput({
                    createExactOutput: () => {
                        losingProducerInvoked = true;

                        return new Uint8Array([2, 4, 6, 8]);
                    },
                    inspectExactOutput,
                    scope,
                }),
            ).rejects.toMatchObject({ code: 'ExactOutputUnavailable' });
            expect(losingProducerInvoked).toBe(false);

            releaseProducer?.();
            await expect(winningOutput).resolves.toMatchObject({
                exactOutputBytes: new Uint8Array([1, 3, 5, 7]),
            });
        });

        it('resumes a committed witness lock after signing interruption and serializes concurrent callers', async () => {
            const databaseName = createDatabaseName();
            const world = new BrowserStateWorld();
            const reservationCarrier = world.registerIntent({
                actionContextHash: hash(11),
                intentObjectHash: hash(12),
                stateKey: hash(13),
                subjectEpoch: 0n,
                subjectParticipantIdentity: hash(14),
                voteKind: 'reservation',
            });
            const firstHandle = await openOwnedStore(databaseName);
            const interruptedCryptography = new BrowserStateCryptography(world);
            interruptedCryptography.failNextSigning = true;
            await expect(
                createService(
                    firstHandle,
                    interruptedCryptography,
                ).obtainSignedWitnessVote({
                    canonicalIntentCarrier: reservationCarrier,
                }),
            ).rejects.toMatchObject({ code: 'SigningFailed' });
            await firstHandle.close();

            const secondHandle = await openOwnedStore(databaseName);
            const services = Array.from({ length: 2 }, () =>
                createService(
                    secondHandle,
                    new BrowserStateCryptography(world),
                ),
            );
            const votes = await Promise.all(
                services.map((service) =>
                    service.obtainSignedWitnessVote({
                        canonicalIntentCarrier: reservationCarrier,
                    }),
                ),
            );
            for (const vote of votes) {
                expect(vote).toEqual(votes[0]);
            }
        });

        it('recovers a signed carrier committed before its caller observed completion', async () => {
            const databaseName = createDatabaseName();
            const world = new BrowserStateWorld();
            const reservationCarrier = world.registerIntent({
                actionContextHash: hash(21),
                intentObjectHash: hash(22),
                stateKey: hash(23),
                subjectEpoch: 0n,
                subjectParticipantIdentity: hash(24),
                voteKind: 'reservation',
            });
            const firstHandle = await openOwnedStore(databaseName);
            const interruptedCryptography = new BrowserStateCryptography(world);
            interruptedCryptography.failVoteResolutionInvocation = 5;
            await expect(
                createService(
                    firstHandle,
                    interruptedCryptography,
                ).obtainSignedWitnessVote({
                    canonicalIntentCarrier: reservationCarrier,
                }),
            ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
            await firstHandle.close();

            const secondHandle = await openOwnedStore(databaseName);
            const recoveredCryptography = new BrowserStateCryptography(world);
            await expect(
                createService(
                    secondHandle,
                    recoveredCryptography,
                ).obtainSignedWitnessVote({
                    canonicalIntentCarrier: reservationCarrier,
                }),
            ).resolves.toBeInstanceOf(Uint8Array);
            expect(recoveredCryptography.signingCount).toBe(0);
        });
    },
);
