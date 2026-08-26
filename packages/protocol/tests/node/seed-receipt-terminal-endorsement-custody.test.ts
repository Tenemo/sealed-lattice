import { describe, expect, it } from 'vitest';

import {
    createRuntimeRecordProtection,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    SeedReceiptTerminalEndorsementCustody,
    deriveSeedReceiptTerminalEndorsementCustodyRecordByteLengths,
    type PreparedSeedReceiptTerminalEndorsementInventory,
    type SeedReceiptTerminalEndorsementCustodyContext,
    type SeedReceiptTerminalEndorsementCustodyKernel,
    type SeedReceiptTerminalEndorsementCustodyLimits,
    type SeedReceiptTerminalEndorsementProductionInput,
    type SeedReceiptTerminalEndorsementValidationInput,
} from '#packages/protocol/src/runtime/seed-receipt-terminal-endorsement-custody';
import {
    generateRuntimeStorageRootKey,
    hashFilledWith,
    InMemoryAuthenticatedStorageRecencyAnchor,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const testLimits: SeedReceiptTerminalEndorsementCustodyLimits = Object.freeze({
    maximumEndorsementAuthorizationBodyByteLength: 256,
    maximumVerifiedReceiptInventoryBodyByteLength: 256,
    maximumReceiptEnvelopeByteLength: 256,
    maximumEndorsementEnvelopeByteLength: 256,
    maximumTerminalBodyByteLength: 256,
    transactionLifetimeMilliseconds: 1_000,
});

const defaultContext = (): SeedReceiptTerminalEndorsementCustodyContext =>
    Object.freeze({
        parameterIdentity: hashFilledWith(0x11),
        participantCount: 4,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: hashFilledWith(0x22),
        endorserPosition: 2,
        rootTerminalIdentity: hashFilledWith(0x33),
    });

const deterministicCryptoProvider = (): Crypto => {
    let invocationCount = 0;
    return {
        getRandomValues: <Value extends ArrayBufferView>(
            value: Value,
        ): Value => {
            invocationCount += 1;
            const bytes = new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
            );
            for (
                let byteIndex = 0;
                byteIndex < bytes.byteLength;
                byteIndex += 1
            ) {
                bytes[byteIndex] =
                    ((invocationCount * 41 + byteIndex * 17) % 255) + 1;
            }
            return value;
        },
        subtle: globalThis.crypto.subtle,
    } as Crypto;
};

class VerifiedReceiptInventoryCapability {
    readonly #identity: number;

    public constructor(identity: number) {
        this.#identity = identity;
    }

    public identityForTest(): number {
        return this.#identity;
    }
}

type ProductionObservation = Readonly<{
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory;
    signatureRandomness: Uint8Array;
}>;

const copyPreparedInventory = (
    prepared: PreparedSeedReceiptTerminalEndorsementInventory,
): PreparedSeedReceiptTerminalEndorsementInventory =>
    Object.freeze({
        endorsementAuthorizationBodyBytes:
            prepared.endorsementAuthorizationBodyBytes.slice(),
        verifiedReceiptInventoryBodyBytes:
            prepared.verifiedReceiptInventoryBodyBytes.slice(),
        verifiedReceiptInventoryIdentity:
            prepared.verifiedReceiptInventoryIdentity.slice(),
        orderedReceiptEnvelopeBytes: Object.freeze(
            prepared.orderedReceiptEnvelopeBytes.map((receiptEnvelope) =>
                receiptEnvelope.slice(),
            ),
        ),
        retainedLocalReceiptBodyIdentity:
            prepared.retainedLocalReceiptBodyIdentity.slice(),
        retainedLocalReceiptEnvelopeIdentity:
            prepared.retainedLocalReceiptEnvelopeIdentity.slice(),
        terminalBodyBytes: prepared.terminalBodyBytes.slice(),
        terminalBodyIdentity: prepared.terminalBodyIdentity.slice(),
    });

const preparedInventoryForMarker = (
    marker: number,
): PreparedSeedReceiptTerminalEndorsementInventory =>
    Object.freeze({
        endorsementAuthorizationBodyBytes: new Uint8Array(13).fill(marker),
        verifiedReceiptInventoryBodyBytes: new Uint8Array(31).fill(marker),
        verifiedReceiptInventoryIdentity: hashFilledWith(marker + 1),
        orderedReceiptEnvelopeBytes: Object.freeze([
            new Uint8Array(17).fill(marker + 2),
            new Uint8Array(19).fill(marker + 3),
            new Uint8Array(23).fill(marker + 4),
            new Uint8Array(27).fill(marker + 5),
        ]),
        retainedLocalReceiptBodyIdentity: hashFilledWith(marker + 6),
        retainedLocalReceiptEnvelopeIdentity: hashFilledWith(marker + 7),
        terminalBodyBytes: new Uint8Array(29).fill(marker + 8),
        terminalBodyIdentity: hashFilledWith(marker + 9),
    });

const deterministicEnvelope = (
    input: SeedReceiptTerminalEndorsementProductionInput,
): Uint8Array => {
    const envelope = new Uint8Array(37);
    const variableByte =
        (input.signatureRandomness[0] ?? 0) ^
        (input.preparedInventory.verifiedReceiptInventoryIdentity[0] ?? 0) ^
        (input.preparedInventory.terminalBodyIdentity[0] ?? 0) ^
        (input.preparedInventory.retainedLocalReceiptBodyIdentity[0] ?? 0) ^
        (input.preparedInventory.retainedLocalReceiptEnvelopeIdentity[0] ?? 0);
    for (let byteIndex = 0; byteIndex < envelope.byteLength; byteIndex += 1) {
        envelope[byteIndex] = (variableByte + byteIndex * 7) & 0xff;
    }
    envelope[0] = 0xa1;
    envelope[1] =
        input.preparedInventory.verifiedReceiptInventoryIdentity[0] ?? 0;
    envelope[2] = input.preparedInventory.terminalBodyIdentity[0] ?? 0;
    return envelope;
};

class DeterministicTerminalEndorsementKernel implements SeedReceiptTerminalEndorsementCustodyKernel<VerifiedReceiptInventoryCapability> {
    public afterProduce: (() => void) | undefined;
    public failNextPreparationCount = 0;
    public failNextProductionCount = 0;
    public failNextValidationCount = 0;
    public malformedNextEnvelope = false;
    public preparationCallCount = 0;
    public readonly productionObservations: ProductionObservation[] = [];
    public readonly validationObservations: SeedReceiptTerminalEndorsementValidationInput[] =
        [];
    readonly #preparedByCapability = new WeakMap<
        VerifiedReceiptInventoryCapability,
        PreparedSeedReceiptTerminalEndorsementInventory
    >();
    #nextCapabilityIdentity = 1;

    public issueCapability(marker = 0x41): VerifiedReceiptInventoryCapability {
        return this.issuePreparedCapability(preparedInventoryForMarker(marker));
    }

    public issuePreparedCapability(
        preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory,
    ): VerifiedReceiptInventoryCapability {
        const capability = new VerifiedReceiptInventoryCapability(
            this.#nextCapabilityIdentity,
        );
        this.#nextCapabilityIdentity += 1;
        this.#preparedByCapability.set(
            capability,
            copyPreparedInventory(preparedInventory),
        );
        return capability;
    }

    public prepare(
        verifiedReceiptInventory: VerifiedReceiptInventoryCapability,
    ): PreparedSeedReceiptTerminalEndorsementInventory {
        this.preparationCallCount += 1;
        if (this.failNextPreparationCount > 0) {
            this.failNextPreparationCount -= 1;
            throw new Error(
                'Injected terminal endorsement preparation failure.',
            );
        }
        const prepared = this.#preparedByCapability.get(
            verifiedReceiptInventory,
        );
        if (prepared === undefined) {
            throw new Error('The test kernel did not issue this inventory.');
        }
        if (verifiedReceiptInventory.identityForTest() <= 0) {
            throw new Error('The test inventory capability has no identity.');
        }
        return copyPreparedInventory(prepared);
    }

    public produce(
        input: SeedReceiptTerminalEndorsementProductionInput,
    ): Uint8Array {
        this.productionObservations.push(
            Object.freeze({
                preparedInventory: copyPreparedInventory(
                    input.preparedInventory,
                ),
                signatureRandomness: input.signatureRandomness.slice(),
            }),
        );
        if (this.failNextProductionCount > 0) {
            this.failNextProductionCount -= 1;
            throw new Error(
                'Injected terminal endorsement production failure.',
            );
        }
        const envelope = deterministicEnvelope(input);
        this.afterProduce?.();
        if (this.malformedNextEnvelope) {
            this.malformedNextEnvelope = false;
            return envelope.subarray(0, 3);
        }
        return envelope;
    }

    public validate(
        input: SeedReceiptTerminalEndorsementValidationInput,
    ): void {
        this.validationObservations.push(
            Object.freeze({
                context: Object.freeze({
                    ...input.context,
                    parameterIdentity: input.context.parameterIdentity.slice(),
                    preparationContextIdentity:
                        input.context.preparationContextIdentity.slice(),
                    rootTerminalIdentity:
                        input.context.rootTerminalIdentity.slice(),
                }),
                preparedInventory: copyPreparedInventory(
                    input.preparedInventory,
                ),
                ...(input.endorsementEnvelopeBytes === undefined
                    ? {}
                    : {
                          endorsementEnvelopeBytes:
                              input.endorsementEnvelopeBytes.slice(),
                      }),
            }),
        );
        if (this.failNextValidationCount > 0) {
            this.failNextValidationCount -= 1;
            throw new Error(
                'Injected terminal endorsement validation failure.',
            );
        }
        if (
            input.context.participantCount !== 4 ||
            input.context.preparationAttemptOrdinal !== 0 ||
            input.context.endorserPosition !== 2 ||
            input.preparedInventory.endorsementAuthorizationBodyBytes
                .byteLength !== 13 ||
            input.preparedInventory.verifiedReceiptInventoryBodyBytes
                .byteLength !== 31 ||
            input.preparedInventory.orderedReceiptEnvelopeBytes.length !== 4 ||
            input.preparedInventory.terminalBodyBytes.byteLength !== 29
        ) {
            throw new Error(
                'Terminal endorsement preparation failed the test validator.',
            );
        }
        if (
            input.endorsementEnvelopeBytes !== undefined &&
            (input.endorsementEnvelopeBytes.byteLength !== 37 ||
                input.endorsementEnvelopeBytes[0] !== 0xa1 ||
                input.endorsementEnvelopeBytes[1] !==
                    input.preparedInventory
                        .verifiedReceiptInventoryIdentity[0] ||
                input.endorsementEnvelopeBytes[2] !==
                    input.preparedInventory.terminalBodyIdentity[0])
        ) {
            throw new Error(
                'Terminal endorsement envelope failed the test validator.',
            );
        }
    }
}

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

type CustodyFixture = Readonly<{
    adapter: InMemoryRuntimeStorageAdapter;
    anchor: InMemoryAuthenticatedStorageRecencyAnchor;
    context: SeedReceiptTerminalEndorsementCustodyContext;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: SeedReceiptTerminalEndorsementCustody<VerifiedReceiptInventoryCapability>;
    kernel: DeterministicTerminalEndorsementKernel;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const createFixture = async (input?: {
    context?: SeedReceiptTerminalEndorsementCustodyContext;
    kernel?: DeterministicTerminalEndorsementKernel;
}): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `seed-receipt-terminal-endorsement-custody-${fixtureOrdinal}`;
    const createIdentifier = createIdentifierFactory();
    const opened = await openRuntimeTestStore({
        createIdentifier,
        namespace,
    });
    const anchor = new InMemoryAuthenticatedStorageRecencyAnchor();
    const coordinator = new AuthenticatedStorageRecencyCoordinator({
        anchor,
        store: opened.store,
    });
    const rootKey = await generateRuntimeStorageRootKey();
    const cryptoProvider = deterministicCryptoProvider();
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider,
        maximumRecordSealingCount: 64,
        rootKey,
    });
    const context = input?.context ?? defaultContext();
    const kernel =
        input?.kernel ?? new DeterministicTerminalEndorsementKernel();
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        context,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody: new SeedReceiptTerminalEndorsementCustody({
            context,
            kernel,
            limits: testLimits,
            protection,
            recencyCoordinator: coordinator,
        }),
        kernel,
        namespace,
        protection,
        rootKey,
    });
};

const reopenCustody = async (
    fixture: CustodyFixture,
    kernel: DeterministicTerminalEndorsementKernel,
    context = fixture.context,
): Promise<
    SeedReceiptTerminalEndorsementCustody<VerifiedReceiptInventoryCapability>
> => {
    const reopened = await openRuntimeTestStore({
        adapter: fixture.adapter,
        createIdentifier: fixture.createIdentifier,
        namespace: fixture.namespace,
    });
    const coordinator = new AuthenticatedStorageRecencyCoordinator({
        anchor: fixture.anchor,
        store: reopened.store,
    });
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider: fixture.cryptoProvider,
        maximumRecordSealingCount: 64,
        rootKey: fixture.rootKey,
    });
    return new SeedReceiptTerminalEndorsementCustody({
        context,
        kernel,
        limits: testLimits,
        protection,
        recencyCoordinator: coordinator,
    });
};

describe('seed-receipt terminal endorsement custody', () => {
    it('independently accounts for the exact completion terminal endorsement records', () => {
        const derived =
            deriveSeedReceiptTerminalEndorsementCustodyRecordByteLengths({
                endorsementAuthorizationBodyByteLength: 174,
                verifiedReceiptInventoryBodyByteLength: 850,
                receiptEnvelopeByteLengths: Array.from(
                    { length: 10 },
                    () => 3_778,
                ),
                endorsementEnvelopeByteLength: 3_599,
                terminalBodyByteLength: 149,
            });
        const independentlyDerivedPrefixByteLength =
            4 + 2 + 1 + 64 * 7 + 2 * 3 + 4 * 3 + 2 + 10 * 4;
        const independentlyDerivedSharedPlaintextByteLength =
            independentlyDerivedPrefixByteLength + 850 + 149 + 174 + 10 * 3_778;
        const independentlyDerivedReservationPlaintextByteLength =
            independentlyDerivedSharedPlaintextByteLength + 32;
        const independentlyDerivedCompletedPlaintextByteLength =
            independentlyDerivedSharedPlaintextByteLength + 4 + 3_599;

        expect(derived).toEqual({
            completedCiphertextByteLength:
                independentlyDerivedCompletedPlaintextByteLength + 54,
            completedPlaintextByteLength:
                independentlyDerivedCompletedPlaintextByteLength,
            copyOnWriteCiphertextOverlapByteLength:
                independentlyDerivedReservationPlaintextByteLength +
                independentlyDerivedCompletedPlaintextByteLength +
                54 * 2,
            reservationCiphertextByteLength:
                independentlyDerivedReservationPlaintextByteLength + 54,
            reservationPlaintextByteLength:
                independentlyDerivedReservationPlaintextByteLength,
        });
        expect(derived).toEqual({
            completedCiphertextByteLength: 43_125,
            completedPlaintextByteLength: 43_071,
            copyOnWriteCiphertextOverlapByteLength: 82_679,
            reservationCiphertextByteLength: 39_554,
            reservationPlaintextByteLength: 39_500,
        });
    });

    it('reserves typed local custody before signing and replays only retained bytes', async () => {
        const fixture = await createFixture();
        const capability = fixture.kernel.issueCapability();

        const first = await fixture.custody.retainForPublication({
            verifiedReceiptInventory: capability,
        });
        expect(fixture.kernel.preparationCallCount).toBe(1);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
        const observation = fixture.kernel.productionObservations[0];
        expect(observation?.signatureRandomness).toHaveLength(32);
        expect(observation?.signatureRandomness).not.toEqual(
            new Uint8Array(32),
        );
        expect(
            observation?.preparedInventory.orderedReceiptEnvelopeBytes.map(
                (receiptEnvelope) => receiptEnvelope.byteLength,
            ),
        ).toEqual([17, 19, 23, 27]);
        expect(fixture.anchor.compareAndSetCallCount).toBe(3);

        const expected = first.endorsementEnvelopeBytes.slice();
        first.endorsementEnvelopeBytes.fill(0);
        const replayed = await fixture.custody.retainForPublication({
            verifiedReceiptInventory: capability,
        });
        expect(replayed.endorsementEnvelopeBytes).toEqual(expected);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
        expect(fixture.anchor.compareAndSetCallCount).toBe(3);
    });

    it('refuses an object the kernel did not issue before reserving state', async () => {
        const fixture = await createFixture();

        await expect(
            fixture.custody.retainForPublication({
                verifiedReceiptInventory:
                    new VerifiedReceiptInventoryCapability(99),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(fixture.kernel.productionObservations).toHaveLength(0);
        expect(fixture.anchor.compareAndSetCallCount).toBe(0);
    });

    it('cold-resumes a reservation from retained custody with the same signing seed', async () => {
        const kernel = new DeterministicTerminalEndorsementKernel();
        kernel.failNextProductionCount = 1;
        const fixture = await createFixture({ kernel });
        const capability = kernel.issueCapability(0x51);

        await expect(
            fixture.custody.retainForPublication({
                verifiedReceiptInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        const failedObservation = kernel.productionObservations[0];

        const resumedKernel = new DeterministicTerminalEndorsementKernel();
        const resumedCustody = await reopenCustody(fixture, resumedKernel);
        const completed = await resumedCustody.resumeForPublication();
        expect(completed?.endorsementEnvelopeBytes).toHaveLength(37);
        expect(resumedKernel.preparationCallCount).toBe(0);
        expect(resumedKernel.productionObservations).toHaveLength(1);
        expect(
            resumedKernel.productionObservations[0]?.signatureRandomness,
        ).toEqual(failedObservation?.signatureRandomness);
        expect(
            resumedKernel.productionObservations[0]?.preparedInventory
                .orderedReceiptEnvelopeBytes,
        ).toEqual(
            failedObservation?.preparedInventory.orderedReceiptEnvelopeBytes,
        );

        const replayKernel = new DeterministicTerminalEndorsementKernel();
        replayKernel.failNextProductionCount = 1;
        const replayCustody = await reopenCustody(fixture, replayKernel);
        await expect(replayCustody.resumeForPublication()).resolves.toEqual(
            completed,
        );
        expect(replayKernel.productionObservations).toHaveLength(0);
    });

    it('does not sign until an interrupted reservation anchor is repaired', async () => {
        const fixture = await createFixture();
        await fixture.coordinator.reconcile();
        fixture.anchor.failNextCompareAndSetCount = 1;
        const capability = fixture.kernel.issueCapability(0x61);

        await expect(
            fixture.custody.retainForPublication({
                verifiedReceiptInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(fixture.kernel.productionObservations).toHaveLength(0);

        const resumed = await fixture.custody.resumeForPublication();
        expect(resumed?.endorsementEnvelopeBytes).toHaveLength(37);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
    });

    it('withholds a locally completed terminal endorsement until its anchor is repaired', async () => {
        const kernel = new DeterministicTerminalEndorsementKernel();
        const fixture = await createFixture({ kernel });
        const capability = kernel.issueCapability(0x71);
        kernel.afterProduce = () => {
            fixture.anchor.failNextCompareAndSetCount = 1;
            kernel.afterProduce = undefined;
        };

        await expect(
            fixture.custody.retainForPublication({
                verifiedReceiptInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(kernel.productionObservations).toHaveLength(1);

        const resumed = await fixture.custody.resumeForPublication();
        expect(resumed?.endorsementEnvelopeBytes).toHaveLength(37);
        expect(kernel.productionObservations).toHaveLength(1);
    });

    it('keeps one slot across alternate receipt carriers, terminal bodies, retained receipts, and root terminals', async () => {
        const fixture = await createFixture();
        const prepared = preparedInventoryForMarker(0x81);
        const firstCapability =
            fixture.kernel.issuePreparedCapability(prepared);
        await fixture.custody.retainForPublication({
            verifiedReceiptInventory: firstCapability,
        });

        const alternateReceiptCarriers = copyPreparedInventory(prepared);
        alternateReceiptCarriers.orderedReceiptEnvelopeBytes[3]?.fill(0x82);
        const alternateTerminalBody = copyPreparedInventory(prepared);
        alternateTerminalBody.terminalBodyBytes.fill(0x83);
        const alternateRetainedLocalReceipt = copyPreparedInventory(prepared);
        alternateRetainedLocalReceipt.retainedLocalReceiptEnvelopeIdentity.fill(
            0x84,
        );
        for (const alternative of [
            alternateReceiptCarriers,
            alternateTerminalBody,
            alternateRetainedLocalReceipt,
        ]) {
            const alternativeCapability =
                fixture.kernel.issuePreparedCapability(alternative);
            await expect(
                fixture.custody.retainForPublication({
                    verifiedReceiptInventory: alternativeCapability,
                }),
            ).rejects.toMatchObject({ code: 'Conflict' });
        }
        expect(fixture.kernel.productionObservations).toHaveLength(1);

        const alternateContext = Object.freeze({
            ...fixture.context,
            rootTerminalIdentity: hashFilledWith(0x34),
        });
        const alternateKernel = new DeterministicTerminalEndorsementKernel();
        const alternateCustody = await reopenCustody(
            fixture,
            alternateKernel,
            alternateContext,
        );
        await expect(
            alternateCustody.resumeForPublication(),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('retains one reservation across production and validation failures', async () => {
        const kernel = new DeterministicTerminalEndorsementKernel();
        kernel.failNextProductionCount = 1;
        const fixture = await createFixture({ kernel });
        const capability = kernel.issueCapability(0x91);

        await expect(
            fixture.custody.retainForPublication({
                verifiedReceiptInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        const firstRandomness =
            kernel.productionObservations[0]?.signatureRandomness;

        kernel.malformedNextEnvelope = true;
        await expect(
            fixture.custody.resumeForPublication(),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(kernel.productionObservations[1]?.signatureRandomness).toEqual(
            firstRandomness,
        );

        const completed = await fixture.custody.resumeForPublication();
        expect(completed?.endorsementEnvelopeBytes).toHaveLength(37);
        expect(kernel.productionObservations[2]?.signatureRandomness).toEqual(
            firstRandomness,
        );
    });

    it('serializes duplicate terminal endorsement requests without endorsing twice', async () => {
        const fixture = await createFixture();
        const capability = fixture.kernel.issueCapability(0xa1);

        const [first, second] = await Promise.all([
            fixture.custody.retainForPublication({
                verifiedReceiptInventory: capability,
            }),
            fixture.custody.retainForPublication({
                verifiedReceiptInventory: capability,
            }),
        ]);
        expect(first).toEqual(second);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
    });

    it('reports a missing durable terminal endorsement as pending and rejects accessor input', async () => {
        const fixture = await createFixture();
        await expect(
            fixture.custody.resumeForPublication(),
        ).resolves.toBeUndefined();

        const accessorInput = Object.create(null) as Record<string, unknown>;
        Object.defineProperty(accessorInput, 'verifiedReceiptInventory', {
            get: () => fixture.kernel.issueCapability(),
        });
        expect(() =>
            fixture.custody.retainForPublication(
                accessorInput as {
                    verifiedReceiptInventory: VerifiedReceiptInventoryCapability;
                },
            ),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        expect(fixture.kernel.productionObservations).toHaveLength(0);
    });
});
