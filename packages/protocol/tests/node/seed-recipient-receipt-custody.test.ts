import type { ProductionSeedRecipientReceiptKernel } from '@sealed-lattice/wasm';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedRecipientReceiptKernel: () => true,
    openProductionSeedRecipientReceiptKernel: () => {
        throw new Error('The custody model test does not open a Wasm kernel.');
    },
}));

import {
    createRuntimeRecordProtection,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    SeedRecipientReceiptCustody,
    consumeSeedRecipientReceiptTerminalEndorsementAuthorization,
    deriveSeedRecipientReceiptKernelByteLengths,
    deriveSeedRecipientReceiptCustodyRecordByteLengths,
    type PreparedSeedRecipientReceiptInventory,
    type SeedRecipientReceiptCustodyContext,
    type SeedRecipientReceiptCustodyKernel,
    type SeedRecipientReceiptCustodyLimits,
    type SeedRecipientReceiptProductionInput,
    type SeedRecipientReceiptValidationInput,
} from '#packages/protocol/src/runtime/seed-recipient-receipt-custody';
import {
    generateRuntimeStorageRootKey,
    hashFilledWith,
    InMemoryAuthenticatedStorageRecencyAnchor,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const testLimits: SeedRecipientReceiptCustodyLimits = Object.freeze({
    maximumAuthenticatedInventoryBodyByteLength: 256,
    maximumLocalSeedCustodySegmentByteLength: 256,
    maximumReceiptEnvelopeByteLength: 256,
    maximumReceiptIntentByteLength: 256,
    transactionLifetimeMilliseconds: 1_000,
});

const defaultContext = (): SeedRecipientReceiptCustodyContext =>
    Object.freeze({
        parameterIdentity: hashFilledWith(0x11),
        participantCount: 4,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: hashFilledWith(0x22),
        recipientPosition: 2,
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

class AuthenticatedInventoryCapability {
    readonly #identity: number;

    public constructor(identity: number) {
        this.#identity = identity;
    }

    public identityForTest(): number {
        return this.#identity;
    }
}

type ProductionObservation = Readonly<{
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    signatureRandomness: Uint8Array;
}>;

const copyPreparedInventory = (
    prepared: PreparedSeedRecipientReceiptInventory,
): PreparedSeedRecipientReceiptInventory =>
    Object.freeze({
        authenticatedInventoryBodyBytes:
            prepared.authenticatedInventoryBodyBytes.slice(),
        authenticatedInventoryIdentity:
            prepared.authenticatedInventoryIdentity.slice(),
        localSeedCustodySegments: Object.freeze(
            prepared.localSeedCustodySegments.map((segment) => segment.slice()),
        ),
        receiptIntentBytes: prepared.receiptIntentBytes.slice(),
        receiptIntentIdentity: prepared.receiptIntentIdentity.slice(),
    });

const preparedInventoryForMarker = (
    marker: number,
): PreparedSeedRecipientReceiptInventory =>
    Object.freeze({
        authenticatedInventoryBodyBytes: new Uint8Array(31).fill(marker),
        authenticatedInventoryIdentity: hashFilledWith(marker + 1),
        localSeedCustodySegments: Object.freeze([
            new Uint8Array(17).fill(marker + 2),
            new Uint8Array(19).fill(marker + 3),
            new Uint8Array(23).fill(marker + 4),
        ]),
        receiptIntentBytes: new Uint8Array(29).fill(marker + 5),
        receiptIntentIdentity: hashFilledWith(marker + 6),
    });

const deterministicEnvelope = (
    input: SeedRecipientReceiptProductionInput,
): Uint8Array => {
    const envelope = new Uint8Array(37);
    const variableByte =
        (input.signatureRandomness[0] ?? 0) ^
        (input.preparedInventory.authenticatedInventoryIdentity[0] ?? 0) ^
        (input.preparedInventory.receiptIntentIdentity[0] ?? 0);
    for (let byteIndex = 0; byteIndex < envelope.byteLength; byteIndex += 1) {
        envelope[byteIndex] = (variableByte + byteIndex * 7) & 0xff;
    }
    envelope[0] = 0xa1;
    envelope[1] =
        input.preparedInventory.authenticatedInventoryIdentity[0] ?? 0;
    envelope[2] = input.preparedInventory.receiptIntentIdentity[0] ?? 0;
    return envelope;
};

class DeterministicReceiptKernel implements SeedRecipientReceiptCustodyKernel<AuthenticatedInventoryCapability> {
    public afterProduce: (() => void) | undefined;
    public failNextPreparationCount = 0;
    public failNextProductionCount = 0;
    public failNextValidationCount = 0;
    public malformedNextEnvelope = false;
    public preparationCallCount = 0;
    public readonly productionObservations: ProductionObservation[] = [];
    public readonly validationObservations: SeedRecipientReceiptValidationInput[] =
        [];
    readonly #preparedByCapability = new WeakMap<
        AuthenticatedInventoryCapability,
        PreparedSeedRecipientReceiptInventory
    >();
    #nextCapabilityIdentity = 1;

    public issueCapability(marker = 0x41): AuthenticatedInventoryCapability {
        const capability = new AuthenticatedInventoryCapability(
            this.#nextCapabilityIdentity,
        );
        this.#nextCapabilityIdentity += 1;
        this.#preparedByCapability.set(
            capability,
            preparedInventoryForMarker(marker),
        );
        return capability;
    }

    public prepare(
        authenticatedInventory: AuthenticatedInventoryCapability,
    ): PreparedSeedRecipientReceiptInventory {
        this.preparationCallCount += 1;
        if (this.failNextPreparationCount > 0) {
            this.failNextPreparationCount -= 1;
            throw new Error('Injected receipt preparation failure.');
        }
        const prepared = this.#preparedByCapability.get(authenticatedInventory);
        if (prepared === undefined) {
            throw new Error('The test kernel did not issue this inventory.');
        }
        if (authenticatedInventory.identityForTest() <= 0) {
            throw new Error('The test inventory capability has no identity.');
        }
        return copyPreparedInventory(prepared);
    }

    public produce(input: SeedRecipientReceiptProductionInput): Uint8Array {
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
            throw new Error('Injected receipt production failure.');
        }
        const envelope = deterministicEnvelope(input);
        this.afterProduce?.();
        if (this.malformedNextEnvelope) {
            this.malformedNextEnvelope = false;
            return envelope.subarray(0, 3);
        }
        return envelope;
    }

    public validate(input: SeedRecipientReceiptValidationInput): void {
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
                ...(input.receiptEnvelopeBytes === undefined
                    ? {}
                    : {
                          receiptEnvelopeBytes:
                              input.receiptEnvelopeBytes.slice(),
                      }),
            }),
        );
        if (this.failNextValidationCount > 0) {
            this.failNextValidationCount -= 1;
            throw new Error('Injected receipt validation failure.');
        }
        if (
            input.context.participantCount !== 4 ||
            input.context.preparationAttemptOrdinal !== 0 ||
            input.context.recipientPosition !== 2 ||
            input.preparedInventory.authenticatedInventoryBodyBytes
                .byteLength !== 31 ||
            input.preparedInventory.localSeedCustodySegments.length !== 3 ||
            input.preparedInventory.receiptIntentBytes.byteLength !== 29
        ) {
            throw new Error('Receipt preparation failed the test validator.');
        }
        if (
            input.receiptEnvelopeBytes !== undefined &&
            (input.receiptEnvelopeBytes.byteLength !== 37 ||
                input.receiptEnvelopeBytes[0] !== 0xa1 ||
                input.receiptEnvelopeBytes[1] !==
                    input.preparedInventory.authenticatedInventoryIdentity[0] ||
                input.receiptEnvelopeBytes[2] !==
                    input.preparedInventory.receiptIntentIdentity[0])
        ) {
            throw new Error('Receipt envelope failed the test validator.');
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
    context: SeedRecipientReceiptCustodyContext;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: SeedRecipientReceiptCustody<AuthenticatedInventoryCapability>;
    kernel: DeterministicReceiptKernel;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const createFixture = async (input?: {
    context?: SeedRecipientReceiptCustodyContext;
    kernel?: DeterministicReceiptKernel;
}): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `seed-recipient-receipt-custody-${fixtureOrdinal}`;
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
    const kernel = input?.kernel ?? new DeterministicReceiptKernel();
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        context,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody:
            new SeedRecipientReceiptCustody<AuthenticatedInventoryCapability>({
                context,
                kernel: kernel as unknown as ProductionSeedRecipientReceiptKernel,
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
    kernel: DeterministicReceiptKernel,
    context = fixture.context,
): Promise<SeedRecipientReceiptCustody<AuthenticatedInventoryCapability>> => {
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
    return new SeedRecipientReceiptCustody<AuthenticatedInventoryCapability>({
        context,
        kernel: kernel as unknown as ProductionSeedRecipientReceiptKernel,
        limits: testLimits,
        protection,
        recencyCoordinator: coordinator,
    });
};

describe('seed-recipient receipt custody', () => {
    it('independently accounts for the exact completion receipt records', () => {
        const derived = deriveSeedRecipientReceiptCustodyRecordByteLengths({
            authenticatedInventoryBodyByteLength: 1_566,
            localSeedCustodySegmentByteLengths: Array.from(
                { length: 9 },
                () => 62_590,
            ),
            receiptEnvelopeByteLength: 3_778,
            receiptIntentByteLength: 374,
        });
        const independentlyDerivedPrefixByteLength =
            4 + 2 + 1 + 64 * 5 + 2 * 3 + 4 * 2 + 2 + 9 * 4;
        const independentlyDerivedSharedPlaintextByteLength =
            independentlyDerivedPrefixByteLength + 1_566 + 374 + 9 * 62_590;
        const independentlyDerivedReservationPlaintextByteLength =
            independentlyDerivedSharedPlaintextByteLength + 32;
        const independentlyDerivedCompletedPlaintextByteLength =
            independentlyDerivedSharedPlaintextByteLength + 4 + 3_778;

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
            completedCiphertextByteLength: 569_465,
            completedPlaintextByteLength: 569_411,
            copyOnWriteCiphertextOverlapByteLength: 1_135_180,
            reservationCiphertextByteLength: 565_715,
            reservationPlaintextByteLength: 565_661,
        });

        const kernelDerived = deriveSeedRecipientReceiptKernelByteLengths({
            authenticatedInventoryBodyByteLength: 1_566,
            carriers: Array.from({ length: 9 }, () => ({
                encryptedChunkByteLengths: [62_606],
                headerByteLength: 1_655,
                manifestByteLength: 215,
                signatureEnvelopeByteLength: 3_713,
            })),
            localSeedCustodySegmentByteLengths: Array.from(
                { length: 9 },
                () => 62_590,
            ),
            preparationContextByteLength: 338,
            receiptEnvelopeByteLength: 3_778,
            receiptIntentByteLength: 374,
            rootAuthorizationPackages: Array.from({ length: 10 }, () => ({
                contributorSignatureEnvelopeByteLength: 3_723,
                exactOutputCertificateByteLength: 25_545,
                reservationCertificateByteLength: 25_515,
                rootBodyByteLength: 522,
            })),
            rootTerminalCertificateByteLength: 36_230,
            rosterByteLength: 31_660,
        });
        const independentlyDerivedRootCorpusByteLength =
            10 * (4 * 4 + 522 + 25_515 + 25_545 + 3_723);
        const independentlyDerivedCarrierCorpusByteLength =
            9 * (2 + (4 + 1_655) + (4 + 215) + (4 + 3_713) + 2 + (4 + 62_606));
        const independentlyDerivedPreparedInventoryByteLength =
            4 + 1_566 + 64 + 2 + 9 * (4 + 62_590) + (4 + 374) + 64;
        const independentlyDerivedOpenRequestByteLength =
            7 +
            64 +
            2 +
            (4 + 338) +
            (4 + 31_660) +
            2 +
            independentlyDerivedRootCorpusByteLength +
            (4 + 36_230) +
            2 +
            independentlyDerivedCarrierCorpusByteLength;
        const independentlyDerivedOpenResponseByteLength =
            7 + 4 + 1_952 + 1_184 + 2 + 9 * 1_088;
        const independentlyDerivedAuthenticationRequestByteLength =
            7 + 4 + 2 + 9 * 32;
        const independentlyDerivedAuthenticationResponseByteLength =
            7 + independentlyDerivedPreparedInventoryByteLength;
        const independentlyDerivedCompleteRequestByteLength =
            7 + 4 + independentlyDerivedPreparedInventoryByteLength + 3_309;
        const independentlyDerivedCompleteResponseByteLength = 7 + 4 + 3_778;
        const independentlyDerivedValidationRequestWithoutEnvelopeByteLength =
            7 +
            4 +
            (64 * 3 + 2 * 3) +
            independentlyDerivedPreparedInventoryByteLength +
            1;
        const independentlyDerivedValidationRequestWithEnvelopeByteLength =
            independentlyDerivedValidationRequestWithoutEnvelopeByteLength +
            4 +
            3_778;
        expect(kernelDerived).toEqual({
            closeContextRequestByteLength: 11,
            closeContextResponseByteLength: 7,
            coldValidationCumulativeRequestByteLength:
                independentlyDerivedOpenRequestByteLength +
                independentlyDerivedAuthenticationRequestByteLength +
                independentlyDerivedValidationRequestWithoutEnvelopeByteLength +
                independentlyDerivedValidationRequestWithEnvelopeByteLength +
                11,
            coldValidationCumulativeResponseByteLength:
                independentlyDerivedOpenResponseByteLength +
                independentlyDerivedAuthenticationResponseByteLength +
                7 +
                7 +
                7,
            coldValidationInvocationCount: 5,
            completeAuthenticationRequestByteLength:
                independentlyDerivedAuthenticationRequestByteLength,
            completeAuthenticationResponseByteLength:
                independentlyDerivedAuthenticationResponseByteLength,
            completeReceiptRequestByteLength:
                independentlyDerivedCompleteRequestByteLength,
            completeReceiptResponseByteLength:
                independentlyDerivedCompleteResponseByteLength,
            maximumRequestByteLength: independentlyDerivedOpenRequestByteLength,
            maximumResponseByteLength:
                independentlyDerivedAuthenticationResponseByteLength,
            openContextRequestByteLength:
                independentlyDerivedOpenRequestByteLength,
            openContextResponseByteLength:
                independentlyDerivedOpenResponseByteLength,
            successfulCumulativeRequestByteLength:
                independentlyDerivedOpenRequestByteLength +
                independentlyDerivedAuthenticationRequestByteLength +
                independentlyDerivedValidationRequestWithoutEnvelopeByteLength +
                independentlyDerivedCompleteRequestByteLength +
                independentlyDerivedValidationRequestWithEnvelopeByteLength +
                11,
            successfulCumulativeResponseByteLength:
                independentlyDerivedOpenResponseByteLength +
                independentlyDerivedAuthenticationResponseByteLength +
                7 +
                independentlyDerivedCompleteResponseByteLength +
                7 +
                7,
            successfulInvocationCount: 6,
            validationRequestByteLengthWithEnvelope:
                independentlyDerivedValidationRequestWithEnvelopeByteLength,
            validationRequestByteLengthWithoutEnvelope:
                independentlyDerivedValidationRequestWithoutEnvelopeByteLength,
            validationResponseByteLength: 7,
        });
        expect(kernelDerived).toEqual({
            closeContextRequestByteLength: 11,
            closeContextResponseByteLength: 7,
            coldValidationCumulativeRequestByteLength: 2_370_770,
            coldValidationCumulativeResponseByteLength: 578_393,
            coldValidationInvocationCount: 5,
            completeAuthenticationRequestByteLength: 301,
            completeAuthenticationResponseByteLength: 565_431,
            completeReceiptRequestByteLength: 568_744,
            completeReceiptResponseByteLength: 3_789,
            maximumRequestByteLength: 1_235_408,
            maximumResponseByteLength: 565_431,
            openContextRequestByteLength: 1_235_408,
            openContextResponseByteLength: 12_941,
            successfulCumulativeRequestByteLength: 2_939_514,
            successfulCumulativeResponseByteLength: 582_182,
            successfulInvocationCount: 6,
            validationRequestByteLengthWithEnvelope: 569_416,
            validationRequestByteLengthWithoutEnvelope: 565_634,
            validationResponseByteLength: 7,
        });
    });

    it('reserves typed local custody before signing and replays only retained bytes', async () => {
        const fixture = await createFixture();
        const capability = fixture.kernel.issueCapability();

        const first = await fixture.custody.retainForPublication({
            authenticatedInventory: capability,
        });
        expect(fixture.kernel.preparationCallCount).toBe(1);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
        const observation = fixture.kernel.productionObservations[0];
        expect(observation?.signatureRandomness).toHaveLength(32);
        expect(observation?.signatureRandomness).not.toEqual(
            new Uint8Array(32),
        );
        expect(
            observation?.preparedInventory.localSeedCustodySegments.map(
                (segment) => segment.byteLength,
            ),
        ).toEqual([17, 19, 23]);
        expect(fixture.anchor.compareAndSetCallCount).toBe(3);

        const expected = first.receiptEnvelopeBytes.slice();
        first.receiptEnvelopeBytes.fill(0);
        const replayed = await fixture.custody.retainForPublication({
            authenticatedInventory: capability,
        });
        expect(replayed.receiptEnvelopeBytes).toEqual(expected);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
        expect(fixture.anchor.compareAndSetCallCount).toBe(3);
    });

    it('authorizes the terminal kernel only from one exact completed receipt record', async () => {
        const fixture = await createFixture();
        const prematureAuthorization =
            fixture.custody.authorizeTerminalEndorsementKernel();
        expect(Object.keys(prematureAuthorization)).toEqual([]);
        await expect(
            consumeSeedRecipientReceiptTerminalEndorsementAuthorization(
                prematureAuthorization,
            ),
        ).rejects.toMatchObject({ code: 'InvalidState' });

        const capability = fixture.kernel.issueCapability(0x4b);
        await fixture.custody.retainForPublication({
            authenticatedInventory: capability,
        });
        const authorization =
            fixture.custody.authorizeTerminalEndorsementKernel();
        const consumed =
            await consumeSeedRecipientReceiptTerminalEndorsementAuthorization(
                authorization,
            );
        expect(consumed.context).toEqual(fixture.context);
        expect(consumed.recordBytes.subarray(0, 7)).toEqual(
            Uint8Array.of(0x53, 0x4c, 0x52, 0x43, 1, 0, 2),
        );
        await expect(
            consumeSeedRecipientReceiptTerminalEndorsementAuthorization(
                authorization,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const repeatedAuthorization =
            fixture.custody.authorizeTerminalEndorsementKernel();
        const repeated =
            await consumeSeedRecipientReceiptTerminalEndorsementAuthorization(
                repeatedAuthorization,
            );
        expect(repeated.recordBytes).toEqual(consumed.recordBytes);
        consumed.context.parameterIdentity.fill(0);
        consumed.context.preparationContextIdentity.fill(0);
        consumed.context.rootTerminalIdentity.fill(0);
        consumed.recordBytes.fill(0);
        repeated.context.parameterIdentity.fill(0);
        repeated.context.preparationContextIdentity.fill(0);
        repeated.context.rootTerminalIdentity.fill(0);
        repeated.recordBytes.fill(0);
    });

    it('refuses an object the kernel did not issue before reserving state', async () => {
        const fixture = await createFixture();

        await expect(
            fixture.custody.retainForPublication({
                authenticatedInventory: new AuthenticatedInventoryCapability(
                    99,
                ),
            }),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(fixture.kernel.productionObservations).toHaveLength(0);
        expect(fixture.anchor.compareAndSetCallCount).toBe(0);
    });

    it('cold-resumes a reservation from retained custody with the same signing seed', async () => {
        const kernel = new DeterministicReceiptKernel();
        kernel.failNextProductionCount = 1;
        const fixture = await createFixture({ kernel });
        const capability = kernel.issueCapability(0x51);

        await expect(
            fixture.custody.retainForPublication({
                authenticatedInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        const failedObservation = kernel.productionObservations[0];

        const resumedKernel = new DeterministicReceiptKernel();
        const resumedCustody = await reopenCustody(fixture, resumedKernel);
        const completed = await resumedCustody.resumeForPublication();
        expect(completed?.receiptEnvelopeBytes).toHaveLength(37);
        expect(resumedKernel.preparationCallCount).toBe(0);
        expect(resumedKernel.productionObservations).toHaveLength(1);
        expect(
            resumedKernel.productionObservations[0]?.signatureRandomness,
        ).toEqual(failedObservation?.signatureRandomness);
        expect(
            resumedKernel.productionObservations[0]?.preparedInventory
                .localSeedCustodySegments,
        ).toEqual(
            failedObservation?.preparedInventory.localSeedCustodySegments,
        );

        const replayKernel = new DeterministicReceiptKernel();
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
                authenticatedInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(fixture.kernel.productionObservations).toHaveLength(0);

        const resumed = await fixture.custody.resumeForPublication();
        expect(resumed?.receiptEnvelopeBytes).toHaveLength(37);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
    });

    it('withholds a locally completed receipt until its anchor is repaired', async () => {
        const kernel = new DeterministicReceiptKernel();
        const fixture = await createFixture({ kernel });
        const capability = kernel.issueCapability(0x71);
        kernel.afterProduce = () => {
            fixture.anchor.failNextCompareAndSetCount = 1;
            kernel.afterProduce = undefined;
        };

        await expect(
            fixture.custody.retainForPublication({
                authenticatedInventory: capability,
            }),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(kernel.productionObservations).toHaveLength(1);

        const resumed = await fixture.custody.resumeForPublication();
        expect(resumed?.receiptEnvelopeBytes).toHaveLength(37);
        expect(kernel.productionObservations).toHaveLength(1);
    });

    it('keeps one slot across alternate delivery carriers and root terminals', async () => {
        const fixture = await createFixture();
        const firstCapability = fixture.kernel.issueCapability(0x81);
        await fixture.custody.retainForPublication({
            authenticatedInventory: firstCapability,
        });

        const alternateCarrierCapability = fixture.kernel.issueCapability(0x82);
        await expect(
            fixture.custody.retainForPublication({
                authenticatedInventory: alternateCarrierCapability,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        expect(fixture.kernel.productionObservations).toHaveLength(1);

        const alternateContext = Object.freeze({
            ...fixture.context,
            rootTerminalIdentity: hashFilledWith(0x34),
        });
        const alternateKernel = new DeterministicReceiptKernel();
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
        const kernel = new DeterministicReceiptKernel();
        kernel.failNextProductionCount = 1;
        const fixture = await createFixture({ kernel });
        const capability = kernel.issueCapability(0x91);

        await expect(
            fixture.custody.retainForPublication({
                authenticatedInventory: capability,
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
        expect(completed?.receiptEnvelopeBytes).toHaveLength(37);
        expect(kernel.productionObservations[2]?.signatureRandomness).toEqual(
            firstRandomness,
        );
    });

    it('serializes duplicate receipt requests without signing twice', async () => {
        const fixture = await createFixture();
        const capability = fixture.kernel.issueCapability(0xa1);

        const [first, second] = await Promise.all([
            fixture.custody.retainForPublication({
                authenticatedInventory: capability,
            }),
            fixture.custody.retainForPublication({
                authenticatedInventory: capability,
            }),
        ]);
        expect(first).toEqual(second);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
    });

    it('reports a missing durable receipt as pending and rejects accessor input', async () => {
        const fixture = await createFixture();
        await expect(
            fixture.custody.resumeForPublication(),
        ).resolves.toBeUndefined();

        const accessorInput = Object.create(null) as Record<string, unknown>;
        Object.defineProperty(accessorInput, 'authenticatedInventory', {
            get: () => fixture.kernel.issueCapability(),
        });
        expect(() =>
            fixture.custody.retainForPublication(
                accessorInput as {
                    authenticatedInventory: AuthenticatedInventoryCapability;
                },
            ),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        expect(fixture.kernel.productionObservations).toHaveLength(0);
    });
});
