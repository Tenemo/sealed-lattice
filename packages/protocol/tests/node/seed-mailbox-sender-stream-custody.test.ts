import type { ProductionSeedMailboxSenderStreamKernel } from '@sealed-lattice/wasm';
import { describe, expect, it, vi } from 'vitest';

vi.mock('@sealed-lattice/wasm', () => ({
    isProductionSeedMailboxSenderStreamKernel: () => true,
    openProductionSeedMailboxSenderStreamKernel: () => {
        throw new Error('The custody model test does not open a Wasm kernel.');
    },
}));

import {
    createRuntimeRecordProtection,
    type RuntimeRecordProtection,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import { AuthenticatedStorageRecencyCoordinator } from '#packages/protocol/src/runtime/authenticated-storage-recency';
import {
    SeedMailboxSenderStreamCustody,
    deriveSeedMailboxSenderStreamCustodyRecordByteLengths,
    deriveSeedMailboxSenderStreamKernelByteLengths,
    type RetainSeedMailboxSenderStreamInput,
    type RetainedSeedMailboxSenderStreamCarrier,
    type SeedMailboxSenderStreamCustodyContext,
    type SeedMailboxSenderStreamCustodyLimits,
    type SeedMailboxSenderStreamGeometry,
    type SeedMailboxSenderStreamKernel,
    type SeedMailboxSenderStreamProductionInput,
    type SeedMailboxSenderStreamValidationInput,
} from '#packages/protocol/src/runtime/seed-mailbox-sender-stream-custody';
import {
    InMemoryAuthenticatedStorageRecencyAnchor,
    openRuntimeTestStore,
    generateRuntimeStorageRootKey,
    hashFilledWith,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const smallGeometry: SeedMailboxSenderStreamGeometry = Object.freeze({
    encryptedChunkByteLengths: Object.freeze([29, 24]),
    headerByteLength: 19,
    manifestByteLength: 17,
    signatureEnvelopeByteLength: 23,
    sourcePayloadByteLength: 37,
    totalCarrierByteLength: 112,
});

const testLimits: SeedMailboxSenderStreamCustodyLimits = Object.freeze({
    maximumCanonicalDeliveryDescriptorByteLength: 512,
    maximumEncryptedChunkByteLength: 1_048_592,
    maximumEncryptedChunkCount: 4,
    maximumHeaderByteLength: 4_096,
    maximumManifestByteLength: 4_096,
    maximumSignatureEnvelopeByteLength: 8_192,
    maximumSourcePayloadByteLength: 1_048_576,
    transactionLifetimeMilliseconds: 1_000,
});

const defaultContext = (): SeedMailboxSenderStreamCustodyContext =>
    Object.freeze({
        parameterIdentity: hashFilledWith(0x11),
        participantCount: 10,
        preparationAttemptOrdinal: 0,
        preparationContextIdentity: hashFilledWith(0x22),
        rootTerminalIdentity: hashFilledWith(0x33),
        senderPosition: 3,
    });

const requestForRecipient = (
    recipientPosition: number,
): RetainSeedMailboxSenderStreamInput =>
    Object.freeze({
        canonicalDeliveryDescriptorBytes: new Uint8Array(41).fill(
            0x60 + recipientPosition,
        ),
        geometry: smallGeometry,
        recipientPosition,
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
                    ((invocationCount * 37 + byteIndex * 11) % 255) + 1;
            }
            return value;
        },
        subtle: globalThis.crypto.subtle,
    } as Crypto;
};

const repeatedRandomnessCryptoProvider = (): Crypto =>
    ({
        getRandomValues: <Value extends ArrayBufferView>(
            value: Value,
        ): Value => {
            new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
            ).fill(0x6a);
            return value;
        },
        subtle: globalThis.crypto.subtle,
    }) as Crypto;

type ProductionObservation = Readonly<{
    canonicalDeliveryDescriptorBytes: Uint8Array;
    encapsulationRandomness: Uint8Array;
    signatureRandomness: Uint8Array;
}>;

const deterministicCarrierPart = (
    byteLength: number,
    marker: number,
    variableByte: number,
): Uint8Array => {
    const bytes = new Uint8Array(byteLength);
    for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
        bytes[byteIndex] = (variableByte + byteIndex * 13) & 0xff;
    }
    bytes[0] = marker;
    return bytes;
};

class DeterministicSeedMailboxKernel implements SeedMailboxSenderStreamKernel {
    public afterProduce: (() => void) | undefined;
    public failNextProductionCount = 0;
    public failNextValidationCount = 0;
    public malformedNextCarrier = false;
    public readonly productionObservations: ProductionObservation[] = [];
    public validationCallCount = 0;

    public produce(
        input: SeedMailboxSenderStreamProductionInput,
    ): RetainedSeedMailboxSenderStreamCarrier {
        this.productionObservations.push(
            Object.freeze({
                canonicalDeliveryDescriptorBytes:
                    input.canonicalDeliveryDescriptorBytes.slice(),
                encapsulationRandomness: input.encapsulationRandomness.slice(),
                signatureRandomness: input.signatureRandomness.slice(),
            }),
        );
        if (this.failNextProductionCount > 0) {
            this.failNextProductionCount -= 1;
            throw new Error('Injected seed-mailbox production failure.');
        }
        const variableByte =
            (input.encapsulationRandomness[0] ?? 0) ^
            (input.signatureRandomness[0] ?? 0) ^
            (input.canonicalDeliveryDescriptorBytes[0] ?? 0);
        const carrier: RetainedSeedMailboxSenderStreamCarrier = {
            encryptedChunks: smallGeometry.encryptedChunkByteLengths.map(
                (byteLength, chunkIndex) =>
                    deterministicCarrierPart(
                        byteLength,
                        0xc0 + chunkIndex,
                        variableByte,
                    ),
            ),
            headerBytes: deterministicCarrierPart(
                smallGeometry.headerByteLength,
                0xa1,
                variableByte,
            ),
            manifestBytes: deterministicCarrierPart(
                smallGeometry.manifestByteLength,
                0xa2,
                variableByte,
            ),
            signatureEnvelopeBytes: deterministicCarrierPart(
                smallGeometry.signatureEnvelopeByteLength,
                0xa3,
                variableByte,
            ),
        };
        if (this.malformedNextCarrier) {
            this.malformedNextCarrier = false;
            return {
                ...carrier,
                headerBytes: carrier.headerBytes.subarray(1),
            };
        }
        this.afterProduce?.();
        return carrier;
    }

    public validate(input: SeedMailboxSenderStreamValidationInput): void {
        this.validationCallCount += 1;
        if (this.failNextValidationCount > 0) {
            this.failNextValidationCount -= 1;
            throw new Error('Injected seed-mailbox validation failure.');
        }
        if (
            input.context.preparationAttemptOrdinal !== 0 ||
            input.context.senderPosition !== 3 ||
            input.context.recipientPosition === input.context.senderPosition ||
            input.canonicalDeliveryDescriptorBytes[0] !==
                0x60 + input.context.recipientPosition ||
            input.carrier.headerBytes[0] !== 0xa1 ||
            input.carrier.manifestBytes[0] !== 0xa2 ||
            input.carrier.signatureEnvelopeBytes[0] !== 0xa3 ||
            input.carrier.encryptedChunks[0]?.[0] !== 0xc0 ||
            input.carrier.encryptedChunks[1]?.[0] !== 0xc1
        ) {
            throw new Error('Seed-mailbox carrier failed the test validator.');
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
    context: SeedMailboxSenderStreamCustodyContext;
    coordinator: AuthenticatedStorageRecencyCoordinator;
    createIdentifier: (kind: 'lease' | 'transaction') => string;
    cryptoProvider: Crypto;
    custody: SeedMailboxSenderStreamCustody;
    kernel: DeterministicSeedMailboxKernel;
    namespace: string;
    protection: RuntimeRecordProtection;
    rootKey: CryptoKey;
}>;

let fixtureOrdinal = 0;

const createFixture = async (input?: {
    cryptoProvider?: Crypto;
    kernel?: DeterministicSeedMailboxKernel;
}): Promise<CustodyFixture> => {
    fixtureOrdinal += 1;
    const namespace = `seed-mailbox-sender-custody-${fixtureOrdinal}`;
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
    const cryptoProvider =
        input?.cryptoProvider ?? deterministicCryptoProvider();
    const protection = createRuntimeRecordProtection({
        authorityContext: runtimeAuthorityContext(),
        cryptoProvider,
        maximumRecordSealingCount: 64,
        rootKey,
    });
    const context = defaultContext();
    const kernel = input?.kernel ?? new DeterministicSeedMailboxKernel();
    return Object.freeze({
        adapter: opened.adapter,
        anchor,
        context,
        coordinator,
        createIdentifier,
        cryptoProvider,
        custody: new SeedMailboxSenderStreamCustody({
            context,
            kernel: kernel as unknown as ProductionSeedMailboxSenderStreamKernel,
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
    kernel: DeterministicSeedMailboxKernel,
    context = fixture.context,
): Promise<SeedMailboxSenderStreamCustody> => {
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
    return new SeedMailboxSenderStreamCustody({
        context,
        kernel: kernel as unknown as ProductionSeedMailboxSenderStreamKernel,
        limits: testLimits,
        protection,
        recencyCoordinator: coordinator,
    });
};

describe('seed-mailbox sender-stream custody', () => {
    it('independently accounts for the exact completion stream records', () => {
        const productionGeometry: SeedMailboxSenderStreamGeometry = {
            encryptedChunkByteLengths: [62_606],
            headerByteLength: 1_655,
            manifestByteLength: 215,
            signatureEnvelopeByteLength: 3_713,
            sourcePayloadByteLength: 62_590,
            totalCarrierByteLength: 68_189,
        };
        const derived = deriveSeedMailboxSenderStreamCustodyRecordByteLengths({
            canonicalDeliveryDescriptorByteLength: 328,
            geometry: productionGeometry,
        });

        const independentlyDerivedCommonByteLength =
            4 + 2 + 1 + 64 * 3 + 2 * 4 + 4 + 328 + 4 * 6 + 4;
        const independentlyDerivedReservationPlaintextByteLength =
            independentlyDerivedCommonByteLength + 32 * 2;
        const independentlyDerivedCompletedPlaintextByteLength =
            independentlyDerivedCommonByteLength + 68_189;
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
            completedCiphertextByteLength: 68_810,
            completedPlaintextByteLength: 68_756,
            copyOnWriteCiphertextOverlapByteLength: 69_495,
            reservationCiphertextByteLength: 685,
            reservationPlaintextByteLength: 631,
        });

        const kernelDerived = deriveSeedMailboxSenderStreamKernelByteLengths({
            canonicalDeliveryDescriptorByteLength: 328,
            geometry: productionGeometry,
            preparationContextByteLength: 338,
            rootAuthorizationPackages: Array.from({ length: 10 }, () => ({
                contributorSignatureEnvelopeByteLength: 3_723,
                exactOutputCertificateByteLength: 25_545,
                reservationCertificateByteLength: 25_515,
                rootBodyByteLength: 522,
            })),
            rootTerminalCertificateByteLength: 36_230,
            rosterByteLength: 31_660,
            sourceCustodyRecordByteLength: 677_741,
            streamCount: 9,
        });
        const independentlyDerivedOpenRequestByteLength =
            7 +
            64 +
            2 +
            (4 + 338) +
            (4 + 31_660) +
            2 +
            10 * (4 * 4 + 522 + 25_515 + 25_545 + 3_723) +
            (4 + 36_230) +
            (64 * 6 + 2 * 3) +
            (4 + 677_741);
        const independentlyDerivedPrepareRequestByteLength =
            7 + 4 + (64 * 3 + 2 * 4) + (4 + 328) + 32;
        const independentlyDerivedPrepareResponseByteLength =
            7 + (4 + 1_655) + (4 + 215) + (4 + 309) + 2 + (4 + 62_606);
        const independentlyDerivedCompleteRequestByteLength =
            7 +
            4 +
            (64 * 3 + 2 * 4) +
            (4 + 328) +
            (4 + 1_655) +
            (4 + 215) +
            2 +
            (4 + 62_606) +
            3_309;
        const independentlyDerivedCompleteResponseByteLength =
            7 + (4 + 1_655) + (4 + 215) + (4 + 3_713) + 2 + (4 + 62_606);
        const independentlyDerivedValidationRequestByteLength =
            7 +
            4 +
            (64 * 3 + 2 * 4) +
            (4 + 328) +
            (5 * 4 + 2 + 4) +
            (4 + 1_655) +
            (4 + 215) +
            (4 + 3_713) +
            2 +
            (4 + 62_606);
        expect(kernelDerived).toEqual({
            closeContextRequestByteLength: 11,
            closeContextResponseByteLength: 7,
            coldValidationCumulativeRequestByteLength:
                independentlyDerivedOpenRequestByteLength +
                9 * independentlyDerivedValidationRequestByteLength +
                11,
            coldValidationCumulativeResponseByteLength: 1_963 + 9 * 7 + 7,
            coldValidationInvocationCount: 11,
            completeCarrierRequestByteLengthPerStream:
                independentlyDerivedCompleteRequestByteLength,
            completeCarrierResponseByteLengthPerStream:
                independentlyDerivedCompleteResponseByteLength,
            maximumRequestByteLength: independentlyDerivedOpenRequestByteLength,
            maximumResponseByteLength:
                independentlyDerivedCompleteResponseByteLength,
            openContextRequestByteLength:
                independentlyDerivedOpenRequestByteLength,
            openContextResponseByteLength: 1_963,
            prepareCarrierRequestByteLengthPerStream:
                independentlyDerivedPrepareRequestByteLength,
            prepareCarrierResponseByteLengthPerStream:
                independentlyDerivedPrepareResponseByteLength,
            signatureBodyByteLengthPerStream: 309,
            signatureContextByteLengthPerStream: 51,
            signatureRandomnessByteLengthPerStream: 32,
            signatureResponseByteLengthPerStream: 3_309,
            signingVerificationKeyByteLengthPerStream: 1_952,
            successfulCumulativeRequestByteLength:
                independentlyDerivedOpenRequestByteLength +
                9 *
                    (independentlyDerivedPrepareRequestByteLength +
                        independentlyDerivedCompleteRequestByteLength +
                        independentlyDerivedValidationRequestByteLength) +
                11,
            successfulCumulativeResponseByteLength:
                1_963 +
                9 *
                    (independentlyDerivedPrepareResponseByteLength +
                        independentlyDerivedCompleteResponseByteLength +
                        7) +
                7,
            successfulInvocationCount: 29,
            validateCarrierRequestByteLengthPerStream:
                independentlyDerivedValidationRequestByteLength,
            validateCarrierResponseByteLengthPerStream: 7,
        });
        expect(kernelDerived).toMatchObject({
            coldValidationCumulativeRequestByteLength: 1_918_655,
            coldValidationCumulativeResponseByteLength: 2_033,
            completeCarrierRequestByteLengthPerStream: 68_342,
            completeCarrierResponseByteLengthPerStream: 68_214,
            maximumRequestByteLength: 1_299_660,
            maximumResponseByteLength: 68_214,
            openContextRequestByteLength: 1_299_660,
            prepareCarrierRequestByteLengthPerStream: 575,
            prepareCarrierResponseByteLengthPerStream: 64_810,
            successfulCumulativeRequestByteLength: 2_538_908,
            successfulCumulativeResponseByteLength: 1_199_249,
            validateCarrierRequestByteLengthPerStream: 68_776,
        });
        expect(() =>
            deriveSeedMailboxSenderStreamKernelByteLengths({
                canonicalDeliveryDescriptorByteLength: 328,
                geometry: productionGeometry,
                preparationContextByteLength: 338,
                rootAuthorizationPackages: [
                    {
                        contributorSignatureEnvelopeByteLength: 3_723,
                        exactOutputCertificateByteLength: 25_545,
                        reservationCertificateByteLength: 25_515,
                        rootBodyByteLength: 8 * 1024 * 1024,
                    },
                ],
                rootTerminalCertificateByteLength: 36_230,
                rosterByteLength: 31_660,
                sourceCustodyRecordByteLength: 677_741,
                streamCount: 9,
            }),
        ).toThrowError(expect.objectContaining({ code: 'ResourceLimit' }));
    });

    it('samples internally, anchors both states, and replays only retained bytes', async () => {
        const fixture = await createFixture();
        const request = requestForRecipient(7);

        const firstCarrier =
            await fixture.custody.retainForPublication(request);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
        const observation = fixture.kernel.productionObservations[0];
        expect(observation).toBeDefined();
        expect(observation?.encapsulationRandomness).toHaveLength(32);
        expect(observation?.signatureRandomness).toHaveLength(32);
        expect(observation?.encapsulationRandomness).not.toEqual(
            observation?.signatureRandomness,
        );
        expect(observation?.encapsulationRandomness).not.toEqual(
            new Uint8Array(32),
        );
        expect(fixture.anchor.compareAndSetCallCount).toBe(3);

        const expectedCarrier = structuredClone(firstCarrier);
        firstCarrier.headerBytes.fill(0);
        firstCarrier.encryptedChunks[0]?.fill(0);
        const replayed = await fixture.custody.retainForPublication(request);
        expect(replayed).toEqual(expectedCarrier);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
        expect(fixture.kernel.validationCallCount).toBe(2);
        expect(fixture.anchor.compareAndSetCallCount).toBe(3);
    });

    it('resumes a persisted reservation with the same randomness after cold reopen', async () => {
        const kernel = new DeterministicSeedMailboxKernel();
        kernel.failNextProductionCount = 1;
        const fixture = await createFixture({ kernel });
        const request = requestForRecipient(6);

        await expect(
            fixture.custody.retainForPublication(request),
        ).rejects.toMatchObject({ code: 'InvalidState' });
        expect(kernel.productionObservations).toHaveLength(1);
        const failedObservation = kernel.productionObservations[0];

        const resumedKernel = new DeterministicSeedMailboxKernel();
        const resumedCustody = await reopenCustody(fixture, resumedKernel);
        const completed = await resumedCustody.retainForPublication(request);
        expect(completed.headerBytes[0]).toBe(0xa1);
        expect(resumedKernel.productionObservations).toHaveLength(1);
        expect(
            resumedKernel.productionObservations[0]?.encapsulationRandomness,
        ).toEqual(failedObservation?.encapsulationRandomness);
        expect(
            resumedKernel.productionObservations[0]?.signatureRandomness,
        ).toEqual(failedObservation?.signatureRandomness);
        const replayKernel = new DeterministicSeedMailboxKernel();
        replayKernel.failNextProductionCount = 1;
        const replayCustody = await reopenCustody(fixture, replayKernel);
        await expect(
            replayCustody.retainForPublication(request),
        ).resolves.toEqual(completed);
        expect(replayKernel.productionObservations).toHaveLength(0);
    });

    it('does not produce until an interrupted reservation anchor is repaired', async () => {
        const fixture = await createFixture();
        await fixture.coordinator.reconcile();
        fixture.anchor.failNextCompareAndSetCount = 1;
        const request = requestForRecipient(5);

        await expect(
            fixture.custody.retainForPublication(request),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(fixture.kernel.productionObservations).toHaveLength(0);

        const resumedCarrier =
            await fixture.custody.retainForPublication(request);
        expect(resumedCarrier.headerBytes).toBeInstanceOf(Uint8Array);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
    });

    it('withholds a locally completed carrier until its anchor is repaired', async () => {
        const kernel = new DeterministicSeedMailboxKernel();
        const fixture = await createFixture({ kernel });
        const request = requestForRecipient(4);
        kernel.afterProduce = () => {
            fixture.anchor.failNextCompareAndSetCount = 1;
            kernel.afterProduce = undefined;
        };

        await expect(
            fixture.custody.retainForPublication(request),
        ).rejects.toMatchObject({ code: 'AnchorFailure' });
        expect(kernel.productionObservations).toHaveLength(1);

        const replayed = await fixture.custody.retainForPublication(request);
        expect(replayed.headerBytes[0]).toBe(0xa1);
        expect(kernel.productionObservations).toHaveLength(1);
    });

    it('keeps one stable slot across descriptor and terminal alternatives', async () => {
        const fixture = await createFixture();
        const request = requestForRecipient(8);
        await fixture.custody.retainForPublication(request);

        await expect(
            fixture.custody.retainForPublication({
                ...request,
                canonicalDeliveryDescriptorBytes:
                    request.canonicalDeliveryDescriptorBytes.map(
                        (byte, byteIndex) =>
                            byteIndex === 19 ? byte ^ 0x01 : byte,
                    ),
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });

        const alternateContext = Object.freeze({
            ...fixture.context,
            rootTerminalIdentity: hashFilledWith(0x34),
        });
        const alternateTerminalCustody = await reopenCustody(
            fixture,
            new DeterministicSeedMailboxKernel(),
            alternateContext,
        );
        await expect(
            alternateTerminalCustody.retainForPublication(request),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('persists the synchronous input snapshot and uses fresh randomness for another stream', async () => {
        const fixture = await createFixture();
        const firstRequest = requestForRecipient(1);
        const expectedDescriptor =
            firstRequest.canonicalDeliveryDescriptorBytes.slice();
        const firstPromise = fixture.custody.retainForPublication(firstRequest);
        firstRequest.canonicalDeliveryDescriptorBytes.fill(0xef);
        await firstPromise;
        expect(
            fixture.kernel.productionObservations[0]
                ?.canonicalDeliveryDescriptorBytes,
        ).toEqual(expectedDescriptor);

        await fixture.custody.retainForPublication(requestForRecipient(2));
        expect(fixture.kernel.productionObservations).toHaveLength(2);
        expect(
            fixture.kernel.productionObservations[0]?.encapsulationRandomness,
        ).not.toEqual(
            fixture.kernel.productionObservations[1]?.encapsulationRandomness,
        );
        expect(
            fixture.kernel.productionObservations[0]?.signatureRandomness,
        ).not.toEqual(
            fixture.kernel.productionObservations[1]?.signatureRandomness,
        );
    });

    it('retains one reservation across malformed output and validation failure', async () => {
        const kernel = new DeterministicSeedMailboxKernel();
        kernel.malformedNextCarrier = true;
        const fixture = await createFixture({ kernel });
        const request = requestForRecipient(0);

        await expect(
            fixture.custody.retainForPublication(request),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        const firstRandomness =
            kernel.productionObservations[0]?.encapsulationRandomness;

        kernel.failNextValidationCount = 1;
        await expect(
            fixture.custody.retainForPublication(request),
        ).rejects.toMatchObject({ code: 'AuthenticationFailed' });
        expect(
            kernel.productionObservations[1]?.encapsulationRandomness,
        ).toEqual(firstRandomness);

        const completedCarrier =
            await fixture.custody.retainForPublication(request);
        expect(completedCarrier.headerBytes).toBeInstanceOf(Uint8Array);
        expect(
            kernel.productionObservations[2]?.encapsulationRandomness,
        ).toEqual(firstRandomness);
    });

    it('serializes duplicate publication requests without producing twice', async () => {
        const fixture = await createFixture();
        const request = requestForRecipient(9);

        const [first, second] = await Promise.all([
            fixture.custody.retainForPublication(request),
            fixture.custody.retainForPublication(request),
        ]);
        expect(first).toEqual(second);
        expect(fixture.kernel.productionObservations).toHaveLength(1);
    });

    it('rejects repeated entropy before writing a reservation', async () => {
        const fixture = await createFixture({
            cryptoProvider: repeatedRandomnessCryptoProvider(),
        });

        await expect(
            fixture.custody.retainForPublication(requestForRecipient(7)),
        ).rejects.toMatchObject({ code: 'EntropyFailure' });
        expect(fixture.kernel.productionObservations).toHaveLength(0);
        expect(fixture.anchor.compareAndSetCallCount).toBe(1);
    });

    it('refuses hostile geometry, endpoint, and accessor inputs before state changes', async () => {
        const fixture = await createFixture();
        const request = requestForRecipient(7);

        expect(() =>
            fixture.custody.retainForPublication({
                ...request,
                recipientPosition: fixture.context.senderPosition,
            }),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        expect(() =>
            fixture.custody.retainForPublication({
                ...request,
                geometry: {
                    ...smallGeometry,
                    totalCarrierByteLength:
                        smallGeometry.totalCarrierByteLength + 1,
                },
            }),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));

        const accessorInput = Object.create(null) as Record<string, unknown>;
        Object.defineProperty(accessorInput, 'recipientPosition', {
            get: () => 7,
        });
        expect(() =>
            fixture.custody.retainForPublication(
                accessorInput as RetainSeedMailboxSenderStreamInput,
            ),
        ).toThrowError(expect.objectContaining({ code: 'InvalidInput' }));
        expect(fixture.anchor.compareAndSetCallCount).toBe(0);
    });
});
