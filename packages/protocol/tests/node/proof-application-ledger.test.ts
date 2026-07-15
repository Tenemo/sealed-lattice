import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    openProofApplicationLedger,
    type ProofApplicationLedger,
    type ProofApplicationLedgerLimits,
    type ProofApplicationReservationCapability,
} from '#packages/protocol/src/index';
import {
    generateRuntimeStorageEncryptionKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    copyProofApplicationReservationBindingDescription,
    loadFreshTranscriptCoreKernel,
    prepareProofApplicationReservationBinding,
    type ProofApplicationReservationBinding,
    ProofApplicationReservationBindingPreparationError,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const canonicalItemTypes = Object.freeze({
    rawBytes: 0x01,
    unsigned16: 0x03,
    unsigned32: 0x04,
    unsigned64: 0x05,
    hash512: 0x06,
    nestedTuple: 0x09,
    optional: 0x0d,
    homogeneousList: 0x0e,
});

const authorityContext = runtimeAuthorityContext();
const orderedFamilies = [
    0x2110, 0x2111, 0x1211, 0x1212, 0x1213, 0x1214, 0x1215, 0x1216, 0x1217,
    0x1218, 0x1302, 0x1621,
] as const;
const limits: ProofApplicationLedgerLimits = {
    maximumProofApplicationBindingByteLength: 2_048,
    maximumProofBytesPerAction: 12n,
    maximumProofObjectsPerAction: 12,
    maximumProofQueriesPerAction: 10n,
    maximumProofVerificationsPerAction: 12,
    maximumRecordSealingCount: 256,
    maximumSignatureVerificationsPerAction: 10,
    orderedFamilyApplicationCeilings: orderedFamilies.map(
        (applicationStatementSchemaIdentifier) => ({
            applicationStatementSchemaIdentifier,
            maximumApplicationSlotCount: 1,
        }),
    ),
    transactionLifetimeMilliseconds: 5_000,
};

const unsigned16 = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32 = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const unsigned64 = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const concatenate = (parts: readonly Uint8Array[]): Uint8Array => {
    const bytes = new Uint8Array(
        parts.reduce((total, part) => total + part.byteLength, 0),
    );
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.byteLength;
    }
    return bytes;
};

const item = (itemType: number, payload: Uint8Array): Uint8Array =>
    concatenate([
        unsigned16(itemType),
        unsigned32(payload.byteLength),
        payload,
    ]);

const tuple = (
    schemaIdentifier: number,
    items: readonly Uint8Array[],
): Uint8Array =>
    concatenate([
        unsigned16(schemaIdentifier),
        unsigned16(1),
        unsigned32(items.length),
        ...items,
    ]);

const optional = (containedType: number, payload?: Uint8Array): Uint8Array =>
    item(
        canonicalItemTypes.optional,
        concatenate([
            unsigned16(containedType),
            new Uint8Array([payload === undefined ? 0 : 1]),
            ...(payload === undefined ? [] : [payload]),
        ]),
    );

const proofApplicationSlot = (rosterPosition: number): Uint8Array =>
    tuple(0x0109, [
        item(canonicalItemTypes.unsigned16, unsigned16(1)),
        item(canonicalItemTypes.hash512, authorityContext.suiteIdentifier),
        item(canonicalItemTypes.hash512, authorityContext.ceremonyContextHash),
        item(canonicalItemTypes.hash512, authorityContext.actionContextHash),
        item(canonicalItemTypes.unsigned16, unsigned16(0x2110)),
        optional(canonicalItemTypes.unsigned16, unsigned16(rosterPosition)),
        optional(canonicalItemTypes.unsigned32),
        optional(canonicalItemTypes.unsigned64),
    ]);

const streamDescriptor = (proofByteLength = 1n): Uint8Array => {
    const chunkCount = Number((proofByteLength + 1_048_575n) / 1_048_576n);
    const digests = Array.from({ length: chunkCount }, (_, index) =>
        new Uint8Array(64).fill(0x60 + index),
    );
    return tuple(0x1800, [
        item(canonicalItemTypes.unsigned64, unsigned64(proofByteLength)),
        item(
            canonicalItemTypes.homogeneousList,
            concatenate([
                unsigned16(canonicalItemTypes.hash512),
                unsigned32(digests.length),
                ...digests,
            ]),
        ),
        item(canonicalItemTypes.hash512, new Uint8Array(64).fill(0x70)),
    ]);
};

const proofApplicationBinding = (input?: {
    headerHashByte?: number;
    proofByteLength?: bigint;
    rosterPosition?: number;
}): Uint8Array => {
    const slot = proofApplicationSlot(input?.rosterPosition ?? 2);
    const descriptor = streamDescriptor(input?.proofByteLength ?? 1n);
    return tuple(0x010a, [
        item(canonicalItemTypes.nestedTuple, slot),
        item(
            canonicalItemTypes.hash512,
            new Uint8Array(64).fill(input?.headerHashByte ?? 0x50),
        ),
        item(canonicalItemTypes.nestedTuple, descriptor),
    ]);
};

const prepareReservationBinding = (
    kernel: TranscriptCoreKernel,
    canonicalBindingBytes: Uint8Array,
): ProofApplicationReservationBinding =>
    prepareProofApplicationReservationBinding(kernel, {
        authorityContext: {
            actionContextHash: authorityContext.actionContextHash,
            ceremonyContextHash: authorityContext.ceremonyContextHash,
            suiteIdentifier: authorityContext.suiteIdentifier,
        },
        canonicalBindingBytes,
    });

const requirePreparationRefusal = (
    operation: () => unknown,
): ProofApplicationReservationBindingPreparationError => {
    try {
        operation();
    } catch (error) {
        expect(error).toBeInstanceOf(
            ProofApplicationReservationBindingPreparationError,
        );
        return error as ProofApplicationReservationBindingPreparationError;
    }
    throw new Error(
        'Expected proof application reservation binding preparation to fail.',
    );
};

describe('proof application ledger', () => {
    let kernel: TranscriptCoreKernel;
    let encryptionKey: CryptoKey;
    let adapter: InMemoryRuntimeStorageAdapter;
    let ledger: ProofApplicationLedger;

    beforeAll(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    beforeEach(async () => {
        encryptionKey = await generateRuntimeStorageEncryptionKey();
        const opened = await openRuntimeTestStore({
            namespace: 'proof-application-ledger-test',
        });
        adapter = opened.adapter;
        ledger = openProofApplicationLedger({
            authorityContext,
            encryptionKey,
            limits,
            store: opened.store,
        });
    });

    it('prepares an opaque reservation binding only after canonical decoding and context checks', async () => {
        const canonicalBindingBytes = proofApplicationBinding();
        const reservationBinding = prepareProofApplicationReservationBinding(
            kernel,
            {
                authorityContext: {
                    actionContextHash: authorityContext.actionContextHash,
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes,
            },
        );

        const wrongContextError = requirePreparationRefusal(() =>
            prepareProofApplicationReservationBinding(kernel, {
                authorityContext: {
                    actionContextHash: new Uint8Array(64).fill(0xaa),
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes,
            }),
        );
        expect(wrongContextError.refusalReason).toBe('wrongContext');

        const malformedError = requirePreparationRefusal(() =>
            prepareProofApplicationReservationBinding(kernel, {
                authorityContext: {
                    actionContextHash: authorityContext.actionContextHash,
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes: canonicalBindingBytes.slice(0, -1),
            }),
        );
        expect(malformedError.refusalReason).toBe('malformedEncoding');

        const wrongTypeError = requirePreparationRefusal(() =>
            prepareProofApplicationReservationBinding(kernel, {
                authorityContext: {
                    actionContextHash: new Uint8Array(63),
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes,
            }),
        );
        expect(wrongTypeError.refusalReason).toBe('wrongTypeOrLength');

        const reservation = await ledger.reserve(reservationBinding);
        expect(ledger.copyReservation(reservation)).toMatchObject({
            proofByteLength: 1n,
            verificationStarted: false,
        });
    });

    it('rejects bytes, decoded descriptions, copies, and fabricated reservation bindings', async () => {
        const canonicalBindingBytes = proofApplicationBinding();
        const reservationBinding = prepareProofApplicationReservationBinding(
            kernel,
            {
                authorityContext: {
                    actionContextHash: authorityContext.actionContextHash,
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes,
            },
        );
        const decodedKernelDescription = kernel.decodeProofApplicationBinding({
            canonicalBytesHex: Array.from(canonicalBindingBytes, (byte) =>
                byte.toString(16).padStart(2, '0'),
            ).join(''),
        });
        const copiedReservationDescription =
            copyProofApplicationReservationBindingDescription(
                reservationBinding,
            );
        copiedReservationDescription.applicationSlotHash.fill(0);
        copiedReservationDescription.canonicalBindingBytes.fill(0);
        copiedReservationDescription.proofHeaderHash.fill(0);
        const fabricatedCandidates = [
            canonicalBindingBytes,
            decodedKernelDescription,
            copiedReservationDescription,
            Object.freeze({}),
            Object.freeze({ isValid: true, value: reservationBinding }),
            structuredClone(reservationBinding),
        ] as const;

        for (const fabricatedCandidate of fabricatedCandidates) {
            await expect(
                ledger.reserve(
                    fabricatedCandidate as unknown as ProofApplicationReservationBinding,
                ),
            ).rejects.toMatchObject({ code: 'InvalidInput' });
        }

        const reservation = await ledger.reserve(reservationBinding);
        expect(ledger.copyReservation(reservation)).toMatchObject({
            proofByteLength: 1n,
            verificationStarted: false,
        });
    });

    it('does not let a reservation binding cross runtime authority contexts', async () => {
        const reservationBinding = prepareReservationBinding(
            kernel,
            proofApplicationBinding(),
        );
        const opened = await openRuntimeTestStore({
            namespace: 'proof-application-ledger-wrong-context-test',
        });
        const wrongContextLedger = openProofApplicationLedger({
            authorityContext: {
                ...authorityContext,
                actionContextHash: new Uint8Array(64).fill(0xaa),
            },
            encryptionKey,
            limits,
            store: opened.store,
        });

        await expect(
            wrongContextLedger.reserve(reservationBinding),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(await wrongContextLedger.snapshot()).toEqual({
            proofByteCount: 0n,
            proofObjectCount: 0,
            proofQueryCount: 0n,
            proofVerificationCount: 0,
            signatureVerificationCount: 0,
        });
    });

    it('rejects malformed runtime input with a typed refusal before calling the ledger', () => {
        const canonicalBindingBytes = proofApplicationBinding();
        const wrongCanonicalByteType = requirePreparationRefusal(() =>
            prepareProofApplicationReservationBinding(kernel, {
                authorityContext: {
                    actionContextHash: authorityContext.actionContextHash,
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes:
                    canonicalBindingBytes.buffer as unknown as Uint8Array,
            }),
        );
        expect(wrongCanonicalByteType.refusalReason).toBe('wrongTypeOrLength');

        const nullInput = requirePreparationRefusal(() =>
            prepareProofApplicationReservationBinding(kernel, null as never),
        );
        expect(nullInput.refusalReason).toBe('wrongTypeOrLength');
    });

    it('reserves exact bindings idempotently and refuses a changed header in the same slot', async () => {
        const binding = prepareReservationBinding(
            kernel,
            proofApplicationBinding(),
        );
        const changedHeaderBinding = prepareReservationBinding(
            kernel,
            proofApplicationBinding({ headerHashByte: 0x51 }),
        );

        const first = await ledger.reserve(binding);
        const replay = await ledger.reserve(binding);
        expect(replay).not.toBe(first);
        expect(ledger.copyReservation(replay)).toEqual(
            ledger.copyReservation(first),
        );
        expect(await ledger.snapshot()).toEqual({
            proofByteCount: 1n,
            proofObjectCount: 1,
            proofQueryCount: 0n,
            proofVerificationCount: 0,
            signatureVerificationCount: 0,
        });

        await expect(
            ledger.reserve(changedHeaderBinding),
        ).rejects.toMatchObject({ code: 'Conflict' });
    });

    it('consumes verification charges once and never releases after header validation starts', async () => {
        const binding = prepareReservationBinding(
            kernel,
            proofApplicationBinding(),
        );
        const reservation = await ledger.reserve(binding);
        const started = await ledger.beginVerification({
            proofQueryCount: 7n,
            reservation,
            signatureVerificationCount: 2,
        });
        expect(started.verificationStarted).toBe(true);
        await expect(
            ledger.beginVerification({
                proofQueryCount: 7n,
                reservation,
                signatureVerificationCount: 2,
            }),
        ).resolves.toEqual(started);
        expect(await ledger.snapshot()).toEqual({
            proofByteCount: 1n,
            proofObjectCount: 1,
            proofQueryCount: 7n,
            proofVerificationCount: 1,
            signatureVerificationCount: 2,
        });

        await expect(
            ledger.beginVerification({
                proofQueryCount: 8n,
                reservation,
                signatureVerificationCount: 2,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(
            ledger.releaseBeforeVerification(reservation),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('releases only an unstarted reservation and enforces the family and query ceilings', async () => {
        const binding = prepareReservationBinding(
            kernel,
            proofApplicationBinding(),
        );
        const releasedReservation = await ledger.reserve(binding);
        await expect(
            ledger.releaseBeforeVerification(releasedReservation),
        ).resolves.toBe(true);
        await expect(
            ledger.releaseBeforeVerification(releasedReservation),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        expect(await ledger.snapshot()).toEqual({
            proofByteCount: 0n,
            proofObjectCount: 0,
            proofQueryCount: 0n,
            proofVerificationCount: 0,
            signatureVerificationCount: 0,
        });

        const secondReservation = await ledger.reserve(binding);
        const secondSlot = prepareReservationBinding(
            kernel,
            proofApplicationBinding({ rosterPosition: 3 }),
        );
        await expect(ledger.reserve(secondSlot)).rejects.toMatchObject({
            code: 'ResourceLimit',
        });
        await expect(
            ledger.beginVerification({
                proofQueryCount: 11n,
                reservation: secondReservation,
                signatureVerificationCount: 0,
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
    });

    it('rejects forged, stale, and wrong-owner reservation capabilities', async () => {
        const binding = prepareReservationBinding(
            kernel,
            proofApplicationBinding(),
        );
        const reservation = await ledger.reserve(binding);
        const forgedReservation = Object.freeze(
            Object.create(null) as object,
        ) as ProofApplicationReservationCapability;

        expect(() => ledger.copyReservation(forgedReservation)).toThrowError(
            expect.objectContaining({ code: 'InvalidInput' }),
        );
        await expect(
            ledger.beginVerification({
                proofQueryCount: 1n,
                reservation: forgedReservation,
                signatureVerificationCount: 0,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        const opened = await openRuntimeTestStore({
            namespace: 'proof-application-ledger-capability-owner-test',
        });
        const otherLedger = openProofApplicationLedger({
            authorityContext,
            encryptionKey,
            limits,
            store: opened.store,
        });
        expect(() => otherLedger.copyReservation(reservation)).toThrowError(
            expect.objectContaining({ code: 'InvalidInput' }),
        );
        await expect(
            otherLedger.releaseBeforeVerification(reservation),
        ).rejects.toMatchObject({ code: 'InvalidInput' });

        await expect(
            ledger.releaseBeforeVerification(reservation),
        ).resolves.toBe(true);
        expect(() => ledger.copyReservation(reservation)).toThrowError(
            expect.objectContaining({ code: 'InvalidInput' }),
        );
        await expect(
            ledger.beginVerification({
                proofQueryCount: 1n,
                reservation,
                signatureVerificationCount: 0,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });

    it('fails closed when untrusted storage changes an authenticated ledger record', async () => {
        const binding = prepareReservationBinding(
            kernel,
            proofApplicationBinding(),
        );
        await ledger.reserve(binding);
        const objectKey = adapter
            .keys()
            .find((key) => key.includes('/objects/'));
        if (objectKey === undefined) {
            throw new Error('proof application object was not stored');
        }
        const stored = adapter.rawRead(objectKey);
        if (stored === undefined) {
            throw new Error('proof application object bytes are missing');
        }
        stored[stored.byteLength - 1] ^= 1;
        adapter.rawWrite(objectKey, stored);
        await expect(ledger.snapshot()).rejects.toMatchObject({
            code: 'AuthenticationFailed',
        });
    });
});
