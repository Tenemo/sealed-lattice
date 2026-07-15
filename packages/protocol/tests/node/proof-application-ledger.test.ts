import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
    openProofApplicationLedger,
    type ProofApplicationLedger,
    type ProofApplicationLedgerLimits,
} from '#packages/protocol/src/index';
import {
    generateRuntimeStorageEncryptionKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
    type InMemoryRuntimeStorageAdapter,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    loadFreshTranscriptCoreKernel,
    verifyProofApplicationBinding,
    type TranscriptCoreKernel,
    type VerifiedProofApplicationBinding,
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

const requireVerifiedBinding = (
    kernel: TranscriptCoreKernel,
    canonicalBindingBytes: Uint8Array,
): VerifiedProofApplicationBinding => {
    const result = verifyProofApplicationBinding(kernel, {
        authorityContext: {
            actionContextHash: authorityContext.actionContextHash,
            ceremonyContextHash: authorityContext.ceremonyContextHash,
            suiteIdentifier: authorityContext.suiteIdentifier,
        },
        canonicalBindingBytes,
    });
    if (!result.isValid) {
        throw new Error(
            `proof application binding refused: ${result.refusalReason}`,
        );
    }
    return result.value;
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

    it('accepts only a kernel-issued binding in the exact action context', async () => {
        const canonicalBindingBytes = proofApplicationBinding();
        const valid = verifyProofApplicationBinding(kernel, {
            authorityContext: {
                actionContextHash: authorityContext.actionContextHash,
                ceremonyContextHash: authorityContext.ceremonyContextHash,
                suiteIdentifier: authorityContext.suiteIdentifier,
            },
            canonicalBindingBytes,
        });
        expect(valid.isValid).toBe(true);

        const wrongContext = verifyProofApplicationBinding(kernel, {
            authorityContext: {
                actionContextHash: new Uint8Array(64).fill(0xaa),
                ceremonyContextHash: authorityContext.ceremonyContextHash,
                suiteIdentifier: authorityContext.suiteIdentifier,
            },
            canonicalBindingBytes,
        });
        expect(wrongContext).toEqual({
            isValid: false,
            refusalReason: 'wrongContext',
        });

        const malformed = canonicalBindingBytes.slice(0, -1);
        expect(
            verifyProofApplicationBinding(kernel, {
                authorityContext: {
                    actionContextHash: authorityContext.actionContextHash,
                    ceremonyContextHash: authorityContext.ceremonyContextHash,
                    suiteIdentifier: authorityContext.suiteIdentifier,
                },
                canonicalBindingBytes: malformed,
            }),
        ).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });

        await expect(
            ledger.reserve({} as VerifiedProofApplicationBinding),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });

    it('reserves exact bindings idempotently and refuses a changed header in the same slot', async () => {
        const binding = requireVerifiedBinding(
            kernel,
            proofApplicationBinding(),
        );
        const changedHeaderBinding = requireVerifiedBinding(
            kernel,
            proofApplicationBinding({ headerHashByte: 0x51 }),
        );

        const first = await ledger.reserve(binding);
        const replay = await ledger.reserve(binding);
        expect(replay).toEqual(first);
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
        const binding = requireVerifiedBinding(
            kernel,
            proofApplicationBinding(),
        );
        await ledger.reserve(binding);
        const started = await ledger.beginVerification({
            proofQueryCount: 7n,
            signatureVerificationCount: 2,
            verifiedBinding: binding,
        });
        expect(started.verificationStarted).toBe(true);
        await expect(
            ledger.beginVerification({
                proofQueryCount: 7n,
                signatureVerificationCount: 2,
                verifiedBinding: binding,
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
                signatureVerificationCount: 2,
                verifiedBinding: binding,
            }),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await expect(
            ledger.releaseBeforeVerification(binding),
        ).rejects.toMatchObject({ code: 'InvalidState' });
    });

    it('releases only an unstarted reservation and enforces the family and query ceilings', async () => {
        const binding = requireVerifiedBinding(
            kernel,
            proofApplicationBinding(),
        );
        await ledger.reserve(binding);
        await expect(ledger.releaseBeforeVerification(binding)).resolves.toBe(
            true,
        );
        await expect(ledger.releaseBeforeVerification(binding)).resolves.toBe(
            false,
        );
        expect(await ledger.snapshot()).toEqual({
            proofByteCount: 0n,
            proofObjectCount: 0,
            proofQueryCount: 0n,
            proofVerificationCount: 0,
            signatureVerificationCount: 0,
        });

        await ledger.reserve(binding);
        const secondSlot = requireVerifiedBinding(
            kernel,
            proofApplicationBinding({ rosterPosition: 3 }),
        );
        await expect(ledger.reserve(secondSlot)).rejects.toMatchObject({
            code: 'ResourceLimit',
        });
        await expect(
            ledger.beginVerification({
                proofQueryCount: 11n,
                signatureVerificationCount: 0,
                verifiedBinding: binding,
            }),
        ).rejects.toMatchObject({ code: 'ResourceLimit' });
    });

    it('fails closed when untrusted storage changes an authenticated ledger record', async () => {
        const binding = requireVerifiedBinding(
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
