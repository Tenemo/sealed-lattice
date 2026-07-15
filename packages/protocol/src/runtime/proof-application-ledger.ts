import {
    copyProofApplicationReservationBindingDescription,
    type ProofApplicationReservationBinding,
    type ProofApplicationReservationBindingDescription,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    type AuthenticatedRuntimeRecordErrorCode,
    bytesEqual,
    bytesToHex,
    copyRuntimeStorageAuthorityContext,
    createRuntimeRecordProtection,
    mapStorageError,
    readRuntimeRecord,
    stageRuntimeRecordWrite,
    type RuntimeStorageAuthorityContext,
} from './authenticated-runtime-record.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const proofApplicationRecordVersion = 1;
const proofApplicationRecordOperationDomain =
    'sealed-lattice/runtime/proof-application-ledger/v1';
const proofApplicationRecordLogicalKey = 'proof-applications/current';
const foundationHashByteLength = 64;
const recordHeaderByteLength = 34;
const entryHeaderByteLength = 91;
const maximumUnsigned32 = 0xffff_ffff;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const reservedEntryState = 1;
const verificationStartedEntryState = 2;
const assignedProofFamilies = Object.freeze([
    0x2110, 0x2111, 0x1211, 0x1212, 0x1213, 0x1214, 0x1215, 0x1216, 0x1217,
    0x1218, 0x1302, 0x1621,
] as const);

export type ProofFamilyApplicationCeiling = Readonly<{
    applicationStatementSchemaIdentifier: number;
    maximumApplicationSlotCount: number;
}>;

export type ProofApplicationLedgerLimits = Readonly<{
    maximumProofApplicationBindingByteLength: number;
    maximumProofBytesPerAction: bigint;
    maximumProofObjectsPerAction: number;
    maximumProofQueriesPerAction: bigint;
    maximumProofVerificationsPerAction: number;
    maximumRecordSealingCount: number;
    maximumSignatureVerificationsPerAction: number;
    orderedFamilyApplicationCeilings: readonly ProofFamilyApplicationCeiling[];
    transactionLifetimeMilliseconds: number;
}>;

export type ProofApplicationReservation = Readonly<{
    applicationSlotHash: Uint8Array;
    applicationStatementSchemaIdentifier: number;
    proofByteLength: bigint;
    verificationStarted: boolean;
}>;

declare const proofApplicationReservationCapabilityBrand: unique symbol;

/**
 * Process-local ownership of one durable proof resource reservation. Canonical
 * proof-binding bytes can create this reservation, but they cannot reconstruct
 * its capability after release or in another ledger instance.
 */
export type ProofApplicationReservationCapability = Readonly<{
    readonly [proofApplicationReservationCapabilityBrand]: true;
}>;

export type ProofApplicationLedgerSnapshot = Readonly<{
    proofByteCount: bigint;
    proofObjectCount: number;
    proofQueryCount: bigint;
    proofVerificationCount: number;
    signatureVerificationCount: number;
}>;

export type ProofApplicationLedger = Readonly<{
    copyAuthorityContext(): RuntimeStorageAuthorityContext;
    reserve(
        reservationBinding: ProofApplicationReservationBinding,
    ): Promise<ProofApplicationReservationCapability>;
    copyReservation(
        reservation: ProofApplicationReservationCapability,
    ): ProofApplicationReservation;
    beginVerification(input: {
        proofQueryCount: bigint;
        reservation: ProofApplicationReservationCapability;
        signatureVerificationCount: number;
    }): Promise<ProofApplicationReservation>;
    releaseBeforeVerification(
        reservation: ProofApplicationReservationCapability,
    ): Promise<boolean>;
    snapshot(): Promise<ProofApplicationLedgerSnapshot>;
}>;

type ProofApplicationEntry = {
    applicationSlotHash: Uint8Array;
    applicationStatementSchemaIdentifier: number;
    canonicalBindingBytes: Uint8Array;
    proofByteLength: bigint;
    proofQueryCount: bigint;
    signatureVerificationCount: number;
    verificationStarted: boolean;
};

type ProofApplicationRecord = {
    entries: ProofApplicationEntry[];
    proofByteCount: bigint;
    proofObjectCount: number;
    proofQueryCount: bigint;
    proofVerificationCount: number;
    signatureVerificationCount: number;
};

type OpenedProofApplicationRecord = Readonly<{
    record: ProofApplicationRecord;
    sealedBytes: Uint8Array | null;
}>;

type ProofApplicationReservationCapabilityRecord = {
    binding: ProofApplicationReservationBinding;
    generation: number;
    reservation: ProofApplicationReservation;
    slotKey: string;
};

const requireSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

const requireUnsigned32 = (value: number, label: string): void => {
    requireSafePositiveInteger(value, label);
    if (value > maximumUnsigned32) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} exceeds the unsigned 32-bit range.`,
        );
    }
};

const requirePositiveUnsigned64 = (value: bigint, label: string): void => {
    if (typeof value !== 'bigint' || value <= 0n || value > maximumUnsigned64) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} must be a positive unsigned 64-bit integer.`,
        );
    }
};

const copyAndValidateLimits = (
    limits: ProofApplicationLedgerLimits,
): ProofApplicationLedgerLimits => {
    if (typeof limits !== 'object' || limits === null) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Proof application ledger limits must be an object.',
        );
    }
    requireSafePositiveInteger(
        limits.maximumProofApplicationBindingByteLength,
        'maximumProofApplicationBindingByteLength',
    );
    requirePositiveUnsigned64(
        limits.maximumProofBytesPerAction,
        'maximumProofBytesPerAction',
    );
    requireUnsigned32(
        limits.maximumProofObjectsPerAction,
        'maximumProofObjectsPerAction',
    );
    requirePositiveUnsigned64(
        limits.maximumProofQueriesPerAction,
        'maximumProofQueriesPerAction',
    );
    requireUnsigned32(
        limits.maximumProofVerificationsPerAction,
        'maximumProofVerificationsPerAction',
    );
    requireUnsigned32(
        limits.maximumRecordSealingCount,
        'maximumRecordSealingCount',
    );
    requireUnsigned32(
        limits.maximumSignatureVerificationsPerAction,
        'maximumSignatureVerificationsPerAction',
    );
    requireSafePositiveInteger(
        limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    const untrustedOrderedFamilyApplicationCeilings: unknown =
        limits.orderedFamilyApplicationCeilings;
    if (
        !Array.isArray(untrustedOrderedFamilyApplicationCeilings) ||
        untrustedOrderedFamilyApplicationCeilings.length !==
            assignedProofFamilies.length
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Proof application limits must contain all assigned family ceilings.',
        );
    }
    const orderedFamilyApplicationCeilings =
        limits.orderedFamilyApplicationCeilings.map((ceiling, index) => {
            const expectedFamily = assignedProofFamilies[index];
            if (
                typeof ceiling !== 'object' ||
                ceiling === null ||
                ceiling.applicationStatementSchemaIdentifier !== expectedFamily
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidConfiguration',
                    'Proof family ceilings are missing, duplicated, or out of canonical order.',
                );
            }
            requireUnsigned32(
                ceiling.maximumApplicationSlotCount,
                `maximumApplicationSlotCount for family ${expectedFamily.toString(16)}`,
            );
            return Object.freeze({ ...ceiling });
        });
    const familyTotal = orderedFamilyApplicationCeilings.reduce(
        (total, ceiling) =>
            checkedNumberAdd(
                total,
                ceiling.maximumApplicationSlotCount,
                'proof family ceiling total',
            ),
        0,
    );
    if (familyTotal !== limits.maximumProofObjectsPerAction) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'The proof object cap does not equal the complete family-slot ceiling sum.',
        );
    }
    if (
        limits.maximumProofVerificationsPerAction <
        limits.maximumProofObjectsPerAction
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'The proof verification cap must cover every permitted proof object.',
        );
    }
    return Object.freeze({
        ...limits,
        orderedFamilyApplicationCeilings: Object.freeze(
            orderedFamilyApplicationCeilings,
        ),
    });
};

export const openProofApplicationLedger = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    limits: ProofApplicationLedgerLimits;
    store: UntrustedStorageTransactionStore;
}): ProofApplicationLedger => {
    const limits = copyAndValidateLimits(input.limits);
    const protection = createRuntimeRecordProtection({
        authorityContext: input.authorityContext,
        cryptoProvider: input.cryptoProvider,
        encryptionKey: input.encryptionKey,
        maximumRecordSealingCount: limits.maximumRecordSealingCount,
    });
    let operationTail = Promise.resolve();
    const enqueue = <Result>(
        operation: () => Promise<Result>,
    ): Promise<Result> => {
        const result = operationTail.then(operation, operation);
        operationTail = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    };
    const reservationCapabilityRecords = new WeakMap<
        object,
        ProofApplicationReservationCapabilityRecord
    >();
    const reservationGenerationBySlot = new Map<string, number>();
    const mintReservationCapability = (
        binding: ProofApplicationReservationBinding,
        reservation: ProofApplicationReservation,
    ): ProofApplicationReservationCapability => {
        const slotKey = bytesToHex(reservation.applicationSlotHash);
        const capability = Object.freeze(
            Object.create(null) as object,
        ) as ProofApplicationReservationCapability;
        reservationCapabilityRecords.set(capability, {
            binding,
            generation: reservationGenerationBySlot.get(slotKey) ?? 0,
            reservation,
            slotKey,
        });
        return capability;
    };
    const requireReservationCapability = (
        reservation: ProofApplicationReservationCapability,
    ): ProofApplicationReservationCapabilityRecord => {
        const record =
            (typeof reservation === 'object' ||
                typeof reservation === 'function') &&
            reservation !== null
                ? reservationCapabilityRecords.get(reservation)
                : undefined;
        if (
            record === undefined ||
            record.generation !==
                (reservationGenerationBySlot.get(record.slotKey) ?? 0)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'The proof application reservation capability is forged, stale, or owned by another ledger.',
            );
        }
        return record;
    };
    const copyReservation = (
        reservation: ProofApplicationReservationCapability,
    ): ProofApplicationReservation =>
        copyReservationValue(
            requireReservationCapability(reservation).reservation,
        );

    const reserve: ProofApplicationLedger['reserve'] = (reservationBinding) =>
        enqueue(async () => {
            const description = copyAndRequireBinding(
                reservationBinding,
                protection.authorityContext,
                limits,
            );
            try {
                const opened = await readRecord(
                    input.store,
                    protection,
                    limits,
                );
                const existing = findEntry(
                    opened.record,
                    description.applicationSlotHash,
                );
                if (existing !== undefined) {
                    requireExactBinding(existing, description);
                    return mintReservationCapability(
                        reservationBinding,
                        reservationFromEntry(existing),
                    );
                }
                requireAvailableFamilySlot(opened.record, description, limits);
                const nextProofByteCount = checkedBigIntAdd(
                    opened.record.proofByteCount,
                    description.proofByteLength,
                    'proof byte count',
                );
                if (
                    opened.record.proofObjectCount >=
                        limits.maximumProofObjectsPerAction ||
                    nextProofByteCount > limits.maximumProofBytesPerAction
                ) {
                    throw resourceLimit(
                        'The action proof object or byte reservation cap was exhausted.',
                    );
                }
                const entry: ProofApplicationEntry = {
                    applicationSlotHash:
                        description.applicationSlotHash.slice(),
                    applicationStatementSchemaIdentifier:
                        description.applicationStatementSchemaIdentifier,
                    canonicalBindingBytes:
                        description.canonicalBindingBytes.slice(),
                    proofByteLength: description.proofByteLength,
                    proofQueryCount: 0n,
                    signatureVerificationCount: 0,
                    verificationStarted: false,
                };
                opened.record.entries.push(entry);
                opened.record.entries.sort(compareEntries);
                recomputeCounters(opened.record, limits);
                await writeRecord(
                    input.store,
                    protection,
                    limits,
                    opened.record,
                    opened.sealedBytes,
                );
                return mintReservationCapability(
                    reservationBinding,
                    reservationFromEntry(entry),
                );
            } finally {
                destroyBindingDescription(description);
            }
        });

    const beginVerification: ProofApplicationLedger['beginVerification'] = (
        verificationInput,
    ) =>
        enqueue(async () => {
            const capabilityRecord = requireReservationCapability(
                verificationInput.reservation,
            );
            const description = copyAndRequireBinding(
                capabilityRecord.binding,
                protection.authorityContext,
                limits,
            );
            const proofQueryCount = requireCounterBigInt(
                verificationInput.proofQueryCount,
                'proofQueryCount',
            );
            const signatureVerificationCount = requireCounterNumber(
                verificationInput.signatureVerificationCount,
                'signatureVerificationCount',
            );
            try {
                const opened = await readRecord(
                    input.store,
                    protection,
                    limits,
                );
                const entry = findEntry(
                    opened.record,
                    description.applicationSlotHash,
                );
                if (entry === undefined) {
                    throw new AuthenticatedRuntimeRecordError(
                        'MissingRecord',
                        'Proof verification requires a durable application reservation.',
                    );
                }
                requireExactBinding(entry, description);
                if (entry.verificationStarted) {
                    if (
                        entry.proofQueryCount !== proofQueryCount ||
                        entry.signatureVerificationCount !==
                            signatureVerificationCount
                    ) {
                        throw new AuthenticatedRuntimeRecordError(
                            'Conflict',
                            'An exact proof binding already began with different resource charges.',
                        );
                    }
                    const reservation = reservationFromEntry(entry);
                    capabilityRecord.reservation = reservation;
                    return reservation;
                }
                const nextProofVerificationCount = checkedNumberAdd(
                    opened.record.proofVerificationCount,
                    1,
                    'proof verification count',
                );
                const nextProofQueryCount = checkedBigIntAdd(
                    opened.record.proofQueryCount,
                    proofQueryCount,
                    'proof query count',
                );
                const nextSignatureVerificationCount = checkedNumberAdd(
                    opened.record.signatureVerificationCount,
                    signatureVerificationCount,
                    'signature verification count',
                );
                if (
                    nextProofVerificationCount >
                        limits.maximumProofVerificationsPerAction ||
                    nextProofQueryCount > limits.maximumProofQueriesPerAction ||
                    nextSignatureVerificationCount >
                        limits.maximumSignatureVerificationsPerAction
                ) {
                    throw resourceLimit(
                        'The action verification, query, or signature counter was exhausted.',
                    );
                }
                entry.verificationStarted = true;
                entry.proofQueryCount = proofQueryCount;
                entry.signatureVerificationCount = signatureVerificationCount;
                recomputeCounters(opened.record, limits);
                await writeRecord(
                    input.store,
                    protection,
                    limits,
                    opened.record,
                    opened.sealedBytes,
                );
                const reservation = reservationFromEntry(entry);
                capabilityRecord.reservation = reservation;
                return reservation;
            } finally {
                destroyBindingDescription(description);
            }
        });

    const releaseBeforeVerification: ProofApplicationLedger['releaseBeforeVerification'] =
        (reservation) =>
            enqueue(async () => {
                const capabilityRecord =
                    requireReservationCapability(reservation);
                const description = copyAndRequireBinding(
                    capabilityRecord.binding,
                    protection.authorityContext,
                    limits,
                );
                try {
                    const opened = await readRecord(
                        input.store,
                        protection,
                        limits,
                    );
                    const entryIndex = opened.record.entries.findIndex(
                        (entry) =>
                            bytesEqual(
                                entry.applicationSlotHash,
                                description.applicationSlotHash,
                            ),
                    );
                    if (entryIndex < 0) {
                        return false;
                    }
                    const entry = opened.record.entries[entryIndex];
                    requireExactBinding(entry, description);
                    if (entry.verificationStarted) {
                        throw new AuthenticatedRuntimeRecordError(
                            'InvalidState',
                            'A proof application reservation cannot be released after verification began.',
                        );
                    }
                    destroyEntry(entry);
                    opened.record.entries.splice(entryIndex, 1);
                    recomputeCounters(opened.record, limits);
                    await writeRecord(
                        input.store,
                        protection,
                        limits,
                        opened.record,
                        opened.sealedBytes,
                    );
                    reservationGenerationBySlot.set(
                        capabilityRecord.slotKey,
                        capabilityRecord.generation + 1,
                    );
                    return true;
                } finally {
                    destroyBindingDescription(description);
                }
            });

    const snapshot: ProofApplicationLedger['snapshot'] = () =>
        enqueue(async () => {
            const opened = await readRecord(input.store, protection, limits);
            return snapshotFromRecord(opened.record);
        });

    return Object.freeze({
        copyAuthorityContext: () =>
            copyRuntimeStorageAuthorityContext(protection.authorityContext),
        reserve,
        copyReservation,
        beginVerification,
        releaseBeforeVerification,
        snapshot,
    });
};

const copyAndRequireBinding = (
    reservationBinding: ProofApplicationReservationBinding,
    authorityContext: RuntimeStorageAuthorityContext,
    limits: ProofApplicationLedgerLimits,
): ProofApplicationReservationBindingDescription => {
    let description: ProofApplicationReservationBindingDescription;
    try {
        description =
            copyProofApplicationReservationBindingDescription(
                reservationBinding,
            );
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'The proof application reservation binding was not prepared by the WASM binding decoder.',
            error,
        );
    }
    if (
        !bytesEqual(
            description.suiteIdentifier,
            authorityContext.suiteIdentifier,
        ) ||
        !bytesEqual(
            description.ceremonyContextHash,
            authorityContext.ceremonyContextHash,
        ) ||
        !bytesEqual(
            description.actionContextHash,
            authorityContext.actionContextHash,
        )
    ) {
        destroyBindingDescription(description);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'The proof application reservation binding belongs to another runtime context.',
        );
    }
    if (
        description.canonicalBindingBytes.byteLength >
            limits.maximumProofApplicationBindingByteLength ||
        description.proofByteLength > limits.maximumProofBytesPerAction
    ) {
        destroyBindingDescription(description);
        throw resourceLimit(
            'The proof application reservation binding exceeds the configured action bounds.',
        );
    }
    return description;
};

const readRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: ReturnType<typeof createRuntimeRecordProtection>,
    limits: ProofApplicationLedgerLimits,
): Promise<OpenedProofApplicationRecord> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: proofApplicationRecordLogicalKey,
        operationDomain: proofApplicationRecordOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return {
            record: emptyRecord(),
            sealedBytes: null,
        };
    }
    try {
        return {
            record: decodeRecord(opened.plaintext, limits),
            sealedBytes: opened.sealedBytes.slice(),
        };
    } finally {
        opened.plaintext.fill(0);
    }
};

const writeRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: ReturnType<typeof createRuntimeRecordProtection>,
    limits: ProofApplicationLedgerLimits,
    record: ProofApplicationRecord,
    expectedCurrentSealedBytes: Uint8Array | null,
): Promise<void> => {
    const transaction = await store.beginTransaction({
        lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
    });
    try {
        if (record.entries.length === 0) {
            if (expectedCurrentSealedBytes === null) {
                await transaction.abort();
                return;
            }
            await transaction.stageDeletion(
                proofApplicationRecordLogicalKey,
                expectedCurrentSealedBytes,
            );
        } else {
            const plaintext = encodeRecord(record, limits);
            try {
                await stageRuntimeRecordWrite({
                    expectedCurrentSealedBytes,
                    logicalRecordKey: proofApplicationRecordLogicalKey,
                    operationDomain: proofApplicationRecordOperationDomain,
                    plaintext,
                    protection,
                    transaction,
                });
            } finally {
                plaintext.fill(0);
            }
        }
        await transaction.commit();
    } catch (error) {
        throw await closeTransactionAfterFailure(transaction, error);
    }
};

const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationFailure: unknown,
): Promise<AuthenticatedRuntimeRecordError> => {
    const mappedOperationFailure = mapStorageError(operationFailure);
    try {
        await transaction.closeAfterFailure();
    } catch (closeFailure) {
        throw new AuthenticatedRuntimeRecordError(
            'CleanupFailed',
            'A proof application transaction failed and could not release its ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const emptyRecord = (): ProofApplicationRecord => ({
    entries: [],
    proofByteCount: 0n,
    proofObjectCount: 0,
    proofQueryCount: 0n,
    proofVerificationCount: 0,
    signatureVerificationCount: 0,
});

const encodeRecord = (
    record: ProofApplicationRecord,
    limits: ProofApplicationLedgerLimits,
): Uint8Array => {
    recomputeCounters(record, limits);
    const byteLength = record.entries.reduce(
        (total, entry) =>
            checkedNumberAdd(
                total,
                checkedNumberAdd(
                    entryHeaderByteLength,
                    entry.canonicalBindingBytes.byteLength,
                    'proof application entry byte length',
                ),
                'proof application record byte length',
            ),
        recordHeaderByteLength,
    );
    const bytes = new Uint8Array(byteLength);
    const view = new DataView(bytes.buffer);
    view.setUint16(0, proofApplicationRecordVersion, true);
    view.setUint32(2, record.proofObjectCount, true);
    view.setBigUint64(6, record.proofByteCount, true);
    view.setUint32(14, record.proofVerificationCount, true);
    view.setBigUint64(18, record.proofQueryCount, true);
    view.setUint32(26, record.signatureVerificationCount, true);
    view.setUint32(30, record.entries.length, true);
    let offset = recordHeaderByteLength;
    for (const entry of record.entries) {
        view.setUint16(
            offset,
            entry.applicationStatementSchemaIdentifier,
            true,
        );
        view.setUint8(
            offset + 2,
            entry.verificationStarted
                ? verificationStartedEntryState
                : reservedEntryState,
        );
        view.setBigUint64(offset + 3, entry.proofQueryCount, true);
        view.setUint32(offset + 11, entry.signatureVerificationCount, true);
        view.setBigUint64(offset + 15, entry.proofByteLength, true);
        bytes.set(entry.applicationSlotHash, offset + 23);
        view.setUint32(
            offset + 87,
            entry.canonicalBindingBytes.byteLength,
            true,
        );
        bytes.set(entry.canonicalBindingBytes, offset + entryHeaderByteLength);
        offset +=
            entryHeaderByteLength + entry.canonicalBindingBytes.byteLength;
    }
    return bytes;
};

const decodeRecord = (
    bytes: Uint8Array,
    limits: ProofApplicationLedgerLimits,
): ProofApplicationRecord => {
    if (bytes.byteLength < recordHeaderByteLength) {
        throw authenticationFailure(
            'The proof application record is truncated.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const declaredObjectCount = view.getUint32(2, true);
    if (
        view.getUint16(0, true) !== proofApplicationRecordVersion ||
        declaredObjectCount === 0 ||
        declaredObjectCount > limits.maximumProofObjectsPerAction ||
        view.getUint32(30, true) !== declaredObjectCount
    ) {
        throw authenticationFailure(
            'The proof application record header is noncanonical.',
        );
    }
    const entries: ProofApplicationEntry[] = [];
    let offset = recordHeaderByteLength;
    for (
        let entryIndex = 0;
        entryIndex < declaredObjectCount;
        entryIndex += 1
    ) {
        if (offset > bytes.byteLength - entryHeaderByteLength) {
            destroyEntries(entries);
            throw authenticationFailure(
                'The proof application record contains a truncated entry.',
            );
        }
        const applicationStatementSchemaIdentifier = view.getUint16(
            offset,
            true,
        );
        const state = view.getUint8(offset + 2);
        const proofQueryCount = view.getBigUint64(offset + 3, true);
        const signatureVerificationCount = view.getUint32(offset + 11, true);
        const proofByteLength = view.getBigUint64(offset + 15, true);
        const applicationSlotHash = bytes.slice(offset + 23, offset + 87);
        const bindingByteLength = view.getUint32(offset + 87, true);
        const bindingOffset = checkedByteOffsetAdd(
            offset,
            entryHeaderByteLength,
            bytes.byteLength,
        );
        const bindingEnd = checkedByteOffsetAdd(
            bindingOffset,
            bindingByteLength,
            bytes.byteLength,
        );
        if (
            !assignedProofFamilies.includes(
                applicationStatementSchemaIdentifier as (typeof assignedProofFamilies)[number],
            ) ||
            (state !== reservedEntryState &&
                state !== verificationStartedEntryState) ||
            proofByteLength === 0n ||
            proofByteLength > limits.maximumProofBytesPerAction ||
            bindingByteLength === 0 ||
            bindingByteLength >
                limits.maximumProofApplicationBindingByteLength ||
            bindingEnd > bytes.byteLength ||
            (state === reservedEntryState &&
                (proofQueryCount !== 0n || signatureVerificationCount !== 0))
        ) {
            applicationSlotHash.fill(0);
            destroyEntries(entries);
            throw authenticationFailure(
                'The proof application record entry is noncanonical.',
            );
        }
        const entry: ProofApplicationEntry = {
            applicationSlotHash,
            applicationStatementSchemaIdentifier,
            canonicalBindingBytes: bytes.slice(bindingOffset, bindingEnd),
            proofByteLength,
            proofQueryCount,
            signatureVerificationCount,
            verificationStarted: state === verificationStartedEntryState,
        };
        if (
            entries.length > 0 &&
            compareEntries(entries[entries.length - 1], entry) >= 0
        ) {
            destroyEntry(entry);
            destroyEntries(entries);
            throw authenticationFailure(
                'The proof application record entries are duplicated or out of order.',
            );
        }
        entries.push(entry);
        offset = bindingEnd;
    }
    if (offset !== bytes.byteLength) {
        destroyEntries(entries);
        throw authenticationFailure(
            'The proof application record contains trailing bytes.',
        );
    }
    const record: ProofApplicationRecord = {
        entries,
        proofByteCount: view.getBigUint64(6, true),
        proofObjectCount: declaredObjectCount,
        proofQueryCount: view.getBigUint64(18, true),
        proofVerificationCount: view.getUint32(14, true),
        signatureVerificationCount: view.getUint32(26, true),
    };
    const declaredCounters = snapshotFromRecord(record);
    try {
        recomputeCounters(record, limits);
    } catch (error) {
        destroyEntries(entries);
        throw error;
    }
    if (
        record.proofObjectCount !== declaredCounters.proofObjectCount ||
        record.proofByteCount !== declaredCounters.proofByteCount ||
        record.proofVerificationCount !==
            declaredCounters.proofVerificationCount ||
        record.proofQueryCount !== declaredCounters.proofQueryCount ||
        record.signatureVerificationCount !==
            declaredCounters.signatureVerificationCount
    ) {
        destroyEntries(entries);
        throw authenticationFailure(
            'The proof application record counters do not match its entries.',
        );
    }
    return record;
};

const recomputeCounters = (
    record: ProofApplicationRecord,
    limits: ProofApplicationLedgerLimits,
): void => {
    const familyCounts = new Map<number, number>();
    let proofByteCount = 0n;
    let proofQueryCount = 0n;
    let proofVerificationCount = 0;
    let signatureVerificationCount = 0;
    for (const entry of record.entries) {
        proofByteCount = checkedBigIntAdd(
            proofByteCount,
            entry.proofByteLength,
            'proof byte count',
        );
        familyCounts.set(
            entry.applicationStatementSchemaIdentifier,
            checkedNumberAdd(
                familyCounts.get(entry.applicationStatementSchemaIdentifier) ??
                    0,
                1,
                'proof family count',
            ),
        );
        if (entry.verificationStarted) {
            proofVerificationCount = checkedNumberAdd(
                proofVerificationCount,
                1,
                'proof verification count',
            );
            proofQueryCount = checkedBigIntAdd(
                proofQueryCount,
                entry.proofQueryCount,
                'proof query count',
            );
            signatureVerificationCount = checkedNumberAdd(
                signatureVerificationCount,
                entry.signatureVerificationCount,
                'signature verification count',
            );
        }
    }
    if (
        record.entries.length > limits.maximumProofObjectsPerAction ||
        proofByteCount > limits.maximumProofBytesPerAction ||
        proofVerificationCount > limits.maximumProofVerificationsPerAction ||
        proofQueryCount > limits.maximumProofQueriesPerAction ||
        signatureVerificationCount >
            limits.maximumSignatureVerificationsPerAction
    ) {
        throw resourceLimit(
            'The stored proof application counters exceed their configured limits.',
        );
    }
    for (const ceiling of limits.orderedFamilyApplicationCeilings) {
        if (
            (familyCounts.get(ceiling.applicationStatementSchemaIdentifier) ??
                0) > ceiling.maximumApplicationSlotCount
        ) {
            throw resourceLimit(
                'The stored proof application family count exceeds its derived ceiling.',
            );
        }
    }
    record.proofObjectCount = record.entries.length;
    record.proofByteCount = proofByteCount;
    record.proofVerificationCount = proofVerificationCount;
    record.proofQueryCount = proofQueryCount;
    record.signatureVerificationCount = signatureVerificationCount;
};

const requireAvailableFamilySlot = (
    record: ProofApplicationRecord,
    description: ProofApplicationReservationBindingDescription,
    limits: ProofApplicationLedgerLimits,
): void => {
    const ceiling = limits.orderedFamilyApplicationCeilings.find(
        (candidate) =>
            candidate.applicationStatementSchemaIdentifier ===
            description.applicationStatementSchemaIdentifier,
    );
    if (ceiling === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'The proof binding uses an unassigned application family.',
        );
    }
    const occupiedSlotCount = record.entries.filter(
        (entry) =>
            entry.applicationStatementSchemaIdentifier ===
            description.applicationStatementSchemaIdentifier,
    ).length;
    if (occupiedSlotCount >= ceiling.maximumApplicationSlotCount) {
        throw resourceLimit(
            'The proof application family slot ceiling was exhausted.',
        );
    }
};

const requireExactBinding = (
    entry: ProofApplicationEntry,
    description: ProofApplicationReservationBindingDescription,
): void => {
    if (
        entry.applicationStatementSchemaIdentifier !==
            description.applicationStatementSchemaIdentifier ||
        entry.proofByteLength !== description.proofByteLength ||
        !bytesEqual(
            entry.canonicalBindingBytes,
            description.canonicalBindingBytes,
        )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'Conflict',
            'A different proof header, descriptor, or slot already occupies this application slot.',
        );
    }
};

const findEntry = (
    record: ProofApplicationRecord,
    applicationSlotHash: Uint8Array,
): ProofApplicationEntry | undefined =>
    record.entries.find((entry) =>
        bytesEqual(entry.applicationSlotHash, applicationSlotHash),
    );

const compareEntries = (
    left: ProofApplicationEntry,
    right: ProofApplicationEntry,
): number => {
    for (
        let byteIndex = 0;
        byteIndex < foundationHashByteLength;
        byteIndex += 1
    ) {
        const difference =
            left.applicationSlotHash[byteIndex] -
            right.applicationSlotHash[byteIndex];
        if (difference !== 0) {
            return difference;
        }
    }
    return 0;
};

const reservationFromEntry = (
    entry: ProofApplicationEntry,
): ProofApplicationReservation =>
    Object.freeze({
        applicationSlotHash: entry.applicationSlotHash.slice(),
        applicationStatementSchemaIdentifier:
            entry.applicationStatementSchemaIdentifier,
        proofByteLength: entry.proofByteLength,
        verificationStarted: entry.verificationStarted,
    });

const copyReservationValue = (
    reservation: ProofApplicationReservation,
): ProofApplicationReservation =>
    Object.freeze({
        applicationSlotHash: reservation.applicationSlotHash.slice(),
        applicationStatementSchemaIdentifier:
            reservation.applicationStatementSchemaIdentifier,
        proofByteLength: reservation.proofByteLength,
        verificationStarted: reservation.verificationStarted,
    });

const snapshotFromRecord = (
    record: ProofApplicationRecord,
): ProofApplicationLedgerSnapshot =>
    Object.freeze({
        proofByteCount: record.proofByteCount,
        proofObjectCount: record.proofObjectCount,
        proofQueryCount: record.proofQueryCount,
        proofVerificationCount: record.proofVerificationCount,
        signatureVerificationCount: record.signatureVerificationCount,
    });

const requireCounterBigInt = (value: bigint, label: string): bigint => {
    if (typeof value !== 'bigint' || value < 0n || value > maximumUnsigned64) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must be an unsigned 64-bit integer.`,
        );
    }
    return value;
};

const requireCounterNumber = (value: number, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > maximumUnsigned32
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must be an unsigned 32-bit integer.`,
        );
    }
    return value;
};

const checkedBigIntAdd = (
    left: bigint,
    right: bigint,
    label: string,
): bigint => {
    const total = left + right;
    if (left < 0n || right < 0n || total > maximumUnsigned64) {
        throw resourceLimit(`${label} exceeds the unsigned 64-bit range.`);
    }
    return total;
};

const checkedNumberAdd = (
    left: number,
    right: number,
    label: string,
): number => {
    const total = left + right;
    if (
        !Number.isSafeInteger(left) ||
        !Number.isSafeInteger(right) ||
        left < 0 ||
        right < 0 ||
        total > maximumUnsigned32
    ) {
        throw resourceLimit(`${label} exceeds the unsigned 32-bit range.`);
    }
    return total;
};

const checkedByteOffsetAdd = (
    offset: number,
    byteLength: number,
    recordByteLength: number,
): number => {
    if (
        !Number.isSafeInteger(offset) ||
        !Number.isSafeInteger(byteLength) ||
        !Number.isSafeInteger(recordByteLength) ||
        offset < 0 ||
        byteLength < 0 ||
        recordByteLength < 0 ||
        offset > recordByteLength - byteLength
    ) {
        throw authenticationFailure(
            'The proof application record contains an out-of-range entry length.',
        );
    }
    return offset + byteLength;
};

const resourceLimit = (message: string): AuthenticatedRuntimeRecordError =>
    new AuthenticatedRuntimeRecordError('ResourceLimit', message);

const authenticationFailure = (
    message: string,
): AuthenticatedRuntimeRecordError =>
    new AuthenticatedRuntimeRecordError('AuthenticationFailed', message);

const destroyEntry = (entry: ProofApplicationEntry): void => {
    entry.applicationSlotHash.fill(0);
    entry.canonicalBindingBytes.fill(0);
};

const destroyEntries = (entries: ProofApplicationEntry[]): void => {
    for (const entry of entries) {
        destroyEntry(entry);
    }
};

const destroyBindingDescription = (
    description: ProofApplicationReservationBindingDescription,
): void => {
    description.actionContextHash.fill(0);
    description.applicationSlotCanonicalBytes.fill(0);
    description.applicationSlotHash.fill(0);
    description.canonicalBindingBytes.fill(0);
    description.ceremonyContextHash.fill(0);
    description.proofHeaderHash.fill(0);
    description.proofStreamDescriptorCanonicalBytes.fill(0);
    description.suiteIdentifier.fill(0);
};

export { AuthenticatedRuntimeRecordError as ProofApplicationLedgerError };
export type { AuthenticatedRuntimeRecordErrorCode as ProofApplicationLedgerErrorCode };
