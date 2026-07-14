import { sha512 } from '@noble/hashes/sha2.js';
import { canonicalJson } from '@sealed-lattice/crypto';

import {
    AuthenticatedRuntimeRecordError,
    type AuthenticatedRuntimeRecordErrorCode,
    bytesEqual,
    bytesToHex,
    copyBoundedBytes,
    copyExactBytes,
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

const recordVersion = 1;
const hashByteLength = 64;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const maximumAesGcmRandomNonceInvocationCount = 0x1_0000_0000;
const ledgerOperationDomain =
    'sealed-lattice/runtime/proof-application-ledger/v1';
const authorityLedgerKeyHashDomain =
    'sealed-lattice/runtime/proof-application-ledger-key/v1';
const applicationSlotHashDomain =
    'sealed-lattice/runtime/proof-application-slot/v1';
const operationIdentifierHashDomain =
    'sealed-lattice/runtime/proof-application-operation/v1';
const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;
const lowercaseHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseBytesPattern = /^(?:[0-9a-f]{2})+$/u;

export type DurableProofApplicationResourceCounters = Readonly<{
    proofByteCount: bigint;
    proofObjectCount: bigint;
    queryCount: bigint;
    signatureCount: bigint;
    verificationCount: bigint;
}>;

export type DurableProofApplicationResourceCeilings =
    DurableProofApplicationResourceCounters;

export type DurableProofApplicationServiceLimits = Readonly<{
    maximumApplicationSlotByteLength: number;
    maximumOperationIdentifierByteLength: number;
    maximumRecordSealingCount: number;
    resourceCeilings: DurableProofApplicationResourceCeilings;
    transactionLifetimeMilliseconds: number;
}>;

export type DurableProofApplicationReservationInput = Readonly<{
    canonicalApplicationSlotBytes: Uint8Array;
    completeProofByteLength: bigint;
    fullProofObjectDigest: Uint8Array;
    proofHeaderHash: Uint8Array;
}>;

export type DurableProofApplicationOperationCharge = Readonly<{
    canonicalOperationIdentifierBytes: Uint8Array;
    queryCount: bigint;
    signatureCount: bigint;
    verificationCount: bigint;
}>;

export type DurableProofApplicationChargeResult = Readonly<{
    disposition: 'exactReplay' | 'fresh';
    resourceCounters: DurableProofApplicationResourceCounters;
}>;

export type DurableProofApplicationReservation = Readonly<{
    chargeOperation(
        input: DurableProofApplicationOperationCharge,
    ): Promise<DurableProofApplicationChargeResult>;
    disposition: 'exactReopen' | 'fresh';
    readResourceCounters(): Promise<DurableProofApplicationResourceCounters>;
}>;

export type DurableProofApplicationService = Readonly<{
    readResourceCounters(): Promise<DurableProofApplicationResourceCounters>;
    reserve(
        input: DurableProofApplicationReservationInput,
    ): Promise<DurableProofApplicationReservation>;
}>;

export { AuthenticatedRuntimeRecordError as DurableProofApplicationServiceError };
export type DurableProofApplicationServiceErrorCode =
    AuthenticatedRuntimeRecordErrorCode;

type StoredResourceCounters = {
    proofByteCount: string;
    proofObjectCount: string;
    queryCount: string;
    signatureCount: string;
    verificationCount: string;
};

type StoredResourcePolicy = {
    maximumApplicationSlotByteLength: number;
    maximumOperationIdentifierByteLength: number;
    maximumProofByteCount: string;
    maximumProofObjectCount: string;
    maximumQueryCount: string;
    maximumSignatureCount: string;
    maximumVerificationCount: string;
};

type StoredOperationCharge = {
    canonicalOperationIdentifierHex: string;
    operationIdentifierHash: string;
    queryCount: string;
    signatureCount: string;
    verificationCount: string;
};

type StoredProofApplicationReservation = {
    applicationSlotHash: string;
    canonicalApplicationSlotHex: string;
    completeProofByteLength: string;
    fullProofObjectDigest: string;
    operations: StoredOperationCharge[];
    proofHeaderHash: string;
};

type StoredProofApplicationLedger = {
    recordVersion: number;
    reservations: StoredProofApplicationReservation[];
    resourceCounters: StoredResourceCounters;
    resourcePolicy: StoredResourcePolicy;
};

type CopiedReservationInput = Readonly<{
    applicationSlotHash: string;
    canonicalApplicationSlotBytes: Uint8Array;
    completeProofByteLength: bigint;
    fullProofObjectDigest: Uint8Array;
    proofHeaderHash: Uint8Array;
}>;

type CopiedOperationCharge = Readonly<{
    canonicalOperationIdentifierBytes: Uint8Array;
    operationIdentifierHash: string;
    queryCount: bigint;
    signatureCount: bigint;
    verificationCount: bigint;
}>;

const proofApplicationOperationTailsByStore = new WeakMap<
    UntrustedStorageTransactionStore,
    Map<string, Promise<void>>
>();

const runSerializedProofApplicationOperation = async <Value>(input: {
    logicalRecordKey: string;
    operation(): Promise<Value>;
    store: UntrustedStorageTransactionStore;
}): Promise<Value> => {
    let operationTails = proofApplicationOperationTailsByStore.get(input.store);
    if (operationTails === undefined) {
        operationTails = new Map();
        proofApplicationOperationTailsByStore.set(input.store, operationTails);
    }
    const previousTail =
        operationTails.get(input.logicalRecordKey) ?? Promise.resolve();
    const operationResult = previousTail.then(() => input.operation());
    const currentTail = operationResult.then(
        () => undefined,
        () => undefined,
    );
    operationTails.set(input.logicalRecordKey, currentTail);
    try {
        return await operationResult;
    } finally {
        if (operationTails.get(input.logicalRecordKey) === currentTail) {
            operationTails.delete(input.logicalRecordKey);
            if (operationTails.size === 0) {
                proofApplicationOperationTailsByStore.delete(input.store);
            }
        }
    }
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;

const requireExactKeys = (
    value: Record<string, unknown>,
    keys: readonly string[],
    label: string,
): void => {
    const observedKeys = Object.keys(value);
    if (
        observedKeys.length !== keys.length ||
        keys.some((key) => !(key in value))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} has the wrong fields.`,
        );
    }
};

const requireSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

const requireConfiguredUnsigned64 = (value: unknown, label: string): bigint => {
    if (typeof value !== 'bigint' || value < 0n || value > maximumUnsigned64) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            `${label} must be an unsigned-64 bigint.`,
        );
    }
    return value;
};

const requireInputUnsigned64 = (
    value: unknown,
    label: string,
    allowZero: boolean,
): bigint => {
    if (
        typeof value !== 'bigint' ||
        value < (allowZero ? 0n : 1n) ||
        value > maximumUnsigned64
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must be ${
                allowZero ? 'an' : 'a positive'
            } unsigned-64 bigint.`,
        );
    }
    return value;
};

const requireStoredUnsigned64 = (value: unknown, label: string): bigint => {
    if (
        typeof value !== 'string' ||
        !canonicalUnsignedDecimalPattern.test(value)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not a canonical unsigned-64 decimal string.`,
        );
    }
    const parsed = BigInt(value);
    if (parsed > maximumUnsigned64) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} exceeds the unsigned-64 range.`,
        );
    }
    return parsed;
};

const checkedAdd = (
    left: bigint,
    right: bigint,
    ceiling: bigint,
    label: string,
    errorCode: 'AuthenticationFailed' | 'ResourceLimit',
): bigint => {
    if (left > maximumUnsigned64 - right) {
        throw new AuthenticatedRuntimeRecordError(
            errorCode,
            `${label} exceeds the unsigned-64 range.`,
        );
    }
    const sum = left + right;
    if (sum > ceiling) {
        throw new AuthenticatedRuntimeRecordError(
            errorCode,
            `${label} exceeds its configured ceiling.`,
        );
    }
    return sum;
};

const requireHashHex = (value: unknown, label: string): string => {
    if (typeof value !== 'string' || !lowercaseHashPattern.test(value)) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not a canonical 64-byte hash.`,
        );
    }
    return value;
};

const hexToBytes = (value: string): Uint8Array => {
    const bytes = new Uint8Array(value.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const requireBoundedStoredBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    if (
        typeof value !== 'string' ||
        value.length > maximumByteLength * 2 ||
        !lowercaseBytesPattern.test(value)
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            `${label} is not nonempty bounded canonical hexadecimal.`,
        );
    }
    return hexToBytes(value);
};

const encodeCanonicalRecord = (value: unknown): Uint8Array =>
    textEncoder.encode(canonicalJson(value));

const parseCanonicalRecord = (bytes: Uint8Array): Record<string, unknown> => {
    let parsed: unknown;
    try {
        parsed = JSON.parse(fatalTextDecoder.decode(bytes));
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The proof-application ledger is not valid UTF-8 JSON.',
            error,
        );
    }
    if (
        !isPlainRecord(parsed) ||
        !bytesEqual(bytes, encodeCanonicalRecord(parsed))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The proof-application ledger is not canonical JSON.',
        );
    }
    return parsed;
};

const deriveFramedHash = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => {
    const domainBytes = textEncoder.encode(domain);
    const allParts = [domainBytes, ...parts];
    const framedByteLength = allParts.reduce(
        (total, part) => total + 8 + part.byteLength,
        8,
    );
    if (!Number.isSafeInteger(framedByteLength)) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Proof-application hash framing exceeds the safe integer range.',
        );
    }
    const framedBytes = new Uint8Array(framedByteLength);
    const view = new DataView(framedBytes.buffer);
    view.setBigUint64(0, BigInt(allParts.length), true);
    let byteOffset = 8;
    for (const part of allParts) {
        view.setBigUint64(byteOffset, BigInt(part.byteLength), true);
        byteOffset += 8;
        framedBytes.set(part, byteOffset);
        byteOffset += part.byteLength;
    }
    try {
        return sha512(framedBytes);
    } finally {
        framedBytes.fill(0);
    }
};

const deriveApplicationSlotHash = (
    canonicalApplicationSlotBytes: Uint8Array,
): string =>
    bytesToHex(
        deriveFramedHash(applicationSlotHashDomain, [
            canonicalApplicationSlotBytes,
        ]),
    );

const deriveOperationIdentifierHash = (
    applicationSlotHash: string,
    canonicalOperationIdentifierBytes: Uint8Array,
): string => {
    const applicationSlotHashBytes = hexToBytes(applicationSlotHash);
    try {
        return bytesToHex(
            deriveFramedHash(operationIdentifierHashDomain, [
                applicationSlotHashBytes,
                canonicalOperationIdentifierBytes,
            ]),
        );
    } finally {
        applicationSlotHashBytes.fill(0);
    }
};

const deriveLedgerLogicalRecordKey = (
    authorityContext: RuntimeStorageAuthorityContext,
): string => {
    const digest = deriveFramedHash(authorityLedgerKeyHashDomain, [
        authorityContext.runtimeBuildManifestHash,
        authorityContext.suiteIdentifier,
        authorityContext.ceremonyContextHash,
        authorityContext.actionContextHash,
        authorityContext.ownerParticipantIdentity,
    ]);
    try {
        return `proof-application-ledger/${bytesToHex(digest)}`;
    } finally {
        digest.fill(0);
    }
};

const copyResourceCounters = (
    counters: DurableProofApplicationResourceCounters,
): DurableProofApplicationResourceCounters =>
    Object.freeze({
        proofByteCount: counters.proofByteCount,
        proofObjectCount: counters.proofObjectCount,
        queryCount: counters.queryCount,
        signatureCount: counters.signatureCount,
        verificationCount: counters.verificationCount,
    });

const zeroResourceCounters = (): DurableProofApplicationResourceCounters =>
    copyResourceCounters({
        proofByteCount: 0n,
        proofObjectCount: 0n,
        queryCount: 0n,
        signatureCount: 0n,
        verificationCount: 0n,
    });

const storedResourceCounters = (
    counters: DurableProofApplicationResourceCounters,
): StoredResourceCounters => ({
    proofByteCount: counters.proofByteCount.toString(),
    proofObjectCount: counters.proofObjectCount.toString(),
    queryCount: counters.queryCount.toString(),
    signatureCount: counters.signatureCount.toString(),
    verificationCount: counters.verificationCount.toString(),
});

const resourcePolicyFromLimits = (
    limits: DurableProofApplicationServiceLimits,
): StoredResourcePolicy => ({
    maximumApplicationSlotByteLength: limits.maximumApplicationSlotByteLength,
    maximumOperationIdentifierByteLength:
        limits.maximumOperationIdentifierByteLength,
    maximumProofByteCount: limits.resourceCeilings.proofByteCount.toString(),
    maximumProofObjectCount:
        limits.resourceCeilings.proofObjectCount.toString(),
    maximumQueryCount: limits.resourceCeilings.queryCount.toString(),
    maximumSignatureCount: limits.resourceCeilings.signatureCount.toString(),
    maximumVerificationCount:
        limits.resourceCeilings.verificationCount.toString(),
});

const freshLedger = (
    limits: DurableProofApplicationServiceLimits,
): StoredProofApplicationLedger => ({
    recordVersion,
    reservations: [],
    resourceCounters: storedResourceCounters(zeroResourceCounters()),
    resourcePolicy: resourcePolicyFromLimits(limits),
});

const requireStoredResourcePolicy = (
    value: unknown,
    limits: DurableProofApplicationServiceLimits,
): StoredResourcePolicy => {
    if (!isPlainRecord(value)) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The stored proof-application resource policy is malformed.',
        );
    }
    requireExactKeys(
        value,
        [
            'maximumApplicationSlotByteLength',
            'maximumOperationIdentifierByteLength',
            'maximumProofByteCount',
            'maximumProofObjectCount',
            'maximumQueryCount',
            'maximumSignatureCount',
            'maximumVerificationCount',
        ],
        'The stored proof-application resource policy',
    );
    if (
        !Number.isSafeInteger(value.maximumApplicationSlotByteLength) ||
        (value.maximumApplicationSlotByteLength as number) <= 0 ||
        !Number.isSafeInteger(value.maximumOperationIdentifierByteLength) ||
        (value.maximumOperationIdentifierByteLength as number) <= 0
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The stored proof-application byte-length policy is malformed.',
        );
    }
    const policy: StoredResourcePolicy = {
        maximumApplicationSlotByteLength:
            value.maximumApplicationSlotByteLength as number,
        maximumOperationIdentifierByteLength:
            value.maximumOperationIdentifierByteLength as number,
        maximumProofByteCount: requireStoredUnsigned64(
            value.maximumProofByteCount,
            'maximumProofByteCount',
        ).toString(),
        maximumProofObjectCount: requireStoredUnsigned64(
            value.maximumProofObjectCount,
            'maximumProofObjectCount',
        ).toString(),
        maximumQueryCount: requireStoredUnsigned64(
            value.maximumQueryCount,
            'maximumQueryCount',
        ).toString(),
        maximumSignatureCount: requireStoredUnsigned64(
            value.maximumSignatureCount,
            'maximumSignatureCount',
        ).toString(),
        maximumVerificationCount: requireStoredUnsigned64(
            value.maximumVerificationCount,
            'maximumVerificationCount',
        ).toString(),
    };
    if (
        canonicalJson(policy) !==
        canonicalJson(resourcePolicyFromLimits(limits))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'Conflict',
            'The proof-application ledger was created under a different resource policy.',
        );
    }
    return policy;
};

const requireStoredResourceCounters = (
    value: unknown,
): DurableProofApplicationResourceCounters => {
    if (!isPlainRecord(value)) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The stored proof-application resource counters are malformed.',
        );
    }
    requireExactKeys(
        value,
        [
            'proofByteCount',
            'proofObjectCount',
            'queryCount',
            'signatureCount',
            'verificationCount',
        ],
        'The stored proof-application resource counters',
    );
    return copyResourceCounters({
        proofByteCount: requireStoredUnsigned64(
            value.proofByteCount,
            'proofByteCount',
        ),
        proofObjectCount: requireStoredUnsigned64(
            value.proofObjectCount,
            'proofObjectCount',
        ),
        queryCount: requireStoredUnsigned64(value.queryCount, 'queryCount'),
        signatureCount: requireStoredUnsigned64(
            value.signatureCount,
            'signatureCount',
        ),
        verificationCount: requireStoredUnsigned64(
            value.verificationCount,
            'verificationCount',
        ),
    });
};

const decodeLedger = (
    bytes: Uint8Array,
    limits: DurableProofApplicationServiceLimits,
): StoredProofApplicationLedger => {
    const value = parseCanonicalRecord(bytes);
    requireExactKeys(
        value,
        ['recordVersion', 'reservations', 'resourceCounters', 'resourcePolicy'],
        'The proof-application ledger',
    );
    if (value.recordVersion !== recordVersion) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The proof-application ledger has an unsupported version.',
        );
    }
    const resourcePolicy = requireStoredResourcePolicy(
        value.resourcePolicy,
        limits,
    );
    const resourceCounters = requireStoredResourceCounters(
        value.resourceCounters,
    );
    if (!Array.isArray(value.reservations)) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'The stored proof-application reservations are not an array.',
        );
    }

    const recomputedCounters = {
        proofByteCount: 0n,
        proofObjectCount: 0n,
        queryCount: 0n,
        signatureCount: 0n,
        verificationCount: 0n,
    };
    const reservations: StoredProofApplicationReservation[] = [];
    let previousApplicationSlotHash: string | undefined;
    for (const [
        reservationIndex,
        reservationValue,
    ] of value.reservations.entries()) {
        if (!isPlainRecord(reservationValue)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `Proof-application reservation ${reservationIndex} is malformed.`,
            );
        }
        requireExactKeys(
            reservationValue,
            [
                'applicationSlotHash',
                'canonicalApplicationSlotHex',
                'completeProofByteLength',
                'fullProofObjectDigest',
                'operations',
                'proofHeaderHash',
            ],
            `Proof-application reservation ${reservationIndex}`,
        );
        const applicationSlotHash = requireHashHex(
            reservationValue.applicationSlotHash,
            `reservation ${reservationIndex} applicationSlotHash`,
        );
        if (
            previousApplicationSlotHash !== undefined &&
            previousApplicationSlotHash >= applicationSlotHash
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Proof-application reservations are not uniquely sorted.',
            );
        }
        const canonicalApplicationSlotBytes = requireBoundedStoredBytes(
            reservationValue.canonicalApplicationSlotHex,
            resourcePolicy.maximumApplicationSlotByteLength,
            `reservation ${reservationIndex} canonicalApplicationSlotHex`,
        );
        const recomputedApplicationSlotHash = deriveApplicationSlotHash(
            canonicalApplicationSlotBytes,
        );
        canonicalApplicationSlotBytes.fill(0);
        if (applicationSlotHash !== recomputedApplicationSlotHash) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'A proof-application slot hash does not match its canonical bytes.',
            );
        }
        const completeProofByteLength = requireStoredUnsigned64(
            reservationValue.completeProofByteLength,
            `reservation ${reservationIndex} completeProofByteLength`,
        );
        if (completeProofByteLength === 0n) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'A stored proof application has an empty proof object.',
            );
        }
        const fullProofObjectDigest = requireHashHex(
            reservationValue.fullProofObjectDigest,
            `reservation ${reservationIndex} fullProofObjectDigest`,
        );
        const proofHeaderHash = requireHashHex(
            reservationValue.proofHeaderHash,
            `reservation ${reservationIndex} proofHeaderHash`,
        );
        if (!Array.isArray(reservationValue.operations)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'A stored proof-application operation list is malformed.',
            );
        }

        recomputedCounters.proofObjectCount = checkedAdd(
            recomputedCounters.proofObjectCount,
            1n,
            limits.resourceCeilings.proofObjectCount,
            'Stored proof-object count',
            'AuthenticationFailed',
        );
        recomputedCounters.proofByteCount = checkedAdd(
            recomputedCounters.proofByteCount,
            completeProofByteLength,
            limits.resourceCeilings.proofByteCount,
            'Stored proof-byte count',
            'AuthenticationFailed',
        );

        const operations: StoredOperationCharge[] = [];
        let previousOperationIdentifierHash: string | undefined;
        for (const [
            operationIndex,
            operationValue,
        ] of reservationValue.operations.entries()) {
            if (!isPlainRecord(operationValue)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    `Proof-application operation ${operationIndex} is malformed.`,
                );
            }
            requireExactKeys(
                operationValue,
                [
                    'canonicalOperationIdentifierHex',
                    'operationIdentifierHash',
                    'queryCount',
                    'signatureCount',
                    'verificationCount',
                ],
                `Proof-application operation ${operationIndex}`,
            );
            const operationIdentifierHash = requireHashHex(
                operationValue.operationIdentifierHash,
                `operation ${operationIndex} operationIdentifierHash`,
            );
            if (
                previousOperationIdentifierHash !== undefined &&
                previousOperationIdentifierHash >= operationIdentifierHash
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Proof-application operations are not uniquely sorted.',
                );
            }
            const canonicalOperationIdentifierBytes = requireBoundedStoredBytes(
                operationValue.canonicalOperationIdentifierHex,
                resourcePolicy.maximumOperationIdentifierByteLength,
                `operation ${operationIndex} canonicalOperationIdentifierHex`,
            );
            const recomputedOperationIdentifierHash =
                deriveOperationIdentifierHash(
                    applicationSlotHash,
                    canonicalOperationIdentifierBytes,
                );
            canonicalOperationIdentifierBytes.fill(0);
            if (operationIdentifierHash !== recomputedOperationIdentifierHash) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'A proof-application operation hash does not match its canonical identifier.',
                );
            }
            const queryCount = requireStoredUnsigned64(
                operationValue.queryCount,
                `operation ${operationIndex} queryCount`,
            );
            const signatureCount = requireStoredUnsigned64(
                operationValue.signatureCount,
                `operation ${operationIndex} signatureCount`,
            );
            const verificationCount = requireStoredUnsigned64(
                operationValue.verificationCount,
                `operation ${operationIndex} verificationCount`,
            );
            if (
                queryCount === 0n &&
                signatureCount === 0n &&
                verificationCount === 0n
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'A stored proof-application operation has no resource charge.',
                );
            }
            recomputedCounters.queryCount = checkedAdd(
                recomputedCounters.queryCount,
                queryCount,
                limits.resourceCeilings.queryCount,
                'Stored query count',
                'AuthenticationFailed',
            );
            recomputedCounters.signatureCount = checkedAdd(
                recomputedCounters.signatureCount,
                signatureCount,
                limits.resourceCeilings.signatureCount,
                'Stored signature count',
                'AuthenticationFailed',
            );
            recomputedCounters.verificationCount = checkedAdd(
                recomputedCounters.verificationCount,
                verificationCount,
                limits.resourceCeilings.verificationCount,
                'Stored verification count',
                'AuthenticationFailed',
            );
            operations.push({
                canonicalOperationIdentifierHex:
                    operationValue.canonicalOperationIdentifierHex as string,
                operationIdentifierHash,
                queryCount: queryCount.toString(),
                signatureCount: signatureCount.toString(),
                verificationCount: verificationCount.toString(),
            });
            previousOperationIdentifierHash = operationIdentifierHash;
        }
        reservations.push({
            applicationSlotHash,
            canonicalApplicationSlotHex:
                reservationValue.canonicalApplicationSlotHex as string,
            completeProofByteLength: completeProofByteLength.toString(),
            fullProofObjectDigest,
            operations,
            proofHeaderHash,
        });
        previousApplicationSlotHash = applicationSlotHash;
    }

    if (
        recomputedCounters.proofByteCount !== resourceCounters.proofByteCount ||
        recomputedCounters.proofObjectCount !==
            resourceCounters.proofObjectCount ||
        recomputedCounters.queryCount !== resourceCounters.queryCount ||
        recomputedCounters.signatureCount !== resourceCounters.signatureCount ||
        recomputedCounters.verificationCount !==
            resourceCounters.verificationCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Stored proof-application counters do not match the recomputed ledger.',
        );
    }

    return {
        recordVersion,
        reservations,
        resourceCounters: storedResourceCounters(resourceCounters),
        resourcePolicy,
    };
};

const countersFromLedger = (
    ledger: StoredProofApplicationLedger,
): DurableProofApplicationResourceCounters =>
    copyResourceCounters({
        proofByteCount: BigInt(ledger.resourceCounters.proofByteCount),
        proofObjectCount: BigInt(ledger.resourceCounters.proofObjectCount),
        queryCount: BigInt(ledger.resourceCounters.queryCount),
        signatureCount: BigInt(ledger.resourceCounters.signatureCount),
        verificationCount: BigInt(ledger.resourceCounters.verificationCount),
    });

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
            'A proof-application ledger transaction failed and could not release its ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const copyReservationInput = (
    input: DurableProofApplicationReservationInput,
    limits: DurableProofApplicationServiceLimits,
): CopiedReservationInput => {
    const canonicalApplicationSlotBytes = copyBoundedBytes(
        input.canonicalApplicationSlotBytes,
        limits.maximumApplicationSlotByteLength,
        'canonicalApplicationSlotBytes',
    );
    return Object.freeze({
        applicationSlotHash: deriveApplicationSlotHash(
            canonicalApplicationSlotBytes,
        ),
        canonicalApplicationSlotBytes,
        completeProofByteLength: requireInputUnsigned64(
            input.completeProofByteLength,
            'completeProofByteLength',
            false,
        ),
        fullProofObjectDigest: copyExactBytes(
            input.fullProofObjectDigest,
            hashByteLength,
            'fullProofObjectDigest',
        ),
        proofHeaderHash: copyExactBytes(
            input.proofHeaderHash,
            hashByteLength,
            'proofHeaderHash',
        ),
    });
};

const destroyCopiedReservationInput = (input: CopiedReservationInput): void => {
    input.canonicalApplicationSlotBytes.fill(0);
    input.fullProofObjectDigest.fill(0);
    input.proofHeaderHash.fill(0);
};

const copyOperationCharge = (
    input: DurableProofApplicationOperationCharge,
    applicationSlotHash: string,
    limits: DurableProofApplicationServiceLimits,
): CopiedOperationCharge => {
    const canonicalOperationIdentifierBytes = copyBoundedBytes(
        input.canonicalOperationIdentifierBytes,
        limits.maximumOperationIdentifierByteLength,
        'canonicalOperationIdentifierBytes',
    );
    const queryCount = requireInputUnsigned64(
        input.queryCount,
        'queryCount',
        true,
    );
    const signatureCount = requireInputUnsigned64(
        input.signatureCount,
        'signatureCount',
        true,
    );
    const verificationCount = requireInputUnsigned64(
        input.verificationCount,
        'verificationCount',
        true,
    );
    if (
        queryCount === 0n &&
        signatureCount === 0n &&
        verificationCount === 0n
    ) {
        canonicalOperationIdentifierBytes.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'A proof-application operation must charge at least one resource.',
        );
    }
    return Object.freeze({
        canonicalOperationIdentifierBytes,
        operationIdentifierHash: deriveOperationIdentifierHash(
            applicationSlotHash,
            canonicalOperationIdentifierBytes,
        ),
        queryCount,
        signatureCount,
        verificationCount,
    });
};

const reservationMatches = (
    stored: StoredProofApplicationReservation,
    expected: CopiedReservationInput,
): boolean =>
    stored.canonicalApplicationSlotHex ===
        bytesToHex(expected.canonicalApplicationSlotBytes) &&
    stored.completeProofByteLength ===
        expected.completeProofByteLength.toString() &&
    stored.fullProofObjectDigest ===
        bytesToHex(expected.fullProofObjectDigest) &&
    stored.proofHeaderHash === bytesToHex(expected.proofHeaderHash);

const operationMatches = (
    stored: StoredOperationCharge,
    expected: CopiedOperationCharge,
): boolean =>
    stored.canonicalOperationIdentifierHex ===
        bytesToHex(expected.canonicalOperationIdentifierBytes) &&
    stored.queryCount === expected.queryCount.toString() &&
    stored.signatureCount === expected.signatureCount.toString() &&
    stored.verificationCount === expected.verificationCount.toString();

export const openDurableProofApplicationService = (input: {
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    limits: DurableProofApplicationServiceLimits;
    store: UntrustedStorageTransactionStore;
}): DurableProofApplicationService => {
    requireSafePositiveInteger(
        input.limits.maximumApplicationSlotByteLength,
        'maximumApplicationSlotByteLength',
    );
    requireSafePositiveInteger(
        input.limits.maximumOperationIdentifierByteLength,
        'maximumOperationIdentifierByteLength',
    );
    requireSafePositiveInteger(
        input.limits.maximumRecordSealingCount,
        'maximumRecordSealingCount',
    );
    if (
        input.limits.maximumRecordSealingCount >
        maximumAesGcmRandomNonceInvocationCount
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'maximumRecordSealingCount exceeds the AES-GCM random-nonce invocation ceiling.',
        );
    }
    requireSafePositiveInteger(
        input.limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    const resourceCeilings = Object.freeze({
        proofByteCount: requireConfiguredUnsigned64(
            input.limits.resourceCeilings.proofByteCount,
            'resourceCeilings.proofByteCount',
        ),
        proofObjectCount: requireConfiguredUnsigned64(
            input.limits.resourceCeilings.proofObjectCount,
            'resourceCeilings.proofObjectCount',
        ),
        queryCount: requireConfiguredUnsigned64(
            input.limits.resourceCeilings.queryCount,
            'resourceCeilings.queryCount',
        ),
        signatureCount: requireConfiguredUnsigned64(
            input.limits.resourceCeilings.signatureCount,
            'resourceCeilings.signatureCount',
        ),
        verificationCount: requireConfiguredUnsigned64(
            input.limits.resourceCeilings.verificationCount,
            'resourceCeilings.verificationCount',
        ),
    });
    const limits = Object.freeze({
        maximumApplicationSlotByteLength:
            input.limits.maximumApplicationSlotByteLength,
        maximumOperationIdentifierByteLength:
            input.limits.maximumOperationIdentifierByteLength,
        maximumRecordSealingCount: input.limits.maximumRecordSealingCount,
        resourceCeilings,
        transactionLifetimeMilliseconds:
            input.limits.transactionLifetimeMilliseconds,
    });
    const protection = createRuntimeRecordProtection({
        authorityContext: input.authorityContext,
        ...(input.cryptoProvider === undefined
            ? {}
            : { cryptoProvider: input.cryptoProvider }),
        encryptionKey: input.encryptionKey,
    });
    const logicalRecordKey = deriveLedgerLogicalRecordKey(
        protection.authorityContext,
    );
    const issuedNonces = new Set<string>();

    const readLedger = async (): Promise<{
        ledger: StoredProofApplicationLedger;
        sealedBytes: Uint8Array | null;
    }> => {
        const opened = await readRuntimeRecord({
            logicalRecordKey,
            operationDomain: ledgerOperationDomain,
            protection,
            store: input.store,
        });
        if (opened === undefined) {
            return { ledger: freshLedger(limits), sealedBytes: null };
        }
        try {
            return {
                ledger: decodeLedger(opened.plaintext, limits),
                sealedBytes: opened.sealedBytes,
            };
        } finally {
            opened.plaintext.fill(0);
        }
    };

    const writeLedger = async (
        ledger: StoredProofApplicationLedger,
        expectedCurrentSealedBytes: Uint8Array | null,
    ): Promise<void> => {
        const plaintext = encodeCanonicalRecord(ledger);
        const transaction = await input.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes,
                issuedNonces,
                logicalRecordKey,
                maximumRecordSealingCount: limits.maximumRecordSealingCount,
                operationDomain: ledgerOperationDomain,
                plaintext,
                protection,
                transaction,
            });
            await transaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        } finally {
            plaintext.fill(0);
        }
    };

    const readResourceCounters =
        async (): Promise<DurableProofApplicationResourceCounters> =>
            runSerializedProofApplicationOperation({
                logicalRecordKey,
                operation: async () => {
                    const { ledger } = await readLedger();
                    return countersFromLedger(ledger);
                },
                store: input.store,
            });

    const createReservationHandle = (
        copiedReservation: CopiedReservationInput,
        disposition: DurableProofApplicationReservation['disposition'],
    ): DurableProofApplicationReservation => {
        const chargeOperation: DurableProofApplicationReservation['chargeOperation'] =
            async (operationInput) => {
                const copiedOperation = copyOperationCharge(
                    operationInput,
                    copiedReservation.applicationSlotHash,
                    limits,
                );
                try {
                    return await runSerializedProofApplicationOperation({
                        logicalRecordKey,
                        operation: async () => {
                            const { ledger, sealedBytes } = await readLedger();
                            const reservation = ledger.reservations.find(
                                (candidate) =>
                                    candidate.applicationSlotHash ===
                                    copiedReservation.applicationSlotHash,
                            );
                            if (
                                reservation === undefined ||
                                !reservationMatches(
                                    reservation,
                                    copiedReservation,
                                )
                            ) {
                                throw new AuthenticatedRuntimeRecordError(
                                    'Conflict',
                                    'The proof-application reservation no longer matches its exact binding.',
                                );
                            }
                            const existingOperation =
                                reservation.operations.find(
                                    (candidate) =>
                                        candidate.operationIdentifierHash ===
                                        copiedOperation.operationIdentifierHash,
                                );
                            if (existingOperation !== undefined) {
                                if (
                                    !operationMatches(
                                        existingOperation,
                                        copiedOperation,
                                    )
                                ) {
                                    throw new AuthenticatedRuntimeRecordError(
                                        'Conflict',
                                        'The operation identifier is already bound to a different resource charge.',
                                    );
                                }
                                return Object.freeze({
                                    disposition: 'exactReplay' as const,
                                    resourceCounters:
                                        countersFromLedger(ledger),
                                });
                            }

                            const currentCounters = countersFromLedger(ledger);
                            const nextCounters = copyResourceCounters({
                                proofByteCount: currentCounters.proofByteCount,
                                proofObjectCount:
                                    currentCounters.proofObjectCount,
                                queryCount: checkedAdd(
                                    currentCounters.queryCount,
                                    copiedOperation.queryCount,
                                    limits.resourceCeilings.queryCount,
                                    'Query count',
                                    'ResourceLimit',
                                ),
                                signatureCount: checkedAdd(
                                    currentCounters.signatureCount,
                                    copiedOperation.signatureCount,
                                    limits.resourceCeilings.signatureCount,
                                    'Signature count',
                                    'ResourceLimit',
                                ),
                                verificationCount: checkedAdd(
                                    currentCounters.verificationCount,
                                    copiedOperation.verificationCount,
                                    limits.resourceCeilings.verificationCount,
                                    'Verification count',
                                    'ResourceLimit',
                                ),
                            });
                            reservation.operations.push({
                                canonicalOperationIdentifierHex: bytesToHex(
                                    copiedOperation.canonicalOperationIdentifierBytes,
                                ),
                                operationIdentifierHash:
                                    copiedOperation.operationIdentifierHash,
                                queryCount:
                                    copiedOperation.queryCount.toString(),
                                signatureCount:
                                    copiedOperation.signatureCount.toString(),
                                verificationCount:
                                    copiedOperation.verificationCount.toString(),
                            });
                            reservation.operations.sort((left, right) =>
                                left.operationIdentifierHash.localeCompare(
                                    right.operationIdentifierHash,
                                ),
                            );
                            ledger.resourceCounters =
                                storedResourceCounters(nextCounters);
                            await writeLedger(ledger, sealedBytes);
                            return Object.freeze({
                                disposition: 'fresh' as const,
                                resourceCounters: nextCounters,
                            });
                        },
                        store: input.store,
                    });
                } finally {
                    copiedOperation.canonicalOperationIdentifierBytes.fill(0);
                }
            };

        return Object.freeze({
            chargeOperation,
            disposition,
            readResourceCounters,
        });
    };

    const reserve: DurableProofApplicationService['reserve'] = async (
        reservationInput,
    ) => {
        const copiedReservation = copyReservationInput(
            reservationInput,
            limits,
        );
        try {
            return await runSerializedProofApplicationOperation({
                logicalRecordKey,
                operation: async () => {
                    const { ledger, sealedBytes } = await readLedger();
                    const existingReservation = ledger.reservations.find(
                        (candidate) =>
                            candidate.applicationSlotHash ===
                            copiedReservation.applicationSlotHash,
                    );
                    if (existingReservation !== undefined) {
                        if (
                            !reservationMatches(
                                existingReservation,
                                copiedReservation,
                            )
                        ) {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'The application slot is already bound to a different proof header, byte length, or full-object digest.',
                            );
                        }
                        return createReservationHandle(
                            copiedReservation,
                            'exactReopen',
                        );
                    }

                    const currentCounters = countersFromLedger(ledger);
                    const nextCounters = copyResourceCounters({
                        proofByteCount: checkedAdd(
                            currentCounters.proofByteCount,
                            copiedReservation.completeProofByteLength,
                            limits.resourceCeilings.proofByteCount,
                            'Proof-byte count',
                            'ResourceLimit',
                        ),
                        proofObjectCount: checkedAdd(
                            currentCounters.proofObjectCount,
                            1n,
                            limits.resourceCeilings.proofObjectCount,
                            'Proof-object count',
                            'ResourceLimit',
                        ),
                        queryCount: currentCounters.queryCount,
                        signatureCount: currentCounters.signatureCount,
                        verificationCount: currentCounters.verificationCount,
                    });
                    ledger.reservations.push({
                        applicationSlotHash:
                            copiedReservation.applicationSlotHash,
                        canonicalApplicationSlotHex: bytesToHex(
                            copiedReservation.canonicalApplicationSlotBytes,
                        ),
                        completeProofByteLength:
                            copiedReservation.completeProofByteLength.toString(),
                        fullProofObjectDigest: bytesToHex(
                            copiedReservation.fullProofObjectDigest,
                        ),
                        operations: [],
                        proofHeaderHash: bytesToHex(
                            copiedReservation.proofHeaderHash,
                        ),
                    });
                    ledger.reservations.sort((left, right) =>
                        left.applicationSlotHash.localeCompare(
                            right.applicationSlotHash,
                        ),
                    );
                    ledger.resourceCounters =
                        storedResourceCounters(nextCounters);
                    await writeLedger(ledger, sealedBytes);
                    return createReservationHandle(copiedReservation, 'fresh');
                },
                store: input.store,
            });
        } catch (error) {
            destroyCopiedReservationInput(copiedReservation);
            throw error;
        }
    };

    return Object.freeze({ readResourceCounters, reserve });
};
