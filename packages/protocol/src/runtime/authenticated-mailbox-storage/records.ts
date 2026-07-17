import { sha512 } from '@noble/hashes/sha2.js';
import type {
    AuthenticatedMailboxCarrier,
    AuthenticatedMailboxInboundSlotAuthority,
    AuthenticatedMailboxOutboundCache,
    AuthenticatedMailboxProducerSlot,
    AuthenticatedMailboxStagingBoundary,
} from '@sealed-lattice/crypto';
import {
    foundationProfile,
    isProtocolHash,
    type ProtocolHash,
} from '@sealed-lattice/types';

import {
    bytesEqual,
    bytesToHex,
    mapStorageError,
    type RuntimeStorageAuthorityContext,
} from '../authenticated-runtime-record.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from '../untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
export const recordVersion = 1;
const maximumAesGcmRandomNonceInvocationCount = 0x1_0000_0000;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const participantIdentityPattern = /^[0-9a-f]{128}$/u;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;
const publicationIdentifierPattern = /^[0-9a-f]{64}$/u;
const chunkDigestPattern = /^[0-9a-f]{128}$/u;

export const outboundJournalOperationDomain =
    'sealed-lattice/authenticated-mailbox/outbound-journal/v1';
export const outboundManifestOperationDomain =
    'sealed-lattice/authenticated-mailbox/outbound-manifest/v1';
export const outboundChunkOperationDomain =
    'sealed-lattice/authenticated-mailbox/outbound-chunk/v1';
export const inboundSlotOperationDomain =
    'sealed-lattice/authenticated-mailbox/inbound-slot/v1';
export const stagingJournalOperationDomain =
    'sealed-lattice/authenticated-mailbox/staging-journal/v1';
export const stagingManifestOperationDomain =
    'sealed-lattice/authenticated-mailbox/staging-manifest/v1';
export const stagingChunkOperationDomain =
    'sealed-lattice/authenticated-mailbox/staging-chunk/v1';
export type AuthenticatedMailboxStorageLimits = Readonly<{
    maximumCarrierByteLength: number;
    maximumMailboxByteLength: number;
    maximumRecordSealingCount: number;
    transactionLifetimeMilliseconds: number;
}>;

export type AuthenticatedMailboxStorageErrorCode =
    | 'AuthenticationFailed'
    | 'CleanupFailed'
    | 'Conflict'
    | 'EntropyFailure'
    | 'Equivocation'
    | 'InvalidConfiguration'
    | 'InvalidInput'
    | 'InvalidState'
    | 'ResourceLimit'
    | 'StorageFailure';

export class AuthenticatedMailboxStorageError extends Error {
    public readonly code: AuthenticatedMailboxStorageErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: AuthenticatedMailboxStorageErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'AuthenticatedMailboxStorageError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

export type BrowserLocalAuthenticatedMailboxStorage = Readonly<{
    inboundSlotAuthority: AuthenticatedMailboxInboundSlotAuthority;
    outboundCache: AuthenticatedMailboxOutboundCache;
    stagingBoundary: AuthenticatedMailboxStagingBoundary;
}>;

export type BrowserLocalAuthenticatedMailboxStorageConfiguration = Readonly<{
    authorityContext: RuntimeStorageAuthorityContext;
    cryptoProvider?: Crypto;
    encryptionKey: CryptoKey;
    limits: AuthenticatedMailboxStorageLimits;
    store: UntrustedStorageTransactionStore;
}>;

type StoredProducerSlot = Readonly<{
    actionContextHash: ProtocolHash;
    ceremonyContextHash: ProtocolHash;
    payloadType: 2;
    producerSequence: string;
    recipientParticipantId: string;
    rosterHash: ProtocolHash;
    sourceParticipantId: string;
    suiteId: ProtocolHash;
}>;

export type StoredStreamJournal = Readonly<{
    producerSlot?: StoredProducerSlot;
    envelopeHash?: ProtocolHash;
    publicationIdentifier: string;
    recordVersion: number;
    totalByteLength: number;
}>;

export type StoredChunkDescriptor = Readonly<{
    digest: string;
}>;

export type StoredOutboundManifest = Readonly<{
    canonicalEnvelopeHex: string;
    chunkDescriptors: readonly StoredChunkDescriptor[];
    plaintextByteLength: number;
    producerSlot: StoredProducerSlot;
    publicationIdentifier: string;
    recordVersion: number;
}>;

export type StoredStagingManifest = Readonly<{
    chunkDescriptors: readonly StoredChunkDescriptor[];
    envelopeHash: ProtocolHash;
    publicationIdentifier: string;
    recordVersion: number;
    totalByteLength: number;
}>;

export type StoredInboundSlot = Readonly<{
    canonicalEnvelopeHex: string;
    producerSlot: StoredProducerSlot;
    recordVersion: number;
}>;

export type OpenedStoredRecord<RecordValue> = Readonly<{
    record: RecordValue;
    sealedBytes: Uint8Array;
}>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (
    value: Record<string, unknown>,
    expectedKeys: readonly string[],
): boolean => {
    const keys = Object.keys(value);

    return (
        keys.length === expectedKeys.length &&
        keys.every((key, index) => key === expectedKeys[index])
    );
};

const assertSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

export const validateLimits = (
    limits: AuthenticatedMailboxStorageLimits,
): AuthenticatedMailboxStorageLimits => {
    assertSafePositiveInteger(
        limits.maximumCarrierByteLength,
        'maximumCarrierByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumMailboxByteLength,
        'maximumMailboxByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumRecordSealingCount,
        'maximumRecordSealingCount',
    );
    assertSafePositiveInteger(
        limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    if (
        limits.maximumMailboxByteLength >
        foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidConfiguration',
            'maximumMailboxByteLength exceeds the supported mailbox profile.',
        );
    }
    if (
        limits.maximumRecordSealingCount >
        maximumAesGcmRandomNonceInvocationCount
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidConfiguration',
            'maximumRecordSealingCount exceeds the AES-GCM random-nonce invocation ceiling.',
        );
    }

    return Object.freeze({ ...limits });
};

export const asStorageError = (
    error: unknown,
): AuthenticatedMailboxStorageError => {
    if (error instanceof AuthenticatedMailboxStorageError) {
        return error;
    }
    const mapped = mapStorageError(error);
    const code: AuthenticatedMailboxStorageErrorCode =
        mapped.code === 'MissingRecord' ? 'AuthenticationFailed' : mapped.code;

    return new AuthenticatedMailboxStorageError(
        code,
        mapped.message,
        mapped.failureCause ?? error,
    );
};

export const cleanupError = (
    message: string,
    failures: readonly unknown[],
): AuthenticatedMailboxStorageError =>
    new AuthenticatedMailboxStorageError(
        'CleanupFailed',
        message,
        failures.map(asStorageError),
    );

const encodeCanonicalJson = (value: unknown): Uint8Array =>
    textEncoder.encode(JSON.stringify(value));

const decodeCanonicalJson = (bytes: Uint8Array): unknown => {
    let value: unknown;
    try {
        value = JSON.parse(fatalTextDecoder.decode(bytes));
    } catch (error) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'An authenticated mailbox storage record is not valid JSON.',
            error,
        );
    }
    if (!bytesEqual(bytes, encodeCanonicalJson(value))) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'An authenticated mailbox storage record is not canonically encoded.',
        );
    }

    return value;
};

export const requireProtocolHash = (
    value: unknown,
    label: string,
): ProtocolHash => {
    if (!isProtocolHash(value)) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            `${label} must be a canonical 64-byte protocol hash.`,
        );
    }

    return value;
};

const requireParticipantIdentity = (value: unknown, label: string): string => {
    if (typeof value !== 'string' || !participantIdentityPattern.test(value)) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            `${label} must be a canonical participant identity.`,
        );
    }

    return value;
};

const requirePublicationIdentifier = (
    value: unknown,
    label: string,
): string => {
    if (
        typeof value !== 'string' ||
        !publicationIdentifierPattern.test(value)
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            `${label} is not a canonical publication identifier.`,
        );
    }

    return value;
};

const requireCanonicalEnvelopeHex = (
    value: unknown,
    maximumCarrierByteLength: number,
): string => {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length % 2 !== 0 ||
        value.length / 2 > maximumCarrierByteLength ||
        !/^[0-9a-f]+$/u.test(value)
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored canonical mailbox envelope bytes have an invalid encoding or length.',
        );
    }

    return value;
};

export const hexToBytes = (value: string): Uint8Array => {
    const bytes = new Uint8Array(value.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const validateStreamShape = (
    totalByteLength: number,
    chunkCount: number,
    limits: AuthenticatedMailboxStorageLimits,
): void => {
    if (
        !Number.isSafeInteger(totalByteLength) ||
        totalByteLength <= 0 ||
        totalByteLength > limits.maximumMailboxByteLength
    ) {
        throw new AuthenticatedMailboxStorageError(
            'ResourceLimit',
            'Mailbox stream byte length is outside the configured profile.',
        );
    }
    const expectedChunkCount = Math.ceil(
        totalByteLength / foundationProfile.streamChunkByteLength,
    );
    if (
        !Number.isSafeInteger(chunkCount) ||
        chunkCount <= 0 ||
        chunkCount !== expectedChunkCount
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            'Mailbox stream chunk count does not match its exact byte length.',
        );
    }
};

export const streamChunkCount = (
    totalByteLength: number,
    limits: AuthenticatedMailboxStorageLimits,
): number => {
    const chunkCount = Math.ceil(
        totalByteLength / foundationProfile.streamChunkByteLength,
    );
    validateStreamShape(totalByteLength, chunkCount, limits);
    return chunkCount;
};

export const expectedChunkByteLength = (
    totalByteLength: number,
    chunkCount: number,
    chunkIndex: number,
): number =>
    chunkIndex + 1 < chunkCount
        ? foundationProfile.streamChunkByteLength
        : totalByteLength -
          (chunkCount - 1) * foundationProfile.streamChunkByteLength;

export const requireArrayBuffer = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (
        Object.prototype.toString.call(value) !== '[object ArrayBuffer]' ||
        !(value instanceof ArrayBuffer) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            `${label} must be an ArrayBuffer containing exactly ${String(expectedByteLength)} bytes.`,
        );
    }

    return new Uint8Array(value).slice();
};

export const throwIfAborted = (abortSignal: AbortSignal | undefined): void => {
    if (abortSignal?.aborted === true) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidState',
            'The authenticated mailbox storage operation was cancelled.',
        );
    }
};

const decodeProducerSlot = (value: unknown): StoredProducerSlot => {
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'actionContextHash',
            'ceremonyContextHash',
            'payloadType',
            'producerSequence',
            'recipientParticipantId',
            'rosterHash',
            'sourceParticipantId',
            'suiteId',
        ])
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox producer slot has a noncanonical shape.',
        );
    }
    if (value.payloadType !== 2) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox payload type is unsupported.',
        );
    }
    if (
        typeof value.producerSequence !== 'string' ||
        value.producerSequence.length > 20 ||
        !canonicalUnsignedDecimalPattern.test(value.producerSequence) ||
        BigInt(value.producerSequence) > maximumUnsigned64
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox producer sequence is not canonical.',
        );
    }

    return Object.freeze({
        actionContextHash: requireProtocolHash(
            value.actionContextHash,
            'actionContextHash',
        ),
        ceremonyContextHash: requireProtocolHash(
            value.ceremonyContextHash,
            'ceremonyContextHash',
        ),
        payloadType: value.payloadType,
        producerSequence: value.producerSequence,
        recipientParticipantId: requireParticipantIdentity(
            value.recipientParticipantId,
            'recipientParticipantId',
        ),
        rosterHash: requireProtocolHash(value.rosterHash, 'rosterHash'),
        sourceParticipantId: requireParticipantIdentity(
            value.sourceParticipantId,
            'sourceParticipantId',
        ),
        suiteId: requireProtocolHash(value.suiteId, 'suiteId'),
    });
};

export const normalizeProducerSlot = (
    value: AuthenticatedMailboxProducerSlot,
): StoredProducerSlot => {
    const canonicalValue = {
        actionContextHash: value.actionContextHash,
        ceremonyContextHash: value.ceremonyContextHash,
        payloadType: value.payloadType,
        producerSequence: value.producerSequence,
        recipientParticipantId: value.recipientParticipantId,
        rosterHash: value.rosterHash,
        sourceParticipantId: value.sourceParticipantId,
        suiteId: value.suiteId,
    };
    try {
        return decodeProducerSlot(canonicalValue);
    } catch (error) {
        const mapped = asStorageError(error);
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            mapped.message,
            mapped,
        );
    }
};

export const producerSlotsEqual = (
    left: StoredProducerSlot,
    right: StoredProducerSlot,
): boolean => JSON.stringify(left) === JSON.stringify(right);

export const producerSlotFingerprint = (
    producerSlot: StoredProducerSlot,
): string => bytesToHex(sha512(encodeCanonicalJson(producerSlot)));

export const validateProducerSlotAuthority = (input: {
    direction: 'inbound' | 'outbound';
    producerSlot: StoredProducerSlot;
    authorityContext: RuntimeStorageAuthorityContext;
}): void => {
    const { authorityContext, producerSlot } = input;
    const expectedOwnerParticipantIdentity =
        input.direction === 'outbound'
            ? producerSlot.sourceParticipantId
            : producerSlot.recipientParticipantId;
    if (
        producerSlot.suiteId !== bytesToHex(authorityContext.suiteIdentifier) ||
        producerSlot.ceremonyContextHash !==
            bytesToHex(authorityContext.ceremonyContextHash) ||
        producerSlot.actionContextHash !==
            bytesToHex(authorityContext.actionContextHash) ||
        expectedOwnerParticipantIdentity !==
            bytesToHex(authorityContext.ownerParticipantIdentity)
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            'Mailbox producer slot does not belong to this browser-local storage authority.',
        );
    }
};

export const deriveChunkDigest = (bytes: Uint8Array): string =>
    bytesToHex(sha512(bytes));

const decodeChunkDescriptors = (
    value: unknown,
    totalByteLength: number,
    limits: AuthenticatedMailboxStorageLimits,
): readonly StoredChunkDescriptor[] => {
    if (!Array.isArray(value)) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox chunk descriptors are not an array.',
        );
    }
    validateStreamShape(totalByteLength, value.length, limits);

    return Object.freeze(
        value.map((descriptor, chunkIndex) => {
            if (
                !isRecord(descriptor) ||
                !hasExactKeys(descriptor, ['digest']) ||
                typeof descriptor.digest !== 'string' ||
                !chunkDigestPattern.test(descriptor.digest)
            ) {
                throw new AuthenticatedMailboxStorageError(
                    'AuthenticationFailed',
                    `Stored mailbox chunk descriptor ${String(chunkIndex)} is invalid.`,
                );
            }

            return Object.freeze({
                digest: descriptor.digest,
            });
        }),
    );
};

export const decodeStreamJournal = (
    bytes: Uint8Array,
    kind: 'outbound' | 'staging',
    limits: AuthenticatedMailboxStorageLimits,
): StoredStreamJournal => {
    const value = decodeCanonicalJson(bytes);
    const expectedKeys =
        kind === 'outbound'
            ? [
                  'producerSlot',
                  'publicationIdentifier',
                  'recordVersion',
                  'totalByteLength',
              ]
            : [
                  'envelopeHash',
                  'publicationIdentifier',
                  'recordVersion',
                  'totalByteLength',
              ];
    if (!isRecord(value) || !hasExactKeys(value, expectedKeys)) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox stream journal has a noncanonical shape.',
        );
    }
    if (value.recordVersion !== recordVersion) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox stream journal has an unsupported version.',
        );
    }
    if (typeof value.totalByteLength !== 'number') {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox stream journal lengths are invalid.',
        );
    }
    streamChunkCount(value.totalByteLength, limits);

    return Object.freeze({
        ...(kind === 'outbound'
            ? { producerSlot: decodeProducerSlot(value.producerSlot) }
            : {
                  envelopeHash: requireProtocolHash(
                      value.envelopeHash,
                      'envelopeHash',
                  ),
              }),
        publicationIdentifier: requirePublicationIdentifier(
            value.publicationIdentifier,
            'publicationIdentifier',
        ),
        recordVersion,
        totalByteLength: value.totalByteLength,
    });
};

export const encodeStreamJournal = (journal: StoredStreamJournal): Uint8Array =>
    encodeCanonicalJson(
        journal.producerSlot === undefined
            ? {
                  envelopeHash: journal.envelopeHash,
                  publicationIdentifier: journal.publicationIdentifier,
                  recordVersion,
                  totalByteLength: journal.totalByteLength,
              }
            : {
                  producerSlot: journal.producerSlot,
                  publicationIdentifier: journal.publicationIdentifier,
                  recordVersion,
                  totalByteLength: journal.totalByteLength,
              },
    );

export const decodeOutboundManifest = (
    bytes: Uint8Array,
    limits: AuthenticatedMailboxStorageLimits,
): StoredOutboundManifest => {
    const value = decodeCanonicalJson(bytes);
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'canonicalEnvelopeHex',
            'chunkDescriptors',
            'plaintextByteLength',
            'producerSlot',
            'publicationIdentifier',
            'recordVersion',
        ]) ||
        value.recordVersion !== recordVersion ||
        typeof value.plaintextByteLength !== 'number'
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored outbound mailbox manifest has a noncanonical shape.',
        );
    }
    const chunkDescriptors = decodeChunkDescriptors(
        value.chunkDescriptors,
        value.plaintextByteLength,
        limits,
    );

    return Object.freeze({
        canonicalEnvelopeHex: requireCanonicalEnvelopeHex(
            value.canonicalEnvelopeHex,
            limits.maximumCarrierByteLength,
        ),
        chunkDescriptors,
        plaintextByteLength: value.plaintextByteLength,
        producerSlot: decodeProducerSlot(value.producerSlot),
        publicationIdentifier: requirePublicationIdentifier(
            value.publicationIdentifier,
            'publicationIdentifier',
        ),
        recordVersion,
    });
};

export const encodeOutboundManifest = (
    manifest: StoredOutboundManifest,
): Uint8Array =>
    encodeCanonicalJson({
        canonicalEnvelopeHex: manifest.canonicalEnvelopeHex,
        chunkDescriptors: manifest.chunkDescriptors,
        plaintextByteLength: manifest.plaintextByteLength,
        producerSlot: manifest.producerSlot,
        publicationIdentifier: manifest.publicationIdentifier,
        recordVersion,
    });

export const decodeStagingManifest = (
    bytes: Uint8Array,
    limits: AuthenticatedMailboxStorageLimits,
): StoredStagingManifest => {
    const value = decodeCanonicalJson(bytes);
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'chunkDescriptors',
            'envelopeHash',
            'publicationIdentifier',
            'recordVersion',
            'totalByteLength',
        ]) ||
        value.recordVersion !== recordVersion ||
        typeof value.totalByteLength !== 'number'
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored mailbox staging manifest has a noncanonical shape.',
        );
    }

    return Object.freeze({
        chunkDescriptors: decodeChunkDescriptors(
            value.chunkDescriptors,
            value.totalByteLength,
            limits,
        ),
        envelopeHash: requireProtocolHash(value.envelopeHash, 'envelopeHash'),
        publicationIdentifier: requirePublicationIdentifier(
            value.publicationIdentifier,
            'publicationIdentifier',
        ),
        recordVersion,
        totalByteLength: value.totalByteLength,
    });
};

export const encodeStagingManifest = (
    manifest: StoredStagingManifest,
): Uint8Array =>
    encodeCanonicalJson({
        chunkDescriptors: manifest.chunkDescriptors,
        envelopeHash: manifest.envelopeHash,
        publicationIdentifier: manifest.publicationIdentifier,
        recordVersion,
        totalByteLength: manifest.totalByteLength,
    });

export const decodeInboundSlot = (
    bytes: Uint8Array,
    limits: AuthenticatedMailboxStorageLimits,
): StoredInboundSlot => {
    const value = decodeCanonicalJson(bytes);
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'canonicalEnvelopeHex',
            'producerSlot',
            'recordVersion',
        ]) ||
        value.recordVersion !== recordVersion
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'Stored inbound mailbox slot has a noncanonical shape.',
        );
    }

    return Object.freeze({
        canonicalEnvelopeHex: requireCanonicalEnvelopeHex(
            value.canonicalEnvelopeHex,
            limits.maximumCarrierByteLength,
        ),
        producerSlot: decodeProducerSlot(value.producerSlot),
        recordVersion,
    });
};

export const encodeInboundSlot = (slot: StoredInboundSlot): Uint8Array =>
    encodeCanonicalJson({
        canonicalEnvelopeHex: slot.canonicalEnvelopeHex,
        producerSlot: slot.producerSlot,
        recordVersion,
    });

export const outboundManifestKey = (slotFingerprint: string): string =>
    `mailbox/outbound/manifest/${slotFingerprint}`;
export const outboundJournalKey = (slotFingerprint: string): string =>
    `mailbox/outbound/journal/${slotFingerprint}`;
export const outboundChunkKey = (input: {
    chunkIndex: number;
    publicationIdentifier: string;
    slotFingerprint: string;
}): string =>
    `mailbox/outbound/chunk/${input.slotFingerprint}/${input.publicationIdentifier}/${String(input.chunkIndex)}`;
export const inboundSlotKey = (slotFingerprint: string): string =>
    `mailbox/inbound/slot/${slotFingerprint}`;
export const stagingManifestKey = (envelopeHash: ProtocolHash): string =>
    `mailbox/staging/manifest/${envelopeHash}`;
export const stagingJournalKey = (envelopeHash: ProtocolHash): string =>
    `mailbox/staging/journal/${envelopeHash}`;
export const stagingChunkKey = (input: {
    chunkIndex: number;
    envelopeHash: ProtocolHash;
    publicationIdentifier: string;
}): string =>
    `mailbox/staging/chunk/${input.envelopeHash}/${input.publicationIdentifier}/${String(input.chunkIndex)}`;

export const carriersEqual = (
    left: AuthenticatedMailboxCarrier,
    right: AuthenticatedMailboxCarrier,
): boolean =>
    bytesEqual(left.canonicalEnvelopeBytes, right.canonicalEnvelopeBytes);

export const copyCarrier = (
    carrier: AuthenticatedMailboxCarrier,
    limits: AuthenticatedMailboxStorageLimits,
): AuthenticatedMailboxCarrier => {
    if (
        !ArrayBuffer.isView(carrier.canonicalEnvelopeBytes) ||
        Object.prototype.toString.call(carrier.canonicalEnvelopeBytes) !==
            '[object Uint8Array]' ||
        carrier.canonicalEnvelopeBytes.byteLength === 0 ||
        carrier.canonicalEnvelopeBytes.byteLength >
            limits.maximumCarrierByteLength
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            'carrier.canonicalEnvelopeBytes has an invalid type or length.',
        );
    }

    return Object.freeze({
        canonicalEnvelopeBytes: carrier.canonicalEnvelopeBytes.slice(),
    });
};

export const carrierFromManifest = (
    manifest: StoredOutboundManifest,
): AuthenticatedMailboxCarrier =>
    Object.freeze({
        canonicalEnvelopeBytes: hexToBytes(manifest.canonicalEnvelopeHex),
    });

export const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationFailure: unknown,
): Promise<AuthenticatedMailboxStorageError> => {
    const mappedOperationFailure = asStorageError(operationFailure);
    try {
        await transaction.closeAfterFailure();
    } catch (closeFailure) {
        return cleanupError(
            'An authenticated mailbox storage transaction failed and could not release its ownership.',
            [mappedOperationFailure, closeFailure],
        );
    }

    return mappedOperationFailure;
};
