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
    copyRuntimeRecordProtectionAuthorityContext,
    createRuntimeRecordProtection,
    mapStorageError,
    readRuntimeRecord,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeStorageAuthorityContext,
} from './authenticated-runtime-record.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const recordVersion = 1;
const maximumAesGcmRandomNonceInvocationCount = 0x1_0000_0000;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const participantIdentityPattern = /^[0-9a-f]{128}$/u;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;
const publicationIdentifierPattern = /^[0-9a-f]{64}$/u;
const chunkDigestPattern = /^[0-9a-f]{128}$/u;

const outboundJournalOperationDomain =
    'sealed-lattice/authenticated-mailbox/outbound-journal/v1';
const outboundManifestOperationDomain =
    'sealed-lattice/authenticated-mailbox/outbound-manifest/v1';
const outboundChunkOperationDomain =
    'sealed-lattice/authenticated-mailbox/outbound-chunk/v1';
const inboundSlotOperationDomain =
    'sealed-lattice/authenticated-mailbox/inbound-slot/v1';
const stagingJournalOperationDomain =
    'sealed-lattice/authenticated-mailbox/staging-journal/v1';
const stagingManifestOperationDomain =
    'sealed-lattice/authenticated-mailbox/staging-manifest/v1';
const stagingChunkOperationDomain =
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

type StoredStreamJournal = Readonly<{
    producerSlot?: StoredProducerSlot;
    envelopeHash?: ProtocolHash;
    publicationIdentifier: string;
    recordVersion: number;
    totalByteLength: number;
}>;

type StoredChunkDescriptor = Readonly<{
    digest: string;
}>;

type StoredOutboundManifest = Readonly<{
    canonicalEnvelopeHex: string;
    chunkDescriptors: readonly StoredChunkDescriptor[];
    plaintextByteLength: number;
    producerSlot: StoredProducerSlot;
    publicationIdentifier: string;
    recordVersion: number;
}>;

type StoredStagingManifest = Readonly<{
    chunkDescriptors: readonly StoredChunkDescriptor[];
    envelopeHash: ProtocolHash;
    publicationIdentifier: string;
    recordVersion: number;
    totalByteLength: number;
}>;

type StoredInboundSlot = Readonly<{
    canonicalEnvelopeHex: string;
    producerSlot: StoredProducerSlot;
    recordVersion: number;
}>;

type OpenedStoredRecord<RecordValue> = Readonly<{
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

const validateLimits = (
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

const asStorageError = (error: unknown): AuthenticatedMailboxStorageError => {
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

const cleanupError = (
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

const requireProtocolHash = (value: unknown, label: string): ProtocolHash => {
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

const streamChunkCount = (
    totalByteLength: number,
    limits: AuthenticatedMailboxStorageLimits,
): number => {
    const chunkCount = Math.ceil(
        totalByteLength / foundationProfile.streamChunkByteLength,
    );
    validateStreamShape(totalByteLength, chunkCount, limits);
    return chunkCount;
};

const expectedChunkByteLength = (
    totalByteLength: number,
    chunkCount: number,
    chunkIndex: number,
): number =>
    chunkIndex + 1 < chunkCount
        ? foundationProfile.streamChunkByteLength
        : totalByteLength -
          (chunkCount - 1) * foundationProfile.streamChunkByteLength;

const requireArrayBuffer = (
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

const throwIfAborted = (abortSignal: AbortSignal | undefined): void => {
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

const normalizeProducerSlot = (
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

const producerSlotsEqual = (
    left: StoredProducerSlot,
    right: StoredProducerSlot,
): boolean => JSON.stringify(left) === JSON.stringify(right);

const producerSlotFingerprint = (producerSlot: StoredProducerSlot): string =>
    bytesToHex(sha512(encodeCanonicalJson(producerSlot)));

const validateProducerSlotAuthority = (input: {
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

const deriveChunkDigest = (bytes: Uint8Array): string =>
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

const decodeStreamJournal = (
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

const encodeStreamJournal = (journal: StoredStreamJournal): Uint8Array =>
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

const decodeOutboundManifest = (
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

const encodeOutboundManifest = (manifest: StoredOutboundManifest): Uint8Array =>
    encodeCanonicalJson({
        canonicalEnvelopeHex: manifest.canonicalEnvelopeHex,
        chunkDescriptors: manifest.chunkDescriptors,
        plaintextByteLength: manifest.plaintextByteLength,
        producerSlot: manifest.producerSlot,
        publicationIdentifier: manifest.publicationIdentifier,
        recordVersion,
    });

const decodeStagingManifest = (
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

const encodeStagingManifest = (manifest: StoredStagingManifest): Uint8Array =>
    encodeCanonicalJson({
        chunkDescriptors: manifest.chunkDescriptors,
        envelopeHash: manifest.envelopeHash,
        publicationIdentifier: manifest.publicationIdentifier,
        recordVersion,
        totalByteLength: manifest.totalByteLength,
    });

const decodeInboundSlot = (
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

const encodeInboundSlot = (slot: StoredInboundSlot): Uint8Array =>
    encodeCanonicalJson({
        canonicalEnvelopeHex: slot.canonicalEnvelopeHex,
        producerSlot: slot.producerSlot,
        recordVersion,
    });

const outboundManifestKey = (slotFingerprint: string): string =>
    `mailbox/outbound/manifest/${slotFingerprint}`;
const outboundJournalKey = (slotFingerprint: string): string =>
    `mailbox/outbound/journal/${slotFingerprint}`;
const outboundChunkKey = (input: {
    chunkIndex: number;
    publicationIdentifier: string;
    slotFingerprint: string;
}): string =>
    `mailbox/outbound/chunk/${input.slotFingerprint}/${input.publicationIdentifier}/${String(input.chunkIndex)}`;
const inboundSlotKey = (slotFingerprint: string): string =>
    `mailbox/inbound/slot/${slotFingerprint}`;
const stagingManifestKey = (envelopeHash: ProtocolHash): string =>
    `mailbox/staging/manifest/${envelopeHash}`;
const stagingJournalKey = (envelopeHash: ProtocolHash): string =>
    `mailbox/staging/journal/${envelopeHash}`;
const stagingChunkKey = (input: {
    chunkIndex: number;
    envelopeHash: ProtocolHash;
    publicationIdentifier: string;
}): string =>
    `mailbox/staging/chunk/${input.envelopeHash}/${input.publicationIdentifier}/${String(input.chunkIndex)}`;

const carriersEqual = (
    left: AuthenticatedMailboxCarrier,
    right: AuthenticatedMailboxCarrier,
): boolean =>
    bytesEqual(left.canonicalEnvelopeBytes, right.canonicalEnvelopeBytes);

const copyCarrier = (
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

const carrierFromManifest = (
    manifest: StoredOutboundManifest,
): AuthenticatedMailboxCarrier =>
    Object.freeze({
        canonicalEnvelopeBytes: hexToBytes(manifest.canonicalEnvelopeHex),
    });

const closeTransactionAfterFailure = async (
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

export const createBrowserLocalAuthenticatedMailboxStorage = (
    configuration: BrowserLocalAuthenticatedMailboxStorageConfiguration,
): BrowserLocalAuthenticatedMailboxStorage => {
    const limits = validateLimits(configuration.limits);
    const protection = createRuntimeRecordProtection({
        authorityContext: configuration.authorityContext,
        ...(configuration.cryptoProvider === undefined
            ? {}
            : { cryptoProvider: configuration.cryptoProvider }),
        encryptionKey: configuration.encryptionKey,
        maximumRecordSealingCount: limits.maximumRecordSealingCount,
    });
    const authorityContext =
        copyRuntimeRecordProtectionAuthorityContext(protection);
    const issuedIdentifiers = new Set<string>();
    const activeOutboundSlots = new Map<string, number>();
    const activeInboundSlots = new Map<string, AuthenticatedMailboxCarrier>();
    const activeStagingEnvelopes = new Set<ProtocolHash>();

    const writeRecord = async (input: {
        expectedCurrentSealedBytes?: Uint8Array | null;
        logicalRecordKey: string;
        operationDomain: string;
        plaintext: Uint8Array;
    }): Promise<void> => {
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                ...(input.expectedCurrentSealedBytes === undefined
                    ? {}
                    : {
                          expectedCurrentSealedBytes:
                              input.expectedCurrentSealedBytes,
                      }),
                logicalRecordKey: input.logicalRecordKey,
                operationDomain: input.operationDomain,
                plaintext: input.plaintext,
                protection,
                transaction,
            });
            await transaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        }
    };

    const deleteRecord = async (logicalRecordKey: string): Promise<void> => {
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await transaction.stageDeletion(logicalRecordKey);
            await transaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        }
    };

    const readDecodedRecord = async <RecordValue>(input: {
        decode: (plaintext: Uint8Array) => RecordValue;
        logicalRecordKey: string;
        operationDomain: string;
    }): Promise<OpenedStoredRecord<RecordValue> | undefined> => {
        const opened = await readRuntimeRecord({
            logicalRecordKey: input.logicalRecordKey,
            operationDomain: input.operationDomain,
            protection,
            store: configuration.store,
        });
        if (opened === undefined) {
            return undefined;
        }
        try {
            let record: RecordValue;
            try {
                record = input.decode(opened.plaintext);
            } catch (error) {
                const mapped = asStorageError(error);
                if (mapped.code === 'AuthenticationFailed') {
                    throw mapped;
                }
                throw new AuthenticatedMailboxStorageError(
                    'AuthenticationFailed',
                    'An authenticated mailbox storage record has invalid contents.',
                    mapped,
                );
            }
            return {
                record,
                sealedBytes: opened.sealedBytes,
            };
        } finally {
            opened.plaintext.fill(0);
        }
    };

    const readOutboundManifest = async (
        slotFingerprint: string,
    ): Promise<OpenedStoredRecord<StoredOutboundManifest> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) => decodeOutboundManifest(plaintext, limits),
            logicalRecordKey: outboundManifestKey(slotFingerprint),
            operationDomain: outboundManifestOperationDomain,
        });

    const readOutboundJournal = async (
        slotFingerprint: string,
    ): Promise<OpenedStoredRecord<StoredStreamJournal> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) =>
                decodeStreamJournal(plaintext, 'outbound', limits),
            logicalRecordKey: outboundJournalKey(slotFingerprint),
            operationDomain: outboundJournalOperationDomain,
        });

    const readStagingManifest = async (
        envelopeHash: ProtocolHash,
    ): Promise<OpenedStoredRecord<StoredStagingManifest> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) => decodeStagingManifest(plaintext, limits),
            logicalRecordKey: stagingManifestKey(envelopeHash),
            operationDomain: stagingManifestOperationDomain,
        });

    const readStagingJournal = async (
        envelopeHash: ProtocolHash,
    ): Promise<OpenedStoredRecord<StoredStreamJournal> | undefined> =>
        readDecodedRecord({
            decode: (plaintext) =>
                decodeStreamJournal(plaintext, 'staging', limits),
            logicalRecordKey: stagingJournalKey(envelopeHash),
            operationDomain: stagingJournalOperationDomain,
        });

    const cleanupStreamChunks = async (input: {
        chunkKey: (chunkIndex: number) => string;
        chunkCount: number;
        journalKey: string;
    }): Promise<void> => {
        const failures: unknown[] = [];
        for (
            let chunkIndex = 0;
            chunkIndex < input.chunkCount;
            chunkIndex += 1
        ) {
            try {
                await deleteRecord(input.chunkKey(chunkIndex));
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length === 0) {
            try {
                await deleteRecord(input.journalKey);
            } catch (error) {
                failures.push(error);
            }
        }
        if (failures.length > 0) {
            throw cleanupError(
                'Authenticated mailbox stream cleanup did not remove every lease-owned record.',
                failures,
            );
        }
    };

    const cleanupOutboundJournal = async (
        slotFingerprint: string,
        journal: StoredStreamJournal,
    ): Promise<void> => {
        if (journal.producerSlot === undefined) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'Outbound mailbox journal omitted its producer slot.',
            );
        }
        await cleanupStreamChunks({
            chunkCount: streamChunkCount(journal.totalByteLength, limits),
            chunkKey: (chunkIndex) =>
                outboundChunkKey({
                    chunkIndex,
                    publicationIdentifier: journal.publicationIdentifier,
                    slotFingerprint,
                }),
            journalKey: outboundJournalKey(slotFingerprint),
        });
    };

    const readChunk = async (input: {
        descriptor: StoredChunkDescriptor;
        expectedByteLength: number;
        logicalRecordKey: string;
        operationDomain: string;
    }): Promise<ArrayBuffer> => {
        const opened = await readRuntimeRecord({
            logicalRecordKey: input.logicalRecordKey,
            operationDomain: input.operationDomain,
            protection,
            store: configuration.store,
        });
        if (opened === undefined) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'An authenticated mailbox chunk is missing.',
            );
        }
        try {
            if (
                opened.plaintext.byteLength !== input.expectedByteLength ||
                deriveChunkDigest(opened.plaintext) !== input.descriptor.digest
            ) {
                throw new AuthenticatedMailboxStorageError(
                    'AuthenticationFailed',
                    'An authenticated mailbox chunk does not match its published descriptor.',
                );
            }
            const result = new Uint8Array(
                new ArrayBuffer(opened.plaintext.byteLength),
            );
            result.set(opened.plaintext);

            return result.buffer;
        } finally {
            opened.plaintext.fill(0);
        }
    };

    const outboundCache: AuthenticatedMailboxOutboundCache = Object.freeze({
        reserve: async ({
            plaintextByteLength,
            producerSlot: untrustedProducerSlot,
        }) => {
            try {
                const chunkCount = streamChunkCount(
                    plaintextByteLength,
                    limits,
                );
                const producerSlot = normalizeProducerSlot(
                    untrustedProducerSlot,
                );
                validateProducerSlotAuthority({
                    authorityContext,
                    direction: 'outbound',
                    producerSlot,
                });
                const slotFingerprint = producerSlotFingerprint(producerSlot);
                const activeReservation =
                    activeOutboundSlots.get(slotFingerprint);
                if (activeReservation !== undefined) {
                    const declarationsMatch =
                        activeReservation === plaintextByteLength;
                    throw new AuthenticatedMailboxStorageError(
                        declarationsMatch ? 'Conflict' : 'Equivocation',
                        declarationsMatch
                            ? 'The outbound mailbox producer slot already has an active reservation.'
                            : 'The outbound mailbox producer slot was reused with conflicting stream declarations.',
                    );
                }

                const existingManifest =
                    await readOutboundManifest(slotFingerprint);
                const existingJournal =
                    await readOutboundJournal(slotFingerprint);
                if (existingManifest !== undefined) {
                    if (
                        !producerSlotsEqual(
                            existingManifest.record.producerSlot,
                            producerSlot,
                        )
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'AuthenticationFailed',
                            'Outbound mailbox slot fingerprint resolves to a different authenticated producer slot.',
                        );
                    }
                    if (
                        existingManifest.record.plaintextByteLength !==
                            plaintextByteLength ||
                        existingManifest.record.chunkDescriptors.length !==
                            chunkCount
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'Equivocation',
                            'The outbound mailbox producer slot already contains conflicting stream declarations.',
                        );
                    }
                    if (existingJournal !== undefined) {
                        if (
                            existingJournal.record.publicationIdentifier ===
                            existingManifest.record.publicationIdentifier
                        ) {
                            await deleteRecord(
                                outboundJournalKey(slotFingerprint),
                            );
                        } else {
                            await cleanupOutboundJournal(
                                slotFingerprint,
                                existingJournal.record,
                            );
                        }
                    }
                    const manifest = existingManifest.record;
                    const carrier = carrierFromManifest(manifest);

                    return Object.freeze({
                        disposition: 'cached' as const,
                        cachedCarrier: () =>
                            Promise.resolve(
                                Object.freeze({
                                    canonicalEnvelopeBytes:
                                        carrier.canonicalEnvelopeBytes.slice(),
                                }),
                            ),
                        stageChunk: () =>
                            Promise.reject(
                                new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'A cached outbound mailbox lease cannot stage chunks.',
                                ),
                            ),
                        commit: () =>
                            Promise.reject(
                                new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'A cached outbound mailbox lease is already committed.',
                                ),
                            ),
                        pullChunk: async ({
                            abortSignal,
                            chunkIndex,
                            expectedByteLength,
                        }) => {
                            throwIfAborted(abortSignal);
                            if (
                                chunkIndex === manifest.chunkDescriptors.length
                            ) {
                                if (expectedByteLength !== 0) {
                                    throw new AuthenticatedMailboxStorageError(
                                        'InvalidInput',
                                        'Trailing mailbox chunk probe must request zero bytes.',
                                    );
                                }
                                return undefined;
                            }
                            const descriptor =
                                manifest.chunkDescriptors[chunkIndex];
                            const descriptorByteLength =
                                expectedChunkByteLength(
                                    manifest.plaintextByteLength,
                                    manifest.chunkDescriptors.length,
                                    chunkIndex,
                                );
                            if (
                                descriptor === undefined ||
                                !Number.isSafeInteger(chunkIndex) ||
                                chunkIndex < 0 ||
                                expectedByteLength !== descriptorByteLength
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidInput',
                                    'Outbound mailbox chunk pull does not match the published descriptor.',
                                );
                            }

                            return readChunk({
                                descriptor,
                                expectedByteLength: descriptorByteLength,
                                logicalRecordKey: outboundChunkKey({
                                    chunkIndex,
                                    publicationIdentifier:
                                        manifest.publicationIdentifier,
                                    slotFingerprint,
                                }),
                                operationDomain: outboundChunkOperationDomain,
                            });
                        },
                        cancel: () => Promise.resolve(),
                    });
                }
                if (existingJournal !== undefined) {
                    if (
                        existingJournal.record.producerSlot === undefined ||
                        !producerSlotsEqual(
                            existingJournal.record.producerSlot,
                            producerSlot,
                        )
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'AuthenticationFailed',
                            'Outbound mailbox journal belongs to a different producer slot.',
                        );
                    }
                    await cleanupOutboundJournal(
                        slotFingerprint,
                        existingJournal.record,
                    );
                }

                const publicationIdentifier = bytesToHex(
                    sampleRuntimeIdentifier(
                        protection,
                        issuedIdentifiers,
                        'outbound mailbox publication identifier',
                    ),
                );
                const journal: StoredStreamJournal = Object.freeze({
                    producerSlot,
                    publicationIdentifier,
                    recordVersion,
                    totalByteLength: plaintextByteLength,
                });
                const journalPlaintext = encodeStreamJournal(journal);
                try {
                    await writeRecord({
                        expectedCurrentSealedBytes: null,
                        logicalRecordKey: outboundJournalKey(slotFingerprint),
                        operationDomain: outboundJournalOperationDomain,
                        plaintext: journalPlaintext,
                    });
                } finally {
                    journalPlaintext.fill(0);
                }
                activeOutboundSlots.set(slotFingerprint, plaintextByteLength);

                const chunkDescriptors: StoredChunkDescriptor[] = [];
                let state:
                    | 'active'
                    | 'cancelled'
                    | 'committing'
                    | 'committed'
                    | 'failed' = 'active';
                let published = false;
                let committedManifest: StoredOutboundManifest | undefined;

                const releaseReservation = (): void => {
                    activeOutboundSlots.delete(slotFingerprint);
                };

                const pullPublishedChunk = async (input: {
                    abortSignal?: AbortSignal;
                    chunkIndex: number;
                    expectedByteLength: number;
                }): Promise<ArrayBuffer | undefined> => {
                    throwIfAborted(input.abortSignal);
                    if (
                        state !== 'committed' ||
                        committedManifest === undefined
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'InvalidState',
                            'Outbound mailbox chunks are unreadable before manifest publication.',
                        );
                    }
                    if (
                        input.chunkIndex ===
                        committedManifest.chunkDescriptors.length
                    ) {
                        if (input.expectedByteLength !== 0) {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidInput',
                                'Trailing mailbox chunk probe must request zero bytes.',
                            );
                        }
                        return undefined;
                    }
                    const descriptor =
                        committedManifest.chunkDescriptors[input.chunkIndex];
                    const descriptorByteLength = expectedChunkByteLength(
                        committedManifest.plaintextByteLength,
                        committedManifest.chunkDescriptors.length,
                        input.chunkIndex,
                    );
                    if (
                        descriptor === undefined ||
                        !Number.isSafeInteger(input.chunkIndex) ||
                        input.chunkIndex < 0 ||
                        input.expectedByteLength !== descriptorByteLength
                    ) {
                        throw new AuthenticatedMailboxStorageError(
                            'InvalidInput',
                            'Outbound mailbox chunk pull does not match the published descriptor.',
                        );
                    }

                    return readChunk({
                        descriptor,
                        expectedByteLength: descriptorByteLength,
                        logicalRecordKey: outboundChunkKey({
                            chunkIndex: input.chunkIndex,
                            publicationIdentifier,
                            slotFingerprint,
                        }),
                        operationDomain: outboundChunkOperationDomain,
                    });
                };

                return Object.freeze({
                    disposition: 'fresh' as const,
                    cachedCarrier: () => {
                        if (
                            state !== 'committed' ||
                            committedManifest === undefined
                        ) {
                            return Promise.reject(
                                new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Fresh outbound mailbox carrier is unavailable before commit.',
                                ),
                            );
                        }

                        return Promise.resolve(
                            carrierFromManifest(committedManifest),
                        );
                    },
                    stageChunk: async ({ bytes, chunkIndex }) => {
                        if (state !== 'active') {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease is not accepting chunks.',
                            );
                        }
                        if (
                            !Number.isSafeInteger(chunkIndex) ||
                            chunkIndex !== chunkDescriptors.length ||
                            chunkIndex >= chunkCount
                        ) {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidInput',
                                'Outbound mailbox chunks must be staged once in exact order.',
                            );
                        }
                        const expectedByteLength = expectedChunkByteLength(
                            plaintextByteLength,
                            chunkCount,
                            chunkIndex,
                        );
                        const chunk = requireArrayBuffer(
                            bytes,
                            expectedByteLength,
                            'outbound mailbox chunk',
                        );
                        const descriptor = Object.freeze({
                            digest: deriveChunkDigest(chunk),
                        });
                        try {
                            await writeRecord({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey: outboundChunkKey({
                                    chunkIndex,
                                    publicationIdentifier,
                                    slotFingerprint,
                                }),
                                operationDomain: outboundChunkOperationDomain,
                                plaintext: chunk,
                            });
                            chunkDescriptors.push(descriptor);
                        } catch (error) {
                            state = 'failed';
                            throw asStorageError(error);
                        } finally {
                            chunk.fill(0);
                        }
                    },
                    commit: async (untrustedCarrier) => {
                        if (state !== 'active') {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease cannot commit from its current state.',
                            );
                        }
                        if (chunkDescriptors.length !== chunkCount) {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease cannot commit before every exact chunk is staged.',
                            );
                        }
                        const carrier = copyCarrier(untrustedCarrier, limits);
                        state = 'committing';
                        const manifest: StoredOutboundManifest = Object.freeze({
                            canonicalEnvelopeHex: bytesToHex(
                                carrier.canonicalEnvelopeBytes,
                            ),
                            chunkDescriptors: Object.freeze([
                                ...chunkDescriptors,
                            ]),
                            plaintextByteLength,
                            producerSlot,
                            publicationIdentifier,
                            recordVersion,
                        });
                        const manifestPlaintext =
                            encodeOutboundManifest(manifest);
                        let transaction:
                            | UntrustedStorageTransaction
                            | undefined;
                        let operationFailure: unknown;
                        try {
                            transaction =
                                await configuration.store.beginTransaction({
                                    lifetimeMilliseconds:
                                        limits.transactionLifetimeMilliseconds,
                                });
                            const currentJournal =
                                await readOutboundJournal(slotFingerprint);
                            if (
                                currentJournal === undefined ||
                                currentJournal.record.publicationIdentifier !==
                                    publicationIdentifier
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'Conflict',
                                    'Outbound mailbox journal changed before manifest publication.',
                                );
                            }
                            await stageRuntimeRecordWrite({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey:
                                    outboundManifestKey(slotFingerprint),
                                operationDomain:
                                    outboundManifestOperationDomain,
                                plaintext: manifestPlaintext,
                                protection,
                                transaction,
                            });
                            await transaction.stageDeletion(
                                outboundJournalKey(slotFingerprint),
                                currentJournal.sealedBytes,
                            );
                            await transaction.commit();
                            published = true;
                        } catch (error) {
                            operationFailure =
                                transaction === undefined
                                    ? asStorageError(error)
                                    : await closeTransactionAfterFailure(
                                          transaction,
                                          error,
                                      );
                            try {
                                const observedManifest =
                                    await readOutboundManifest(slotFingerprint);
                                if (
                                    observedManifest !== undefined &&
                                    bytesEqual(
                                        encodeOutboundManifest(
                                            observedManifest.record,
                                        ),
                                        encodeOutboundManifest(manifest),
                                    )
                                ) {
                                    published = true;
                                }
                            } catch (observationFailure) {
                                state = 'failed';
                                throw cleanupError(
                                    'Outbound mailbox publication failed and its committed state could not be confirmed.',
                                    [operationFailure, observationFailure],
                                );
                            }
                        } finally {
                            manifestPlaintext.fill(0);
                            carrier.canonicalEnvelopeBytes.fill(0);
                        }
                        try {
                            if (published) {
                                const reread =
                                    await readOutboundManifest(slotFingerprint);
                                if (
                                    reread === undefined ||
                                    !producerSlotsEqual(
                                        reread.record.producerSlot,
                                        producerSlot,
                                    ) ||
                                    reread.record.publicationIdentifier !==
                                        publicationIdentifier
                                ) {
                                    state = 'failed';
                                    releaseReservation();
                                    throw new AuthenticatedMailboxStorageError(
                                        'AuthenticationFailed',
                                        'Published outbound mailbox manifest failed its authenticated reread.',
                                    );
                                }
                                committedManifest = reread.record;
                                state = 'committed';
                                releaseReservation();
                            } else {
                                state = 'failed';
                            }
                            if (operationFailure !== undefined) {
                                throw asStorageError(operationFailure);
                            }
                        } catch (error) {
                            if (state === 'committing') {
                                state = 'failed';
                            }
                            throw asStorageError(error);
                        }
                    },
                    pullChunk: pullPublishedChunk,
                    cancel: async () => {
                        if (state === 'cancelled' || state === 'committed') {
                            return;
                        }
                        if (state === 'committing') {
                            throw new AuthenticatedMailboxStorageError(
                                'InvalidState',
                                'Outbound mailbox lease cannot cancel during manifest publication.',
                            );
                        }
                        if (published) {
                            state = 'committed';
                            releaseReservation();
                            return;
                        }
                        try {
                            await cleanupOutboundJournal(
                                slotFingerprint,
                                journal,
                            );
                            state = 'cancelled';
                            releaseReservation();
                        } catch (error) {
                            state = 'failed';
                            releaseReservation();
                            throw asStorageError(error);
                        }
                    },
                });
            } catch (error) {
                throw asStorageError(error);
            }
        },
    });

    const inboundSlotAuthority: AuthenticatedMailboxInboundSlotAuthority =
        Object.freeze({
            reserve: async ({
                canonicalEnvelopeBytes: untrustedCanonicalEnvelopeBytes,
                producerSlot: untrustedProducerSlot,
            }) => {
                try {
                    const producerSlot = normalizeProducerSlot(
                        untrustedProducerSlot,
                    );
                    validateProducerSlotAuthority({
                        authorityContext,
                        direction: 'inbound',
                        producerSlot,
                    });
                    const carrier = copyCarrier(
                        {
                            canonicalEnvelopeBytes:
                                untrustedCanonicalEnvelopeBytes,
                        },
                        limits,
                    );
                    const slotFingerprint =
                        producerSlotFingerprint(producerSlot);
                    const activeReservation =
                        activeInboundSlots.get(slotFingerprint);
                    if (activeReservation !== undefined) {
                        const identical = carriersEqual(
                            activeReservation,
                            carrier,
                        );
                        carrier.canonicalEnvelopeBytes.fill(0);

                        return identical
                            ? {
                                  isValid: false as const,
                                  refusalReason: 'consumedState' as const,
                              }
                            : {
                                  isValid: false as const,
                                  refusalReason: 'equivocation' as const,
                              };
                    }
                    const logicalRecordKey = inboundSlotKey(slotFingerprint);
                    const opened = await readDecodedRecord({
                        decode: (plaintext) =>
                            decodeInboundSlot(plaintext, limits),
                        logicalRecordKey,
                        operationDomain: inboundSlotOperationDomain,
                    });
                    if (opened !== undefined) {
                        if (
                            !producerSlotsEqual(
                                opened.record.producerSlot,
                                producerSlot,
                            )
                        ) {
                            carrier.canonicalEnvelopeBytes.fill(0);
                            throw new AuthenticatedMailboxStorageError(
                                'AuthenticationFailed',
                                'Inbound mailbox slot fingerprint resolves to a different authenticated producer slot.',
                            );
                        }
                        const storedCarrier = Object.freeze({
                            canonicalEnvelopeBytes: hexToBytes(
                                opened.record.canonicalEnvelopeHex,
                            ),
                        });
                        const identical = carriersEqual(storedCarrier, carrier);
                        storedCarrier.canonicalEnvelopeBytes.fill(0);
                        carrier.canonicalEnvelopeBytes.fill(0);
                        if (!identical) {
                            return {
                                isValid: false,
                                refusalReason: 'equivocation',
                            };
                        }

                        return {
                            isValid: true,
                            value: Object.freeze({
                                disposition:
                                    'byteIdenticalRetransmission' as const,
                                cancel: () => Promise.resolve(),
                                commit: () => Promise.resolve(),
                            }),
                        };
                    }

                    activeInboundSlots.set(
                        slotFingerprint,
                        Object.freeze({
                            canonicalEnvelopeBytes:
                                carrier.canonicalEnvelopeBytes.slice(),
                        }),
                    );
                    let state:
                        | 'active'
                        | 'cancelled'
                        | 'committed'
                        | 'committing'
                        | 'failed' = 'active';
                    const releaseReservation = (): void => {
                        const active = activeInboundSlots.get(slotFingerprint);
                        active?.canonicalEnvelopeBytes.fill(0);
                        activeInboundSlots.delete(slotFingerprint);
                    };

                    return {
                        isValid: true,
                        value: Object.freeze({
                            disposition: 'fresh' as const,
                            cancel: () => {
                                if (state === 'committing') {
                                    return Promise.reject(
                                        new AuthenticatedMailboxStorageError(
                                            'InvalidState',
                                            'Inbound mailbox slot cannot cancel during commit.',
                                        ),
                                    );
                                }
                                if (state === 'active') {
                                    state = 'cancelled';
                                    releaseReservation();
                                }
                                carrier.canonicalEnvelopeBytes.fill(0);
                                return Promise.resolve();
                            },
                            commit: async () => {
                                if (state !== 'active') {
                                    throw new AuthenticatedMailboxStorageError(
                                        'InvalidState',
                                        'Inbound mailbox slot cannot commit from its current state.',
                                    );
                                }
                                state = 'committing';
                                const storedSlot: StoredInboundSlot =
                                    Object.freeze({
                                        canonicalEnvelopeHex: bytesToHex(
                                            carrier.canonicalEnvelopeBytes,
                                        ),
                                        producerSlot,
                                        recordVersion,
                                    });
                                const plaintext = encodeInboundSlot(storedSlot);
                                let operationFailure: unknown;
                                try {
                                    try {
                                        await writeRecord({
                                            expectedCurrentSealedBytes: null,
                                            logicalRecordKey,
                                            operationDomain:
                                                inboundSlotOperationDomain,
                                            plaintext,
                                        });
                                    } catch (error) {
                                        operationFailure = error;
                                        const observed =
                                            await readDecodedRecord({
                                                decode: (bytes) =>
                                                    decodeInboundSlot(
                                                        bytes,
                                                        limits,
                                                    ),
                                                logicalRecordKey,
                                                operationDomain:
                                                    inboundSlotOperationDomain,
                                            });
                                        state =
                                            observed !== undefined &&
                                            observed.record
                                                .canonicalEnvelopeHex ===
                                                storedSlot.canonicalEnvelopeHex &&
                                            producerSlotsEqual(
                                                observed.record.producerSlot,
                                                producerSlot,
                                            )
                                                ? 'committed'
                                                : 'failed';
                                    }
                                    if (operationFailure === undefined) {
                                        const reread = await readDecodedRecord({
                                            decode: (bytes) =>
                                                decodeInboundSlot(
                                                    bytes,
                                                    limits,
                                                ),
                                            logicalRecordKey,
                                            operationDomain:
                                                inboundSlotOperationDomain,
                                        });
                                        if (
                                            reread === undefined ||
                                            reread.record
                                                .canonicalEnvelopeHex !==
                                                storedSlot.canonicalEnvelopeHex
                                        ) {
                                            state = 'failed';
                                            throw new AuthenticatedMailboxStorageError(
                                                'AuthenticationFailed',
                                                'Committed inbound mailbox slot failed its authenticated reread.',
                                            );
                                        }
                                        state = 'committed';
                                    }
                                    if (operationFailure !== undefined) {
                                        throw asStorageError(operationFailure);
                                    }
                                } catch (error) {
                                    if (state === 'committing') {
                                        state = 'failed';
                                    }
                                    throw asStorageError(error);
                                } finally {
                                    plaintext.fill(0);
                                    carrier.canonicalEnvelopeBytes.fill(0);
                                    releaseReservation();
                                }
                            },
                        }),
                    };
                } catch (error) {
                    throw asStorageError(error);
                }
            },
        });

    const convertStagingManifestToJournal = async (input: {
        envelopeHash: ProtocolHash;
        manifest: OpenedStoredRecord<StoredStagingManifest>;
    }): Promise<StoredStreamJournal> => {
        const journal: StoredStreamJournal = Object.freeze({
            envelopeHash: input.envelopeHash,
            publicationIdentifier: input.manifest.record.publicationIdentifier,
            recordVersion,
            totalByteLength: input.manifest.record.totalByteLength,
        });
        const journalPlaintext = encodeStreamJournal(journal);
        const transaction = await configuration.store.beginTransaction({
            lifetimeMilliseconds: limits.transactionLifetimeMilliseconds,
        });
        try {
            await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes: null,
                logicalRecordKey: stagingJournalKey(input.envelopeHash),
                operationDomain: stagingJournalOperationDomain,
                plaintext: journalPlaintext,
                protection,
                transaction,
            });
            await transaction.stageDeletion(
                stagingManifestKey(input.envelopeHash),
                input.manifest.sealedBytes,
            );
            await transaction.commit();
        } catch (error) {
            throw await closeTransactionAfterFailure(transaction, error);
        } finally {
            journalPlaintext.fill(0);
        }

        return journal;
    };

    const cleanupStagingJournal = async (
        envelopeHash: ProtocolHash,
        journal: StoredStreamJournal,
    ): Promise<void> => {
        if (journal.envelopeHash !== envelopeHash) {
            throw new AuthenticatedMailboxStorageError(
                'AuthenticationFailed',
                'Mailbox staging journal belongs to a different envelope.',
            );
        }
        await cleanupStreamChunks({
            chunkCount: streamChunkCount(journal.totalByteLength, limits),
            chunkKey: (chunkIndex) =>
                stagingChunkKey({
                    chunkIndex,
                    envelopeHash,
                    publicationIdentifier: journal.publicationIdentifier,
                }),
            journalKey: stagingJournalKey(envelopeHash),
        });
    };

    const stagingBoundary: AuthenticatedMailboxStagingBoundary = Object.freeze({
        open: ({ envelopeHash: untrustedEnvelopeHash, totalByteLength }) => {
            try {
                const envelopeHash = requireProtocolHash(
                    untrustedEnvelopeHash,
                    'envelopeHash',
                );
                const chunkCount = streamChunkCount(totalByteLength, limits);
                if (activeStagingEnvelopes.has(envelopeHash)) {
                    throw new AuthenticatedMailboxStorageError(
                        'Conflict',
                        'The mailbox envelope already has an active staging lease.',
                    );
                }
                const publicationIdentifier = bytesToHex(
                    sampleRuntimeIdentifier(
                        protection,
                        issuedIdentifiers,
                        'mailbox staging publication identifier',
                    ),
                );
                activeStagingEnvelopes.add(envelopeHash);
                const journal: StoredStreamJournal = Object.freeze({
                    envelopeHash,
                    publicationIdentifier,
                    recordVersion,
                    totalByteLength,
                });
                const chunkDescriptors: StoredChunkDescriptor[] = [];
                let state:
                    | 'active'
                    | 'busy'
                    | 'disposed'
                    | 'failed'
                    | 'sealed' = 'active';
                let prepared = false;
                let preparePromise: Promise<void> | undefined;

                const releaseLease = (): void => {
                    activeStagingEnvelopes.delete(envelopeHash);
                };

                const prepare = (): Promise<void> => {
                    preparePromise ??= (async () => {
                        const staleManifest =
                            await readStagingManifest(envelopeHash);
                        const staleJournal =
                            await readStagingJournal(envelopeHash);
                        if (staleManifest !== undefined) {
                            if (
                                staleManifest.record.envelopeHash !==
                                envelopeHash
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'AuthenticationFailed',
                                    'Stored mailbox staging manifest belongs to another envelope.',
                                );
                            }
                            if (staleJournal !== undefined) {
                                await cleanupStagingJournal(
                                    envelopeHash,
                                    staleJournal.record,
                                );
                            }
                            const cleanupJournal =
                                await convertStagingManifestToJournal({
                                    envelopeHash,
                                    manifest: staleManifest,
                                });
                            await cleanupStagingJournal(
                                envelopeHash,
                                cleanupJournal,
                            );
                        } else if (staleJournal !== undefined) {
                            await cleanupStagingJournal(
                                envelopeHash,
                                staleJournal.record,
                            );
                        }
                        const journalPlaintext = encodeStreamJournal(journal);
                        try {
                            await writeRecord({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey:
                                    stagingJournalKey(envelopeHash),
                                operationDomain: stagingJournalOperationDomain,
                                plaintext: journalPlaintext,
                            });
                            prepared = true;
                        } finally {
                            journalPlaintext.fill(0);
                        }
                    })();

                    return preparePromise;
                };

                const disposePreparedRecords = async (): Promise<void> => {
                    const manifest = await readStagingManifest(envelopeHash);
                    let cleanupJournal = await readStagingJournal(envelopeHash);
                    if (manifest !== undefined) {
                        if (cleanupJournal !== undefined) {
                            await cleanupStagingJournal(
                                envelopeHash,
                                cleanupJournal.record,
                            );
                        }
                        const converted = await convertStagingManifestToJournal(
                            {
                                envelopeHash,
                                manifest,
                            },
                        );
                        cleanupJournal = {
                            record: converted,
                            sealedBytes: new Uint8Array(),
                        };
                    }
                    if (cleanupJournal !== undefined) {
                        await cleanupStagingJournal(
                            envelopeHash,
                            cleanupJournal.record,
                        );
                    }
                };

                return Promise.resolve(
                    Object.freeze({
                        stageChunk: async ({ bytes, chunkIndex }) => {
                            if (state !== 'active') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease is not accepting chunks.',
                                );
                            }
                            if (
                                !Number.isSafeInteger(chunkIndex) ||
                                chunkIndex !== chunkDescriptors.length ||
                                chunkIndex >= chunkCount
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidInput',
                                    'Mailbox staging chunks must be written once in exact order.',
                                );
                            }
                            const expectedByteLength = expectedChunkByteLength(
                                totalByteLength,
                                chunkCount,
                                chunkIndex,
                            );
                            const chunk = requireArrayBuffer(
                                bytes,
                                expectedByteLength,
                                'mailbox staging chunk',
                            );
                            state = 'busy';
                            try {
                                await prepare();
                                const descriptor = Object.freeze({
                                    digest: deriveChunkDigest(chunk),
                                });
                                await writeRecord({
                                    expectedCurrentSealedBytes: null,
                                    logicalRecordKey: stagingChunkKey({
                                        chunkIndex,
                                        envelopeHash,
                                        publicationIdentifier,
                                    }),
                                    operationDomain:
                                        stagingChunkOperationDomain,
                                    plaintext: chunk,
                                });
                                chunkDescriptors.push(descriptor);
                                state = 'active';
                            } catch (error) {
                                state = 'failed';
                                throw asStorageError(error);
                            } finally {
                                chunk.fill(0);
                            }
                        },
                        seal: async () => {
                            if (state !== 'active') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease cannot seal from its current state.',
                                );
                            }
                            if (chunkDescriptors.length !== chunkCount) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease cannot seal before every exact chunk is stored.',
                                );
                            }
                            state = 'busy';
                            let manifestPlaintext: Uint8Array | undefined;
                            let transaction:
                                | UntrustedStorageTransaction
                                | undefined;
                            try {
                                await prepare();
                                const manifest: StoredStagingManifest =
                                    Object.freeze({
                                        chunkDescriptors: Object.freeze([
                                            ...chunkDescriptors,
                                        ]),
                                        envelopeHash,
                                        publicationIdentifier,
                                        recordVersion,
                                        totalByteLength,
                                    });
                                manifestPlaintext =
                                    encodeStagingManifest(manifest);
                                transaction =
                                    await configuration.store.beginTransaction({
                                        lifetimeMilliseconds:
                                            limits.transactionLifetimeMilliseconds,
                                    });
                                const currentJournal =
                                    await readStagingJournal(envelopeHash);
                                if (
                                    currentJournal === undefined ||
                                    currentJournal.record
                                        .publicationIdentifier !==
                                        publicationIdentifier
                                ) {
                                    throw new AuthenticatedMailboxStorageError(
                                        'Conflict',
                                        'Mailbox staging journal changed before manifest publication.',
                                    );
                                }
                                await stageRuntimeRecordWrite({
                                    expectedCurrentSealedBytes: null,
                                    logicalRecordKey:
                                        stagingManifestKey(envelopeHash),
                                    operationDomain:
                                        stagingManifestOperationDomain,
                                    plaintext: manifestPlaintext,
                                    protection,
                                    transaction,
                                });
                                await transaction.stageDeletion(
                                    stagingJournalKey(envelopeHash),
                                    currentJournal.sealedBytes,
                                );
                                await transaction.commit();
                                state = 'sealed';
                            } catch (error) {
                                const mapped =
                                    transaction === undefined
                                        ? asStorageError(error)
                                        : await closeTransactionAfterFailure(
                                              transaction,
                                              error,
                                          );
                                try {
                                    const observed =
                                        await readStagingManifest(envelopeHash);
                                    state =
                                        observed?.record
                                            .publicationIdentifier ===
                                        publicationIdentifier
                                            ? 'sealed'
                                            : 'failed';
                                } catch (observationFailure) {
                                    state = 'failed';
                                    throw cleanupError(
                                        'Mailbox staging publication failed and its committed state could not be confirmed.',
                                        [mapped, observationFailure],
                                    );
                                }
                                throw mapped;
                            } finally {
                                manifestPlaintext?.fill(0);
                            }
                            const reread =
                                await readStagingManifest(envelopeHash);
                            if (
                                reread === undefined ||
                                reread.record.publicationIdentifier !==
                                    publicationIdentifier ||
                                reread.record.chunkDescriptors.length !==
                                    chunkCount
                            ) {
                                state = 'failed';
                                throw new AuthenticatedMailboxStorageError(
                                    'AuthenticationFailed',
                                    'Published mailbox staging manifest failed its authenticated reread.',
                                );
                            }
                        },
                        pullChunk: async ({
                            abortSignal,
                            chunkIndex,
                            expectedByteLength,
                        }) => {
                            throwIfAborted(abortSignal);
                            if (state !== 'sealed') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging chunks are unreadable before the manifest commits.',
                                );
                            }
                            if (chunkIndex === chunkCount) {
                                if (expectedByteLength !== 0) {
                                    throw new AuthenticatedMailboxStorageError(
                                        'InvalidInput',
                                        'Trailing mailbox staging probe must request zero bytes.',
                                    );
                                }
                                return undefined;
                            }
                            const descriptor = chunkDescriptors[chunkIndex];
                            const descriptorByteLength =
                                expectedChunkByteLength(
                                    totalByteLength,
                                    chunkCount,
                                    chunkIndex,
                                );
                            if (
                                descriptor === undefined ||
                                !Number.isSafeInteger(chunkIndex) ||
                                chunkIndex < 0 ||
                                expectedByteLength !== descriptorByteLength
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidInput',
                                    'Mailbox staging pull does not match its published descriptor.',
                                );
                            }
                            const manifest =
                                await readStagingManifest(envelopeHash);
                            if (
                                manifest === undefined ||
                                manifest.record.publicationIdentifier !==
                                    publicationIdentifier ||
                                manifest.record.chunkDescriptors[chunkIndex]
                                    ?.digest !== descriptor.digest
                            ) {
                                throw new AuthenticatedMailboxStorageError(
                                    'AuthenticationFailed',
                                    'Mailbox staging manifest changed before chunk reread.',
                                );
                            }

                            return readChunk({
                                descriptor,
                                expectedByteLength: descriptorByteLength,
                                logicalRecordKey: stagingChunkKey({
                                    chunkIndex,
                                    envelopeHash,
                                    publicationIdentifier,
                                }),
                                operationDomain: stagingChunkOperationDomain,
                            });
                        },
                        dispose: async () => {
                            if (state === 'disposed') {
                                return;
                            }
                            if (state === 'busy') {
                                throw new AuthenticatedMailboxStorageError(
                                    'InvalidState',
                                    'Mailbox staging lease cannot dispose during another operation.',
                                );
                            }
                            try {
                                if (
                                    prepared ||
                                    state === 'sealed' ||
                                    state === 'failed'
                                ) {
                                    await disposePreparedRecords();
                                }
                                state = 'disposed';
                                releaseLease();
                            } catch (error) {
                                state = 'failed';
                                releaseLease();
                                throw asStorageError(error);
                            }
                        },
                    }),
                );
            } catch (error) {
                return Promise.reject(asStorageError(error));
            }
        },
    });

    return Object.freeze({
        inboundSlotAuthority,
        outboundCache,
        stagingBoundary,
    });
};
