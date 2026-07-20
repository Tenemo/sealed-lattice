import type {
    AuthenticatedMailboxPlaintextSinkBoundary,
    AuthenticatedMailboxProducerSlot,
    SetupMailboxSlot,
} from '@sealed-lattice/crypto';
import {
    isProtocolHash,
    recipientPrivateVssShareMailboxPayloadType,
    type ProtocolHash,
} from '@sealed-lattice/types';
import type {
    AggregateThresholdShareAuthenticatedRecipientConsumer,
    AggregateThresholdShareRecipientAuthority,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedMailboxStorageError,
    normalizeProducerSlot,
    producerSlotsEqual,
    requireProtocolHash,
    type AuthenticatedMailboxStorageLimits,
    type StoredProducerSlot,
} from '../authenticated-mailbox-storage/records.js';
import type { RuntimeRecordProtection } from '../authenticated-runtime-record.js';
import type { UntrustedStorageTransactionStore } from '../untrusted-storage-transaction-store.js';

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;
const publicationIdentifierPattern = /^[0-9a-f]{64}$/u;
const participantIdentityPattern = /^[0-9a-f]{128}$/u;

export const recipientVssPlaintextRecordVersion = 1;
export const recipientVssPlaintextJournalOperationDomain =
    'sealed-lattice/authenticated-mailbox/recipient-vss-plaintext-journal/v1';
export const recipientVssPlaintextManifestOperationDomain =
    'sealed-lattice/authenticated-mailbox/recipient-vss-plaintext-manifest/v1';
export const recipientVssPlaintextChunkOperationDomain =
    'sealed-lattice/authenticated-mailbox/recipient-vss-plaintext-chunk/v1';

export type RecipientVssAuthenticatedPlaintextConsumer =
    AggregateThresholdShareAuthenticatedRecipientConsumer;

export type RecipientVssAuthenticatedMailboxPlaintextSink = Readonly<{
    plaintextSinkBoundary: AuthenticatedMailboxPlaintextSinkBoundary;
}>;

export type RecipientVssAuthenticatedMailboxPlaintextSinkConfiguration =
    Readonly<{
        authority: AggregateThresholdShareRecipientAuthority;
        expectedSetupMailboxSlot: SetupMailboxSlot;
        expectedSetupMailboxSlotHash: ProtocolHash;
        limits: AuthenticatedMailboxStorageLimits;
        protection: RuntimeRecordProtection;
        store: UntrustedStorageTransactionStore;
    }>;

export type RecipientVssAuthenticatedMailboxPlaintextSinkInternalConfiguration =
    Omit<
        RecipientVssAuthenticatedMailboxPlaintextSinkConfiguration,
        'authority'
    > &
        Readonly<{
            consumer: RecipientVssAuthenticatedPlaintextConsumer;
        }>;

export type StoredRecipientVssPlaintextJournal = Readonly<{
    envelopeHash: ProtocolHash;
    plaintextByteLength: number;
    producerSlot: StoredProducerSlot;
    publicationIdentifier: string;
    recordVersion: number;
    setupMailboxSlotHash: ProtocolHash;
}>;

export type StoredRecipientVssPlaintextManifest =
    StoredRecipientVssPlaintextJournal &
        Readonly<{
            disposition: 'committed' | 'prepared';
        }>;

export type OpenedStoredRecipientVssRecord<RecordValue> = Readonly<{
    record: RecordValue;
    sealedBytes: Uint8Array;
}>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

const encodeCanonicalJson = (value: unknown): Uint8Array =>
    textEncoder.encode(JSON.stringify(value));

const decodeCanonicalJson = (bytes: Uint8Array): unknown => {
    let value: unknown;
    try {
        value = JSON.parse(fatalTextDecoder.decode(bytes));
    } catch (error) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS mailbox plaintext record is not valid JSON.',
            error,
        );
    }
    if (!bytesEqual(bytes, encodeCanonicalJson(value))) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS mailbox plaintext record is not canonically encoded.',
        );
    }
    return value;
};

const requireParticipantIdentity = (value: unknown, label: string): string => {
    if (typeof value !== 'string' || !participantIdentityPattern.test(value)) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            `${label} is not a canonical participant identity.`,
        );
    }
    return value;
};

const requireProducerSequence = (value: unknown): string => {
    if (
        typeof value !== 'string' ||
        value.length > 20 ||
        !canonicalUnsignedDecimalPattern.test(value) ||
        BigInt(value) > maximumUnsigned64
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS plaintext record has a noncanonical producer sequence.',
        );
    }
    return value;
};

const decodeStoredProducerSlot = (value: unknown): StoredProducerSlot => {
    if (
        !isRecord(value) ||
        value.payloadType !== recipientPrivateVssShareMailboxPayloadType
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS plaintext record has a malformed producer slot.',
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
        producerSequence: requireProducerSequence(value.producerSequence),
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

const requirePublicationIdentifier = (value: unknown): string => {
    if (
        typeof value !== 'string' ||
        !publicationIdentifierPattern.test(value)
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS plaintext publication identifier is malformed.',
        );
    }
    return value;
};

const requirePositiveSafeInteger = (value: unknown, label: string): number => {
    if (!Number.isSafeInteger(value) || Number(value) <= 0) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            `${label} is not a positive safe integer.`,
        );
    }
    return Number(value);
};

const decodeJournalFields = (
    value: Record<string, unknown>,
): StoredRecipientVssPlaintextJournal => {
    if (value.recordVersion !== recipientVssPlaintextRecordVersion) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS plaintext record has an unsupported version.',
        );
    }
    return Object.freeze({
        envelopeHash: requireProtocolHash(value.envelopeHash, 'envelopeHash'),
        plaintextByteLength: requirePositiveSafeInteger(
            value.plaintextByteLength,
            'Recipient VSS plaintext byte length',
        ),
        producerSlot: decodeStoredProducerSlot(value.producerSlot),
        publicationIdentifier: requirePublicationIdentifier(
            value.publicationIdentifier,
        ),
        recordVersion: recipientVssPlaintextRecordVersion,
        setupMailboxSlotHash: requireProtocolHash(
            value.setupMailboxSlotHash,
            'setupMailboxSlotHash',
        ),
    });
};

export const encodeRecipientVssPlaintextJournal = (
    record: StoredRecipientVssPlaintextJournal,
): Uint8Array => encodeCanonicalJson(record);

export const decodeRecipientVssPlaintextJournal = (
    bytes: Uint8Array,
): StoredRecipientVssPlaintextJournal => {
    const value = decodeCanonicalJson(bytes);
    if (!isRecord(value)) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS plaintext journal has a noncanonical shape.',
        );
    }
    return decodeJournalFields(value);
};

export const encodeRecipientVssPlaintextManifest = (
    record: StoredRecipientVssPlaintextManifest,
): Uint8Array => encodeCanonicalJson(record);

export const decodeRecipientVssPlaintextManifest = (
    bytes: Uint8Array,
): StoredRecipientVssPlaintextManifest => {
    const value = decodeCanonicalJson(bytes);
    if (
        !isRecord(value) ||
        (value.disposition !== 'committed' && value.disposition !== 'prepared')
    ) {
        throw new AuthenticatedMailboxStorageError(
            'AuthenticationFailed',
            'A recipient VSS plaintext manifest has a noncanonical shape.',
        );
    }
    return Object.freeze({
        ...decodeJournalFields(value),
        disposition: value.disposition,
    });
};

export const recipientVssPlaintextManifestKey = (
    envelopeHash: ProtocolHash,
): string => `mailbox/recipient-vss/plaintext/manifest/${envelopeHash}`;

export const recipientVssPlaintextJournalKey = (
    envelopeHash: ProtocolHash,
): string => `mailbox/recipient-vss/plaintext/journal/${envelopeHash}`;

export const recipientVssPlaintextChunkKey = (input: {
    chunkIndex: number;
    envelopeHash: ProtocolHash;
    publicationIdentifier: string;
}): string =>
    `mailbox/recipient-vss/plaintext/chunk/${input.envelopeHash}/${input.publicationIdentifier}/${String(input.chunkIndex)}`;

export const copyExpectedSetupMailboxSlot = (
    value: SetupMailboxSlot,
): SetupMailboxSlot => {
    if (
        typeof value !== 'object' ||
        value === null ||
        !isProtocolHash(value.suiteId) ||
        !isProtocolHash(value.ceremonyContextHash) ||
        !isProtocolHash(value.actionContextHash) ||
        !isProtocolHash(value.rosterHash) ||
        !isProtocolHash(value.sourceParticipantId) ||
        !isProtocolHash(value.recipientParticipantId) ||
        typeof value.producerSequence !== 'string' ||
        value.producerSequence.length > 20 ||
        !canonicalUnsignedDecimalPattern.test(value.producerSequence) ||
        BigInt(value.producerSequence) > maximumUnsigned64 ||
        value.payloadType !== recipientPrivateVssShareMailboxPayloadType ||
        !isProtocolHash(value.statementHash) ||
        !Array.isArray(value.orderedMaterialRoots) ||
        value.orderedMaterialRoots.length === 0 ||
        !value.orderedMaterialRoots.every(isProtocolHash)
    ) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            'The expected recipient VSS setup-mailbox slot is malformed.',
        );
    }
    return Object.freeze({
        actionContextHash: value.actionContextHash,
        ceremonyContextHash: value.ceremonyContextHash,
        orderedMaterialRoots: Object.freeze([...value.orderedMaterialRoots]),
        payloadType: value.payloadType,
        producerSequence: value.producerSequence,
        recipientParticipantId: value.recipientParticipantId,
        rosterHash: value.rosterHash,
        sourceParticipantId: value.sourceParticipantId,
        statementHash: value.statementHash,
        suiteId: value.suiteId,
    });
};

export const producerSlotFromSetupMailboxSlot = (
    value: SetupMailboxSlot,
): StoredProducerSlot =>
    normalizeProducerSlot({
        actionContextHash: value.actionContextHash,
        ceremonyContextHash: value.ceremonyContextHash,
        payloadType: value.payloadType,
        producerSequence: value.producerSequence,
        recipientParticipantId: value.recipientParticipantId,
        rosterHash: value.rosterHash,
        sourceParticipantId: value.sourceParticipantId,
        suiteId: value.suiteId,
    });

export const recipientVssPlaintextRecordMatches = (input: {
    envelopeHash: ProtocolHash;
    expectedProducerSlot: StoredProducerSlot;
    expectedSetupMailboxSlotHash: ProtocolHash;
    plaintextByteLength: number;
    record: StoredRecipientVssPlaintextJournal;
}): boolean =>
    input.record.envelopeHash === input.envelopeHash &&
    input.record.plaintextByteLength === input.plaintextByteLength &&
    input.record.setupMailboxSlotHash === input.expectedSetupMailboxSlotHash &&
    producerSlotsEqual(input.record.producerSlot, input.expectedProducerSlot);

export const requireMatchingReservedProducerSlot = (
    value: AuthenticatedMailboxProducerSlot,
    expected: StoredProducerSlot,
): StoredProducerSlot => {
    const normalized = normalizeProducerSlot(value);
    if (!producerSlotsEqual(normalized, expected)) {
        throw new AuthenticatedMailboxStorageError(
            'InvalidInput',
            'The authenticated mailbox producer slot does not match the recipient VSS delivery.',
        );
    }
    return normalized;
};
