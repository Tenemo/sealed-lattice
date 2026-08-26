import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';

import {
    AuthenticatedRuntimeRecordError,
    bytesEqual,
    copyBoundedBytes,
    copyExactBytes,
    mapStorageError,
    readRuntimeRecord,
    runtimeRecordEnvelopeOverheadByteLength,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
} from './authenticated-runtime-record.js';
import { AuthenticatedStorageRecencyCoordinator } from './authenticated-storage-recency.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const receiptCustodyRecordMagic = Uint8Array.of(0x53, 0x4c, 0x52, 0x43);
const receiptCustodyRecordVersion = 1;
const reservedRecordKind = 1;
const completedRecordKind = 2;
const hashByteLength = 64;
const signatureRandomnessByteLength = 32;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const receiptCustodyOperationDomain =
    'sealed-lattice/runtime/seed-recipient-receipt-record/v1';

export type SeedRecipientReceiptCustodyContext = Readonly<{
    parameterIdentity: Uint8Array;
    participantCount: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    recipientPosition: number;
    rootTerminalIdentity: Uint8Array;
}>;

export type SeedRecipientReceiptCustodyLimits = Readonly<{
    maximumAuthenticatedInventoryBodyByteLength: number;
    maximumLocalSeedCustodySegmentByteLength: number;
    maximumReceiptEnvelopeByteLength: number;
    maximumReceiptIntentByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

export type PreparedSeedRecipientReceiptInventory = Readonly<{
    authenticatedInventoryBodyBytes: Uint8Array;
    authenticatedInventoryIdentity: Uint8Array;
    localSeedCustodySegments: readonly Uint8Array[];
    receiptIntentBytes: Uint8Array;
    receiptIntentIdentity: Uint8Array;
}>;

export type SeedRecipientReceiptProductionInput = Readonly<{
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    signatureRandomness: Uint8Array;
}>;

export type SeedRecipientReceiptValidationInput = Readonly<{
    context: SeedRecipientReceiptCustodyContext;
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    receiptEnvelopeBytes?: Uint8Array;
}>;

export type SeedRecipientReceiptCustodyKernel<
    AuthenticatedInventory extends object,
> = Readonly<{
    prepare(
        authenticatedInventory: AuthenticatedInventory,
    ):
        | Promise<PreparedSeedRecipientReceiptInventory>
        | PreparedSeedRecipientReceiptInventory;
    produce(
        input: SeedRecipientReceiptProductionInput,
    ): Promise<Uint8Array> | Uint8Array;
    validate(input: SeedRecipientReceiptValidationInput): Promise<void> | void;
}>;

/**
 * Exact public receipt carrier retained for byte-identical publication replay.
 *
 * This output is inert. It is not a complete receipt inventory, receipt
 * terminal, seed-combination capability, coin-opening capability, burn result,
 * or preparation-continuation capability.
 */
type RetainedSeedRecipientReceiptPublication = Readonly<{
    receiptEnvelopeBytes: Uint8Array;
}>;

type SeedRecipientReceiptCustodyRecordByteLengths = Readonly<{
    completedCiphertextByteLength: number;
    completedPlaintextByteLength: number;
    copyOnWriteCiphertextOverlapByteLength: number;
    reservationCiphertextByteLength: number;
    reservationPlaintextByteLength: number;
}>;

type ReservedSeedRecipientReceiptRecord = Readonly<{
    context: SeedRecipientReceiptCustodyContext;
    kind: 'reserved';
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    signatureRandomness: Uint8Array;
}>;

type CompletedSeedRecipientReceiptRecord = Readonly<{
    context: SeedRecipientReceiptCustodyContext;
    kind: 'completed';
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    receiptEnvelopeBytes: Uint8Array;
}>;

type SeedRecipientReceiptRecord =
    | ReservedSeedRecipientReceiptRecord
    | CompletedSeedRecipientReceiptRecord;

type OpenedSeedRecipientReceiptRecord = Readonly<{
    record: SeedRecipientReceiptRecord;
    sealedBytes: Uint8Array;
}>;

/**
 * Exact authenticated predecessor bytes admitted only for the local/global
 * master transition. The caller must erase both arrays after the transition.
 */
export type CompletedSeedRecipientReceiptCustodyForMasterJoin = Readonly<{
    recordBytes: Uint8Array;
    recordKey: string;
    sealedBytes: Uint8Array;
}>;

export const snapshotSeedRecipientReceiptCustodyLimitsForMasterJoin = (
    value: unknown,
): SeedRecipientReceiptCustodyLimits => copyLimits(value);

const snapshotDataProperty = (
    container: unknown,
    propertyName: string,
    containerName: string,
): unknown => {
    if (
        container === null ||
        (typeof container !== 'object' && typeof container !== 'function')
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName} must be an object.`,
        );
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
        descriptor = Object.getOwnPropertyDescriptor(container, propertyName);
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must be an ordinary data property.`,
            error,
        );
    }
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const requireSafeInteger = (
    value: unknown,
    minimum: number,
    maximum: number,
    label: string,
    code:
        | 'AuthenticationFailed'
        | 'InvalidConfiguration'
        | 'InvalidInput' = 'InvalidInput',
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < minimum ||
        value > maximum
    ) {
        throw new AuthenticatedRuntimeRecordError(
            code,
            `${label} is outside the supported integer range.`,
        );
    }
    return value;
};

const checkedAdd = (left: number, right: number, label: string): number => {
    const result = left + right;
    if (!Number.isSafeInteger(result) || result > unsigned32Maximum) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the local record length range.`,
        );
    }
    return result;
};

const checkedMultiply = (
    left: number,
    right: number,
    label: string,
): number => {
    const result = left * right;
    if (!Number.isSafeInteger(result) || result > unsigned32Maximum) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the local record length range.`,
        );
    }
    return result;
};

const sumByteLengths = (
    byteLengths: readonly number[],
    label: string,
): number =>
    byteLengths.reduce(
        (total, byteLength) => checkedAdd(total, byteLength, label),
        0,
    );

const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const concatenateBytes = (
    parts: readonly Uint8Array[],
    expectedByteLength: number,
): Uint8Array => {
    const output = new Uint8Array(expectedByteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    if (offset !== expectedByteLength) {
        output.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Seed-recipient receipt custody encoded an unexpected byte length.',
        );
    }
    return output;
};

const copyNonemptyBoundedBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    const bytes = copyBoundedBytes(value, maximumByteLength, label);
    if (bytes.byteLength === 0) {
        bytes.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must not be empty.`,
        );
    }
    return bytes;
};

const copyContext = (value: unknown): SeedRecipientReceiptCustodyContext => {
    const participantCount = requireSafeInteger(
        snapshotDataProperty(value, 'participantCount', 'context'),
        configurableParticipantCountRange.minimum,
        configurableParticipantCountRange.maximum,
        'context.participantCount',
        'InvalidConfiguration',
    );
    return Object.freeze({
        parameterIdentity: copyExactBytes(
            snapshotDataProperty(value, 'parameterIdentity', 'context'),
            hashByteLength,
            'context.parameterIdentity',
        ),
        participantCount,
        preparationAttemptOrdinal: requireSafeInteger(
            snapshotDataProperty(value, 'preparationAttemptOrdinal', 'context'),
            0,
            unsigned16Maximum,
            'context.preparationAttemptOrdinal',
            'InvalidConfiguration',
        ),
        preparationContextIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'preparationContextIdentity',
                'context',
            ),
            hashByteLength,
            'context.preparationContextIdentity',
        ),
        recipientPosition: requireSafeInteger(
            snapshotDataProperty(value, 'recipientPosition', 'context'),
            0,
            participantCount - 1,
            'context.recipientPosition',
            'InvalidConfiguration',
        ),
        rootTerminalIdentity: copyExactBytes(
            snapshotDataProperty(value, 'rootTerminalIdentity', 'context'),
            hashByteLength,
            'context.rootTerminalIdentity',
        ),
    });
};

const copyLimits = (value: unknown): SeedRecipientReceiptCustodyLimits => {
    const readByteLimit = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(value, propertyName, 'limits'),
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            `limits.${propertyName}`,
            'InvalidConfiguration',
        );
    const limits = Object.freeze({
        maximumAuthenticatedInventoryBodyByteLength: readByteLimit(
            'maximumAuthenticatedInventoryBodyByteLength',
        ),
        maximumLocalSeedCustodySegmentByteLength: readByteLimit(
            'maximumLocalSeedCustodySegmentByteLength',
        ),
        maximumReceiptEnvelopeByteLength: readByteLimit(
            'maximumReceiptEnvelopeByteLength',
        ),
        maximumReceiptIntentByteLength: readByteLimit(
            'maximumReceiptIntentByteLength',
        ),
        transactionLifetimeMilliseconds: requireSafeInteger(
            snapshotDataProperty(
                value,
                'transactionLifetimeMilliseconds',
                'limits',
            ),
            1,
            Number.MAX_SAFE_INTEGER,
            'limits.transactionLifetimeMilliseconds',
            'InvalidConfiguration',
        ),
    });
    const maximumSegmentCount = configurableParticipantCountRange.maximum - 1;
    const maximumSharedPlaintextByteLength = sumByteLengths(
        [
            commonRecordPrefixByteLength(maximumSegmentCount),
            limits.maximumAuthenticatedInventoryBodyByteLength,
            limits.maximumReceiptIntentByteLength,
            checkedMultiply(
                maximumSegmentCount,
                limits.maximumLocalSeedCustodySegmentByteLength,
                'Maximum local seed custody corpus',
            ),
        ],
        'Maximum seed-recipient receipt custody record',
    );
    const maximumReservationPlaintextByteLength = checkedAdd(
        maximumSharedPlaintextByteLength,
        signatureRandomnessByteLength,
        'Maximum seed-recipient receipt reservation',
    );
    const maximumCompletedPlaintextByteLength = sumByteLengths(
        [
            maximumSharedPlaintextByteLength,
            4,
            limits.maximumReceiptEnvelopeByteLength,
        ],
        'Maximum seed-recipient completed receipt record',
    );
    if (
        maximumReservationPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        maximumCompletedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-recipient receipt custody limits exceed the absolute copied-buffer bound.',
        );
    }
    return limits;
};

const commonRecordPrefixByteLength = (segmentCount: number): number =>
    sumByteLengths(
        [
            receiptCustodyRecordMagic.byteLength,
            2,
            1,
            hashByteLength * 5,
            2 * 3,
            4 * 2,
            2,
            checkedMultiply(
                segmentCount,
                4,
                'Local seed custody segment-length table',
            ),
        ],
        'Seed-recipient receipt record prefix',
    );

export const deriveSeedRecipientReceiptCustodyRecordByteLengths = (input: {
    authenticatedInventoryBodyByteLength: number;
    localSeedCustodySegmentByteLengths: readonly number[];
    receiptEnvelopeByteLength: number;
    receiptIntentByteLength: number;
}): SeedRecipientReceiptCustodyRecordByteLengths => {
    const authenticatedInventoryBodyByteLength = requireSafeInteger(
        snapshotDataProperty(
            input,
            'authenticatedInventoryBodyByteLength',
            'input',
        ),
        1,
        unsigned32Maximum,
        'input.authenticatedInventoryBodyByteLength',
    );
    const receiptIntentByteLength = requireSafeInteger(
        snapshotDataProperty(input, 'receiptIntentByteLength', 'input'),
        1,
        unsigned32Maximum,
        'input.receiptIntentByteLength',
    );
    const receiptEnvelopeByteLength = requireSafeInteger(
        snapshotDataProperty(input, 'receiptEnvelopeByteLength', 'input'),
        1,
        unsigned32Maximum,
        'input.receiptEnvelopeByteLength',
    );
    const segmentByteLengthsValue = snapshotDataProperty(
        input,
        'localSeedCustodySegmentByteLengths',
        'input',
    );
    if (!Array.isArray(segmentByteLengthsValue)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'input.localSeedCustodySegmentByteLengths must be an array.',
        );
    }
    const segmentCount = requireSafeInteger(
        snapshotDataProperty(
            segmentByteLengthsValue,
            'length',
            'input.localSeedCustodySegmentByteLengths',
        ),
        1,
        unsigned16Maximum,
        'input.localSeedCustodySegmentByteLengths.length',
    );
    const segmentByteLengths = Array.from(
        { length: segmentCount },
        (_unused, segmentIndex) =>
            requireSafeInteger(
                snapshotDataProperty(
                    segmentByteLengthsValue,
                    String(segmentIndex),
                    'input.localSeedCustodySegmentByteLengths',
                ),
                1,
                unsigned32Maximum,
                `input.localSeedCustodySegmentByteLengths[${segmentIndex}]`,
            ),
    );
    const sharedPlaintextByteLength = sumByteLengths(
        [
            commonRecordPrefixByteLength(segmentCount),
            authenticatedInventoryBodyByteLength,
            receiptIntentByteLength,
            sumByteLengths(
                segmentByteLengths,
                'Local seed custody corpus byte length',
            ),
        ],
        'Seed-recipient receipt shared record bytes',
    );
    const reservationPlaintextByteLength = checkedAdd(
        sharedPlaintextByteLength,
        signatureRandomnessByteLength,
        'Seed-recipient receipt reservation record',
    );
    const completedPlaintextByteLength = sumByteLengths(
        [sharedPlaintextByteLength, 4, receiptEnvelopeByteLength],
        'Seed-recipient completed receipt record',
    );
    const reservationCiphertextByteLength = checkedAdd(
        reservationPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-recipient receipt reservation ciphertext',
    );
    const completedCiphertextByteLength = checkedAdd(
        completedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-recipient receipt completed ciphertext',
    );
    return Object.freeze({
        completedCiphertextByteLength,
        completedPlaintextByteLength,
        copyOnWriteCiphertextOverlapByteLength: checkedAdd(
            reservationCiphertextByteLength,
            completedCiphertextByteLength,
            'Seed-recipient receipt copy-on-write ciphertext overlap',
        ),
        reservationCiphertextByteLength,
        reservationPlaintextByteLength,
    });
};

const copyPreparedInventory = (
    value: unknown,
    context: SeedRecipientReceiptCustodyContext,
    limits: SeedRecipientReceiptCustodyLimits,
): PreparedSeedRecipientReceiptInventory => {
    const segmentsValue = snapshotDataProperty(
        value,
        'localSeedCustodySegments',
        'preparedInventory',
    );
    if (!Array.isArray(segmentsValue)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'preparedInventory.localSeedCustodySegments must be an array.',
        );
    }
    const expectedSegmentCount = context.participantCount - 1;
    const segmentCount = requireSafeInteger(
        snapshotDataProperty(
            segmentsValue,
            'length',
            'preparedInventory.localSeedCustodySegments',
        ),
        expectedSegmentCount,
        expectedSegmentCount,
        'preparedInventory.localSeedCustodySegments.length',
    );
    const prepared = Object.freeze({
        authenticatedInventoryBodyBytes: copyNonemptyBoundedBytes(
            snapshotDataProperty(
                value,
                'authenticatedInventoryBodyBytes',
                'preparedInventory',
            ),
            limits.maximumAuthenticatedInventoryBodyByteLength,
            'preparedInventory.authenticatedInventoryBodyBytes',
        ),
        authenticatedInventoryIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'authenticatedInventoryIdentity',
                'preparedInventory',
            ),
            hashByteLength,
            'preparedInventory.authenticatedInventoryIdentity',
        ),
        localSeedCustodySegments: Object.freeze(
            Array.from({ length: segmentCount }, (_unused, segmentIndex) =>
                copyNonemptyBoundedBytes(
                    snapshotDataProperty(
                        segmentsValue,
                        String(segmentIndex),
                        'preparedInventory.localSeedCustodySegments',
                    ),
                    limits.maximumLocalSeedCustodySegmentByteLength,
                    `preparedInventory.localSeedCustodySegments[${segmentIndex}]`,
                ),
            ),
        ),
        receiptIntentBytes: copyNonemptyBoundedBytes(
            snapshotDataProperty(
                value,
                'receiptIntentBytes',
                'preparedInventory',
            ),
            limits.maximumReceiptIntentByteLength,
            'preparedInventory.receiptIntentBytes',
        ),
        receiptIntentIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'receiptIntentIdentity',
                'preparedInventory',
            ),
            hashByteLength,
            'preparedInventory.receiptIntentIdentity',
        ),
    });
    const byteLengths = deriveSeedRecipientReceiptCustodyRecordByteLengths({
        authenticatedInventoryBodyByteLength:
            prepared.authenticatedInventoryBodyBytes.byteLength,
        localSeedCustodySegmentByteLengths:
            prepared.localSeedCustodySegments.map(
                (segment) => segment.byteLength,
            ),
        receiptEnvelopeByteLength: limits.maximumReceiptEnvelopeByteLength,
        receiptIntentByteLength: prepared.receiptIntentBytes.byteLength,
    });
    if (
        byteLengths.reservationPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        byteLengths.completedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        destroyPreparedInventory(prepared);
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Seed-recipient receipt custody record exceeds the absolute copied-buffer bound.',
        );
    }
    return prepared;
};

const destroyContext = (
    context: SeedRecipientReceiptCustodyContext | undefined,
): void => {
    context?.parameterIdentity.fill(0);
    context?.preparationContextIdentity.fill(0);
    context?.rootTerminalIdentity.fill(0);
};

const destroyPreparedInventory = (
    prepared: PreparedSeedRecipientReceiptInventory | undefined,
): void => {
    prepared?.authenticatedInventoryBodyBytes.fill(0);
    prepared?.authenticatedInventoryIdentity.fill(0);
    prepared?.localSeedCustodySegments.forEach((segment) => segment.fill(0));
    prepared?.receiptIntentBytes.fill(0);
    prepared?.receiptIntentIdentity.fill(0);
};

const contextsEqual = (
    left: SeedRecipientReceiptCustodyContext,
    right: SeedRecipientReceiptCustodyContext,
): boolean =>
    left.participantCount === right.participantCount &&
    left.preparationAttemptOrdinal === right.preparationAttemptOrdinal &&
    left.recipientPosition === right.recipientPosition &&
    bytesEqual(left.parameterIdentity, right.parameterIdentity) &&
    bytesEqual(
        left.preparationContextIdentity,
        right.preparationContextIdentity,
    ) &&
    bytesEqual(left.rootTerminalIdentity, right.rootTerminalIdentity);

const preparedInventoriesEqual = (
    left: PreparedSeedRecipientReceiptInventory,
    right: PreparedSeedRecipientReceiptInventory,
): boolean =>
    bytesEqual(
        left.authenticatedInventoryBodyBytes,
        right.authenticatedInventoryBodyBytes,
    ) &&
    bytesEqual(
        left.authenticatedInventoryIdentity,
        right.authenticatedInventoryIdentity,
    ) &&
    bytesEqual(left.receiptIntentBytes, right.receiptIntentBytes) &&
    bytesEqual(left.receiptIntentIdentity, right.receiptIntentIdentity) &&
    left.localSeedCustodySegments.length ===
        right.localSeedCustodySegments.length &&
    left.localSeedCustodySegments.every((segment, segmentIndex) =>
        bytesEqual(segment, right.localSeedCustodySegments[segmentIndex]),
    );

const logicalRecordKey = (
    context: SeedRecipientReceiptCustodyContext,
): string =>
    `seed-mailbox/recipient-receipt/${context.preparationAttemptOrdinal
        .toString(10)
        .padStart(5, '0')}/${context.recipientPosition
        .toString(10)
        .padStart(5, '0')}`;

const encodeRecord = (record: SeedRecipientReceiptRecord): Uint8Array => {
    const prepared = record.preparedInventory;
    const byteLengths = deriveSeedRecipientReceiptCustodyRecordByteLengths({
        authenticatedInventoryBodyByteLength:
            prepared.authenticatedInventoryBodyBytes.byteLength,
        localSeedCustodySegmentByteLengths:
            prepared.localSeedCustodySegments.map(
                (segment) => segment.byteLength,
            ),
        receiptEnvelopeByteLength:
            record.kind === 'completed'
                ? record.receiptEnvelopeBytes.byteLength
                : 1,
        receiptIntentByteLength: prepared.receiptIntentBytes.byteLength,
    });
    const sharedParts = [
        receiptCustodyRecordMagic,
        unsigned16LittleEndian(receiptCustodyRecordVersion),
        Uint8Array.of(
            record.kind === 'reserved'
                ? reservedRecordKind
                : completedRecordKind,
        ),
        record.context.parameterIdentity,
        record.context.preparationContextIdentity,
        record.context.rootTerminalIdentity,
        unsigned16LittleEndian(record.context.preparationAttemptOrdinal),
        unsigned16LittleEndian(record.context.participantCount),
        unsigned16LittleEndian(record.context.recipientPosition),
        prepared.authenticatedInventoryIdentity,
        prepared.receiptIntentIdentity,
        unsigned32LittleEndian(
            prepared.authenticatedInventoryBodyBytes.byteLength,
        ),
        unsigned32LittleEndian(prepared.receiptIntentBytes.byteLength),
        unsigned16LittleEndian(prepared.localSeedCustodySegments.length),
        ...prepared.localSeedCustodySegments.map((segment) =>
            unsigned32LittleEndian(segment.byteLength),
        ),
        prepared.authenticatedInventoryBodyBytes,
        prepared.receiptIntentBytes,
        ...prepared.localSeedCustodySegments,
    ];
    if (record.kind === 'reserved') {
        return concatenateBytes(
            [...sharedParts, record.signatureRandomness],
            byteLengths.reservationPlaintextByteLength,
        );
    }
    return concatenateBytes(
        [
            ...sharedParts,
            unsigned32LittleEndian(record.receiptEnvelopeBytes.byteLength),
            record.receiptEnvelopeBytes,
        ],
        byteLengths.completedPlaintextByteLength,
    );
};

class BoundedRecordCursor {
    readonly #bytes: Uint8Array;
    #offset = 0;

    public constructor(bytes: Uint8Array) {
        this.#bytes = bytes;
    }

    public readExact(byteLength: number, label: string): Uint8Array {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > this.#bytes.byteLength - this.#offset
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `Seed-recipient receipt custody record ends within ${label}.`,
            );
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;
        return value;
    }

    public readUnsigned8(label: string): number {
        const bytes = this.readExact(1, label);
        try {
            return bytes[0] ?? 0;
        } finally {
            bytes.fill(0);
        }
    }

    public readUnsigned16(label: string): number {
        const bytes = this.readExact(2, label);
        try {
            return new DataView(
                bytes.buffer,
                bytes.byteOffset,
                bytes.byteLength,
            ).getUint16(0, true);
        } finally {
            bytes.fill(0);
        }
    }

    public readUnsigned32(label: string): number {
        const bytes = this.readExact(4, label);
        try {
            return new DataView(
                bytes.buffer,
                bytes.byteOffset,
                bytes.byteLength,
            ).getUint32(0, true);
        } finally {
            bytes.fill(0);
        }
    }

    public requireComplete(): void {
        if (this.#offset !== this.#bytes.byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-recipient receipt custody record has trailing bytes.',
            );
        }
    }
}

const decodeRecord = (
    plaintext: Uint8Array,
    limits: SeedRecipientReceiptCustodyLimits,
): SeedRecipientReceiptRecord => {
    if (
        plaintext.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient receipt custody record exceeds the absolute copied-buffer bound.',
        );
    }
    const cursor = new BoundedRecordCursor(plaintext);
    const magic = cursor.readExact(
        receiptCustodyRecordMagic.byteLength,
        'record magic',
    );
    try {
        if (!bytesEqual(magic, receiptCustodyRecordMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-recipient receipt custody record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (
        cursor.readUnsigned16('record version') !== receiptCustodyRecordVersion
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient receipt custody record has an unsupported version.',
        );
    }
    const recordKind = cursor.readUnsigned8('record kind');
    if (
        recordKind !== reservedRecordKind &&
        recordKind !== completedRecordKind
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient receipt custody record has an invalid kind.',
        );
    }
    const parameterIdentity = cursor.readExact(
        hashByteLength,
        'parameter identity',
    );
    const preparationContextIdentity = cursor.readExact(
        hashByteLength,
        'preparation-context identity',
    );
    const rootTerminalIdentity = cursor.readExact(
        hashByteLength,
        'root-terminal identity',
    );
    const preparationAttemptOrdinal = cursor.readUnsigned16(
        'preparation-attempt ordinal',
    );
    const participantCount = cursor.readUnsigned16('participant count');
    const recipientPosition = cursor.readUnsigned16('recipient position');
    if (
        participantCount < configurableParticipantCountRange.minimum ||
        participantCount > configurableParticipantCountRange.maximum ||
        recipientPosition >= participantCount
    ) {
        parameterIdentity.fill(0);
        preparationContextIdentity.fill(0);
        rootTerminalIdentity.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient receipt custody record has invalid roster coordinates.',
        );
    }
    const authenticatedInventoryIdentity = cursor.readExact(
        hashByteLength,
        'authenticated-inventory identity',
    );
    const receiptIntentIdentity = cursor.readExact(
        hashByteLength,
        'receipt-intent identity',
    );
    const authenticatedInventoryBodyByteLength = requireSafeInteger(
        cursor.readUnsigned32('authenticated-inventory body byte length'),
        1,
        limits.maximumAuthenticatedInventoryBodyByteLength,
        'Stored authenticated-inventory body byte length',
        'AuthenticationFailed',
    );
    const receiptIntentByteLength = requireSafeInteger(
        cursor.readUnsigned32('receipt-intent byte length'),
        1,
        limits.maximumReceiptIntentByteLength,
        'Stored receipt-intent byte length',
        'AuthenticationFailed',
    );
    const expectedSegmentCount = participantCount - 1;
    const segmentCount = requireSafeInteger(
        cursor.readUnsigned16('local seed custody segment count'),
        expectedSegmentCount,
        expectedSegmentCount,
        'Stored local seed custody segment count',
        'AuthenticationFailed',
    );
    const segmentByteLengths = Array.from(
        { length: segmentCount },
        (_unused, segmentIndex) =>
            requireSafeInteger(
                cursor.readUnsigned32(
                    `local seed custody segment ${segmentIndex} byte length`,
                ),
                1,
                limits.maximumLocalSeedCustodySegmentByteLength,
                `Stored local seed custody segment ${segmentIndex} byte length`,
                'AuthenticationFailed',
            ),
    );
    const context = Object.freeze({
        parameterIdentity,
        participantCount,
        preparationAttemptOrdinal,
        preparationContextIdentity,
        recipientPosition,
        rootTerminalIdentity,
    });
    let authenticatedInventoryBodyBytes: Uint8Array | undefined;
    let receiptIntentBytes: Uint8Array | undefined;
    let localSeedCustodySegments: Uint8Array[] | undefined;
    try {
        authenticatedInventoryBodyBytes = cursor.readExact(
            authenticatedInventoryBodyByteLength,
            'authenticated-inventory body',
        );
        receiptIntentBytes = cursor.readExact(
            receiptIntentByteLength,
            'receipt intent',
        );
        localSeedCustodySegments = segmentByteLengths.map(
            (byteLength, segmentIndex) =>
                cursor.readExact(
                    byteLength,
                    `local seed custody segment ${segmentIndex}`,
                ),
        );
        const preparedInventory = Object.freeze({
            authenticatedInventoryBodyBytes,
            authenticatedInventoryIdentity,
            localSeedCustodySegments: Object.freeze(localSeedCustodySegments),
            receiptIntentBytes,
            receiptIntentIdentity,
        });
        authenticatedInventoryBodyBytes = undefined;
        receiptIntentBytes = undefined;
        localSeedCustodySegments = undefined;
        if (recordKind === reservedRecordKind) {
            let signatureRandomness: Uint8Array | undefined;
            try {
                signatureRandomness = cursor.readExact(
                    signatureRandomnessByteLength,
                    'signature randomness',
                );
                cursor.requireComplete();
                if (signatureRandomness.every((byte) => byte === 0)) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Seed-recipient receipt custody record has invalid signature randomness.',
                    );
                }
                const record = Object.freeze({
                    context,
                    kind: 'reserved' as const,
                    preparedInventory,
                    signatureRandomness,
                });
                signatureRandomness = undefined;
                return record;
            } catch (error) {
                destroyPreparedInventory(preparedInventory);
                throw error;
            } finally {
                signatureRandomness?.fill(0);
            }
        }
        let receiptEnvelopeBytes: Uint8Array | undefined;
        try {
            const receiptEnvelopeByteLength = requireSafeInteger(
                cursor.readUnsigned32('receipt-envelope byte length'),
                1,
                limits.maximumReceiptEnvelopeByteLength,
                'Stored receipt-envelope byte length',
                'AuthenticationFailed',
            );
            receiptEnvelopeBytes = cursor.readExact(
                receiptEnvelopeByteLength,
                'receipt envelope',
            );
            cursor.requireComplete();
            const record = Object.freeze({
                context,
                kind: 'completed' as const,
                preparedInventory,
                receiptEnvelopeBytes,
            });
            receiptEnvelopeBytes = undefined;
            return record;
        } catch (error) {
            destroyPreparedInventory(preparedInventory);
            throw error;
        } finally {
            receiptEnvelopeBytes?.fill(0);
        }
    } catch (error) {
        destroyContext(context);
        throw error;
    } finally {
        authenticatedInventoryBodyBytes?.fill(0);
        receiptIntentBytes?.fill(0);
        localSeedCustodySegments?.forEach((segment) => segment.fill(0));
    }
};

const destroyRecord = (
    record: SeedRecipientReceiptRecord | undefined,
): void => {
    if (record === undefined) {
        return;
    }
    destroyContext(record.context);
    destroyPreparedInventory(record.preparedInventory);
    if (record.kind === 'reserved') {
        record.signatureRandomness.fill(0);
    } else {
        record.receiptEnvelopeBytes.fill(0);
    }
};

const readRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: SeedRecipientReceiptCustodyLimits,
): Promise<OpenedSeedRecipientReceiptRecord | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: receiptCustodyOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        return Object.freeze({
            record: decodeRecord(opened.plaintext, limits),
            sealedBytes: opened.sealedBytes.slice(),
        });
    } finally {
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

export const readCompletedSeedRecipientReceiptCustodyForMasterJoin =
    async (input: {
        context: SeedRecipientReceiptCustodyContext;
        limits: SeedRecipientReceiptCustodyLimits;
        protection: RuntimeRecordProtection;
        store: UntrustedStorageTransactionStore;
    }): Promise<
        | CompletedSeedRecipientReceiptCustodyForMasterJoin
        | 'incomplete'
        | undefined
    > => {
        const context = copyContext(input.context);
        const limits = copyLimits(input.limits);
        const recordKey = logicalRecordKey(context);
        const opened = await readRuntimeRecord({
            logicalRecordKey: recordKey,
            operationDomain: receiptCustodyOperationDomain,
            protection: input.protection,
            store: input.store,
        });
        if (opened === undefined) {
            destroyContext(context);
            return undefined;
        }
        let decoded: SeedRecipientReceiptRecord | undefined;
        let canonicalRecordBytes: Uint8Array | undefined;
        try {
            decoded = decodeRecord(opened.plaintext, limits);
            if (!contextsEqual(decoded.context, context)) {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'The seed-recipient receipt predecessor is bound to a different context.',
                );
            }
            if (decoded.kind !== 'completed') {
                return 'incomplete';
            }
            canonicalRecordBytes = encodeRecord(decoded);
            if (!bytesEqual(canonicalRecordBytes, opened.plaintext)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'The seed-recipient receipt predecessor is not canonical.',
                );
            }
            return Object.freeze({
                recordBytes: opened.plaintext.slice(),
                recordKey,
                sealedBytes: opened.sealedBytes.slice(),
            });
        } finally {
            canonicalRecordBytes?.fill(0);
            destroyRecord(decoded);
            destroyContext(context);
            opened.plaintext.fill(0);
            opened.sealedBytes.fill(0);
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
            'Seed-recipient receipt custody failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const commitRecord = async (input: {
    expectedCurrentSealedBytes: Uint8Array | null;
    limits: SeedRecipientReceiptCustodyLimits;
    protection: RuntimeRecordProtection;
    record: SeedRecipientReceiptRecord;
    recordKey: string;
    store: UntrustedStorageTransactionStore;
}): Promise<Uint8Array> => {
    const plaintext = encodeRecord(input.record);
    const transaction = await input.store.beginTransaction({
        lifetimeMilliseconds: input.limits.transactionLifetimeMilliseconds,
    });
    let stagedSealedBytes: Uint8Array | undefined;
    try {
        stagedSealedBytes = await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: input.expectedCurrentSealedBytes,
            logicalRecordKey: input.recordKey,
            operationDomain: receiptCustodyOperationDomain,
            plaintext,
            protection: input.protection,
            transaction,
        });
        await transaction.commit();
        return stagedSealedBytes.slice();
    } catch (error) {
        throw await closeTransactionAfterFailure(transaction, error);
    } finally {
        plaintext.fill(0);
        stagedSealedBytes?.fill(0);
    }
};

const errorHasCode = (error: unknown, code: string): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code;

const copyValidationContext = (
    context: SeedRecipientReceiptCustodyContext,
): SeedRecipientReceiptCustodyContext =>
    Object.freeze({
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        recipientPosition: context.recipientPosition,
        rootTerminalIdentity: context.rootTerminalIdentity.slice(),
    });

const copyPublication = (
    receiptEnvelopeBytes: Uint8Array,
): RetainedSeedRecipientReceiptPublication =>
    Object.freeze({ receiptEnvelopeBytes: receiptEnvelopeBytes.slice() });

/**
 * Owns one alternative-independent recipient receipt slot for an action.
 * Exact local seed custody, the typed kernel's receipt intent, and one internally
 * sampled signing seed are encrypted and recency-anchored before signing. The
 * complete envelope is then atomically retained before publication.
 *
 * The kernel boundary must accept only its own complete authenticated-inventory
 * capability. This class accepts no caller-supplied intent, signature seed, or
 * receipt carrier and constructs no protocol acceptance capability.
 */
export class SeedRecipientReceiptCustody<
    AuthenticatedInventory extends object,
> {
    readonly #context: SeedRecipientReceiptCustodyContext;
    readonly #issuedRandomness = new Set<string>();
    readonly #kernel: SeedRecipientReceiptCustodyKernel<AuthenticatedInventory>;
    readonly #limits: SeedRecipientReceiptCustodyLimits;
    readonly #protection: RuntimeRecordProtection;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        context: SeedRecipientReceiptCustodyContext;
        kernel: SeedRecipientReceiptCustodyKernel<AuthenticatedInventory>;
        limits: SeedRecipientReceiptCustodyLimits;
        protection: RuntimeRecordProtection;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    }) {
        if (
            typeof input.kernel?.prepare !== 'function' ||
            typeof input.kernel?.produce !== 'function' ||
            typeof input.kernel?.validate !== 'function'
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-recipient receipt custody requires a complete kernel boundary.',
            );
        }
        if (
            !(
                input.recencyCoordinator instanceof
                AuthenticatedStorageRecencyCoordinator
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-recipient receipt custody requires an authenticated storage recency coordinator.',
            );
        }
        this.#context = copyContext(input.context);
        this.#kernel = Object.freeze({
            prepare: input.kernel.prepare.bind(input.kernel),
            produce: input.kernel.produce.bind(input.kernel),
            validate: input.kernel.validate.bind(input.kernel),
        });
        this.#limits = copyLimits(input.limits);
        this.#protection = input.protection;
        this.#recencyCoordinator = input.recencyCoordinator;
    }

    public retainForPublication(input: {
        authenticatedInventory: AuthenticatedInventory;
    }): Promise<RetainedSeedRecipientReceiptPublication> {
        const authenticatedInventory = snapshotDataProperty(
            input,
            'authenticatedInventory',
            'input',
        );
        if (
            authenticatedInventory === null ||
            (typeof authenticatedInventory !== 'object' &&
                typeof authenticatedInventory !== 'function')
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'input.authenticatedInventory must be a kernel-owned object.',
            );
        }
        return this.#schedule(() =>
            this.#prepareAndRetain(
                authenticatedInventory as AuthenticatedInventory,
            ),
        );
    }

    public resumeForPublication(): Promise<
        RetainedSeedRecipientReceiptPublication | undefined
    > {
        return this.#schedule(() => this.#resume());
    }

    #schedule<Result>(operation: () => Promise<Result>): Promise<Result> {
        const scheduled = this.#operationTail.then(operation);
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    async #prepareAndRetain(
        authenticatedInventory: AuthenticatedInventory,
    ): Promise<RetainedSeedRecipientReceiptPublication> {
        let prepared: PreparedSeedRecipientReceiptInventory | undefined;
        try {
            let preparationFailed = false;
            let preparationFailure: unknown;
            let preparedValue: unknown;
            try {
                preparedValue = await this.#kernel.prepare(
                    authenticatedInventory,
                );
            } catch (error) {
                preparationFailed = true;
                preparationFailure = error;
            }
            if (preparationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-recipient receipt preparation rejected the authenticated-inventory capability.',
                    preparationFailure,
                );
            }
            prepared = copyPreparedInventory(
                preparedValue,
                this.#context,
                this.#limits,
            );
            await this.#validate(prepared);
            const recordKey = logicalRecordKey(this.#context);
            let opened = await this.#readOpenedRecord(recordKey);
            if (opened === undefined) {
                opened = await this.#reserve(recordKey, prepared);
            }
            return await this.#continueOpened(recordKey, opened, prepared);
        } finally {
            destroyPreparedInventory(prepared);
        }
    }

    async #resume(): Promise<
        RetainedSeedRecipientReceiptPublication | undefined
    > {
        const recordKey = logicalRecordKey(this.#context);
        const opened = await this.#readOpenedRecord(recordKey);
        if (opened === undefined) {
            return undefined;
        }
        return this.#continueOpened(recordKey, opened);
    }

    async #continueOpened(
        recordKey: string,
        opened: OpenedSeedRecipientReceiptRecord,
        expectedPrepared?: PreparedSeedRecipientReceiptInventory,
    ): Promise<RetainedSeedRecipientReceiptPublication> {
        try {
            this.#requireMatchingRecord(opened.record, expectedPrepared);
            if (expectedPrepared === undefined) {
                await this.#validate(opened.record.preparedInventory);
            }
            if (opened.record.kind === 'completed') {
                await this.#validate(
                    opened.record.preparedInventory,
                    opened.record.receiptEnvelopeBytes,
                );
                return copyPublication(opened.record.receiptEnvelopeBytes);
            }
            const receiptEnvelopeBytes = await this.#produce(opened.record);
            try {
                await this.#validate(
                    opened.record.preparedInventory,
                    receiptEnvelopeBytes,
                );
                return await this.#completeReservation({
                    expectedPrepared,
                    receiptEnvelopeBytes,
                    recordKey,
                    reservation: opened.record,
                    sealedReservationBytes: opened.sealedBytes,
                });
            } finally {
                receiptEnvelopeBytes.fill(0);
            }
        } finally {
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
        }
    }

    #requireMatchingRecord(
        record: SeedRecipientReceiptRecord,
        expectedPrepared?: PreparedSeedRecipientReceiptInventory,
    ): void {
        if (
            !contextsEqual(record.context, this.#context) ||
            (expectedPrepared !== undefined &&
                !preparedInventoriesEqual(
                    record.preparedInventory,
                    expectedPrepared,
                ))
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The seed-recipient receipt slot is durably bound to a different authenticated inventory or terminal.',
            );
        }
    }

    async #readOpenedRecord(
        recordKey: string,
    ): Promise<OpenedSeedRecipientReceiptRecord | undefined> {
        return this.#recencyCoordinator.runRead((store) =>
            readRecord(store, this.#protection, recordKey, this.#limits),
        );
    }

    async #reserve(
        recordKey: string,
        prepared: PreparedSeedRecipientReceiptInventory,
    ): Promise<OpenedSeedRecipientReceiptRecord> {
        let signatureRandomness: Uint8Array | undefined;
        try {
            signatureRandomness = sampleRuntimeIdentifier(
                this.#protection,
                this.#issuedRandomness,
                'Seed-recipient ML-DSA signature randomness',
            );
            const reservation: ReservedSeedRecipientReceiptRecord =
                Object.freeze({
                    context: copyValidationContext(this.#context),
                    kind: 'reserved' as const,
                    preparedInventory: copyPreparedInventory(
                        prepared,
                        this.#context,
                        this.#limits,
                    ),
                    signatureRandomness: signatureRandomness.slice(),
                });
            try {
                let sealedBytes: Uint8Array;
                try {
                    sealedBytes = await this.#recencyCoordinator.runMutation(
                        (store) =>
                            commitRecord({
                                expectedCurrentSealedBytes: null,
                                limits: this.#limits,
                                protection: this.#protection,
                                record: reservation,
                                recordKey,
                                store,
                            }),
                    );
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readOpenedRecord(recordKey);
                    if (existing === undefined) {
                        throw error;
                    }
                    this.#requireMatchingRecord(existing.record, prepared);
                    return existing;
                }
                return Object.freeze({
                    record: Object.freeze({
                        context: copyValidationContext(reservation.context),
                        kind: 'reserved' as const,
                        preparedInventory: copyPreparedInventory(
                            reservation.preparedInventory,
                            reservation.context,
                            this.#limits,
                        ),
                        signatureRandomness:
                            reservation.signatureRandomness.slice(),
                    }),
                    sealedBytes,
                });
            } finally {
                destroyRecord(reservation);
            }
        } finally {
            signatureRandomness?.fill(0);
        }
    }

    async #produce(
        reservation: ReservedSeedRecipientReceiptRecord,
    ): Promise<Uint8Array> {
        const productionInput: SeedRecipientReceiptProductionInput =
            Object.freeze({
                preparedInventory: copyPreparedInventory(
                    reservation.preparedInventory,
                    reservation.context,
                    this.#limits,
                ),
                signatureRandomness: reservation.signatureRandomness.slice(),
            });
        let productionFailed = false;
        let productionFailure: unknown;
        let produced: unknown;
        try {
            try {
                produced = await this.#kernel.produce(productionInput);
            } catch (error) {
                productionFailed = true;
                productionFailure = error;
            }
            if (productionFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Seed-recipient receipt production failed before publication.',
                    productionFailure,
                );
            }
            return copyNonemptyBoundedBytes(
                produced,
                this.#limits.maximumReceiptEnvelopeByteLength,
                'receiptEnvelopeBytes',
            );
        } finally {
            destroyPreparedInventory(productionInput.preparedInventory);
            productionInput.signatureRandomness.fill(0);
        }
    }

    async #validate(
        prepared: PreparedSeedRecipientReceiptInventory,
        receiptEnvelopeBytes?: Uint8Array,
    ): Promise<void> {
        const validationContext = copyValidationContext(this.#context);
        const validationInput: SeedRecipientReceiptValidationInput =
            Object.freeze({
                context: validationContext,
                preparedInventory: copyPreparedInventory(
                    prepared,
                    validationContext,
                    this.#limits,
                ),
                ...(receiptEnvelopeBytes === undefined
                    ? {}
                    : { receiptEnvelopeBytes: receiptEnvelopeBytes.slice() }),
            });
        let validationFailed = false;
        let validationFailure: unknown;
        try {
            try {
                await this.#kernel.validate(validationInput);
            } catch (error) {
                validationFailed = true;
                validationFailure = error;
            }
            if (validationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-recipient receipt custody failed kernel validation.',
                    validationFailure,
                );
            }
        } finally {
            destroyContext(validationContext);
            destroyPreparedInventory(validationInput.preparedInventory);
            validationInput.receiptEnvelopeBytes?.fill(0);
        }
    }

    async #completeReservation(input: {
        expectedPrepared?: PreparedSeedRecipientReceiptInventory;
        receiptEnvelopeBytes: Uint8Array;
        recordKey: string;
        reservation: ReservedSeedRecipientReceiptRecord;
        sealedReservationBytes: Uint8Array;
    }): Promise<RetainedSeedRecipientReceiptPublication> {
        const completedRecord: CompletedSeedRecipientReceiptRecord =
            Object.freeze({
                context: copyValidationContext(input.reservation.context),
                kind: 'completed' as const,
                preparedInventory: copyPreparedInventory(
                    input.reservation.preparedInventory,
                    input.reservation.context,
                    this.#limits,
                ),
                receiptEnvelopeBytes: input.receiptEnvelopeBytes.slice(),
            });
        try {
            try {
                const committedSealedBytes =
                    await this.#recencyCoordinator.runMutation((store) =>
                        commitRecord({
                            expectedCurrentSealedBytes:
                                input.sealedReservationBytes,
                            limits: this.#limits,
                            protection: this.#protection,
                            record: completedRecord,
                            recordKey: input.recordKey,
                            store,
                        }),
                    );
                committedSealedBytes.fill(0);
                return copyPublication(completedRecord.receiptEnvelopeBytes);
            } catch (error) {
                if (!errorHasCode(error, 'Conflict')) {
                    throw error;
                }
                const existing = await this.#readOpenedRecord(input.recordKey);
                if (existing === undefined) {
                    throw error;
                }
                try {
                    this.#requireMatchingRecord(
                        existing.record,
                        input.reservation.preparedInventory,
                    );
                    if (
                        existing.record.kind !== 'completed' ||
                        !bytesEqual(
                            existing.record.receiptEnvelopeBytes,
                            input.receiptEnvelopeBytes,
                        )
                    ) {
                        throw new AuthenticatedRuntimeRecordError(
                            'Conflict',
                            'Concurrent seed-recipient receipt completion selected different carrier bytes.',
                        );
                    }
                    await this.#validate(
                        existing.record.preparedInventory,
                        existing.record.receiptEnvelopeBytes,
                    );
                    return copyPublication(
                        existing.record.receiptEnvelopeBytes,
                    );
                } finally {
                    existing.sealedBytes.fill(0);
                    destroyRecord(existing.record);
                }
            }
        } finally {
            destroyRecord(completedRecord);
        }
    }
}
