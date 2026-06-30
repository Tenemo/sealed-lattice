import {
    decryptLocalTrusteeState,
    deriveProtocolHash,
    encryptLocalTrusteeSetupSealedMaterial,
    encryptLocalTrusteeState,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupStateSealedMaterial,
    type LocalTrusteeSetupStateSealedPayload,
    type LocalTrusteeStateStorageDecryptionResult,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    compactVssCommitmentPrivateOpeningRoot,
    compactVssMessageDigitBase,
    compactVssMessageDigitCount,
    computeCompactVssCommitmentFromOpening,
    decodeCompactVssTernaryRandomnessColumnsHex,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssAggregateOpeningCredential,
    verifyCompactVssDerivedRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssAggregateThresholdOpeningCredential,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssRecipientShareOpeningCredential,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageStatement,
} from './compact-vss-commitments.js';
import { bytesFromStandardBase64 } from './proof-byte-encoding.js';
import type {
    CollectiveBgvSetupContext,
    PrivateVssEnvelopeVerificationReference,
} from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

const compactVssMessageCoordinateBound =
    compactVssMessageDigitBase ** BigInt(compactVssMessageDigitCount);

export type LocalTrusteeSetupStateCommitmentInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
    readonly aggregateThresholdShareRoot: ProtocolHash;
    readonly targetDecryptionProofWitnessRoot: ProtocolHash;
    readonly issuedVssAcceptanceRoot: ProtocolHash;
    readonly issuedVssComplaintRoots: readonly ProtocolHash[];
};

export type LocalTrusteeSetupStateEncryptionInput =
    LocalTrusteeSetupStateCommitmentInput & {
        readonly localStatePlaintext: LocalTrusteeSetupStateSealedPayload;
        readonly storageKeyBytesHex: string;
        readonly aeadNonceBytesHex?: string;
    };

export type LocalTrusteeSetupStateEncryptionResult = Readonly<{
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStatePlaintextHash: ProtocolHash;
    readonly storageAadHash: ProtocolHash;
}>;

export type GeneratedCompactVssTargetProofWitnessInput = Readonly<{
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly targetDecryptionRnsLimbCount?: number;
    readonly recipientShareOpeningCredentials?: readonly CompactVssRecipientShareOpeningCredential[];
    readonly shareLinkageStatement: CompactVssShareLinkageStatement;
}>;

export type GeneratedLocalTrusteeSetupStateInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly deviceEpoch: number;
    readonly thresholdShareCommitments: unknown;
    readonly privateVssEnvelopeCommitments: unknown;
    readonly verifiedPrivateVssShareEnvelopes: readonly unknown[];
    readonly vssShareAcceptances: unknown;
    readonly vssComplaints?: unknown;
    readonly storageKeyBytesHex: string;
    readonly localStateAeadNonceBytesHex?: string;
    readonly sealedAggregateThresholdShareAeadNonceBytesHex?: string;
    readonly sealedTargetDecryptionProofWitnessAeadNonceBytesHex?: string;
    readonly compactVssTargetProofWitness?: GeneratedCompactVssTargetProofWitnessInput;
}>;

export type GeneratedLocalTrusteeSetupStateResult =
    LocalTrusteeSetupStateEncryptionResult &
        Readonly<{
            readonly sealedAggregateThresholdShare: LocalTrusteeSetupStateSealedMaterial;
            readonly sealedTargetDecryptionProofWitness: LocalTrusteeSetupStateSealedMaterial;
        }>;

export type LocalTrusteeSetupStateDecryptionInput = Readonly<{
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly sealedAggregateThresholdShare: LocalTrusteeSetupStateSealedMaterial;
    readonly sealedTargetDecryptionProofWitness: LocalTrusteeSetupStateSealedMaterial;
    readonly expectedLocalStateRoot: ProtocolHash;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly storageKeyBytesHex: string;
}>;

export type LocalTrusteeSetupStateDeletionReceipt = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateDeletionReceipt';
        readonly objectVersion: 1;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly trusteePoint: number;
    }
>;

export type LocalTrusteeSetupStateCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'LocalTrusteeSetupStateCommitment';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly trusteePoint: number;
        readonly thresholdShareCommitmentRecipientRoot: ProtocolHash;
        readonly aggregateThresholdShareRoot: ProtocolHash;
        readonly targetDecryptionProofWitnessRoot: ProtocolHash;
        readonly issuedVssAcceptanceRoot: ProtocolHash;
        readonly issuedVssComplaintRoots: readonly ProtocolHash[];
        readonly deletionReceiptRoot: ProtocolHash;
        readonly deletionReceipt: LocalTrusteeSetupStateDeletionReceipt;
        readonly localStateRoot: ProtocolHash;
    }
>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^[0-9a-f]+$/u;
const privateVssShareValueByteLength = 6;
const maximumPrivateVssShareValueExclusive = 1n << 48n;

const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const safeNumberFromBigInt = (value: bigint, fieldName: string): number => {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`${fieldName} exceeds the safe integer range.`);
    }

    return Number(value);
};

const nonNegativeIntegerToBigInt = (
    value: number | bigint,
    fieldName: string,
): bigint => {
    const valueWide =
        typeof value === 'bigint'
            ? value
            : Number.isSafeInteger(value)
              ? BigInt(value)
              : undefined;
    if (valueWide === undefined || valueWide < 0n) {
        throw new TypeError(`${fieldName} must be a non-negative integer.`);
    }

    return valueWide;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    if (hex.length === 0 || hex.length % 2 !== 0) {
        throw new TypeError(`${fieldName} must be whole-byte lowercase hex.`);
    }
    if (!lowercaseHexPattern.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex.`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const compactVssShareCarryValueBitWidth = 11;

const unsignedIntegerVectorFromLittleEndianBitPackedBytes = (
    bytes: Uint8Array,
    valueCount: number,
    bitWidth: number,
    fieldName: string,
): readonly number[] => {
    if (!Number.isSafeInteger(valueCount) || valueCount < 0) {
        throw new TypeError('valueCount must be a non-negative safe integer.');
    }
    if (!Number.isSafeInteger(bitWidth) || bitWidth <= 0 || bitWidth > 30) {
        throw new TypeError('bitWidth must be a positive safe integer.');
    }
    const expectedByteLength = Math.ceil((valueCount * bitWidth) / 8);
    if (bytes.length !== expectedByteLength) {
        throw new TypeError(
            `${fieldName} length does not match the expected packed vector size.`,
        );
    }
    const values: number[] = [];
    for (let valueIndex = 0; valueIndex < valueCount; valueIndex += 1) {
        let value = 0;
        let bitOffset = valueIndex * bitWidth;
        for (let consumedBits = 0; consumedBits < bitWidth; ) {
            const byteIndex = Math.floor(bitOffset / 8);
            const bitIndexInByte = bitOffset % 8;
            const chunkBitCount = Math.min(
                8 - bitIndexInByte,
                bitWidth - consumedBits,
            );
            const chunkMask = (1 << chunkBitCount) - 1;
            const chunkValue =
                ((bytes[byteIndex] ?? 0) >> bitIndexInByte) & chunkMask;
            value += chunkValue * 2 ** consumedBits;
            bitOffset += chunkBitCount;
            consumedBits += chunkBitCount;
        }
        values.push(value);
    }
    const usedBitsInLastByte = (valueCount * bitWidth) % 8;
    if (usedBitsInLastByte !== 0 && bytes.length > 0) {
        const unusedMask = (0xff << usedBitsInLastByte) & 0xff;
        if (((bytes[bytes.length - 1] ?? 0) & unusedMask) !== 0) {
            throw new TypeError(
                `${fieldName} has nonzero padding bits after the packed vector.`,
            );
        }
    }

    return values;
};

const unsignedIntegerVectorFromLittleEndianBitPackedHex = (
    hex: string,
    valueCount: number,
    bitWidth: number,
    fieldName: string,
): readonly number[] =>
    unsignedIntegerVectorFromLittleEndianBitPackedBytes(
        bytesFromHex(hex, fieldName),
        valueCount,
        bitWidth,
        fieldName,
    );

const unsignedIntegerVectorFromLittleEndianBitPackedBase64 = (
    base64Value: string,
    valueCount: number,
    bitWidth: number,
    fieldName: string,
): readonly number[] =>
    unsignedIntegerVectorFromLittleEndianBitPackedBytes(
        bytesFromStandardBase64(base64Value, fieldName),
        valueCount,
        bitWidth,
        fieldName,
    );

const unsignedIntegerVectorFromLittleEndianBitPackedBigIntBytes = (
    bytes: Uint8Array,
    valueCount: number,
    bitWidth: number,
    fieldName: string,
): readonly bigint[] => {
    if (!Number.isSafeInteger(valueCount) || valueCount < 0) {
        throw new TypeError('valueCount must be a non-negative safe integer.');
    }
    if (!Number.isSafeInteger(bitWidth) || bitWidth <= 0 || bitWidth > 64) {
        throw new TypeError('bitWidth must be a positive safe integer.');
    }
    const expectedByteLength = Math.ceil((valueCount * bitWidth) / 8);
    if (bytes.length !== expectedByteLength) {
        throw new TypeError(
            `${fieldName} length does not match the expected packed vector size.`,
        );
    }
    const values: bigint[] = [];
    for (let valueIndex = 0; valueIndex < valueCount; valueIndex += 1) {
        let value = 0n;
        let bitOffset = valueIndex * bitWidth;
        for (let consumedBits = 0; consumedBits < bitWidth; ) {
            const byteIndex = Math.floor(bitOffset / 8);
            const bitIndexInByte = bitOffset % 8;
            const chunkBitCount = Math.min(
                8 - bitIndexInByte,
                bitWidth - consumedBits,
            );
            const chunkMask = (1 << chunkBitCount) - 1;
            const chunkValue =
                ((bytes[byteIndex] ?? 0) >> bitIndexInByte) & chunkMask;
            value += BigInt(chunkValue) << BigInt(consumedBits);
            bitOffset += chunkBitCount;
            consumedBits += chunkBitCount;
        }
        values.push(value);
    }
    const usedBitsInLastByte = (valueCount * bitWidth) % 8;
    if (usedBitsInLastByte !== 0 && bytes.length > 0) {
        const unusedMask = (0xff << usedBitsInLastByte) & 0xff;
        if (((bytes[bytes.length - 1] ?? 0) & unusedMask) !== 0) {
            throw new TypeError(
                `${fieldName} has nonzero padding bits after the packed vector.`,
            );
        }
    }

    return values;
};

const unsignedIntegerVectorFromLittleEndianBitPackedBigIntHex = (
    hex: string,
    valueCount: number,
    bitWidth: number,
    fieldName: string,
): readonly bigint[] =>
    unsignedIntegerVectorFromLittleEndianBitPackedBigIntBytes(
        bytesFromHex(hex, fieldName),
        valueCount,
        bitWidth,
        fieldName,
    );

const unsignedIntegerVectorFromLittleEndianBitPackedBigIntBase64 = (
    base64Value: string,
    valueCount: number,
    bitWidth: number,
    fieldName: string,
): readonly bigint[] =>
    unsignedIntegerVectorFromLittleEndianBitPackedBigIntBytes(
        bytesFromStandardBase64(base64Value, fieldName),
        valueCount,
        bitWidth,
        fieldName,
    );

const u32VectorToLittleEndianHex = (
    values: readonly (number | bigint)[],
    fieldName: string,
): string => {
    const bytes = new Uint8Array(values.length * 4);
    values.forEach((value, valueIndex) => {
        const valueWide =
            typeof value === 'bigint'
                ? value
                : Number.isSafeInteger(value)
                  ? BigInt(value)
                  : undefined;
        if (
            valueWide === undefined ||
            valueWide < 0n ||
            valueWide >= 1n << 32n
        ) {
            throw new TypeError(
                `${fieldName}.${String(valueIndex)} must fit unsigned 32-bit encoding.`,
            );
        }
        let remainingValue = valueWide;
        for (let byteIndex = 0; byteIndex < 4; byteIndex += 1) {
            bytes[valueIndex * 4 + byteIndex] = Number(remainingValue & 0xffn);
            remainingValue >>= 8n;
        }
    });

    return bytesToHex(bytes);
};

const u64VectorToLittleEndianHex = (
    values: readonly (number | bigint)[],
    fieldName: string,
): string => {
    const bytes = new Uint8Array(values.length * 8);
    values.forEach((value, valueIndex) => {
        const valueWide =
            typeof value === 'bigint'
                ? value
                : Number.isSafeInteger(value)
                  ? BigInt(value)
                  : undefined;
        if (
            valueWide === undefined ||
            valueWide < 0n ||
            valueWide >= 1n << 64n
        ) {
            throw new TypeError(
                `${fieldName}.${String(valueIndex)} must fit unsigned 64-bit encoding.`,
            );
        }
        let remainingValue = valueWide;
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[valueIndex * 8 + byteIndex] = Number(remainingValue & 0xffn);
            remainingValue >>= 8n;
        }
    });

    return bytesToHex(bytes);
};

const compactVssAggregateDigitColumnStorage = (
    columns: readonly (readonly (number | bigint)[])[],
): JsonRecord => {
    const fitsU32 = columns.every((column) =>
        column.every((value) => {
            const valueWide =
                typeof value === 'bigint'
                    ? value
                    : Number.isSafeInteger(value)
                      ? BigInt(value)
                      : undefined;

            return (
                valueWide !== undefined &&
                valueWide >= 0n &&
                valueWide < 1n << 32n
            );
        }),
    );

    return fitsU32
        ? {
              aggregateCommitmentMessageDigitColumnsLe32Hex: columns.map(
                  (digitColumn, digitIndex) =>
                      u32VectorToLittleEndianHex(
                          digitColumn,
                          `aggregateCommitmentMessageDigitColumns.${String(digitIndex)}`,
                      ),
              ),
          }
        : {
              aggregateCommitmentMessageDigitColumnsLe64Hex: columns.map(
                  (digitColumn, digitIndex) =>
                      u64VectorToLittleEndianHex(
                          digitColumn,
                          `aggregateCommitmentMessageDigitColumns.${String(digitIndex)}`,
                      ),
              ),
          };
};

const signedByteVectorToHex = (
    values: readonly number[],
    fieldName: string,
): string => {
    const bytes = new Uint8Array(values.length);
    values.forEach((value, valueIndex) => {
        if (!Number.isSafeInteger(value) || value < -128 || value > 127) {
            throw new TypeError(
                `${fieldName}.${String(valueIndex)} must fit signed-byte encoding.`,
            );
        }
        bytes[valueIndex] = value < 0 ? value + 256 : value;
    });

    return bytesToHex(bytes);
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const isJsonRecord = (value: unknown): value is JsonRecord =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const jsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (!isJsonRecord(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value;
};

const jsonRecordArray = (
    value: unknown,
    fieldName: string,
): readonly JsonRecord[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an array.`);
    }

    return value.map((entry, entryIndex) =>
        jsonRecord(entry, `${fieldName}.${String(entryIndex)}`),
    );
};

const stringField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string') {
        throw new TypeError(`${objectPath}.${fieldName} must be a string.`);
    }

    return fieldValue;
};

const numberField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'number') {
        throw new TypeError(`${objectPath}.${fieldName} must be a number.`);
    }

    return fieldValue;
};

const protocolHashField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const fieldValue = stringField(value, fieldName, objectPath);
    assertProtocolHash(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

const nonNegativeIntegerField = (
    value: JsonRecord,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = numberField(value, fieldName, objectPath);
    assertNonNegativeSafeInteger(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

const assertSetupContextBinding = (
    setupContext: CollectiveBgvSetupContext,
    value: JsonRecord,
    objectPath: string,
): void => {
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const validateInput = (input: LocalTrusteeSetupStateCommitmentInput): void => {
    assertNonEmptyString(
        input.setupContext.ceremonyId,
        'setupContext.ceremonyId',
    );
    assertNonEmptyString(
        input.setupContext.setupEpoch,
        'setupContext.setupEpoch',
    );
    for (const fieldName of contextFieldNames) {
        if (fieldName !== 'ceremonyId' && fieldName !== 'setupEpoch') {
            assertProtocolHash(
                input.setupContext[fieldName],
                `setupContext.${fieldName}`,
            );
        }
    }
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        input.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    assertProtocolHash(
        input.thresholdShareCommitmentRecipientRoot,
        'thresholdShareCommitmentRecipientRoot',
    );
    assertProtocolHash(
        input.aggregateThresholdShareRoot,
        'aggregateThresholdShareRoot',
    );
    assertProtocolHash(
        input.targetDecryptionProofWitnessRoot,
        'targetDecryptionProofWitnessRoot',
    );
    assertProtocolHash(
        input.issuedVssAcceptanceRoot,
        'issuedVssAcceptanceRoot',
    );
    input.issuedVssComplaintRoots.forEach((complaintRoot, complaintRootIndex) =>
        assertProtocolHash(
            complaintRoot,
            `issuedVssComplaintRoots.${String(complaintRootIndex)}`,
        ),
    );
};

export const createLocalTrusteeSetupStateCommitment = (
    input: LocalTrusteeSetupStateCommitmentInput,
): LocalTrusteeSetupStateCommitment => {
    validateInput(input);

    const trusteePoint = input.trusteeRosterPosition + 1;
    const deletionReceipt = {
        objectType: 'LocalTrusteeSetupStateDeletionReceipt',
        objectVersion: 1,
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        trusteePoint,
    } satisfies LocalTrusteeSetupStateDeletionReceipt;
    const deletionReceiptRoot = deriveProtocolHash(
        'LocalTrusteeDeletionReceiptRoot',
        deletionReceipt,
    );
    const localStateWithoutRoot = {
        objectType: 'LocalTrusteeSetupStateCommitment',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        trusteePoint,
        thresholdShareCommitmentRecipientRoot:
            input.thresholdShareCommitmentRecipientRoot,
        aggregateThresholdShareRoot: input.aggregateThresholdShareRoot,
        targetDecryptionProofWitnessRoot:
            input.targetDecryptionProofWitnessRoot,
        issuedVssAcceptanceRoot: input.issuedVssAcceptanceRoot,
        issuedVssComplaintRoots: input.issuedVssComplaintRoots,
        deletionReceiptRoot,
        deletionReceipt,
    } as const satisfies JsonRecord;

    return {
        ...localStateWithoutRoot,
        localStateRoot: deriveProtocolHash(
            'LocalTrusteeSetupStateRoot',
            localStateWithoutRoot,
        ),
    } satisfies LocalTrusteeSetupStateCommitment;
};

const thresholdShareCommitmentRecipientRoot = (
    input: GeneratedLocalTrusteeSetupStateInput,
): ProtocolHash => {
    const thresholdShareCommitments = jsonRecord(
        input.thresholdShareCommitments,
        'thresholdShareCommitments',
    );
    assertSetupContextBinding(
        input.setupContext,
        thresholdShareCommitments,
        'thresholdShareCommitments',
    );
    const recipientRecords = jsonRecordArray(
        thresholdShareCommitments.recipientRecords,
        'thresholdShareCommitments.recipientRecords',
    ).filter(
        (record) =>
            record.recipientRosterPosition === input.trusteeRosterPosition,
    );
    if (recipientRecords.length !== 1) {
        throw new Error(
            'thresholdShareCommitments must contain exactly one recipient record for the trustee.',
        );
    }
    const recipientRecord = recipientRecords[0];
    if (recipientRecord.recipientIdentity !== input.trusteeIdentity) {
        throw new Error(
            'thresholdShareCommitments recipient identity must match the trustee identity.',
        );
    }

    return protocolHashField(
        recipientRecord,
        'recipientCommitmentRoot',
        'thresholdShareCommitments.recipientRecords',
    );
};

const recipientEnvelopeReferences = (
    input: GeneratedLocalTrusteeSetupStateInput,
): readonly PrivateVssEnvelopeVerificationReference[] => {
    const privateVssEnvelopeCommitments = jsonRecord(
        input.privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitments',
    );
    assertSetupContextBinding(
        input.setupContext,
        privateVssEnvelopeCommitments,
        'privateVssEnvelopeCommitments',
    );
    const participantCount = nonNegativeIntegerField(
        privateVssEnvelopeCommitments,
        'participantCount',
        'privateVssEnvelopeCommitments',
    );
    if (participantCount === 0) {
        throw new Error(
            'privateVssEnvelopeCommitments.participantCount must be positive.',
        );
    }
    const envelopeReferences = jsonRecordArray(
        privateVssEnvelopeCommitments.envelopeReferences,
        'privateVssEnvelopeCommitments.envelopeReferences',
    )
        .filter(
            (reference) =>
                reference.recipientRosterPosition ===
                input.trusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                Number(left.sourceTrusteeRosterPosition) -
                Number(right.sourceTrusteeRosterPosition),
        );
    if (envelopeReferences.length !== participantCount) {
        throw new Error(
            'privateVssEnvelopeCommitments must include one envelope reference from every source trustee for the trustee.',
        );
    }
    envelopeReferences.forEach((reference, referenceIndex) => {
        const objectPath = `privateVssEnvelopeCommitments.envelopeReferences.${String(referenceIndex)}`;
        assertSetupContextBinding(input.setupContext, reference, objectPath);
        if (reference.sourceTrusteeRosterPosition !== referenceIndex) {
            throw new Error(
                'private VSS envelope references for a trustee must cover contiguous source trustee roster positions.',
            );
        }
        if (reference.recipientIdentity !== input.trusteeIdentity) {
            throw new Error(
                `${objectPath}.recipientIdentity must match the trustee identity.`,
            );
        }
        if (reference.recipientRosterPosition !== input.trusteeRosterPosition) {
            throw new Error(
                `${objectPath}.recipientRosterPosition must match the trustee roster position.`,
            );
        }
        protocolHashField(reference, 'privateEnvelopeHash', objectPath);
        protocolHashField(reference, 'localVerificationRoot', objectPath);
        protocolHashField(reference, 'sourceTrusteeCommitmentRoot', objectPath);
    });

    return envelopeReferences as unknown as readonly PrivateVssEnvelopeVerificationReference[];
};

const issuedVssAcceptanceRoot = (
    input: GeneratedLocalTrusteeSetupStateInput,
    privateVssEnvelopeCommitmentRoot: ProtocolHash,
    expectedAcceptanceCount: number,
): ProtocolHash => {
    const vssShareAcceptances = jsonRecord(
        input.vssShareAcceptances,
        'vssShareAcceptances',
    );
    assertSetupContextBinding(
        input.setupContext,
        vssShareAcceptances,
        'vssShareAcceptances',
    );
    const acceptanceRoots = jsonRecordArray(
        vssShareAcceptances.acceptanceRecords,
        'vssShareAcceptances.acceptanceRecords',
    )
        .filter(
            (record) =>
                record.recipientRosterPosition === input.trusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                Number(left.sourceTrusteeRosterPosition) -
                Number(right.sourceTrusteeRosterPosition),
        )
        .map((record, recordIndex) => {
            const objectPath = `vssShareAcceptances.acceptanceRecords.${String(recordIndex)}`;
            assertSetupContextBinding(input.setupContext, record, objectPath);
            if (record.recipientIdentity !== input.trusteeIdentity) {
                throw new Error(
                    `${objectPath}.recipientIdentity must match the trustee identity.`,
                );
            }
            if (
                record.privateVssEnvelopeCommitmentRoot !==
                privateVssEnvelopeCommitmentRoot
            ) {
                throw new Error(
                    `${objectPath}.privateVssEnvelopeCommitmentRoot must match the local private VSS envelope commitment set.`,
                );
            }

            return protocolHashField(record, 'acceptanceRoot', objectPath);
        });
    if (acceptanceRoots.length !== expectedAcceptanceCount) {
        throw new Error(
            'vssShareAcceptances must contain one acceptance issued by the trustee for every source trustee.',
        );
    }

    return deriveProtocolHash('VssShareAcceptanceRoot', {
        objectType: 'LocalTrusteeIssuedVssAcceptanceSet',
        objectVersion: 1,
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        privateVssEnvelopeCommitmentRoot,
        acceptanceRoots,
    });
};

const issuedVssComplaintRoots = (
    input: GeneratedLocalTrusteeSetupStateInput,
    privateVssEnvelopeCommitmentRoot: ProtocolHash,
): readonly ProtocolHash[] => {
    if (input.vssComplaints === undefined) {
        return [];
    }
    const vssComplaints = jsonRecord(input.vssComplaints, 'vssComplaints');
    assertSetupContextBinding(
        input.setupContext,
        vssComplaints,
        'vssComplaints',
    );

    return jsonRecordArray(
        vssComplaints.complaintRecords,
        'vssComplaints.complaintRecords',
    )
        .filter(
            (record) =>
                record.recipientRosterPosition === input.trusteeRosterPosition,
        )
        .sort(
            (left, right) =>
                Number(left.sourceTrusteeRosterPosition) -
                Number(right.sourceTrusteeRosterPosition),
        )
        .map((record, recordIndex) => {
            const objectPath = `vssComplaints.complaintRecords.${String(recordIndex)}`;
            assertSetupContextBinding(input.setupContext, record, objectPath);
            if (record.recipientIdentity !== input.trusteeIdentity) {
                throw new Error(
                    `${objectPath}.recipientIdentity must match the trustee identity.`,
                );
            }
            if (
                record.privateVssEnvelopeCommitmentRoot !==
                privateVssEnvelopeCommitmentRoot
            ) {
                throw new Error(
                    `${objectPath}.privateVssEnvelopeCommitmentRoot must match the local private VSS envelope commitment set.`,
                );
            }

            return protocolHashField(record, 'complaintRoot', objectPath);
        });
};

type AggregateLimbAccumulator = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    shareValues: bigint[];
};

const sourcePrivateEnvelopeReferences = (
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
): readonly JsonRecord[] =>
    envelopeReferences.map((reference) => ({
        objectType: 'LocalTrusteePrivateVssEnvelopeReference',
        objectVersion: 1,
        sourceTrusteeIdentity: reference.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: reference.sourceTrusteeRosterPosition,
        sourceTrusteeCommitmentRoot: reference.sourceTrusteeCommitmentRoot,
        privateEnvelopeHash: reference.privateEnvelopeHash,
        localVerificationRoot: reference.localVerificationRoot,
    }));

const numericVector = (
    value: unknown,
    objectPath: string,
): readonly number[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${objectPath} must be an array.`);
    }

    return value.map((entry, entryIndex) => {
        if (!Number.isSafeInteger(entry)) {
            throw new TypeError(
                `${objectPath}.${String(entryIndex)} must be a safe integer.`,
            );
        }

        return Number(entry);
    });
};

const nonNegativeIntegerVector = (
    value: unknown,
    objectPath: string,
): readonly bigint[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${objectPath} must be an array.`);
    }
    const entries = value as readonly unknown[];

    return entries.map((entry, entryIndex) => {
        const entryPath = `${objectPath}.${String(entryIndex)}`;
        if (typeof entry !== 'number' && typeof entry !== 'bigint') {
            throw new TypeError(`${entryPath} must be a non-negative integer.`);
        }

        return nonNegativeIntegerToBigInt(entry, entryPath);
    });
};

const aggregateShareValuesToLittleEndian48Hex = (
    values: readonly bigint[],
    rnsPrime: number,
    fieldName: string,
): string => {
    if (BigInt(rnsPrime) > maximumPrivateVssShareValueExclusive) {
        throw new TypeError(
            `${fieldName} rnsPrime must fit the packed 48-bit field.`,
        );
    }
    const bytes = new Uint8Array(
        values.length * privateVssShareValueByteLength,
    );
    values.forEach((value, valueIndex) => {
        if (value < 0n || value >= BigInt(rnsPrime)) {
            throw new TypeError(
                `${fieldName}.${String(valueIndex)} must be a residue below rnsPrime.`,
            );
        }
        let remainingValue = value;
        for (
            let byteIndex = 0;
            byteIndex < privateVssShareValueByteLength;
            byteIndex += 1
        ) {
            bytes[valueIndex * privateVssShareValueByteLength + byteIndex] =
                Number(remainingValue & 0xffn);
            remainingValue >>= 8n;
        }
    });

    return bytesToHex(bytes);
};

const shareValuesFromLittleEndian48Hex = (
    value: unknown,
    rnsPrime: number,
    objectPath: string,
    rnsPrimeObjectPath: string,
): readonly number[] => {
    if (typeof value !== 'string') {
        throw new TypeError(`${objectPath} must be a string.`);
    }
    const encodedShareValueLength = privateVssShareValueByteLength * 2;
    if (
        value.length === 0 ||
        value.length % encodedShareValueLength !== 0 ||
        !lowercaseHexPattern.test(value)
    ) {
        throw new TypeError(
            `${objectPath} must be non-empty lowercase 48-bit little-endian hex.`,
        );
    }
    if (BigInt(rnsPrime) > maximumPrivateVssShareValueExclusive) {
        throw new TypeError(
            `${rnsPrimeObjectPath} must fit the packed 48-bit field.`,
        );
    }

    const shareValues: number[] = [];
    for (
        let valueOffset = 0;
        valueOffset < value.length;
        valueOffset += encodedShareValueLength
    ) {
        let shareValue = 0n;
        for (
            let byteIndex = 0;
            byteIndex < privateVssShareValueByteLength;
            byteIndex += 1
        ) {
            const byteValue = Number.parseInt(
                value.slice(
                    valueOffset + byteIndex * 2,
                    valueOffset + byteIndex * 2 + 2,
                ),
                16,
            );
            shareValue |= BigInt(byteValue) << BigInt(byteIndex * 8);
        }
        if (shareValue >= BigInt(rnsPrime)) {
            throw new TypeError(
                `${objectPath}.${String(shareValues.length)} must be a residue below rnsPrime.`,
            );
        }
        shareValues.push(Number(shareValue));
    }

    return shareValues;
};

const assertPrivateEnvelopeMatchesReference = (
    setupContext: CollectiveBgvSetupContext,
    privateEnvelope: JsonRecord,
    privateEnvelopeHash: ProtocolHash,
    envelopeReference: PrivateVssEnvelopeVerificationReference,
): void => {
    assertSetupContextBinding(setupContext, privateEnvelope, 'privateEnvelope');
    if (privateEnvelopeHash !== envelopeReference.privateEnvelopeHash) {
        throw new Error(
            'verified private VSS envelope hash must match the public envelope reference.',
        );
    }
    for (const fieldName of [
        'sourceTrusteeIdentity',
        'sourceTrusteeRosterPosition',
        'recipientIdentity',
        'recipientRosterPosition',
        'sourceTrusteeCommitmentRoot',
    ] as const) {
        if (privateEnvelope[fieldName] !== envelopeReference[fieldName]) {
            throw new Error(
                `privateEnvelope.${fieldName} must match the public envelope reference.`,
            );
        }
    }
};

const assertSameShareValues = (
    leftValues: readonly number[],
    rightValues: readonly number[],
    objectPath: string,
    expectedDescription = 'the aggregate threshold share material',
): void => {
    if (leftValues.length !== rightValues.length) {
        throw new Error(`${objectPath} length must match.`);
    }
    leftValues.forEach((leftValue, valueIndex) => {
        if (leftValue !== rightValues[valueIndex]) {
            throw new Error(
                `${objectPath}.${String(valueIndex)} must match ${expectedDescription}.`,
            );
        }
    });
};

const compactCredentialRandomnessByColumn = (
    compactCredential: JsonRecord,
    ringDegree: number,
): readonly (readonly number[])[] => {
    if (Array.isArray(compactCredential.randomnessByColumn)) {
        return compactCredential.randomnessByColumn.map(
            (randomnessColumn, columnIndex) =>
                numericVector(
                    randomnessColumn,
                    `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.randomnessByColumn.${String(columnIndex)}`,
                ),
        );
    }
    if (Array.isArray(compactCredential.randomnessByColumnPackedTernaryHex)) {
        return decodeCompactVssTernaryRandomnessColumnsHex(
            compactCredential.randomnessByColumnPackedTernaryHex.map(
                (packedColumn, columnIndex) => {
                    if (typeof packedColumn !== 'string') {
                        throw new TypeError(
                            `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.randomnessByColumnPackedTernaryHex.${String(columnIndex)} must be a string.`,
                        );
                    }

                    return packedColumn;
                },
            ),
            ringDegree,
        );
    }

    throw new Error(
        'compact VSS recipient share opening credential must include randomnessByColumn or randomnessByColumnPackedTernaryHex.',
    );
};

const compactCredentialShareCommitmentMessageCarryValues = (
    compactCredential: JsonRecord,
    ringDegree: number,
): readonly number[] => {
    if (Array.isArray(compactCredential.shareCommitmentMessageCarryValues)) {
        const carryValues = numericVector(
            compactCredential.shareCommitmentMessageCarryValues,
            'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageCarryValues',
        );
        if (carryValues.length !== ringDegree) {
            throw new Error(
                'compact VSS recipient share opening credential carry vector length must match ringDegree.',
            );
        }

        return carryValues;
    }
    if (
        typeof compactCredential.shareCommitmentMessageCarryValuesPacked11Base64 ===
        'string'
    ) {
        return unsignedIntegerVectorFromLittleEndianBitPackedBase64(
            compactCredential.shareCommitmentMessageCarryValuesPacked11Base64,
            ringDegree,
            compactVssShareCarryValueBitWidth,
            'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageCarryValuesPacked11Base64',
        );
    }
    if (
        typeof compactCredential.shareCommitmentMessageCarryValuesPacked11Hex ===
        'string'
    ) {
        return unsignedIntegerVectorFromLittleEndianBitPackedHex(
            compactCredential.shareCommitmentMessageCarryValuesPacked11Hex,
            ringDegree,
            compactVssShareCarryValueBitWidth,
            'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageCarryValuesPacked11Hex',
        );
    }

    throw new Error(
        'compact VSS recipient share opening credential must include shareCommitmentMessageCarryValues, shareCommitmentMessageCarryValuesPacked11Base64, or shareCommitmentMessageCarryValuesPacked11Hex.',
    );
};

const compactCredentialShareCommitmentMessageDigitColumns = (
    compactCredential: JsonRecord,
    ringDegree: number,
): readonly (readonly bigint[])[] | undefined => {
    if (Array.isArray(compactCredential.shareCommitmentMessageDigitColumns)) {
        return compactCredential.shareCommitmentMessageDigitColumns.map(
            (digitColumn, digitIndex) => {
                const decodedColumn = nonNegativeIntegerVector(
                    digitColumn,
                    `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumns.${String(digitIndex)}`,
                );
                if (decodedColumn.length !== ringDegree) {
                    throw new Error(
                        'compact VSS recipient share opening credential digit column length must match ringDegree.',
                    );
                }

                return decodedColumn;
            },
        );
    }

    const packedDigitColumnsBase64 =
        compactCredential.shareCommitmentMessageDigitColumnsPackedBase64;
    const packedDigitColumnBitWidths =
        compactCredential.shareCommitmentMessageDigitColumnBitWidths;
    if (
        packedDigitColumnsBase64 !== undefined ||
        packedDigitColumnBitWidths !== undefined
    ) {
        if (!Array.isArray(packedDigitColumnsBase64)) {
            throw new TypeError(
                'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnsPackedBase64 must be an array.',
            );
        }
        if (!Array.isArray(packedDigitColumnBitWidths)) {
            throw new TypeError(
                'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnBitWidths must be an array.',
            );
        }
        if (
            packedDigitColumnsBase64.length !==
            packedDigitColumnBitWidths.length
        ) {
            throw new Error(
                'compact VSS recipient share opening credential packed digit columns and bit widths must have the same length.',
            );
        }

        return packedDigitColumnsBase64.map((packedColumn, digitIndex) => {
            if (typeof packedColumn !== 'string') {
                throw new TypeError(
                    `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnsPackedBase64.${String(digitIndex)} must be a string.`,
                );
            }
            const bitWidthValue: unknown =
                packedDigitColumnBitWidths[digitIndex];
            if (
                typeof bitWidthValue !== 'number' ||
                !Number.isSafeInteger(bitWidthValue) ||
                bitWidthValue <= 0 ||
                bitWidthValue > 64
            ) {
                throw new TypeError(
                    `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnBitWidths.${String(digitIndex)} must be between 1 and 64.`,
                );
            }
            const bitWidth = bitWidthValue;

            return unsignedIntegerVectorFromLittleEndianBitPackedBigIntBase64(
                packedColumn,
                ringDegree,
                bitWidth,
                `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnsPackedBase64.${String(digitIndex)}`,
            );
        });
    }

    const packedDigitColumns =
        compactCredential.shareCommitmentMessageDigitColumnsPackedHex;
    const packedDigitColumnBitWidth =
        compactCredential.shareCommitmentMessageDigitColumnBitWidth;
    if (
        packedDigitColumns === undefined &&
        packedDigitColumnBitWidth === undefined
    ) {
        return undefined;
    }
    if (!Array.isArray(packedDigitColumns)) {
        throw new TypeError(
            'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnsPackedHex must be an array.',
        );
    }
    const bitWidth = nonNegativeIntegerField(
        compactCredential,
        'shareCommitmentMessageDigitColumnBitWidth',
        'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential',
    );
    if (bitWidth <= 0 || bitWidth > 64) {
        throw new TypeError(
            'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnBitWidth must be between 1 and 64.',
        );
    }

    return packedDigitColumns.map((packedColumn, digitIndex) => {
        if (typeof packedColumn !== 'string') {
            throw new TypeError(
                `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnsPackedHex.${String(digitIndex)} must be a string.`,
            );
        }

        return unsignedIntegerVectorFromLittleEndianBitPackedBigIntHex(
            packedColumn,
            ringDegree,
            bitWidth,
            `privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential.shareCommitmentMessageDigitColumnsPackedHex.${String(digitIndex)}`,
        );
    });
};

const aggregateVerifiedPrivateVssMaterial = (
    input: GeneratedLocalTrusteeSetupStateInput,
    thresholdShareCommitmentRecipientRootValue: ProtocolHash,
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
): Readonly<{
    readonly aggregateThresholdShareMaterial: JsonRecord;
    readonly compactVssRecipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
}> => {
    const privateEnvelopeByHash = new Map<ProtocolHash, JsonRecord>();
    for (const privateEnvelopeValue of input.verifiedPrivateVssShareEnvelopes) {
        const privateEnvelope = jsonRecord(
            privateEnvelopeValue,
            'verifiedPrivateVssShareEnvelopes',
        );
        const privateEnvelopeHash = deriveProtocolHash(
            'PrivateVssShareEnvelopeHash',
            privateEnvelope,
        );
        if (privateEnvelopeByHash.has(privateEnvelopeHash)) {
            throw new Error(
                'verifiedPrivateVssShareEnvelopes must not contain duplicate private envelope hashes.',
            );
        }
        privateEnvelopeByHash.set(privateEnvelopeHash, privateEnvelope);
    }

    const aggregateByLimb = new Map<number, AggregateLimbAccumulator>();
    const compactVssRecipientShareOpeningCredentials: CompactVssRecipientShareOpeningCredential[] =
        [];
    for (const envelopeReference of envelopeReferences) {
        const privateEnvelope = privateEnvelopeByHash.get(
            envelopeReference.privateEnvelopeHash,
        );
        if (privateEnvelope === undefined) {
            throw new Error(
                'verifiedPrivateVssShareEnvelopes must include the private envelope referenced by each public envelope commitment.',
            );
        }
        assertPrivateEnvelopeMatchesReference(
            input.setupContext,
            privateEnvelope,
            envelopeReference.privateEnvelopeHash,
            envelopeReference,
        );
        const rnsShareOpenings = jsonRecordArray(
            privateEnvelope.rnsShareOpenings,
            'privateEnvelope.rnsShareOpenings',
        );
        for (const limbOpening of rnsShareOpenings) {
            const rnsLimbIndex = nonNegativeIntegerField(
                limbOpening,
                'rnsLimbIndex',
                'privateEnvelope.rnsShareOpenings',
            );
            const rnsPrime = nonNegativeIntegerField(
                limbOpening,
                'rnsPrime',
                'privateEnvelope.rnsShareOpenings',
            );
            if (rnsPrime === 0) {
                throw new Error('private VSS share rnsPrime must be positive.');
            }
            const shareValues = shareValuesFromLittleEndian48Hex(
                limbOpening.shareValuesLittleEndian48Hex,
                rnsPrime,
                'privateEnvelope.rnsShareOpenings.shareValuesLittleEndian48Hex',
                'privateEnvelope.rnsShareOpenings.rnsPrime',
            );
            if (
                limbOpening.compactVssRecipientShareOpeningCredential !==
                undefined
            ) {
                const compactCredential = jsonRecord(
                    limbOpening.compactVssRecipientShareOpeningCredential,
                    'privateEnvelope.rnsShareOpenings.compactVssRecipientShareOpeningCredential',
                );
                if (
                    compactCredential.sourceTrusteeIdentity !==
                        envelopeReference.sourceTrusteeIdentity ||
                    compactCredential.sourceTrusteeRosterPosition !==
                        envelopeReference.sourceTrusteeRosterPosition ||
                    compactCredential.recipientIdentity !==
                        envelopeReference.recipientIdentity ||
                    compactCredential.recipientRosterPosition !==
                        envelopeReference.recipientRosterPosition ||
                    compactCredential.rnsLimbIndex !== rnsLimbIndex ||
                    compactCredential.rnsPrime !== rnsPrime
                ) {
                    throw new Error(
                        'compact VSS recipient share opening credential must match its private VSS envelope limb binding.',
                    );
                }
                const shareCommitmentMessageDigitColumns =
                    compactCredentialShareCommitmentMessageDigitColumns(
                        compactCredential,
                        shareValues.length,
                    );
                const {
                    shareCommitmentMessageCarryValuesPacked11Base64:
                        _shareCommitmentMessageCarryValuesPacked11Base64,
                    shareCommitmentMessageCarryValuesPacked11Hex:
                        _shareCommitmentMessageCarryValuesPacked11Hex,
                    shareCommitmentMessageDigitColumnBitWidth:
                        _shareCommitmentMessageDigitColumnBitWidth,
                    shareCommitmentMessageDigitColumnBitWidths:
                        _shareCommitmentMessageDigitColumnBitWidths,
                    shareCommitmentMessageDigitColumnsPackedBase64:
                        _shareCommitmentMessageDigitColumnsPackedBase64,
                    shareCommitmentMessageDigitColumnsPackedHex:
                        _shareCommitmentMessageDigitColumnsPackedHex,
                    ...compactCredentialWithoutPackedDigitColumns
                } = compactCredential;
                void _shareCommitmentMessageCarryValuesPacked11Base64;
                void _shareCommitmentMessageCarryValuesPacked11Hex;
                void _shareCommitmentMessageDigitColumnBitWidth;
                void _shareCommitmentMessageDigitColumnBitWidths;
                void _shareCommitmentMessageDigitColumnsPackedBase64;
                void _shareCommitmentMessageDigitColumnsPackedHex;
                compactVssRecipientShareOpeningCredentials.push({
                    ...compactCredentialWithoutPackedDigitColumns,
                    shareValues,
                    shareCommitmentMessageCarryValues:
                        compactCredentialShareCommitmentMessageCarryValues(
                            compactCredential,
                            shareValues.length,
                        ),
                    ...(shareCommitmentMessageDigitColumns === undefined
                        ? {}
                        : { shareCommitmentMessageDigitColumns }),
                    randomnessByColumn: compactCredentialRandomnessByColumn(
                        compactCredential,
                        shareValues.length,
                    ),
                } as unknown as CompactVssRecipientShareOpeningCredential);
            }
            const existingAccumulator = aggregateByLimb.get(rnsLimbIndex);
            if (existingAccumulator === undefined) {
                aggregateByLimb.set(rnsLimbIndex, {
                    rnsLimbIndex,
                    rnsPrime,
                    shareValues: shareValues.map((shareValue) =>
                        BigInt(shareValue),
                    ),
                });
                continue;
            }
            if (existingAccumulator.rnsPrime !== rnsPrime) {
                throw new Error(
                    'private VSS share values must use one rnsPrime per limb.',
                );
            }
            if (existingAccumulator.shareValues.length !== shareValues.length) {
                throw new Error(
                    'private VSS share vectors for the same limb must have equal length.',
                );
            }
            const rnsPrimeWide = BigInt(rnsPrime);
            shareValues.forEach((shareValue, shareValueIndex) => {
                existingAccumulator.shareValues[shareValueIndex] =
                    ((existingAccumulator.shareValues[shareValueIndex] ?? 0n) +
                        BigInt(shareValue)) %
                    rnsPrimeWide;
            });
        }
    }

    const orderedAggregates = [...aggregateByLimb.values()].sort(
        (left, right) => left.rnsLimbIndex - right.rnsLimbIndex,
    );
    const localEnvelopeReferences =
        sourcePrivateEnvelopeReferences(envelopeReferences);
    const materialCommonFields = {
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        sourcePrivateEnvelopeReferences: localEnvelopeReferences,
    } as const satisfies JsonRecord;

    return {
        aggregateThresholdShareMaterial: {
            objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
            objectVersion: 1,
            ...materialCommonFields,
            materialDerivation: 'sum-of-verified-private-vss-share-values-v1',
            aggregateShareByRnsLimb: orderedAggregates.map((aggregate) => ({
                objectType: 'LocalTrusteeAggregateThresholdShareLimb',
                objectVersion: 1,
                rnsLimbIndex: aggregate.rnsLimbIndex,
                rnsPrime: aggregate.rnsPrime,
                shareValuesLittleEndian48Hex:
                    aggregateShareValuesToLittleEndian48Hex(
                        aggregate.shareValues,
                        aggregate.rnsPrime,
                        'aggregateThresholdShareMaterial.aggregateShareByRnsLimb.shareValuesLittleEndian48Hex',
                    ),
            })),
        },
        compactVssRecipientShareOpeningCredentials,
    };
};

type AggregateThresholdShareLimbMaterial = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shareValues: readonly number[];
}>;

const aggregateThresholdShareLimbMaterials = (
    aggregateThresholdShareMaterial: JsonRecord,
): readonly AggregateThresholdShareLimbMaterial[] =>
    jsonRecordArray(
        aggregateThresholdShareMaterial.aggregateShareByRnsLimb,
        'aggregateThresholdShareMaterial.aggregateShareByRnsLimb',
    ).map((limbMaterial, limbIndex) => {
        const objectPath = `aggregateThresholdShareMaterial.aggregateShareByRnsLimb.${String(limbIndex)}`;
        const rnsLimbIndex = nonNegativeIntegerField(
            limbMaterial,
            'rnsLimbIndex',
            objectPath,
        );
        const rnsPrime = nonNegativeIntegerField(
            limbMaterial,
            'rnsPrime',
            objectPath,
        );
        if (rnsPrime === 0) {
            throw new Error(
                `${objectPath}.rnsPrime must be a positive integer.`,
            );
        }
        const shareValues = shareValuesFromLittleEndian48Hex(
            limbMaterial.shareValuesLittleEndian48Hex,
            rnsPrime,
            `${objectPath}.shareValuesLittleEndian48Hex`,
            `${objectPath}.rnsPrime`,
        );

        return {
            rnsLimbIndex,
            rnsPrime,
            shareValues,
        };
    });

const compactVssCredentialKey = (
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string => `${String(recipientRosterPosition)}:${String(rnsLimbIndex)}`;

const compactMessageValuesFromResiduesAndCarries = (input: {
    readonly residues: readonly number[];
    readonly carryValues: readonly number[];
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly fieldName: string;
}): readonly bigint[] => {
    if (input.residues.length !== input.ringDegree) {
        throw new Error(`${input.fieldName}.residues length must match.`);
    }
    if (input.carryValues.length !== input.ringDegree) {
        throw new Error(`${input.fieldName}.carryValues length must match.`);
    }
    const rnsPrimeWide = BigInt(input.rnsPrime);

    return input.residues.map((residue, coefficientIndex) => {
        assertNonNegativeSafeInteger(
            residue,
            `${input.fieldName}.residues.${String(coefficientIndex)}`,
        );
        if (residue >= input.rnsPrime) {
            throw new TypeError(
                `${input.fieldName}.residues.${String(coefficientIndex)} must be below rnsPrime.`,
            );
        }
        const carryValue = input.carryValues[coefficientIndex];
        if (carryValue === undefined) {
            throw new Error(
                `${input.fieldName}.carryValues length must match.`,
            );
        }
        assertNonNegativeSafeInteger(
            carryValue,
            `${input.fieldName}.carryValues.${String(coefficientIndex)}`,
        );

        return BigInt(residue) + BigInt(carryValue) * rnsPrimeWide;
    });
};

const compactVssCanonicalMessageDigitColumns = (
    messageCoefficients: readonly number[],
    ringDegree: number,
): readonly (readonly bigint[])[] => {
    if (messageCoefficients.length !== ringDegree) {
        throw new Error('compact VSS message coefficients length must match.');
    }
    const columns = Array.from({ length: compactVssMessageDigitCount }, () =>
        Array.from({ length: ringDegree }, () => 0n),
    );
    messageCoefficients.forEach((coefficient, coefficientIndex) => {
        assertNonNegativeSafeInteger(
            coefficient,
            `messageCoefficients.${String(coefficientIndex)}`,
        );
        let remaining = BigInt(coefficient);
        for (
            let digitIndex = 0;
            digitIndex < compactVssMessageDigitCount;
            digitIndex += 1
        ) {
            const column = columns[digitIndex];
            if (column === undefined) {
                throw new Error(
                    'compact VSS message digit column is outside the selected profile.',
                );
            }
            column[coefficientIndex] = remaining % compactVssMessageDigitBase;
            remaining /= compactVssMessageDigitBase;
        }
        if (remaining !== 0n) {
            throw new Error(
                `messageCoefficients.${String(coefficientIndex)} exceeds the compact VSS digit range.`,
            );
        }
    });

    return columns;
};

const aggregateCompactVssOpeningCredentialsFromRecipientCredentials = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly targetDecryptionRnsLimbCount: number;
    readonly recipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
}): readonly CompactVssAggregateThresholdOpeningCredential[] => {
    const aggregateThresholdCommitmentSet =
        verifyCompactVssAggregateThresholdCommitmentSet({
            aggregateThresholdCommitmentSet:
                input.aggregateThresholdCommitmentSet,
        });
    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords
        .filter(
            (record) =>
                record.recipientIdentity === input.trusteeIdentity &&
                record.recipientRosterPosition ===
                    input.trusteeRosterPosition &&
                record.rnsLimbIndex < input.targetDecryptionRnsLimbCount,
        )
        .sort((left, right) => left.rnsLimbIndex - right.rnsLimbIndex);
    return recipientRecords.map((record) => {
        const credentials = input.recipientShareOpeningCredentials
            .filter(
                (credential) =>
                    credential.recipientIdentity === input.trusteeIdentity &&
                    credential.recipientRosterPosition ===
                        input.trusteeRosterPosition &&
                    credential.rnsLimbIndex === record.rnsLimbIndex,
            )
            .sort(
                (left, right) =>
                    left.sourceTrusteeRosterPosition -
                    right.sourceTrusteeRosterPosition,
            );
        if (
            credentials.length !==
            aggregateThresholdCommitmentSet.participantCount
        ) {
            throw new Error(
                'compact VSS recipient share opening credentials must cover every source trustee for each local recipient limb.',
            );
        }
        const seenSourcePositions = new Set<number>();
        const sourceShareCommitmentRoots = new Set(
            record.sourceShareCommitmentRoots,
        );
        const sourceShareOpeningRoots = new Set(record.sourceShareOpeningRoots);
        const aggregateCommitmentMessageValues = Array.from(
            { length: aggregateThresholdCommitmentSet.ringDegree },
            () => 0n,
        );
        const aggregateCommitmentMessageDigitColumns = Array.from(
            { length: compactVssMessageDigitCount },
            () =>
                Array.from(
                    { length: aggregateThresholdCommitmentSet.ringDegree },
                    () => 0n,
                ),
        );
        const aggregateRandomnessByColumn: number[][] | undefined =
            credentials[0]?.randomnessByColumn.map((randomnessColumn) =>
                Array.from({ length: randomnessColumn.length }, () => 0),
            );
        if (aggregateRandomnessByColumn === undefined) {
            throw new Error(
                'compact VSS recipient share opening credentials must not be empty.',
            );
        }
        credentials.forEach((credential) => {
            if (
                seenSourcePositions.has(credential.sourceTrusteeRosterPosition)
            ) {
                throw new Error(
                    'compact VSS recipient share opening credentials must contain at most one credential per source trustee for each recipient limb.',
                );
            }
            seenSourcePositions.add(credential.sourceTrusteeRosterPosition);
            if (
                credential.rnsPrime !== record.rnsPrime ||
                credential.recipientTrusteePoint !==
                    record.recipientTrusteePoint ||
                credential.shareValues.length !==
                    aggregateThresholdCommitmentSet.ringDegree ||
                credential.shareCommitmentMessageCarryValues.length !==
                    aggregateThresholdCommitmentSet.ringDegree ||
                !sourceShareCommitmentRoots.has(
                    credential.shareCommitmentRoot,
                ) ||
                !sourceShareOpeningRoots.has(credential.shareOpeningRoot)
            ) {
                throw new Error(
                    'compact VSS recipient share opening credential must match the public aggregate threshold commitment record.',
                );
            }
            const recipientShareMessageCoefficients =
                credential.shareCommitmentMessageDigitColumns === undefined
                    ? credential.shareValues
                    : compactMessageValuesFromResiduesAndCarries({
                          residues: credential.shareValues,
                          carryValues:
                              credential.shareCommitmentMessageCarryValues,
                          rnsPrime: credential.rnsPrime,
                          ringDegree:
                              aggregateThresholdCommitmentSet.ringDegree,
                          fieldName: 'recipientShareOpeningCredential',
                      });
            const shareDigitColumns =
                credential.shareCommitmentMessageDigitColumns ??
                compactVssCanonicalMessageDigitColumns(
                    credential.shareValues,
                    aggregateThresholdCommitmentSet.ringDegree,
                );
            const recipientShareOpening = {
                commitmentRole: 'recipient-share',
                commitmentContext: {
                    objectType:
                        credential.shareCommitmentMessageDigitColumns ===
                        undefined
                            ? 'CompactVssRecipientShareCommitmentContext'
                            : 'CompactVssDerivedRecipientShareCommitmentContext',
                    objectVersion: 1,
                    ...setupContextFields(input.setupContext),
                    sourceTrusteeIdentity: credential.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        credential.sourceTrusteeRosterPosition,
                    recipientIdentity: credential.recipientIdentity,
                    recipientRosterPosition: credential.recipientRosterPosition,
                    rnsLimbIndex: credential.rnsLimbIndex,
                    rnsPrime: credential.rnsPrime,
                },
                publicMatrixSeedHash:
                    aggregateThresholdCommitmentSet.publicMatrixSeedHash,
                rnsLimbIndex: credential.rnsLimbIndex,
                rnsPrime: credential.rnsPrime,
                ringDegree: aggregateThresholdCommitmentSet.ringDegree,
                messageCoefficients: recipientShareMessageCoefficients,
                messageDigitColumns: shareDigitColumns,
                messageCoefficientBound:
                    credential.shareCommitmentMessageDigitColumns === undefined
                        ? credential.rnsPrime
                        : compactVssMessageCoordinateBound,
                randomnessByColumn: credential.randomnessByColumn,
            } as const;
            const recomputedCommitment = computeCompactVssCommitmentFromOpening(
                recipientShareOpening,
            );
            if (
                recomputedCommitment.commitmentRoot !==
                    credential.shareCommitmentRoot ||
                compactVssCommitmentPrivateOpeningRoot(
                    recipientShareOpening,
                ) !== credential.shareOpeningRoot
            ) {
                throw new Error(
                    'compact VSS recipient share opening credential does not open its public recipient-share commitment.',
                );
            }
            shareDigitColumns.forEach((column, digitIndex) => {
                const aggregateColumn =
                    aggregateCommitmentMessageDigitColumns[digitIndex];
                if (aggregateColumn === undefined) {
                    throw new Error(
                        'compact VSS aggregate digit column is outside the selected profile.',
                    );
                }
                column.forEach((digit, coefficientIndex) => {
                    aggregateColumn[coefficientIndex] =
                        (aggregateColumn[coefficientIndex] ?? 0n) +
                        nonNegativeIntegerToBigInt(
                            digit,
                            `recipientShareOpeningCredential.shareCommitmentMessageDigitColumns.${String(digitIndex)}.${String(coefficientIndex)}`,
                        );
                });
            });
            recipientShareMessageCoefficients.forEach(
                (messageValue, coefficientIndex) => {
                    aggregateCommitmentMessageValues[coefficientIndex] =
                        (aggregateCommitmentMessageValues[coefficientIndex] ??
                            0n) + BigInt(messageValue);
                },
            );
            credential.randomnessByColumn.forEach(
                (randomnessColumn, columnIndex) => {
                    const aggregateRandomnessColumn =
                        aggregateRandomnessByColumn[columnIndex];
                    if (
                        aggregateRandomnessColumn?.length !==
                        randomnessColumn.length
                    ) {
                        throw new Error(
                            'compact VSS recipient share opening credential randomness shape must match across source trustees.',
                        );
                    }
                    randomnessColumn.forEach(
                        (randomnessCoefficient, coefficientIndex) => {
                            aggregateRandomnessColumn[coefficientIndex] =
                                (aggregateRandomnessColumn[coefficientIndex] ??
                                    0) + randomnessCoefficient;
                        },
                    );
                },
            );
        });

        const rnsPrimeWide = BigInt(record.rnsPrime);
        const aggregateShareValues = aggregateCommitmentMessageValues.map(
            (messageValue, coefficientIndex) =>
                safeNumberFromBigInt(
                    messageValue % rnsPrimeWide,
                    `aggregateShareValues.${String(coefficientIndex)}`,
                ),
        );
        const aggregateCommitmentMessageCarryValues =
            aggregateCommitmentMessageValues.map(
                (messageValue, coefficientIndex) =>
                    safeNumberFromBigInt(
                        (messageValue -
                            BigInt(
                                aggregateShareValues[coefficientIndex] ?? 0,
                            )) /
                            rnsPrimeWide,
                        `aggregateCommitmentMessageCarryValues.${String(coefficientIndex)}`,
                    ),
            );
        const aggregateOpening = {
            commitmentRole: 'aggregate-threshold-share',
            commitmentContext: {
                objectType:
                    'CompactVssAggregateThresholdShareCommitmentContext',
                objectVersion: 1,
                ...setupContextFields(input.setupContext),
                recipientIdentity: record.recipientIdentity,
                recipientRosterPosition: record.recipientRosterPosition,
                rnsLimbIndex: record.rnsLimbIndex,
                rnsPrime: record.rnsPrime,
            },
            publicMatrixSeedHash:
                aggregateThresholdCommitmentSet.publicMatrixSeedHash,
            rnsLimbIndex: record.rnsLimbIndex,
            rnsPrime: record.rnsPrime,
            ringDegree: aggregateThresholdCommitmentSet.ringDegree,
            messageCoefficients: aggregateCommitmentMessageValues,
            messageDigitColumns: aggregateCommitmentMessageDigitColumns,
            messageCoefficientBound: compactVssMessageCoordinateBound,
            randomnessByColumn: aggregateRandomnessByColumn,
        } as const;
        const credential = {
            objectType: 'CompactVssAggregateThresholdOpeningCredential',
            objectVersion: 1,
            profileId: aggregateThresholdCommitmentSet.profileId,
            recipientIdentity: record.recipientIdentity,
            recipientRosterPosition: record.recipientRosterPosition,
            recipientTrusteePoint: record.recipientTrusteePoint,
            rnsLimbIndex: record.rnsLimbIndex,
            rnsPrime: record.rnsPrime,
            aggregateShareValues,
            aggregateCommitmentMessageCarryValues,
            aggregateCommitmentMessageDigitColumns,
            aggregateRandomnessByColumn,
            aggregateCommitmentRoot: record.aggregateCommitmentRoot,
            aggregateOpeningRoot:
                compactVssCommitmentPrivateOpeningRoot(aggregateOpening),
            sourceShareOpeningRoots: credentials.map(
                (sourceCredential) => sourceCredential.shareOpeningRoot,
            ),
        } satisfies CompactVssAggregateThresholdOpeningCredential;
        return verifyCompactVssAggregateOpeningCredential({
            credential,
            participantCount: aggregateThresholdCommitmentSet.participantCount,
            ringDegree: aggregateThresholdCommitmentSet.ringDegree,
        });
    });
};

const buildTargetDecryptionProofWitnessMaterial = (
    input: GeneratedLocalTrusteeSetupStateInput,
    thresholdShareCommitmentRecipientRootValue: ProtocolHash,
    aggregateThresholdShareRoot: ProtocolHash,
    aggregateThresholdShareMaterial: JsonRecord,
    envelopeReferences: readonly PrivateVssEnvelopeVerificationReference[],
    deliveredCompactVssRecipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[],
): JsonRecord => {
    const commonWitnessFields = {
        objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ...setupContextFields(input.setupContext),
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        aggregateThresholdShareRoot,
        sourcePrivateEnvelopeReferences:
            sourcePrivateEnvelopeReferences(envelopeReferences),
    } as const satisfies JsonRecord;

    if (input.compactVssTargetProofWitness === undefined) {
        return {
            ...commonWitnessFields,
        };
    }

    const compactWitness = input.compactVssTargetProofWitness;
    const aggregateThresholdCommitmentSet =
        verifyCompactVssAggregateThresholdCommitmentSet({
            aggregateThresholdCommitmentSet:
                compactWitness.aggregateThresholdCommitmentSet,
        });
    const targetDecryptionRnsLimbCount =
        compactWitness.targetDecryptionRnsLimbCount ??
        aggregateThresholdCommitmentSet.rnsLimbCount;
    if (
        !Number.isSafeInteger(targetDecryptionRnsLimbCount) ||
        targetDecryptionRnsLimbCount <= 0 ||
        targetDecryptionRnsLimbCount >
            aggregateThresholdCommitmentSet.rnsLimbCount
    ) {
        throw new Error(
            'compact VSS target proof witness targetDecryptionRnsLimbCount must be a positive safe integer within the aggregate commitment limb count.',
        );
    }

    if (
        compactWitness.coefficientCommitmentSet === undefined ||
        compactWitness.recipientShareCommitmentSet === undefined
    ) {
        throw new Error(
            'compact VSS target proof witness must include coefficient and recipient-share commitment evidence.',
        );
    }
    const activeRecipientShareOpeningCredentials = [
        ...deliveredCompactVssRecipientShareOpeningCredentials,
        ...(compactWitness.recipientShareOpeningCredentials ?? []),
    ].filter(
        (credential) =>
            credential.recipientIdentity === input.trusteeIdentity &&
            credential.recipientRosterPosition ===
                input.trusteeRosterPosition &&
            credential.rnsLimbIndex < targetDecryptionRnsLimbCount,
    );
    const hasDerivedRecipientShareOpeningCredentials =
        activeRecipientShareOpeningCredentials.some(
            (credential) =>
                credential.shareCommitmentMessageDigitColumns !== undefined,
        );
    if (hasDerivedRecipientShareOpeningCredentials) {
        verifyCompactVssDerivedRecipientShareCommitmentSet({
            setupContext: input.setupContext,
            coefficientCommitmentSet: compactWitness.coefficientCommitmentSet,
            recipientShareCommitmentSet:
                compactWitness.recipientShareCommitmentSet,
            derivedRnsLimbCount: targetDecryptionRnsLimbCount,
        });
    }
    const shareLinkageStatement = verifyCompactVssShareLinkageStatement({
        statement: compactWitness.shareLinkageStatement,
        coefficientCommitmentSet: compactWitness.coefficientCommitmentSet,
        recipientShareCommitmentSet: compactWitness.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });
    const shareLinkageStatementRecord =
        shareLinkageStatement as unknown as JsonRecord;
    assertSetupContextBinding(
        input.setupContext,
        shareLinkageStatementRecord,
        'compactVssTargetProofWitness.shareLinkageStatement',
    );
    const targetBasisHash = protocolHashField(
        shareLinkageStatementRecord,
        'targetBasisHash',
        'compactVssTargetProofWitness.shareLinkageStatement',
    );
    if (
        shareLinkageStatement.aggregateThresholdCommitmentRoot !==
        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot
    ) {
        throw new Error(
            'compact VSS share linkage statement must bind the aggregate threshold commitment set root.',
        );
    }
    if (
        shareLinkageStatement.publicMatrixSeedHash !==
        aggregateThresholdCommitmentSet.publicMatrixSeedHash
    ) {
        throw new Error(
            'compact VSS share linkage statement must bind the aggregate threshold commitment matrix seed.',
        );
    }

    const aggregateShareByLimb = new Map(
        aggregateThresholdShareLimbMaterials(
            aggregateThresholdShareMaterial,
        ).map((limbMaterial) => [limbMaterial.rnsLimbIndex, limbMaterial]),
    );
    const credentialsByCoordinate = new Map<
        string,
        CompactVssAggregateThresholdOpeningCredential
    >();
    const aggregateThresholdOpeningCredentials =
        aggregateCompactVssOpeningCredentialsFromRecipientCredentials({
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            aggregateThresholdCommitmentSet,
            targetDecryptionRnsLimbCount,
            recipientShareOpeningCredentials:
                activeRecipientShareOpeningCredentials,
        });
    aggregateThresholdOpeningCredentials
        .filter(
            (credential) =>
                credential.recipientIdentity === input.trusteeIdentity &&
                credential.recipientRosterPosition ===
                    input.trusteeRosterPosition &&
                credential.rnsLimbIndex < targetDecryptionRnsLimbCount,
        )
        .forEach((credential) => {
            const credentialKey = compactVssCredentialKey(
                credential.recipientRosterPosition,
                credential.rnsLimbIndex,
            );
            if (credentialsByCoordinate.has(credentialKey)) {
                throw new Error(
                    'compact VSS aggregate opening credentials must contain at most one credential for each recipient limb.',
                );
            }
            credentialsByCoordinate.set(credentialKey, credential);
        });

    const recipientRecords = aggregateThresholdCommitmentSet.recipientRecords
        .filter(
            (record) =>
                record.recipientIdentity === input.trusteeIdentity &&
                record.recipientRosterPosition ===
                    input.trusteeRosterPosition &&
                record.rnsLimbIndex < targetDecryptionRnsLimbCount,
        )
        .sort((left, right) => left.rnsLimbIndex - right.rnsLimbIndex);
    if (recipientRecords.length === 0) {
        throw new Error(
            'compact VSS aggregate threshold commitment set must contain records for the local trustee.',
        );
    }
    if (credentialsByCoordinate.size !== recipientRecords.length) {
        throw new Error(
            'compact VSS aggregate opening credentials must cover every local recipient limb.',
        );
    }

    const compactAggregateOpeningCredentials = recipientRecords.map(
        (record) => {
            const credential = credentialsByCoordinate.get(
                compactVssCredentialKey(
                    record.recipientRosterPosition,
                    record.rnsLimbIndex,
                ),
            );
            if (credential === undefined) {
                throw new Error(
                    'compact VSS aggregate opening credential is missing for a local recipient limb.',
                );
            }
            verifyCompactVssAggregateOpeningCredential({
                credential,
                participantCount:
                    aggregateThresholdCommitmentSet.participantCount,
                ringDegree: aggregateThresholdCommitmentSet.ringDegree,
            });
            if (
                credential.recipientTrusteePoint !==
                    record.recipientTrusteePoint ||
                credential.rnsPrime !== record.rnsPrime ||
                credential.aggregateCommitmentRoot !==
                    record.aggregateCommitmentRoot ||
                credential.aggregateOpeningRoot !== record.aggregateOpeningRoot
            ) {
                throw new Error(
                    'compact VSS aggregate opening credential must match its public aggregate commitment record.',
                );
            }
            const aggregateShareMaterial = aggregateShareByLimb.get(
                record.rnsLimbIndex,
            );
            if (aggregateShareMaterial === undefined) {
                throw new Error(
                    'compact VSS aggregate opening credential must have matching aggregate threshold share material.',
                );
            }
            if (aggregateShareMaterial.rnsPrime !== record.rnsPrime) {
                throw new Error(
                    'compact VSS aggregate opening credential rnsPrime must match aggregate threshold share material.',
                );
            }
            assertSameShareValues(
                credential.aggregateShareValues,
                aggregateShareMaterial.shareValues,
                'compactVssTargetProofWitness.derivedAggregateOpeningCredentials.aggregateShareValues',
            );
            const aggregateOpening = {
                commitmentRole: 'aggregate-threshold-share',
                commitmentContext: {
                    objectType:
                        'CompactVssAggregateThresholdShareCommitmentContext',
                    objectVersion: 1,
                    ...setupContextFields(input.setupContext),
                    recipientIdentity: credential.recipientIdentity,
                    recipientRosterPosition: credential.recipientRosterPosition,
                    rnsLimbIndex: credential.rnsLimbIndex,
                    rnsPrime: credential.rnsPrime,
                },
                publicMatrixSeedHash:
                    aggregateThresholdCommitmentSet.publicMatrixSeedHash,
                rnsLimbIndex: credential.rnsLimbIndex,
                rnsPrime: credential.rnsPrime,
                ringDegree: aggregateThresholdCommitmentSet.ringDegree,
                messageCoefficients: compactMessageValuesFromResiduesAndCarries(
                    {
                        residues: credential.aggregateShareValues,
                        carryValues:
                            credential.aggregateCommitmentMessageCarryValues,
                        rnsPrime: credential.rnsPrime,
                        ringDegree: aggregateThresholdCommitmentSet.ringDegree,
                        fieldName: 'aggregateOpeningCredential',
                    },
                ),
                messageDigitColumns:
                    credential.aggregateCommitmentMessageDigitColumns,
                messageCoefficientBound: compactVssMessageCoordinateBound,
                randomnessByColumn: credential.aggregateRandomnessByColumn,
            } as const;
            const recomputedCommitment =
                computeCompactVssCommitmentFromOpening(aggregateOpening);
            if (
                recomputedCommitment.commitmentRoot !==
                    credential.aggregateCommitmentRoot ||
                compactVssCommitmentPrivateOpeningRoot(aggregateOpening) !==
                    credential.aggregateOpeningRoot
            ) {
                throw new Error(
                    'compact VSS aggregate opening credential does not open its public aggregate commitment.',
                );
            }

            return {
                objectType: 'LocalTrusteeCompactVssAggregateOpeningCredential',
                objectVersion: 1,
                recipientIdentity: credential.recipientIdentity,
                recipientRosterPosition: credential.recipientRosterPosition,
                recipientTrusteePoint: credential.recipientTrusteePoint,
                rnsLimbIndex: credential.rnsLimbIndex,
                rnsPrime: credential.rnsPrime,
                aggregateCommitmentRoot: credential.aggregateCommitmentRoot,
                aggregateOpeningRoot: credential.aggregateOpeningRoot,
                ...compactVssAggregateDigitColumnStorage(
                    credential.aggregateCommitmentMessageDigitColumns,
                ),
                aggregateRandomnessByColumnSignedByteHex:
                    credential.aggregateRandomnessByColumn.map(
                        (randomnessColumn, columnIndex) =>
                            signedByteVectorToHex(
                                randomnessColumn,
                                `aggregateRandomnessByColumn.${String(columnIndex)}`,
                            ),
                    ),
            } satisfies JsonRecord;
        },
    );

    return {
        ...commonWitnessFields,
        compactAggregateOpening: {
            objectType: 'LocalTrusteeCompactVssAggregateOpeningWitness',
            objectVersion: 1,
            profileId: aggregateThresholdCommitmentSet.profileId,
            publicMatrixSeedHash:
                aggregateThresholdCommitmentSet.publicMatrixSeedHash,
            targetBasisHash,
            shareLinkageStatementRoot: shareLinkageStatement.statementRoot,
            aggregateThresholdCommitmentRoot:
                aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
            compactAggregateOpeningCredentials,
        },
    };
};

export async function encryptLocalTrusteeSetupState(
    input: LocalTrusteeSetupStateEncryptionInput,
): Promise<LocalTrusteeSetupStateEncryptionResult> {
    const localStateCommitment = createLocalTrusteeSetupStateCommitment(input);
    const encryptedState = await encryptLocalTrusteeState({
        localStatePlaintext: input.localStatePlaintext,
        localStateCommitment,
        setupContext: input.setupContext,
        storageKeyBytesHex: input.storageKeyBytesHex,
        aeadNonceBytesHex: input.aeadNonceBytesHex,
    });

    return {
        localStateCommitment,
        encryptedLocalState: encryptedState.encryptedLocalState,
        localStatePlaintextHash: encryptedState.localStatePlaintextHash,
        storageAadHash: encryptedState.storageAadHash,
    };
}

export const createEncryptedLocalTrusteeSetupStateFromVerifiedShares = async (
    input: GeneratedLocalTrusteeSetupStateInput,
): Promise<GeneratedLocalTrusteeSetupStateResult> => {
    assertNonEmptyString(input.trusteeIdentity, 'trusteeIdentity');
    assertNonNegativeSafeInteger(
        input.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    assertNonNegativeSafeInteger(input.deviceEpoch, 'deviceEpoch');
    const thresholdShareCommitmentRecipientRootValue =
        thresholdShareCommitmentRecipientRoot(input);
    const envelopeReferences = recipientEnvelopeReferences(input);
    const privateVssEnvelopeCommitmentRoot = protocolHashField(
        jsonRecord(
            input.privateVssEnvelopeCommitments,
            'privateVssEnvelopeCommitments',
        ),
        'privateVssEnvelopeCommitmentRoot',
        'privateVssEnvelopeCommitments',
    );
    const materialPlaintexts = aggregateVerifiedPrivateVssMaterial(
        input,
        thresholdShareCommitmentRecipientRootValue,
        envelopeReferences,
    );
    const sealedAggregateThresholdShare =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'aggregate-threshold-share-sealed',
            materialPlaintext:
                materialPlaintexts.aggregateThresholdShareMaterial,
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                thresholdShareCommitmentRecipientRootValue,
            storageKeyBytesHex: input.storageKeyBytesHex,
            aeadNonceBytesHex:
                input.sealedAggregateThresholdShareAeadNonceBytesHex,
        });
    const targetDecryptionProofWitnessMaterial =
        buildTargetDecryptionProofWitnessMaterial(
            input,
            thresholdShareCommitmentRecipientRootValue,
            sealedAggregateThresholdShare.materialRoot,
            materialPlaintexts.aggregateThresholdShareMaterial,
            envelopeReferences,
            materialPlaintexts.compactVssRecipientShareOpeningCredentials,
        );
    const sealedTargetDecryptionProofWitness =
        await encryptLocalTrusteeSetupSealedMaterial({
            materialClass: 'target-decryption-proof-witness-sealed',
            materialPlaintext: targetDecryptionProofWitnessMaterial,
            setupContext: input.setupContext,
            trusteeIdentity: input.trusteeIdentity,
            trusteeRosterPosition: input.trusteeRosterPosition,
            thresholdShareCommitmentRecipientRoot:
                thresholdShareCommitmentRecipientRootValue,
            storageKeyBytesHex: input.storageKeyBytesHex,
            aeadNonceBytesHex:
                input.sealedTargetDecryptionProofWitnessAeadNonceBytesHex,
        });
    const acceptanceRoot = issuedVssAcceptanceRoot(
        input,
        privateVssEnvelopeCommitmentRoot,
        envelopeReferences.length,
    );
    const complaintRoots = issuedVssComplaintRoots(
        input,
        privateVssEnvelopeCommitmentRoot,
    );
    const localStatePlaintext = {
        objectType: 'LocalTrusteeSetupStateSealedPayload',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupEpoch: input.setupContext.setupEpoch,
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        deviceEpoch: input.deviceEpoch,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        sealedAggregateThresholdShare:
            sealedAggregateThresholdShare.sealedMaterial,
        sealedTargetDecryptionProofWitness:
            sealedTargetDecryptionProofWitness.sealedMaterial,
        issuedVssAcceptanceRoots: [acceptanceRoot],
        issuedVssComplaintRoots: complaintRoots,
    } satisfies LocalTrusteeSetupStateSealedPayload;
    const encryptedLocalState = await encryptLocalTrusteeSetupState({
        setupContext: input.setupContext,
        trusteeIdentity: input.trusteeIdentity,
        trusteeRosterPosition: input.trusteeRosterPosition,
        thresholdShareCommitmentRecipientRoot:
            thresholdShareCommitmentRecipientRootValue,
        aggregateThresholdShareRoot: sealedAggregateThresholdShare.materialRoot,
        targetDecryptionProofWitnessRoot:
            sealedTargetDecryptionProofWitness.materialRoot,
        issuedVssAcceptanceRoot: acceptanceRoot,
        issuedVssComplaintRoots: complaintRoots,
        localStatePlaintext,
        storageKeyBytesHex: input.storageKeyBytesHex,
        aeadNonceBytesHex: input.localStateAeadNonceBytesHex,
    });

    return {
        ...encryptedLocalState,
        sealedAggregateThresholdShare:
            sealedAggregateThresholdShare.sealedMaterial,
        sealedTargetDecryptionProofWitness:
            sealedTargetDecryptionProofWitness.sealedMaterial,
    };
};

export const decryptLocalTrusteeSetupState = async (
    input: LocalTrusteeSetupStateDecryptionInput,
): Promise<LocalTrusteeStateStorageDecryptionResult> =>
    decryptLocalTrusteeState(input);
