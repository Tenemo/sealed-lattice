import {
    BrowserActionStorageCustodyError,
    type BrowserActionStorageCustodyErrorCode,
    type BrowserLocalRecordExpectedContext,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
} from '@sealed-lattice/types';

const foundationHashByteLength = 64;
const identifierByteLength = 32;
const maximumUnsigned16 = 0xffff;
const maximumUnsigned32 = 0xffff_ffff;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;
const maximumCheckpointSourceDigestCount = 4_096;

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const malformed = (
    errorCode: BrowserActionStorageCustodyErrorCode,
    message: string,
): BrowserActionStorageCustodyError =>
    new BrowserActionStorageCustodyError(errorCode, message);

export const copyLocalRecordBytes = (
    value: unknown,
    input: {
        readonly allowEmpty: boolean;
        readonly errorCode: BrowserActionStorageCustodyErrorCode;
        readonly exactByteLength?: number;
        readonly label: string;
    },
): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        (!input.allowEmpty && value.byteLength === 0) ||
        (input.exactByteLength !== undefined &&
            value.byteLength !== input.exactByteLength)
    ) {
        const lengthDescription =
            input.exactByteLength === undefined
                ? input.allowEmpty
                    ? 'bytes'
                    : 'non-empty bytes'
                : `exactly ${String(input.exactByteLength)} bytes`;
        throw malformed(
            input.errorCode,
            `${input.label} must contain ${lengthDescription}.`,
        );
    }

    return value.slice();
};

const copyUnsignedNumber = (
    value: unknown,
    maximum: number,
    label: string,
    errorCode: BrowserActionStorageCustodyErrorCode,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > maximum
    ) {
        throw malformed(
            errorCode,
            `${label} must be an unsigned integer no greater than ${String(maximum)}.`,
        );
    }

    return Number(value);
};

const copyUnsigned64 = (
    value: unknown,
    label: string,
    errorCode: BrowserActionStorageCustodyErrorCode,
): bigint => {
    if (typeof value !== 'bigint' || value < 0n || value > maximumUnsigned64) {
        throw malformed(
            errorCode,
            `${label} must be an unsigned 64-bit bigint.`,
        );
    }

    return value;
};

export const copyLocalRecordIdentifierInput = (
    value: unknown,
    errorCode: BrowserActionStorageCustodyErrorCode = 'InvalidInput',
): BrowserLocalRecordIdentifierInput => {
    if (!isRecord(value) || typeof value.recordType !== 'string') {
        throw malformed(
            errorCode,
            'Local-record identifier input is malformed.',
        );
    }

    switch (value.recordType) {
        case 'actionRandomness':
        case 'publicCoinPrivateMaterial':
            return Object.freeze({ recordType: value.recordType });
        case 'sourceVssMaterial':
            return Object.freeze({
                materialContextHash: copyLocalRecordBytes(
                    value.materialContextHash,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: foundationHashByteLength,
                        label: 'Material-context hash',
                    },
                ),
                recordType: value.recordType,
            });
        case 'aggregateThresholdShare':
            return Object.freeze({
                recipientInputRoot: copyLocalRecordBytes(
                    value.recipientInputRoot,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: foundationHashByteLength,
                        label: 'Recipient-input root',
                    },
                ),
                recordType: value.recordType,
            });
        case 'proofAttempt':
            return Object.freeze({
                applicationSlotHash: copyLocalRecordBytes(
                    value.applicationSlotHash,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: foundationHashByteLength,
                        label: 'Application-slot hash',
                    },
                ),
                recordType: value.recordType,
            });
        case 'ballotAttempt':
            return Object.freeze({
                ballotEncryptionAttemptIdentifier: copyLocalRecordBytes(
                    value.ballotEncryptionAttemptIdentifier,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: identifierByteLength,
                        label: 'Ballot-encryption attempt identifier',
                    },
                ),
                canonicalBallotStatementBytes: copyLocalRecordBytes(
                    value.canonicalBallotStatementBytes,
                    {
                        allowEmpty: false,
                        errorCode,
                        label: 'Canonical ballot statement',
                    },
                ),
                recordType: value.recordType,
            });
        case 'exactOutputChunk':
            return Object.freeze({
                capabilityKind: copyUnsignedNumber(
                    value.capabilityKind,
                    maximumUnsigned16,
                    'Capability kind',
                    errorCode,
                ),
                exactOutputHash: copyLocalRecordBytes(value.exactOutputHash, {
                    allowEmpty: false,
                    errorCode,
                    exactByteLength: foundationHashByteLength,
                    label: 'Exact-output hash',
                }),
                outputChunkIndex: copyUnsigned64(
                    value.outputChunkIndex,
                    'Output-chunk index',
                    errorCode,
                ),
                recordType: value.recordType,
            });
        case 'subjectState':
        case 'witnessState':
            return Object.freeze({
                recordType: value.recordType,
                stateKey: copyLocalRecordBytes(value.stateKey, {
                    allowEmpty: false,
                    errorCode,
                    exactByteLength: foundationHashByteLength,
                    label: 'State key',
                }),
            });
        case 'checkpointManifest': {
            if (
                !Array.isArray(value.orderedSourceDigests) ||
                value.orderedSourceDigests.length >
                    maximumCheckpointSourceDigestCount
            ) {
                throw malformed(
                    errorCode,
                    `Ordered checkpoint source digests must contain at most ${String(maximumCheckpointSourceDigestCount)} hashes.`,
                );
            }
            const orderedSourceDigests = value.orderedSourceDigests.map(
                (digest) =>
                    copyLocalRecordBytes(digest, {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: foundationHashByteLength,
                        label: 'Checkpoint source digest',
                    }),
            );

            return Object.freeze({
                checkpointLineageIdentifier: copyLocalRecordBytes(
                    value.checkpointLineageIdentifier,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: identifierByteLength,
                        label: 'Checkpoint-lineage identifier',
                    },
                ),
                operationKind: copyUnsignedNumber(
                    value.operationKind,
                    maximumUnsigned16,
                    'Checkpoint operation kind',
                    errorCode,
                ),
                orderedSourceDigests: Object.freeze(orderedSourceDigests),
                recordType: value.recordType,
                runtimeBuildManifestHash: copyLocalRecordBytes(
                    value.runtimeBuildManifestHash,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: foundationHashByteLength,
                        label: 'Runtime build-manifest hash',
                    },
                ),
                safeBoundaryOrdinal: copyUnsignedNumber(
                    value.safeBoundaryOrdinal,
                    maximumUnsigned32,
                    'Checkpoint safe-boundary ordinal',
                    errorCode,
                ),
            });
        }
        case 'checkpointChunk':
            return Object.freeze({
                checkpointIdentifier: copyLocalRecordBytes(
                    value.checkpointIdentifier,
                    {
                        allowEmpty: false,
                        errorCode,
                        exactByteLength: foundationHashByteLength,
                        label: 'Checkpoint identifier',
                    },
                ),
                chunkDigest: copyLocalRecordBytes(value.chunkDigest, {
                    allowEmpty: false,
                    errorCode,
                    exactByteLength: foundationHashByteLength,
                    label: 'Checkpoint chunk digest',
                }),
                chunkIndex: copyUnsignedNumber(
                    value.chunkIndex,
                    maximumUnsigned32,
                    'Checkpoint chunk index',
                    errorCode,
                ),
                recordType: value.recordType,
            });
        default:
            throw malformed(errorCode, 'Local-record type is unsupported.');
    }
};

const copyLocalRecordExpectedContext = (
    value: unknown,
    errorCode: BrowserActionStorageCustodyErrorCode = 'InvalidInput',
): BrowserLocalRecordExpectedContext => {
    if (!isRecord(value)) {
        throw malformed(
            errorCode,
            'Local-record expected context is malformed.',
        );
    }
    const recordVersion = copyUnsigned64(
        value.recordVersion,
        'Local-record version',
        errorCode,
    );
    const predecessorRecordHash =
        value.predecessorRecordHash === undefined
            ? undefined
            : copyLocalRecordBytes(value.predecessorRecordHash, {
                  allowEmpty: false,
                  errorCode,
                  exactByteLength: foundationHashByteLength,
                  label: 'Predecessor record hash',
              });
    if ((recordVersion === 0n) !== (predecessorRecordHash === undefined)) {
        throw malformed(
            errorCode,
            'Predecessor record-hash presence must match the local-record version.',
        );
    }

    return Object.freeze({
        actionRandomnessCommitment: copyLocalRecordBytes(
            value.actionRandomnessCommitment,
            {
                allowEmpty: false,
                errorCode,
                exactByteLength: foundationHashByteLength,
                label: 'Action-randomness commitment',
            },
        ),
        creationRecoveryEpoch: copyUnsigned64(
            value.creationRecoveryEpoch,
            'Local-record creation recovery epoch',
            errorCode,
        ),
        identifierInput: copyLocalRecordIdentifierInput(
            value.identifierInput,
            errorCode,
        ),
        ...(predecessorRecordHash === undefined
            ? {}
            : { predecessorRecordHash }),
        recordVersion,
    });
};

export const copyLocalRecordSealInput = (
    value: unknown,
    errorCode: BrowserActionStorageCustodyErrorCode = 'InvalidInput',
): BrowserLocalRecordSealInput => {
    if (!isRecord(value)) {
        throw malformed(errorCode, 'Local-record seal input is malformed.');
    }

    return Object.freeze({
        ...copyLocalRecordExpectedContext(value, errorCode),
        plaintext: copyLocalRecordBytes(value.plaintext, {
            allowEmpty: true,
            errorCode,
            label: 'Local-record plaintext',
        }),
    });
};

export const copyLocalRecordOpenInput = (
    value: unknown,
    errorCode: BrowserActionStorageCustodyErrorCode = 'InvalidInput',
): BrowserLocalRecordOpenInput => {
    if (!isRecord(value)) {
        throw malformed(errorCode, 'Local-record open input is malformed.');
    }

    return Object.freeze({
        ...copyLocalRecordExpectedContext(value, errorCode),
        envelope: copyLocalRecordBytes(value.envelope, {
            allowEmpty: false,
            errorCode,
            label: 'Local-record envelope',
        }),
    });
};
