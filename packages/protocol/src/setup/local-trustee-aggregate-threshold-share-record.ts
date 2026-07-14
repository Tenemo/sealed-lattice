import { foundationProfile } from '@sealed-lattice/types';

import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesFromHex,
    bytesToHex,
} from './common-fields.js';
import { appendVaruint } from './varuint-encoding.js';
import type { LocalTrusteeVssPublicAggregateOpeningCredentialHandoff } from './vss-commitments/commitment-sets.js';

const recordMagic = new Uint8Array([
    0x53, 0x4c, 0x41, 0x54, 0x53, 0x52, 0x30, 0x31,
]);
const foundationHashByteLength = 64;
const maximumCredentialCount = 17;
const maximumIdentityByteLength = 4_096;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', {
    fatal: true,
    ignoreBOM: true,
});

type AggregateOpeningCredential =
    LocalTrusteeVssPublicAggregateOpeningCredentialHandoff['aggregateOpeningCredentials'][number];

const isCredentialArray = (
    value: unknown,
): value is readonly AggregateOpeningCredential[] => Array.isArray(value);

const appendBytes = (output: number[], bytes: Uint8Array): void => {
    for (const byte of bytes) {
        output.push(byte);
    }
};

const appendLengthPrefixedBytes = (
    output: number[],
    bytes: Uint8Array,
): void => {
    appendVaruint(output, bytes.byteLength);
    appendBytes(output, bytes);
};

const encodeIdentity = (identity: string, fieldName: string): Uint8Array => {
    assertNonEmptyString(identity, fieldName);
    const bytes = textEncoder.encode(identity);
    if (bytes.byteLength > maximumIdentityByteLength) {
        throw new Error(
            `${fieldName} exceeds the supported UTF-8 byte length.`,
        );
    }

    return bytes;
};

const validateCredential = (
    credential: AggregateOpeningCredential,
    credentialIndex: number,
    handoff: LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
    previousLimbIndex: number | undefined,
): Readonly<{
    aggregateCommitmentMessageBytes: Uint8Array;
    aggregateMaterialSeedBytes: Uint8Array;
}> => {
    const objectPath = `aggregateOpeningCredentials.${String(credentialIndex)}`;
    if (
        credential.objectType !==
        'LocalTrusteeVssPublicAggregateOpeningCredential'
    ) {
        throw new TypeError(
            `${objectPath}.objectType must be LocalTrusteeVssPublicAggregateOpeningCredential.`,
        );
    }
    if (
        credential.recipientIdentity !== handoff.trusteeIdentity ||
        credential.recipientRosterPosition !== handoff.trusteeRosterPosition
    ) {
        throw new Error(
            `${objectPath} must belong to the local trustee named by the handoff.`,
        );
    }
    assertNonNegativeSafeInteger(
        credential.rnsLimbIndex,
        `${objectPath}.rnsLimbIndex`,
    );
    if (
        previousLimbIndex !== undefined &&
        credential.rnsLimbIndex <= previousLimbIndex
    ) {
        throw new Error(
            'aggregate opening credentials must be ordered by unique increasing RNS limb index.',
        );
    }
    assertPositiveSafeInteger(credential.rnsPrime, `${objectPath}.rnsPrime`);
    assertProtocolHash(
        credential.aggregateCommitmentRoot,
        `${objectPath}.aggregateCommitmentRoot`,
    );
    assertProtocolHash(
        credential.aggregateOpeningRoot,
        `${objectPath}.aggregateOpeningRoot`,
    );
    assertProtocolHash(
        credential.aggregateMaterialSeedHex,
        `${objectPath}.aggregateMaterialSeedHex`,
    );
    const aggregateCommitmentMessageBytes = bytesFromHex(
        credential.aggregateCommitmentMessageValuesLeHex,
        `${objectPath}.aggregateCommitmentMessageValuesLeHex`,
    );
    if (
        aggregateCommitmentMessageBytes.byteLength === 0 ||
        aggregateCommitmentMessageBytes.byteLength % 8 !== 0
    ) {
        throw new Error(
            `${objectPath}.aggregateCommitmentMessageValuesLeHex must encode a non-empty vector of unsigned 64-bit values.`,
        );
    }

    return {
        aggregateCommitmentMessageBytes,
        aggregateMaterialSeedBytes: bytesFromHex(
            credential.aggregateMaterialSeedHex,
            `${objectPath}.aggregateMaterialSeedHex`,
        ),
    };
};

export const encodeAggregateThresholdShareRecord = (
    handoff: LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
): Uint8Array => {
    if (
        typeof handoff !== 'object' ||
        handoff === null ||
        handoff.objectType !==
            'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff'
    ) {
        throw new TypeError(
            'aggregate opening credential handoff has the wrong type.',
        );
    }
    const trusteeIdentityBytes = encodeIdentity(
        handoff.trusteeIdentity,
        'trusteeIdentity',
    );
    assertNonNegativeSafeInteger(
        handoff.trusteeRosterPosition,
        'trusteeRosterPosition',
    );
    const aggregateOpeningCredentials: unknown =
        handoff.aggregateOpeningCredentials;
    if (
        !isCredentialArray(aggregateOpeningCredentials) ||
        aggregateOpeningCredentials.length === 0 ||
        aggregateOpeningCredentials.length > maximumCredentialCount
    ) {
        throw new Error(
            `aggregateOpeningCredentials must contain 1 through ${String(maximumCredentialCount)} credentials.`,
        );
    }

    const output: number[] = [];
    appendBytes(output, recordMagic);
    appendLengthPrefixedBytes(output, trusteeIdentityBytes);
    appendVaruint(output, handoff.trusteeRosterPosition);
    appendVaruint(output, aggregateOpeningCredentials.length);
    let previousLimbIndex: number | undefined;
    aggregateOpeningCredentials.forEach((credential, credentialIndex) => {
        const validated = validateCredential(
            credential,
            credentialIndex,
            handoff,
            previousLimbIndex,
        );
        previousLimbIndex = credential.rnsLimbIndex;
        appendLengthPrefixedBytes(
            output,
            encodeIdentity(
                credential.recipientIdentity,
                `aggregateOpeningCredentials.${String(credentialIndex)}.recipientIdentity`,
            ),
        );
        appendVaruint(output, credential.recipientRosterPosition);
        appendVaruint(output, credential.rnsLimbIndex);
        appendVaruint(output, credential.rnsPrime);
        appendBytes(
            output,
            bytesFromHex(
                credential.aggregateCommitmentRoot,
                `aggregateOpeningCredentials.${String(credentialIndex)}.aggregateCommitmentRoot`,
            ),
        );
        appendBytes(
            output,
            bytesFromHex(
                credential.aggregateOpeningRoot,
                `aggregateOpeningCredentials.${String(credentialIndex)}.aggregateOpeningRoot`,
            ),
        );
        appendLengthPrefixedBytes(
            output,
            validated.aggregateCommitmentMessageBytes,
        );
        appendBytes(output, validated.aggregateMaterialSeedBytes);
        if (output.length > foundationProfile.streamChunkByteLength) {
            throw new Error(
                'aggregate threshold-share record exceeds the local-record plaintext limit.',
            );
        }
    });

    return Uint8Array.from(output);
};

class RecordReader {
    readonly #bytes: Uint8Array;
    #offset = 0;

    public constructor(bytes: Uint8Array) {
        this.#bytes = bytes;
    }

    public get finished(): boolean {
        return this.#offset === this.#bytes.byteLength;
    }

    public readBytes(byteLength: number, fieldName: string): Uint8Array {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            this.#offset + byteLength > this.#bytes.byteLength
        ) {
            throw new Error(`${fieldName} is truncated.`);
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;

        return value;
    }

    public readVaruint(fieldName: string): number {
        const encodedBytes: number[] = [];
        let multiplier = 1;
        let value = 0;
        while (true) {
            const [byte] = this.readBytes(1, fieldName);
            if (byte === undefined) {
                throw new Error(`${fieldName} is truncated.`);
            }
            encodedBytes.push(byte);
            value += (byte & 0x7f) * multiplier;
            if (!Number.isSafeInteger(value)) {
                throw new Error(`${fieldName} exceeds the safe integer range.`);
            }
            if ((byte & 0x80) === 0) {
                break;
            }
            multiplier *= 128;
            if (!Number.isSafeInteger(multiplier)) {
                throw new Error(`${fieldName} is too large.`);
            }
        }
        const canonicalBytes: number[] = [];
        appendVaruint(canonicalBytes, value);
        if (
            canonicalBytes.length !== encodedBytes.length ||
            canonicalBytes.some(
                (canonicalByte, byteIndex) =>
                    canonicalByte !== encodedBytes[byteIndex],
            )
        ) {
            throw new Error(`${fieldName} uses a non-canonical varuint.`);
        }

        return value;
    }

    public readLengthPrefixedBytes(fieldName: string): Uint8Array {
        return this.readBytes(
            this.readVaruint(`${fieldName}.length`),
            fieldName,
        );
    }
}

const decodeIdentity = (reader: RecordReader, fieldName: string): string => {
    const bytes = reader.readLengthPrefixedBytes(fieldName);
    if (
        bytes.byteLength === 0 ||
        bytes.byteLength > maximumIdentityByteLength
    ) {
        throw new Error(`${fieldName} has an unsupported UTF-8 byte length.`);
    }
    let identity: string;
    try {
        identity = textDecoder.decode(bytes);
    } catch {
        throw new Error(`${fieldName} is not canonical UTF-8.`);
    }
    const reencoded = textEncoder.encode(identity);
    if (
        reencoded.byteLength !== bytes.byteLength ||
        reencoded.some((byte, byteIndex) => byte !== bytes[byteIndex])
    ) {
        throw new Error(`${fieldName} is not canonical UTF-8.`);
    }

    return identity;
};

export const decodeAggregateThresholdShareRecord = (
    plaintext: Uint8Array,
): LocalTrusteeVssPublicAggregateOpeningCredentialHandoff => {
    if (
        !(plaintext instanceof Uint8Array) ||
        plaintext.byteLength === 0 ||
        plaintext.byteLength > foundationProfile.streamChunkByteLength
    ) {
        throw new TypeError(
            'aggregate threshold-share plaintext has an unsupported length.',
        );
    }
    const reader = new RecordReader(plaintext);
    const magic = reader.readBytes(recordMagic.byteLength, 'record magic');
    if (magic.some((byte, byteIndex) => byte !== recordMagic[byteIndex])) {
        throw new Error(
            'aggregate threshold-share record has the wrong magic.',
        );
    }
    const trusteeIdentity = decodeIdentity(reader, 'trusteeIdentity');
    const trusteeRosterPosition = reader.readVaruint('trusteeRosterPosition');
    const credentialCount = reader.readVaruint('credentialCount');
    if (credentialCount === 0 || credentialCount > maximumCredentialCount) {
        throw new Error(
            `credentialCount must be 1 through ${String(maximumCredentialCount)}.`,
        );
    }
    const aggregateOpeningCredentials: AggregateOpeningCredential[] = [];
    for (
        let credentialIndex = 0;
        credentialIndex < credentialCount;
        credentialIndex += 1
    ) {
        const objectPath = `aggregateOpeningCredentials.${String(credentialIndex)}`;
        const recipientIdentity = decodeIdentity(
            reader,
            `${objectPath}.recipientIdentity`,
        );
        const recipientRosterPosition = reader.readVaruint(
            `${objectPath}.recipientRosterPosition`,
        );
        const rnsLimbIndex = reader.readVaruint(`${objectPath}.rnsLimbIndex`);
        const rnsPrime = reader.readVaruint(`${objectPath}.rnsPrime`);
        const aggregateCommitmentRoot = bytesToHex(
            reader.readBytes(
                foundationHashByteLength,
                `${objectPath}.aggregateCommitmentRoot`,
            ),
        );
        const aggregateOpeningRoot = bytesToHex(
            reader.readBytes(
                foundationHashByteLength,
                `${objectPath}.aggregateOpeningRoot`,
            ),
        );
        const aggregateCommitmentMessageValuesLeHex = bytesToHex(
            reader.readLengthPrefixedBytes(
                `${objectPath}.aggregateCommitmentMessageValuesLeHex`,
            ),
        );
        const aggregateMaterialSeedHex = bytesToHex(
            reader.readBytes(
                foundationHashByteLength,
                `${objectPath}.aggregateMaterialSeedHex`,
            ),
        );
        aggregateOpeningCredentials.push({
            objectType: 'LocalTrusteeVssPublicAggregateOpeningCredential',
            recipientIdentity,
            recipientRosterPosition,
            rnsLimbIndex,
            rnsPrime,
            aggregateCommitmentRoot,
            aggregateOpeningRoot,
            aggregateCommitmentMessageValuesLeHex,
            aggregateMaterialSeedHex,
        });
    }
    if (!reader.finished) {
        throw new Error(
            'aggregate threshold-share record contains trailing bytes.',
        );
    }
    const handoff = {
        objectType: 'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff',
        trusteeIdentity,
        trusteeRosterPosition,
        aggregateOpeningCredentials,
    } as const satisfies LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
    const canonicalBytes = encodeAggregateThresholdShareRecord(handoff);
    if (
        canonicalBytes.byteLength !== plaintext.byteLength ||
        canonicalBytes.some((byte, byteIndex) => byte !== plaintext[byteIndex])
    ) {
        throw new Error(
            'aggregate threshold-share record is not canonically encoded.',
        );
    }

    return handoff;
};
