import { hashCanonicalCarrierFixtureFrame } from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';

const canonicalTupleVersion = 1;
const textEncoder = new TextEncoder();

export const concatenateBytes = (
    ...byteArrays: readonly Uint8Array[]
): Uint8Array => {
    const byteLength = byteArrays.reduce(
        (totalByteLength, bytes) => totalByteLength + bytes.byteLength,
        0,
    );
    const result = new Uint8Array(byteLength);
    let byteOffset = 0;
    for (const bytes of byteArrays) {
        result.set(bytes, byteOffset);
        byteOffset += bytes.byteLength;
    }

    return result;
};

export const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

export const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

export const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

export const variableValue = (value: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(value.byteLength), value);

export const canonicalItem = (
    itemType: number,
    canonicalValue: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalValue.byteLength),
        canonicalValue,
    );

export const canonicalTuple = (
    schemaIdentifier: number,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(canonicalTupleVersion),
        unsigned32LittleEndian(items.length),
        ...items,
    );

export const asciiItem = (value: string): Uint8Array =>
    canonicalItem(0x02, variableValue(textEncoder.encode(value)));

export const unsigned16Item = (value: number): Uint8Array =>
    canonicalItem(0x03, unsigned16LittleEndian(value));

export const unsigned32Item = (value: number): Uint8Array =>
    canonicalItem(0x04, unsigned32LittleEndian(value));

export const unsigned64Item = (value: bigint): Uint8Array =>
    canonicalItem(0x05, unsigned64LittleEndian(value));

export const hashItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x06, value);

export const variableBytesItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x01, variableValue(value));

export const fixedBytesItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x01, value);

export const participantIdentityItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x07, value);

export const displayTextItem = (value: string): Uint8Array =>
    canonicalItem(0x0c, variableValue(textEncoder.encode(value)));

export const homogeneousListItem = (
    elementItemType: number,
    canonicalValues: readonly Uint8Array[],
): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(elementItemType),
            unsigned32LittleEndian(canonicalValues.length),
            ...canonicalValues,
        ),
    );

export const emptyOptionalItem = (containedItemType: number): Uint8Array =>
    canonicalItem(
        0x0d,
        concatenateBytes(
            unsigned16LittleEndian(containedItemType),
            Uint8Array.of(0),
        ),
    );

export const presentOptionalItem = (
    containedItemType: number,
    canonicalValue: Uint8Array,
): Uint8Array =>
    canonicalItem(
        0x0d,
        concatenateBytes(
            unsigned16LittleEndian(containedItemType),
            Uint8Array.of(1),
            canonicalValue,
        ),
    );

export const emptyHomogeneousListItem = (elementItemType: number): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(elementItemType),
            unsigned32LittleEndian(0),
        ),
    );

export const foundationHash512 = (
    domain: string,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    hashCanonicalCarrierFixtureFrame(
        canonicalTuple(0x0001, asciiItem(domain), ...items),
    );

export const createCanonicalTestRosterBytes = (
    entries: readonly Readonly<{
        signingVerificationKey: Uint8Array;
        mailboxEncapsulationKey: Uint8Array;
    }>[],
): Uint8Array => {
    const rosterEntries = entries.map((entry, rosterPosition) =>
        canonicalTuple(
            0x0114,
            unsigned16Item(rosterPosition),
            canonicalItem(0x01, entry.signingVerificationKey),
            canonicalItem(0x01, entry.mailboxEncapsulationKey),
        ),
    );

    return canonicalTuple(
        0x0115,
        canonicalItem(
            0x0e,
            concatenateBytes(
                unsigned16LittleEndian(0x09),
                unsigned32LittleEndian(rosterEntries.length),
                ...rosterEntries,
            ),
        ),
    );
};
