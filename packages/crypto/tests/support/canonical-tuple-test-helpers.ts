import { hashCanonicalCarrierFixtureFrame } from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';

const canonicalTupleVersion = 1;
const textEncoder = new TextEncoder();

const concatenateBytes = (...byteArrays: readonly Uint8Array[]): Uint8Array => {
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

const variableValue = (value: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(value.byteLength), value);

const canonicalItem = (
    itemType: number,
    canonicalValue: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalValue.byteLength),
        canonicalValue,
    );

const canonicalTuple = (
    schemaIdentifier: number,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(canonicalTupleVersion),
        unsigned32LittleEndian(items.length),
        ...items,
    );

const asciiItem = (value: string): Uint8Array =>
    canonicalItem(0x02, variableValue(textEncoder.encode(value)));

const unsigned16Item = (value: number): Uint8Array =>
    canonicalItem(0x03, unsigned16LittleEndian(value));

export const variableBytesItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x01, variableValue(value));

export const fixedBytesItem = (value: Uint8Array): Uint8Array =>
    canonicalItem(0x01, value);

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
            fixedBytesItem(entry.signingVerificationKey),
            fixedBytesItem(entry.mailboxEncapsulationKey),
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
