// Byte encodings shared by the participant worker and its host. Integers are
// little-endian, matching the Rust research crates.

export const encodeText = (value: string): Uint8Array =>
    new TextEncoder().encode(value);

export const hexadecimal = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');

export const fromHexadecimal = (value: string): Uint8Array => {
    if (!/^(?:[0-9a-f]{2})*$/u.test(value))
        throw new Error('Malformed hexadecimal bytes.');
    return Uint8Array.from(value.match(/../gu) ?? [], (byte) =>
        Number.parseInt(byte, 16),
    );
};

export const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
    left.length === right.length &&
    left.every((value, index) => value === right[index]);

export const concatenate = (...parts: readonly Uint8Array[]): Uint8Array => {
    const bytes = new Uint8Array(
        parts.reduce((sum, part) => sum + part.length, 0),
    );
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.length;
    }
    return bytes;
};

export const unsigned16 = (value: number): Uint8Array => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff)
        throw new Error('Value exceeds an unsigned 16-bit integer.');
    return Uint8Array.of(value & 0xff, value >>> 8);
};

export const unsigned32 = (value: number): Uint8Array => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff)
        throw new Error('Value exceeds an unsigned 32-bit integer.');
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

export const unsigned64 = (value: bigint): Uint8Array => {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn)
        throw new Error('Value exceeds an unsigned 64-bit integer.');
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const view = (bytes: Uint8Array) =>
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

export const readUnsigned16 = (bytes: Uint8Array, offset: number): number =>
    view(bytes).getUint16(offset, true);

export const readUnsigned32 = (bytes: Uint8Array, offset: number): number =>
    view(bytes).getUint32(offset, true);

export const readUnsigned64 = (bytes: Uint8Array, offset: number): bigint =>
    view(bytes).getBigUint64(offset, true);

// The values of a canonical tuple: a two-byte schema identifier and two-byte
// version, a four-byte value count, then per value a two-byte type and a
// four-byte length before its bytes.
export const tupleFields = (bytes: Uint8Array): Uint8Array[] => {
    if (bytes.length < 8) throw new Error('Canonical tuple is truncated.');
    const count = readUnsigned32(bytes, 4);
    const fields: Uint8Array[] = [];
    let position = 8;
    for (let index = 0; index < count; index++) {
        if (position + 6 > bytes.length)
            throw new Error('Canonical tuple is truncated.');
        const length = readUnsigned32(bytes, position + 2);
        if (position + 6 + length > bytes.length)
            throw new Error('Canonical tuple is truncated.');
        fields.push(bytes.subarray(position + 6, position + 6 + length));
        position += 6 + length;
    }
    if (position !== bytes.length)
        throw new Error('Canonical tuple has trailing bytes.');
    return fields;
};
