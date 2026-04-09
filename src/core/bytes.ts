const textEncoder = new TextEncoder();

export const normalizeInputToBytes = (
    input: string | Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (typeof input === 'string') {
        return Uint8Array.from(textEncoder.encode(input));
    }

    return Uint8Array.from(input);
};

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
