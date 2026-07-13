import { hexToBytes } from '@noble/hashes/utils.js';

const isLowercaseCanonicalHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

export const decodeCanonicalHex = (
    value: string,
    fieldName: string,
): Uint8Array => {
    if (!isLowercaseCanonicalHex(value)) {
        throw new TypeError(`${fieldName} must be lowercase canonical hex.`);
    }

    return hexToBytes(value);
};

export const decodeFixedHex = (
    value: string,
    expectedByteLength: number,
    fieldName: string,
): Uint8Array => {
    const bytes = decodeCanonicalHex(value, fieldName);
    if (bytes.byteLength !== expectedByteLength) {
        throw new TypeError(
            `${fieldName} must be ${String(expectedByteLength)} bytes.`,
        );
    }

    return Uint8Array.from(bytes);
};

export const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

export const webCryptoRandomBytes = (
    byteLength: number,
    unavailableMessage: string,
): Uint8Array => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(unavailableMessage);
    }
    const bytes = new Uint8Array(byteLength);
    cryptoProvider.getRandomValues(bytes);

    return bytes;
};

export const requireSubtleCrypto = (
    unavailableMessage: string,
): SubtleCrypto => {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined) {
        throw new Error(unavailableMessage);
    }

    return subtle;
};

export const importAesGcmKey = async (
    keyBytes: Uint8Array,
    keyUsages: readonly KeyUsage[],
    unavailableMessage: string,
): Promise<CryptoKey> =>
    requireSubtleCrypto(unavailableMessage).importKey(
        'raw',
        arrayBufferFromBytes(keyBytes),
        'AES-GCM',
        false,
        keyUsages,
    );
