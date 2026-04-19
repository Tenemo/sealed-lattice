type SupportedCrypto = Crypto & {
    subtle: SubtleCrypto;
};

const textEncoder = new TextEncoder();

const hasDigest = (value: Crypto | undefined): value is SupportedCrypto =>
    typeof value?.subtle?.digest === 'function';

const normalizeInputToBytes = (
    input: string | Uint8Array,
): Uint8Array<ArrayBuffer> => {
    if (typeof input === 'string') {
        return Uint8Array.from(textEncoder.encode(input));
    }

    return Uint8Array.from(input);
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');

/**
 * Error thrown when the current runtime does not provide the Web Crypto API
 * features required by the public API surface.
 */
export class UnsupportedRuntimeError extends Error {
    public constructor(
        message = 'sealed-lattice requires globalThis.crypto.subtle.digest.',
    ) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

const getWebCrypto = (): SupportedCrypto => {
    const cryptoApi = globalThis.crypto;
    if (!hasDigest(cryptoApi)) {
        throw new UnsupportedRuntimeError();
    }

    return cryptoApi;
};

/**
 * Returns the lowercase hexadecimal SHA-256 digest of the provided text or
 * byte input.
 */
export const sha256Hex = async (
    input: string | Uint8Array,
): Promise<string> => {
    const digest = await getWebCrypto().subtle.digest(
        'SHA-256',
        normalizeInputToBytes(input),
    );

    return bytesToHex(new Uint8Array(digest));
};
