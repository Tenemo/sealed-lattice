import { bytesToHex, normalizeInputToBytes } from './bytes.js';
import { UnsupportedRuntimeError } from './errors.js';

type SupportedCrypto = Crypto & {
    subtle: SubtleCrypto;
};

const hasDigest = (value: Crypto | undefined): value is SupportedCrypto =>
    typeof value?.subtle?.digest === 'function';

export const getWebCrypto = (): SupportedCrypto => {
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
