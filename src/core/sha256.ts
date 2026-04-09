import { bytesToHex, normalizeInputToBytes } from './bytes.js';
import { requireWebCrypto } from './runtime.js';

/**
 * Returns the lowercase hexadecimal SHA-256 digest of the provided text or
 * byte input.
 */
export const sha256Hex = async (
    input: string | Uint8Array,
): Promise<string> => {
    const cryptoApi = requireWebCrypto();
    const digest = await cryptoApi.subtle.digest(
        'SHA-256',
        normalizeInputToBytes(input),
    );

    return bytesToHex(new Uint8Array(digest));
};
