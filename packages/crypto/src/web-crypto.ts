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
