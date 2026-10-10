import { concatenate, encodeText } from '../shared/bytes.js';

// The root nonce is the generation as a 96-bit big-endian counter; every
// root after the initial enrollment uses a fresh key, so a repeated
// generation never repeats a nonce under one key.
const rootNonce = (generation: number) => {
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(4, BigInt(generation));
    return nonce;
};

export const rootAssociatedData = (runtime: Uint8Array) =>
    concatenate(encodeText('POL1'), runtime);

export const createRootKey = () =>
    crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
    ]);

export const sealRoot = async (
    key: CryptoKey,
    generation: number,
    associatedData: Uint8Array,
    plaintext: Uint8Array,
) =>
    new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: rootNonce(generation),
                additionalData: new Uint8Array(associatedData),
            },
            key,
            new Uint8Array(plaintext),
        ),
    );

export const openRoot = async (
    key: CryptoKey,
    generation: number,
    associatedData: Uint8Array,
    sealed: Uint8Array,
) =>
    new Uint8Array(
        await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: rootNonce(generation),
                additionalData: new Uint8Array(associatedData),
            },
            key,
            new Uint8Array(sealed),
        ),
    );
