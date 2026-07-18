import { webcrypto } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
} from '#packages/wasm/src/canonical-stream-runtime';
import {
    loadFreshTranscriptCoreKernel,
    openMailboxGcmRuntime,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const cryptoProvider = webcrypto as unknown as Crypto;

const deterministicBytes = (
    byteLength: number,
    seed: number,
): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(byteLength);
    for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
        bytes[byteIndex] = (seed + byteIndex * 131) & 0xff;
    }
    return bytes;
};

const fragments = (
    bytes: Uint8Array,
    fragmentByteLength: number,
): readonly ArrayBuffer[] => {
    const output: ArrayBuffer[] = [];
    for (
        let byteOffset = 0;
        byteOffset < bytes.byteLength;
        byteOffset += fragmentByteLength
    ) {
        output.push(
            bytes.slice(byteOffset, byteOffset + fragmentByteLength).buffer,
        );
    }
    return output;
};

const concatenate = (
    parts: readonly ArrayBuffer[],
): Uint8Array<ArrayBuffer> => {
    const byteLength = parts.reduce(
        (totalByteLength, part) => totalByteLength + part.byteLength,
        0,
    );
    const output = new Uint8Array(byteLength);
    let byteOffset = 0;
    for (const part of parts) {
        output.set(new Uint8Array(part), byteOffset);
        byteOffset += part.byteLength;
    }
    return output;
};

describe('Mailbox AES-GCM real-WASM runtime', () => {
    let kernel: TranscriptCoreKernel;

    beforeAll(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('matches Web Crypto across independent encryption, authentication, and decryption fragmentations', async () => {
        const key = deterministicBytes(32, 0x29);
        const nonce = deterministicBytes(12, 0x71);
        const associatedData = deterministicBytes(79, 0x43);
        const plaintext = deterministicBytes(65_537, 0x17);
        const importedKey = await cryptoProvider.subtle.importKey(
            'raw',
            key,
            'AES-GCM',
            false,
            ['encrypt'],
        );
        const webCryptoSealed = new Uint8Array(
            await cryptoProvider.subtle.encrypt(
                {
                    additionalData: associatedData,
                    iv: nonce,
                    name: 'AES-GCM',
                    tagLength: 128,
                },
                importedKey,
                plaintext,
            ),
        );
        const expectedCiphertext = webCryptoSealed.slice(0, -16);
        const expectedTag = webCryptoSealed.slice(-16);

        for (const encryptionFragmentByteLength of [1, 15, 16, 17, 65_536]) {
            const runtime = openMailboxGcmRuntime({ kernel });
            const encryptor = runtime.openEncryptor({
                associatedData,
                key,
                nonce,
                totalByteLength: plaintext.byteLength,
            });
            const encryptedFragments = fragments(
                plaintext,
                encryptionFragmentByteLength,
            );
            for (const fragment of encryptedFragments) {
                encryptor.encryptChunk(fragment);
            }
            const tag = encryptor.finish();
            const ciphertext = concatenate(encryptedFragments);
            expect(ciphertext).toEqual(expectedCiphertext);
            expect(tag).toEqual(expectedTag);
            expect(encryptor.state()).toBe('completed');

            const verifier = runtime.openVerifier({
                associatedData,
                key,
                nonce,
                totalByteLength: ciphertext.byteLength,
            });
            for (const fragment of fragments(ciphertext, 257)) {
                verifier.authenticateChunk(fragment);
            }
            verifier.finishAuthentication(tag);
            const decryptedFragments = fragments(ciphertext, 31);
            for (const fragment of decryptedFragments) {
                verifier.decryptChunk(fragment);
            }
            const authenticatedPlaintextCapability =
                verifier.finishDecryption();
            expect(concatenate(decryptedFragments)).toEqual(plaintext);
            expect(verifier.state()).toBe('completed');
            expect(() =>
                runtime.openEncryptor({
                    associatedData,
                    key,
                    nonce,
                    totalByteLength: plaintext.byteLength,
                }),
            ).toThrow(CanonicalStreamResourceError);
            authenticatedPlaintextCapability.release();
            expect(() => authenticatedPlaintextCapability.release()).toThrow(
                CanonicalStreamInternalError,
            );
        }
    });

    it('never releases plaintext before the complete ciphertext and tag authenticate', () => {
        const key = deterministicBytes(32, 3);
        const nonce = deterministicBytes(12, 7);
        const associatedData = deterministicBytes(23, 11);
        const plaintext = deterministicBytes(1025, 13);
        const runtime = openMailboxGcmRuntime({ kernel });
        const encryptor = runtime.openEncryptor({
            associatedData,
            key,
            nonce,
            totalByteLength: plaintext.byteLength,
        });
        const ciphertextBuffer = plaintext.slice().buffer;
        encryptor.encryptChunk(ciphertextBuffer);
        const ciphertext = new Uint8Array(ciphertextBuffer.slice(0));
        const tag = encryptor.finish();

        const verifier = runtime.openVerifier({
            associatedData,
            key,
            nonce,
            totalByteLength: ciphertext.byteLength,
        });
        const prematureDecryption = ciphertext.slice().buffer;
        expect(() => verifier.decryptChunk(prematureDecryption)).toThrow(
            CanonicalStreamInternalError,
        );
        expect(new Uint8Array(prematureDecryption)).toEqual(ciphertext);
        verifier.authenticateChunk(ciphertext.slice().buffer);
        const tamperedTag = tag.slice();
        tamperedTag[9] ^= 0x80;
        expect(() => verifier.finishAuthentication(tamperedTag)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(verifier.state()).toBe('failed');
        expect(() => verifier.decryptChunk(ciphertext.slice().buffer)).toThrow(
            CanonicalStreamInternalError,
        );
    });

    it('refuses truncated, overlong, and cancelled lifecycles without retaining a session', () => {
        const key = deterministicBytes(32, 19);
        const nonce = deterministicBytes(12, 23);
        const associatedData = deterministicBytes(17, 29);
        const runtime = openMailboxGcmRuntime({ kernel });
        const shortEncryptor = runtime.openEncryptor({
            associatedData,
            key,
            nonce,
            totalByteLength: 17,
        });
        shortEncryptor.encryptChunk(deterministicBytes(16, 31).buffer);
        expect(() => shortEncryptor.finish()).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(shortEncryptor.state()).toBe('failed');

        const overlongEncryptor = runtime.openEncryptor({
            associatedData,
            key,
            nonce,
            totalByteLength: 16,
        });
        const overlongChunk = deterministicBytes(17, 37).buffer;
        expect(() => overlongEncryptor.encryptChunk(overlongChunk)).toThrow(
            CanonicalStreamRefusalError,
        );
        expect(new Uint8Array(overlongChunk)).toEqual(new Uint8Array(17));
        expect(overlongEncryptor.state()).toBe('failed');

        const cancelledEncryptor = runtime.openEncryptor({
            associatedData,
            key,
            nonce,
            totalByteLength: 1,
        });
        cancelledEncryptor.cancel();
        expect(cancelledEncryptor.state()).toBe('cancelled');
        expect(() =>
            cancelledEncryptor.encryptChunk(new ArrayBuffer(1)),
        ).toThrow(CanonicalStreamInternalError);
    });
});
