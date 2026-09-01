import { describe, expect, it } from 'vitest';

import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
import {
    createPairEncryptionRuntimeLoader,
    pairCiphertextByteLength,
    pairDecryptionKeyByteLength,
    pairEncryptionKeyByteLength,
    pairEncryptionKeyGenerationRandomnessByteLength,
    pairEncryptionRandomnessByteLength,
    pairMessageByteLength,
} from '../../src/pair-encryption-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const pseudorandomBytes = (length: number, seed: bigint): Uint8Array => {
    let state = seed;
    const mask = (1n << 64n) - 1n;
    return Uint8Array.from({ length }, () => {
        state ^= (state << 13n) & mask;
        state ^= state >> 7n;
        state ^= (state << 17n) & mask;
        state &= mask;
        return Number(state & 0xffn);
    });
};

describe('pair encryption scalar WASM runtime', () => {
    it('generates the explicit-matrix key, encrypts, and decrypts deterministically', async () => {
        const runtime = await createPairEncryptionRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();
        const keyRandomness = pseudorandomBytes(
            pairEncryptionKeyGenerationRandomnessByteLength,
            0x5a17n,
        );
        const encryptionRandomness = pseudorandomBytes(
            pairEncryptionRandomnessByteLength,
            0x9123n,
        );
        const message = Uint8Array.from(
            { length: pairMessageByteLength },
            (_unused, index) => index,
        );

        const keyPair = runtime.generateKeyPair(keyRandomness);
        expect(keyPair.encryptionKey).toHaveLength(pairEncryptionKeyByteLength);
        expect(keyPair.decryptionKey).toHaveLength(pairDecryptionKeyByteLength);
        const ciphertext = runtime.encrypt(
            keyPair.encryptionKey,
            message,
            encryptionRandomness,
        );
        expect(ciphertext).toHaveLength(pairCiphertextByteLength);
        expect(runtime.decrypt(keyPair.decryptionKey, ciphertext)).toEqual(
            message,
        );
        expect(
            runtime.encrypt(
                keyPair.encryptionKey,
                message,
                encryptionRandomness,
            ),
        ).toEqual(ciphertext);

        const malformedEncryptionKey = Uint8Array.from(keyPair.encryptionKey);
        malformedEncryptionKey.subarray(0, 3).fill(0xff);
        expect(() =>
            runtime.encrypt(
                malformedEncryptionKey,
                message,
                encryptionRandomness,
            ),
        ).toThrowError(ConstructionKernelCommandError);
    });

    it('rejects every wrong-width input before crossing WASM', async () => {
        const runtime = await createPairEncryptionRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();
        expect(() => runtime.generateKeyPair(new Uint8Array(1))).toThrow(
            /6912-byte/u,
        );
        expect(() =>
            runtime.encrypt(
                new Uint8Array(pairEncryptionKeyByteLength),
                new Uint8Array(pairMessageByteLength - 1),
                new Uint8Array(pairEncryptionRandomnessByteLength),
            ),
        ).toThrow(/32-byte/u);
        expect(() =>
            runtime.decrypt(
                new Uint8Array(pairDecryptionKeyByteLength),
                new Uint8Array(pairCiphertextByteLength - 1),
            ),
        ).toThrow(/1088-byte/u);
    });
});
