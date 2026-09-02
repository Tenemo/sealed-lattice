import { describe, expect, it } from 'vitest';

import {
    actionSignatureByteLength,
    actionSignatureKeyGenerationRandomnessByteLength,
    actionSignatureSecretKeyByteLength,
    actionSignatureSigningRandomnessByteLength,
    actionSignatureVerificationKeyByteLength,
    createActionSignatureRuntimeLoader,
} from '../../src/action-signature-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const deterministicBytes = (length: number, seed: number): Uint8Array =>
    Uint8Array.from(
        { length },
        (_unused, index) => (seed + index * 37 + (index >> 2)) & 0xff,
    );

describe('action signature scalar WASM runtime', () => {
    it('emits exact deterministic ML-DSA-65 bytes and refuses mutations', async () => {
        const runtime = await createActionSignatureRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();
        const keyRandomness = deterministicBytes(
            actionSignatureKeyGenerationRandomnessByteLength,
            0x23,
        );
        const keyPair = runtime.generateKeyPair(keyRandomness);
        expect(keyPair.secretKey).toHaveLength(
            actionSignatureSecretKeyByteLength,
        );
        expect(keyPair.verificationKey).toHaveLength(
            actionSignatureVerificationKeyByteLength,
        );
        expect(runtime.generateKeyPair(keyRandomness)).toEqual(keyPair);

        const bodyIdentity = deterministicBytes(64, 0x41);
        const signingRandomness = deterministicBytes(
            actionSignatureSigningRandomnessByteLength,
            0x91,
        );
        const signature = runtime.signBodyIdentity(
            keyPair.secretKey,
            3,
            'source',
            bodyIdentity,
            signingRandomness,
        );
        expect(signature).toHaveLength(actionSignatureByteLength);
        expect(
            runtime.signBodyIdentity(
                keyPair.secretKey,
                3,
                'source',
                bodyIdentity,
                signingRandomness,
            ),
        ).toEqual(signature);
        expect(
            runtime.verifySignature(
                keyPair.verificationKey,
                3,
                'source',
                bodyIdentity,
                signature,
            ),
        ).toBe(true);

        const mutatedSignature = Uint8Array.from(signature);
        mutatedSignature[1_709] ^= 1;
        expect(
            runtime.verifySignature(
                keyPair.verificationKey,
                3,
                'source',
                bodyIdentity,
                mutatedSignature,
            ),
        ).toBe(false);
        const wrongIdentity = Uint8Array.from(bodyIdentity);
        wrongIdentity[0] ^= 1;
        expect(
            runtime.verifySignature(
                keyPair.verificationKey,
                3,
                'source',
                wrongIdentity,
                signature,
            ),
        ).toBe(false);
    });

    it('rejects wrong-width keys, randomness, and identities before crossing WASM', async () => {
        const runtime = await createActionSignatureRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();
        expect(() => runtime.generateKeyPair(new Uint8Array(31))).toThrow(
            /32-byte/u,
        );
        expect(() =>
            runtime.signBodyIdentity(
                new Uint8Array(actionSignatureSecretKeyByteLength),
                0,
                'preparation',
                new Uint8Array(63),
                new Uint8Array(actionSignatureSigningRandomnessByteLength),
            ),
        ).toThrow(/64-byte/u);
        expect(() =>
            runtime.signBodyIdentity(
                new Uint8Array(actionSignatureSecretKeyByteLength),
                0,
                'preparation',
                new Uint8Array(64),
                new Uint8Array(31),
            ),
        ).toThrow(/32-byte/u);
    });
});
