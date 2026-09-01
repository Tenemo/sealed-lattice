import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    actionSignatureKeyByteLength,
    createActionSignatureRuntimeLoader,
} from '../../src/action-signature-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const chainValueByteLength = 48;
const messageChainCount = 128;
const chainCount = 131;

const shakeChain = (input: Uint8Array, stepCount: number): Uint8Array => {
    let value = Uint8Array.from(input);
    for (let step = 0; step < stepCount; step += 1) {
        value = Uint8Array.from(
            createHash('shake256', { outputLength: chainValueByteLength })
                .update(value)
                .digest(),
        );
    }
    return value;
};

const messageDigits = (message: Uint8Array): Uint8Array => {
    const digits = new Uint8Array(chainCount);
    for (const [byteIndex, byte] of message.entries()) {
        digits[2 * byteIndex] = byte >> 4;
        digits[2 * byteIndex + 1] = byte & 0x0f;
    }
    let checksum = 0;
    for (const digit of digits.subarray(0, messageChainCount)) {
        checksum += 15 - digit;
    }
    digits[messageChainCount] = (checksum >> 8) & 0x0f;
    digits[messageChainCount + 1] = (checksum >> 4) & 0x0f;
    digits[messageChainCount + 2] = checksum & 0x0f;
    return digits;
};

const referenceTransform = (
    input: Uint8Array,
    steps: (chainIndex: number) => number,
): Uint8Array => {
    const output = new Uint8Array(actionSignatureKeyByteLength);
    for (let chainIndex = 0; chainIndex < chainCount; chainIndex += 1) {
        const start = chainIndex * chainValueByteLength;
        output.set(
            shakeChain(
                input.subarray(start, start + chainValueByteLength),
                steps(chainIndex),
            ),
            start,
        );
    }
    return output;
};

describe('action signature scalar WASM runtime', () => {
    it('matches an independent Node SHAKE implementation and refuses mutations', async () => {
        const runtime = await createActionSignatureRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();
        const secretKey = Uint8Array.from(
            { length: actionSignatureKeyByteLength },
            (_unused, index) => (index * 29 + 17) % 251,
        );
        const bodyIdentity = Uint8Array.from(
            { length: 64 },
            (_unused, index) => (index * 37 + 11) & 0xff,
        );
        const digits = messageDigits(bodyIdentity);
        const expectedVerificationKey = referenceTransform(secretKey, () => 15);
        const expectedSignature = referenceTransform(
            secretKey,
            (chainIndex) => digits[chainIndex] ?? 0,
        );

        const verificationKey = runtime.deriveVerificationKey(secretKey);
        const signature = runtime.signBodyIdentity(secretKey, bodyIdentity);
        expect(verificationKey).toEqual(expectedVerificationKey);
        expect(signature).toEqual(expectedSignature);
        expect(
            runtime.verifySignature(verificationKey, bodyIdentity, signature),
        ).toBe(true);

        const mutatedSignature = Uint8Array.from(signature);
        mutatedSignature[137] ^= 1;
        expect(
            runtime.verifySignature(
                verificationKey,
                bodyIdentity,
                mutatedSignature,
            ),
        ).toBe(false);
        const wrongIdentity = Uint8Array.from(bodyIdentity);
        wrongIdentity[0] ^= 1;
        expect(
            runtime.verifySignature(verificationKey, wrongIdentity, signature),
        ).toBe(false);
    });

    it('rejects wrong-width keys and identities before crossing WASM', async () => {
        const runtime = await createActionSignatureRuntimeLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })();
        expect(() => runtime.deriveVerificationKey(new Uint8Array(1))).toThrow(
            /6288-byte/u,
        );
        expect(() =>
            runtime.signBodyIdentity(
                new Uint8Array(actionSignatureKeyByteLength),
                new Uint8Array(63),
            ),
        ).toThrow(/64-byte/u);
    });
});
