import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    purposeSignatureBytes,
    purposeSignatureChains,
    purposeSignatureContexts,
    purposeSignatureRoot,
    signPurpose,
    verifyPurpose,
} from '#tests/purpose-signature-model.js';
import { purposeSignatureSizes } from '#tests/purpose-signature-parameters.js';
import { protocolHashPrefix } from '#tests/word-proof-reference/transcript.js';

// The native purpose-signature tests pin the same root and signature
// digests for this seed and these frames.
const seed = Buffer.alloc(64, 0x39);
const frame = (purpose: number) =>
    Buffer.from(
        Array.from({ length: purpose * 97 }, (_, index) => (index * 11) & 255),
    );
const protocolDigest = (bytes: Uint8Array) =>
    createHash('shake256', { outputLength: 64 })
        .update(protocolHashPrefix)
        .update(bytes)
        .digest('hex');
const root = purposeSignatureRoot(seed);

describe('purpose-signature model', () => {
    it('derives the chain count and signature length from the digest and base', () => {
        expect(purposeSignatureChains).toBe(131);
        expect(BigInt(purposeSignatureBytes)).toBe(
            purposeSignatureSizes.signatureBytes,
        );
        expect(BigInt(root.length)).toBe(purposeSignatureSizes.publicKeyBytes);
        expect(purposeSignatureContexts).toHaveLength(12);
    });

    it('reproduces the native known-answer root and signatures', () => {
        expect(root.toString('hex')).toBe(
            '1cb9cbd79d9d8a0333b75f285eaaccf81857802b58ac0fda955545688c05fd4585ef64d81f18f860344c622823a5904df69af3a2b44c4c264dc3751cb8e3c310',
        );
        const expected = new Map([
            [
                0,
                'c0831560df1e820c0cfa5efdecd71d9845370ef3cf345128c13a729e3d07bdee05a85d0f7f87bfca8adcff8bf50817a516d823a0ef13a09ecae08ff3ed38a237',
            ],
            [
                7,
                'bb71e80e088b4d46b8eda9c2a79a8d9a7f80b723f6b9478dd3806b0b3ab4fc37be65ecc87b7d5593ebc6fbfbd35a5903ea35f69b48de1fbbd74d0b6db1deeac2',
            ],
            [
                11,
                'af861de5533718b1a5e99c3ed3281c45c186b6ead1bea3b007fd811d80ca8cdf107621a15fd56ad6e4826c5995ebae636c016431f13a3d5761d0c65d23b5476f',
            ],
        ]);
        for (const [purpose, digest] of expected) {
            const signature = signPurpose(seed, purpose, frame(purpose));
            expect(protocolDigest(signature)).toBe(digest);
            expect(
                verifyPurpose(root, purpose, frame(purpose), signature),
            ).toBe(true);
        }
    });

    it('refuses another frame, purpose, root or edited signature', () => {
        const purpose = 7;
        const signature = signPurpose(seed, purpose, frame(purpose));
        const changedFrame = Buffer.concat([frame(purpose), Uint8Array.of(0)]);
        expect(verifyPurpose(root, purpose, changedFrame, signature)).toBe(
            false,
        );
        expect(verifyPurpose(root, 6, frame(purpose), signature)).toBe(false);
        expect(
            verifyPurpose(
                purposeSignatureRoot(Buffer.alloc(64, 0x3a)),
                purpose,
                frame(purpose),
                signature,
            ),
        ).toBe(false);
        // The version byte, the purpose byte, the first and last chain
        // values and the last authentication-path node.
        for (const index of [
            0,
            1,
            2,
            2 + 130 * 64,
            purposeSignatureBytes - 1,
        ]) {
            const edited = Buffer.from(signature);
            edited[index] ^= 1;
            expect(verifyPurpose(root, purpose, frame(purpose), edited)).toBe(
                false,
            );
        }
        expect(
            verifyPurpose(
                root,
                purpose,
                frame(purpose),
                signature.subarray(0, purposeSignatureBytes - 1),
            ),
        ).toBe(false);
        expect(() => signPurpose(seed, 12, frame(1))).toThrow(
            'signing context',
        );
    });
});
