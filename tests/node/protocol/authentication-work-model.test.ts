import { describe, expect, it } from 'vitest';

import {
    compileCompleteAuthenticationFrameWork,
    compileCompleteCredentialIntentBounds,
    compilePurposeSignatureWork,
    completeAuthenticationPurposes,
    purposeSignatureFrame,
} from '#tests/authentication-work-model.js';
import {
    spongePermutations,
    shake256RateBytes,
} from '#tests/node/protocol/reference/sponge-permutations.js';
import {
    readRustSource,
    rustFunctionBody,
    rustIntegerConstant,
} from '#tests/node/rust-source.js';

describe('purpose signature work and framing', () => {
    it('binds complete roots, purpose indices, lengths and varied messages', () => {
        for (const purpose of [0, 1, 11])
            for (const length of [0, 1, 214, 2048]) {
                const root = Buffer.from(
                    Array.from({ length: 64 }, (_, index) => index),
                );
                const message = Buffer.from(
                    Array.from({ length }, (_, index) => (index * 13) & 255),
                );
                const prefix = Buffer.alloc(64);
                prefix.write('sealed-lattice/fixed-hash');
                const size = Buffer.alloc(8);
                size.writeBigUInt64LE(BigInt(length));
                const expected = Buffer.concat([
                    prefix,
                    Buffer.from('purpose-wots/message/v1'),
                    root,
                    Uint8Array.of(purpose),
                    size,
                    message,
                ]);
                expect(purposeSignatureFrame(root, purpose, message)).toEqual(
                    expected,
                );
                const changed = Buffer.from(root);
                changed[63] ^= 1;
                expect(
                    purposeSignatureFrame(changed, purpose, message),
                ).not.toEqual(expected);
            }
        for (const purpose of [-1, 12, 1.5])
            expect(() =>
                purposeSignatureFrame(
                    new Uint8Array(64),
                    purpose,
                    new Uint8Array(),
                ),
            ).toThrow();
        expect(() =>
            purposeSignatureFrame(new Uint8Array(63), 0, new Uint8Array()),
        ).toThrow();
    });
    it('derives the credential predecessor from native key generation', async () => {
        const [signature, digest] = await Promise.all([
            readRustSource(
                'crates/protocol-research/purpose-signature/src/lib.rs',
            ),
            readRustSource(
                'crates/protocol-research/parallel-work/src/protocol-hash.rs',
            ),
        ]);
        // Each signing context is one active purpose, and the declared array
        // length must agree with its distinct entries.
        const contexts =
            /\bconst\s+SIGNING_CONTEXTS\s*:\s*\[&\[u8\];\s*(\d+)\]\s*=\s*\[([^\]]*)\]/u.exec(
                signature,
            );
        expect(contexts).not.toBeNull();
        const contextNames = [...contexts![2].matchAll(/b"([^"]*)"/gu)].map(
            (match) => match[1],
        );
        expect(BigInt(contextNames.length)).toBe(BigInt(contexts![1]));
        expect(new Set(contextNames).size).toBe(contextNames.length);
        // Key generation walks every chain of every active purpose once.
        const walks = [
            ...rustFunctionBody(signature, 'new').matchAll(
                /for\s+_\s+in\s+0\.\.(\d+)\s*\{\s*\*value\s*=\s*step\(&value\);\s*\}/gu,
            ),
        ];
        expect(walks).toHaveLength(1);
        // One chain step hashes its domain and one digest after the prefix.
        const domain = /^\{\s*hash\(b"([^"]*)",\s*&\[value\]\)\s*\}$/u.exec(
            rustFunctionBody(signature, 'step'),
        );
        expect(domain).not.toBeNull();
        expect(signature).toMatch(/\btype\s+Digest\s*=\s*\[u8;\s*64\];/u);
        const chainInputBytes =
            rustIntegerConstant(digest, 'PREFIX_BYTES') +
            BigInt(Buffer.byteLength(domain![1])) +
            64n;
        expect(chainInputBytes).toBe(149n);
        const chainPermutations = spongePermutations(
            chainInputBytes,
            64n,
            rustIntegerConstant(digest, 'RATE'),
        );
        // The cost convention charges each Keccak-f[1600] permutation 38400
        // gates.
        expect(compilePurposeSignatureWork().credentialPredecessorGates).toBe(
            BigInt(contextNames.length) *
                rustIntegerConstant(signature, 'CHAINS') *
                BigInt(walks[0][1]) *
                chainPermutations *
                38400n,
        );
    });
    it('uses the independent sponge counter and complete key-tree predecessor', () => {
        expect(completeAuthenticationPurposes).toHaveLength(12);
        for (const row of compileCompleteAuthenticationFrameWork()) {
            const frame = purposeSignatureFrame(
                new Uint8Array(64),
                completeAuthenticationPurposes.indexOf(row.purpose),
                new Uint8Array(Number(row.messageBytes)),
            );
            expect(row.representativeInputBytes).toBe(BigInt(frame.length));
            expect(row.representativePermutations).toBe(
                spongePermutations(
                    BigInt(frame.length),
                    64n,
                    shake256RateBytes,
                ),
            );
        }
        const work = compilePurposeSignatureWork();
        expect(work.keyHashCalls).toBe(12n * 131n * 16n + 12n + 4n + 15n);
        expect(work.credentialPredecessorGates).toBe(
            12n * 131n * 15n * 2n * 38400n,
        );
        expect(work.maximumKnownBankCallsPerCredential).toBeLessThan(1n << 16n);
        // The organizer's own poll, roster and selection purposes and its
        // close intent and proposal, the target vote and the release share
        // each add one purpose; the optional ballot adds the last.
        const rows = compileCompleteCredentialIntentBounds(20);
        expect(
            rows.map((row) => [
                row.branch,
                row.role,
                row.firstEvaluatedIntentBound,
            ]),
        ).toEqual([
            ['Encrypted result with own target vote', 'organizer', 12n],
            ['Encrypted result with own target vote', 'other participant', 7n],
            ['No result', 'organizer', 11n],
            ['No result', 'other participant', 6n],
            ['Encrypted release without own target vote', 'organizer', 11n],
            [
                'Encrypted release without own target vote',
                'other participant',
                6n,
            ],
        ]);
        for (const row of rows) {
            expect(new Set(row.fixedPurposes).size).toBe(
                row.fixedPurposes.length,
            );
            expect(row.fixedPurposes).not.toContain('ballot-envelope');
            expect(row.firstEvaluatedIntentBound).toBeLessThanOrEqual(
                BigInt(completeAuthenticationPurposes.length),
            );
        }
    });
});
