import { describe, expect, it } from 'vitest';

import {
    decodeCandidateManifest,
    decodeCandidatePage,
    decodeCandidateReceipt,
    encodeCandidateManifest,
    encodeCandidatePage,
    encodeCandidateReceipt,
    isCandidateFileName,
    isCandidateKey,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';

describe('bounded candidate transport framing', () => {
    it('matches an independently encoded correlated manifest, including an empty file', () => {
        const manifest = encodeCandidateManifest({
            files: [
                { name: 'proof.bin', length: 1, chunks: ['ab'.repeat(16)] },
                { name: 'empty.bin', length: 0, chunks: [] },
            ],
        });
        const fixed = Buffer.alloc(6);
        fixed.write('RCM1');
        fixed.writeUInt16LE(2, 4);
        const file = (name: string, length: bigint, chunk?: string) => {
            const bytes = Buffer.alloc(2 + name.length + 8);
            bytes.writeUInt16LE(name.length);
            bytes.write(name, 2, 'ascii');
            bytes.writeBigUInt64LE(length, 2 + name.length);
            return Buffer.concat([bytes, Buffer.from(chunk ?? '', 'hex')]);
        };
        expect(Buffer.from(manifest)).toEqual(
            Buffer.concat([
                fixed,
                file('empty.bin', 0n),
                file('proof.bin', 1n, 'ab'.repeat(16)),
            ]),
        );
        expect(
            decodeCandidateManifest(manifest).files.map((entry) => entry.name),
        ).toEqual(['empty.bin', 'proof.bin']);
        for (let length = 0; length < manifest.length; length++)
            expect(() =>
                decodeCandidateManifest(manifest.subarray(0, length)),
            ).toThrow();
        expect(() =>
            decodeCandidateManifest(
                Buffer.concat([manifest, Buffer.from([0])]),
            ),
        ).toThrow();
    });

    it('enforces the stream, file count, name and manifest limits at their boundaries', () => {
        const maximum = 0xffff_fffb;
        const files = Array.from({ length: 256 }, (_, index) => ({
            name: 'part-' + String(index).padStart(3, '0'),
            length: 0,
            chunks: [],
        }));
        expect(
            decodeCandidateManifest(encodeCandidateManifest({ files })).files,
        ).toHaveLength(256);
        expect(() =>
            encodeCandidateManifest({
                files: [...files, { name: 'extra', length: 0, chunks: [] }],
            }),
        ).toThrow();
        expect(isCandidateFileName('a'.repeat(160))).toBe(true);
        expect(isCandidateFileName('a'.repeat(161))).toBe(false);
        expect(isCandidateKey('a'.repeat(256))).toBe(true);
        expect(isCandidateKey('a'.repeat(257))).toBe(false);
        for (const invalid of [
            '',
            '..',
            '../body',
            'body/../proof',
            'body\\proof',
            '/body',
            'body//proof',
            'body%2fproof',
        ])
            expect(isCandidateKey(invalid)).toBe(false);
        const wide = {
            name: 'body.bin',
            length: maximum,
            chunks: Array.from({ length: 4096 }, () => '12'.repeat(16)),
        };
        expect(
            decodeCandidateManifest(encodeCandidateManifest({ files: [wide] }))
                .files[0].length,
        ).toBe(maximum);
        expect(() =>
            encodeCandidateManifest({
                files: [{ ...wide, length: maximum + 1 }],
            }),
        ).toThrow();
        const changedLength = encodeCandidateManifest({ files: [wide] });
        new DataView(changedLength.buffer).setBigUint64(
            8 + wide.name.length,
            BigInt(maximum) + 1n,
            true,
        );
        expect(() => decodeCandidateManifest(changedLength)).toThrow();

        // The descriptor bytes are 6 + 16*21 + 10; 65514 references then
        // fill the manifest exactly, without materializing their payloads.
        const full = Array.from({ length: 16 }, (_, index) => ({
            name:
                (index === 0 ? 'a'.repeat(10) : '') +
                'body-' +
                String(index).padStart(2, '0') +
                '.bin',
            length: index === 15 ? 4074 * 1_048_576 : maximum,
            chunks: Array.from({ length: index === 15 ? 4074 : 4096 }, () =>
                '34'.repeat(16),
            ),
        }));
        const encoded = encodeCandidateManifest({ files: full });
        expect(encoded.length).toBe(1_048_576);
        expect(decodeCandidateManifest(encoded).files).toHaveLength(16);
        expect(() =>
            encodeCandidateManifest({
                files: full.map((entry, index) =>
                    index === 0 ? { ...entry, name: 'a' + entry.name } : entry,
                ),
            }),
        ).toThrow();
        expect(() =>
            decodeCandidateManifest(Buffer.concat([encoded, Buffer.from([0])])),
        ).toThrow();
    });

    it('refuses duplicate names, inconsistent chunk counts and noncanonical locators', () => {
        const file = { name: 'body.bin', length: 1, chunks: ['ab'.repeat(16)] };
        for (const files of [
            [],
            [file, file],
            [{ ...file, chunks: [] }],
            [{ ...file, chunks: ['AB'.repeat(16)] }],
            [{ ...file, length: 0 }],
        ])
            expect(() => encodeCandidateManifest({ files })).toThrow();
        const encoded = encodeCandidateManifest({ files: [file] });
        for (const offset of [0, 4, 6, 8]) {
            const changed = encoded.slice();
            changed[offset] ^= 255;
            expect(() => decodeCandidateManifest(changed)).toThrow();
        }
    });

    it('keeps receipt and page integers exact and caps every page before allocation', () => {
        const id = 'de'.repeat(16);
        const maximum = Number.MAX_SAFE_INTEGER;
        expect(
            decodeCandidateReceipt(
                encodeCandidateReceipt({ id, index: maximum }),
            ),
        ).toEqual({ id, index: maximum });
        expect(() =>
            encodeCandidateReceipt({ id, index: maximum + 1 }),
        ).toThrow();
        const receipt = encodeCandidateReceipt({ id, index: 0 });
        new DataView(receipt.buffer).setBigUint64(
            16,
            BigInt(maximum) + 1n,
            true,
        );
        expect(() => decodeCandidateReceipt(receipt)).toThrow();
        const page = {
            total: maximum,
            ids: Array.from({ length: 64 }, () => id),
        };
        expect(decodeCandidatePage(encodeCandidatePage(page))).toEqual(page);
        expect(() =>
            encodeCandidatePage({ total: maximum, ids: [...page.ids, id] }),
        ).toThrow();
        const encoded = encodeCandidatePage(page);
        encoded[8] = 65;
        expect(() => decodeCandidatePage(encoded)).toThrow();
        expect(() =>
            decodeCandidatePage(new Uint8Array(12 + 65 * 16)),
        ).toThrow();
    });
});
