import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
    parseSourceManifestRows,
    verifySourceManifest,
} from '#tools/ci/verify-source-manifest.js';

const pinnedBytes = Buffer.from('pinned primary source text\n', 'utf8');
const pinnedDigest = createHash('sha512').update(pinnedBytes).digest('hex');
const otherDigest = createHash('sha512').update('other').digest('hex');

const manifestFor = (rows: readonly string[]): string =>
    [
        '# Manifest',
        '',
        '| Identifier | Local bytes | Bytes | SHA-512 | Pinned claim |',
        '| --- | --- | --- | --- | --- |',
        ...rows,
        '',
    ].join('\n');

const row = (
    identifier: string,
    relativePath: string,
    byteLength: string,
    digest: string,
): string =>
    `| \`${identifier}\` | \`${relativePath}\` | ${byteLength} | \`${digest}\` | A pinned claim. |`;

describe('source manifest verifier', () => {
    let rootDirectory = '';

    beforeAll(async () => {
        rootDirectory = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-source-manifest-'),
        );
        await writeFile(path.join(rootDirectory, 'pinned.txt'), pinnedBytes);
    });

    afterAll(async () => {
        await rm(rootDirectory, { force: true, recursive: true });
    });

    it('parses source rows and skips header rows', () => {
        const rows = parseSourceManifestRows(
            manifestFor([
                row('A1', 'pinned.txt', '27', pinnedDigest),
                row('B2', 'dir/other.pdf', '1,234', otherDigest),
            ]),
        );
        expect(rows).toEqual([
            {
                identifier: 'A1',
                relativePath: 'pinned.txt',
                byteLength: 27,
                sha512Hex: pinnedDigest,
                lineNumber: 5,
            },
            {
                identifier: 'B2',
                relativePath: 'dir/other.pdf',
                byteLength: 1234,
                sha512Hex: otherDigest,
                lineNumber: 6,
            },
        ]);
    });

    it('rejects malformed rows and duplicate identifiers', () => {
        expect(() =>
            parseSourceManifestRows(
                manifestFor([row('A1', 'pinned.txt', 'x', pinnedDigest)]),
            ),
        ).toThrow(/byte length/u);
        expect(() =>
            parseSourceManifestRows(
                manifestFor([row('A1', 'pinned.txt', '27', 'abc')]),
            ),
        ).toThrow(/SHA-512/u);
        expect(() =>
            parseSourceManifestRows(
                manifestFor([
                    row('A1', 'pinned.txt', '27', pinnedDigest),
                    row('A1', 'pinned.txt', '27', pinnedDigest),
                ]),
            ),
        ).toThrow(/duplicate identifier/u);
        expect(() =>
            parseSourceManifestRows('| `A1` | `pinned.txt` | 27 |\n'),
        ).toThrow(/five cells/u);
    });

    it('verifies bytes and digests against the pinned files', async () => {
        const result = await verifySourceManifest(
            manifestFor([
                row('OK', 'pinned.txt', '27', pinnedDigest),
                row('SIZE', 'pinned.txt', '28', pinnedDigest),
                row('HASH', 'pinned.txt', '27', otherDigest),
                row('MISSING', 'absent.txt', '27', pinnedDigest),
            ]),
            rootDirectory,
        );
        expect(result.verifiedCount).toBe(1);
        expect(result.failures.map((failure) => failure.identifier)).toEqual([
            'SIZE',
            'HASH',
            'MISSING',
        ]);
        expect(result.failures[0]?.reason).toMatch(/28/u);
        expect(result.failures[1]?.reason).toMatch(/digest/u);
        expect(result.failures[2]?.reason).toMatch(/missing/u);
    });
});
