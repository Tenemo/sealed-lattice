import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    collectGeneratedArtifactFingerprints,
    compareGeneratedArtifactFingerprints,
} from '#tools/ci/verify-build-reproducibility';

describe('Build reproducibility verification', () => {
    it('detects changed bytes, changed lengths, missing files, and added files', async () => {
        const temporaryRoot = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-build-fingerprints-'),
        );
        const firstPath = path.join(temporaryRoot, 'first.bin');
        const secondPath = path.join(temporaryRoot, 'nested', 'second.bin');

        try {
            await mkdir(path.dirname(secondPath), { recursive: true });
            await writeFile(firstPath, Uint8Array.of(1, 2, 3));
            await writeFile(secondPath, Uint8Array.of(4, 5));
            const before = await collectGeneratedArtifactFingerprints(
                temporaryRoot,
                ['first.bin', 'nested/second.bin'],
            );

            await writeFile(firstPath, Uint8Array.of(1, 2, 4));
            await writeFile(secondPath, Uint8Array.of(4, 5, 6));
            const after = await collectGeneratedArtifactFingerprints(
                temporaryRoot,
                ['first.bin', 'nested/second.bin'],
            );

            expect(compareGeneratedArtifactFingerprints(before, after)).toEqual(
                ['first.bin', 'nested/second.bin'],
            );
            const beforeFingerprint = before.get('first.bin');
            const afterFingerprint = after.get('first.bin');
            if (
                beforeFingerprint === undefined ||
                afterFingerprint === undefined
            ) {
                throw new Error('Expected both fingerprints to be present.');
            }
            expect(
                compareGeneratedArtifactFingerprints(
                    new Map([['only-before.bin', beforeFingerprint]]),
                    new Map([['only-after.bin', afterFingerprint]]),
                ),
            ).toEqual(['only-after.bin', 'only-before.bin']);
        } finally {
            await rm(temporaryRoot, { force: true, recursive: true });
        }
    });
});
