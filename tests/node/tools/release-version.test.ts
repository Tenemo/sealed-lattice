import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    incrementPrototypeVersion,
    prepareReleaseVersion,
} from '#tools/ci/release-version';

describe('release version preparation', () => {
    it('increments stable prototype patch and minor versions', () => {
        expect(incrementPrototypeVersion('0.0.19', 'patch')).toBe('0.0.20');
        expect(incrementPrototypeVersion('0.9.73', 'minor')).toBe('0.10.0');
    });

    it('rejects prerelease, malformed, leading-zero, and post-1.0 versions', () => {
        for (const version of [
            '0.1.0-beta.1',
            '0.01.0',
            '0.1',
            '1.0.0',
            '2.4.6',
        ]) {
            expect(() => incrementPrototypeVersion(version, 'patch')).toThrow();
        }
    });

    it('updates only the public manifest version', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-release-version-'),
        );
        const manifestPath = path.join(temporaryDirectoryPath, 'package.json');
        const manifest = {
            name: 'sealed-lattice',
            version: '0.4.9',
            private: false,
            exports: { '.': './dist/index.js' },
        };

        try {
            await writeFile(
                manifestPath,
                `${JSON.stringify(manifest, null, 4)}\n`,
                'utf8',
            );
            const result = await prepareReleaseVersion({
                increment: 'minor',
                manifestPath,
            });

            expect(result).toEqual({
                previousVersion: '0.4.9',
                tag: 'v0.5.0',
                version: '0.5.0',
            });
            expect(JSON.parse(await readFile(manifestPath, 'utf8'))).toEqual({
                ...manifest,
                version: '0.5.0',
            });
        } finally {
            await rm(temporaryDirectoryPath, { recursive: true, force: true });
        }
    });

    it('rejects unrelated and malformed manifests without rewriting them', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-release-invalid-'),
        );
        const manifestPath = path.join(temporaryDirectoryPath, 'package.json');

        try {
            await writeFile(
                manifestPath,
                '{"name":"other-package","version":"0.1.0"}\n',
                'utf8',
            );
            await expect(
                prepareReleaseVersion({ increment: 'patch', manifestPath }),
            ).rejects.toThrow('must identify sealed-lattice');
            expect(await readFile(manifestPath, 'utf8')).toBe(
                '{"name":"other-package","version":"0.1.0"}\n',
            );

            await writeFile(manifestPath, '{not-json}\n', 'utf8');
            await expect(
                prepareReleaseVersion({ increment: 'patch', manifestPath }),
            ).rejects.toThrow();
            expect(await readFile(manifestPath, 'utf8')).toBe('{not-json}\n');
        } finally {
            await rm(temporaryDirectoryPath, { recursive: true, force: true });
        }
    });
});
