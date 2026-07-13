import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';

import {
    isDocumentationOnlyCiPath,
    isToolingOnlyCiPath,
    isVersionOnlyReleaseManifestChange,
    parseNullDelimitedGitNameStatus,
    shouldRunHeavyCiLanes,
} from '#tools/ci/classify-ci-changes.mjs';

describe('CI heavy-lane change classification', () => {
    it('skips heavy lanes for documentation and tooling-only changes', () => {
        const documentationPaths = [
            'README.md',
            'packages/protocol/README.md',
            'SECURITY.md',
            'LICENSE',
            'reference-documents/paper.txt',
        ];

        expect(documentationPaths.every(isDocumentationOnlyCiPath)).toBe(true);
        expect(shouldRunHeavyCiLanes(documentationPaths)).toBe(false);
        const toolingPaths = [
            '.github/workflows/ci.yml',
            'eslint.config.js',
            'tests/node/tools/run-command.test.ts',
            'tools/ci/run-command.ts',
            'tools/lattigo-oracle/main.go',
        ];
        expect(toolingPaths.every(isToolingOnlyCiPath)).toBe(true);
        expect(shouldRunHeavyCiLanes(toolingPaths)).toBe(false);
    });

    it('runs heavy lanes for proof runtime dependencies and unknown paths', () => {
        for (const changedPath of [
            'packages/sdk/src/index.ts',
            'packages/sdk/package.json',
            'pnpm-lock.yaml',
            'crates/sealed-lattice-kernel/src/bgv/setup.rs',
            'packages/wasm/tests/node/transcript-core-kernel/core-kernel-and-fixtures.kernel.test.ts',
            'tools/process-memory-guard/src/main.rs',
            'unclassified/generated.txt',
            '../outside.md',
        ]) {
            expect(shouldRunHeavyCiLanes([changedPath])).toBe(true);
        }
    });

    it('runs heavy lanes for empty and mixed change sets', () => {
        expect(shouldRunHeavyCiLanes([])).toBe(true);
        expect(
            shouldRunHeavyCiLanes([
                'README.md',
                'packages/protocol/src/index.ts',
            ]),
        ).toBe(true);
    });

    it('skips only an exact patch or minor public-package version change', () => {
        const previousManifest = JSON.stringify({
            dependencies: { example: '1.0.0' },
            name: 'sealed-lattice',
            version: '0.7.12',
        });
        const patchManifest = JSON.stringify({
            dependencies: { example: '1.0.0' },
            name: 'sealed-lattice',
            version: '0.7.13',
        });
        const minorManifest = JSON.stringify({
            dependencies: { example: '1.0.0' },
            name: 'sealed-lattice',
            version: '0.8.0',
        });

        expect(
            isVersionOnlyReleaseManifestChange(previousManifest, patchManifest),
        ).toBe(true);
        expect(
            isVersionOnlyReleaseManifestChange(previousManifest, minorManifest),
        ).toBe(true);
        expect(shouldRunHeavyCiLanes(['packages/sdk/package.json'], true)).toBe(
            false,
        );

        for (const nextManifest of [
            JSON.stringify({
                dependencies: { example: '2.0.0' },
                name: 'sealed-lattice',
                version: '0.7.13',
            }),
            JSON.stringify({
                dependencies: { example: '1.0.0' },
                name: 'sealed-lattice',
                version: '0.7.14',
            }),
            JSON.stringify({
                dependencies: { example: '1.0.0' },
                name: 'sealed-lattice',
                version: '0.8.1',
            }),
            JSON.stringify({ name: 'sealed-lattice', version: '1.0.0' }),
            'not JSON',
        ]) {
            expect(
                isVersionOnlyReleaseManifestChange(
                    previousManifest,
                    nextManifest,
                ),
            ).toBe(false);
        }
        expect(
            shouldRunHeavyCiLanes(
                ['packages/sdk/package.json', 'README.md'],
                true,
            ),
        ).toBe(true);
    });

    it('parses null-delimited git statuses and retains both rename paths', () => {
        const entries = parseNullDelimitedGitNameStatus(
            Buffer.from(
                'M\0README.md\0R100\0packages/protocol/src/old.ts\0reference-documents/paper notes.txt\0',
            ),
        );
        expect(entries).toEqual([
            { paths: ['README.md'], status: 'M' },
            {
                paths: [
                    'packages/protocol/src/old.ts',
                    'reference-documents/paper notes.txt',
                ],
                status: 'R100',
            },
        ]);
        const changedPaths = entries.flatMap((entry) => entry.paths);
        expect(shouldRunHeavyCiLanes(changedPaths)).toBe(true);
        expect(() =>
            parseNullDelimitedGitNameStatus(Buffer.from('R100\0README.md\0')),
        ).toThrow('missing a path');
    });
});
