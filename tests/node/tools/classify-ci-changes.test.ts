import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';

import {
    isVersionOnlyReleaseManifestChange,
    parseNullDelimitedGitNameStatus,
    resolveHeavyCiLaneSelection,
    shouldRunHeavyCiLanes,
    shouldRunRoutineCiLanes,
} from '#tools/ci/classify-ci-changes.mjs';

describe('CI heavy-lane change classification', () => {
    it('requires active registry entries and emits one exact matrix row per entry', () => {
        expect(
            resolveHeavyCiLaneSelection(['crates/kernel.rs'], false, []),
        ).toEqual({
            heavyTestMatrix: { include: [] },
            runHeavyLanes: false,
        });

        const activeTestFilters = [
            'heavy_rust_kernel_expensive_relation',
            'heavy_rust_kernel_second_relation',
        ];
        expect(
            resolveHeavyCiLaneSelection(
                ['crates/kernel.rs'],
                false,
                activeTestFilters,
            ),
        ).toEqual({
            heavyTestMatrix: {
                include: activeTestFilters.map((testFilter) => ({
                    testFilter,
                })),
            },
            runHeavyLanes: true,
        });
        expect(
            resolveHeavyCiLaneSelection(['README.md'], false, activeTestFilters)
                .runHeavyLanes,
        ).toBe(false);
    });

    it('skips documentation and non-lane tooling while failing closed for lane definitions, runtime, and unknown changes', () => {
        for (const changedPaths of [
            ['README.md', 'SECURITY.md', 'reference-documents/paper.txt'],
            [
                'packages/wasm/tests/node/foundation-ceremony-runtime.kernel.test.ts',
                'tests/node/tools/run-command.test.ts',
                'tools/internal/generate-fixture.ts',
            ],
        ]) {
            expect(shouldRunHeavyCiLanes(changedPaths)).toBe(false);
        }

        for (const changedPath of [
            'packages/sdk/src/index.ts',
            'pnpm-lock.yaml',
            'crates/sealed-lattice-kernel/src/tally_preparation/replicated_key_ceremony.rs',
            '.github/workflows/ci.yml',
            'tools/ci/run-rust-kernel-heavy-tests.ts',
            'tools/ci/new-heavy-lane-runner.ts',
            'unclassified/generated.txt',
        ]) {
            expect(shouldRunHeavyCiLanes([changedPath])).toBe(true);
        }
        expect(shouldRunHeavyCiLanes([])).toBe(true);
        expect(
            shouldRunHeavyCiLanes([
                'README.md',
                'packages/protocol/src/index.ts',
            ]),
        ).toBe(true);
        expect(
            shouldRunRoutineCiLanes([
                'README.md',
                'reference-documents/paper.txt',
            ]),
        ).toBe(false);
        expect(shouldRunRoutineCiLanes(['tools/ci/run-command.ts'])).toBe(true);
    });

    it('skips only an exact patch or minor public-package version change', () => {
        const previousManifest = JSON.stringify({
            dependencies: { example: '1.0.0' },
            name: 'sealed-lattice',
            version: '0.7.12',
        });
        for (const version of ['0.7.13', '0.8.0']) {
            const nextManifest = JSON.stringify({
                dependencies: { example: '1.0.0' },
                name: 'sealed-lattice',
                version,
            });
            expect(
                isVersionOnlyReleaseManifestChange(
                    previousManifest,
                    nextManifest,
                ),
            ).toBe(true);
        }
        expect(shouldRunHeavyCiLanes(['packages/sdk/package.json'], true)).toBe(
            false,
        );
        expect(
            shouldRunRoutineCiLanes(['packages/sdk/package.json'], true),
        ).toBe(false);

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
