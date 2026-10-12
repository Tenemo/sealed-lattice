import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { importClosure } from '#tools/ci/import-closure';

const withRepository = async <Result>(
    files: Readonly<Record<string, string>>,
    action: (root: string) => Promise<Result>,
): Promise<Result> => {
    const root = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-import-closure-'),
    );
    try {
        await writeFile(
            path.join(root, 'package.json'),
            JSON.stringify({ imports: { '#tools/*': './tools/*' } }),
        );
        for (const [file, contents] of Object.entries(files)) {
            await mkdir(path.dirname(path.join(root, file)), {
                recursive: true,
            });
            await writeFile(path.join(root, file), contents);
        }
        return await action(root);
    } finally {
        await rm(root, { force: true, recursive: true });
    }
};

describe('import closure', () => {
    it('follows relative, subpath, re-exported and dynamic imports through cycles', () =>
        withRepository(
            {
                'tools/entry.ts': [
                    "import { readFile } from 'node:fs/promises';",
                    "import { build } from 'tsdown';",
                    "import { first } from './first.js';",
                    "import type { Second } from '#tools/second.js';",
                    "import data from './data.json' with { type: 'json' };",
                    "export * from './worker.mjs';",
                    "// import { ignored } from './commented.js';",
                    'const text = "import(\'./quoted.js\')";',
                    "export const load = () => import('./dynamic.ts');",
                ].join('\n'),
                'tools/first.ts':
                    "import { load } from './entry.js';\nexport const first = load;\n",
                'tools/second.ts': 'export type Second = string;\n',
                'tools/data.json': '{}\n',
                'tools/worker.mjs': "import { first } from './first.js';\n",
                'tools/dynamic.ts': "import '#tools/nested/leaf';\n",
                'tools/nested/leaf.ts': 'export {};\n',
                'tools/unimported.ts': 'export {};\n',
            },
            async (root) => {
                expect(await importClosure(['tools/entry.ts'], root)).toEqual([
                    'tools/data.json',
                    'tools/dynamic.ts',
                    'tools/entry.ts',
                    'tools/first.ts',
                    'tools/nested/leaf.ts',
                    'tools/second.ts',
                    'tools/worker.mjs',
                ]);
            },
        ));

    it('refuses an import that names no repository file', () =>
        withRepository(
            { 'tools/entry.ts': "import { gone } from './gone.js';\n" },
            async (root) => {
                await expect(
                    importClosure(['tools/entry.ts'], root),
                ).rejects.toThrow(
                    `${path.join('tools', 'entry.ts')} imports ./gone.js, which names no repository file.`,
                );
            },
        ));

    it('refuses an undeclared subpath and a missing entry', () =>
        withRepository(
            { 'tools/entry.ts': "import { other } from '#other/file.js';\n" },
            async (root) => {
                await expect(
                    importClosure(['tools/entry.ts'], root),
                ).rejects.toThrow(
                    'An import names an undeclared subpath: #other/file.js',
                );
                await expect(
                    importClosure(['tools/absent.ts'], root),
                ).rejects.toThrow(
                    `An entry names no repository file: ${path.join('tools', 'absent.ts')}`,
                );
            },
        ));

    it('covers every module of the participant browser runner', async () => {
        const closure = await importClosure([
            'tools/ci/run-participant-browser.ts',
        ]);
        for (const file of [
            'tools/ci/run-participant-browser.ts',
            'tools/ci/participant-browser-cohort.ts',
            'tools/ci/participant-browser-relay.ts',
            'tools/ci/participant-browser-public-records.ts',
            'tools/ci/participant-browser-roster-completion.ts',
            'tools/ci/participant-browser-single-roster.ts',
            'tools/ci/participant-browser-two-rosters.ts',
            'tools/ci/participant-browser-fault-schedule.ts',
            'tools/ci/participant-browser-options.ts',
            'tools/ci/participant-workflow-measurements.ts',
            'tools/ci/participant-padding-halt.ts',
            'tools/ci/participant-padding-corruption.ts',
            'tools/ci/participant-preparation-storage.ts',
            'tools/ci/participant-relay-record.ts',
            'tools/ci/participant-offer-announcements.ts',
            'tools/ci/participant-runtime-chrome.ts',
            'tests/setup-selection-model.ts',
            'tests/threshold-completion-model.ts',
        ])
            expect(closure).toContain(file);
    });
});
