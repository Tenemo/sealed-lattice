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
});
