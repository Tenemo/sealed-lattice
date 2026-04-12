import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
    collectOutputFiles,
    resolveRuntimeSpecifier,
    rewriteFile,
} from '../../../tools/build/rewrite-dist-relative-imports';

const tempDirectories: string[] = [];

const createTempDirectory = async (): Promise<string> => {
    const directory = await mkdtemp(
        path.join(tmpdir(), 'sealed-lattice-rewrite-dist-'),
    );
    tempDirectories.push(directory);
    return directory;
};

describe('rewrite dist relative imports', () => {
    afterEach(async () => {
        await Promise.all(
            tempDirectories
                .splice(0)
                .map((directory) =>
                    rm(directory, { recursive: true, force: true }),
                ),
        );
    });

    it('collects emitted JavaScript and declaration files in sorted order', async () => {
        const root = await createTempDirectory();
        await mkdir(path.join(root, 'nested'), { recursive: true });
        await writeFile(path.join(root, 'nested', 'b.js'), '', 'utf8');
        await writeFile(path.join(root, 'a.d.ts'), '', 'utf8');
        await writeFile(path.join(root, 'ignore.txt'), '', 'utf8');

        expect(await collectOutputFiles(root)).toEqual([
            path.join(root, 'a.d.ts'),
            path.join(root, 'nested', 'b.js'),
        ]);
    });

    it('leaves specifiers with explicit extensions unchanged', async () => {
        const filePath = path.join(
            await createTempDirectory(),
            'entrypoint.js',
        );

        await expect(
            resolveRuntimeSpecifier(filePath, './dep.js'),
        ).resolves.toBe('./dep.js');
    });

    it('resolves extensionless specifiers to emitted files', async () => {
        const root = await createTempDirectory();
        const filePath = path.join(root, 'entrypoint.js');

        await writeFile(filePath, '', 'utf8');
        await writeFile(path.join(root, 'dep.js'), '', 'utf8');

        await expect(resolveRuntimeSpecifier(filePath, './dep')).resolves.toBe(
            './dep.js',
        );
    });

    it('resolves extensionless specifiers to emitted index files', async () => {
        const root = await createTempDirectory();
        const filePath = path.join(root, 'entrypoint.js');

        await mkdir(path.join(root, 'nested'), { recursive: true });
        await writeFile(filePath, '', 'utf8');
        await writeFile(path.join(root, 'nested', 'index.js'), '', 'utf8');

        await expect(
            resolveRuntimeSpecifier(filePath, './nested'),
        ).resolves.toBe('./nested/index.js');
    });

    it('rewrites static, re-exported, and dynamic import specifiers', async () => {
        const root = await createTempDirectory();
        const filePath = path.join(root, 'entrypoint.js');

        await mkdir(path.join(root, 'nested'), { recursive: true });
        await mkdir(path.join(root, 'dynamic'), { recursive: true });
        await writeFile(path.join(root, 'dep.js'), '', 'utf8');
        await writeFile(path.join(root, 'nested', 'index.js'), '', 'utf8');
        await writeFile(path.join(root, 'dynamic', 'index.js'), '', 'utf8');
        await writeFile(
            filePath,
            [
                "import './dep';",
                "export { value } from './nested';",
                "const loaded = import('./dynamic');",
            ].join('\n'),
            'utf8',
        );

        await expect(rewriteFile(filePath)).resolves.toBe(3);
        await expect(readFile(filePath, 'utf8')).resolves.toBe(
            [
                "import './dep.js';",
                "export { value } from './nested/index.js';",
                "const loaded = import('./dynamic/index.js');",
            ].join('\n'),
        );
    });

    it('does not rewrite files that already point to emitted targets', async () => {
        const root = await createTempDirectory();
        const filePath = path.join(root, 'entrypoint.d.ts');

        await writeFile(
            filePath,
            "export { type Value } from './dep.js';",
            'utf8',
        );

        await expect(rewriteFile(filePath)).resolves.toBe(0);
        await expect(readFile(filePath, 'utf8')).resolves.toBe(
            "export { type Value } from './dep.js';",
        );
    });

    it('throws when an emitted runtime target cannot be resolved', async () => {
        const root = await createTempDirectory();
        const filePath = path.join(root, 'entrypoint.js');

        await writeFile(filePath, "import './missing';", 'utf8');

        await expect(rewriteFile(filePath)).rejects.toThrow(
            'Could not resolve emitted runtime target',
        );
    });
});
