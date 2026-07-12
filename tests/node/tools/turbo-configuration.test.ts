import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

type TurboTask = {
    readonly inputs?: readonly string[];
    readonly outputs?: readonly string[];
};

type TurboConfiguration = {
    readonly globalDependencies?: readonly string[];
    readonly tasks: Readonly<Record<string, TurboTask>>;
};

describe('Turbo build inputs', () => {
    it('hashes only build inputs and every output-affecting toolchain file', async () => {
        const configuration = JSON.parse(
            await readFile(path.join(process.cwd(), 'turbo.json'), 'utf8'),
        ) as TurboConfiguration;
        expect(configuration.globalDependencies).toEqual(
            expect.arrayContaining([
                '.nvmrc',
                'package.json',
                'pnpm-lock.yaml',
                'pnpm-workspace.yaml',
                'tsconfig.base.json',
            ]),
        );

        const buildTask = configuration.tasks.build;
        const wasmBuildTask = configuration.tasks['@sealed-lattice/wasm#build'];
        const sdkBuildTask = configuration.tasks['sealed-lattice#build'];
        expect(buildTask?.inputs).toEqual([
            'package.json',
            'src/**',
            'tsconfig.json',
        ]);
        expect(wasmBuildTask?.inputs).toEqual(
            expect.arrayContaining([
                '../../Cargo.lock',
                '../../Cargo.toml',
                '../../rust-toolchain.toml',
                '../../crates/*/Cargo.toml',
                '../../crates/*/src/**',
                '!../../crates/*/src/**/temp/**',
            ]),
        );
        expect(wasmBuildTask?.inputs).not.toContain('../../crates/**');

        for (const task of [buildTask, wasmBuildTask, sdkBuildTask]) {
            expect(task?.outputs).toEqual(['dist/**']);
            expect(task?.inputs).not.toContain('$TURBO_DEFAULT$');
            expect(task?.inputs?.join('\n')).not.toMatch(
                /tests?\/|README|api-surface-summary/iu,
            );
        }
    });
});
