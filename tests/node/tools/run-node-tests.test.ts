import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { buildNodeTestCommands } from '#tools/ci/run-node-tests';

const packageManagerRunner = {
    command: 'node',
    commandArgumentsPrefix: ['pnpm-entrypoint.js'],
} as const;

const readWorkspacePackageScripts = async (): Promise<
    Record<string, string>
> => {
    const packageJsonText = await readFile(
        new URL('../../../package.json', import.meta.url),
        'utf8',
    );
    const packageJson = JSON.parse(packageJsonText) as {
        readonly scripts?: Record<string, string>;
    };

    return packageJson.scripts ?? {};
};

describe('node test runner', () => {
    it('routes the package script through the TypeScript runner', async () => {
        const scripts = await readWorkspacePackageScripts();

        expect(scripts['test:node:built']).toBe(
            'tsx ./tools/ci/run-node-tests.ts',
        );
    });

    it('keeps kernel-heavy proof tests out of the fast and heavy node phase', () => {
        const commands = buildNodeTestCommands({ packageManagerRunner });

        expect(commands.map((command) => command.description)).toEqual([
            'Run fast and heavy Node tests',
            'Run heavy Node kernel tests',
        ]);
        expect(commands.map((command) => command.args)).toEqual([
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node',
                '--project',
                'node-heavy',
                '--run',
            ],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node-kernel-heavy',
                '--run',
            ],
        ]);
    });
});
