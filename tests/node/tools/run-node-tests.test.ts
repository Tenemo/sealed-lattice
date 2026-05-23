import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    buildNodeTestCommands,
    parseRequestedNodeTestLanes,
} from '#tools/ci/run-node-tests';

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
    it('keeps package scripts focused on local build entry points', async () => {
        const scripts = await readWorkspacePackageScripts();

        expect(
            Object.keys(scripts).filter((scriptName) =>
                scriptName.endsWith(':built'),
            ),
        ).toEqual([]);
        expect(scripts['test:node']).toBe(
            'pnpm run build && tsx ./tools/ci/run-node-tests.ts',
        );
        expect(scripts['test:node:fast']).toBe(
            'pnpm run build && tsx ./tools/ci/run-node-tests.ts --only fast',
        );
        expect(scripts['test:browser']).toBe(
            'pnpm run build && vitest --project browser-desktop --project browser-mobile --run',
        );
    });

    it('keeps heavy Node lanes independently runnable', () => {
        const commands = buildNodeTestCommands({ packageManagerRunner });

        expect(commands.map((command) => command.description)).toEqual([
            'Run fast Node tests',
            'Run relation-heavy Node tests',
            'Run proof-input-heavy Node tests',
            'Run remaining heavy Node kernel tests',
            'Run aggregate heavy Node kernel tests',
        ]);
        expect(commands.map((command) => command.args)).toEqual([
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node',
                '--run',
            ],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node-relation-heavy',
                '--run',
            ],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node-proof-input-heavy',
                '--run',
            ],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node-kernel-remaining',
                '--run',
            ],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node-kernel-aggregate',
                '--run',
            ],
        ]);
    });

    it('can select one or more lanes for parallel CI jobs', () => {
        expect(parseRequestedNodeTestLanes(['--only', 'fast'])).toEqual([
            'fast',
        ]);
        expect(
            parseRequestedNodeTestLanes([
                '--only',
                'kernel-remaining,kernel-aggregate,kernel-remaining',
            ]),
        ).toEqual(['kernel-remaining', 'kernel-aggregate']);
    });

    it('rejects unsupported lane selectors', () => {
        expect(() => parseRequestedNodeTestLanes(['--only', 'kernel'])).toThrow(
            'Unsupported Node test lane: kernel',
        );
        expect(() => parseRequestedNodeTestLanes(['--lane', 'fast'])).toThrow(
            'Usage: run-node-tests.ts [--only lane[,lane...]].',
        );
    });
});
