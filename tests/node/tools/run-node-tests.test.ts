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

const readWorkspaceFile = async (relativePath: string): Promise<string> =>
    readFile(new URL(`../../../${relativePath}`, import.meta.url), 'utf8');

const readWorkspacePackageScripts = async (): Promise<
    Record<string, string>
> => {
    const packageJsonText = await readWorkspaceFile('package.json');
    const packageJson = JSON.parse(packageJsonText) as {
        readonly scripts?: Record<string, string>;
    };

    return packageJson.scripts ?? {};
};

const splitNodeLaneScriptNames = [
    'test:node:fast',
    'test:node:relation-heavy',
    'test:node:proof-input-heavy',
    'test:node:kernel-remaining',
    'test:node:kernel-aggregate',
] as const;

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
        expect(scripts['test:node:relation-heavy']).toBe(
            'pnpm run build && tsx ./tools/ci/run-node-tests.ts --only relation-heavy',
        );
        expect(scripts['test:node:proof-input-heavy']).toBe(
            'pnpm run build && tsx ./tools/ci/run-node-tests.ts --only proof-input-heavy',
        );
        expect(scripts['test:node:kernel-remaining']).toBe(
            'pnpm run build && tsx ./tools/ci/run-node-tests.ts --only kernel-remaining',
        );
        expect(scripts['test:node:kernel-aggregate']).toBe(
            'pnpm run build && tsx ./tools/ci/run-node-tests.ts --only kernel-aggregate',
        );
        expect(scripts['test:browser']).toBe(
            'pnpm run build && vitest --project browser-desktop --project browser-mobile --run',
        );
    });

    it('keeps split workflow jobs on package script entry points', async () => {
        const workflowTexts = await Promise.all([
            readWorkspaceFile('.github/workflows/ci.yml'),
            readWorkspaceFile('.github/workflows/release.yml'),
        ]);

        for (const workflowText of workflowTexts) {
            expect(workflowText).not.toContain(
                'pnpm exec tsx ./tools/ci/run-node-tests.ts',
            );
            for (const scriptName of splitNodeLaneScriptNames) {
                expect(workflowText).toContain(`- run: pnpm run ${scriptName}`);
            }
        }
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
