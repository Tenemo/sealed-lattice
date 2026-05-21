import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    buildProofBenchmarkCommands,
    parseRequestedProofBenchmarkLanes,
} from '#tools/ci/run-proof-benchmarks';

const proofBenchmarkEnvironmentVariableName =
    'VITE_SEALED_LATTICE_ENABLE_THROTTLED_MOBILE_BENCHMARK';

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

describe('proof benchmark runner', () => {
    it('keeps one package script namespace without plural aliases', async () => {
        const scripts = await readWorkspacePackageScripts();
        const proofBenchmarkScriptNames = Object.keys(scripts)
            .filter((scriptName) =>
                scriptName.startsWith('test:proof-benchmark'),
            )
            .sort();

        expect(proofBenchmarkScriptNames).toEqual([
            'test:proof-benchmark',
            'test:proof-benchmark:browser:desktop',
            'test:proof-benchmark:browser:mobile:throttled',
            'test:proof-benchmark:node',
        ]);
        expect(
            Object.keys(scripts).filter((scriptName) =>
                scriptName.startsWith('test:proof-benchmarks'),
            ),
        ).toEqual([]);
        expect(scripts).not.toHaveProperty(
            'test:proof-benchmark:browser:mobile',
        );
    });

    it('runs node and desktop lanes by default', () => {
        const commands = buildProofBenchmarkCommands({
            packageManagerRunner,
        });

        expect(commands.map((command) => command.description)).toEqual([
            'Build workspace packages',
            'Run node proof benchmark',
            'Run desktop proof benchmark',
        ]);
        expect(commands.map((command) => command.args)).toEqual([
            ['pnpm-entrypoint.js', 'run', 'build'],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'node-proof-benchmark',
                '--run',
            ],
            [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'browser-desktop-proof-benchmark',
                '--run',
            ],
        ]);
    });

    it('runs the mobile lane only through the throttled project and environment flag', () => {
        const commands = buildProofBenchmarkCommands({
            lanes: ['mobile-throttled'],
            packageManagerRunner,
        });

        expect(commands).toHaveLength(2);
        expect(commands[1]).toMatchObject({
            args: [
                'pnpm-entrypoint.js',
                'exec',
                'vitest',
                '--project',
                'browser-mobile-throttled-proof-benchmark',
                '--run',
            ],
            description:
                'Run manually throttled mobile Chromium proof benchmark',
        });
        expect(commands[1]?.env?.[proofBenchmarkEnvironmentVariableName]).toBe(
            '1',
        );
    });

    it('rejects the removed non-throttled mobile lane', () => {
        expect(() =>
            parseRequestedProofBenchmarkLanes(['--only', 'mobile']),
        ).toThrow('Unsupported proof benchmark lane: mobile');
    });
});
