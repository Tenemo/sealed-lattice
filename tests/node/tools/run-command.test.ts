import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    buildPackageManagerEntryPointCandidates,
    resolvePackageManagerRunnerForPackageManager,
    resolvePackageManagerRunnerFromArguments,
} from '#tools/ci/run-command';

describe('package manager runner resolution', () => {
    it('resolves a requested package manager through the shared runner helper', () => {
        const nodeExecutablePath = path.resolve(
            'toolchains',
            'node',
            'bin',
            'node',
        );
        const npmEntryPointCandidates = buildPackageManagerEntryPointCandidates(
            'npm',
            '',
            nodeExecutablePath,
        );
        const expectedNpmEntryPoint = npmEntryPointCandidates[1];
        if (expectedNpmEntryPoint === undefined) {
            throw new Error(
                'Expected the npm candidate list to include fallback entries.',
            );
        }

        const runner = resolvePackageManagerRunnerForPackageManager(
            'npm',
            path.resolve('toolchains', 'pnpm', 'bin', 'pnpm.cjs'),
            '',
            nodeExecutablePath,
            (candidatePath) => candidatePath === expectedNpmEntryPoint,
        );

        expect(runner).toEqual({
            command: nodeExecutablePath,
            commandArgumentsPrefix: [expectedNpmEntryPoint],
            kind: 'npm',
        });
    });

    it('uses the same runner helper for command-line package manager overrides', () => {
        const nodeExecutablePath = path.resolve(
            'toolchains',
            'node',
            'bin',
            'node',
        );
        const expectedNpmEntryPoint = buildPackageManagerEntryPointCandidates(
            'npm',
            '',
            nodeExecutablePath,
        )[0];
        if (expectedNpmEntryPoint === undefined) {
            throw new Error(
                'Expected the npm candidate list to include an entry.',
            );
        }

        const runner = resolvePackageManagerRunnerFromArguments(
            ['--package-manager', 'npm'],
            path.resolve('toolchains', 'pnpm', 'bin', 'pnpm.cjs'),
            '',
            nodeExecutablePath,
            (candidatePath) => candidatePath === expectedNpmEntryPoint,
        );

        expect(runner).toEqual({
            command: nodeExecutablePath,
            commandArgumentsPrefix: [expectedNpmEntryPoint],
            kind: 'npm',
        });
    });
});
