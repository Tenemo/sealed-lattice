import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    buildLattigoOracleDockerBuildArguments,
    buildLattigoOracleDockerRunArguments,
    lattigoOracleDirectoryPath,
} from '#tools/lattigo-oracle/run-lattigo-oracle';

describe('independent test entrypoint containment', () => {
    it('routes internal WASM kernel scripts through root orchestration', async () => {
        const internalWasmPackageManifest = JSON.parse(
            await readFile(
                path.resolve('packages', 'wasm', 'package.json'),
                'utf8',
            ),
        ) as {
            readonly scripts?: Readonly<Record<string, string>>;
        };
        const workspacePackageManifest = JSON.parse(
            await readFile(path.resolve('package.json'), 'utf8'),
        ) as {
            readonly scripts?: Readonly<Record<string, string>>;
        };

        expect(internalWasmPackageManifest.scripts).toMatchObject({
            'test:node': 'pnpm --workspace-root run test:node:kernel',
            'test:node:kernel': 'pnpm --workspace-root run test:node:kernel',
            'test:node:kernel:fast':
                'pnpm --workspace-root run test:node:kernel:fast',
            'test:node:kernel:heavy':
                'pnpm --workspace-root run test:node:kernel:heavy',
        });
        expect(workspacePackageManifest.scripts).toMatchObject({
            'test:node:kernel': 'tsx ./tools/ci/run-node-tests.ts kernel',
            'test:node:kernel:fast':
                'tsx ./tools/ci/run-node-tests.ts kernel-fast',
            'test:node:kernel:heavy':
                'tsx ./tools/ci/run-node-tests.ts kernel-heavy',
        });
    });

    it('builds the oracle from its own directory and caps the container memory', async () => {
        expect(path.resolve(lattigoOracleDirectoryPath)).toBe(
            path.resolve('tools', 'lattigo-oracle'),
        );
        expect(buildLattigoOracleDockerBuildArguments()).toEqual([
            'build',
            '-f',
            'Dockerfile',
            '-t',
            'sealed-lattice-lattigo-oracle:bgv-rns',
            '.',
        ]);
        expect(buildLattigoOracleDockerRunArguments()).toEqual([
            'run',
            '--rm',
            '--network',
            'none',
            '--read-only',
            '--cap-drop',
            'ALL',
            '--security-opt',
            'no-new-privileges',
            '--pids-limit',
            '128',
            '--memory',
            '2g',
            '--memory-swap',
            '2g',
            'sealed-lattice-lattigo-oracle:bgv-rns',
        ]);
        const dockerfile = await readFile(
            path.resolve('tools', 'lattigo-oracle', 'Dockerfile'),
            'utf8',
        );
        expect(dockerfile).toContain('AS build');
        expect(dockerfile).toContain('FROM scratch');
        expect(dockerfile).toContain('CGO_ENABLED=0 go build');
        expect(dockerfile).toContain('USER 65532:65532');
        expect(dockerfile).not.toContain('go run');
    });
});
