import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    buildLattigoOracleDockerBuildArguments,
    buildLattigoOracleDockerRunArguments,
    lattigoOracleDirectoryPath,
    parseDockerContainerState,
    requireSuccessfulDockerCapture,
} from '#tools/lattigo-oracle/run-lattigo-oracle';

describe('external oracle containment', () => {
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
        expect(buildLattigoOracleDockerRunArguments('oracle-test-run')).toEqual(
            [
                'run',
                '--name',
                'oracle-test-run',
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
            ],
        );
        const dockerfile = await readFile(
            path.resolve('tools', 'lattigo-oracle', 'Dockerfile'),
            'utf8',
        );
        expect(dockerfile).toContain('AS build');
        expect(dockerfile).toContain('FROM scratch');
        expect(dockerfile).toContain('CGO_ENABLED=0 go build');
        expect(dockerfile).toContain('USER 65532:65532');
        expect(dockerfile).not.toContain('go run');
        expect(
            parseDockerContainerState(
                '{"Status":"exited","OOMKilled":true,"ExitCode":137,"Error":""}',
            ),
        ).toMatchObject({
            Error: '',
            ExitCode: 137,
            OOMKilled: true,
            Status: 'exited',
        });
        expect(parseDockerContainerState('not JSON')).toBeUndefined();
    });

    it('rejects failed or empty Docker identity probes', () => {
        expect(
            requireSuccessfulDockerCapture(
                {
                    exitCode: 0,
                    stderr: '',
                    stdout: 'sha256:abc\n',
                    terminationSignal: null,
                },
                'image identity',
                { requireOutput: true },
            ),
        ).toBe('sha256:abc');
        expect(() =>
            requireSuccessfulDockerCapture(
                {
                    exitCode: 1,
                    stderr: 'daemon unavailable',
                    stdout: '',
                    terminationSignal: null,
                },
                'Docker version',
            ),
        ).toThrow(/daemon unavailable/u);
        expect(() =>
            requireSuccessfulDockerCapture(
                {
                    exitCode: 0,
                    stderr: '',
                    stdout: '  ',
                    terminationSignal: null,
                },
                'image identity',
                { requireOutput: true },
            ),
        ).toThrow(/returned no output/u);
    });
});
