// Requires Docker. Builds and runs the development-only Lattigo Docker oracle
// against the committed canonical RNS fixtures to cross-check sealed-lattice
// BGV-RNS ring, RNS, NTT, and coefficient arithmetic. This oracle is a
// developer sanity tool: its build, output, and any roots it prints are never
// runtime code, public SDK inputs, or protocol evidence. The pinned Lattigo
// module version and checksums live in tools/lattigo-oracle/go.mod + go.sum.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

export const lattigoOracleDirectoryPath = fileURLToPath(
    new URL('./', import.meta.url),
);
const oracleImageName = 'sealed-lattice-lattigo-oracle:bgv-rns';

export const buildLattigoOracleDockerBuildArguments = (): readonly string[] => [
    'build',
    '-f',
    'Dockerfile',
    '-t',
    oracleImageName,
    '.',
];

export const buildLattigoOracleDockerRunArguments = (): readonly string[] => [
    'run',
    '--rm',
    '--memory',
    '2g',
    '--memory-swap',
    '2g',
    oracleImageName,
];

const runDockerCommand = async (
    commandArguments: readonly string[],
): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
        const dockerProcess = spawn('docker', [...commandArguments], {
            cwd: lattigoOracleDirectoryPath,
            stdio: 'inherit',
        });
        dockerProcess.once('error', reject);
        dockerProcess.once('exit', (exitCode) => {
            if (exitCode === 0) {
                resolve();
                return;
            }
            reject(
                new Error(
                    `docker ${commandArguments.join(' ')} exited with code ${exitCode}.`,
                ),
            );
        });
    });
};

const main = async (): Promise<void> => {
    await runDockerCommand(buildLattigoOracleDockerBuildArguments());
    await runDockerCommand(buildLattigoOracleDockerRunArguments());
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
