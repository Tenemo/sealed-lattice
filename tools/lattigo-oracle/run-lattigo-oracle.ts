// Requires Docker. Builds and runs the development-only Lattigo Docker oracle
// against the committed canonical RNS fixtures to cross-check sealed-lattice
// BGV-RNS ring, RNS, NTT, and coefficient arithmetic. This oracle is a
// developer sanity tool: its build, output, and any roots it prints are never
// runtime code, public SDK inputs, or protocol evidence. The pinned Lattigo
// commit lives in tools/lattigo-oracle/go.mod + go.sum as an ordinary
// commit-pinned Go module dependency.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const oracleImageName = 'sealed-lattice-lattigo-oracle:bgv-rns';

const runDockerCommand = async (
    commandArguments: readonly string[],
): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
        const dockerProcess = spawn('docker', [...commandArguments], {
            cwd: repoRoot,
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
    await runDockerCommand([
        'build',
        '-f',
        'tools/lattigo-oracle/Dockerfile',
        '-t',
        oracleImageName,
        '.',
    ]);
    await runDockerCommand(['run', '--rm', oracleImageName]);
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
