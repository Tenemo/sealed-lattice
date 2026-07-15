import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { runPackageManagerAndCaptureOutput } from './run-command.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const generatedArtifactRelativePaths = [
    'packages/wasm/dist/sealed-lattice-kernel.wasm',
    'packages/sdk/dist/index.d.ts',
    'packages/sdk/dist/index.js',
    'packages/sdk/dist/index.js.map',
    'packages/sdk/dist/sealed-lattice-kernel.wasm',
] as const;

const collectGeneratedArtifactHashes = async (): Promise<readonly string[]> =>
    Promise.all(
        generatedArtifactRelativePaths.map(async (relativePath) =>
            createHash('sha256')
                .update(
                    await readFile(path.resolve(repositoryRoot, relativePath)),
                )
                .digest('hex'),
        ),
    );

const runPackageCommand = (argumentsList: readonly string[]): void => {
    const output = runPackageManagerAndCaptureOutput(
        resolvePackageManagerRunner(),
        argumentsList,
        repositoryRoot,
    );
    if (output.length > 0) {
        process.stdout.write(output);
    }
};

export const verifyBuildReproducibility = async (): Promise<void> => {
    const before = await collectGeneratedArtifactHashes();

    runPackageCommand([
        '--filter',
        '@sealed-lattice/wasm',
        'run',
        'build:wasm',
    ]);
    runPackageCommand(['--filter', 'sealed-lattice', 'run', 'build']);

    const after = await collectGeneratedArtifactHashes();
    const changedRelativePaths = generatedArtifactRelativePaths.filter(
        (_, index) => before[index] !== after[index],
    );
    if (changedRelativePaths.length > 0) {
        throw new Error(
            `Repeated builds changed generated package bytes:\n${changedRelativePaths.join('\n')}`,
        );
    }

    console.log('Repeated WASM and SDK builds reproduced every package byte.');
};

if (import.meta.main) {
    await verifyBuildReproducibility();
}
