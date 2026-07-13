import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
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

export type GeneratedArtifactFingerprint = {
    readonly byteLength: number;
    readonly sha256: string;
};

export const collectGeneratedArtifactFingerprints = async (
    rootDirectoryPath: string,
    relativePaths: readonly string[] = generatedArtifactRelativePaths,
): Promise<ReadonlyMap<string, GeneratedArtifactFingerprint>> => {
    const fingerprints = new Map<string, GeneratedArtifactFingerprint>();

    for (const relativePath of [...relativePaths].sort()) {
        const absolutePath = path.resolve(rootDirectoryPath, relativePath);
        const fileStatistics = await stat(absolutePath);
        if (!fileStatistics.isFile()) {
            throw new Error(
                `Generated build artifact is not a file: ${relativePath}`,
            );
        }
        const bytes = await readFile(absolutePath);
        fingerprints.set(relativePath, {
            byteLength: bytes.byteLength,
            sha256: createHash('sha256').update(bytes).digest('hex'),
        });
    }

    return fingerprints;
};

export const compareGeneratedArtifactFingerprints = (
    before: ReadonlyMap<string, GeneratedArtifactFingerprint>,
    after: ReadonlyMap<string, GeneratedArtifactFingerprint>,
): readonly string[] => {
    const relativePaths = new Set([...before.keys(), ...after.keys()]);

    return [...relativePaths].sort().filter((relativePath) => {
        const first = before.get(relativePath);
        const second = after.get(relativePath);
        return (
            first === undefined ||
            first.byteLength !== second?.byteLength ||
            first.sha256 !== second.sha256
        );
    });
};

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
    const before = await collectGeneratedArtifactFingerprints(repositoryRoot);

    runPackageCommand([
        '--filter',
        '@sealed-lattice/wasm',
        'run',
        'build:wasm',
    ]);
    runPackageCommand(['--filter', 'sealed-lattice', 'run', 'build']);

    const after = await collectGeneratedArtifactFingerprints(repositoryRoot);
    const changedRelativePaths = compareGeneratedArtifactFingerprints(
        before,
        after,
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
