import { createHash } from 'node:crypto';
import { readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { runPackageManagerAndCaptureOutput } from './run-command.js';

import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const generatedArtifactRelativePaths = [
    'packages/sdk/dist/index.d.ts',
    'packages/sdk/dist/index.js',
    'packages/sdk/dist/index.js.map',
    'packages/sdk/dist/participant-source-manifest.json',
    'packages/sdk/dist/participant-worker.js',
    'packages/sdk/dist/participant.wasm',
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

// The participant module build's own target directory. The repeated build
// starts without it, so cargo recompiles the module instead of reusing the
// cached one.
const participantModuleTargetPath = path.resolve(
    repositoryRoot,
    'target/participant-module',
);

export const verifyBuildReproducibility = async (): Promise<void> => {
    const before = await collectGeneratedArtifactHashes();

    await rm(participantModuleTargetPath, { recursive: true, force: true });
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

    console.log(
        'A repeated SDK build with a recompiled participant module reproduced every package byte.',
    );
};

if (import.meta.main) {
    await runWithLocalRunLog(
        {
            scriptName: 'build:verify-reproducible',
            commandLineArguments: [],
            lanes: ['Exact package reproduction and source identity'],
        },
        async (log) => {
            await verifyBuildReproducibility();
            const directory = path.join(repositoryRoot, 'packages/sdk/dist');
            const manifest = await readFile(
                path.join(directory, 'participant-source-manifest.json'),
            );
            const entries = (
                JSON.parse(manifest.toString()) as {
                    files: { file: string; sha512: string; bytes: number }[];
                }
            ).files;
            for (const entry of entries) {
                const bytes = await readFile(
                    path.join(repositoryRoot, entry.file),
                );
                if (
                    bytes.length !== entry.bytes ||
                    createHash('sha512').update(bytes).digest('hex') !==
                        entry.sha512
                )
                    throw new Error(
                        'The package source manifest differs from the reviewed source: ' +
                            entry.file,
                    );
            }
            const identity = participantRuntimeIdentity(
                manifest,
                await readFile(path.join(directory, 'participant.wasm')),
                await readFile(path.join(directory, 'participant-worker.js')),
            );
            const files = [];
            for (const file of generatedArtifactRelativePaths) {
                const bytes = await readFile(path.join(repositoryRoot, file));
                files.push({
                    file,
                    bytes: bytes.length,
                    sha512: createHash('sha512').update(bytes).digest('hex'),
                });
            }
            const report = {
                identity,
                files,
                sourceManifestVerified: true,
                packageReproduced: true,
            };
            await writeFile(
                path.join(log.runDirectoryPath, 'build-identity.json'),
                JSON.stringify(report, null, 2) + '\n',
                { flag: 'wx' },
            );
            log.writeEvent({ eventType: 'build-pinned', details: report });
            process.stdout.write(log.runDirectoryPath + '\n');
        },
    );
}
