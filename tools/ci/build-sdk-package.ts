import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'tsdown';

import {
    buildParticipantModule,
    participantRuntimeIdentity,
    participantSourceManifest,
} from './build-participant-module.js';
import { recordBundleSources } from './compiled-inputs.js';
import { sdkPackageOptions } from './sdk-package-tsdown.config.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const workerStagingPath = path.join(
    repositoryRoot,
    'target',
    'public-sdk-participant-worker',
);
const entryStagingPath = path.join(
    repositoryRoot,
    'target',
    'public-sdk-entry-sources',
);
const sdkOutputDirectoryPath = path.join(
    repositoryRoot,
    'packages',
    'sdk',
    'dist',
);

// Bundles the participant worker into one unminified browser module, and
// reports the repository sources the bundle read.
const buildParticipantWorker = async (): Promise<
    Readonly<{ worker: Buffer; sources: readonly string[] }>
> => {
    const recorded = recordBundleSources();
    await rm(workerStagingPath, { recursive: true, force: true });
    await build({
        config: false,
        clean: true,
        cwd: repositoryRoot,
        dts: false,
        entry: {
            'participant-worker': path.join(
                repositoryRoot,
                'packages/sdk/src/participant/worker/worker.ts',
            ),
        },
        failOnWarn: true,
        format: 'esm',
        logLevel: 'warn',
        minify: false,
        outDir: workerStagingPath,
        outputOptions: { codeSplitting: false },
        platform: 'browser',
        report: false,
        sourcemap: false,
        target: 'es2022',
        treeshake: true,
        tsconfig: path.join(repositoryRoot, 'packages/sdk/tsconfig.json'),
        plugins: [recorded.plugin],
    });
    const outputs = (await readdir(workerStagingPath)).filter((name) =>
        /\.m?js$/u.test(name),
    );
    if (outputs.length !== 1)
        throw new Error('The participant worker bundle is not one file.');
    return {
        worker: await readFile(path.join(workerStagingPath, outputs[0])),
        sources: recorded.sources,
    };
};

// The repository sources the SDK entry's bundle reads. The entry embeds the
// runtime identity, which covers these sources, so they are read from a
// bundle with the same options and placeholder values before the entry is
// built.
const sdkEntrySources = async (): Promise<readonly string[]> => {
    const recorded = recordBundleSources();
    await rm(entryStagingPath, { recursive: true, force: true });
    try {
        await build({
            ...sdkPackageOptions(null),
            config: false,
            dts: false,
            logLevel: 'warn',
            outDir: entryStagingPath,
            sourcemap: false,
            plugins: [recorded.plugin],
        });
    } finally {
        await rm(entryStagingPath, { recursive: true, force: true });
    }
    return recorded.sources;
};

export const buildSdkPackage = async (): Promise<void> => {
    const participant = await buildParticipantModule();
    const { worker, sources: workerSources } = await buildParticipantWorker();
    const sourceManifest = Buffer.from(
        await participantSourceManifest(participant, [
            ...workerSources,
            ...(await sdkEntrySources()),
        ]),
    );
    // The SDK carries the worker's source and passes it these digests; the
    // worker recomputes the runtime identity from them and the module it
    // fetches.
    const {
        source,
        module,
        worker: workerDigest,
    } = participantRuntimeIdentity(sourceManifest, participant.module, worker);
    const participantRuntime = {
        identity: { source, module, worker: workerDigest },
        worker: worker.toString('utf8'),
    };
    if (!Buffer.from(participantRuntime.worker, 'utf8').equals(worker))
        throw new Error('The participant worker is not canonical UTF-8.');
    // Pass the worker directly: its source exceeds Linux's per-string limit
    // for a child process's arguments and environment.
    await build({ ...sdkPackageOptions(participantRuntime), config: false });

    await mkdir(sdkOutputDirectoryPath, { recursive: true });
    for (const [name, bytes] of [
        ['participant.wasm', participant.module],
        ['participant-worker.js', worker],
        ['participant-source-manifest.json', sourceManifest],
    ] as const)
        await writeFile(path.join(sdkOutputDirectoryPath, name), bytes);
    console.log('Public SDK bundled with the participant module and worker.');
};

if (import.meta.main) await buildSdkPackage();
