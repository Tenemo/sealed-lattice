import {
    copyFile,
    mkdir,
    readdir,
    readFile,
    rm,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'tsdown';

import {
    buildParticipantModule,
    participantSourceManifest,
} from './build-participant-module.js';
import { buildWasmKernel } from './build-wasm-kernel.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { runPackageManagerAndCaptureOutput } from './run-command.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const kernelStagingPath = path.join(
    repositoryRoot,
    'target',
    'public-sdk-kernel',
    'sealed-lattice-kernel.wasm',
);
const workerStagingPath = path.join(
    repositoryRoot,
    'target',
    'public-sdk-participant-worker',
);
const sdkOutputDirectoryPath = path.join(
    repositoryRoot,
    'packages',
    'sdk',
    'dist',
);
const kernelOutputPath = path.join(
    sdkOutputDirectoryPath,
    'sealed-lattice-kernel.wasm',
);

// Bundles the participant worker into one unminified browser module.
const buildParticipantWorker = async (): Promise<Buffer> => {
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
    });
    const outputs = (await readdir(workerStagingPath)).filter((name) =>
        /\.m?js$/u.test(name),
    );
    if (outputs.length !== 1)
        throw new Error('The participant worker bundle is not one file.');
    return readFile(path.join(workerStagingPath, outputs[0]));
};

export const buildSdkPackage = async (): Promise<void> => {
    const { hash: kernelHash } = await buildWasmKernel({
        outputFilePath: kernelStagingPath,
    });
    const kernelBytes = await readFile(kernelStagingPath);
    const participant = await buildParticipantModule();
    const sourceManifest = await participantSourceManifest(participant);
    const runner = resolvePackageManagerRunner();
    const output = runPackageManagerAndCaptureOutput(
        runner,
        [
            'exec',
            'tsdown',
            '--config',
            path.join(
                repositoryRoot,
                'tools',
                'ci',
                'sdk-package-tsdown.config.ts',
            ),
        ],
        repositoryRoot,
        {
            environment: {
                ...process.env,
                SEALED_LATTICE_KERNEL_SHA256_HEX: kernelHash,
            },
        },
    );
    if (output.length > 0) process.stdout.write(output);
    const worker = await buildParticipantWorker();

    await mkdir(sdkOutputDirectoryPath, { recursive: true });
    await copyFile(kernelStagingPath, kernelOutputPath);
    if (!kernelBytes.equals(await readFile(kernelOutputPath))) {
        throw new Error('The public SDK kernel copy differs from its build.');
    }
    for (const [name, bytes] of [
        ['participant.wasm', participant.module],
        ['participant-worker.js', worker],
        ['participant-source-manifest.json', Buffer.from(sourceManifest)],
    ] as const)
        await writeFile(path.join(sdkOutputDirectoryPath, name), bytes);
    console.log(
        `Public SDK bundled with exact kernel ${kernelHash} and the participant module and worker.`,
    );
};

if (import.meta.main) await buildSdkPackage();
