import { copyFile, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

export const buildSdkPackage = async (): Promise<void> => {
    const { hash: kernelHash } = await buildWasmKernel({
        includeConstruction: false,
        outputFilePath: kernelStagingPath,
    });
    const kernelBytes = await readFile(kernelStagingPath);
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

    await mkdir(sdkOutputDirectoryPath, { recursive: true });
    await copyFile(kernelStagingPath, kernelOutputPath);
    if (!kernelBytes.equals(await readFile(kernelOutputPath))) {
        throw new Error('The public SDK kernel copy differs from its build.');
    }
    console.log(`Public SDK bundled with exact kernel ${kernelHash}.`);
};

if (import.meta.main) await buildSdkPackage();
