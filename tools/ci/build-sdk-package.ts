import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { runPackageManagerAndCaptureOutput } from './run-command.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const kernelSourcePath = path.join(
    repositoryRoot,
    'packages',
    'wasm',
    'dist',
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

const hashWasmKernel = (bytes: Uint8Array): string =>
    createHash('sha256').update(bytes).digest('hex');

export const buildSdkPackage = async (): Promise<void> => {
    let kernelBytes: Buffer;
    try {
        kernelBytes = await readFile(kernelSourcePath);
    } catch {
        throw new Error(
            'Build @sealed-lattice/wasm before building the public SDK.',
        );
    }
    const kernelHash = hashWasmKernel(kernelBytes);
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
    await copyFile(kernelSourcePath, kernelOutputPath);
    if (!kernelBytes.equals(await readFile(kernelOutputPath))) {
        throw new Error('The public SDK kernel copy differs from its source.');
    }
    console.log(`Public SDK bundled with exact kernel ${kernelHash}.`);
};

if (import.meta.main) await buildSdkPackage();
