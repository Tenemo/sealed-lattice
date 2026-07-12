import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { runPackageManagerAndCaptureOutput } from './run-command.js';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const wasmKernelSourcePath = path.resolve(
    repoRoot,
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const sdkDistDirectoryPath = path.resolve(repoRoot, 'packages', 'sdk', 'dist');
const sdkDeclarationScratchDirectoryPath = path.resolve(
    repoRoot,
    '.turbo',
    'sdk-package-declarations',
);
const sdkKernelOutputPath = path.join(
    sdkDistDirectoryPath,
    'sealed-lattice-kernel.wasm',
);
const tsdownConfigPath = path.resolve(
    repoRoot,
    'tools',
    'ci',
    'sdk-package-tsdown.config.ts',
);
const kernelHashEnvironmentVariable =
    'SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX';
const declarationEntryEnvironmentVariable =
    'SEALED_LATTICE_SDK_DECLARATION_ENTRY_PATH';

export const hashNormalizedWasmKernel = (bytes: Uint8Array): string =>
    createHash('sha256')
        .update(normalizeTranscriptCoreKernelBytesForHash(bytes))
        .digest('hex');

export const copyWasmKernelByteIdentically = async (input: {
    readonly destinationPath: string;
    readonly sourceBytes: Uint8Array;
    readonly sourcePath: string;
}): Promise<void> => {
    await mkdir(path.dirname(input.destinationPath), { recursive: true });
    await copyFile(input.sourcePath, input.destinationPath);
    const copiedKernelBytes = await readFile(input.destinationPath);
    if (!Buffer.from(input.sourceBytes).equals(copiedKernelBytes)) {
        throw new Error(
            'The public SDK WASM kernel copy differs from the internal package artifact.',
        );
    }
};

const runPackageBuildCommand = (
    commandArguments: readonly string[],
    environment: NodeJS.ProcessEnv = process.env,
): void => {
    const output = runPackageManagerAndCaptureOutput(
        resolvePackageManagerRunner(),
        commandArguments,
        repoRoot,
        { environment },
    );

    if (output.length > 0) {
        process.stdout.write(output);
    }
};

const emitSdkDeclarationEntry = (
    declarationOutputDirectoryPath: string,
): void => {
    runPackageBuildCommand([
        'exec',
        'tsc',
        '--project',
        path.resolve(repoRoot, 'packages', 'sdk', 'tsconfig.json'),
        '--emitDeclarationOnly',
        '--outDir',
        declarationOutputDirectoryPath,
        '--tsBuildInfoFile',
        path.join(declarationOutputDirectoryPath, 'tsconfig.tsbuildinfo'),
    ]);
};

const bundleSdkOutput = (
    kernelHash: string,
    declarationEntryPath: string,
): void => {
    const environment = {
        ...process.env,
        [declarationEntryEnvironmentVariable]: declarationEntryPath,
        [kernelHashEnvironmentVariable]: kernelHash,
    };

    for (const configurationName of ['sdk-javascript', 'sdk-declarations']) {
        runPackageBuildCommand(
            [
                'exec',
                'tsdown',
                '--config',
                tsdownConfigPath,
                '--filter',
                configurationName,
            ],
            environment,
        );
    }
};

export const buildSdkPackage = async (): Promise<void> => {
    let kernelBytes: Buffer;
    try {
        kernelBytes = await readFile(wasmKernelSourcePath);
    } catch (error) {
        const buildError = new Error(
            'Cannot build the public SDK before @sealed-lattice/wasm. Run the workspace build so Turborepo builds package dependencies first.',
        ) as Error & { cause: unknown };
        buildError.cause = error;
        throw buildError;
    }

    const kernelHash = hashNormalizedWasmKernel(kernelBytes);
    await rm(sdkDeclarationScratchDirectoryPath, {
        force: true,
        recursive: true,
    });
    await mkdir(sdkDeclarationScratchDirectoryPath, { recursive: true });

    try {
        emitSdkDeclarationEntry(sdkDeclarationScratchDirectoryPath);
        bundleSdkOutput(
            kernelHash,
            path.join(sdkDeclarationScratchDirectoryPath, 'index.d.ts'),
        );
    } finally {
        await rm(sdkDeclarationScratchDirectoryPath, {
            force: true,
            recursive: true,
        });
    }

    await copyWasmKernelByteIdentically({
        destinationPath: sdkKernelOutputPath,
        sourceBytes: kernelBytes,
        sourcePath: wasmKernelSourcePath,
    });

    console.log(
        `Public SDK bundled with the byte-identical WASM kernel (${kernelHash}).`,
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    await buildSdkPackage();
}
