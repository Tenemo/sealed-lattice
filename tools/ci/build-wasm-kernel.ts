import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
    copyFile,
    mkdir,
    mkdtemp,
    readFile,
    rename,
    rm,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { foundationProfile } from '#packages/types/src/foundation-contract.js';
import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const cargoTargetDirectory = path.resolve(repoRoot, 'target', 'wasm-kernel');
const wasmBuildScratchRoot = path.resolve(
    repoRoot,
    '.turbo',
    'wasm-kernel-builds',
);
const encodedRustflagSeparator = '\x1f';
const wasmOutputFilePath = path.resolve(
    repoRoot,
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const wasmOptimizerScriptFilePath = path.resolve(
    repoRoot,
    'node_modules',
    'binaryen',
    'bin',
    'wasm-opt',
);

const runCheckedCommand = (input: {
    readonly args: readonly string[];
    readonly command: string;
    readonly description: string;
    readonly env?: NodeJS.ProcessEnv;
}): void => {
    const result = spawnSync(input.command, input.args, {
        cwd: repoRoot,
        env: input.env,
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start ${input.description}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `${input.description} terminated by signal ${result.signal}`,
        );
    }
    if (result.status !== 0) {
        const stdout = result.stdout?.trim();
        const stderr = result.stderr?.trim();
        const formattedOutput =
            stdout !== '' || stderr !== ''
                ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                : '';

        throw new Error(
            `${input.description} exited with status ${result.status ?? 'null'}${formattedOutput}`,
        );
    }
};

export const createDeterministicCargoEnvironment = (
    environment: NodeJS.ProcessEnv = process.env,
    input: {
        readonly cargoHome?: string;
        readonly projectRoot?: string;
        readonly targetDirectory?: string;
    } = {},
): NodeJS.ProcessEnv => {
    const inheritedEncodedRustflags = environment.CARGO_ENCODED_RUSTFLAGS;
    if (
        inheritedEncodedRustflags !== undefined &&
        inheritedEncodedRustflags.length > 0
    ) {
        throw new Error(
            'CARGO_ENCODED_RUSTFLAGS must be unset for the deterministic WASM build.',
        );
    }

    const projectRoot = input.projectRoot ?? repoRoot;
    const cargoHome = path.resolve(
        input.cargoHome ??
            environment.CARGO_HOME ??
            path.join(os.homedir(), '.cargo'),
    );
    const deterministicRustflags = [
        '--remap-path-prefix',
        `${projectRoot}=/workspace`,
        '--remap-path-prefix',
        `${cargoHome}=/cargo`,
        '-C',
        `link-arg=--max-memory=${foundationProfile.maximumWasmMemoryByteLength}`,
    ];

    return {
        ...environment,
        CARGO_ENCODED_RUSTFLAGS: deterministicRustflags.join(
            encodedRustflagSeparator,
        ),
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR: input.targetDirectory ?? cargoTargetDirectory,
        SOURCE_DATE_EPOCH: '0',
    };
};

const runCargoBuild = (): void => {
    runCheckedCommand({
        command: 'cargo',
        args: [
            'build',
            '--locked',
            '--package',
            'sealed-lattice-kernel',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
            '--release',
        ],
        description: 'cargo build',
        env: createDeterministicCargoEnvironment(),
    });
};

const runWasmOptimizer = (
    inputFilePath: string,
    outputFilePath: string,
): void => {
    runCheckedCommand({
        command: process.execPath,
        args: [
            wasmOptimizerScriptFilePath,
            '-O3',
            inputFilePath,
            '-o',
            outputFilePath,
        ],
        description: 'wasm-opt',
    });
};

const cargoWasmOutputFilePath = (): string =>
    path.resolve(
        cargoTargetDirectory,
        'wasm32-unknown-unknown',
        'release',
        'sealed_lattice_kernel.wasm',
    );

const hashNormalizedWasmKernel = async (filePath: string): Promise<string> =>
    createHash('sha256')
        .update(
            normalizeTranscriptCoreKernelBytesForHash(await readFile(filePath)),
        )
        .digest('hex');

export const buildWasmKernel = async (): Promise<void> => {
    const outputDirectoryPath = path.dirname(wasmOutputFilePath);
    await mkdir(outputDirectoryPath, { recursive: true });
    await mkdir(wasmBuildScratchRoot, { recursive: true });
    const scratchDirectoryPath = await mkdtemp(
        path.join(wasmBuildScratchRoot, 'build-'),
    );
    const unoptimizedOutputFilePath = path.join(
        scratchDirectoryPath,
        'kernel.unoptimized.wasm',
    );
    const optimizedOutputFilePath = path.join(
        scratchDirectoryPath,
        'kernel.wasm',
    );

    try {
        runCargoBuild();
        await copyFile(cargoWasmOutputFilePath(), unoptimizedOutputFilePath);
        runWasmOptimizer(unoptimizedOutputFilePath, optimizedOutputFilePath);

        const kernelHash = await hashNormalizedWasmKernel(
            optimizedOutputFilePath,
        );
        await rename(optimizedOutputFilePath, wasmOutputFilePath);

        console.log(
            `Transcript-core kernel built at packages/wasm/dist/sealed-lattice-kernel.wasm (${kernelHash}).`,
        );
    } finally {
        await rm(scratchDirectoryPath, { force: true, recursive: true });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    await buildWasmKernel();
}
