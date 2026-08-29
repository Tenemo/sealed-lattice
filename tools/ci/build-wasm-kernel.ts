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

import { maximumFoundationWasmMemoryByteLength } from '#packages/wasm/src/foundation-contract.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const cargoTargetDirectory = path.resolve(repoRoot, 'target', 'wasm-kernel');
const wasmBuildScratchRoot = path.resolve(
    repoRoot,
    'temp',
    'build-scratch',
    'wasm-kernel-builds',
);
const encodedRustflagSeparator = '\x1f';
export const wasmStackByteLength = 1_048_576;
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
        `link-arg=--max-memory=${maximumFoundationWasmMemoryByteLength}`,
        '-C',
        'link-arg=-z',
        '-C',
        `link-arg=stack-size=${wasmStackByteLength}`,
        '-C',
        'link-arg=--stack-first',
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

const wasmCargoBuildArguments = [
    'build',
    '--locked',
    '--package',
    'sealed-lattice-kernel',
    '--lib',
    '--target',
    'wasm32-unknown-unknown',
    '--release',
] as const;

const runCargoBuild = (input: {
    readonly environment: NodeJS.ProcessEnv;
    readonly targetDirectoryPath: string;
}): void => {
    runCheckedCommand({
        command: 'cargo',
        args: wasmCargoBuildArguments,
        description: 'cargo build',
        env: createDeterministicCargoEnvironment(input.environment, {
            targetDirectory: input.targetDirectoryPath,
        }),
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

const cargoWasmOutputFilePath = (targetDirectoryPath: string): string =>
    path.resolve(
        targetDirectoryPath,
        'wasm32-unknown-unknown',
        'release',
        'sealed_lattice_kernel.wasm',
    );

const hashWasmKernel = async (filePath: string): Promise<string> =>
    createHash('sha256')
        .update(await readFile(filePath))
        .digest('hex');

export const buildOptimizedWasmKernelArtifact = async (input: {
    readonly artifactLabel: string;
    readonly outputFilePath: string;
    readonly scratchDirectoryPrefix: string;
    readonly targetDirectoryPath: string;
}): Promise<void> => {
    const outputDirectoryPath = path.dirname(input.outputFilePath);
    await mkdir(outputDirectoryPath, { recursive: true });
    await mkdir(wasmBuildScratchRoot, { recursive: true });
    const scratchDirectoryPath = await mkdtemp(
        path.join(wasmBuildScratchRoot, input.scratchDirectoryPrefix),
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
        runCargoBuild({
            environment: process.env,
            targetDirectoryPath: input.targetDirectoryPath,
        });
        await copyFile(
            cargoWasmOutputFilePath(input.targetDirectoryPath),
            unoptimizedOutputFilePath,
        );
        runWasmOptimizer(unoptimizedOutputFilePath, optimizedOutputFilePath);

        const sha256Hex = await hashWasmKernel(optimizedOutputFilePath);
        await rename(optimizedOutputFilePath, input.outputFilePath);

        console.log(
            `${input.artifactLabel} built at ${path.relative(repoRoot, input.outputFilePath)} (${sha256Hex}); deterministic WASM stack ${wasmStackByteLength} bytes.`,
        );
    } finally {
        await rm(scratchDirectoryPath, { force: true, recursive: true });
    }
};

export const buildWasmKernel = async (): Promise<void> => {
    await buildOptimizedWasmKernelArtifact({
        artifactLabel: 'Foundation kernel',
        outputFilePath: wasmOutputFilePath,
        scratchDirectoryPrefix: 'build-',
        targetDirectoryPath: cargoTargetDirectory,
    });
};

if (import.meta.main) {
    await buildWasmKernel();
}
