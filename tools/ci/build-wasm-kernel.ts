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

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const defaultOutputFilePath = path.join(
    repositoryRoot,
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const optimizerPath = path.join(
    repositoryRoot,
    'node_modules',
    'binaryen',
    'bin',
    'wasm-opt',
);
const stackByteLength = 1_048_576;
const rustflagSeparator = '\x1f';

const run = (
    command: string,
    args: readonly string[],
    environment: NodeJS.ProcessEnv = process.env,
): void => {
    const result = spawnSync(command, args, {
        cwd: repositoryRoot,
        env: environment,
        stdio: 'inherit',
        windowsHide: true,
    });
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0) {
        throw new Error(
            `${path.basename(command)} failed${result.signal === null ? ` with status ${String(result.status)}` : ` with signal ${result.signal}`}.`,
        );
    }
};

const cargoEnvironment = (cargoTargetDirectory: string): NodeJS.ProcessEnv => {
    if ((process.env.CARGO_ENCODED_RUSTFLAGS?.length ?? 0) > 0) {
        throw new Error(
            'CARGO_ENCODED_RUSTFLAGS must be unset for the deterministic WASM build.',
        );
    }
    const cargoHome = path.resolve(
        process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'),
    );
    return {
        ...process.env,
        CARGO_ENCODED_RUSTFLAGS: [
            '--remap-path-prefix',
            `${repositoryRoot}=/workspace`,
            '--remap-path-prefix',
            `${cargoHome}=/cargo`,
            '-C',
            `link-arg=--max-memory=${maximumFoundationWasmMemoryByteLength}`,
            '-C',
            'link-arg=-z',
            '-C',
            `link-arg=stack-size=${stackByteLength}`,
            '-C',
            'link-arg=--stack-first',
        ].join(rustflagSeparator),
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR: cargoTargetDirectory,
        SOURCE_DATE_EPOCH: '0',
    };
};

export type WasmKernelBuildOptions = Readonly<{
    includeConstruction?: boolean;
    outputFilePath?: string;
}>;

export const buildWasmKernel = async (
    options: WasmKernelBuildOptions = {},
): Promise<Readonly<{ hash: string; outputFilePath: string }>> => {
    const includeConstruction = options.includeConstruction ?? true;
    const outputFilePath = options.outputFilePath ?? defaultOutputFilePath;
    const variantName = includeConstruction
        ? 'construction'
        : 'foundation-only';
    const cargoTargetDirectory = path.join(
        repositoryRoot,
        'target',
        `wasm-kernel-${variantName}`,
    );
    const scratchRoot = path.join(
        repositoryRoot,
        'temp',
        'build-scratch',
        'wasm-kernel-builds',
        variantName,
    );
    await Promise.all([
        mkdir(path.dirname(outputFilePath), { recursive: true }),
        mkdir(scratchRoot, { recursive: true }),
    ]);
    const scratchDirectory = await mkdtemp(path.join(scratchRoot, 'build-'));
    const unoptimizedFilePath = path.join(
        scratchDirectory,
        'kernel.unoptimized.wasm',
    );
    const optimizedFilePath = path.join(scratchDirectory, 'kernel.wasm');

    try {
        const cargoArguments = [
            'build',
            '--locked',
            '--package',
            'sealed-lattice-kernel',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
            '--release',
        ];
        if (!includeConstruction) cargoArguments.push('--no-default-features');
        run('cargo', cargoArguments, cargoEnvironment(cargoTargetDirectory));
        await copyFile(
            path.join(
                cargoTargetDirectory,
                'wasm32-unknown-unknown',
                'release',
                'sealed_lattice_kernel.wasm',
            ),
            unoptimizedFilePath,
        );
        run(process.execPath, [
            optimizerPath,
            '-O3',
            unoptimizedFilePath,
            '-o',
            optimizedFilePath,
        ]);
        const hash = createHash('sha256')
            .update(await readFile(optimizedFilePath))
            .digest('hex');
        await rename(optimizedFilePath, outputFilePath);
        console.log(
            `${includeConstruction ? 'Internal construction' : 'Public foundation-only'} kernel built at ${path.relative(repositoryRoot, outputFilePath)} (${hash}); deterministic WASM stack ${stackByteLength} bytes.`,
        );
        return { hash, outputFilePath };
    } finally {
        await rm(scratchDirectory, { recursive: true, force: true });
    }
};

if (import.meta.main) await buildWasmKernel();
