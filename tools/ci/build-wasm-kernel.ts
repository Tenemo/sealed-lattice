import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
    cp,
    copyFile,
    mkdir,
    mkdtemp,
    readFile,
    rename,
    rm,
    writeFile,
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
const kernelCratePath = path.join(
    repositoryRoot,
    'crates',
    'sealed-lattice-kernel',
);
const resourceScreenKernelSourcePath = path.join(
    repositoryRoot,
    'tools',
    'ci',
    'external-chrome-resource-screen-kernel.rs',
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

const cargoEnvironment = (
    cargoTargetDirectory: string,
    sourceWorkspacePath: string,
): NodeJS.ProcessEnv => {
    if ((process.env.CARGO_ENCODED_RUSTFLAGS?.length ?? 0) > 0) {
        throw new Error(
            'CARGO_ENCODED_RUSTFLAGS must be unset for the deterministic WASM build.',
        );
    }
    const cargoHome = path.resolve(
        process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'),
    );
    const encodedRustFlags = [
        '--remap-path-prefix',
        `${sourceWorkspacePath}=/workspace`,
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
    ];
    return {
        ...process.env,
        CARGO_ENCODED_RUSTFLAGS: encodedRustFlags.join(rustflagSeparator),
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR: cargoTargetDirectory,
        SOURCE_DATE_EPOCH: '0',
    };
};

const countOccurrences = (source: string, marker: string): number =>
    source.split(marker).length - 1;

const prepareResourceScreenWorkspace = async (
    scratchDirectory: string,
): Promise<string> => {
    const sourceWorkspacePath = path.join(
        scratchDirectory,
        'resource-screen-workspace',
    );
    const copiedKernelCratePath = path.join(
        sourceWorkspacePath,
        'crates',
        'sealed-lattice-kernel',
    );
    await mkdir(path.dirname(copiedKernelCratePath), { recursive: true });
    await Promise.all([
        copyFile(
            path.join(repositoryRoot, 'Cargo.toml'),
            path.join(sourceWorkspacePath, 'Cargo.toml'),
        ),
        copyFile(
            path.join(repositoryRoot, 'Cargo.lock'),
            path.join(sourceWorkspacePath, 'Cargo.lock'),
        ),
        cp(kernelCratePath, copiedKernelCratePath, { recursive: true }),
    ]);
    await copyFile(
        resourceScreenKernelSourcePath,
        path.join(copiedKernelCratePath, 'src', 'resource_screen.rs'),
    );

    const librarySourcePath = path.join(copiedKernelCratePath, 'src', 'lib.rs');
    const librarySource = await readFile(librarySourcePath, 'utf8');
    const lineEnding = librarySource.includes('\r\n') ? '\r\n' : '\n';
    const protocolModuleMarker = `#[cfg(feature = "construction")]${lineEnding}mod protocol;${lineEnding}`;
    if (countOccurrences(librarySource, protocolModuleMarker) !== 1) {
        throw new Error(
            'The resource-screen build could not locate the protocol module declaration.',
        );
    }
    await writeFile(
        librarySourcePath,
        librarySource.replace(
            protocolModuleMarker,
            `${protocolModuleMarker}mod resource_screen;${lineEnding}`,
        ),
        'utf8',
    );

    const paddedContinuationSourcePath = path.join(
        copiedKernelCratePath,
        'src',
        'protocol',
        'padded_continuation.rs',
    );
    const paddedContinuationSource = await readFile(
        paddedContinuationSourcePath,
        'utf8',
    );
    const paddedKmacMarker =
        'fn padded_kmac256<const LENGTH: usize>(key: &[u8], message: &[u8]) -> [u8; LENGTH] {';
    if (countOccurrences(paddedContinuationSource, paddedKmacMarker) !== 1) {
        throw new Error(
            'The resource-screen build could not locate the production padded KMAC function.',
        );
    }
    await writeFile(
        paddedContinuationSourcePath,
        paddedContinuationSource.replace(
            paddedKmacMarker,
            `pub(crate) ${paddedKmacMarker}`,
        ),
        'utf8',
    );
    return sourceWorkspacePath;
};

export type WasmKernelBuildOptions = Readonly<{
    includeConstruction?: boolean;
    outputFilePath?: string;
    resourceScreen?: boolean;
}>;

export const buildWasmKernel = async (
    options: WasmKernelBuildOptions = {},
): Promise<Readonly<{ hash: string; outputFilePath: string }>> => {
    const includeConstruction = options.includeConstruction ?? true;
    const resourceScreen = options.resourceScreen ?? false;
    if (resourceScreen && !includeConstruction) {
        throw new Error(
            'The resource-screen kernel requires the construction feature.',
        );
    }
    const outputFilePath = options.outputFilePath ?? defaultOutputFilePath;
    const variantName = resourceScreen
        ? 'resource-screen'
        : includeConstruction
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
        const sourceWorkspacePath = resourceScreen
            ? await prepareResourceScreenWorkspace(scratchDirectory)
            : repositoryRoot;
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
        if (resourceScreen) {
            cargoArguments.push(
                '--manifest-path',
                path.join(sourceWorkspacePath, 'Cargo.toml'),
            );
        }
        run(
            'cargo',
            cargoArguments,
            cargoEnvironment(cargoTargetDirectory, sourceWorkspacePath),
        );
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
