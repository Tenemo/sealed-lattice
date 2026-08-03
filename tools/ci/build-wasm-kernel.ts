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
        `link-arg=--max-memory=${foundationProfile.maximumWasmMemoryByteLength}`,
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

export const createWasmCargoBuildArguments = (
    cargoFeatures: readonly string[] = [],
): readonly string[] => [
    'build',
    '--locked',
    '--package',
    'sealed-lattice-kernel',
    '--lib',
    '--target',
    'wasm32-unknown-unknown',
    '--release',
    ...(cargoFeatures.length === 0
        ? []
        : ['--features', cargoFeatures.join(',')]),
];

const runCargoBuild = (input: {
    readonly cargoFeatures: readonly string[];
    readonly environment: NodeJS.ProcessEnv;
    readonly targetDirectoryPath: string;
}): void => {
    runCheckedCommand({
        command: 'cargo',
        args: createWasmCargoBuildArguments(input.cargoFeatures),
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

const hashNormalizedWasmKernel = async (filePath: string): Promise<string> =>
    createHash('sha256')
        .update(
            normalizeTranscriptCoreKernelBytesForHash(await readFile(filePath)),
        )
        .digest('hex');

const readUnsignedLeb128 = (
    bytes: Uint8Array,
    startingOffset: number,
): { readonly nextOffset: number; readonly value: number } => {
    let offset = startingOffset;
    let value = 0;
    let shift = 0;
    while (offset < bytes.length && shift <= 28) {
        const byte = bytes[offset];
        if (byte === undefined) {
            break;
        }
        offset += 1;
        value |= (byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) {
            return { nextOffset: offset, value: value >>> 0 };
        }
        shift += 7;
    }
    throw new Error('WASM contains an invalid unsigned LEB128 value.');
};

const readSignedI32Leb128 = (
    bytes: Uint8Array,
    startingOffset: number,
): { readonly nextOffset: number; readonly value: number } => {
    let offset = startingOffset;
    let value = 0;
    let shift = 0;
    let byte: number;
    do {
        const nextByte = bytes[offset];
        if (nextByte === undefined || shift > 28) {
            throw new Error(
                'WASM contains an invalid signed i32 LEB128 value.',
            );
        }
        byte = nextByte;
        offset += 1;
        value |= (byte & 0x7f) << shift;
        shift += 7;
    } while ((byte & 0x80) !== 0);
    if (shift < 32 && (byte & 0x40) !== 0) {
        value |= ~0 << shift;
    }
    return { nextOffset: offset, value: value | 0 };
};

export const assertDeterministicWasmStackLayout = (bytes: Uint8Array): void => {
    const expectedHeader = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    if (
        bytes.length < expectedHeader.length ||
        expectedHeader.some((byte, index) => bytes[index] !== byte)
    ) {
        throw new Error(
            'WASM stack inspection received an invalid module header.',
        );
    }
    let module: WebAssembly.Module;
    try {
        const ownedModuleBytes = new Uint8Array(bytes.byteLength);
        ownedModuleBytes.set(bytes);
        module = new WebAssembly.Module(ownedModuleBytes.buffer);
    } catch (error) {
        throw Object.assign(
            new Error('WASM stack inspection received an invalid module.'),
            { cause: error },
        );
    }
    if (
        WebAssembly.Module.imports(module).some(
            (entry) => entry.kind === 'global',
        )
    ) {
        throw new Error(
            'WASM stack layout must not depend on imported globals.',
        );
    }

    let offset = expectedHeader.length;
    let mutableI32GlobalCount = 0;
    let configuredStackGlobalCount = 0;
    let observedGlobalSection = false;
    while (offset < bytes.length) {
        const sectionIdentifier = bytes[offset];
        if (sectionIdentifier === undefined) {
            throw new Error('WASM section identifier is truncated.');
        }
        offset += 1;
        const sectionLength = readUnsignedLeb128(bytes, offset);
        offset = sectionLength.nextOffset;
        const sectionEnd = offset + sectionLength.value;
        if (sectionEnd > bytes.length) {
            throw new Error('WASM section payload is truncated.');
        }
        if (sectionIdentifier !== 6) {
            offset = sectionEnd;
            continue;
        }
        if (observedGlobalSection) {
            throw new Error('WASM contains more than one global section.');
        }
        observedGlobalSection = true;
        const globalCount = readUnsignedLeb128(bytes, offset);
        offset = globalCount.nextOffset;
        for (
            let globalIndex = 0;
            globalIndex < globalCount.value;
            globalIndex += 1
        ) {
            const valueType = bytes[offset];
            const mutability = bytes[offset + 1];
            const initializerOpcode = bytes[offset + 2];
            if (
                valueType === undefined ||
                mutability === undefined ||
                initializerOpcode === undefined
            ) {
                throw new Error('WASM global declaration is truncated.');
            }
            offset += 3;
            if (valueType !== 0x7f || initializerOpcode !== 0x41) {
                throw new Error(
                    'WASM stack inspection requires i32 globals with i32.const initializers.',
                );
            }
            const initializer = readSignedI32Leb128(bytes, offset);
            offset = initializer.nextOffset;
            if (bytes[offset] !== 0x0b) {
                throw new Error(
                    'WASM global initializer is not terminated canonically.',
                );
            }
            offset += 1;
            if (mutability === 1) {
                mutableI32GlobalCount += 1;
                if (initializer.value === wasmStackByteLength) {
                    configuredStackGlobalCount += 1;
                }
            } else if (mutability !== 0) {
                throw new Error('WASM global has invalid mutability.');
            }
        }
        if (offset !== sectionEnd) {
            throw new Error('WASM global section contains trailing bytes.');
        }
    }
    if (
        !observedGlobalSection ||
        mutableI32GlobalCount !== 1 ||
        configuredStackGlobalCount !== 1
    ) {
        throw new Error(
            `WASM must contain exactly one mutable i32 stack global initialized to ${wasmStackByteLength}.`,
        );
    }
};

export type BuiltWasmKernelArtifact = Readonly<{
    normalizedSha256Hex: string;
    outputFilePath: string;
}>;

export const buildOptimizedWasmKernelArtifact = async (input: {
    readonly artifactLabel: string;
    readonly cargoFeatures?: readonly string[];
    readonly outputFilePath: string;
    readonly scratchDirectoryPrefix: string;
    readonly targetDirectoryPath: string;
}): Promise<BuiltWasmKernelArtifact> => {
    const cargoFeatures = input.cargoFeatures ?? [];
    if (
        cargoFeatures.some(
            (feature, featureIndex) =>
                !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(feature) ||
                cargoFeatures.indexOf(feature) !== featureIndex,
        )
    ) {
        throw new Error(
            'The deterministic WASM build requires unique kebab-case Cargo features.',
        );
    }
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
            cargoFeatures,
            environment: process.env,
            targetDirectoryPath: input.targetDirectoryPath,
        });
        await copyFile(
            cargoWasmOutputFilePath(input.targetDirectoryPath),
            unoptimizedOutputFilePath,
        );
        runWasmOptimizer(unoptimizedOutputFilePath, optimizedOutputFilePath);

        assertDeterministicWasmStackLayout(
            await readFile(optimizedOutputFilePath),
        );

        const normalizedSha256Hex = await hashNormalizedWasmKernel(
            optimizedOutputFilePath,
        );
        await rename(optimizedOutputFilePath, input.outputFilePath);

        console.log(
            `${input.artifactLabel} built at ${path.relative(repoRoot, input.outputFilePath)} (${normalizedSha256Hex}); deterministic WASM stack ${wasmStackByteLength} bytes.`,
        );
        return Object.freeze({
            normalizedSha256Hex,
            outputFilePath: input.outputFilePath,
        });
    } finally {
        await rm(scratchDirectoryPath, { force: true, recursive: true });
    }
};

export const buildWasmKernel = async (): Promise<void> => {
    await buildOptimizedWasmKernelArtifact({
        artifactLabel: 'Transcript-core kernel',
        outputFilePath: wasmOutputFilePath,
        scratchDirectoryPrefix: 'build-',
        targetDirectoryPath: cargoTargetDirectory,
    });
};

if (import.meta.main) {
    await buildWasmKernel();
}
