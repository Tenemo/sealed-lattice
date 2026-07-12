import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';
import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { isWithinDirectory } from '#tools/internal/files.js';
import { foundationProfile } from '@sealed-lattice/types';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const cargoTargetDirectory = path.resolve(repoRoot, 'target');
const encodedRustflagSeparator = '\x1f';
const sdkKernelOutputFilePath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const sdkKernelLoaderFilePath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'dist',
    'kernel.js',
);
const kernelHashAssignmentPattern =
    /const packagedTranscriptCoreKernelNormalizedSha256Hex(?:\s*:\s*string\s*\|\s*undefined)?\s*=\s*(?:undefined|'[a-f0-9]{64}');/u;
const sha256HexPattern = /^[a-f0-9]{64}$/u;
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

export const resolveOutputFilePath = (
    commandLineArguments: readonly string[],
    projectRoot: string = repoRoot,
): string => {
    const outputIndex = commandLineArguments.indexOf('--out');
    const outputPath =
        outputIndex === -1
            ? path.join(
                  'packages',
                  'wasm',
                  'dist',
                  'sealed-lattice-kernel.wasm',
              )
            : commandLineArguments[outputIndex + 1];

    if (outputPath === undefined) {
        throw new Error('--out requires a repository-relative output path');
    }
    if (path.isAbsolute(outputPath)) {
        throw new Error('--out must be repository-relative');
    }

    const resolvedOutputPath = path.resolve(projectRoot, outputPath);
    if (!isWithinDirectory(projectRoot, resolvedOutputPath)) {
        throw new Error('--out must resolve inside the repository');
    }

    return resolvedOutputPath;
};

const runCargoBuild = (): void => {
    const cargoHome = path.resolve(
        process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'),
    );
    const existingEncodedRustflags =
        process.env.CARGO_ENCODED_RUSTFLAGS?.split(
            encodedRustflagSeparator,
        ).filter(Boolean) ?? [];
    const deterministicRustflags = [
        ...existingEncodedRustflags,
        '--remap-path-prefix',
        `${repoRoot}=/workspace`,
        '--remap-path-prefix',
        `${cargoHome}=/cargo`,
        '-C',
        `link-arg=--max-memory=${foundationProfile.maximumWasmMemoryByteLength}`,
    ];
    runCheckedCommand({
        command: 'cargo',
        args: [
            'build',
            '--package',
            'sealed-lattice-kernel',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
            '--release',
        ],
        description: 'cargo build',
        env: {
            ...process.env,
            CARGO_ENCODED_RUSTFLAGS: deterministicRustflags.join(
                encodedRustflagSeparator,
            ),
            CARGO_TARGET_DIR: cargoTargetDirectory,
        },
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

const resolveSourceFilePath = (): string =>
    path.resolve(
        cargoTargetDirectory,
        'wasm32-unknown-unknown',
        'release',
        'sealed_lattice_kernel.wasm',
    );

const hashFileSha256Hex = async (filePath: string): Promise<string> => {
    const bytes = await readFile(filePath);

    return createHash('sha256')
        .update(normalizeTranscriptCoreKernelBytesForHash(bytes))
        .digest('hex');
};

export const pinKernelHashInLoaderSource = (
    sourceText: string,
    sha256Hex: string,
): string => {
    if (!sha256HexPattern.test(sha256Hex)) {
        throw new Error(
            `Cannot pin an invalid transcript-core kernel hash: ${sha256Hex}`,
        );
    }

    const replacement = [
        'const packagedTranscriptCoreKernelNormalizedSha256Hex =',
        `    '${sha256Hex}';`,
    ].join('\n');
    let assignmentFound = false;
    const pinnedSourceText = sourceText.replace(
        kernelHashAssignmentPattern,
        () => {
            assignmentFound = true;

            return replacement;
        },
    );

    if (!assignmentFound) {
        throw new Error(
            'Cannot pin the transcript-core kernel hash because the loader file does not contain the expected hash assignment.',
        );
    }

    return pinnedSourceText;
};

const writePinnedKernelHashIfChanged = async (
    loaderFilePath: string,
    sha256Hex: string,
): Promise<void> => {
    const sourceText = await readFile(loaderFilePath, 'utf8');
    const pinnedSourceText = pinKernelHashInLoaderSource(sourceText, sha256Hex);

    if (pinnedSourceText === sourceText) {
        return;
    }

    await writeFile(loaderFilePath, pinnedSourceText, 'utf8');
};

const pinSdkKernelHashIfNeeded = async (
    outputFilePath: string,
    sha256Hex: string,
): Promise<void> => {
    if (path.resolve(outputFilePath) !== sdkKernelOutputFilePath) {
        return;
    }

    await writePinnedKernelHashIfChanged(sdkKernelLoaderFilePath, sha256Hex);
};

export const buildWasmKernel = async (): Promise<void> => {
    const outputFilePath = resolveOutputFilePath(process.argv.slice(2));
    const outputDirectory = path.dirname(outputFilePath);
    const unoptimizedOutputFilePath = path.join(
        outputDirectory,
        `${path.basename(outputFilePath)}.unoptimized`,
    );

    runCargoBuild();
    await mkdir(outputDirectory, { recursive: true });
    await copyFile(resolveSourceFilePath(), unoptimizedOutputFilePath);
    try {
        runWasmOptimizer(unoptimizedOutputFilePath, outputFilePath);
    } finally {
        await rm(unoptimizedOutputFilePath, { force: true });
    }
    const sha256Hex = await hashFileSha256Hex(outputFilePath);
    await pinSdkKernelHashIfNeeded(outputFilePath, sha256Hex);

    console.log(
        `transcript-core kernel copied to ${path.relative(repoRoot, outputFilePath)} (${sha256Hex})`,
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void buildWasmKernel();
}
