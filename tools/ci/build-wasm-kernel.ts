import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { isWithinDirectory } from '../internal/files.js';

import { normalizeTranscriptCoreKernelBytesForDigest } from '#packages/wasm/src/transcript-core-bridge.js';

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
const sdkKernelDigestAssignmentPattern =
    /const packagedTranscriptCoreKernelNormalizedSha256Hex =\s*(?:undefined|'[a-f0-9]{64}');/u;
const sha256HexPattern = /^[a-f0-9]{64}$/u;

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
    ];
    const result = spawnSync(
        'cargo',
        [
            'build',
            '--package',
            'sealed-lattice-kernel',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
            '--release',
        ],
        {
            cwd: repoRoot,
            env: {
                ...process.env,
                CARGO_ENCODED_RUSTFLAGS: deterministicRustflags.join(
                    encodedRustflagSeparator,
                ),
                CARGO_TARGET_DIR: cargoTargetDirectory,
            },
            encoding: 'utf8',
            maxBuffer: 100 * 1024 * 1024,
        },
    );

    if (result.error !== undefined) {
        throw new Error(`Failed to start cargo build: ${result.error.message}`);
    }
    if (result.signal !== null) {
        throw new Error(`cargo build terminated by signal ${result.signal}`);
    }
    if (result.status !== 0) {
        const stdout = result.stdout?.trim();
        const stderr = result.stderr?.trim();
        const formattedOutput =
            stdout !== '' || stderr !== ''
                ? `\n${[stdout, stderr].filter(Boolean).join('\n')}`
                : '';

        throw new Error(
            `cargo build exited with status ${result.status ?? 'null'}${formattedOutput}`,
        );
    }
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
        .update(normalizeTranscriptCoreKernelBytesForDigest(bytes))
        .digest('hex');
};

export const pinSdkKernelDigestInLoaderSource = (
    sourceText: string,
    sha256Hex: string,
): string => {
    if (!sha256HexPattern.test(sha256Hex)) {
        throw new Error(
            `Cannot pin an invalid transcript-core kernel digest: ${sha256Hex}`,
        );
    }

    const replacement = `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${sha256Hex}';`;
    const pinnedSourceText = sourceText.replace(
        sdkKernelDigestAssignmentPattern,
        replacement,
    );

    if (pinnedSourceText === sourceText) {
        throw new Error(
            'Cannot pin the transcript-core kernel digest because packages/sdk/dist/kernel.js does not contain the expected digest assignment.',
        );
    }

    return pinnedSourceText;
};

const pinSdkKernelDigestIfNeeded = async (
    outputFilePath: string,
    sha256Hex: string,
): Promise<void> => {
    if (path.resolve(outputFilePath) !== sdkKernelOutputFilePath) {
        return;
    }

    const sourceText = await readFile(sdkKernelLoaderFilePath, 'utf8');
    await writeFile(
        sdkKernelLoaderFilePath,
        pinSdkKernelDigestInLoaderSource(sourceText, sha256Hex),
        'utf8',
    );
};

export const buildWasmKernel = async (): Promise<void> => {
    const outputFilePath = resolveOutputFilePath(process.argv.slice(2));
    const outputDirectory = path.dirname(outputFilePath);

    runCargoBuild();
    await mkdir(outputDirectory, { recursive: true });
    await copyFile(resolveSourceFilePath(), outputFilePath);
    const sha256Hex = await hashFileSha256Hex(outputFilePath);
    await pinSdkKernelDigestIfNeeded(outputFilePath, sha256Hex);

    console.log(
        `transcript-core kernel copied to ${path.relative(repoRoot, outputFilePath)} (${sha256Hex})`,
    );
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void buildWasmKernel();
}
