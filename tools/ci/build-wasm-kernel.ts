import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner,
    normalizeTranscriptCoreKernelBytesForDigest,
    type TranscriptCoreKernelBuildRunner,
} from '../../packages/wasm/src/transcript-core-bridge.js';
import { isWithinDirectory } from '../internal/files.js';

const repoRoot = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const cargoTargetDirectory = path.resolve(repoRoot, 'target');
const encodedRustflagSeparator = '\x1f';
const currentTranscriptCoreKernelBuildRunners = [
    'windowsDeveloperBuild',
    'githubActionsUbuntuLatest',
    'githubActionsMacosLatest',
] as const satisfies readonly TranscriptCoreKernelBuildRunner[];
const currentTranscriptCoreKernelNormalizedSha256HexValues = new Set<string>(
    currentTranscriptCoreKernelBuildRunners.map(
        (buildRunner) =>
            currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner[
                buildRunner
            ],
    ),
);

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

const formatCurrentKernelDigestManifest = (): string =>
    currentTranscriptCoreKernelBuildRunners
        .map(
            (buildRunner) =>
                `${buildRunner}=${currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner[buildRunner]}`,
        )
        .join(', ');

const verifyKernelDigest = async (outputFilePath: string): Promise<string> => {
    const actualSha256Hex = await hashFileSha256Hex(outputFilePath);
    if (
        !currentTranscriptCoreKernelNormalizedSha256HexValues.has(
            actualSha256Hex,
        )
    ) {
        throw new Error(
            [
                'Transcript-core WASM normalized digest mismatch.',
                `Expected one current-kernel digest from ${formatCurrentKernelDigestManifest()}.`,
                `Received ${actualSha256Hex}.`,
                'Update currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner in packages/wasm/src/transcript-core-bridge.ts after reviewing the kernel change.',
            ].join(' '),
        );
    }

    return actualSha256Hex;
};

export const buildWasmKernel = async (): Promise<void> => {
    const outputFilePath = resolveOutputFilePath(process.argv.slice(2));
    const outputDirectory = path.dirname(outputFilePath);

    runCargoBuild();
    await mkdir(outputDirectory, { recursive: true });
    await copyFile(resolveSourceFilePath(), outputFilePath);
    const sha256Hex = await verifyKernelDigest(outputFilePath);

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
