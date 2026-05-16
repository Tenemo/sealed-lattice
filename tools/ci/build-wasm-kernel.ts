import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { normalizeTranscriptCoreKernelBytesForDigest } from '../../packages/wasm/src/transcript-core-bridge.js';
import { isWithinDirectory } from '../internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const cargoTargetDirectory = path.resolve(repoRoot, 'target');
const bridgeSourcePath = path.resolve(
    repoRoot,
    'packages',
    'wasm',
    'src',
    'transcript-core-bridge.ts',
);
const expectedKernelDigestPattern =
    /const transcriptCoreKernelNormalizedSha256Hex =\s*['"]([a-f0-9]{64})['"]/u;

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

const readExpectedKernelSha256Hex = async (): Promise<string> => {
    const sourceText = await readFile(bridgeSourcePath, 'utf8');
    const match = expectedKernelDigestPattern.exec(sourceText);
    if (match?.[1] === undefined) {
        throw new Error(
            'Could not find transcriptCoreKernelSha256Hex in the WASM bridge source.',
        );
    }

    return match[1];
};

const verifyKernelDigest = async (outputFilePath: string): Promise<string> => {
    const [actualSha256Hex, expectedSha256Hex] = await Promise.all([
        hashFileSha256Hex(outputFilePath),
        readExpectedKernelSha256Hex(),
    ]);
    if (actualSha256Hex !== expectedSha256Hex) {
        throw new Error(
            [
                'Transcript-core WASM normalized digest mismatch.',
                `Expected ${expectedSha256Hex}.`,
                `Received ${actualSha256Hex}.`,
                'Update transcriptCoreKernelNormalizedSha256Hex in packages/wasm/src/transcript-core-bridge.ts after reviewing the kernel change.',
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
