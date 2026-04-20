import { spawnSync } from 'node:child_process';
import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const cargoTargetDirectory = path.resolve(repoRoot, 'target');
const outputDirectory = path.resolve(repoRoot, 'packages', 'wasm', 'dist');
const outputFilePath = path.resolve(
    outputDirectory,
    'sealed-lattice-kernel.wasm',
);

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

const main = async (): Promise<void> => {
    runCargoBuild();
    await mkdir(outputDirectory, { recursive: true });
    await copyFile(resolveSourceFilePath(), outputFilePath);

    console.log(
        `Byte-buffer kernel copied to ${path.relative(repoRoot, outputFilePath)}`,
    );
};

void main();
