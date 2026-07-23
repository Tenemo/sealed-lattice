import { randomUUID } from 'node:crypto';
import { access, link, mkdir, open, unlink } from 'node:fs/promises';
import path from 'node:path';

import type { CommandInvocation } from './run-command.js';

const cargoFeatureName = 'proof-backend-bakeoff';
const cargoPackageName = 'sealed-lattice-kernel';
const backendEnvironmentVariable =
    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND';
const sampleOrdinalEnvironmentVariable =
    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL';
const resultPathEnvironmentVariable =
    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH';

const buildCargoArguments = (): readonly string[] => [
    'test',
    '--locked',
    '--release',
    '-p',
    cargoPackageName,
    '--features',
    cargoFeatureName,
    '--lib',
];

export const buildProofBackendBakeoffEnvironment = (
    input: {
        readonly baseEnvironment?: NodeJS.ProcessEnv;
        readonly targetDirectoryPath?: string;
    } = {},
): NodeJS.ProcessEnv => {
    const environment: NodeJS.ProcessEnv = {
        ...(input.baseEnvironment ?? process.env),
        CARGO_BUILD_JOBS: '1',
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR:
            input.targetDirectoryPath ??
            path.resolve(process.cwd(), 'target', 'proof-backend-bakeoff'),
        RAYON_NUM_THREADS: '1',
        RUST_BACKTRACE: 'full',
        RUST_TEST_THREADS: '1',
    };
    delete environment[backendEnvironmentVariable];
    delete environment[sampleOrdinalEnvironmentVariable];
    delete environment[resultPathEnvironmentVariable];
    delete environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS;
    delete environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT;
    return environment;
};

export const buildProofBackendBakeoffPrecompileCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [...buildCargoArguments(), '--no-run'],
    command: 'cargo',
    description: 'precompile the release proof backend bakeoff fragment',
    env: environment,
    logFileSlug: 'cargo-precompile-proof-backend-bakeoff',
});

const requirePathDoesNotExist = async (filePath: string): Promise<void> => {
    try {
        await access(filePath);
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return;
        }
        throw error;
    }
    throw new Error(`Refusing to overwrite bakeoff evidence: ${filePath}.`);
};

export const writeJsonAtomicallyAndExclusively = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await mkdir(path.dirname(filePath), { recursive: true });
    await requirePathDoesNotExist(filePath);
    const temporaryPath = path.join(
        path.dirname(filePath),
        `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`,
    );
    const fileHandle = await open(temporaryPath, 'wx');
    let temporaryFileExists = true;
    try {
        await fileHandle.writeFile(`${JSON.stringify(value, null, 2)}\n`, {
            encoding: 'utf8',
        });
        await fileHandle.sync();
        await fileHandle.close();
        await link(temporaryPath, filePath);
        await unlink(temporaryPath);
        temporaryFileExists = false;
    } finally {
        await fileHandle.close().catch(() => undefined);
        if (temporaryFileExists) {
            await unlink(temporaryPath).catch(() => undefined);
        }
    }
};

export const executeProofBackendBakeoffSequence = (
    input: unknown,
): Promise<never> => {
    void input;
    return Promise.reject(
        new Error(
            'The recorded proof backend bakeoff is immutable and must not be rerun. Use the proof-storage width evidence lane.',
        ),
    );
};

export const runProofBackendBakeoff = (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (effectiveArguments.length !== 0) {
        return Promise.reject(
            new Error('The proof backend bakeoff runner accepts no arguments.'),
        );
    }
    return Promise.reject(
        new Error(
            'The recorded proof backend bakeoff is immutable and must not be rerun. Use the proof-storage width evidence lane.',
        ),
    );
};

if (import.meta.main) {
    void runProofBackendBakeoff();
}
