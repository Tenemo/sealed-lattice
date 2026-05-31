import path from 'node:path';

export type RunnerTarget = 'fast';
export type WorkerJob = 'bridge-contributor' | 'component-receiver';

export type RunnerConfig = {
    readonly checkpointDir: string;
    readonly forceRecompute: ReadonlySet<string>;
    readonly requireCheckpoints: boolean;
    readonly resumeCheckpoints: boolean;
    readonly selectedContributorCount: number | null;
    readonly target: RunnerTarget;
    readonly workers: number;
};

export type WorkerConfig = Omit<RunnerConfig, 'forceRecompute'> & {
    readonly dependencyArtifactHash: string;
    readonly forceRecompute: readonly string[];
    readonly kernelHash: string;
    readonly receiver: number;
    readonly runConfigPath: string;
    readonly sourceFingerprint: string;
    readonly workerJob: WorkerJob;
    readonly workerOutputPath: string;
};

export const usageText = `Usage:
  pnpm run test:aggregate-derivation-kernel
  pnpm run test:aggregate-derivation-kernel -- --workers 4
  pnpm run test:aggregate-derivation-kernel -- --workers 8 --force-recompute bridge-contributors

Flags:
  --workers <count> (default: 8)
  --checkpoint-dir <path>
  --force-recompute ballot-package|bridge-contributors|bgv-passive-setup

This runner has one mode only: fast representative aggregate/bridge readiness.
It always tries valid checkpoints first, ignores stale or corrupt checkpoints,
and recomputes the affected stage.
`;

const argumentValues = (
    argumentsList: readonly string[],
    flag: string,
): readonly string[] => {
    const values: string[] = [];
    for (let index = 0; index < argumentsList.length; index += 1) {
        if (argumentsList[index] !== flag) {
            continue;
        }
        const value = argumentsList[index + 1];
        if (value === undefined || value.startsWith('--')) {
            throw new Error(`Missing value for ${flag}.`);
        }
        values.push(value);
        index += 1;
    }

    return values;
};

const argumentValue = (
    argumentsList: readonly string[],
    flag: string,
): string | null => argumentValues(argumentsList, flag)[0] ?? null;

const removePackageManagerSeparator = (
    argumentsList: readonly string[],
): readonly string[] => argumentsList.filter((argument) => argument !== '--');

const parsePositiveIntegerFlag = (
    argumentsList: readonly string[],
    flag: string,
    fallback: number,
): number => {
    const rawValue = argumentValue(argumentsList, flag);
    if (rawValue === null) {
        return fallback;
    }
    const value = Number(rawValue);
    if (!Number.isInteger(value) || value < 1) {
        throw new Error(`${flag} must be a positive integer.`);
    }

    return value;
};

export const parseRunnerConfig = (
    rawArguments: readonly string[],
): RunnerConfig | WorkerConfig => {
    const argumentsList = removePackageManagerSeparator(rawArguments);
    const workerJob = argumentValue(argumentsList, '--worker-job');
    const target: RunnerTarget = 'fast';
    const workers = parsePositiveIntegerFlag(argumentsList, '--workers', 8);
    const checkpointDir = path.resolve(
        process.cwd(),
        argumentValue(argumentsList, '--checkpoint-dir') ??
            path.join('temp', 'test-checkpoints'),
    );
    const forceRecompute = argumentValues(argumentsList, '--force-recompute');
    const resumeCheckpoints = true;
    const requireCheckpoints = false;
    const selectedContributorCount = null;
    if (workerJob !== null) {
        if (
            workerJob !== 'bridge-contributor' &&
            workerJob !== 'component-receiver'
        ) {
            throw new Error(`Unsupported worker job: ${workerJob}`);
        }
        const runConfigPath = argumentValue(argumentsList, '--run-config');
        const workerOutputPath = argumentValue(
            argumentsList,
            '--worker-output',
        );
        if (runConfigPath === null || workerOutputPath === null) {
            throw new Error(
                'Worker jobs require --run-config and --worker-output.',
            );
        }

        return {
            checkpointDir,
            dependencyArtifactHash: '',
            forceRecompute,
            kernelHash: '',
            receiver: parsePositiveIntegerFlag(argumentsList, '--receiver', 1),
            requireCheckpoints,
            resumeCheckpoints,
            runConfigPath,
            selectedContributorCount,
            sourceFingerprint: '',
            target,
            workerJob,
            workerOutputPath,
            workers,
        };
    }

    return {
        checkpointDir,
        forceRecompute: new Set(forceRecompute),
        requireCheckpoints,
        resumeCheckpoints,
        selectedContributorCount,
        target,
        workers,
    };
};
