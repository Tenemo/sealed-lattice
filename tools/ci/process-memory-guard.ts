import os from 'node:os';
import path from 'node:path';

import type { CommandInvocation } from './run-command.js';

const bytesPerGigabyte = 1024 ** 3;
const defaultHardMemoryLimitGigabytes = 32;
const maximumHostMemoryFraction = 0.7;
const reservedHostMemoryGigabytes = 2;

export type ProcessMemoryGuard = Readonly<{
    buildVerificationCommand: () => CommandInvocation;
    guardCommand: (
        command: CommandInvocation,
        memoryLimitBytes?: number,
    ) => CommandInvocation;
    memoryLimitBytes: number;
    memoryLimitGigabytes: number;
}>;

// Thirty-two GiB is the workstation ceiling. Smaller hosts receive a lower
// ceiling, and every host retains at least two GiB of currently free memory for
// the runner and operating system. This is a hard OS limit, not a scheduling
// estimate.
export const deriveProcessMemoryLimitGigabytes = (input: {
    readonly freeMemoryGigabytes: number;
    readonly insufficientFreeMemoryRunDescription: string;
    readonly totalMemoryGigabytes: number;
}): number => {
    if (
        !Number.isFinite(input.totalMemoryGigabytes) ||
        input.totalMemoryGigabytes <= 0 ||
        !Number.isFinite(input.freeMemoryGigabytes) ||
        input.freeMemoryGigabytes <= 0
    ) {
        throw new Error('Host memory values must be positive finite numbers.');
    }
    const freeMemoryAfterReserve = Math.floor(
        input.freeMemoryGigabytes - reservedHostMemoryGigabytes,
    );
    if (freeMemoryAfterReserve < 1) {
        throw new Error(
            `${input.insufficientFreeMemoryRunDescription} require at least ${reservedHostMemoryGigabytes + 1} GiB of free host memory.`,
        );
    }

    return Math.min(
        defaultHardMemoryLimitGigabytes,
        Math.max(
            1,
            Math.floor(input.totalMemoryGigabytes * maximumHostMemoryFraction),
        ),
        freeMemoryAfterReserve,
    );
};

export const resolveProcessMemoryLimitGigabytes = (input: {
    readonly automaticLimitGigabytes: number;
    readonly environment?: NodeJS.ProcessEnv;
    readonly memoryLimitEnvironmentVariable?: string;
}): number => {
    if (input.memoryLimitEnvironmentVariable === undefined) {
        return input.automaticLimitGigabytes;
    }

    const override = (input.environment ?? process.env)[
        input.memoryLimitEnvironmentVariable
    ];
    if (override === undefined) {
        return input.automaticLimitGigabytes;
    }
    if (!/^[1-9][0-9]*$/u.test(override)) {
        throw new Error(
            `${input.memoryLimitEnvironmentVariable} must be a positive integer.`,
        );
    }
    const overrideGigabytes = Number.parseInt(override, 10);
    if (overrideGigabytes > input.automaticLimitGigabytes) {
        throw new Error(
            `${input.memoryLimitEnvironmentVariable} cannot exceed the automatic safe ceiling of ${input.automaticLimitGigabytes} GiB.`,
        );
    }

    return overrideGigabytes;
};

export const createProcessMemoryGuard = (input: {
    readonly insufficientFreeMemoryRunDescription: string;
    readonly memoryLimitEnvironmentVariable?: string;
}): ProcessMemoryGuard => {
    const automaticMemoryLimitGigabytes = deriveProcessMemoryLimitGigabytes({
        freeMemoryGigabytes: os.freemem() / bytesPerGigabyte,
        insufficientFreeMemoryRunDescription:
            input.insufficientFreeMemoryRunDescription,
        totalMemoryGigabytes: os.totalmem() / bytesPerGigabyte,
    });
    const memoryLimitGigabytes = resolveProcessMemoryLimitGigabytes({
        automaticLimitGigabytes: automaticMemoryLimitGigabytes,
        memoryLimitEnvironmentVariable: input.memoryLimitEnvironmentVariable,
    });
    const memoryLimitBytes = memoryLimitGigabytes * bytesPerGigabyte;
    const processMemoryGuardTargetDirectory = path.resolve(
        process.cwd(),
        'target',
        'process-memory-guard',
    );
    const processMemoryGuardExecutablePath = path.join(
        processMemoryGuardTargetDirectory,
        'debug',
        process.platform === 'win32'
            ? 'sealed-lattice-process-memory-guard.exe'
            : 'sealed-lattice-process-memory-guard',
    );

    return {
        buildVerificationCommand: (): CommandInvocation => {
            const environment = { ...process.env };
            delete environment.CARGO_TARGET_DIR;

            return {
                args: [
                    'test',
                    '--locked',
                    '-p',
                    'sealed-lattice-process-memory-guard',
                    '--target-dir',
                    processMemoryGuardTargetDirectory,
                ],
                command: 'cargo',
                description: 'verify process memory guard',
                env: environment,
                logFileSlug: 'cargo-test-process-memory-guard',
            };
        },
        guardCommand: (
            command: CommandInvocation,
            commandMemoryLimitBytes = memoryLimitBytes,
        ): CommandInvocation => ({
            ...command,
            args: [
                '--memory-limit-bytes',
                String(commandMemoryLimitBytes),
                '--',
                command.command,
                ...command.args,
            ],
            command: processMemoryGuardExecutablePath,
        }),
        memoryLimitBytes,
        memoryLimitGigabytes,
    };
};
