type ErrorDiagnostic = {
    readonly cause?: ErrorDiagnostic;
    readonly code?: string | number;
    readonly message: string;
    readonly name: string;
    readonly stack?: string;
};

type NormalizedProcessStatus = {
    readonly conventionalShellSignal?: {
        readonly evidence: 'inferred-from-shell-convention';
        readonly signalName?: NodeJS.Signals;
        readonly signalNumber: number;
    };
    readonly hexadecimalExitCode?: string;
    readonly rawExitCode: number | null;
    readonly signedExitCode?: number;
    readonly symbolicStatus?: string;
    readonly terminationSignal: NodeJS.Signals | null;
    readonly unsignedExitCode?: number;
};

const allowedEnvironmentVariableNames = [
    'CARGO_BUILD_JOBS',
    'CARGO_INCREMENTAL',
    'CARGO_TARGET_DIR',
    'CI',
    'GITHUB_ACTION',
    'GITHUB_ACTIONS',
    'GITHUB_JOB',
    'GITHUB_REF',
    'GITHUB_REF_NAME',
    'GITHUB_REPOSITORY',
    'GITHUB_RUN_ATTEMPT',
    'GITHUB_RUN_ID',
    'GITHUB_RUN_NUMBER',
    'GITHUB_SHA',
    'NODE_OPTIONS',
    'RAYON_NUM_THREADS',
    'RUST_BACKTRACE',
    'RUST_TEST_THREADS',
    'SEALED_LATTICE_PROCESS_MEMORY_LIMIT_BYTES',
    'SEALED_LATTICE_RUN_DIRECTORY',
    'SEALED_LATTICE_ACCEPTED_SETUP_MEMORY_LIMIT_GIB',
    'SEALED_LATTICE_RESUME_TEST_CHECKPOINTS',
    'SEALED_LATTICE_TEST_ATTACHMENT_DIRECTORY',
    'SEALED_LATTICE_TEST_CHECKPOINT_ROOT',
    'SEALED_LATTICE_TEST_DIAGNOSTIC_REPORT_DIRECTORY',
    'SEALED_LATTICE_TEST_EVENT_FILE',
    'SEALED_LATTICE_TEST_PROJECT_LABEL',
    'SEALED_LATTICE_TEST_RESULT_FILE',
    'SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE',
    'VITEST_MAX_THREADS',
    'VITEST_MIN_THREADS',
] as const;

const knownWindowsStatuses: Readonly<Record<number, string>> = {
    0x8000_0003: 'STATUS_BREAKPOINT',
    0xc000_0005: 'STATUS_ACCESS_VIOLATION',
    0xc000_0008: 'STATUS_INVALID_HANDLE',
    0xc000_0017: 'STATUS_NO_MEMORY',
    0xc000_00fd: 'STATUS_STACK_OVERFLOW',
    0xc000_0135: 'STATUS_DLL_NOT_FOUND',
    0xc000_0139: 'STATUS_ENTRYPOINT_NOT_FOUND',
    0xc000_013a: 'CONTROL_C_EXIT',
    0xc000_0142: 'STATUS_DLL_INIT_FAILED',
    0xc000_0374: 'STATUS_HEAP_CORRUPTION',
    0xc000_0409: 'STATUS_STACK_BUFFER_OVERRUN',
    0xc000_0602: 'STATUS_FAIL_FAST_EXCEPTION',
};

const conventionalPosixSignalNames: Readonly<
    Partial<Record<number, NodeJS.Signals>>
> = {
    1: 'SIGHUP',
    2: 'SIGINT',
    3: 'SIGQUIT',
    4: 'SIGILL',
    5: 'SIGTRAP',
    6: 'SIGABRT',
    7: 'SIGBUS',
    8: 'SIGFPE',
    9: 'SIGKILL',
    10: 'SIGUSR1',
    11: 'SIGSEGV',
    12: 'SIGUSR2',
    13: 'SIGPIPE',
    14: 'SIGALRM',
    15: 'SIGTERM',
    24: 'SIGXCPU',
    25: 'SIGXFSZ',
};

const sensitiveArgumentNamePattern =
    /(?:auth|authorization|cookie|credential|password|private[-_]?key|secret|token)$/iu;
const sensitiveAssignmentPattern =
    /^(?<prefix>--?(?:auth|authorization|cookie|credential|password|private[-_]?key|secret|token)|(?:auth|authorization|cookie|credential|password|private[-_]?key|secret|token))=(?<value>.*)$/iu;
const bearerTokenPattern = /\bBearer\s+[^\s"']+/giu;
const sensitiveTextAssignmentPattern =
    /\b(auth|authorization|cookie|credential|password|private[-_]?key|secret|token)\s*[:=]\s*([^\s,;]+)/giu;
const urlCredentialsPattern = /([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/giu;

export const redactDiagnosticText = (value: string): string =>
    value
        .replace(urlCredentialsPattern, '$1[redacted]@')
        .replace(bearerTokenPattern, 'Bearer [redacted]')
        .replace(
            sensitiveTextAssignmentPattern,
            (_match, name: string) => `${name}=[redacted]`,
        );

export const redactCommandLineArguments = (
    commandLineArguments: readonly string[],
): readonly string[] => {
    let redactNextArgument = false;

    return commandLineArguments.map((argument) => {
        if (redactNextArgument) {
            redactNextArgument = false;

            return '[redacted]';
        }

        const assignment = sensitiveAssignmentPattern.exec(argument);
        if (assignment?.groups?.prefix !== undefined) {
            return `${assignment.groups.prefix}=[redacted]`;
        }

        const normalizedArgumentName = argument.replace(/^-+/u, '');
        if (sensitiveArgumentNamePattern.test(normalizedArgumentName)) {
            redactNextArgument = true;

            return argument;
        }

        return redactDiagnosticText(argument);
    });
};

export const selectDiagnosticEnvironment = (
    environment: NodeJS.ProcessEnv,
): Readonly<Record<string, string>> =>
    Object.fromEntries(
        allowedEnvironmentVariableNames.flatMap((name) => {
            const value = environment[name];

            return value === undefined
                ? []
                : [[name, redactDiagnosticText(value)]];
        }),
    );

export const serializeErrorDiagnostic = (
    error: unknown,
    depth = 0,
): ErrorDiagnostic => {
    if (typeof error !== 'object' || error === null) {
        return {
            message: redactDiagnosticText(String(error)),
            name: 'NonErrorThrown',
        };
    }

    const errorRecord = error as Readonly<{
        readonly cause?: unknown;
        readonly code?: unknown;
        readonly message?: unknown;
        readonly name?: unknown;
        readonly stack?: unknown;
    }>;
    const code =
        typeof errorRecord.code === 'string' ||
        typeof errorRecord.code === 'number'
            ? errorRecord.code
            : undefined;
    const cause =
        depth < 5 && errorRecord.cause !== undefined
            ? serializeErrorDiagnostic(errorRecord.cause, depth + 1)
            : undefined;
    const message =
        typeof errorRecord.message === 'string'
            ? errorRecord.message
            : 'Non-Error object thrown';
    const name =
        typeof errorRecord.name === 'string'
            ? errorRecord.name
            : 'NonErrorThrown';
    const stack =
        typeof errorRecord.stack === 'string' ? errorRecord.stack : undefined;

    return {
        ...(cause === undefined ? {} : { cause }),
        ...(code === undefined ? {} : { code }),
        message: redactDiagnosticText(message),
        name,
        ...(stack === undefined ? {} : { stack: redactDiagnosticText(stack) }),
    };
};

export const normalizeProcessStatus = (
    rawExitCode: number | null,
    terminationSignal: NodeJS.Signals | null,
): NormalizedProcessStatus => {
    if (rawExitCode === null) {
        return {
            rawExitCode,
            terminationSignal,
        };
    }

    const unsignedExitCode = rawExitCode >>> 0;
    const signedExitCode = unsignedExitCode | 0;
    const conventionalSignalNumber =
        rawExitCode >= 129 && rawExitCode <= 255
            ? rawExitCode - 128
            : undefined;

    return {
        hexadecimalExitCode: `0x${unsignedExitCode
            .toString(16)
            .toUpperCase()
            .padStart(8, '0')}`,
        rawExitCode,
        signedExitCode,
        ...(conventionalSignalNumber === undefined
            ? {}
            : {
                  conventionalShellSignal: {
                      evidence: 'inferred-from-shell-convention' as const,
                      ...(conventionalPosixSignalNames[
                          conventionalSignalNumber
                      ] === undefined
                          ? {}
                          : {
                                signalName:
                                    conventionalPosixSignalNames[
                                        conventionalSignalNumber
                                    ],
                            }),
                      signalNumber: conventionalSignalNumber,
                  },
              }),
        ...(knownWindowsStatuses[unsignedExitCode] === undefined
            ? {}
            : { symbolicStatus: knownWindowsStatuses[unsignedExitCode] }),
        terminationSignal,
        unsignedExitCode,
    };
};
