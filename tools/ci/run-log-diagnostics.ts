type ErrorDiagnostic = {
    readonly cause?: ErrorDiagnostic;
    readonly code?: string | number;
    readonly message: string;
    readonly name: string;
    readonly stack?: string;
};

const diagnosticEnvironmentVariableNames = [
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
    'SEALED_LATTICE_RUN_DIRECTORY',
    'SEALED_LATTICE_TEST_PROJECT_LABEL',
    'VITEST_MAX_THREADS',
    'VITEST_MIN_THREADS',
] as const;

const sensitiveName =
    '(?:auth|authorization|cookie|credential|password|private[-_]?key|secret|token)';
const sensitiveArgumentPattern = new RegExp(`^${sensitiveName}$`, 'iu');
const sensitiveAssignmentPattern = new RegExp(
    `^(?<name>--?${sensitiveName}|${sensitiveName})=(?:.*)$`,
    'iu',
);
const sensitiveTextPattern = new RegExp(
    `\\b(${sensitiveName})\\s*[:=]\\s*([^\\s,;]+)`,
    'giu',
);

export const redactDiagnosticText = (value: string): string =>
    value
        .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/giu, '$1[redacted]@')
        .replace(/\bBearer\s+[^\s"']+/giu, 'Bearer [redacted]')
        .replace(
            sensitiveTextPattern,
            (_match, name: string) => `${name}=[redacted]`,
        );

export const redactCommandLineArguments = (
    commandLineArguments: readonly string[],
): readonly string[] => {
    let redactNext = false;
    return commandLineArguments.map((argument) => {
        if (redactNext) {
            redactNext = false;
            return '[redacted]';
        }

        const assignment = sensitiveAssignmentPattern.exec(argument);
        if (assignment?.groups?.name !== undefined) {
            return `${assignment.groups.name}=[redacted]`;
        }
        if (sensitiveArgumentPattern.test(argument.replace(/^-+/u, ''))) {
            redactNext = true;
            return argument;
        }
        return redactDiagnosticText(argument);
    });
};

export const selectDiagnosticEnvironment = (
    environment: NodeJS.ProcessEnv,
): Readonly<Record<string, string>> =>
    Object.fromEntries(
        diagnosticEnvironmentVariableNames.flatMap((name) => {
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
    if (!(error instanceof Error)) {
        return {
            message: redactDiagnosticText(String(error)),
            name: 'NonErrorThrown',
        };
    }

    const { cause, code } = error as Error & {
        readonly cause?: unknown;
        readonly code?: unknown;
    };
    return {
        ...(depth < 3 && cause !== undefined
            ? { cause: serializeErrorDiagnostic(cause, depth + 1) }
            : {}),
        ...(typeof code === 'string' || typeof code === 'number'
            ? { code }
            : {}),
        message: redactDiagnosticText(error.message),
        name: error.name,
        ...(error.stack === undefined
            ? {}
            : { stack: redactDiagnosticText(error.stack) }),
    };
};
