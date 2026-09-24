import path from 'node:path';

const testDiagnosticEnvironmentVariables = {
    projectLabel: 'SEALED_LATTICE_TEST_PROJECT_LABEL',
    runDirectory: 'SEALED_LATTICE_RUN_DIRECTORY',
} as const;

type ResolvedTestDiagnosticPaths = {
    readonly attachmentDirectoryPath?: string;
    readonly diagnosticReportDirectoryPath?: string;
    readonly projectLabel: string;
    readonly resultFilePath?: string;
};

export const resolveTestDiagnosticPaths = (
    environment: NodeJS.ProcessEnv = process.env,
): ResolvedTestDiagnosticPaths => {
    const runDirectoryPath =
        environment[testDiagnosticEnvironmentVariables.runDirectory];
    const projectLabel =
        environment[testDiagnosticEnvironmentVariables.projectLabel] ??
        `vitest-${process.pid}`;
    if (runDirectoryPath === undefined) {
        return { projectLabel };
    }

    return {
        attachmentDirectoryPath: path.join(
            runDirectoryPath,
            'attachments',
            projectLabel,
        ),
        diagnosticReportDirectoryPath: path.join(
            runDirectoryPath,
            'diagnostic-reports',
            projectLabel,
        ),
        projectLabel,
        resultFilePath: path.join(
            runDirectoryPath,
            'vitest-results',
            `${projectLabel}.json`,
        ),
    };
};
