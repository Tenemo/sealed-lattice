import type { ReleaseCommandProbe } from './release-policy.js';

const ciRegistrationAttemptCount = 12;
const ciRegistrationDelayMilliseconds = 5_000;
const ciStatusPollCount = 710;
const ciStatusPollDelayMilliseconds = 30_000;

type ListedCiRun = {
    readonly conclusion: string;
    readonly headRevision: string;
    readonly runIdentifier: number;
    readonly status: string;
    readonly url: string;
};

type ViewedCiRun = ListedCiRun & {
    readonly jobs: readonly {
        readonly conclusion: string;
        readonly name: string;
    }[];
};

export type GitHubCommandInvocation = {
    readonly arguments: readonly string[];
    readonly description: string;
    readonly logFileSlug: string;
};

export type GitHubCommandExecutor = (
    invocation: GitHubCommandInvocation,
) => Promise<ReleaseCommandProbe> | ReleaseCommandProbe;

type Delay = (durationMilliseconds: number) => Promise<void>;

const waitForDelay: Delay = async (durationMilliseconds) => {
    await new Promise<void>((resolve) => {
        setTimeout(resolve, durationMilliseconds);
    });
};

const requireSuccessfulGitHubCommand = (
    invocation: GitHubCommandInvocation,
    probe: ReleaseCommandProbe,
): string => {
    if (probe.exitCode === 0) {
        return probe.stdout;
    }
    const output = [probe.stdout.trim(), probe.stderr.trim()]
        .filter((entry) => entry.length > 0)
        .join('\n');
    throw new Error(
        `${invocation.description} failed with exit code ${String(probe.exitCode)}${
            output.length === 0 ? '.' : `:\n${output}`
        }`,
    );
};

const requireRecord = (
    value: unknown,
    description: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${description} is not a JSON object.`);
    }
    return value as Record<string, unknown>;
};

const requireString = (
    record: Record<string, unknown>,
    propertyName: string,
    description: string,
): string => {
    const value = record[propertyName];
    if (typeof value !== 'string') {
        throw new Error(`${description}.${propertyName} is not a string.`);
    }
    return value;
};

const requireRunIdentifier = (
    record: Record<string, unknown>,
    description: string,
): number => {
    const runIdentifier = record.databaseId;
    if (
        typeof runIdentifier !== 'number' ||
        !Number.isSafeInteger(runIdentifier) ||
        runIdentifier <= 0
    ) {
        throw new Error(`${description}.databaseId is not a positive integer.`);
    }
    return runIdentifier;
};

const parseListedCiRun = (value: unknown, runIndex: number): ListedCiRun => {
    const description = `CI run list entry ${String(runIndex)}`;
    const record = requireRecord(value, description);
    return {
        conclusion: requireString(record, 'conclusion', description),
        headRevision: requireString(record, 'headSha', description),
        runIdentifier: requireRunIdentifier(record, description),
        status: requireString(record, 'status', description),
        url: requireString(record, 'url', description),
    };
};

const parseListedCiRuns = (output: string): readonly ListedCiRun[] => {
    let parsed: unknown;
    try {
        parsed = JSON.parse(output);
    } catch {
        throw new Error('The exact-source CI run list is not valid JSON.');
    }
    if (!Array.isArray(parsed)) {
        throw new Error('The exact-source CI run list is not a JSON array.');
    }
    return parsed.map(parseListedCiRun);
};

const parseViewedCiRun = (output: string): ViewedCiRun => {
    let parsed: unknown;
    try {
        parsed = JSON.parse(output);
    } catch {
        throw new Error('The exact-source CI run detail is not valid JSON.');
    }
    const record = requireRecord(parsed, 'CI run detail');
    if (!Array.isArray(record.jobs)) {
        throw new Error('CI run detail.jobs is not a JSON array.');
    }
    return {
        conclusion: requireString(record, 'conclusion', 'CI run detail'),
        headRevision: requireString(record, 'headSha', 'CI run detail'),
        jobs: record.jobs.map((job, jobIndex) => {
            const description = `CI run detail job ${String(jobIndex)}`;
            const jobRecord = requireRecord(job, description);
            return {
                conclusion: requireString(jobRecord, 'conclusion', description),
                name: requireString(jobRecord, 'name', description),
            };
        }),
        runIdentifier: requireRunIdentifier(record, 'CI run detail'),
        status: requireString(record, 'status', 'CI run detail'),
        url: requireString(record, 'url', 'CI run detail'),
    };
};

const executeGitHubCommand = async (
    executor: GitHubCommandExecutor,
    invocation: GitHubCommandInvocation,
): Promise<string> =>
    requireSuccessfulGitHubCommand(invocation, await executor(invocation));

const listExactSourceCiRuns = async (input: {
    readonly executor: GitHubCommandExecutor;
    readonly repository: string;
    readonly sourceRevision: string;
}): Promise<readonly ListedCiRun[]> => {
    const invocation: GitHubCommandInvocation = {
        arguments: [
            'run',
            'list',
            '--repo',
            input.repository,
            '--workflow',
            'ci.yml',
            '--commit',
            input.sourceRevision,
            '--limit',
            '20',
            '--json',
            'databaseId,status,conclusion,url,headSha',
        ],
        description: 'The exact-source CI run lookup',
        logFileSlug: 'gh-ci-run-list',
    };
    const runs = parseListedCiRuns(
        await executeGitHubCommand(input.executor, invocation),
    );
    for (const run of runs) {
        if (run.headRevision !== input.sourceRevision) {
            throw new Error(
                `CI run ${String(run.runIdentifier)} resolves to ${run.headRevision}, not exact source ${input.sourceRevision}.`,
            );
        }
    }
    return runs;
};

const viewCiRun = async (input: {
    readonly executor: GitHubCommandExecutor;
    readonly repository: string;
    readonly runIdentifier: number;
    readonly sourceRevision: string;
}): Promise<ViewedCiRun> => {
    const invocation: GitHubCommandInvocation = {
        arguments: [
            'run',
            'view',
            String(input.runIdentifier),
            '--repo',
            input.repository,
            '--json',
            'databaseId,status,conclusion,url,headSha,jobs',
        ],
        description: `The CI run ${String(input.runIdentifier)} lookup`,
        logFileSlug: 'gh-ci-run-view',
    };
    const run = parseViewedCiRun(
        await executeGitHubCommand(input.executor, invocation),
    );
    if (run.runIdentifier !== input.runIdentifier) {
        throw new Error(
            `The CI run lookup returned ${String(run.runIdentifier)}, not requested run ${String(input.runIdentifier)}.`,
        );
    }
    if (run.headRevision !== input.sourceRevision) {
        throw new Error(
            `CI run ${String(run.runIdentifier)} resolves to ${run.headRevision}, not exact source ${input.sourceRevision}.`,
        );
    }
    return run;
};

const hasSuccessfulVerifyJob = (run: ViewedCiRun): boolean =>
    run.jobs.some(
        (job) => job.name === 'verify' && job.conclusion === 'success',
    );

const requireSuccessfulVerifiedCiRun = (run: ViewedCiRun): void => {
    if (run.status !== 'completed' || run.conclusion !== 'success') {
        throw new Error(
            `Exact-source CI run ${String(run.runIdentifier)} concluded with status ${run.status} and conclusion ${run.conclusion || 'none'}.`,
        );
    }
    if (!hasSuccessfulVerifyJob(run)) {
        throw new Error(
            `Exact-source CI run ${String(run.runIdentifier)} completed without a successful verify job.`,
        );
    }
};

export const waitForSuccessfulExactSourceCi = async (input: {
    readonly delay?: Delay;
    readonly executor: GitHubCommandExecutor;
    readonly repository: string;
    readonly sourceRevision: string;
}): Promise<{ readonly runIdentifier: number; readonly url: string }> => {
    const delay = input.delay ?? waitForDelay;
    let listedRuns: readonly ListedCiRun[] = [];
    for (
        let registrationAttempt = 0;
        registrationAttempt < ciRegistrationAttemptCount;
        registrationAttempt += 1
    ) {
        listedRuns = await listExactSourceCiRuns(input);
        if (listedRuns.length > 0) {
            break;
        }
        if (registrationAttempt + 1 < ciRegistrationAttemptCount) {
            console.log(
                `Waiting for the CI workflow to register exact source ${input.sourceRevision}.`,
            );
            await delay(ciRegistrationDelayMilliseconds);
        }
    }
    if (listedRuns.length === 0) {
        throw new Error(
            `No CI run exists for exact source ${input.sourceRevision}.`,
        );
    }

    for (const listedRun of listedRuns) {
        if (
            listedRun.status === 'completed' &&
            listedRun.conclusion === 'success'
        ) {
            const completedRun = await viewCiRun({
                executor: input.executor,
                repository: input.repository,
                runIdentifier: listedRun.runIdentifier,
                sourceRevision: input.sourceRevision,
            });
            if (
                completedRun.status === 'completed' &&
                completedRun.conclusion === 'success' &&
                hasSuccessfulVerifyJob(completedRun)
            ) {
                return {
                    runIdentifier: completedRun.runIdentifier,
                    url: completedRun.url,
                };
            }
        }
    }

    const selectedRun =
        listedRuns.find((run) => run.status !== 'completed') ?? listedRuns[0];
    if (selectedRun === undefined) {
        throw new Error('The exact-source CI run selection is empty.');
    }
    for (let statusPoll = 0; statusPoll < ciStatusPollCount; statusPoll += 1) {
        const currentRun = await viewCiRun({
            executor: input.executor,
            repository: input.repository,
            runIdentifier: selectedRun.runIdentifier,
            sourceRevision: input.sourceRevision,
        });
        if (currentRun.status === 'completed') {
            requireSuccessfulVerifiedCiRun(currentRun);
            return {
                runIdentifier: currentRun.runIdentifier,
                url: currentRun.url,
            };
        }
        console.log(
            `Waiting for exact-source CI run ${String(currentRun.runIdentifier)}; current status ${currentRun.status}.`,
        );
        await delay(ciStatusPollDelayMilliseconds);
    }

    throw new Error(
        `Exact-source CI run ${String(selectedRun.runIdentifier)} did not complete within the release wait boundary.`,
    );
};
