import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ActiveLocalRunLog } from './local-run-log.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunnerForPackageManager,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import { waitForSuccessfulExactSourceCi } from './release-ci-gate.js';
import {
    requireUnpublishedNpmVersion,
    requireUnusedReleaseTag,
    resolveGitHubRelease,
    resolveNpmPublication,
    validateCheckedOutReleaseCommit,
    validateReleaseMetadataPaths,
    validateUnmovedDefaultBranch,
    type ReleaseCommandProbe,
} from './release-policy.js';
import {
    runCommandAndCaptureOutput,
    type CommandInvocation,
} from './run-command.js';

export type ReleaseCommandInvocation = {
    readonly arguments: readonly string[];
    readonly command: string;
    readonly description?: string;
    readonly environment?: NodeJS.ProcessEnv;
    readonly logFileSlug?: string;
    readonly workingDirectoryPath: string;
};

export type ReleaseCommandExecutor = (
    invocation: ReleaseCommandInvocation,
) => Promise<ReleaseCommandProbe> | ReleaseCommandProbe;

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

const createReleaseCommandExecutor =
    (runLog?: ActiveLocalRunLog): ReleaseCommandExecutor =>
    async (invocation) => {
        const commandInvocation: CommandInvocation = {
            args: invocation.arguments,
            command: invocation.command,
            description:
                invocation.description ??
                [invocation.command, ...invocation.arguments].join(' '),
            env: invocation.environment,
            logFileSlug: invocation.logFileSlug,
            workingDirectoryPath: invocation.workingDirectoryPath,
        };
        const result = await runCommandAndCaptureOutput(commandInvocation, {
            runLog,
        });
        if (result.terminationSignal !== null) {
            throw new Error(
                `${invocation.command} terminated by signal ${result.terminationSignal}.`,
            );
        }

        return {
            exitCode: result.exitCode,
            stderr: result.stderr,
            stdout: result.stdout,
        };
    };

const formatCommandFailure = (
    description: string,
    probe: ReleaseCommandProbe,
): Error => {
    const output = [probe.stdout.trim(), probe.stderr.trim()]
        .filter((entry) => entry.length > 0)
        .join('\n');
    return new Error(
        `${description} failed with exit code ${String(probe.exitCode)}${
            output.length === 0 ? '.' : `:\n${output}`
        }`,
    );
};

const requireSuccessfulCommand = (
    description: string,
    probe: ReleaseCommandProbe,
): string => {
    if (probe.exitCode !== 0) {
        throw formatCommandFailure(description, probe);
    }
    return probe.stdout;
};

const runPackageManagerCommand = async (
    executor: ReleaseCommandExecutor,
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    workingDirectoryPath: string,
): Promise<ReleaseCommandProbe> =>
    executor({
        arguments: [...runner.commandArgumentsPrefix, ...commandArguments],
        command: runner.command,
        description: `${runner.kind} ${commandArguments.join(' ')}`,
        logFileSlug: `${runner.kind}-${commandArguments[0] ?? 'command'}`,
        workingDirectoryPath,
    });

const runGitCommand = async (
    executor: ReleaseCommandExecutor,
    commandArguments: readonly string[],
    workingDirectoryPath = repositoryRoot,
): Promise<ReleaseCommandProbe> =>
    executor({
        arguments: commandArguments,
        command: 'git',
        description: `git ${commandArguments.join(' ')}`,
        logFileSlug: `git-${commandArguments[0] ?? 'command'}`,
        workingDirectoryPath,
    });

const readRequiredEnvironment = (environmentName: string): string => {
    const environmentValue = process.env[environmentName];
    if (environmentValue === undefined || environmentValue.length === 0) {
        throw new Error(`${environmentName} is required.`);
    }
    return environmentValue;
};

const parseNullDelimitedPaths = (output: string): readonly string[] =>
    output.split('\0').filter((entry) => entry.length > 0);

const parseRemoteRevision = (output: string): string =>
    output.trim().split(/\s+/u)[0] ?? '';

const appendGitHubOutput = async (
    outputName: string,
    outputValue: string,
): Promise<void> => {
    const githubOutputPath = process.env.GITHUB_OUTPUT;
    if (githubOutputPath !== undefined && githubOutputPath.length > 0) {
        await appendFile(
            githubOutputPath,
            `${outputName}=${outputValue}\n`,
            'utf8',
        );
    }
};

export const verifyReleaseTargets = async (input: {
    readonly defaultBranch: string;
    readonly executor?: ReleaseCommandExecutor;
    readonly releaseTag: string;
    readonly releaseVersion: string;
    readonly sourceRevision: string;
    readonly runLog?: ActiveLocalRunLog;
    readonly workingDirectoryPath?: string;
}): Promise<void> => {
    const executor =
        input.executor ?? createReleaseCommandExecutor(input.runLog);
    const workingDirectoryPath = input.workingDirectoryPath ?? repositoryRoot;
    const remoteBranchLookup = await runGitCommand(
        executor,
        ['ls-remote', 'origin', `refs/heads/${input.defaultBranch}`],
        workingDirectoryPath,
    );
    const remoteRevision = parseRemoteRevision(
        requireSuccessfulCommand(
            'The remote default-branch lookup',
            remoteBranchLookup,
        ),
    );
    validateUnmovedDefaultBranch({
        defaultBranch: input.defaultBranch,
        remoteRevision,
        sourceRevision: input.sourceRevision,
    });

    requireUnusedReleaseTag(
        input.releaseTag,
        await runGitCommand(
            executor,
            [
                'ls-remote',
                '--exit-code',
                '--tags',
                'origin',
                `refs/tags/${input.releaseTag}`,
            ],
            workingDirectoryPath,
        ),
    );

    const npmRunner = resolvePackageManagerRunnerForPackageManager('npm');
    requireUnpublishedNpmVersion(
        input.releaseVersion,
        await runPackageManagerCommand(
            executor,
            npmRunner,
            [
                'view',
                `sealed-lattice@${input.releaseVersion}`,
                'version',
                '--json',
            ],
            workingDirectoryPath,
        ),
    );
};

export const verifyReleaseMetadata = async (
    input: {
        readonly executor?: ReleaseCommandExecutor;
        readonly runLog?: ActiveLocalRunLog;
        readonly workingDirectoryPath?: string;
    } = {},
): Promise<void> => {
    const executor =
        input.executor ?? createReleaseCommandExecutor(input.runLog);
    const workingDirectoryPath = input.workingDirectoryPath ?? repositoryRoot;
    const changedPaths = parseNullDelimitedPaths(
        requireSuccessfulCommand(
            'The release metadata diff',
            await runGitCommand(
                executor,
                ['diff', '--name-only', '-z'],
                workingDirectoryPath,
            ),
        ),
    );
    const untrackedPaths = parseNullDelimitedPaths(
        requireSuccessfulCommand(
            'The untracked-file inventory',
            await runGitCommand(
                executor,
                ['ls-files', '--others', '--exclude-standard', '-z'],
                workingDirectoryPath,
            ),
        ),
    );

    validateReleaseMetadataPaths({ changedPaths, untrackedPaths });
};

export const determineNpmPublication = async (input: {
    readonly executor?: ReleaseCommandExecutor;
    readonly packageIntegrity: string;
    readonly packageTarballPath: string;
    readonly releaseVersion: string;
    readonly runLog?: ActiveLocalRunLog;
}): Promise<'already-identical' | 'publish'> => {
    const executor =
        input.executor ?? createReleaseCommandExecutor(input.runLog);
    const npmRunner = resolvePackageManagerRunnerForPackageManager('npm');
    const packageTarballPath = path.resolve(input.packageTarballPath);
    const actualPackageIntegrity = `sha512-${createHash('sha512')
        .update(await readFile(packageTarballPath))
        .digest('base64')}`;
    if (actualPackageIntegrity !== input.packageIntegrity) {
        throw new Error(
            'The retained package tarball no longer matches the package smoke integrity.',
        );
    }
    const workingDirectoryPath = path.dirname(packageTarballPath);

    const registryLookup = await runPackageManagerCommand(
        executor,
        npmRunner,
        [
            'view',
            `sealed-lattice@${input.releaseVersion}`,
            'dist.integrity',
            '--json',
        ],
        workingDirectoryPath,
    );
    const latestTagLookup =
        registryLookup.exitCode === 0
            ? await runPackageManagerCommand(
                  executor,
                  npmRunner,
                  ['view', 'sealed-lattice', 'dist-tags.latest', '--json'],
                  workingDirectoryPath,
              )
            : undefined;
    const publicationDisposition = resolveNpmPublication({
        latestTagLookup,
        localIntegrity: input.packageIntegrity,
        packageVersion: input.releaseVersion,
        registryLookup,
    });
    return publicationDisposition;
};

export const determineGitHubRelease = async (input: {
    readonly executor?: ReleaseCommandExecutor;
    readonly repository: string;
    readonly runLog?: ActiveLocalRunLog;
    readonly tag: string;
}): Promise<'already-exists' | 'create'> => {
    const executor =
        input.executor ?? createReleaseCommandExecutor(input.runLog);
    return resolveGitHubRelease({
        releaseLookup: await executor({
            arguments: [
                'api',
                `repos/${input.repository}/releases/tags/${input.tag}`,
            ],
            command: 'gh',
            workingDirectoryPath: repositoryRoot,
        }),
        tag: input.tag,
    });
};

export const verifyCheckedOutReleaseTag = async (input: {
    readonly executor?: ReleaseCommandExecutor;
    readonly releaseRevision: string;
    readonly runLog?: ActiveLocalRunLog;
    readonly tag: string;
    readonly workingDirectoryPath?: string;
}): Promise<void> => {
    const executor =
        input.executor ?? createReleaseCommandExecutor(input.runLog);
    const workingDirectoryPath = input.workingDirectoryPath ?? repositoryRoot;
    const headRevision = requireSuccessfulCommand(
        'The checked-out release commit lookup',
        await runGitCommand(
            executor,
            ['rev-parse', '--verify', 'HEAD^{commit}'],
            workingDirectoryPath,
        ),
    ).trim();
    validateCheckedOutReleaseCommit({
        checkedOutRevision: headRevision,
        releaseRevision: input.releaseRevision,
        tag: `checked-out HEAD for ${input.tag}`,
    });
    const checkedOutRevision = requireSuccessfulCommand(
        `The ${input.tag} commit lookup`,
        await runGitCommand(
            executor,
            ['rev-parse', '--verify', `refs/tags/${input.tag}^{commit}`],
            workingDirectoryPath,
        ),
    ).trim();
    validateCheckedOutReleaseCommit({
        checkedOutRevision,
        releaseRevision: input.releaseRevision,
        tag: input.tag,
    });
};

const runTargetsCommand = async (runLog: ActiveLocalRunLog): Promise<void> => {
    await verifyReleaseTargets({
        defaultBranch: readRequiredEnvironment('DEFAULT_BRANCH'),
        releaseTag: readRequiredEnvironment('RELEASE_TAG'),
        releaseVersion: readRequiredEnvironment('RELEASE_VERSION'),
        runLog,
        sourceRevision: readRequiredEnvironment('SOURCE_SHA'),
    });
};

const runAwaitCiCommand = async (runLog: ActiveLocalRunLog): Promise<void> => {
    const executor = createReleaseCommandExecutor(runLog);
    const result = await waitForSuccessfulExactSourceCi({
        executor: (invocation) =>
            executor({
                arguments: invocation.arguments,
                command: 'gh',
                description: invocation.description,
                logFileSlug: invocation.logFileSlug,
                workingDirectoryPath: repositoryRoot,
            }),
        repository: readRequiredEnvironment('GITHUB_REPOSITORY'),
        sourceRevision: readRequiredEnvironment('GITHUB_SHA'),
    });
    console.log(
        `Exact source ${readRequiredEnvironment('GITHUB_SHA')} passed CI in run ${String(result.runIdentifier)} (${result.url}).`,
    );
};

const runNpmDispositionCommand = async (
    runLog: ActiveLocalRunLog,
): Promise<void> => {
    const packageVersion = readRequiredEnvironment('RELEASE_VERSION');
    const action = await determineNpmPublication({
        packageIntegrity: readRequiredEnvironment('PACKAGE_INTEGRITY'),
        packageTarballPath: readRequiredEnvironment('PACKAGE_TARBALL_PATH'),
        releaseVersion: packageVersion,
        runLog,
    });
    await appendGitHubOutput('publish', String(action === 'publish'));
    console.log(
        action === 'publish'
            ? `sealed-lattice@${packageVersion} is not yet published.`
            : `sealed-lattice@${packageVersion} is already published with identical integrity.`,
    );
};

const runGitHubReleaseDispositionCommand = async (
    runLog: ActiveLocalRunLog,
): Promise<void> => {
    const tag = readRequiredEnvironment('RELEASE_TAG');
    const action = await determineGitHubRelease({
        repository: readRequiredEnvironment('GITHUB_REPOSITORY'),
        runLog,
        tag,
    });
    await appendGitHubOutput('create', String(action === 'create'));
    console.log(
        action === 'create'
            ? `GitHub release ${tag} does not yet exist.`
            : `GitHub release ${tag} already exists.`,
    );
};

const runCheckedOutTagCommand = async (
    runLog: ActiveLocalRunLog,
): Promise<void> => {
    await verifyCheckedOutReleaseTag({
        releaseRevision: readRequiredEnvironment('RELEASE_SHA'),
        runLog,
        tag: readRequiredEnvironment('RELEASE_TAG'),
    });
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Release verification'],
            scriptName: 'release-gates',
        },
        async (runLog) => {
            const [command] = rawArguments;
            runLog.writeEvent({
                details: { command: command ?? null },
                eventType: 'release-gate-started',
            });
            switch (command) {
                case 'await-ci':
                    await runAwaitCiCommand(runLog);
                    break;
                case 'targets':
                    await runTargetsCommand(runLog);
                    break;
                case 'metadata':
                    await verifyReleaseMetadata({ runLog });
                    break;
                case 'npm-disposition':
                    await runNpmDispositionCommand(runLog);
                    break;
                case 'github-release-disposition':
                    await runGitHubReleaseDispositionCommand(runLog);
                    break;
                case 'checked-out-tag':
                    await runCheckedOutTagCommand(runLog);
                    break;
                default:
                    throw new Error(
                        'Usage: release-gates.ts await-ci|targets|metadata|npm-disposition|github-release-disposition|checked-out-tag.',
                    );
            }
            runLog.writeEvent({
                details: { command },
                eventType: 'release-gate-finished',
            });
        },
    );
};

if (import.meta.main) {
    void main();
}
