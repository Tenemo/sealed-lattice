import { spawnSync } from 'node:child_process';
import {
    appendFile,
    mkdir,
    mkdtemp,
    readFile,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    resolvePackageManagerRunner,
    resolvePackageManagerRunnerForPackageManager,
    type PackageManagerRunner,
} from './package-manager-runner.js';
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
    deriveReleaseVersion,
    parseReleaseIncrement,
    type ReleaseIncrement,
    type ReleaseVersionResult,
} from './release-version.js';
import { stagePublicPackage } from './stage-public-package.mjs';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

export type ReleaseCommandInvocation = {
    readonly arguments: readonly string[];
    readonly command: string;
    readonly environment?: NodeJS.ProcessEnv;
    readonly workingDirectoryPath: string;
};

export type ReleaseCommandExecutor = (
    invocation: ReleaseCommandInvocation,
) => ReleaseCommandProbe;

type StagedReleasePackage = {
    readonly packageDirectory: string;
    readonly packageJsonPath: string;
};

export type MutationFreeReleaseVerificationDependencies = {
    readonly buildAndSmoke: (
        temporaryDirectoryPath: string,
        releaseVersion: ReleaseVersionResult,
    ) => Promise<void>;
    readonly createTemporaryDirectory: () => Promise<string>;
    readonly inspectWorkingTree: () => Promise<string>;
    readonly publishDryRun: (packageDirectory: string) => Promise<void>;
    readonly removeTemporaryDirectory: (
        temporaryDirectoryPath: string,
    ) => Promise<void>;
    readonly stagePackage: (
        temporaryDirectoryPath: string,
    ) => Promise<StagedReleasePackage>;
    readonly verifyTargets: (
        releaseVersion: ReleaseVersionResult,
    ) => Promise<void>;
};

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const publicPackageManifestPath = path.resolve(
    repositoryRoot,
    'packages',
    'sdk',
    'package.json',
);

const executeReleaseCommand: ReleaseCommandExecutor = (invocation) => {
    const result = spawnSync(invocation.command, invocation.arguments, {
        cwd: invocation.workingDirectoryPath,
        encoding: 'utf8',
        env: invocation.environment ?? process.env,
        maxBuffer: 100 * 1024 * 1024,
    });

    if (result.error !== undefined) {
        throw new Error(
            `Failed to start ${invocation.command}: ${result.error.message}`,
        );
    }
    if (result.signal !== null) {
        throw new Error(
            `${invocation.command} terminated by signal ${result.signal}.`,
        );
    }

    return {
        exitCode: result.status ?? 1,
        stderr: result.stderr ?? '',
        stdout: result.stdout ?? '',
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

const runPackageManagerCommand = (
    executor: ReleaseCommandExecutor,
    runner: PackageManagerRunner,
    commandArguments: readonly string[],
    workingDirectoryPath: string,
): ReleaseCommandProbe =>
    executor({
        arguments: [...runner.commandArgumentsPrefix, ...commandArguments],
        command: runner.command,
        workingDirectoryPath,
    });

const runGitCommand = (
    executor: ReleaseCommandExecutor,
    commandArguments: readonly string[],
    workingDirectoryPath = repositoryRoot,
): ReleaseCommandProbe =>
    executor({
        arguments: commandArguments,
        command: 'git',
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

export const verifyReleaseTargets = (input: {
    readonly defaultBranch: string;
    readonly executor?: ReleaseCommandExecutor;
    readonly releaseTag: string;
    readonly releaseVersion: string;
    readonly sourceRevision: string;
    readonly workingDirectoryPath?: string;
}): void => {
    const executor = input.executor ?? executeReleaseCommand;
    const workingDirectoryPath = input.workingDirectoryPath ?? repositoryRoot;
    const remoteBranchLookup = runGitCommand(
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
        runGitCommand(
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
        runPackageManagerCommand(
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

export const verifyReleaseMetadata = (
    input: {
        readonly executor?: ReleaseCommandExecutor;
        readonly workingDirectoryPath?: string;
    } = {},
): void => {
    const executor = input.executor ?? executeReleaseCommand;
    const workingDirectoryPath = input.workingDirectoryPath ?? repositoryRoot;
    const changedPaths = parseNullDelimitedPaths(
        requireSuccessfulCommand(
            'The release metadata diff',
            runGitCommand(
                executor,
                ['diff', '--name-only', '-z'],
                workingDirectoryPath,
            ),
        ),
    );
    const untrackedPaths = parseNullDelimitedPaths(
        requireSuccessfulCommand(
            'The untracked-file inventory',
            runGitCommand(
                executor,
                ['ls-files', '--others', '--exclude-standard', '-z'],
                workingDirectoryPath,
            ),
        ),
    );

    validateReleaseMetadataPaths({ changedPaths, untrackedPaths });
};

type NpmPackMetadata = {
    readonly filename: string;
    readonly integrity: string;
    readonly name: string;
    readonly version: string;
};

const parseNpmPackMetadata = (packOutput: string): NpmPackMetadata => {
    let parsedOutput: unknown;
    try {
        parsedOutput = JSON.parse(packOutput) as unknown;
    } catch {
        throw new Error('npm pack returned malformed JSON.');
    }

    if (!Array.isArray(parsedOutput) || parsedOutput.length !== 1) {
        throw new Error('npm pack must describe exactly one package.');
    }
    const packageMetadata: unknown = parsedOutput[0];
    if (
        typeof packageMetadata !== 'object' ||
        packageMetadata === null ||
        !('filename' in packageMetadata) ||
        typeof packageMetadata.filename !== 'string' ||
        !('integrity' in packageMetadata) ||
        typeof packageMetadata.integrity !== 'string' ||
        !('name' in packageMetadata) ||
        typeof packageMetadata.name !== 'string' ||
        !('version' in packageMetadata) ||
        typeof packageMetadata.version !== 'string'
    ) {
        throw new Error(
            'npm pack did not return a filename, integrity, package name, and package version.',
        );
    }

    return {
        filename: packageMetadata.filename,
        integrity: packageMetadata.integrity,
        name: packageMetadata.name,
        version: packageMetadata.version,
    };
};

export const determineNpmPublication = async (input: {
    readonly executor?: ReleaseCommandExecutor;
    readonly packageDirectory: string;
    readonly releaseVersion: string;
}): Promise<'already-identical' | 'publish'> => {
    const executor = input.executor ?? executeReleaseCommand;
    const npmRunner = resolvePackageManagerRunnerForPackageManager('npm');
    const packMetadata = parseNpmPackMetadata(
        requireSuccessfulCommand(
            'npm pack',
            runPackageManagerCommand(
                executor,
                npmRunner,
                ['pack', '--json', '--ignore-scripts'],
                input.packageDirectory,
            ),
        ),
    );
    if (
        packMetadata.name !== 'sealed-lattice' ||
        packMetadata.version !== input.releaseVersion
    ) {
        throw new Error(
            `npm pack produced ${packMetadata.name}@${packMetadata.version}; expected sealed-lattice@${input.releaseVersion}.`,
        );
    }
    const packageArchivePath = path.resolve(
        input.packageDirectory,
        packMetadata.filename,
    );
    if (
        path.dirname(packageArchivePath) !==
        path.resolve(input.packageDirectory)
    ) {
        throw new Error(
            'npm pack returned a filename outside the package directory.',
        );
    }
    await rm(packageArchivePath, { force: true });

    const registryLookup = runPackageManagerCommand(
        executor,
        npmRunner,
        [
            'view',
            `sealed-lattice@${input.releaseVersion}`,
            'dist.integrity',
            '--json',
        ],
        input.packageDirectory,
    );
    const latestTagLookup =
        registryLookup.exitCode === 0
            ? runPackageManagerCommand(
                  executor,
                  npmRunner,
                  ['view', 'sealed-lattice', 'dist-tags.latest', '--json'],
                  input.packageDirectory,
              )
            : undefined;
    const publicationDisposition = resolveNpmPublication({
        latestTagLookup,
        localIntegrity: packMetadata.integrity,
        packageVersion: input.releaseVersion,
        registryLookup,
    });
    return publicationDisposition.action;
};

export const determineGitHubRelease = (input: {
    readonly executor?: ReleaseCommandExecutor;
    readonly repository: string;
    readonly tag: string;
}): 'already-exists' | 'create' => {
    const executor = input.executor ?? executeReleaseCommand;
    return resolveGitHubRelease({
        releaseLookup: executor({
            arguments: [
                'api',
                `repos/${input.repository}/releases/tags/${input.tag}`,
            ],
            command: 'gh',
            workingDirectoryPath: repositoryRoot,
        }),
        tag: input.tag,
    }).action;
};

export const verifyCheckedOutReleaseTag = (input: {
    readonly executor?: ReleaseCommandExecutor;
    readonly releaseRevision: string;
    readonly tag: string;
    readonly workingDirectoryPath?: string;
}): void => {
    const executor = input.executor ?? executeReleaseCommand;
    const workingDirectoryPath = input.workingDirectoryPath ?? repositoryRoot;
    const headRevision = requireSuccessfulCommand(
        'The checked-out release commit lookup',
        runGitCommand(
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
        runGitCommand(
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

const updateStagedPackageVersion = async (
    packageJsonPath: string,
    releaseVersion: string,
): Promise<void> => {
    let packageManifest: unknown;
    try {
        packageManifest = JSON.parse(
            await readFile(packageJsonPath, 'utf8'),
        ) as unknown;
    } catch {
        throw new Error(
            'The staged public package manifest is not valid JSON.',
        );
    }
    if (
        typeof packageManifest !== 'object' ||
        packageManifest === null ||
        !('name' in packageManifest) ||
        packageManifest.name !== 'sealed-lattice' ||
        !('version' in packageManifest) ||
        typeof packageManifest.version !== 'string'
    ) {
        throw new Error(
            'The staged package manifest does not identify sealed-lattice.',
        );
    }

    packageManifest.version = releaseVersion;
    await writeFile(
        packageJsonPath,
        `${JSON.stringify(packageManifest, null, 4)}\n`,
        'utf8',
    );
};

export const verifyReleaseWithoutMutation = async (input: {
    readonly dependencies: MutationFreeReleaseVerificationDependencies;
    readonly increment: ReleaseIncrement;
    readonly manifestPath?: string;
}): Promise<ReleaseVersionResult> => {
    const manifestPath = path.resolve(
        input.manifestPath ?? publicPackageManifestPath,
    );
    const sourceManifestText = await readFile(manifestPath, 'utf8');
    const releaseVersion = deriveReleaseVersion(
        sourceManifestText,
        input.increment,
    );
    const initialWorkingTree = await input.dependencies.inspectWorkingTree();
    if (initialWorkingTree.length > 0) {
        throw new Error(
            'Release verification must start from a clean working tree.',
        );
    }

    let temporaryDirectoryPath: string | undefined;
    let verificationFailure: unknown;
    try {
        await input.dependencies.verifyTargets(releaseVersion);
        temporaryDirectoryPath =
            await input.dependencies.createTemporaryDirectory();
        await input.dependencies.buildAndSmoke(
            temporaryDirectoryPath,
            releaseVersion,
        );
        const stagedPackage = await input.dependencies.stagePackage(
            temporaryDirectoryPath,
        );
        await updateStagedPackageVersion(
            stagedPackage.packageJsonPath,
            releaseVersion.version,
        );
        await input.dependencies.publishDryRun(stagedPackage.packageDirectory);
    } catch (error) {
        verificationFailure = error;
    } finally {
        if (temporaryDirectoryPath !== undefined) {
            await input.dependencies.removeTemporaryDirectory(
                temporaryDirectoryPath,
            );
        }
    }

    const finalWorkingTree = await input.dependencies.inspectWorkingTree();
    if (finalWorkingTree !== initialWorkingTree) {
        throw new Error('Release verification changed the working tree.');
    }
    if (verificationFailure !== undefined) {
        throw verificationFailure instanceof Error
            ? verificationFailure
            : new Error(
                  typeof verificationFailure === 'string'
                      ? verificationFailure
                      : 'Release verification failed with a non-Error value.',
              );
    }
    if ((await readFile(manifestPath, 'utf8')) !== sourceManifestText) {
        throw new Error(
            'Release verification changed the public package manifest.',
        );
    }

    return releaseVersion;
};

const makeDefaultMutationFreeDependencies = (input: {
    readonly defaultBranch: string;
    readonly sourceRevision: string;
}): MutationFreeReleaseVerificationDependencies => {
    const pnpmRunner = resolvePackageManagerRunner();
    const npmRunner = resolvePackageManagerRunnerForPackageManager('npm');

    return {
        buildAndSmoke: async (temporaryDirectoryPath, releaseVersion) => {
            const isolatedSourcePath = path.join(
                temporaryDirectoryPath,
                'source',
            );
            await mkdir(isolatedSourcePath, { recursive: true });
            const checkoutPrefix = `${isolatedSourcePath}${path.sep}`.replace(
                /\\/gu,
                '/',
            );
            requireSuccessfulCommand(
                'The isolated source copy',
                runGitCommand(executeReleaseCommand, [
                    'checkout-index',
                    '--all',
                    '--force',
                    `--prefix=${checkoutPrefix}`,
                ]),
            );
            await updateStagedPackageVersion(
                path.join(
                    isolatedSourcePath,
                    'packages',
                    'sdk',
                    'package.json',
                ),
                releaseVersion.version,
            );
            const installProbe = executeReleaseCommand({
                arguments: [
                    ...pnpmRunner.commandArgumentsPrefix,
                    'install',
                    '--frozen-lockfile',
                ],
                command: pnpmRunner.command,
                environment: { ...process.env, HUSKY: '0' },
                workingDirectoryPath: isolatedSourcePath,
            });
            requireSuccessfulCommand(
                'The isolated frozen installation',
                installProbe,
            );
            requireSuccessfulCommand(
                'The packed-package smoke test',
                runPackageManagerCommand(
                    executeReleaseCommand,
                    pnpmRunner,
                    ['run', 'smoke:pack:npm'],
                    isolatedSourcePath,
                ),
            );
        },
        createTemporaryDirectory: async () =>
            mkdtemp(path.join(tmpdir(), 'sealed-lattice-release-verify-')),
        inspectWorkingTree: () =>
            Promise.resolve(
                requireSuccessfulCommand(
                    'The working-tree inspection',
                    runGitCommand(executeReleaseCommand, [
                        'status',
                        '--porcelain=v1',
                        '--untracked-files=all',
                    ]),
                ),
            ),
        publishDryRun: (packageDirectory) => {
            const publishProbe = runPackageManagerCommand(
                executeReleaseCommand,
                npmRunner,
                ['publish', '--dry-run', '--ignore-scripts', '--tag', 'latest'],
                packageDirectory,
            );
            const output = requireSuccessfulCommand(
                'The npm publication dry run',
                publishProbe,
            ).trim();
            if (output.length > 0) {
                console.log(output);
            }
            return Promise.resolve();
        },
        removeTemporaryDirectory: async (temporaryDirectoryPath) => {
            await rm(temporaryDirectoryPath, { force: true, recursive: true });
        },
        stagePackage: async (temporaryDirectoryPath) =>
            stagePublicPackage({
                destinationPath: path.join(
                    temporaryDirectoryPath,
                    'public-package',
                ),
                projectRoot: path.join(temporaryDirectoryPath, 'source'),
            }),
        verifyTargets: (releaseVersion) => {
            verifyReleaseTargets({
                defaultBranch: input.defaultBranch,
                releaseTag: releaseVersion.tag,
                releaseVersion: releaseVersion.version,
                sourceRevision: input.sourceRevision,
            });
            return Promise.resolve();
        },
    };
};

const resolveDefaultBranch = (): string => {
    const configuredDefaultBranch = process.env.DEFAULT_BRANCH;
    if (
        configuredDefaultBranch !== undefined &&
        configuredDefaultBranch.length > 0
    ) {
        return configuredDefaultBranch;
    }

    const symbolicRemoteBranch = requireSuccessfulCommand(
        'The default-branch lookup',
        runGitCommand(executeReleaseCommand, [
            'symbolic-ref',
            '--quiet',
            '--short',
            'refs/remotes/origin/HEAD',
        ]),
    ).trim();
    const remotePrefix = 'origin/';
    if (!symbolicRemoteBranch.startsWith(remotePrefix)) {
        throw new Error(
            'Cannot derive the default branch from origin/HEAD. Set DEFAULT_BRANCH explicitly.',
        );
    }
    return symbolicRemoteBranch.slice(remotePrefix.length);
};

const runTargetsCommand = (): void => {
    verifyReleaseTargets({
        defaultBranch: readRequiredEnvironment('DEFAULT_BRANCH'),
        releaseTag: readRequiredEnvironment('RELEASE_TAG'),
        releaseVersion: readRequiredEnvironment('RELEASE_VERSION'),
        sourceRevision: readRequiredEnvironment('SOURCE_SHA'),
    });
};

const runNpmDispositionCommand = async (): Promise<void> => {
    const packageVersion = readRequiredEnvironment('RELEASE_VERSION');
    const action = await determineNpmPublication({
        packageDirectory: readRequiredEnvironment('PUBLIC_PACKAGE_DIR'),
        releaseVersion: packageVersion,
    });
    await appendGitHubOutput('publish', String(action === 'publish'));
    console.log(
        action === 'publish'
            ? `sealed-lattice@${packageVersion} is not yet published.`
            : `sealed-lattice@${packageVersion} is already published with identical integrity.`,
    );
};

const runGitHubReleaseDispositionCommand = async (): Promise<void> => {
    const tag = readRequiredEnvironment('RELEASE_TAG');
    const action = determineGitHubRelease({
        repository: readRequiredEnvironment('GITHUB_REPOSITORY'),
        tag,
    });
    await appendGitHubOutput('create', String(action === 'create'));
    console.log(
        action === 'create'
            ? `GitHub release ${tag} does not yet exist.`
            : `GitHub release ${tag} already exists.`,
    );
};

const runCheckedOutTagCommand = (): void => {
    verifyCheckedOutReleaseTag({
        releaseRevision: readRequiredEnvironment('RELEASE_SHA'),
        tag: readRequiredEnvironment('RELEASE_TAG'),
    });
};

const runDryRunCommand = async (
    commandArguments: readonly string[],
): Promise<void> => {
    const increment = parseReleaseIncrement(commandArguments);
    const sourceRevision = requireSuccessfulCommand(
        'The source revision lookup',
        runGitCommand(executeReleaseCommand, ['rev-parse', 'HEAD']),
    ).trim();
    const releaseVersion = await verifyReleaseWithoutMutation({
        dependencies: makeDefaultMutationFreeDependencies({
            defaultBranch: resolveDefaultBranch(),
            sourceRevision,
        }),
        increment,
    });
    console.log(
        `Verified sealed-lattice ${releaseVersion.previousVersion} -> ${releaseVersion.version} in an isolated source copy without mutating the working tree.`,
    );
};

const main = async (): Promise<void> => {
    const [command, ...commandArguments] = process.argv.slice(2);
    switch (command) {
        case 'targets':
            runTargetsCommand();
            break;
        case 'metadata':
            verifyReleaseMetadata();
            break;
        case 'npm-disposition':
            await runNpmDispositionCommand();
            break;
        case 'github-release-disposition':
            await runGitHubReleaseDispositionCommand();
            break;
        case 'checked-out-tag':
            runCheckedOutTagCommand();
            break;
        case 'dry-run':
            await runDryRunCommand(commandArguments);
            break;
        default:
            throw new Error(
                'Usage: release-gates.ts targets|metadata|npm-disposition|github-release-disposition|checked-out-tag|dry-run [patch|minor].',
            );
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
