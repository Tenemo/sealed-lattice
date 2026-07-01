import { existsSync } from 'node:fs';
import path from 'node:path';

export type PackageManager = 'npm' | 'pnpm';

export type PackageManagerRunner = {
    readonly command: string;
    readonly commandArgumentsPrefix: readonly string[];
    readonly kind: PackageManager;
};

export const detectPackageManager = (
    packageManagerEntryPointPath: string,
): PackageManager => {
    const normalizedEntryPointPath = packageManagerEntryPointPath.toLowerCase();
    if (normalizedEntryPointPath.includes('pnpm')) {
        return 'pnpm';
    }
    if (normalizedEntryPointPath.includes('npm')) {
        return 'npm';
    }

    throw new Error(
        `Unsupported package manager entry point: ${packageManagerEntryPointPath}`,
    );
};

export const buildPackageManagerEntryPointCandidates = (
    packageManager: PackageManager,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
): readonly string[] => {
    const nodeDirectoryPath = path.dirname(nodeExecutablePath);
    const pathDirectoryPaths = pathEnvironment
        .split(path.delimiter)
        .filter((directoryPath) => directoryPath.length > 0);
    const baseDirectoryPaths = [nodeDirectoryPath, ...pathDirectoryPaths];
    const relativeEntryPointPaths =
        packageManager === 'npm'
            ? [
                  path.join('node_modules', 'npm', 'bin', 'npm-cli.js'),
                  path.join(
                      '..',
                      'lib',
                      'node_modules',
                      'npm',
                      'bin',
                      'npm-cli.js',
                  ),
              ]
            : [
                  path.join('node_modules', 'corepack', 'dist', 'pnpm.js'),
                  path.join('node_modules', 'pnpm', 'bin', 'pnpm.cjs'),
                  path.join(
                      '..',
                      'lib',
                      'node_modules',
                      'pnpm',
                      'bin',
                      'pnpm.cjs',
                  ),
              ];

    return baseDirectoryPaths.flatMap((baseDirectoryPath) =>
        relativeEntryPointPaths.map((relativeEntryPointPath) =>
            path.resolve(baseDirectoryPath, relativeEntryPointPath),
        ),
    );
};

export const resolvePackageManagerEntryPoint = (
    packageManager: PackageManager,
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): string => {
    if (packageManagerEntryPointPath !== undefined) {
        try {
            if (
                detectPackageManager(packageManagerEntryPointPath) ===
                packageManager
            ) {
                return packageManagerEntryPointPath;
            }
        } catch {
            // Keep searching for a real Node entry point below.
        }
    }

    const entryPointPath = buildPackageManagerEntryPointCandidates(
        packageManager,
        pathEnvironment,
        nodeExecutablePath,
    ).find(pathExists);

    if (entryPointPath === undefined) {
        throw new Error(
            `Cannot find a Node entry point for ${packageManager}. Avoid shell shims and run through npm_execpath or a Node-installed package-manager CLI.`,
        );
    }

    return entryPointPath;
};

export const resolvePackageManagerRunner = (
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): PackageManagerRunner => {
    const resolvedPackageManagerEntryPointPath =
        packageManagerEntryPointPath ??
        resolvePackageManagerEntryPoint(
            'pnpm',
            undefined,
            pathEnvironment,
            nodeExecutablePath,
            pathExists,
        );

    return {
        command: nodeExecutablePath,
        commandArgumentsPrefix: [resolvedPackageManagerEntryPointPath],
        kind: detectPackageManager(resolvedPackageManagerEntryPointPath),
    };
};

export const resolvePackageManagerRunnerForPackageManager = (
    packageManager: PackageManager,
    packageManagerEntryPointPath = process.env.npm_execpath,
    pathEnvironment: string = process.env.PATH ?? '',
    nodeExecutablePath: string = process.execPath,
    pathExists: (candidatePath: string) => boolean = existsSync,
): PackageManagerRunner => {
    const entryPointPath = resolvePackageManagerEntryPoint(
        packageManager,
        packageManagerEntryPointPath,
        pathEnvironment,
        nodeExecutablePath,
        pathExists,
    );

    return {
        command: nodeExecutablePath,
        commandArgumentsPrefix: [entryPointPath],
        kind: packageManager,
    };
};
