import { existsSync } from 'node:fs';
import path from 'node:path';

type PackageManager = 'npm' | 'pnpm';

export type PackageManagerRunner = {
    readonly command: string;
    readonly commandArgumentsPrefix: readonly string[];
};

const detectPackageManager = (
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

const buildPackageManagerEntryPointCandidates = (
    packageManager: PackageManager,
): readonly string[] => {
    const nodeDirectoryPath = path.dirname(process.execPath);
    const pathDirectoryPaths = (process.env.PATH ?? '')
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

const resolvePackageManagerEntryPoint = (
    packageManager: PackageManager,
): string => {
    const packageManagerEntryPointPath = process.env.npm_execpath;
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

    const entryPointPath =
        buildPackageManagerEntryPointCandidates(packageManager).find(
            existsSync,
        );

    if (entryPointPath === undefined) {
        throw new Error(
            `Cannot find a Node entry point for ${packageManager}. Avoid shell shims and run through npm_execpath or a Node-installed package-manager CLI.`,
        );
    }

    return entryPointPath;
};

// A JavaScript entry point runs under this Node. A native package-manager
// executable, such as the binary pnpm itself ships, runs directly.
const runnerFor = (entryPointPath: string): PackageManagerRunner =>
    /\.[cm]?js$/iu.test(entryPointPath)
        ? {
              command: process.execPath,
              commandArgumentsPrefix: [entryPointPath],
          }
        : { command: entryPointPath, commandArgumentsPrefix: [] };

export const resolvePackageManagerRunner = (): PackageManagerRunner =>
    runnerFor(
        process.env.npm_execpath ?? resolvePackageManagerEntryPoint('pnpm'),
    );

export const resolvePackageManagerRunnerForPackageManager = (
    packageManager: PackageManager,
): PackageManagerRunner =>
    runnerFor(resolvePackageManagerEntryPoint(packageManager));
