import { promises as fileSystem } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import {
    collectFiles,
    isWithinDirectory,
    toPosixPath,
} from '#tools/internal/files.js';
import { extractModuleSpecifiers } from '#tools/internal/module-specifiers.js';

type WorkspacePackage = {
    readonly directoryPath: string;
    readonly name: string;
    readonly sourceDirectoryPath: string;
};

type BoundaryViolation = {
    readonly filePath: string;
    readonly message: string;
};

const workspaceRoot = fileURLToPath(new URL('../../', import.meta.url));
const packagesDirectoryPath = path.resolve(workspaceRoot, 'packages');
const packageSourceExtensions = ['.ts'] as const;
const repositoryPrivateAliasPrefixes = [
    '#packages/',
    '#tests/',
    '#tools/',
    '#test-vectors/',
] as const;

// Encodes the intended package layering (types <- crypto <- wasm <- protocol <- sdk):
// each entry is the set of workspace packages that package may import.
// @sealed-lattice/types maps to an empty set, so it must stay dependency-free.
const allowedWorkspaceImportsByPackageName = new Map<
    string,
    ReadonlySet<string>
>([
    ['@sealed-lattice/types', new Set()],
    ['@sealed-lattice/crypto', new Set(['@sealed-lattice/types'])],
    ['@sealed-lattice/wasm', new Set(['@sealed-lattice/types'])],
    [
        '@sealed-lattice/protocol',
        new Set(['@sealed-lattice/crypto', '@sealed-lattice/types']),
    ],
    [
        'sealed-lattice',
        new Set([
            '@sealed-lattice/crypto',
            '@sealed-lattice/protocol',
            '@sealed-lattice/types',
            '@sealed-lattice/wasm',
        ]),
    ],
]);

const readJsonFile = async (filePath: string): Promise<unknown> =>
    JSON.parse(await fileSystem.readFile(filePath, 'utf8')) as unknown;

const readWorkspacePackages = async (): Promise<
    readonly WorkspacePackage[]
> => {
    const packageDirectories = await fileSystem.readdir(packagesDirectoryPath, {
        withFileTypes: true,
    });
    const packages: WorkspacePackage[] = [];

    for (const packageDirectory of packageDirectories) {
        if (!packageDirectory.isDirectory()) {
            continue;
        }

        const directoryPath = path.resolve(
            packagesDirectoryPath,
            packageDirectory.name,
        );
        const packageJson = await readJsonFile(
            path.resolve(directoryPath, 'package.json'),
        );
        if (
            typeof packageJson !== 'object' ||
            packageJson === null ||
            !('name' in packageJson) ||
            typeof packageJson.name !== 'string'
        ) {
            throw new Error(
                `${toPosixPath(path.relative(workspaceRoot, directoryPath))}/package.json must define a package name.`,
            );
        }

        packages.push({
            directoryPath,
            name: packageJson.name,
            sourceDirectoryPath: path.resolve(directoryPath, 'src'),
        });
    }

    return packages.sort((left, right) => left.name.localeCompare(right.name));
};

const findWorkspacePackageBySpecifier = (
    moduleSpecifier: string,
    workspacePackages: readonly WorkspacePackage[],
): WorkspacePackage | undefined =>
    workspacePackages.find(
        (workspacePackage) =>
            moduleSpecifier === workspacePackage.name ||
            moduleSpecifier.startsWith(`${workspacePackage.name}/`),
    );

const packageSourcePath = (
    workspacePackage: WorkspacePackage,
    filePath: string,
): string =>
    toPosixPath(path.relative(workspacePackage.sourceDirectoryPath, filePath));

const pushViolation = (
    violations: BoundaryViolation[],
    workspacePackage: WorkspacePackage,
    filePath: string,
    message: string,
): void => {
    violations.push({
        filePath: `${workspacePackage.name}:${packageSourcePath(workspacePackage, filePath)}`,
        message,
    });
};

const isRelativeModuleSpecifier = (moduleSpecifier: string): boolean =>
    moduleSpecifier.startsWith('./') || moduleSpecifier.startsWith('../');

const isRepositoryPrivateAlias = (moduleSpecifier: string): boolean =>
    repositoryPrivateAliasPrefixes.some((prefix) =>
        moduleSpecifier.startsWith(prefix),
    );

const checkRelativeSpecifier = (input: {
    readonly filePath: string;
    readonly moduleSpecifier: string;
    readonly violations: BoundaryViolation[];
    readonly workspacePackage: WorkspacePackage;
}): void => {
    const resolvedImportPath = path.resolve(
        path.dirname(input.filePath),
        input.moduleSpecifier,
    );
    if (
        !isWithinDirectory(
            input.workspacePackage.directoryPath,
            resolvedImportPath,
        )
    ) {
        pushViolation(
            input.violations,
            input.workspacePackage,
            input.filePath,
            `relative import crosses the package boundary: ${input.moduleSpecifier}`,
        );
    }
};

const checkWorkspacePackageSpecifier = (input: {
    readonly filePath: string;
    readonly moduleSpecifier: string;
    readonly violations: BoundaryViolation[];
    readonly workspacePackage: WorkspacePackage;
    readonly workspacePackages: readonly WorkspacePackage[];
}): void => {
    const importedPackage = findWorkspacePackageBySpecifier(
        input.moduleSpecifier,
        input.workspacePackages,
    );
    if (importedPackage === undefined) {
        return;
    }

    if (input.moduleSpecifier !== importedPackage.name) {
        pushViolation(
            input.violations,
            input.workspacePackage,
            input.filePath,
            `workspace package imports must use package entry points, not deep imports: ${input.moduleSpecifier}`,
        );
    }

    if (importedPackage.name === input.workspacePackage.name) {
        return;
    }

    const allowedImports = allowedWorkspaceImportsByPackageName.get(
        input.workspacePackage.name,
    );
    if (allowedImports?.has(importedPackage.name) === true) {
        return;
    }

    pushViolation(
        input.violations,
        input.workspacePackage,
        input.filePath,
        `${input.workspacePackage.name} must not import ${importedPackage.name}`,
    );
};

const checkModuleSpecifier = (input: {
    readonly filePath: string;
    readonly moduleSpecifier: string;
    readonly violations: BoundaryViolation[];
    readonly workspacePackage: WorkspacePackage;
    readonly workspacePackages: readonly WorkspacePackage[];
}): void => {
    if (isRepositoryPrivateAlias(input.moduleSpecifier)) {
        pushViolation(
            input.violations,
            input.workspacePackage,
            input.filePath,
            `package runtime source must not use repo-private aliases: ${input.moduleSpecifier}`,
        );
        return;
    }

    if (isRelativeModuleSpecifier(input.moduleSpecifier)) {
        checkRelativeSpecifier(input);
        return;
    }

    checkWorkspacePackageSpecifier(input);
};

export const checkPackageBoundaries = async (): Promise<
    readonly BoundaryViolation[]
> => {
    const workspacePackages = await readWorkspacePackages();
    const violations: BoundaryViolation[] = [];

    for (const workspacePackage of workspacePackages) {
        const sourceFiles = await collectFiles(
            workspacePackage.sourceDirectoryPath,
            {
                extensions: packageSourceExtensions,
            },
        );

        for (const filePath of sourceFiles) {
            const sourceText = await fileSystem.readFile(filePath, 'utf8');
            for (const moduleSpecifier of extractModuleSpecifiers(
                sourceText,
                filePath,
            )) {
                checkModuleSpecifier({
                    filePath,
                    moduleSpecifier,
                    violations,
                    workspacePackage,
                    workspacePackages,
                });
            }
        }
    }

    return violations;
};

const main = async (): Promise<void> => {
    const violations = await checkPackageBoundaries();
    if (violations.length > 0) {
        console.error('Package boundary verification failed:');
        for (const violation of violations) {
            console.error(`- ${violation.filePath}: ${violation.message}`);
        }
        process.exitCode = 1;
        return;
    }

    console.log('Package boundary verification passed.');
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
