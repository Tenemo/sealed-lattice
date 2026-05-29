import { promises as fileSystem } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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
const testVectorsDirectoryPath = path.resolve(workspaceRoot, 'test-vectors');
const testsDirectoryPath = path.resolve(workspaceRoot, 'tests');
const testSupportDirectoryPath = path.resolve(testsDirectoryPath, 'support');
const toolsDirectoryPath = path.resolve(workspaceRoot, 'tools');
const typedocToolsDirectoryPath = path.resolve(
    workspaceRoot,
    'docs',
    'typedoc',
);
const packageSourceExtensions = ['.ts', '.tsx', '.mts', '.cts'] as const;
const repositoryImportPolicyExtensions = [
    '.ts',
    '.tsx',
    '.mts',
    '.cts',
    '.js',
    '.mjs',
    '.cjs',
] as const;
const repositoryPrivateAliasPrefixes = [
    '#packages/',
    '#tests/',
    '#tools/',
    '#test-vectors/',
] as const;

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

const workspacePath = (filePath: string): string =>
    toPosixPath(path.relative(workspaceRoot, filePath));

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

const pushFileViolation = (
    violations: BoundaryViolation[],
    filePath: string,
    message: string,
): void => {
    violations.push({
        filePath: workspacePath(filePath),
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

const packageSourceAliasForTarget = (
    targetPath: string,
    workspacePackages: readonly WorkspacePackage[],
): string | undefined => {
    const targetPackage = workspacePackages.find((workspacePackage) =>
        isWithinDirectory(workspacePackage.sourceDirectoryPath, targetPath),
    );
    if (targetPackage === undefined) {
        return undefined;
    }

    const packageDirectoryName = path.basename(targetPackage.directoryPath);
    const packageSourceRelativePath = toPosixPath(
        path.relative(targetPackage.sourceDirectoryPath, targetPath),
    );

    return `#packages/${packageDirectoryName}/src/${packageSourceRelativePath}`;
};

const repositoryAliasForTarget = (
    filePath: string,
    moduleSpecifier: string,
    workspacePackages: readonly WorkspacePackage[],
): string | undefined => {
    if (!isRelativeModuleSpecifier(moduleSpecifier)) {
        return undefined;
    }

    const targetPath = path.resolve(path.dirname(filePath), moduleSpecifier);
    const packageSourceAlias = packageSourceAliasForTarget(
        targetPath,
        workspacePackages,
    );
    if (packageSourceAlias !== undefined) {
        return packageSourceAlias;
    }

    if (isWithinDirectory(testVectorsDirectoryPath, targetPath)) {
        return `#test-vectors/${toPosixPath(path.relative(testVectorsDirectoryPath, targetPath))}`;
    }

    const fileIsInTestSupport = isWithinDirectory(
        testSupportDirectoryPath,
        filePath,
    );
    if (
        !fileIsInTestSupport &&
        isWithinDirectory(testSupportDirectoryPath, targetPath)
    ) {
        return `#tests/${toPosixPath(path.relative(testsDirectoryPath, targetPath))}`;
    }

    const fileIsInTools = isWithinDirectory(toolsDirectoryPath, filePath);
    const targetIsInTools = isWithinDirectory(toolsDirectoryPath, targetPath);
    if (!targetIsInTools) {
        return undefined;
    }

    if (!fileIsInTools) {
        return `#tools/${toPosixPath(path.relative(toolsDirectoryPath, targetPath))}`;
    }

    const [fileToolArea] = toPosixPath(
        path.relative(toolsDirectoryPath, filePath),
    ).split('/');
    const [targetToolArea] = toPosixPath(
        path.relative(toolsDirectoryPath, targetPath),
    ).split('/');

    return moduleSpecifier.startsWith('../') && fileToolArea !== targetToolArea
        ? `#tools/${toPosixPath(path.relative(toolsDirectoryPath, targetPath))}`
        : undefined;
};

const collectRepositoryImportPolicyFiles = async (
    workspacePackages: readonly WorkspacePackage[],
): Promise<readonly string[]> => {
    const filePaths = new Set<string>();
    const addFiles = async (directoryPath: string): Promise<void> => {
        const files = await collectFiles(directoryPath, {
            allowMissing: true,
            extensions: repositoryImportPolicyExtensions,
        });
        for (const filePath of files) {
            filePaths.add(filePath);
        }
    };

    for (const workspacePackage of workspacePackages) {
        await addFiles(path.resolve(workspacePackage.directoryPath, 'tests'));
    }

    await addFiles(testsDirectoryPath);
    await addFiles(toolsDirectoryPath);
    await addFiles(typedocToolsDirectoryPath);

    return [...filePaths].sort();
};

const checkRepositoryImportPolicy = async (
    workspacePackages: readonly WorkspacePackage[],
    violations: BoundaryViolation[],
): Promise<void> => {
    const files = await collectRepositoryImportPolicyFiles(workspacePackages);

    for (const filePath of files) {
        const sourceText = await fileSystem.readFile(filePath, 'utf8');
        for (const moduleSpecifier of extractModuleSpecifiers(
            sourceText,
            filePath,
        )) {
            const alias = repositoryAliasForTarget(
                filePath,
                moduleSpecifier,
                workspacePackages,
            );
            if (alias === undefined) {
                continue;
            }

            pushFileViolation(
                violations,
                filePath,
                `test and tooling imports that cross repository boundaries must use ${alias} instead of ${moduleSpecifier}`,
            );
        }
    }
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

    await checkRepositoryImportPolicy(workspacePackages, violations);

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

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
