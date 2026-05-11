import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    ScriptKind,
    ScriptTarget,
    SyntaxKind,
    createSourceFile,
    forEachChild,
    isCallExpression,
    isExportDeclaration,
    isImportDeclaration,
    isImportTypeNode,
    isLiteralTypeNode,
    isStringLiteral,
    type Node,
    type StringLiteral,
} from 'typescript';

import {
    collectFiles,
    isWithinDirectory,
    toPosixPath,
} from '../internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const packagesRoot = path.resolve(repoRoot, 'packages');
const codeFilePattern = /\.(?:cts|mts|ts|tsx|js|mjs)$/u;

export type WorkspacePackage = {
    directoryPath: string;
    internalDependencies: readonly string[];
    name: string;
};

export type ImportObservation = {
    filePath: string;
    packageName: string;
    specifier: string;
};

export const allowedInternalDependencyMap = {
    'sealed-lattice': [
        '@sealed-lattice/types',
        '@sealed-lattice/protocol',
        '@sealed-lattice/crypto',
        '@sealed-lattice/wasm',
    ],
    '@sealed-lattice/types': [],
    '@sealed-lattice/protocol': [
        '@sealed-lattice/crypto',
        '@sealed-lattice/types',
    ],
    '@sealed-lattice/crypto': ['@sealed-lattice/types'],
    '@sealed-lattice/wasm': ['@sealed-lattice/types'],
    '@sealed-lattice/testkit': [
        'sealed-lattice',
        '@sealed-lattice/types',
        '@sealed-lattice/crypto',
        '@sealed-lattice/wasm',
    ],
} as const satisfies Record<string, readonly string[]>;

type PackageJsonShape = {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    name: string;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
};

export const collectInternalDependencies = (
    packageJson: PackageJsonShape,
    workspacePackageNames: readonly string[],
): string[] => {
    const dependencyNames = new Set<string>([
        ...Object.keys(packageJson.dependencies ?? {}),
        ...Object.keys(packageJson.devDependencies ?? {}),
        ...Object.keys(packageJson.optionalDependencies ?? {}),
        ...Object.keys(packageJson.peerDependencies ?? {}),
    ]);

    return [...dependencyNames]
        .filter((dependencyName) =>
            workspacePackageNames.includes(dependencyName),
        )
        .sort();
};

const collectImportSpecifierLiterals = (
    sourceText: string,
): readonly StringLiteral[] => {
    const sourceFile = createSourceFile(
        'package-boundary-source.tsx',
        sourceText,
        ScriptTarget.Latest,
        true,
        ScriptKind.TSX,
    );
    const specifiers: StringLiteral[] = [];

    const visit = (node: Node): void => {
        if (
            isImportDeclaration(node) &&
            isStringLiteral(node.moduleSpecifier)
        ) {
            specifiers.push(node.moduleSpecifier);
        } else if (
            isExportDeclaration(node) &&
            node.moduleSpecifier !== undefined &&
            isStringLiteral(node.moduleSpecifier)
        ) {
            specifiers.push(node.moduleSpecifier);
        } else if (
            isCallExpression(node) &&
            node.expression.kind === SyntaxKind.ImportKeyword
        ) {
            const [moduleSpecifier] = node.arguments;
            if (
                moduleSpecifier !== undefined &&
                isStringLiteral(moduleSpecifier)
            ) {
                specifiers.push(moduleSpecifier);
            }
        } else if (isImportTypeNode(node)) {
            const importTypeArgument = node.argument;
            if (
                isLiteralTypeNode(importTypeArgument) &&
                isStringLiteral(importTypeArgument.literal)
            ) {
                specifiers.push(importTypeArgument.literal);
            }
        }

        forEachChild(node, visit);
    };

    visit(sourceFile);

    return specifiers;
};

export const extractImportSpecifiers = (sourceText: string): string[] => {
    const specifiers = new Set<string>();

    for (const moduleSpecifier of collectImportSpecifierLiterals(sourceText)) {
        specifiers.add(moduleSpecifier.text);
    }

    return [...specifiers];
};

export const validateDeclaredInternalDependencies = (
    workspacePackages: readonly WorkspacePackage[],
): string[] => {
    const failures: string[] = [];

    for (const workspacePackage of workspacePackages) {
        const allowedDependencies: string[] = [
            ...(allowedInternalDependencyMap[
                workspacePackage.name as keyof typeof allowedInternalDependencyMap
            ] ?? []),
        ];

        for (const dependencyName of workspacePackage.internalDependencies) {
            if (!allowedDependencies.includes(dependencyName)) {
                failures.push(
                    `${workspacePackage.name} declares forbidden internal dependency ${dependencyName}`,
                );
            }
        }
    }

    return failures;
};

export const findDependencyCycleFailures = (
    workspacePackages: readonly WorkspacePackage[],
): string[] => {
    const dependencyMap = new Map(
        workspacePackages.map((workspacePackage) => [
            workspacePackage.name,
            workspacePackage.internalDependencies,
        ]),
    );
    const visited = new Set<string>();
    const activeStack: string[] = [];
    const reportedCycles = new Set<string>();

    const visitPackage = (packageName: string): void => {
        if (activeStack.includes(packageName)) {
            const cycleStartIndex = activeStack.indexOf(packageName);
            const cyclePath = [
                ...activeStack.slice(cycleStartIndex),
                packageName,
            ];
            reportedCycles.add(cyclePath.join(' -> '));
            return;
        }

        if (visited.has(packageName)) {
            return;
        }

        visited.add(packageName);
        activeStack.push(packageName);

        /* v8 ignore next */
        for (const dependencyName of dependencyMap.get(packageName) ?? []) {
            visitPackage(dependencyName);
        }

        activeStack.pop();
    };

    for (const workspacePackage of workspacePackages) {
        visitPackage(workspacePackage.name);
    }

    return [...reportedCycles].sort();
};

export const validateImportBoundaries = (
    workspacePackages: readonly WorkspacePackage[],
    importObservations: readonly ImportObservation[],
): string[] => {
    const failures: string[] = [];
    const workspacePackageNames = workspacePackages.map(
        (workspacePackage) => workspacePackage.name,
    );
    const workspacePackageNameSet = new Set(workspacePackageNames);
    const workspacePackageByName = new Map(
        workspacePackages.map((workspacePackage) => [
            workspacePackage.name,
            workspacePackage,
        ]),
    );

    for (const importObservation of importObservations) {
        const sourcePackage = workspacePackageByName.get(
            importObservation.packageName,
        );
        if (sourcePackage === undefined) {
            continue;
        }

        for (const workspacePackageName of workspacePackageNames) {
            if (
                importObservation.specifier.startsWith(
                    `${workspacePackageName}/`,
                )
            ) {
                failures.push(
                    `${importObservation.packageName} deep-imports ${importObservation.specifier} from ${toPosixPath(path.relative(repoRoot, importObservation.filePath))}`,
                );
                break;
            }
        }

        if (workspacePackageNameSet.has(importObservation.specifier)) {
            const targetPackage = workspacePackageByName.get(
                importObservation.specifier,
            );
            if (targetPackage?.name === sourcePackage.name) {
                continue;
            }
            if (
                targetPackage !== undefined &&
                !sourcePackage.internalDependencies.includes(targetPackage.name)
            ) {
                failures.push(
                    `${importObservation.packageName} imports undeclared internal package ${targetPackage.name} from ${path.relative(repoRoot, importObservation.filePath).replace(/\\/g, '/')}`,
                );
            }
            continue;
        }

        if (!importObservation.specifier.startsWith('.')) {
            continue;
        }

        const resolvedTargetPath = path.resolve(
            path.dirname(importObservation.filePath),
            importObservation.specifier,
        );
        const targetPackage = workspacePackages.find((workspacePackage) =>
            isWithinDirectory(
                workspacePackage.directoryPath,
                resolvedTargetPath,
            ),
        );

        if (
            targetPackage !== undefined &&
            targetPackage.name !== importObservation.packageName
        ) {
            failures.push(
                `${importObservation.packageName} uses cross-package relative import ${importObservation.specifier} from ${toPosixPath(path.relative(repoRoot, importObservation.filePath))} into ${targetPackage.name}`,
            );
        }
    }

    return failures;
};

/* v8 ignore start */
const collectCodeFiles = async (directoryPath: string): Promise<string[]> => {
    return collectFiles(directoryPath, {
        allowMissing: true,
        fileNamePattern: codeFilePattern,
    });
};

const loadWorkspacePackages = async (): Promise<WorkspacePackage[]> => {
    const entries = await fs.readdir(packagesRoot, { withFileTypes: true });
    const packageJsonPaths = entries
        .filter((entry) => entry.isDirectory())
        .map((entry) => path.join(packagesRoot, entry.name, 'package.json'));
    const packageJsonContents = await Promise.all(
        packageJsonPaths.map(async (packageJsonPath) => ({
            directoryPath: path.dirname(packageJsonPath),
            packageJson: JSON.parse(
                await fs.readFile(packageJsonPath, 'utf8'),
            ) as PackageJsonShape,
        })),
    );
    const workspacePackageNames = packageJsonContents.map(
        ({ packageJson }) => packageJson.name,
    );

    return packageJsonContents.map(({ directoryPath, packageJson }) => ({
        directoryPath,
        internalDependencies: collectInternalDependencies(
            packageJson,
            workspacePackageNames,
        ),
        name: packageJson.name,
    }));
};

const collectImportObservations = async (
    workspacePackages: readonly WorkspacePackage[],
): Promise<ImportObservation[]> => {
    const importObservations: ImportObservation[] = [];

    for (const workspacePackage of workspacePackages) {
        const codeFiles = [
            ...(await collectCodeFiles(
                path.join(workspacePackage.directoryPath, 'src'),
            )),
            ...(await collectCodeFiles(
                path.join(workspacePackage.directoryPath, 'tests'),
            )),
        ];

        for (const filePath of codeFiles) {
            const sourceText = await fs.readFile(filePath, 'utf8');
            for (const specifier of extractImportSpecifiers(sourceText)) {
                importObservations.push({
                    filePath,
                    packageName: workspacePackage.name,
                    specifier,
                });
            }
        }
    }

    return importObservations;
};

const main = async (): Promise<void> => {
    const workspacePackages = await loadWorkspacePackages();
    const importObservations =
        await collectImportObservations(workspacePackages);
    const failures = [
        ...validateDeclaredInternalDependencies(workspacePackages),
        ...findDependencyCycleFailures(workspacePackages).map(
            (cyclePath) => `Dependency cycle detected: ${cyclePath}`,
        ),
        ...validateImportBoundaries(workspacePackages, importObservations),
    ];

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
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
/* v8 ignore stop */
