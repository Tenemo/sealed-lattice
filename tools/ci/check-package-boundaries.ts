import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const packagesRoot = path.resolve(repoRoot, 'packages');
const codeFilePattern = /\.(?:cts|mts|ts|tsx|js|mjs)$/u;
const importSpecifierPattern =
    /\b(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\sfrom\s*)?['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/gu;

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
        '@sealed-lattice/protocol',
        '@sealed-lattice/crypto',
        '@sealed-lattice/wasm',
    ],
    '@sealed-lattice/protocol': [],
    '@sealed-lattice/crypto': [],
    '@sealed-lattice/wasm': [],
    '@sealed-lattice/testkit': [
        'sealed-lattice',
        '@sealed-lattice/protocol',
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

const isWithinDirectory = (
    directoryPath: string,
    candidatePath: string,
): boolean => {
    const relativePath = path.relative(directoryPath, candidatePath);

    return (
        relativePath === '' ||
        (!relativePath.startsWith('..') && !path.isAbsolute(relativePath))
    );
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

export const extractImportSpecifiers = (sourceText: string): string[] => {
    const specifiers = new Set<string>();

    for (const match of sourceText.matchAll(importSpecifierPattern)) {
        const specifier = match[1] ?? match[2];
        /* v8 ignore next */
        if (specifier !== undefined && specifier !== '') {
            specifiers.add(specifier);
        }
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
                    `${importObservation.packageName} deep-imports ${importObservation.specifier} from ${path.relative(repoRoot, importObservation.filePath).replace(/\\/g, '/')}`,
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
                `${importObservation.packageName} uses cross-package relative import ${importObservation.specifier} from ${path.relative(repoRoot, importObservation.filePath).replace(/\\/g, '/')} into ${targetPackage.name}`,
            );
        }
    }

    return failures;
};

/* v8 ignore start */
const collectCodeFiles = async (directoryPath: string): Promise<string[]> => {
    try {
        const stats = await fs.stat(directoryPath);
        if (!stats.isDirectory()) {
            return [];
        }
    } catch {
        return [];
    }

    const files: string[] = [];
    const pending = [directoryPath];

    while (pending.length > 0) {
        const currentDirectoryPath = pending.pop();
        if (currentDirectoryPath === undefined) {
            continue;
        }

        const entries = await fs.readdir(currentDirectoryPath, {
            withFileTypes: true,
        });

        for (const entry of entries) {
            const entryPath = path.join(currentDirectoryPath, entry.name);
            if (entry.isDirectory()) {
                pending.push(entryPath);
                continue;
            }

            if (entry.isFile() && codeFilePattern.test(entry.name)) {
                files.push(entryPath);
            }
        }
    }

    return files.sort();
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
