import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    publicPackagePolicy,
    type PublicPackagePolicy,
} from './public-package-policy.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';
import { extractModuleSpecifiers } from '#tools/internal/module-specifiers.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkRuntimePath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'dist',
    'index.js',
);
const protocolSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'protocol',
    'src',
);
const cryptoSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'crypto',
    'src',
);

const sortedUnique = (values: readonly string[]): string[] =>
    [...new Set(values)].sort((left, right) => left.localeCompare(right));

const toPosixPath = (filePath: string): string =>
    filePath.split(path.sep).join('/');

const duplicates = (values: readonly string[]): string[] => {
    const seen = new Set<string>();
    const duplicateValues = new Set<string>();

    for (const value of values) {
        if (seen.has(value)) {
            duplicateValues.add(value);
        }
        seen.add(value);
    }

    return [...duplicateValues].sort((left, right) =>
        left.localeCompare(right),
    );
};

const protocolRuntimeSourcePathForEntrySource = (source: string): string =>
    source.replace(/\.js$/u, '.ts');

const runtimeSourcePathForSpecifier = (
    runtimeSourceDirectoryPath: string,
    sourceRelativePath: string,
    moduleSpecifier: string,
): string | undefined => {
    if (!moduleSpecifier.startsWith('.')) {
        return undefined;
    }

    const sourceDirectoryPath = path.dirname(
        path.resolve(runtimeSourceDirectoryPath, sourceRelativePath),
    );
    const sourceModulePath = path.resolve(sourceDirectoryPath, moduleSpecifier);
    const sourcePath = sourceModulePath.endsWith('.js')
        ? sourceModulePath.replace(/\.js$/u, '.ts')
        : sourceModulePath;
    const relativeSourcePath = toPosixPath(
        path.relative(runtimeSourceDirectoryPath, sourcePath),
    );

    if (
        relativeSourcePath.startsWith('../') ||
        path.isAbsolute(relativeSourcePath)
    ) {
        return undefined;
    }

    return relativeSourcePath;
};

const isRelativeVendoredModulePath = (relativePath: string): boolean =>
    relativePath.endsWith('.ts') &&
    !relativePath.startsWith('/') &&
    !relativePath.startsWith('..') &&
    !path.isAbsolute(relativePath);

const validateUnique = (label: string, values: readonly string[]): string[] =>
    duplicates(values).map((value) => `${label} contains duplicate "${value}"`);

const collectReachableVendoredRuntimeModules = async (
    runtimeSourceDirectoryPath: string,
    entrySources: readonly string[],
    missingSourceLabel: string,
    unsupportedModuleLabel: string,
): Promise<{
    readonly failures: readonly string[];
    readonly reachableModules: ReadonlySet<string>;
}> => {
    const failures: string[] = [];
    const reachableModules = new Set<string>();
    const pendingModules = [...entrySources];

    while (pendingModules.length > 0) {
        const relativeSourcePath = pendingModules.pop();
        if (relativeSourcePath === undefined) {
            continue;
        }
        if (reachableModules.has(relativeSourcePath)) {
            continue;
        }
        reachableModules.add(relativeSourcePath);

        const absoluteSourcePath = path.resolve(
            runtimeSourceDirectoryPath,
            relativeSourcePath,
        );
        let sourceText: string;
        try {
            sourceText = await fs.readFile(absoluteSourcePath, 'utf8');
        } catch {
            failures.push(
                `${missingSourceLabel} reaches missing source "${relativeSourcePath}"`,
            );
            continue;
        }

        for (const moduleSpecifier of extractModuleSpecifiers(
            sourceText,
            absoluteSourcePath,
        )) {
            const dependencySourcePath = runtimeSourcePathForSpecifier(
                runtimeSourceDirectoryPath,
                relativeSourcePath,
                moduleSpecifier,
            );
            if (dependencySourcePath === undefined) {
                continue;
            }
            if (!dependencySourcePath.endsWith('.ts')) {
                failures.push(
                    `${unsupportedModuleLabel} source "${relativeSourcePath}" imports unsupported local module "${moduleSpecifier}"`,
                );
                continue;
            }
            if (!reachableModules.has(dependencySourcePath)) {
                pendingModules.push(dependencySourcePath);
            }
        }
    }

    return {
        failures,
        reachableModules,
    };
};

const validateVendoredProtocolRuntime = async (
    policy: PublicPackagePolicy,
    runtimeExports: ReadonlySet<string>,
): Promise<string[]> => {
    const failures: string[] = [];
    const vendoredModules = new Set(policy.vendoredProtocolRuntimeModules);
    const entrySourcePaths = policy.vendoredProtocolRuntimeEntryExports.map(
        (entry) => protocolRuntimeSourcePathForEntrySource(entry.source),
    );

    failures.push(
        ...validateUnique(
            'vendoredProtocolRuntimeModules',
            policy.vendoredProtocolRuntimeModules,
        ),
        ...validateUnique(
            'vendoredProtocolRuntimeEntryExports sources',
            policy.vendoredProtocolRuntimeEntryExports.map(
                (entry) => entry.source,
            ),
        ),
    );

    for (const relativeSourcePath of policy.vendoredProtocolRuntimeModules) {
        if (!isRelativeVendoredModulePath(relativeSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeModules contains invalid path "${relativeSourcePath}"`,
            );
            continue;
        }

        try {
            await fs.access(
                path.resolve(protocolSourceDirectoryPath, relativeSourcePath),
            );
        } catch {
            failures.push(
                `vendoredProtocolRuntimeModules references missing source "${relativeSourcePath}"`,
            );
        }
    }

    for (const entry of policy.vendoredProtocolRuntimeEntryExports) {
        failures.push(
            ...validateUnique(
                `vendoredProtocolRuntimeEntryExports ${entry.source}`,
                entry.exports,
            ),
        );

        if (!entry.source.endsWith('.js')) {
            failures.push(
                `vendoredProtocolRuntimeEntryExports source "${entry.source}" must end with .js`,
            );
            continue;
        }

        const relativeSourcePath = protocolRuntimeSourcePathForEntrySource(
            entry.source,
        );
        if (!vendoredModules.has(relativeSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeEntryExports source "${entry.source}" is not listed in vendoredProtocolRuntimeModules`,
            );
        }

        for (const exportName of entry.exports) {
            if (
                entry.runtimeVisibility === 'public' &&
                !runtimeExports.has(exportName)
            ) {
                failures.push(
                    `vendoredProtocolRuntimeEntryExports ${entry.source} exposes "${exportName}" outside the SDK runtime facade`,
                );
            }
            if (
                entry.runtimeVisibility === 'internal' &&
                runtimeExports.has(exportName)
            ) {
                failures.push(
                    `vendoredProtocolRuntimeEntryExports ${entry.source} marks "${exportName}" internal but the SDK runtime exports it`,
                );
            }
        }
    }

    const reachableRuntimeModules =
        await collectReachableVendoredRuntimeModules(
            protocolSourceDirectoryPath,
            entrySourcePaths,
            'vendoredProtocolRuntimeEntryExports',
            'vendored protocol runtime',
        );
    failures.push(...reachableRuntimeModules.failures);

    for (const reachableSourcePath of reachableRuntimeModules.reachableModules) {
        if (!vendoredModules.has(reachableSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeModules is missing reachable source "${reachableSourcePath}"`,
            );
        }
    }
    for (const relativeSourcePath of policy.vendoredProtocolRuntimeModules) {
        if (!reachableRuntimeModules.reachableModules.has(relativeSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeModules includes unreachable source "${relativeSourcePath}"`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

const validateVendoredCryptoRuntime = async (
    policy: PublicPackagePolicy,
): Promise<string[]> => {
    const failures: string[] = [];
    const vendoredModules = new Set(policy.vendoredCryptoRuntimeModules);

    failures.push(
        ...validateUnique(
            'vendoredCryptoRuntimeModules',
            policy.vendoredCryptoRuntimeModules,
        ),
    );

    for (const relativeSourcePath of policy.vendoredCryptoRuntimeModules) {
        if (!isRelativeVendoredModulePath(relativeSourcePath)) {
            failures.push(
                `vendoredCryptoRuntimeModules contains invalid path "${relativeSourcePath}"`,
            );
            continue;
        }

        try {
            await fs.access(
                path.resolve(cryptoSourceDirectoryPath, relativeSourcePath),
            );
        } catch {
            failures.push(
                `vendoredCryptoRuntimeModules references missing source "${relativeSourcePath}"`,
            );
        }
    }

    const reachableRuntimeModules =
        await collectReachableVendoredRuntimeModules(
            cryptoSourceDirectoryPath,
            ['index.ts'],
            'vendoredCryptoRuntimeModules',
            'vendored crypto runtime',
        );
    failures.push(...reachableRuntimeModules.failures);

    for (const reachableSourcePath of reachableRuntimeModules.reachableModules) {
        if (!vendoredModules.has(reachableSourcePath)) {
            failures.push(
                `vendoredCryptoRuntimeModules is missing reachable source "${reachableSourcePath}"`,
            );
        }
    }
    for (const relativeSourcePath of policy.vendoredCryptoRuntimeModules) {
        if (!reachableRuntimeModules.reachableModules.has(relativeSourcePath)) {
            failures.push(
                `vendoredCryptoRuntimeModules includes unreachable source "${relativeSourcePath}"`,
            );
        }
    }

    return failures.sort((left, right) => left.localeCompare(right));
};

export const validatePublicPackagePolicy = async (
    policy: PublicPackagePolicy,
    runtimeExports: readonly string[],
): Promise<string[]> => {
    const failures: string[] = [];
    const runtimeExportSet = new Set(runtimeExports);

    failures.push(
        ...(await validateVendoredProtocolRuntime(policy, runtimeExportSet)),
        ...(await validateVendoredCryptoRuntime(policy)),
    );

    return sortedUnique(failures);
};

const loadRuntimeExportNames = async (): Promise<string[]> => {
    const runtimeModule = (await import(
        pathToFileURL(sdkRuntimePath).href
    )) as Record<string, unknown>;

    return Object.keys(runtimeModule).sort((left, right) =>
        left.localeCompare(right),
    );
};

const main = async (): Promise<void> => {
    const failures = await validatePublicPackagePolicy(
        publicPackagePolicy,
        await loadRuntimeExportNames(),
    );

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Public package policy verification passed.');
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
