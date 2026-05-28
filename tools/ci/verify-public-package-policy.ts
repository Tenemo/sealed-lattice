import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import publicSurfacePolicy from '#packages/sdk/public-surface.json' with { type: 'json' };

type VendoredProtocolRuntimeEntryExport = {
    readonly exports: readonly string[];
    readonly source: string;
};

type PublicPackagePolicy = {
    readonly forbiddenRuntimeExports: readonly string[];
    readonly vendoredProtocolRuntimeEntryExports: readonly VendoredProtocolRuntimeEntryExport[];
    readonly vendoredProtocolRuntimeModules: readonly string[];
};

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

const sortedUnique = (values: readonly string[]): string[] =>
    [...new Set(values)].sort((left, right) => left.localeCompare(right));

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

const isRelativeVendoredModulePath = (relativePath: string): boolean =>
    relativePath.endsWith('.ts') &&
    !relativePath.startsWith('/') &&
    !relativePath.startsWith('..') &&
    !path.isAbsolute(relativePath);

const validateUnique = (label: string, values: readonly string[]): string[] =>
    duplicates(values).map((value) => `${label} contains duplicate "${value}"`);

const validateVendoredProtocolRuntime = async (
    policy: PublicPackagePolicy,
    runtimeExports: ReadonlySet<string>,
): Promise<string[]> => {
    const failures: string[] = [];
    const vendoredModules = new Set(policy.vendoredProtocolRuntimeModules);

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
            if (!runtimeExports.has(exportName)) {
                failures.push(
                    `vendoredProtocolRuntimeEntryExports ${entry.source} exposes "${exportName}" outside the SDK runtime facade`,
                );
            }
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
        ...validateUnique(
            'forbiddenRuntimeExports',
            policy.forbiddenRuntimeExports,
        ),
    );

    for (const exportName of policy.forbiddenRuntimeExports) {
        if (runtimeExportSet.has(exportName)) {
            failures.push(`Forbidden runtime export is public: ${exportName}`);
        }
    }

    failures.push(
        ...(await validateVendoredProtocolRuntime(policy, runtimeExportSet)),
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
        publicSurfacePolicy as PublicPackagePolicy,
        await loadRuntimeExportNames(),
    );

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Public package policy verification passed.');
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
