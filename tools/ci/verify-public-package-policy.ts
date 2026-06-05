import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    publicPackagePolicy,
    type PublicPackagePolicy,
} from './public-package-policy.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

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
    typeExports: readonly string[] = [],
): Promise<string[]> => {
    const failures: string[] = [];
    const runtimeExportSet = new Set(runtimeExports);
    const typeExportSet = new Set(typeExports);

    failures.push(
        ...validateUnique('forbiddenTypeExports', policy.forbiddenTypeExports),
    );

    for (const exportName of policy.forbiddenTypeExports) {
        if (typeExportSet.has(exportName)) {
            failures.push(`Forbidden type export is public: ${exportName}`);
        }
    }

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

export const collectEntryPointTypeExportNames = (
    declarationText: string,
): string[] => {
    const exportNames: string[] = [];
    const namedExportPattern =
        /export\s+type\s*\{(?<body>[^}]+)\}\s*from\s*['"][^'"]+['"]/gu;
    const typeDeclarationPattern =
        /export\s+(?:declare\s+)?(?:type|interface)\s+(?<name>[A-Za-z_$][\w$]*)/gu;

    for (const match of declarationText.matchAll(namedExportPattern)) {
        const body = match.groups?.body;
        if (body === undefined) {
            continue;
        }
        exportNames.push(
            ...body
                .split(',')
                .map((part) => part.trim())
                .filter((part) => part.length > 0)
                .map((part) => {
                    const [exportName] = part.split(/\s+as\s+/u);

                    return exportName.trim();
                }),
        );
    }

    for (const match of declarationText.matchAll(typeDeclarationPattern)) {
        const exportName = match.groups?.name;
        if (exportName !== undefined) {
            exportNames.push(exportName);
        }
    }

    return sortedUnique(exportNames);
};

const loadEntryPointTypeExportNames = async (): Promise<string[]> =>
    collectEntryPointTypeExportNames(
        await fs.readFile(
            path.resolve(repoRoot, 'packages', 'sdk', 'dist', 'index.d.ts'),
            'utf8',
        ),
    );

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
        await loadEntryPointTypeExportNames(),
    );

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Public package policy verification passed.');
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
