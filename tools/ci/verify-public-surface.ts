import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    ScriptKind,
    ScriptTarget,
    SyntaxKind,
    canHaveModifiers,
    createSourceFile,
    forEachChild,
    getModifiers,
    isClassDeclaration,
    isEnumDeclaration,
    isExportDeclaration,
    isFunctionDeclaration,
    isIdentifier,
    isInterfaceDeclaration,
    isNamedExports,
    isTypeAliasDeclaration,
    isVariableStatement,
    type BindingName,
    type Node,
} from 'typescript';

import publicSurfaceManifest from '#packages/sdk/public-surface.json' with { type: 'json' };

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkFacadeSourcePath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'src',
    'index.ts',
);
const protocolSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'protocol',
    'src',
);

export type VendoredProtocolRuntimeEntryExport = {
    readonly exports: readonly string[];
    readonly source: string;
};

export type PublicSurfaceManifest = {
    readonly forbiddenRuntimeExports: readonly string[];
    readonly publicTypeExports: readonly string[];
    readonly runtimeExports: readonly string[];
    readonly vendoredProtocolRuntimeEntryExports: readonly VendoredProtocolRuntimeEntryExport[];
    readonly vendoredProtocolRuntimeModules: readonly string[];
};

export type SourceExportNames = {
    readonly runtimeExports: readonly string[];
    readonly typeExports: readonly string[];
    readonly unsupportedExportDeclarations: readonly string[];
};

export type PublicSurfaceValidationInput = {
    readonly publicSurface: PublicSurfaceManifest;
    readonly protocolRuntimeModuleTextByRelativePath: ReadonlyMap<
        string,
        string
    >;
    readonly sdkFacadeSourcePath?: string;
    readonly sdkFacadeSourceText: string;
};

const sortedUnique = (values: readonly string[]): string[] =>
    [...new Set(values)].sort();

const hasExportModifier = (node: Node): boolean =>
    canHaveModifiers(node) &&
    (getModifiers(node)?.some(
        (modifier) => modifier.kind === SyntaxKind.ExportKeyword,
    ) ??
        false);

const collectBindingNames = (bindingName: BindingName): string[] => {
    if (isIdentifier(bindingName)) {
        return [bindingName.text];
    }

    const names: string[] = [];
    for (const element of bindingName.elements) {
        if (element.kind === SyntaxKind.OmittedExpression) {
            continue;
        }
        names.push(...collectBindingNames(element.name));
    }

    return names;
};

export const collectSourceExportNames = (
    sourceText: string,
    sourcePath = 'public-surface-source.ts',
): SourceExportNames => {
    const sourceFile = createSourceFile(
        sourcePath,
        sourceText,
        ScriptTarget.Latest,
        true,
        ScriptKind.TS,
    );
    const runtimeExports = new Set<string>();
    const typeExports = new Set<string>();
    const unsupportedExportDeclarations: string[] = [];

    const addExportDeclarationNames = (node: Node): void => {
        if (!isExportDeclaration(node)) {
            return;
        }
        if (node.exportClause === undefined) {
            unsupportedExportDeclarations.push(
                `${sourcePath}: export star declarations are not supported by public-surface verification`,
            );
            return;
        }
        if (!isNamedExports(node.exportClause)) {
            unsupportedExportDeclarations.push(
                `${sourcePath}: namespace export declarations are not supported by public-surface verification`,
            );
            return;
        }

        const targetSet = node.isTypeOnly ? typeExports : runtimeExports;
        for (const exportSpecifier of node.exportClause.elements) {
            targetSet.add(exportSpecifier.name.text);
        }
    };

    const visit = (node: Node): void => {
        if (isVariableStatement(node) && hasExportModifier(node)) {
            for (const declaration of node.declarationList.declarations) {
                for (const exportName of collectBindingNames(
                    declaration.name,
                )) {
                    runtimeExports.add(exportName);
                }
            }
        } else if (
            isFunctionDeclaration(node) &&
            hasExportModifier(node) &&
            node.name !== undefined
        ) {
            runtimeExports.add(node.name.text);
        } else if (
            isClassDeclaration(node) &&
            hasExportModifier(node) &&
            node.name !== undefined
        ) {
            runtimeExports.add(node.name.text);
        } else if (
            isEnumDeclaration(node) &&
            hasExportModifier(node) &&
            node.name !== undefined
        ) {
            runtimeExports.add(node.name.text);
        } else if (isTypeAliasDeclaration(node) && hasExportModifier(node)) {
            typeExports.add(node.name.text);
        } else if (isInterfaceDeclaration(node) && hasExportModifier(node)) {
            typeExports.add(node.name.text);
        } else if (isExportDeclaration(node)) {
            addExportDeclarationNames(node);
        }

        forEachChild(node, visit);
    };

    visit(sourceFile);

    return {
        runtimeExports: sortedUnique([...runtimeExports]),
        typeExports: sortedUnique([...typeExports]),
        unsupportedExportDeclarations,
    };
};

const assertSortedUnique = (
    label: string,
    values: readonly string[],
): string[] => {
    const expected = sortedUnique(values);

    return values.length === expected.length &&
        values.every((value, index) => value === expected[index])
        ? []
        : [`${label} must be sorted and unique`];
};

const compareExactList = (
    label: string,
    actual: readonly string[],
    expected: readonly string[],
): string[] => {
    const sortedActual = sortedUnique(actual);
    const sortedExpected = sortedUnique(expected);

    if (
        sortedActual.length === sortedExpected.length &&
        sortedActual.every((value, index) => value === sortedExpected[index])
    ) {
        return [];
    }

    const actualSet = new Set(sortedActual);
    const expectedSet = new Set(sortedExpected);
    const missing = sortedExpected.filter((value) => !actualSet.has(value));
    const unexpected = sortedActual.filter((value) => !expectedSet.has(value));
    const failures: string[] = [];

    for (const value of missing) {
        failures.push(`${label} is missing "${value}"`);
    }
    for (const value of unexpected) {
        failures.push(`${label} contains unexpected "${value}"`);
    }

    return failures;
};

const protocolRuntimeSourcePathForEntrySource = (source: string): string =>
    source.replace(/\.js$/u, '.ts');

const isRelativeVendoredModulePath = (relativePath: string): boolean =>
    relativePath.endsWith('.ts') &&
    !relativePath.startsWith('/') &&
    !relativePath.startsWith('..') &&
    !path.isAbsolute(relativePath);

const validateVendoredProtocolRuntime = (
    input: PublicSurfaceValidationInput,
    sdkRuntimeExports: ReadonlySet<string>,
): string[] => {
    const failures: string[] = [];
    const vendoredModules = new Set(
        input.publicSurface.vendoredProtocolRuntimeModules,
    );

    failures.push(
        ...assertSortedUnique(
            'vendoredProtocolRuntimeModules',
            input.publicSurface.vendoredProtocolRuntimeModules,
        ),
        ...assertSortedUnique(
            'vendoredProtocolRuntimeEntryExports sources',
            input.publicSurface.vendoredProtocolRuntimeEntryExports.map(
                (entry) => entry.source,
            ),
        ),
    );

    for (const relativeSourcePath of input.publicSurface
        .vendoredProtocolRuntimeModules) {
        if (!isRelativeVendoredModulePath(relativeSourcePath)) {
            failures.push(
                `vendoredProtocolRuntimeModules contains invalid path "${relativeSourcePath}"`,
            );
        }
        if (
            !input.protocolRuntimeModuleTextByRelativePath.has(
                relativeSourcePath,
            )
        ) {
            failures.push(
                `vendoredProtocolRuntimeModules references missing source "${relativeSourcePath}"`,
            );
        }
    }

    for (const entry of input.publicSurface
        .vendoredProtocolRuntimeEntryExports) {
        failures.push(
            ...assertSortedUnique(
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
            continue;
        }

        const sourceText =
            input.protocolRuntimeModuleTextByRelativePath.get(
                relativeSourcePath,
            );
        if (sourceText === undefined) {
            continue;
        }

        const moduleExports = collectSourceExportNames(
            sourceText,
            relativeSourcePath,
        );
        const moduleRuntimeExports = new Set(moduleExports.runtimeExports);

        failures.push(...moduleExports.unsupportedExportDeclarations);

        for (const exportName of entry.exports) {
            if (!moduleRuntimeExports.has(exportName)) {
                failures.push(
                    `vendoredProtocolRuntimeEntryExports ${entry.source} does not export "${exportName}"`,
                );
            }
            if (!sdkRuntimeExports.has(exportName)) {
                failures.push(
                    `vendoredProtocolRuntimeEntryExports ${entry.source} exposes "${exportName}" outside the SDK runtime facade`,
                );
            }
        }
    }

    return failures;
};

export const validatePublicSurface = (
    input: PublicSurfaceValidationInput,
): string[] => {
    const failures: string[] = [];
    const sdkExports = collectSourceExportNames(
        input.sdkFacadeSourceText,
        input.sdkFacadeSourcePath,
    );

    failures.push(
        ...assertSortedUnique(
            'runtimeExports',
            input.publicSurface.runtimeExports,
        ),
        ...assertSortedUnique(
            'publicTypeExports',
            input.publicSurface.publicTypeExports,
        ),
        ...sdkExports.unsupportedExportDeclarations,
        ...compareExactList(
            'runtimeExports',
            input.publicSurface.runtimeExports,
            sdkExports.runtimeExports,
        ),
        ...compareExactList(
            'publicTypeExports',
            input.publicSurface.publicTypeExports,
            sdkExports.typeExports,
        ),
    );

    const runtimeExports = new Set(input.publicSurface.runtimeExports);
    const typeExports = new Set(input.publicSurface.publicTypeExports);

    for (const exportName of input.publicSurface.forbiddenRuntimeExports) {
        if (runtimeExports.has(exportName)) {
            failures.push(
                `forbiddenRuntimeExports overlaps runtimeExports at "${exportName}"`,
            );
        }
        if (typeExports.has(exportName)) {
            failures.push(
                `forbiddenRuntimeExports overlaps publicTypeExports at "${exportName}"`,
            );
        }
    }

    failures.push(...validateVendoredProtocolRuntime(input, runtimeExports));

    return failures.sort();
};

const loadVendoredProtocolRuntimeModules = async (
    publicSurface: PublicSurfaceManifest,
): Promise<ReadonlyMap<string, string>> => {
    const moduleTextByRelativePath = new Map<string, string>();

    for (const relativeSourcePath of publicSurface.vendoredProtocolRuntimeModules) {
        if (!isRelativeVendoredModulePath(relativeSourcePath)) {
            continue;
        }

        const sourcePath = path.resolve(
            protocolSourceDirectoryPath,
            relativeSourcePath,
        );
        const sourcePathRelativeToProtocolRoot = path.relative(
            protocolSourceDirectoryPath,
            sourcePath,
        );
        if (
            sourcePathRelativeToProtocolRoot.startsWith('..') ||
            path.isAbsolute(sourcePathRelativeToProtocolRoot)
        ) {
            continue;
        }

        try {
            moduleTextByRelativePath.set(
                relativeSourcePath,
                await fs.readFile(sourcePath, 'utf8'),
            );
        } catch {
            continue;
        }
    }

    return moduleTextByRelativePath;
};

/* v8 ignore start */
const main = async (): Promise<void> => {
    const publicSurface = publicSurfaceManifest as PublicSurfaceManifest;
    const failures = validatePublicSurface({
        publicSurface,
        sdkFacadeSourcePath,
        sdkFacadeSourceText: await fs.readFile(sdkFacadeSourcePath, 'utf8'),
        protocolRuntimeModuleTextByRelativePath:
            await loadVendoredProtocolRuntimeModules(publicSurface),
    });

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('Public surface verification passed.');
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
/* v8 ignore stop */
