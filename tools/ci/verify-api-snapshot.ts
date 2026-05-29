import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as ts from 'typescript';

type ApiSnapshot = {
    readonly declarationFiles: readonly string[];
    readonly declarationHash: string;
    readonly runtimeExports: readonly string[];
    readonly schemaVersion: 1;
    readonly typeExports: readonly string[];
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkDistDirectoryPath = path.resolve(repoRoot, 'packages', 'sdk', 'dist');
const sdkEntryDeclarationPath = path.join(sdkDistDirectoryPath, 'index.d.ts');
const sdkRuntimePath = path.join(sdkDistDirectoryPath, 'index.js');
const apiSnapshotPath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'api-snapshot.json',
);

const sortedUnique = (values: Iterable<string>): string[] =>
    [...new Set(values)].sort((left, right) => left.localeCompare(right));

const normalizePath = (filePath: string): string =>
    path.relative(repoRoot, filePath).split(path.sep).join('/');

const normalizeText = (text: string): string =>
    text.replace(/\r\n/gu, '\n').replace(/\r/gu, '\n');

const hasExportModifier = (
    node: ts.Node,
): node is ts.Node & { readonly modifiers: ts.NodeArray<ts.ModifierLike> } =>
    ts.canHaveModifiers(node) &&
    (ts
        .getModifiers(node)
        ?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ??
        false);

const collectExportedDeclarationName = (statement: ts.Statement): string[] => {
    if (!hasExportModifier(statement)) {
        return [];
    }

    if (
        ts.isTypeAliasDeclaration(statement) ||
        ts.isInterfaceDeclaration(statement) ||
        ts.isClassDeclaration(statement) ||
        ts.isEnumDeclaration(statement)
    ) {
        if (statement.name === undefined) {
            return [];
        }

        return [statement.name.text];
    }

    return [];
};

const collectNamedTypeExports = (sourceFile: ts.SourceFile): string[] => {
    const exportNames: string[] = [];

    for (const statement of sourceFile.statements) {
        if (
            ts.isExportDeclaration(statement) &&
            statement.isTypeOnly &&
            statement.exportClause !== undefined &&
            ts.isNamedExports(statement.exportClause)
        ) {
            exportNames.push(
                ...statement.exportClause.elements.map(
                    (exportSpecifier) => exportSpecifier.name.text,
                ),
            );
            continue;
        }

        exportNames.push(...collectExportedDeclarationName(statement));
    }

    return sortedUnique(exportNames);
};

const relativeDeclarationPathForModuleSpecifier = (
    containingFilePath: string,
    moduleSpecifier: string,
): string | null => {
    if (!moduleSpecifier.startsWith('.')) {
        return null;
    }

    const containingDirectoryPath = path.dirname(containingFilePath);
    const resolvedModulePath = path.resolve(
        containingDirectoryPath,
        moduleSpecifier,
    );
    const declarationPath = resolvedModulePath.replace(/\.js$/u, '.d.ts');

    return declarationPath;
};

const collectRelativeDeclarationReferences = (
    sourceFile: ts.SourceFile,
): string[] => {
    const references: string[] = [];

    for (const statement of sourceFile.statements) {
        if (
            (ts.isImportDeclaration(statement) ||
                ts.isExportDeclaration(statement)) &&
            statement.moduleSpecifier !== undefined &&
            ts.isStringLiteral(statement.moduleSpecifier)
        ) {
            const declarationPath = relativeDeclarationPathForModuleSpecifier(
                sourceFile.fileName,
                statement.moduleSpecifier.text,
            );
            if (declarationPath !== null) {
                references.push(declarationPath);
            }
        }
    }

    return references;
};

const readDeclarationSourceFile = async (
    declarationPath: string,
): Promise<ts.SourceFile> => {
    const declarationText = await fs.readFile(declarationPath, 'utf8');

    return ts.createSourceFile(
        declarationPath,
        declarationText,
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TS,
    );
};

const collectReachableDeclarationFilePaths = async (): Promise<string[]> => {
    const visitedDeclarationPaths = new Set<string>();
    const pendingDeclarationPaths = [sdkEntryDeclarationPath];

    while (pendingDeclarationPaths.length > 0) {
        const declarationPath = path.resolve(
            pendingDeclarationPaths.pop() ?? '',
        );
        if (visitedDeclarationPaths.has(declarationPath)) {
            continue;
        }

        visitedDeclarationPaths.add(declarationPath);
        const sourceFile = await readDeclarationSourceFile(declarationPath);
        for (const referencedDeclarationPath of collectRelativeDeclarationReferences(
            sourceFile,
        )) {
            pendingDeclarationPaths.push(referencedDeclarationPath);
        }
    }

    return sortedUnique(visitedDeclarationPaths);
};

const hashReachableDeclarations = async (
    declarationFilePaths: readonly string[],
): Promise<string> => {
    const hash = createHash('sha256');

    for (const declarationFilePath of declarationFilePaths) {
        const relativePath = normalizePath(declarationFilePath);
        const declarationText = normalizeText(
            await fs.readFile(declarationFilePath, 'utf8'),
        );

        hash.update(`file:${relativePath}\n`, 'utf8');
        hash.update(declarationText, 'utf8');
        hash.update('\n', 'utf8');
    }

    return `sha256:${hash.digest('hex')}`;
};

const loadRuntimeExportNames = async (): Promise<string[]> => {
    const runtimeModule = (await import(
        pathToFileURL(sdkRuntimePath).href
    )) as Record<string, unknown>;

    return sortedUnique(Object.keys(runtimeModule));
};

const createCurrentApiSnapshot = async (): Promise<ApiSnapshot> => {
    const declarationFilePaths = await collectReachableDeclarationFilePaths();
    const entrySourceFile = await readDeclarationSourceFile(
        sdkEntryDeclarationPath,
    );

    return {
        schemaVersion: 1,
        declarationFiles: declarationFilePaths.map(normalizePath),
        declarationHash: await hashReachableDeclarations(declarationFilePaths),
        runtimeExports: await loadRuntimeExportNames(),
        typeExports: collectNamedTypeExports(entrySourceFile),
    };
};

const formatSnapshot = (snapshot: ApiSnapshot): string =>
    `${JSON.stringify(snapshot, null, 4)}\n`;

const diffValues = (
    expectedValues: readonly string[],
    actualValues: readonly string[],
): { readonly added: string[]; readonly removed: string[] } => {
    const expected = new Set(expectedValues);
    const actual = new Set(actualValues);

    return {
        added: actualValues.filter((value) => !expected.has(value)),
        removed: expectedValues.filter((value) => !actual.has(value)),
    };
};

const formatList = (values: readonly string[]): string =>
    values.length === 0
        ? '(none)'
        : values.map((value) => `- ${value}`).join('\n');

const hasNodeErrorCode = (
    error: unknown,
): error is Error & { readonly code: string } => {
    if (!(error instanceof Error) || !('code' in error)) {
        return false;
    }

    return typeof (error as { readonly code?: unknown }).code === 'string';
};

const formatMismatch = (
    expectedSnapshot: ApiSnapshot,
    actualSnapshot: ApiSnapshot,
): string => {
    const runtimeDiff = diffValues(
        expectedSnapshot.runtimeExports,
        actualSnapshot.runtimeExports,
    );
    const typeDiff = diffValues(
        expectedSnapshot.typeExports,
        actualSnapshot.typeExports,
    );

    return [
        'Public API snapshot is out of date. Run `pnpm run api-surface:update` after intentional public SDK API changes.',
        '',
        `Expected declaration hash: ${expectedSnapshot.declarationHash}`,
        `Actual declaration hash:   ${actualSnapshot.declarationHash}`,
        '',
        'Added runtime exports:',
        formatList(runtimeDiff.added),
        '',
        'Removed runtime exports:',
        formatList(runtimeDiff.removed),
        '',
        'Added type exports:',
        formatList(typeDiff.added),
        '',
        'Removed type exports:',
        formatList(typeDiff.removed),
    ].join('\n');
};

const readExpectedSnapshot = async (): Promise<ApiSnapshot> => {
    try {
        return JSON.parse(
            await fs.readFile(apiSnapshotPath, 'utf8'),
        ) as ApiSnapshot;
    } catch (error) {
        if (hasNodeErrorCode(error) && error.code === 'ENOENT') {
            error.message = `Missing public API snapshot. Run \`pnpm run api-surface:update\` to create packages/sdk/api-snapshot.json. ${error.message}`;
            throw error;
        }

        throw error;
    }
};

const main = async (): Promise<void> => {
    const shouldUpdate = process.argv.includes('--update');
    const currentSnapshot = await createCurrentApiSnapshot();
    const currentSnapshotText = formatSnapshot(currentSnapshot);

    if (shouldUpdate) {
        await fs.writeFile(apiSnapshotPath, currentSnapshotText, 'utf8');
        console.log(
            `Public API snapshot updated: ${normalizePath(apiSnapshotPath)}`,
        );
        return;
    }

    const expectedSnapshot = await readExpectedSnapshot();
    const expectedSnapshotText = formatSnapshot(expectedSnapshot);
    if (expectedSnapshotText !== currentSnapshotText) {
        throw new Error(formatMismatch(expectedSnapshot, currentSnapshot));
    }

    console.log('Public API snapshot verification passed.');
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
