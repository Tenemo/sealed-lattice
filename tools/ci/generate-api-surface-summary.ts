import { promises as fs } from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as ts from 'typescript';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

type ApiSurfaceSummary = {
    readonly declarationFiles: readonly string[];
    readonly declarations: readonly DeclarationSurfaceFile[];
    readonly runtimeExports: readonly string[];
    readonly schemaVersion: 1;
    readonly typeExports: readonly string[];
};

type DeclarationSurfaceFile = {
    readonly file: string;
    readonly lines: readonly string[];
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkDistDirectoryPath = path.resolve(repoRoot, 'packages', 'sdk', 'dist');
const sdkEntryDeclarationPath = path.join(sdkDistDirectoryPath, 'index.d.ts');
const sdkRuntimePath = path.join(sdkDistDirectoryPath, 'index.js');
const apiSurfaceSummaryPath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'api-surface-summary.json',
);

const sortedUnique = (values: Iterable<string>): string[] =>
    [...new Set(values)].sort((left, right) => left.localeCompare(right));

const normalizePath = (filePath: string): string =>
    path.relative(repoRoot, filePath).split(path.sep).join('/');

const normalizeText = (text: string): string =>
    text.replace(/\r\n/gu, '\n').replace(/\r/gu, '\n').trimEnd();

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

    return resolvedModulePath.replace(/\.js$/u, '.d.ts');
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

const loadRuntimeExportNames = async (): Promise<string[]> => {
    const runtimeModule = (await import(
        pathToFileURL(sdkRuntimePath).href
    )) as Record<string, unknown>;

    return sortedUnique(Object.keys(runtimeModule));
};

const loadDeclarationSurfaceFiles = async (
    declarationFilePaths: readonly string[],
): Promise<DeclarationSurfaceFile[]> =>
    Promise.all(
        declarationFilePaths.map(async (declarationFilePath) => ({
            file: normalizePath(declarationFilePath),
            lines: normalizeText(
                await fs.readFile(declarationFilePath, 'utf8'),
            ).split('\n'),
        })),
    );

const createCurrentApiSurfaceSummary = async (): Promise<ApiSurfaceSummary> => {
    const declarationFilePaths = await collectReachableDeclarationFilePaths();
    const entrySourceFile = await readDeclarationSourceFile(
        sdkEntryDeclarationPath,
    );

    return {
        schemaVersion: 1,
        declarationFiles: declarationFilePaths.map(normalizePath),
        declarations: await loadDeclarationSurfaceFiles(declarationFilePaths),
        runtimeExports: await loadRuntimeExportNames(),
        typeExports: collectNamedTypeExports(entrySourceFile),
    };
};

const formatSummary = (summary: ApiSurfaceSummary): string =>
    `${JSON.stringify(summary, null, 4)}\n`;

const writeTextWithWindowsRetry = async (
    filePath: string,
    text: string,
): Promise<void> => {
    const temporaryPath = `${filePath}.${String(process.pid)}.tmp`;
    let lastError: unknown;

    for (let attemptIndex = 0; attemptIndex < 5; attemptIndex += 1) {
        try {
            await fs.writeFile(temporaryPath, text, 'utf8');
            await fs.rename(temporaryPath, filePath);

            return;
        } catch (error) {
            lastError = error;
            await fs.rm(temporaryPath, { force: true });
            await delay(50 * (attemptIndex + 1));
        }
    }

    throw lastError instanceof Error ? lastError : new Error(String(lastError));
};

const main = async (): Promise<void> => {
    const currentSummary = await createCurrentApiSurfaceSummary();
    await writeTextWithWindowsRetry(
        apiSurfaceSummaryPath,
        formatSummary(currentSummary),
    );
    console.log(
        `Public API surface summary generated: ${normalizePath(apiSurfaceSummaryPath)}`,
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
