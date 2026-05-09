import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as ts from 'typescript';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));

type SourceByName = ReadonlyMap<string, string>;

const protocolIndexPath = 'packages/protocol/src/index.ts';
const protocolShellIndexPath = 'packages/protocol/src/protocol-shell/index.ts';
const protocolShellTypesPath = 'packages/protocol/src/protocol-shell/types.ts';
const sdkIndexPath = 'packages/sdk/src/index.ts';
const sdkTypesPath = 'packages/sdk/src/types.ts';
const sdkKernelPath = 'packages/sdk/src/kernel.ts';
const sdkProtocolShellDeclarationPath =
    'packages/sdk/src/internal/protocol-shell/index.d.ts';
const sdkTranscriptCoreBridgeDeclarationPath =
    'packages/sdk/src/internal/transcript-core-bridge.d.ts';
const wasmTranscriptCoreBridgePath =
    'packages/wasm/src/transcript-core-bridge.ts';

const parseSourceText = (fileName: string, sourceText: string): ts.SourceFile =>
    ts.createSourceFile(fileName, sourceText, ts.ScriptTarget.Latest, true);

const readSourceFile = (relativePath: string): ts.SourceFile =>
    parseSourceText(
        relativePath,
        readFileSync(path.resolve(repoRoot, relativePath), 'utf8'),
    );

const isExported = (node: {
    readonly modifiers?: ts.NodeArray<ts.ModifierLike>;
}): boolean =>
    node.modifiers?.some(
        (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
    ) ?? false;

const stringifyNode = (sourceFile: ts.SourceFile, node: ts.Node): string =>
    node.getText(sourceFile).replace(/\s+/g, ' ').trim();

const sorted = (values: Iterable<string>): string[] =>
    [...values].sort((left, right) => left.localeCompare(right));

const difference = (
    leftValues: Iterable<string>,
    rightValues: Iterable<string>,
): string[] => {
    const right = new Set(rightValues);

    return sorted([...leftValues].filter((value) => !right.has(value)));
};

const formatList = (values: readonly string[]): string => values.join(', ');

export const collectExportedTypeAliases = (
    sourceText: string,
    fileName = 'source.ts',
): SourceByName => {
    const sourceFile = parseSourceText(fileName, sourceText);
    const aliases = new Map<string, string>();

    for (const statement of sourceFile.statements) {
        if (!ts.isTypeAliasDeclaration(statement) || !isExported(statement)) {
            continue;
        }

        aliases.set(
            statement.name.text,
            stringifyNode(sourceFile, statement.type),
        );
    }

    return aliases;
};

export const collectTypeExportSpecifiers = (
    sourceText: string,
    moduleSpecifier: string,
    fileName = 'source.ts',
): string[] => {
    const sourceFile = parseSourceText(fileName, sourceText);
    const names = new Set<string>();

    for (const statement of sourceFile.statements) {
        if (
            !ts.isExportDeclaration(statement) ||
            !statement.isTypeOnly ||
            statement.moduleSpecifier === undefined ||
            !ts.isStringLiteral(statement.moduleSpecifier) ||
            statement.moduleSpecifier.text !== moduleSpecifier ||
            statement.exportClause === undefined ||
            !ts.isNamedExports(statement.exportClause)
        ) {
            continue;
        }

        for (const element of statement.exportClause.elements) {
            names.add(element.propertyName?.text ?? element.name.text);
        }
    }

    return sorted(names);
};

export const collectNamedImportsFromModule = (
    sourceText: string,
    moduleSpecifier: string,
    fileName = 'source.ts',
): string[] => {
    const sourceFile = parseSourceText(fileName, sourceText);
    const names = new Set<string>();

    for (const statement of sourceFile.statements) {
        if (
            !ts.isImportDeclaration(statement) ||
            !ts.isStringLiteral(statement.moduleSpecifier) ||
            statement.moduleSpecifier.text !== moduleSpecifier ||
            statement.importClause?.namedBindings === undefined ||
            !ts.isNamedImports(statement.importClause.namedBindings)
        ) {
            continue;
        }

        for (const element of statement.importClause.namedBindings.elements) {
            names.add(element.propertyName?.text ?? element.name.text);
        }
    }

    return sorted(names);
};

export const collectDeclaredExportValueNames = (
    sourceText: string,
    fileName = 'source.ts',
): string[] => {
    const sourceFile = parseSourceText(fileName, sourceText);
    const names = new Set<string>();

    for (const statement of sourceFile.statements) {
        if (
            (ts.isFunctionDeclaration(statement) ||
                ts.isClassDeclaration(statement) ||
                ts.isInterfaceDeclaration(statement) ||
                ts.isTypeAliasDeclaration(statement)) &&
            isExported(statement) &&
            statement.name !== undefined
        ) {
            names.add(statement.name.text);
            continue;
        }

        if (!ts.isVariableStatement(statement) || !isExported(statement)) {
            continue;
        }

        for (const declaration of statement.declarationList.declarations) {
            if (ts.isIdentifier(declaration.name)) {
                names.add(declaration.name.text);
            }
        }
    }

    return sorted(names);
};

export const collectNamedExportSpecifiers = (
    sourceText: string,
    fileName = 'source.ts',
): string[] => {
    const sourceFile = parseSourceText(fileName, sourceText);
    const names = new Set<string>();

    for (const statement of sourceFile.statements) {
        if (
            (ts.isFunctionDeclaration(statement) ||
                ts.isClassDeclaration(statement) ||
                ts.isInterfaceDeclaration(statement) ||
                ts.isTypeAliasDeclaration(statement)) &&
            isExported(statement) &&
            statement.name !== undefined
        ) {
            names.add(statement.name.text);
            continue;
        }

        if (ts.isVariableStatement(statement) && isExported(statement)) {
            for (const declaration of statement.declarationList.declarations) {
                if (ts.isIdentifier(declaration.name)) {
                    names.add(declaration.name.text);
                }
            }
            continue;
        }

        if (
            !ts.isExportDeclaration(statement) ||
            statement.isTypeOnly ||
            statement.exportClause === undefined ||
            !ts.isNamedExports(statement.exportClause)
        ) {
            continue;
        }

        for (const element of statement.exportClause.elements) {
            names.add(element.propertyName?.text ?? element.name.text);
        }
    }

    return sorted(names);
};

export const collectStringUnionValues = (
    sourceText: string,
    typeName: string,
    fileName = 'source.ts',
): string[] | undefined => {
    const sourceFile = parseSourceText(fileName, sourceText);

    for (const statement of sourceFile.statements) {
        if (
            !ts.isTypeAliasDeclaration(statement) ||
            statement.name.text !== typeName
        ) {
            continue;
        }

        const nodes = ts.isUnionTypeNode(statement.type)
            ? statement.type.types
            : [statement.type];
        const values: string[] = [];

        for (const node of nodes) {
            if (
                !ts.isLiteralTypeNode(node) ||
                !ts.isStringLiteral(node.literal)
            ) {
                return undefined;
            }

            values.push(node.literal.text);
        }

        return sorted(values);
    }

    return undefined;
};

export const collectStringSetValues = (
    sourceText: string,
    variableName: string,
    fileName = 'source.ts',
): string[] => {
    const sourceFile = parseSourceText(fileName, sourceText);

    for (const statement of sourceFile.statements) {
        if (!ts.isVariableStatement(statement)) {
            continue;
        }

        for (const declaration of statement.declarationList.declarations) {
            if (
                !ts.isIdentifier(declaration.name) ||
                declaration.name.text !== variableName ||
                declaration.initializer === undefined ||
                !ts.isNewExpression(declaration.initializer)
            ) {
                continue;
            }

            const [firstArgument] = declaration.initializer.arguments ?? [];
            if (
                firstArgument === undefined ||
                !ts.isArrayLiteralExpression(firstArgument)
            ) {
                throw new Error(
                    `${variableName} must be initialized from an array.`,
                );
            }

            return sorted(
                firstArgument.elements.map((element) => {
                    if (!ts.isStringLiteral(element)) {
                        throw new Error(
                            `${variableName} must contain only string literals.`,
                        );
                    }

                    return element.text;
                }),
            );
        }
    }

    throw new Error(`Missing string set: ${variableName}.`);
};

export const findSdkSurfaceFailures = (sources: {
    readonly protocolIndexText: string;
    readonly protocolShellIndexText: string;
    readonly protocolShellTypesText: string;
    readonly sdkIndexText: string;
    readonly sdkKernelText: string;
    readonly sdkProtocolShellDeclarationText: string;
    readonly sdkTranscriptCoreBridgeDeclarationText: string;
    readonly sdkTypesText: string;
    readonly wasmTranscriptCoreBridgeText: string;
}): string[] => {
    const failures: string[] = [];
    const protocolTypeAliases = new Map([
        ...collectExportedTypeAliases(sources.protocolIndexText),
        ...collectExportedTypeAliases(sources.protocolShellTypesText),
    ]);
    const sdkTypeAliases = collectExportedTypeAliases(sources.sdkTypesText);
    const publicSdkTypeNames = collectTypeExportSpecifiers(
        sources.sdkIndexText,
        './types.js',
    );

    for (const typeName of publicSdkTypeNames) {
        if (!sdkTypeAliases.has(typeName)) {
            failures.push(
                `SDK public type export is missing from sdk types: ${typeName}`,
            );
        }
        if (!protocolTypeAliases.has(typeName)) {
            failures.push(
                `SDK public type export does not have a protocol source type: ${typeName}`,
            );
        }
    }

    for (const typeName of publicSdkTypeNames) {
        const protocolValues =
            collectStringUnionValues(
                sources.protocolIndexText,
                typeName,
                protocolIndexPath,
            ) ??
            collectStringUnionValues(
                sources.protocolShellTypesText,
                typeName,
                protocolShellTypesPath,
            );
        const sdkValues = collectStringUnionValues(
            sources.sdkTypesText,
            typeName,
            sdkTypesPath,
        );

        if (protocolValues === undefined || sdkValues === undefined) {
            continue;
        }

        const missingFromSdk = difference(protocolValues, sdkValues);
        const extraInSdk = difference(sdkValues, protocolValues);
        if (missingFromSdk.length > 0 || extraInSdk.length > 0) {
            failures.push(
                `SDK string union ${typeName} drifted from protocol source. Missing: ${
                    formatList(missingFromSdk) || 'none'
                }. Extra: ${formatList(extraInSdk) || 'none'}.`,
            );
        }
    }

    const canonicalErrorValues = collectStringUnionValues(
        sources.sdkTypesText,
        'CanonicalErrorCode',
        sdkTypesPath,
    );
    const bridgeErrorValues = collectStringSetValues(
        sources.wasmTranscriptCoreBridgeText,
        'canonicalErrorCodes',
        wasmTranscriptCoreBridgePath,
    );
    if (canonicalErrorValues === undefined) {
        failures.push('SDK CanonicalErrorCode must remain a string union.');
    } else {
        const missingFromBridge = difference(
            canonicalErrorValues,
            bridgeErrorValues,
        );
        const extraInBridge = difference(
            bridgeErrorValues,
            canonicalErrorValues,
        );
        if (missingFromBridge.length > 0 || extraInBridge.length > 0) {
            failures.push(
                `WASM bridge canonical error-code guard drifted from SDK types. Missing: ${
                    formatList(missingFromBridge) || 'none'
                }. Extra: ${formatList(extraInBridge) || 'none'}.`,
            );
        }
    }

    const sdkProtocolShellImports = collectNamedImportsFromModule(
        sources.sdkIndexText,
        './internal/protocol-shell/index.js',
        sdkIndexPath,
    );
    const sdkProtocolShellDeclarations = collectDeclaredExportValueNames(
        sources.sdkProtocolShellDeclarationText,
        sdkProtocolShellDeclarationPath,
    );
    const protocolShellRuntimeExports = collectNamedExportSpecifiers(
        sources.protocolShellIndexText,
        protocolShellIndexPath,
    );

    const missingProtocolShellDeclarations = difference(
        sdkProtocolShellImports,
        sdkProtocolShellDeclarations,
    );
    const unusedProtocolShellDeclarations = difference(
        sdkProtocolShellDeclarations,
        sdkProtocolShellImports,
    );
    const missingProtocolShellRuntimeExports = difference(
        sdkProtocolShellImports,
        protocolShellRuntimeExports,
    );
    if (
        missingProtocolShellDeclarations.length > 0 ||
        unusedProtocolShellDeclarations.length > 0 ||
        missingProtocolShellRuntimeExports.length > 0
    ) {
        failures.push(
            `SDK protocol-shell internal declarations drifted. Missing declarations: ${
                formatList(missingProtocolShellDeclarations) || 'none'
            }. Unused declarations: ${
                formatList(unusedProtocolShellDeclarations) || 'none'
            }. Missing runtime exports: ${
                formatList(missingProtocolShellRuntimeExports) || 'none'
            }.`,
        );
    }

    const sdkBridgeImports = collectNamedImportsFromModule(
        sources.sdkKernelText,
        './internal/transcript-core-bridge.js',
        sdkKernelPath,
    );
    const sdkBridgeDeclarations = collectDeclaredExportValueNames(
        sources.sdkTranscriptCoreBridgeDeclarationText,
        sdkTranscriptCoreBridgeDeclarationPath,
    );
    const wasmBridgeRuntimeExports = collectNamedExportSpecifiers(
        sources.wasmTranscriptCoreBridgeText,
        wasmTranscriptCoreBridgePath,
    );
    const missingBridgeDeclarations = difference(
        sdkBridgeImports,
        sdkBridgeDeclarations,
    );
    const missingBridgeRuntimeExports = difference(
        sdkBridgeImports,
        wasmBridgeRuntimeExports,
    );
    if (
        missingBridgeDeclarations.length > 0 ||
        missingBridgeRuntimeExports.length > 0
    ) {
        failures.push(
            `SDK transcript-core bridge declarations drifted. Missing declarations: ${
                formatList(missingBridgeDeclarations) || 'none'
            }. Missing runtime exports: ${
                formatList(missingBridgeRuntimeExports) || 'none'
            }.`,
        );
    }

    return failures;
};

const loadRepositorySources = (): Parameters<
    typeof findSdkSurfaceFailures
>[0] => ({
    protocolIndexText: readSourceFile(protocolIndexPath).text,
    protocolShellIndexText: readSourceFile(protocolShellIndexPath).text,
    protocolShellTypesText: readSourceFile(protocolShellTypesPath).text,
    sdkIndexText: readSourceFile(sdkIndexPath).text,
    sdkKernelText: readSourceFile(sdkKernelPath).text,
    sdkProtocolShellDeclarationText: readSourceFile(
        sdkProtocolShellDeclarationPath,
    ).text,
    sdkTranscriptCoreBridgeDeclarationText: readSourceFile(
        sdkTranscriptCoreBridgeDeclarationPath,
    ).text,
    sdkTypesText: readSourceFile(sdkTypesPath).text,
    wasmTranscriptCoreBridgeText: readSourceFile(wasmTranscriptCoreBridgePath)
        .text,
});

/* v8 ignore start */
const main = (): void => {
    const failures = findSdkSurfaceFailures(loadRepositorySources());

    if (failures.length > 0) {
        throw new Error(failures.join('\n'));
    }

    console.log('SDK surface verification passed.');
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    main();
}
/* v8 ignore stop */
