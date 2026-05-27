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

export type ModuleSpecifierLiteral = {
    readonly end: number;
    readonly quote: string;
    readonly start: number;
    readonly text: string;
};

export type ModuleSpecifierRewrite = (specifier: string) => string | undefined;

type ModuleSpecifierReplacement = {
    readonly end: number;
    readonly start: number;
    readonly text: string;
};

const quoteModuleSpecifier = (specifier: string, quote: string): string => {
    const escapedSpecifier = specifier
        .replace(/\\/g, '\\\\')
        .split(quote)
        .join(`\\${quote}`);

    return `${quote}${escapedSpecifier}${quote}`;
};

export const collectModuleSpecifierLiterals = (
    sourceText: string,
    sourcePath = 'module-specifier-source.tsx',
): readonly ModuleSpecifierLiteral[] => {
    const sourceFile = createSourceFile(
        sourcePath,
        sourceText,
        ScriptTarget.Latest,
        true,
        ScriptKind.TSX,
    );
    const literals: ModuleSpecifierLiteral[] = [];

    const pushLiteral = (literal: StringLiteral): void => {
        const start = literal.getStart(sourceFile);
        literals.push({
            start,
            end: literal.end,
            quote: sourceText[start] ?? "'",
            text: literal.text,
        });
    };

    const visit = (node: Node): void => {
        if (
            isImportDeclaration(node) &&
            isStringLiteral(node.moduleSpecifier)
        ) {
            pushLiteral(node.moduleSpecifier);
        } else if (
            isExportDeclaration(node) &&
            node.moduleSpecifier !== undefined &&
            isStringLiteral(node.moduleSpecifier)
        ) {
            pushLiteral(node.moduleSpecifier);
        } else if (
            isCallExpression(node) &&
            node.expression.kind === SyntaxKind.ImportKeyword
        ) {
            const [moduleSpecifier] = node.arguments;
            if (
                moduleSpecifier !== undefined &&
                isStringLiteral(moduleSpecifier)
            ) {
                pushLiteral(moduleSpecifier);
            }
        } else if (isImportTypeNode(node)) {
            const importTypeArgument = node.argument;
            if (
                isLiteralTypeNode(importTypeArgument) &&
                isStringLiteral(importTypeArgument.literal)
            ) {
                pushLiteral(importTypeArgument.literal);
            }
        }

        forEachChild(node, visit);
    };

    visit(sourceFile);

    return literals;
};

export const extractModuleSpecifiers = (
    sourceText: string,
    sourcePath?: string,
): string[] => {
    const specifiers = new Set<string>();

    for (const moduleSpecifier of collectModuleSpecifierLiterals(
        sourceText,
        sourcePath,
    )) {
        specifiers.add(moduleSpecifier.text);
    }

    return [...specifiers];
};

export const rewriteModuleSpecifiers = (
    sourcePath: string,
    sourceText: string,
    rewriteSpecifier: ModuleSpecifierRewrite,
): string => {
    const replacements: ModuleSpecifierReplacement[] = [];

    for (const literal of collectModuleSpecifierLiterals(
        sourceText,
        sourcePath,
    )) {
        const rewrittenSpecifier = rewriteSpecifier(literal.text);
        if (
            rewrittenSpecifier === undefined ||
            rewrittenSpecifier === literal.text
        ) {
            continue;
        }

        replacements.push({
            start: literal.start,
            end: literal.end,
            text: quoteModuleSpecifier(rewrittenSpecifier, literal.quote),
        });
    }

    return replacements
        .sort((left, right) => right.start - left.start)
        .reduce(
            (rewrittenText, replacement) =>
                `${rewrittenText.slice(0, replacement.start)}${replacement.text}${rewrittenText.slice(replacement.end)}`,
            sourceText,
        );
};
