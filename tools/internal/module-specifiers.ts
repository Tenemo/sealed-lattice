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

export const extractModuleSpecifiers = (
    sourceText: string,
    sourcePath = 'module-specifier-source.ts',
): string[] => {
    const sourceFile = createSourceFile(
        sourcePath,
        sourceText,
        ScriptTarget.Latest,
        true,
        ScriptKind.TS,
    );
    const specifiers = new Set<string>();

    const pushLiteral = (literal: StringLiteral): void => {
        specifiers.add(literal.text);
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

    return [...specifiers];
};
