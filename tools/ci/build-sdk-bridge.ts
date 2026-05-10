import {
    mkdir,
    readFile,
    readdir,
    rm,
    stat,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    DiagnosticCategory,
    ModuleKind,
    ScriptKind,
    ScriptTarget,
    SyntaxKind,
    createSourceFile,
    formatDiagnosticsWithColorAndContext,
    forEachChild,
    isCallExpression,
    isExportDeclaration,
    isImportDeclaration,
    isImportTypeNode,
    isLiteralTypeNode,
    isStringLiteral,
    transpileModule,
    type Node,
    type StringLiteral,
} from 'typescript';

import { collectFiles } from '../internal/files.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const sdkDistDirectoryPath = path.resolve(repoRoot, 'packages', 'sdk', 'dist');
const bridgeSourcePath = path.resolve(
    repoRoot,
    'packages',
    'wasm',
    'src',
    'transcript-core-bridge.ts',
);
const bridgeOutputPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'transcript-core-bridge.js',
);
const protocolShellSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'protocol',
    'src',
    'protocol-shell',
);
const protocolShellOutputDirectoryPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'protocol-shell',
);
const typesPackageName = '@sealed-lattice/types';
const typesDeclarationSourcePath = path.resolve(
    repoRoot,
    'packages',
    'types',
    'dist',
    'index.d.ts',
);
const typesRuntimeSourcePath = path.resolve(
    repoRoot,
    'packages',
    'types',
    'src',
    'index.ts',
);
const typesDeclarationOutputPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'types.d.ts',
);
const typesRuntimeOutputPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'types.js',
);
const runtimeImportTargets = new Map([
    ['@sealed-lattice/types', typesRuntimeOutputPath],
    ['@sealed-lattice/protocol', protocolShellOutputDirectoryPath],
    ['@sealed-lattice/wasm', bridgeOutputPath],
]);

export const transpileSdkInternalSource = (
    sourceText: string,
    sourcePath: string,
): string => {
    const result = transpileModule(sourceText, {
        compilerOptions: {
            target: ScriptTarget.ES2020,
            module: ModuleKind.ESNext,
            removeComments: true,
            sourceMap: false,
        },
        fileName: sourcePath,
        reportDiagnostics: true,
    });
    const diagnostics = result.diagnostics ?? [];
    const errors = diagnostics.filter(
        (diagnostic) => diagnostic.category === DiagnosticCategory.Error,
    );

    if (errors.length > 0) {
        throw new Error(
            formatDiagnosticsWithColorAndContext(errors, {
                getCanonicalFileName: (fileName) => fileName,
                getCurrentDirectory: () => repoRoot,
                getNewLine: () => '\n',
            }),
        );
    }

    return result.outputText;
};

export const transpileBridgeSource = (sourceText: string): string =>
    transpileSdkInternalSource(sourceText, bridgeSourcePath);

export const buildSdkBridge = async (): Promise<void> => {
    const sourceText = await readFile(bridgeSourcePath, 'utf8');
    const outputText = transpileBridgeSource(sourceText);

    await mkdir(path.dirname(bridgeOutputPath), { recursive: true });
    await writeFile(bridgeOutputPath, outputText, 'utf8');
};

export const buildSdkProtocolShellRuntime = async (): Promise<void> => {
    const sourceFileNames = (await readdir(protocolShellSourceDirectoryPath))
        .filter((sourceFileName) => sourceFileName.endsWith('.ts'))
        .sort();

    await rm(protocolShellOutputDirectoryPath, {
        recursive: true,
        force: true,
    });
    await mkdir(protocolShellOutputDirectoryPath, { recursive: true });

    await Promise.all(
        sourceFileNames.map(async (sourceFileName) => {
            const sourcePath = path.join(
                protocolShellSourceDirectoryPath,
                sourceFileName,
            );
            const outputPath = path.join(
                protocolShellOutputDirectoryPath,
                sourceFileName.replace(/\.ts$/u, '.js'),
            );
            const sourceText = await readFile(sourcePath, 'utf8');
            const outputText = transpileSdkInternalSource(
                sourceText,
                sourcePath,
            );

            await writeFile(outputPath, outputText, 'utf8');
        }),
    );
};

type ModuleSpecifierRewrite = (specifier: string) => string | undefined;

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

const collectModuleSpecifierLiterals = (
    sourceText: string,
    sourcePath: string,
): {
    readonly literals: readonly StringLiteral[];
    readonly sourceFile: ReturnType<typeof createSourceFile>;
} => {
    const sourceFile = createSourceFile(
        sourcePath,
        sourceText,
        ScriptTarget.Latest,
        true,
        ScriptKind.TSX,
    );
    const literals: StringLiteral[] = [];

    const visit = (node: Node): void => {
        if (
            isImportDeclaration(node) &&
            isStringLiteral(node.moduleSpecifier)
        ) {
            literals.push(node.moduleSpecifier);
        } else if (
            isExportDeclaration(node) &&
            node.moduleSpecifier !== undefined &&
            isStringLiteral(node.moduleSpecifier)
        ) {
            literals.push(node.moduleSpecifier);
        } else if (
            isCallExpression(node) &&
            node.expression.kind === SyntaxKind.ImportKeyword
        ) {
            const [moduleSpecifier] = node.arguments;
            if (
                moduleSpecifier !== undefined &&
                isStringLiteral(moduleSpecifier)
            ) {
                literals.push(moduleSpecifier);
            }
        } else if (isImportTypeNode(node)) {
            const importTypeArgument = node.argument;
            if (
                isLiteralTypeNode(importTypeArgument) &&
                isStringLiteral(importTypeArgument.literal)
            ) {
                literals.push(importTypeArgument.literal);
            }
        }

        forEachChild(node, visit);
    };

    visit(sourceFile);

    return { literals, sourceFile };
};

const rewriteModuleSpecifiers = (
    sourcePath: string,
    sourceText: string,
    rewriteSpecifier: ModuleSpecifierRewrite,
): string => {
    const { literals, sourceFile } = collectModuleSpecifierLiterals(
        sourceText,
        sourcePath,
    );
    const replacements: ModuleSpecifierReplacement[] = [];

    for (const literal of literals) {
        const rewrittenSpecifier = rewriteSpecifier(literal.text);
        if (
            rewrittenSpecifier === undefined ||
            rewrittenSpecifier === literal.text
        ) {
            continue;
        }

        const start = literal.getStart(sourceFile);
        const end = literal.end;
        const quote = sourceText[start];
        replacements.push({
            start,
            end,
            text: quoteModuleSpecifier(rewrittenSpecifier, quote),
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

export const computeRelativeTypesSpecifier = (
    declarationFilePath: string,
    typesRuntimePath: string,
): string => {
    const containingDirectory = path.dirname(declarationFilePath);
    const relativeWithDeclarationExtension = path.relative(
        containingDirectory,
        typesRuntimePath,
    );
    const posixSpecifier = relativeWithDeclarationExtension
        .split(path.sep)
        .join('/');

    return posixSpecifier.startsWith('.')
        ? posixSpecifier
        : `./${posixSpecifier}`;
};

const computeRelativeRuntimeSpecifier = (
    sourceFilePath: string,
    runtimeTargetPath: string,
): string => {
    const containingDirectory = path.dirname(sourceFilePath);
    const targetPath =
        path.extname(runtimeTargetPath) === ''
            ? path.join(runtimeTargetPath, 'index.js')
            : runtimeTargetPath;
    const relativePath = path
        .relative(containingDirectory, targetPath)
        .split(path.sep)
        .join('/');

    return relativePath.startsWith('.') ? relativePath : `./${relativePath}`;
};

export const rewriteRuntimeImports = (
    sourceFilePath: string,
    sourceText: string,
): string =>
    rewriteModuleSpecifiers(sourceFilePath, sourceText, (specifier) => {
        for (const [
            packageName,
            runtimeTargetPath,
        ] of runtimeImportTargets.entries()) {
            if (specifier === packageName) {
                return computeRelativeRuntimeSpecifier(
                    sourceFilePath,
                    runtimeTargetPath,
                );
            }
            if (specifier.startsWith(`${packageName}/`)) {
                throw new Error(
                    `Cannot vendor deep workspace runtime import ${specifier}. Import ${packageName} instead.`,
                );
            }
        }

        return undefined;
    });

export const rewriteTypesImports = (
    declarationFilePath: string,
    declarationText: string,
    typesRuntimePath: string,
): string => {
    const relativeSpecifier = computeRelativeTypesSpecifier(
        declarationFilePath,
        typesRuntimePath,
    );

    return rewriteModuleSpecifiers(
        declarationFilePath,
        declarationText,
        (specifier) => {
            if (specifier === typesPackageName) {
                return relativeSpecifier;
            }
            if (specifier.startsWith(`${typesPackageName}/`)) {
                throw new Error(
                    `Cannot inline deep ${typesPackageName} declaration import ${specifier}. Import ${typesPackageName} instead.`,
                );
            }

            return undefined;
        },
    );
};

const ensureTypesPackageBuilt = async (): Promise<void> => {
    try {
        await stat(typesDeclarationSourcePath);
    } catch {
        throw new Error(
            `Cannot inline @sealed-lattice/types into the published sdk. The types package has not been built. Run \`pnpm --filter @sealed-lattice/types run build\` first (the workspace \`pnpm run build\` already chains it via Turborepo).`,
        );
    }
};

export const rewriteWorkspaceRuntimeImports = async (): Promise<void> => {
    const runtimeFiles = await collectFiles(sdkDistDirectoryPath, {
        extensions: ['.js'],
    });

    await Promise.all(
        runtimeFiles.map(async (runtimeFilePath) => {
            const original = await readFile(runtimeFilePath, 'utf8');
            const rewritten = rewriteRuntimeImports(runtimeFilePath, original);
            if (rewritten !== original) {
                await writeFile(runtimeFilePath, rewritten, 'utf8');
            }
        }),
    );
};

export const inlineTypesIntoSdkDist = async (): Promise<void> => {
    await ensureTypesPackageBuilt();

    const typesDeclarationText = await readFile(
        typesDeclarationSourcePath,
        'utf8',
    );

    await mkdir(path.dirname(typesDeclarationOutputPath), {
        recursive: true,
    });
    await writeFile(typesDeclarationOutputPath, typesDeclarationText, 'utf8');
    await writeFile(
        typesRuntimeOutputPath,
        transpileSdkInternalSource(
            await readFile(typesRuntimeSourcePath, 'utf8'),
            typesRuntimeSourcePath,
        ),
        'utf8',
    );

    const declarationFiles = await collectFiles(sdkDistDirectoryPath, {
        extensions: ['.d.ts'],
    });

    await Promise.all(
        declarationFiles.map(async (declarationFilePath) => {
            if (declarationFilePath === typesDeclarationOutputPath) {
                return;
            }

            const original = await readFile(declarationFilePath, 'utf8');
            if (!original.includes(typesPackageName)) {
                return;
            }

            const rewritten = rewriteTypesImports(
                declarationFilePath,
                original,
                typesRuntimeOutputPath,
            );
            if (rewritten !== original) {
                await writeFile(declarationFilePath, rewritten, 'utf8');
            }
        }),
    );
};

export const buildSdkInternalRuntime = async (): Promise<void> => {
    await buildSdkBridge();
    await buildSdkProtocolShellRuntime();
    await rewriteWorkspaceRuntimeImports();
    await inlineTypesIntoSdkDist();
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    await buildSdkInternalRuntime();
}
