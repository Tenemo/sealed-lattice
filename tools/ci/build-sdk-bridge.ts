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
    ScriptTarget,
    formatDiagnosticsWithColorAndContext,
    transpileModule,
} from 'typescript';

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

const typesImportPattern = /(['"])@sealed-lattice\/types(?:\/[^'"]*)?\1/gu;

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

export const rewriteTypesImports = (
    declarationFilePath: string,
    declarationText: string,
    typesRuntimePath: string,
): string => {
    const relativeSpecifier = computeRelativeTypesSpecifier(
        declarationFilePath,
        typesRuntimePath,
    );

    return declarationText.replace(
        typesImportPattern,
        (_match, quote: string) => `${quote}${relativeSpecifier}${quote}`,
    );
};

const collectDeclarationFiles = async (
    directoryPath: string,
): Promise<string[]> => {
    const entries = await readdir(directoryPath, { withFileTypes: true });
    const collected: string[] = [];

    for (const entry of entries) {
        const entryPath = path.join(directoryPath, entry.name);
        if (entry.isDirectory()) {
            collected.push(...(await collectDeclarationFiles(entryPath)));
            continue;
        }
        if (entry.isFile() && entry.name.endsWith('.d.ts')) {
            collected.push(entryPath);
        }
    }

    return collected;
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
    await writeFile(typesRuntimeOutputPath, 'export {};\n', 'utf8');

    const declarationFiles =
        await collectDeclarationFiles(sdkDistDirectoryPath);

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
    await inlineTypesIntoSdkDist();
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    await buildSdkInternalRuntime();
}
