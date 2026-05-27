import {
    copyFile,
    mkdir,
    readFile,
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

import { collectFiles } from '../internal/files.js';
import { rewriteModuleSpecifiers } from '../internal/module-specifiers.js';

import publicSurface from '#packages/sdk/public-surface.json' with { type: 'json' };

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
const bridgePartsSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'wasm',
    'src',
    'transcript-core-bridge',
);
const bridgePartsOutputDirectoryPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'transcript-core-bridge',
);
const protocolSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'protocol',
    'src',
);
const cryptoSourceDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'crypto',
    'src',
);
const electionFoundationOutputDirectoryPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'election-foundation',
);
const cryptoOutputDirectoryPath = path.resolve(
    sdkDistDirectoryPath,
    'internal',
    'crypto',
);
const typesPackageName = '@sealed-lattice/types';
const typesBuildOutputDirectoryPath = path.resolve(
    repoRoot,
    'packages',
    'types',
    'dist',
);
const typesDeclarationSourcePath = path.resolve(
    typesBuildOutputDirectoryPath,
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
    ['@sealed-lattice/crypto', cryptoOutputDirectoryPath],
    ['@sealed-lattice/types', typesRuntimeOutputPath],
    ['@sealed-lattice/protocol', electionFoundationOutputDirectoryPath],
    ['@sealed-lattice/wasm', bridgeOutputPath],
]);
export const sdkProtocolRuntimeSourceRelativePaths =
    publicSurface.vendoredProtocolRuntimeModules;
const sdkProtocolRuntimeIndexSource =
    publicSurface.vendoredProtocolRuntimeEntryExports
        .map(
            (entry) =>
                `export { ${entry.exports.join(', ')} } from './${entry.source}';`,
        )
        .join('\n') + '\n';

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

    const bridgePartSourcePaths = await collectFiles(
        bridgePartsSourceDirectoryPath,
        {
            extensions: ['.ts'],
        },
    );

    await rm(bridgePartsOutputDirectoryPath, {
        recursive: true,
        force: true,
    });
    await mkdir(bridgePartsOutputDirectoryPath, { recursive: true });
    await Promise.all(
        bridgePartSourcePaths.map(async (sourcePath) => {
            const relativeSourcePath = path.relative(
                bridgePartsSourceDirectoryPath,
                sourcePath,
            );
            const outputPath = path.join(
                bridgePartsOutputDirectoryPath,
                relativeSourcePath.replace(/\.ts$/u, '.js'),
            );
            const bridgePartSourceText = await readFile(sourcePath, 'utf8');
            const bridgePartOutputText = transpileSdkInternalSource(
                bridgePartSourceText,
                sourcePath,
            );

            await mkdir(path.dirname(outputPath), { recursive: true });
            await writeFile(outputPath, bridgePartOutputText, 'utf8');
        }),
    );
};

export const buildSdkProtocolRuntime = async (): Promise<void> => {
    await rm(electionFoundationOutputDirectoryPath, {
        recursive: true,
        force: true,
    });
    await mkdir(electionFoundationOutputDirectoryPath, { recursive: true });

    await Promise.all(
        sdkProtocolRuntimeSourceRelativePaths.map(
            async (relativeSourcePath) => {
                const sourcePath = path.join(
                    protocolSourceDirectoryPath,
                    relativeSourcePath,
                );
                const outputPath = path.join(
                    electionFoundationOutputDirectoryPath,
                    relativeSourcePath.replace(/\.ts$/u, '.js'),
                );
                const sourceText = await readFile(sourcePath, 'utf8');
                const outputText = transpileSdkInternalSource(
                    sourceText,
                    sourcePath,
                );

                await mkdir(path.dirname(outputPath), { recursive: true });
                await writeFile(outputPath, outputText, 'utf8');
            },
        ),
    );
    await writeFile(
        path.join(electionFoundationOutputDirectoryPath, 'index.js'),
        sdkProtocolRuntimeIndexSource,
        'utf8',
    );
};

export const buildSdkCryptoRuntime = async (): Promise<void> => {
    const sourceFilePaths = await collectFiles(cryptoSourceDirectoryPath, {
        extensions: ['.ts'],
    });

    await rm(cryptoOutputDirectoryPath, {
        recursive: true,
        force: true,
    });
    await mkdir(cryptoOutputDirectoryPath, { recursive: true });

    await Promise.all(
        sourceFilePaths.map(async (sourcePath) => {
            const relativeSourcePath = path.relative(
                cryptoSourceDirectoryPath,
                sourcePath,
            );
            const outputPath = path.join(
                cryptoOutputDirectoryPath,
                relativeSourcePath.replace(/\.ts$/u, '.js'),
            );
            const sourceText = await readFile(sourcePath, 'utf8');
            const outputText = transpileSdkInternalSource(
                sourceText,
                sourcePath,
            );

            await mkdir(path.dirname(outputPath), { recursive: true });
            await writeFile(outputPath, outputText, 'utf8');
        }),
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
            `Cannot inline @sealed-lattice/types into the published SDK. The types package has not been built. Run \`pnpm --filter @sealed-lattice/types run build\` first (the workspace \`pnpm run build\` already chains it via Turborepo).`,
        );
    }
};

const stripJavaScriptSourceMapComment = (sourceText: string): string =>
    sourceText.replace(/\r?\n\/\/# sourceMappingURL=.*(?:\r?\n)?$/u, '\n');

const copyTypesPackageSupportFiles = async (): Promise<void> => {
    const supportFilePaths = await collectFiles(typesBuildOutputDirectoryPath, {
        fileNamePattern: /\.(?:d\.ts|js)$/u,
    });

    await Promise.all(
        supportFilePaths.map(async (sourcePath) => {
            const relativeSourcePath = path.relative(
                typesBuildOutputDirectoryPath,
                sourcePath,
            );
            if (
                relativeSourcePath === 'index.d.ts' ||
                relativeSourcePath === 'index.js' ||
                relativeSourcePath === 'index.js.map'
            ) {
                return;
            }

            const outputPath = path.join(
                sdkDistDirectoryPath,
                'internal',
                relativeSourcePath,
            );

            await mkdir(path.dirname(outputPath), { recursive: true });
            if (sourcePath.endsWith('.js')) {
                await writeFile(
                    outputPath,
                    stripJavaScriptSourceMapComment(
                        await readFile(sourcePath, 'utf8'),
                    ),
                    'utf8',
                );
                return;
            }

            await copyFile(sourcePath, outputPath);
        }),
    );
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
    await copyTypesPackageSupportFiles();

    const declarationFiles = await collectFiles(sdkDistDirectoryPath, {
        fileNamePattern: /\.d\.ts$/u,
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
    await buildSdkCryptoRuntime();
    await buildSdkProtocolRuntime();
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
