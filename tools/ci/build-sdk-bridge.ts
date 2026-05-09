import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
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
const bridgeSourcePath = path.resolve(
    repoRoot,
    'packages',
    'wasm',
    'src',
    'transcript-core-bridge.ts',
);
const bridgeOutputPath = path.resolve(
    repoRoot,
    'packages',
    'sdk',
    'dist',
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
    repoRoot,
    'packages',
    'sdk',
    'dist',
    'internal',
    'protocol-shell',
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

export const buildSdkInternalRuntime = async (): Promise<void> => {
    await buildSdkBridge();
    await buildSdkProtocolShellRuntime();
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    await buildSdkInternalRuntime();
}
