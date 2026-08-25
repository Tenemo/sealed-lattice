import { fileURLToPath } from 'node:url';

import { defineConfig } from 'tsdown';

const sdkDeclarationEntryEnvironmentVariable =
    'SEALED_LATTICE_SDK_DECLARATION_ENTRY_PATH';
const sdkKernelHashEnvironmentVariable =
    'SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX';
const sha256HexPattern = /^[a-f0-9]{64}$/u;
const kernelHash = process.env[sdkKernelHashEnvironmentVariable];
const declarationEntryPath =
    process.env[sdkDeclarationEntryEnvironmentVariable];
const sdkPackageDirectoryPath = fileURLToPath(
    new URL('../../packages/sdk/', import.meta.url),
);
const sdkTsconfigPath = fileURLToPath(
    new URL('../../packages/sdk/tsconfig.json', import.meta.url),
);

if (kernelHash === undefined || !sha256HexPattern.test(kernelHash)) {
    throw new Error(
        `${sdkKernelHashEnvironmentVariable} must contain the normalized SHA-256 hash of the packaged WASM kernel. Run the SDK package build through its package script.`,
    );
}
if (declarationEntryPath === undefined) {
    throw new Error(
        `${sdkDeclarationEntryEnvironmentVariable} must identify the declaration entry emitted by TypeScript. Run the SDK package build through its package script.`,
    );
}

const bundledWorkspacePackagePattern =
    /^@sealed-lattice\/(?:protocol|types|wasm)$/u;
const externalCryptographyPackagePattern = /^@noble\//u;
const externalNodeBuiltinPattern = /^node:/u;
const dependencyPolicy = {
    alwaysBundle: [bundledWorkspacePackagePattern],
    dts: {
        alwaysBundle: [bundledWorkspacePackagePattern],
        neverBundle: [
            externalCryptographyPackagePattern,
            externalNodeBuiltinPattern,
        ],
    },
    neverBundle: [
        externalCryptographyPackagePattern,
        externalNodeBuiltinPattern,
    ],
};

export default defineConfig([
    {
        clean: true,
        cwd: sdkPackageDirectoryPath,
        define: {
            __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
                JSON.stringify(kernelHash),
        },
        deps: dependencyPolicy,
        dts: false,
        entry: {
            index: 'src/index.ts',
        },
        failOnWarn: true,
        fixedExtension: false,
        format: 'esm',
        hash: false,
        minify: false,
        name: 'sdk-javascript',
        outDir: 'dist',
        outputOptions: {
            codeSplitting: false,
        },
        platform: 'neutral',
        report: false,
        sourcemap: true,
        target: 'es2020',
        treeshake: true,
        tsconfig: sdkTsconfigPath,
    },
    {
        clean: false,
        cwd: sdkPackageDirectoryPath,
        deps: dependencyPolicy,
        dts: {
            dtsInput: true,
            emitDtsOnly: true,
            tsconfig: false,
        },
        entry: {
            index: declarationEntryPath,
        },
        failOnWarn: true,
        fixedExtension: false,
        format: 'esm',
        hash: false,
        minify: false,
        name: 'sdk-declarations',
        outDir: 'dist',
        outputOptions: {
            codeSplitting: false,
        },
        platform: 'neutral',
        report: false,
        sourcemap: false,
        target: 'es2020',
        treeshake: true,
        tsconfig: false,
    },
]);
