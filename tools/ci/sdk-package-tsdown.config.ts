import { fileURLToPath } from 'node:url';

import { defineConfig } from 'tsdown';

const kernelHash = process.env.SEALED_LATTICE_KERNEL_SHA256_HEX;
if (!/^[a-f0-9]{64}$/u.test(kernelHash ?? '')) {
    throw new Error(
        'Build the SDK through its package script so the exact kernel hash is available.',
    );
}

const sdkPackageDirectoryPath = fileURLToPath(
    new URL('../../packages/sdk/', import.meta.url),
);
const internalWasmPackage = /^@sealed-lattice\/wasm(?:\/|$)/u;
const nodeBuiltin = /^node:/u;

export default defineConfig({
    clean: true,
    cwd: sdkPackageDirectoryPath,
    define: {
        __SEALED_LATTICE_KERNEL_SHA256_HEX__: JSON.stringify(kernelHash),
    },
    deps: {
        alwaysBundle: [internalWasmPackage],
        dts: {
            alwaysBundle: [internalWasmPackage],
            neverBundle: [nodeBuiltin],
        },
        neverBundle: [nodeBuiltin],
    },
    dts: {
        incremental: false,
        newContext: true,
    },
    entry: { index: 'src/index.ts' },
    failOnWarn: true,
    format: 'esm',
    minify: false,
    outDir: 'dist',
    outputOptions: { codeSplitting: false },
    platform: 'neutral',
    report: false,
    sourcemap: true,
    target: 'es2020',
    treeshake: true,
    tsconfig: fileURLToPath(
        new URL('../../packages/sdk/tsconfig.json', import.meta.url),
    ),
});
