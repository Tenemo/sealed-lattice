import { fileURLToPath } from 'node:url';

import type { UserConfig } from 'tsdown';

const sdkPackageDirectoryPath = fileURLToPath(
    new URL('../../packages/sdk/', import.meta.url),
);
const nodeBuiltin = /^node:/u;

// The SDK entry's bundle options, which embed the participant runtime the
// SDK build packaged.
export const sdkPackageOptions = (participantRuntime: unknown): UserConfig => ({
    clean: true,
    cwd: sdkPackageDirectoryPath,
    define: {
        __SEALED_LATTICE_PARTICIPANT_RUNTIME__:
            JSON.stringify(participantRuntime),
    },
    deps: {
        dts: {
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
