import { fileURLToPath } from 'node:url';

import { defineConfig, type UserConfig } from 'tsdown';

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

// The participant runtime the SDK build packaged: the digests of its source
// manifest, module and worker, the runtime identity they form, and the
// worker's source.
const hexadecimalDigest = /^[a-f0-9]{128}$/u;
const isParticipantRuntime = (
    value: unknown,
): value is Readonly<{
    identity: Readonly<Record<string, unknown>>;
    worker: unknown;
}> =>
    typeof value === 'object' &&
    value !== null &&
    'identity' in value &&
    typeof value.identity === 'object' &&
    value.identity !== null &&
    'worker' in value &&
    Object.keys(value).length === 2;

export default defineConfig(() => {
    const participantRuntime: unknown = JSON.parse(
        process.env.SEALED_LATTICE_PARTICIPANT_RUNTIME ?? 'null',
    );
    if (
        !isParticipantRuntime(participantRuntime) ||
        Object.keys(participantRuntime.identity).sort().join(',') !==
            'module,runtime,source,worker' ||
        !Object.values(participantRuntime.identity).every(
            (digest) =>
                typeof digest === 'string' && hexadecimalDigest.test(digest),
        ) ||
        typeof participantRuntime.worker !== 'string' ||
        participantRuntime.worker.length === 0
    ) {
        throw new Error(
            'Build the SDK through its package script so the participant runtime is available.',
        );
    }
    return sdkPackageOptions(participantRuntime);
});
