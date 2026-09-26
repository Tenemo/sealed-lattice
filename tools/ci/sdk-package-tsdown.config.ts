import { fileURLToPath } from 'node:url';

import { defineConfig } from 'tsdown';

const kernelHash = process.env.SEALED_LATTICE_KERNEL_SHA256_HEX;
if (!/^[a-f0-9]{64}$/u.test(kernelHash ?? '')) {
    throw new Error(
        'Build the SDK through its package script so the exact kernel hash is available.',
    );
}

// The participant runtime the SDK build packaged: the digests of its source
// manifest, module and worker, the runtime identity they form, and the
// worker's source.
const hexadecimalDigest = /^[a-f0-9]{128}$/u;
const participantRuntime: unknown = JSON.parse(
    process.env.SEALED_LATTICE_PARTICIPANT_RUNTIME ?? 'null',
);
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
        __SEALED_LATTICE_PARTICIPANT_RUNTIME__:
            JSON.stringify(participantRuntime),
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
