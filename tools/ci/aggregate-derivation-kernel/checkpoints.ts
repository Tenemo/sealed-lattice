import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { canonicalJson } from '#packages/crypto/src/index';
import {
    bytesToHex,
    normalizeRustSourcePathsForHash,
} from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

export type CheckpointStage =
    | 'aggregate-kernel-ballot-proof-package'
    | 'aggregate-kernel-bgv-passive-setup'
    | 'aggregate-kernel-bridge-contributor'
    | 'aggregate-kernel-component-receiver';

export type RuntimeBinding = {
    readonly dependencyArtifactHash: string;
    readonly kernelHash: string;
    readonly sourceFingerprint: string;
};

export type CheckpointContext = RuntimeBinding & {
    readonly checkpointName: string;
    readonly inputHash: string;
    readonly stage: CheckpointStage;
};

type CheckpointManifestEntry = {
    readonly artifactHash: string;
    readonly dependencyArtifactHash: string;
    readonly inputHash: string;
    readonly kernelHash: string;
    readonly schemaVersion: string;
    readonly sourceFingerprint: string;
    readonly stage: CheckpointStage;
    readonly verifierOutputHash: string | null;
};

type CheckpointManifest = {
    readonly entries: Record<string, CheckpointManifestEntry>;
    readonly objectType: 'AggregateDerivationKernelCheckpointManifest';
    readonly objectVersion: 1;
};

type CheckpointEnvelope<Value> = CheckpointManifestEntry & {
    readonly artifactHash: string;
    readonly cachedFreshCsprngArtifact: boolean;
    readonly checkpointName: string;
    readonly objectType: 'AggregateDerivationKernelCheckpoint';
    readonly objectVersion: 1;
    readonly value: Value;
};

const checkpointSchemaVersion = 'aggregate-derivation-kernel-checkpoint-v1';
const manifestFileName = 'aggregate-derivation-kernel-manifest.json';

const sleep = async (milliseconds: number): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, milliseconds);
    });

const hashBytes = (bytes: Uint8Array): string =>
    bytesToHex(createHash('sha256').update(bytes).digest());

const hashText = (text: string): string =>
    createHash('sha256').update(text, 'utf8').digest('hex');

const checkpointSafeValue = (value: unknown): unknown => {
    if (value === undefined) {
        return null;
    }
    if (Array.isArray(value)) {
        return value.map(checkpointSafeValue);
    }
    if (typeof value !== 'object' || value === null) {
        return value;
    }

    return Object.fromEntries(
        Object.entries(value)
            .filter((entry) => entry[1] !== undefined)
            .map(([key, entryValue]) => [key, checkpointSafeValue(entryValue)]),
    );
};

export const hashJson = (value: unknown): string =>
    hashText(canonicalJson(checkpointSafeValue(value)));

export const readJsonFile = async <Value>(filePath: string): Promise<Value> =>
    JSON.parse(await readFile(filePath, 'utf8')) as Value;

export const writeJsonFileAtomic = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await mkdir(path.dirname(filePath), { recursive: true });
    const tempPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await rm(filePath, { force: true });
    await rename(tempPath, filePath);
};

const acquireLock = async (lockPath: string): Promise<() => Promise<void>> => {
    await mkdir(path.dirname(lockPath), { recursive: true });
    for (let attempt = 0; attempt < 600; attempt += 1) {
        try {
            const handle = await open(lockPath, 'wx');

            return async () => {
                await handle.close();
                await rm(lockPath, { force: true });
            };
        } catch (error) {
            const code =
                typeof error === 'object' && error !== null
                    ? (error as { readonly code?: unknown }).code
                    : undefined;
            if (code !== 'EEXIST') {
                throw error;
            }
            await sleep(100);
        }
    }

    throw new Error(`Timed out waiting for checkpoint lock: ${lockPath}`);
};

const manifestPath = (checkpointDir: string): string =>
    path.join(checkpointDir, manifestFileName);

const checkpointPath = (
    checkpointDir: string,
    checkpointName: string,
): string => path.join(checkpointDir, `${checkpointName}.json`);

const readManifest = async (
    checkpointDir: string,
): Promise<CheckpointManifest> => {
    const filePath = manifestPath(checkpointDir);
    if (!existsSync(filePath)) {
        return {
            entries: {},
            objectType: 'AggregateDerivationKernelCheckpointManifest',
            objectVersion: 1,
        };
    }

    return readJsonFile<CheckpointManifest>(filePath);
};

const writeManifest = async (
    checkpointDir: string,
    manifest: CheckpointManifest,
): Promise<void> => {
    await writeJsonFileAtomic(manifestPath(checkpointDir), manifest);
};

const equivalentManifestEntry = (
    left: CheckpointManifestEntry,
    right: CheckpointManifestEntry,
): boolean =>
    left.artifactHash === right.artifactHash &&
    left.dependencyArtifactHash === right.dependencyArtifactHash &&
    left.inputHash === right.inputHash &&
    left.kernelHash === right.kernelHash &&
    left.schemaVersion === right.schemaVersion &&
    left.sourceFingerprint === right.sourceFingerprint &&
    left.stage === right.stage &&
    left.verifierOutputHash === right.verifierOutputHash;

const hashExistingFiles = async (
    filePaths: readonly string[],
): Promise<string> => {
    const entries = await Promise.all(
        filePaths.map(async (filePath) => {
            const absolutePath = path.resolve(process.cwd(), filePath);
            if (!existsSync(absolutePath)) {
                return {
                    filePath,
                    hash: null,
                };
            }

            return {
                filePath,
                hash: hashBytes(new Uint8Array(await readFile(absolutePath))),
            };
        }),
    );

    return hashJson(entries);
};

const computeSourceFingerprint = async (): Promise<string> =>
    hashExistingFiles([
        'tools/ci/run-aggregate-derivation-kernel.ts',
        'tools/ci/run-encrypted-aggregate-evaluator-representative.ts',
        'tools/ci/aggregate-derivation-kernel/checkpoints.ts',
        'tools/ci/aggregate-derivation-kernel/config.ts',
        'tools/ci/aggregate-derivation-kernel/runner.ts',
        'tools/ci/aggregate-derivation-kernel/types.ts',
        'tools/ci/aggregate-derivation-kernel/worker-process.ts',
        'packages/protocol/tests/node/ballot-privacy-proof-record-generation-fixtures/fixture-assembly.ts',
        'packages/protocol/tests/node/ballot-privacy-proof-record-generation-fixtures/fixture-inputs.ts',
        'packages/protocol/src/ballot-privacy/aggregate-derivation.ts',
        'packages/protocol/src/ballot-privacy/aggregate-bridge.ts',
        'packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification/pending-bridge-proof-record.ts',
        'packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification/ready-record.ts',
        'crates/sealed-lattice-kernel/src/bgv/profile.rs',
        'crates/sealed-lattice-kernel/src/bgv/setup.rs',
        'crates/sealed-lattice-kernel/src/bgv/setup/certificates.rs',
        'crates/sealed-lattice-kernel/src/bgv/setup/encrypted_aggregate_bridge_trace.rs',
        'crates/sealed-lattice-kernel/src/bgv/setup/key_material.rs',
        'crates/sealed-lattice-kernel/src/bgv/evaluator/circuit.rs',
        'crates/sealed-lattice-kernel/src/bgv/evaluator/commands.rs',
        'crates/sealed-lattice-kernel/src/bgv/evaluator/engine.rs',
        'crates/sealed-lattice-kernel/src/bgv/evaluator/key_switch.rs',
        'crates/sealed-lattice-kernel/src/bgv/evaluator/records.rs',
        'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k.rs',
        'crates/sealed-lattice-kernel/src/ballot_privacy/aggregate_bridge_proof.rs',
        'crates/sealed-lattice-kernel/src/ballot_privacy/aggregate_bridge_proof/statement.rs',
        'crates/sealed-lattice-kernel/src/ballot_privacy/aggregate_bridge_proof/verification.rs',
    ]);

const computeDependencyArtifactHash = async (): Promise<string> =>
    hashExistingFiles([
        'package.json',
        'pnpm-lock.yaml',
        'packages/wasm/dist/index.js',
        'packages/wasm/dist/transcript-core-bridge/kernel-loader.js',
        'packages/wasm/dist/transcript-core-bridge/kernel-types.d.ts',
    ]);

export const runtimeContext = async (): Promise<RuntimeBinding> => {
    const wasmPath = path.resolve(
        process.cwd(),
        'packages',
        'wasm',
        'dist',
        'sealed-lattice-kernel.wasm',
    );
    const wasmBytes = new Uint8Array(await readFile(wasmPath));
    const kernelHash = hashBytes(normalizeRustSourcePathsForHash(wasmBytes));
    const sourceFingerprint = await computeSourceFingerprint();
    const dependencyArtifactHash = await computeDependencyArtifactHash();

    return {
        dependencyArtifactHash,
        kernelHash,
        sourceFingerprint,
    };
};

export const checkpointContext = (
    input: RuntimeBinding & {
        readonly checkpointName: string;
        readonly input: unknown;
        readonly stage: CheckpointStage;
    },
): CheckpointContext => ({
    checkpointName: input.checkpointName,
    dependencyArtifactHash: input.dependencyArtifactHash,
    inputHash: hashJson(input.input),
    kernelHash: input.kernelHash,
    sourceFingerprint: input.sourceFingerprint,
    stage: input.stage,
});

export const readCheckpoint = async <Value>(input: {
    readonly checkpointDir: string;
    readonly context: CheckpointContext;
    readonly requireCheckpoints: boolean;
    readonly requireVerifierOutput: boolean;
    readonly resumeCheckpoints: boolean;
}): Promise<Value | undefined> => {
    if (!input.resumeCheckpoints) {
        return undefined;
    }
    const filePath = checkpointPath(
        input.checkpointDir,
        input.context.checkpointName,
    );
    if (!existsSync(filePath)) {
        if (input.requireCheckpoints) {
            throw new Error(`Missing required checkpoint: ${filePath}`);
        }

        return undefined;
    }

    try {
        const [manifest, envelope] = await Promise.all([
            readManifest(input.checkpointDir),
            readJsonFile<CheckpointEnvelope<Value>>(filePath),
        ]);
        const manifestEntry = manifest.entries[input.context.checkpointName];
        const expectedBase = {
            artifactHash: hashJson(envelope.value),
            dependencyArtifactHash: input.context.dependencyArtifactHash,
            inputHash: input.context.inputHash,
            kernelHash: input.context.kernelHash,
            schemaVersion: checkpointSchemaVersion,
            sourceFingerprint: input.context.sourceFingerprint,
            stage: input.context.stage,
            verifierOutputHash: envelope.verifierOutputHash,
        } satisfies CheckpointManifestEntry;
        const envelopeEntry = {
            artifactHash: envelope.artifactHash,
            dependencyArtifactHash: envelope.dependencyArtifactHash,
            inputHash: envelope.inputHash,
            kernelHash: envelope.kernelHash,
            schemaVersion: envelope.schemaVersion,
            sourceFingerprint: envelope.sourceFingerprint,
            stage: envelope.stage,
            verifierOutputHash: envelope.verifierOutputHash,
        } satisfies CheckpointManifestEntry;
        if (
            envelope.objectType !== 'AggregateDerivationKernelCheckpoint' ||
            envelope.objectVersion !== 1 ||
            envelope.checkpointName !== input.context.checkpointName ||
            !equivalentManifestEntry(envelopeEntry, expectedBase) ||
            manifestEntry === undefined ||
            !equivalentManifestEntry(manifestEntry, expectedBase)
        ) {
            if (input.requireCheckpoints) {
                throw new Error(
                    `Required checkpoint is stale or mismatched: ${filePath}`,
                );
            }

            return undefined;
        }
        if (
            input.requireVerifierOutput &&
            envelope.verifierOutputHash === null
        ) {
            if (input.requireCheckpoints) {
                throw new Error(
                    `Required checkpoint has no verifier output hash: ${filePath}`,
                );
            }

            return undefined;
        }

        console.log(
            `checkpoint hit: ${input.context.checkpointName} (${input.context.stage})`,
        );

        return envelope.value;
    } catch (error) {
        if (input.requireCheckpoints) {
            throw error;
        }
        console.warn(
            `checkpoint ignored: ${input.context.checkpointName} (${String(error)})`,
        );

        return undefined;
    }
};

const writeCheckpoint = async <Value>(input: {
    readonly cachedFreshCsprngArtifact?: boolean;
    readonly checkpointDir: string;
    readonly context: CheckpointContext;
    readonly value: Value;
    readonly verifierOutput?: unknown;
}): Promise<void> => {
    const release = await acquireLock(
        path.join(input.checkpointDir, '.checkpoint-manifest.lock'),
    );
    try {
        const value = checkpointSafeValue(input.value) as Value;
        const artifactHash = hashJson(value);
        const verifierOutputHash =
            input.verifierOutput === undefined
                ? null
                : hashJson(input.verifierOutput);
        const entry = {
            artifactHash,
            dependencyArtifactHash: input.context.dependencyArtifactHash,
            inputHash: input.context.inputHash,
            kernelHash: input.context.kernelHash,
            schemaVersion: checkpointSchemaVersion,
            sourceFingerprint: input.context.sourceFingerprint,
            stage: input.context.stage,
            verifierOutputHash,
        } satisfies CheckpointManifestEntry;
        const envelope = {
            ...entry,
            cachedFreshCsprngArtifact: input.cachedFreshCsprngArtifact ?? false,
            checkpointName: input.context.checkpointName,
            objectType: 'AggregateDerivationKernelCheckpoint',
            objectVersion: 1,
            value,
        } satisfies CheckpointEnvelope<Value>;
        await writeJsonFileAtomic(
            checkpointPath(input.checkpointDir, input.context.checkpointName),
            envelope,
        );
        const manifest = await readManifest(input.checkpointDir);
        await writeManifest(input.checkpointDir, {
            entries: {
                ...manifest.entries,
                [input.context.checkpointName]: entry,
            },
            objectType: 'AggregateDerivationKernelCheckpointManifest',
            objectVersion: 1,
        });
        console.log(
            `checkpoint written: ${input.context.checkpointName} (${input.context.stage})`,
        );
    } finally {
        await release();
    }
};

const forceMatches = (
    forceRecompute: ReadonlySet<string>,
    stage: CheckpointStage,
): boolean => {
    if (forceRecompute.has(stage)) {
        return true;
    }
    if (
        stage === 'aggregate-kernel-ballot-proof-package' &&
        forceRecompute.has('ballot-package')
    ) {
        return true;
    }
    if (
        stage === 'aggregate-kernel-bgv-passive-setup' &&
        forceRecompute.has('bgv-passive-setup')
    ) {
        return true;
    }
    if (
        stage === 'aggregate-kernel-bridge-contributor' &&
        forceRecompute.has('bridge-contributors')
    ) {
        return true;
    }

    return false;
};

export const loadOrComputeCheckpoint = async <Value>(input: {
    readonly cachedFreshCsprngArtifact?: boolean;
    readonly checkpointDir: string;
    readonly compute: () =>
        | Promise<{
              readonly value: Value;
              readonly verifierOutput?: unknown;
          }>
        | {
              readonly value: Value;
              readonly verifierOutput?: unknown;
          };
    readonly context: CheckpointContext;
    readonly forceRecompute: ReadonlySet<string>;
    readonly requireCheckpoints: boolean;
    readonly requireVerifierOutput?: boolean;
    readonly resumeCheckpoints: boolean;
}): Promise<{ readonly fromCheckpoint: boolean; readonly value: Value }> => {
    if (!forceMatches(input.forceRecompute, input.context.stage)) {
        const checkpoint = await readCheckpoint<Value>({
            checkpointDir: input.checkpointDir,
            context: input.context,
            requireCheckpoints: input.requireCheckpoints,
            requireVerifierOutput: input.requireVerifierOutput ?? false,
            resumeCheckpoints: input.resumeCheckpoints,
        });
        if (checkpoint !== undefined) {
            return { fromCheckpoint: true, value: checkpoint };
        }
    }
    if (input.requireCheckpoints) {
        throw new Error(
            `Required checkpoint was not reusable: ${input.context.checkpointName}`,
        );
    }

    const computed = await input.compute();
    await writeCheckpoint({
        cachedFreshCsprngArtifact: input.cachedFreshCsprngArtifact,
        checkpointDir: input.checkpointDir,
        context: input.context,
        value: computed.value,
        verifierOutput: computed.verifierOutput,
    });

    return { fromCheckpoint: false, value: computed.value };
};
