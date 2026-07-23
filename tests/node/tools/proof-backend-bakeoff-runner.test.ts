import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    buildProofBackendBakeoffEnvironment,
    buildProofBackendBakeoffPrecompileCommand,
    executeProofBackendBakeoffSequence,
    runProofBackendBakeoff,
    writeJsonAtomicallyAndExclusively,
} from '#tools/ci/run-proof-backend-bakeoff';

const withTemporaryDirectory = async <Result>(
    action: (directoryPath: string) => Promise<Result>,
): Promise<Result> => {
    const directoryPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-proof-backend-bakeoff-'),
    );
    try {
        return await action(directoryPath);
    } finally {
        await rm(directoryPath, { force: true, recursive: true });
    }
};

describe('Proof backend bakeoff runner', () => {
    it('pins the release feature and isolates the reusable preflight environment', () => {
        const environment = buildProofBackendBakeoffEnvironment({
            baseEnvironment: {
                CARGO_TARGET_DIR: 'inherited-target',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND:
                    'inherited-backend',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH:
                    'inherited-result',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL: '9',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            },
            targetDirectoryPath: 'dedicated-target',
        });
        expect(environment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: 'dedicated-target',
            RAYON_NUM_THREADS: '1',
            RUST_TEST_THREADS: '1',
        });
        expect(
            environment.SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND,
        ).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();

        const precompileCommand =
            buildProofBackendBakeoffPrecompileCommand(environment);
        expect(precompileCommand.args).toEqual(
            expect.arrayContaining([
                '--locked',
                '--release',
                '--features',
                'proof-backend-bakeoff',
                '--lib',
                '--no-run',
            ]),
        );
    });

    it('refuses to rerun the immutable recorded bakeoff', async () => {
        await expect(runProofBackendBakeoff([])).rejects.toThrow(
            /recorded proof backend bakeoff is immutable/u,
        );
    });

    it('refuses direct executor access before consulting injected dependencies', async () => {
        let dependencyWasCalled = false;
        await expect(
            executeProofBackendBakeoffSequence({
                dependencies: {
                    executeCommand: () => {
                        dependencyWasCalled = true;
                        throw new Error('The retired executor ran a command.');
                    },
                },
            }),
        ).rejects.toThrow(/recorded proof backend bakeoff is immutable/u);
        expect(dependencyWasCalled).toBe(false);
    });

    it('publishes aggregate JSON atomically without overwriting evidence', () =>
        withTemporaryDirectory(async (directoryPath) => {
            const evidencePath = path.join(directoryPath, 'evidence.json');
            await writeJsonAtomicallyAndExclusively(evidencePath, {
                sampleCount: 6,
            });
            await expect(
                writeJsonAtomicallyAndExclusively(evidencePath, {
                    sampleCount: 7,
                }),
            ).rejects.toThrow(/Refusing to overwrite/u);
            expect(JSON.parse(await readFile(evidencePath, 'utf8'))).toEqual({
                sampleCount: 6,
            });
            expect(await readdir(directoryPath)).toEqual(['evidence.json']);
        }));
});
