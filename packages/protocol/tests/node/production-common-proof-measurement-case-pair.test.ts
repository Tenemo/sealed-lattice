import type {
    CommonProofGenerationCheckpoint,
    CommonProofGenerationWorkerOptions,
} from '@sealed-lattice/wasm';
import { CommonProofWorkerRuntimeError } from '@sealed-lattice/wasm';
import { describe, expect, it } from 'vitest';

import type {
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import {
    createProductionCommonProofMeasurementCasePair,
    type ProductionCommonProofMeasurementOperation,
} from '#packages/protocol/tests/support/production-common-proof-measurement-case-pair';

const measurementIdentity = Object.freeze({
    actionContextHash: '1'.repeat(128),
    inputCorpusHash: '2'.repeat(128),
    manifestHash: '3'.repeat(128),
    packagedWasmSha256: '4'.repeat(64),
    runtimeBuildManifestHash: '5'.repeat(128),
    suiteIdentifier: '6'.repeat(128),
});

const checkpoint = Object.freeze({
    canonicalStateBytes: Uint8Array.of(1, 2),
    privateRandomCursorManifestBytes: Uint8Array.of(3, 4),
    safeBoundaryOrdinal: 1,
    stableAttemptBindingHash: new Uint8Array(64).fill(5),
}) satisfies CommonProofGenerationCheckpoint;

const resumeDescriptor = (): CommonProofCheckpointResumeDescriptor =>
    Object.freeze({
        checkpointLineageIdentifier: new Uint8Array(32).fill(6),
        commonProofEnvironmentIdentifier: new Uint8Array(32).fill(7),
        privateRandomCursorManifestBytes: Uint8Array.of(8, 9),
        privateRandomnessStreamAttemptIdentifier: new Uint8Array(32).fill(10),
        safeBoundaryOrdinal: 1,
        stableAttemptBindingHash: new Uint8Array(64).fill(11),
    });

const controlledCustody = (input: {
    events: string[];
    label: string;
    resumeDescriptor?: CommonProofCheckpointResumeDescriptor;
}): CommonProofBrowserCustody =>
    Object.freeze({
        armApplicationHandoff: () =>
            Promise.resolve({
                canonicalMarkerRecordBytes: Uint8Array.of(1),
                logicalRecordKey: 'handoff',
            }),
        checkpointCustody: Object.freeze({
            publishAuthenticatedCheckpoint: () => {
                input.events.push(`${input.label}:publish`);
                return Promise.resolve();
            },
            restoreAuthenticatedCheckpointState: () => {
                input.events.push(`${input.label}:restore`);
                return Promise.resolve(Uint8Array.of(1, 2));
            },
        }),
        completeVerifiedOutput: () => {
            input.events.push(`${input.label}:complete`);
            return Promise.resolve();
        },
        copyCheckpointResumeDescriptor: () => {
            input.events.push(`${input.label}:copy-resume`);
            return input.resumeDescriptor;
        },
        externalMemory: Object.freeze({
            executeTransaction: () => Promise.resolve([]),
        }),
        prefixReplayExternalMemory: Object.freeze({
            executeDeterministicPrefixReplayTransaction: () => {
                input.events.push(`${input.label}:prefix-replay`);
                return Promise.resolve([]);
            },
        }),
        outputStore: Object.freeze({
            commitChunk: () => {
                input.events.push(`${input.label}:commit-output`);
                return Promise.resolve();
            },
            readChunk: () => Promise.resolve(Uint8Array.of(1)),
        }),
        authenticatedOutput: () =>
            Object.freeze({
                declaredByteLength: 1,
                readCommittedChunk: () => Promise.resolve(Uint8Array.of(1)),
            }),
        releaseExternalMemory: () => Promise.resolve(),
        retire: () => Promise.resolve(),
        sealCanonicalOutput: () =>
            input.events.push(`${input.label}:seal-output`),
        suspendForAuthenticatedResume: () => {
            input.events.push(`${input.label}:suspend`);
            return Promise.resolve();
        },
    });

const operationFixture = (input?: {
    freshRunBehavior?:
        | 'cancel-after-checkpoint'
        | 'complete-without-checkpoint';
}) => {
    const events: string[] = [];
    const descriptor = resumeDescriptor();
    const freshCustody = controlledCustody({
        events,
        label: 'fresh-custody',
        resumeDescriptor: descriptor,
    });
    const resumedCustody = controlledCustody({
        events,
        label: 'resumed-custody',
        resumeDescriptor: descriptor,
    });
    let openedDescriptor: CommonProofCheckpointResumeDescriptor | undefined;
    let runCount = 0;
    let closeCount = 0;
    const operation: ProductionCommonProofMeasurementOperation = Object.freeze({
        close: () => {
            closeCount += 1;
            return Promise.resolve();
        },
        initialCustody: freshCustody,
        measurementIdentity,
        openResumedCustody: (candidateDescriptor) => {
            events.push('operation:open-resumed');
            openedDescriptor = candidateDescriptor;
            return Promise.resolve(resumedCustody);
        },
        run: async ({ custody, generationMode, generationOptions }) => {
            runCount += 1;
            events.push(`operation:run-${generationMode}`);
            if (generationMode === 'fresh') {
                if (input?.freshRunBehavior === 'complete-without-checkpoint') {
                    return;
                }
                await generationOptions.checkpointCustody?.publishAuthenticatedCheckpoint(
                    checkpoint,
                );
                if (generationOptions.signal?.aborted === true) {
                    throw new CommonProofWorkerRuntimeError(
                        'Cancelled',
                        'Interrupted at the checkpoint selected by the measurement.',
                        generationOptions.signal.reason,
                    );
                }
                custody.sealCanonicalOutput();
                return;
            }
            const resume = requireResumeOptions(generationOptions);
            await resume.checkpointCustody.restoreAuthenticatedCheckpointState();
            await resume.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                {} as never,
            );
            await custody.outputStore.commitChunk(0, Uint8Array.of(1));
            custody.sealCanonicalOutput();
            await custody.completeVerifiedOutput();
        },
        wasmMemory: new WebAssembly.Memory({ initial: 1 }),
    });
    return Object.freeze({
        descriptor,
        events,
        get closeCount(): number {
            return closeCount;
        },
        get openedDescriptor():
            | CommonProofCheckpointResumeDescriptor
            | undefined {
            return openedDescriptor;
        },
        operation,
        get runCount(): number {
            return runCount;
        },
    });
};

const requireResumeOptions = (
    options: CommonProofGenerationWorkerOptions,
): NonNullable<CommonProofGenerationWorkerOptions['resume']> => {
    if (options.resume === undefined) {
        throw new Error('Expected resumed generation options.');
    }
    return options.resume;
};

const casePair = (fixture: ReturnType<typeof operationFixture>) =>
    createProductionCommonProofMeasurementCasePair({
        freshCaseIdentifier: 'controlled-proof-fresh',
        openOperation: () => Promise.resolve(fixture.operation),
        resumedCaseIdentifier: 'controlled-proof-resumed',
    });

const yieldControl = (): Promise<void> => Promise.resolve();

describe('Production common-proof measurement case pair', () => {
    it('opens resources without proof work and runs the fresh operation only inside execute', async () => {
        const fixture = operationFixture();
        const session = await casePair(fixture).fresh.open();
        expect(fixture.runCount).toBe(0);
        expect(session.custody).toBe(fixture.operation.initialCustody);

        await session.execute({
            custody: session.custody,
            yieldControl,
        });
        expect(fixture.events).toEqual([
            'operation:run-fresh',
            'fresh-custody:publish',
            'fresh-custody:seal-output',
        ]);
        await session.close();
        expect(fixture.closeCount).toBe(1);
    });

    it('measures checkpoint interruption, authenticated suspension, replay, and resumed completion through one custody facade', async () => {
        const fixture = operationFixture();
        const session = await casePair(fixture).resumed.open();
        expect(fixture.runCount).toBe(0);

        await session.execute({
            custody: session.custody,
            yieldControl,
        });

        expect(fixture.runCount).toBe(2);
        expect(fixture.events).toEqual([
            'operation:run-fresh',
            'fresh-custody:publish',
            'fresh-custody:copy-resume',
            'fresh-custody:suspend',
            'operation:open-resumed',
            'operation:run-resumed',
            'resumed-custody:restore',
            'resumed-custody:prefix-replay',
            'resumed-custody:commit-output',
            'resumed-custody:seal-output',
            'resumed-custody:complete',
        ]);
        expect(fixture.openedDescriptor).toBe(fixture.descriptor);
        for (const bytes of [
            fixture.descriptor.checkpointLineageIdentifier,
            fixture.descriptor.commonProofEnvironmentIdentifier,
            fixture.descriptor.privateRandomCursorManifestBytes,
            fixture.descriptor.privateRandomnessStreamAttemptIdentifier,
            fixture.descriptor.stableAttemptBindingHash,
        ]) {
            expect(bytes?.every((byte) => byte === 0)).toBe(true);
        }
    });

    it('fails closed when a fresh attempt exposes no authenticated resume boundary', async () => {
        const fixture = operationFixture({
            freshRunBehavior: 'complete-without-checkpoint',
        });
        const session = await casePair(fixture).resumed.open();

        await expect(
            session.execute({
                custody: session.custody,
                yieldControl,
            }),
        ).rejects.toThrow('without an authenticated resume boundary');
        expect(fixture.events).toEqual(['operation:run-fresh']);
        expect(fixture.runCount).toBe(1);
    });
});
