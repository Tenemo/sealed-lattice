import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import {
    acquireLocalHeavyLaneLease,
    withLocalHeavyLaneLease,
} from '#tools/ci/heavy-lane-lease';
import type {
    ActiveLocalRunLog,
    LocalRunEventInput,
} from '#tools/ci/local-run-log';

type RecordedRunLog = {
    readonly events: LocalRunEventInput[];
    readonly output: string[];
    readonly runLog: ActiveLocalRunLog;
};

const createRecordedRunLog = (runDirectoryPath: string): RecordedRunLog => {
    const events: LocalRunEventInput[] = [];
    const output: string[] = [];

    return {
        events,
        output,
        runLog: {
            runDirectoryPath,
            createCommandLogFiles: () => {
                throw new Error('Command logs are not used by lease tests.');
            },
            finish: () => Promise.resolve(),
            writeCombinedOutput: (chunk) => {
                output.push(chunk.toString());
            },
            writeCommandOutput: (input) => {
                void input;
            },
            writeEvent: (event) => {
                events.push(event);
            },
        },
    };
};

const createTemporaryLeasePath = async (): Promise<{
    readonly leaseDirectoryPath: string;
    readonly temporaryRootPath: string;
}> => {
    const temporaryRootPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-heavy-lane-lease-test-'),
    );
    return {
        leaseDirectoryPath: path.join(temporaryRootPath, 'lease'),
        temporaryRootPath,
    };
};

const expectPathNotToExist = async (filePath: string): Promise<void> => {
    await expect(access(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
};

const createDeferred = (): {
    readonly promise: Promise<void>;
    resolve(): void;
} => {
    let resolvePromise: (() => void) | undefined;
    const promise = new Promise<void>((resolve) => {
        resolvePromise = resolve;
    });
    return {
        promise,
        resolve: () => resolvePromise?.(),
    };
};

describe('local guarded heavy-lane lease', () => {
    it('bypasses the machine lease on isolated GitHub Actions runners', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const recordedRunLog = createRecordedRunLog('logs/github-actions');
        try {
            const action = vi.fn(() => Promise.resolve('completed'));
            await expect(
                withLocalHeavyLaneLease({
                    action,
                    dependencies: { leaseDirectoryPath },
                    environment: { GITHUB_ACTIONS: 'true' },
                    laneLabel: 'Node kernel heavy',
                    runLog: recordedRunLog.runLog,
                }),
            ).resolves.toBe('completed');

            expect(action).toHaveBeenCalledOnce();
            expect(recordedRunLog.events).toContainEqual({
                details: { reason: 'isolated-github-actions-runner' },
                eventType: 'heavy-lane-lease-bypassed',
            });
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });

    it('waits for a live owner and acquires only after release', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const firstRunLog = createRecordedRunLog('logs/first-heavy-run');
        const secondRunLog = createRecordedRunLog('logs/second-heavy-run');
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        try {
            const firstLease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'first-lease',
                    processIdentifier: 1001,
                },
                laneLabel: 'Rust accepted setup',
                runLog: firstRunLog.runLog,
            });
            let waitCount = 0;
            const secondLease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'second-lease',
                    pollIntervalMilliseconds: 1,
                    processIdentifier: 1002,
                    sleep: async () => {
                        waitCount += 1;
                        await firstLease.release();
                    },
                    waitDiagnosticIntervalMilliseconds: 1,
                },
                laneLabel: 'Node kernel heavy',
                runLog: secondRunLog.runLog,
            });

            expect(waitCount).toBe(1);
            expect(secondRunLog.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-waiting',
                }),
            );
            expect(secondLease.owner.processIdentifier).toBe(1002);
            await secondLease.release();
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            vi.restoreAllMocks();
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });

    it('cannot let a stalled candidate initializer remove its successor', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const stalledRunLog = createRecordedRunLog(
            'logs/stalled-candidate-heavy-run',
        );
        const successorRunLog = createRecordedRunLog(
            'logs/candidate-successor-heavy-run',
        );
        const candidateInitialized = createDeferred();
        const resumeCandidatePromotion = createDeferred();
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        try {
            const successorLeaseHolder: {
                lease?: Awaited<ReturnType<typeof acquireLocalHeavyLaneLease>>;
            } = {};
            const stalledAcquisition = acquireLocalHeavyLaneLease({
                dependencies: {
                    beforeCandidatePromotion: async () => {
                        candidateInitialized.resolve();
                        await resumeCandidatePromotion.promise;
                    },
                    isProcessAlive: (processIdentifier) =>
                        processIdentifier === 5002,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'stalled-candidate',
                    pollIntervalMilliseconds: 1,
                    processIdentifier: 5001,
                    sleep: async () => {
                        await successorLeaseHolder.lease?.release();
                    },
                },
                laneLabel: 'Rust accepted setup',
                runLog: stalledRunLog.runLog,
            });
            await candidateInitialized.promise;

            successorLeaseHolder.lease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'candidate-successor',
                    processIdentifier: 5002,
                },
                laneLabel: 'Node kernel heavy',
                runLog: successorRunLog.runLog,
            });
            resumeCandidatePromotion.resolve();

            const stalledLease = await stalledAcquisition;
            expect(stalledLease.owner.leaseIdentifier).toBe(
                'stalled-candidate',
            );
            expect(successorRunLog.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-released',
                }),
            );
            await stalledLease.release();
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            vi.restoreAllMocks();
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });

    it('recovers a crashed owner only after its process is no longer alive', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const crashedRunLog = createRecordedRunLog('logs/crashed-heavy-run');
        const recoveringRunLog = createRecordedRunLog(
            'logs/recovering-heavy-run',
        );
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        try {
            await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'crashed-lease',
                    processIdentifier: 2001,
                },
                laneLabel: 'Rust kernel heavy',
                runLog: crashedRunLog.runLog,
            });

            const recoveredLease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: (processIdentifier) =>
                        processIdentifier !== 2001,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'recovered-lease',
                    processIdentifier: 2002,
                },
                laneLabel: 'Rust accepted setup',
                runLog: recoveringRunLog.runLog,
            });

            const recoveryEvent = recoveringRunLog.events.find(
                (event) =>
                    event.eventType ===
                    'heavy-lane-lease-stale-owner-recovered',
            );
            expect(recoveryEvent?.details?.previousProcessIdentifier).toBe(
                2001,
            );
            expect(recoveredLease.owner.processIdentifier).toBe(2002);
            await recoveredLease.release();
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            vi.restoreAllMocks();
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });

    it('prevents a delayed stale observer from retiring the successor generation', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const crashedRunLog = createRecordedRunLog(
            'logs/generation-crashed-heavy-run',
        );
        const recoveringRunLog = createRecordedRunLog(
            'logs/generation-recovering-heavy-run',
        );
        const delayedRunLog = createRecordedRunLog(
            'logs/generation-delayed-heavy-run',
        );
        const staleGenerationObserved = createDeferred();
        const resumeStaleRetirement = createDeferred();
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        try {
            await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'generation-crashed-owner',
                    processIdentifier: 6001,
                },
                laneLabel: 'Rust kernel heavy',
                runLog: crashedRunLog.runLog,
            });

            const successorLeaseHolder: {
                lease?: Awaited<ReturnType<typeof acquireLocalHeavyLaneLease>>;
            } = {};
            const delayedAcquisition = acquireLocalHeavyLaneLease({
                dependencies: {
                    beforeStaleRetirement: async (owner) => {
                        if (
                            owner.leaseIdentifier === 'generation-crashed-owner'
                        ) {
                            staleGenerationObserved.resolve();
                            await resumeStaleRetirement.promise;
                        }
                    },
                    isProcessAlive: (processIdentifier) =>
                        processIdentifier === 6002,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'generation-delayed-observer',
                    pollIntervalMilliseconds: 1,
                    processIdentifier: 6003,
                    sleep: async () => {
                        await successorLeaseHolder.lease?.release();
                    },
                },
                laneLabel: 'Rust accepted setup',
                runLog: delayedRunLog.runLog,
            });
            await staleGenerationObserved.promise;

            successorLeaseHolder.lease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: (processIdentifier) =>
                        processIdentifier !== 6001,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'generation-successor',
                    processIdentifier: 6002,
                },
                laneLabel: 'Node kernel heavy',
                runLog: recoveringRunLog.runLog,
            });
            resumeStaleRetirement.resolve();

            const delayedLease = await delayedAcquisition;
            expect(delayedLease.owner.leaseIdentifier).toBe(
                'generation-delayed-observer',
            );
            expect(recoveringRunLog.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-released',
                }),
            );
            await delayedLease.release();
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            vi.restoreAllMocks();
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });

    it('recovers old incomplete ownership metadata without guessing at a live owner', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const recoveringRunLog = createRecordedRunLog(
            'logs/recovering-incomplete-heavy-run',
        );
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        try {
            await mkdir(leaseDirectoryPath);
            await writeFile(
                path.join(leaseDirectoryPath, 'owner.json'),
                '{incomplete',
                'utf8',
            );
            const recoveredLease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    initializationGraceMilliseconds: 0,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'metadata-recovery-lease',
                    processIdentifier: 3001,
                },
                laneLabel: 'Node kernel heavy',
                runLog: recoveringRunLog.runLog,
            });

            expect(recoveringRunLog.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-stale-metadata-recovered',
                }),
            );
            await recoveredLease.release();
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            vi.restoreAllMocks();
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });

    it('releases the lease when the guarded action throws', async () => {
        const { leaseDirectoryPath, temporaryRootPath } =
            await createTemporaryLeasePath();
        const recordedRunLog = createRecordedRunLog('logs/failing-heavy-run');
        vi.spyOn(console, 'log').mockImplementation(() => undefined);
        try {
            await expect(
                withLocalHeavyLaneLease({
                    action: () => {
                        throw new Error('simulated runner failure');
                    },
                    dependencies: {
                        leaseDirectoryPath,
                        leaseIdentifier: () => 'failing-action-lease',
                        processIdentifier: 4001,
                    },
                    environment: {},
                    laneLabel: 'Rust kernel heavy',
                    runLog: recordedRunLog.runLog,
                }),
            ).rejects.toThrow('simulated runner failure');

            expect(recordedRunLog.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-released',
                }),
            );
            await expectPathNotToExist(leaseDirectoryPath);
        } finally {
            vi.restoreAllMocks();
            await rm(temporaryRootPath, { force: true, recursive: true });
        }
    });
});
