import { access, mkdtemp, rm } from 'node:fs/promises';
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

const createRunLog = (
    runDirectoryPath: string,
): {
    readonly events: LocalRunEventInput[];
    readonly runLog: ActiveLocalRunLog;
} => {
    const events: LocalRunEventInput[] = [];
    return {
        events,
        runLog: {
            runDirectoryPath,
            createCommandLogFiles: () => {
                throw new Error('Command logs are not used by lease tests.');
            },
            finish: () => Promise.resolve(),
            writeCombinedOutput: () => undefined,
            writeCommandOutput: () => undefined,
            writeEvent: (event) => events.push(event),
        },
    };
};

const withTemporaryLease = async <Result>(
    action: (leaseDirectoryPath: string) => Promise<Result>,
): Promise<Result> => {
    const temporaryRootPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-heavy-lane-lease-test-'),
    );
    try {
        return await action(path.join(temporaryRootPath, 'lease'));
    } finally {
        vi.restoreAllMocks();
        await rm(temporaryRootPath, { force: true, recursive: true });
    }
};

const expectReleased = async (leaseDirectoryPath: string): Promise<void> => {
    await expect(access(leaseDirectoryPath)).rejects.toMatchObject({
        code: 'ENOENT',
    });
};

const createDeferred = (): {
    readonly promise: Promise<void>;
    resolve(): void;
} => {
    let resolvePromise: (() => void) | undefined;
    return {
        promise: new Promise((resolve) => {
            resolvePromise = resolve;
        }),
        resolve: () => resolvePromise?.(),
    };
};

describe('local guarded heavy-lane lease', () => {
    it('waits for a live owner before acquiring the machine lease', () =>
        withTemporaryLease(async (leaseDirectoryPath) => {
            vi.spyOn(console, 'log').mockImplementation(() => undefined);
            const firstRun = createRunLog('logs/first-heavy-run');
            const secondRun = createRunLog('logs/second-heavy-run');
            const firstLease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'first-lease',
                    processIdentifier: 1001,
                },
                laneLabel: 'Rust accepted setup',
                runLog: firstRun.runLog,
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
                laneLabel: 'Rust kernel heavy',
                runLog: secondRun.runLog,
            });

            expect(waitCount).toBe(1);
            expect(secondRun.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-waiting',
                }),
            );
            expect(secondLease.owner.processIdentifier).toBe(1002);
            await secondLease.release();
            await expectReleased(leaseDirectoryPath);
        }));

    it('recovers ownership only after the previous process dies', () =>
        withTemporaryLease(async (leaseDirectoryPath) => {
            vi.spyOn(console, 'log').mockImplementation(() => undefined);
            const crashedRun = createRunLog('logs/crashed-heavy-run');
            const recoveringRun = createRunLog('logs/recovering-heavy-run');
            await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'crashed-lease',
                    processIdentifier: 2001,
                },
                laneLabel: 'Rust kernel heavy',
                runLog: crashedRun.runLog,
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
                runLog: recoveringRun.runLog,
            });

            const recoveryEvent = recoveringRun.events.find(
                (event) =>
                    event.eventType ===
                    'heavy-lane-lease-stale-owner-recovered',
            );
            expect(recoveryEvent?.details?.previousProcessIdentifier).toBe(
                2001,
            );
            expect(recoveredLease.owner.processIdentifier).toBe(2002);
            await recoveredLease.release();
            await expectReleased(leaseDirectoryPath);
        }));

    it('does not let a delayed stale observer retire a successor generation', () =>
        withTemporaryLease(async (leaseDirectoryPath) => {
            vi.spyOn(console, 'log').mockImplementation(() => undefined);
            const staleGenerationObserved = createDeferred();
            const resumeStaleRetirement = createDeferred();
            const crashedRun = createRunLog('logs/crashed-heavy-run');
            const recoveringRun = createRunLog('logs/recovering-heavy-run');
            const delayedRun = createRunLog('logs/delayed-heavy-run');
            await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: () => true,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'crashed-owner',
                    processIdentifier: 6001,
                },
                laneLabel: 'Rust kernel heavy',
                runLog: crashedRun.runLog,
            });

            const successorLeaseHolder: {
                lease?: Awaited<ReturnType<typeof acquireLocalHeavyLaneLease>>;
            } = {};
            const delayedAcquisition = acquireLocalHeavyLaneLease({
                dependencies: {
                    beforeStaleRetirement: async (owner) => {
                        if (owner.leaseIdentifier === 'crashed-owner') {
                            staleGenerationObserved.resolve();
                            await resumeStaleRetirement.promise;
                        }
                    },
                    isProcessAlive: (processIdentifier) =>
                        processIdentifier === 6002,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'delayed-observer',
                    pollIntervalMilliseconds: 1,
                    processIdentifier: 6003,
                    sleep: async () => successorLeaseHolder.lease?.release(),
                },
                laneLabel: 'Rust accepted setup',
                runLog: delayedRun.runLog,
            });
            await staleGenerationObserved.promise;

            successorLeaseHolder.lease = await acquireLocalHeavyLaneLease({
                dependencies: {
                    isProcessAlive: (processIdentifier) =>
                        processIdentifier !== 6001,
                    leaseDirectoryPath,
                    leaseIdentifier: () => 'successor',
                    processIdentifier: 6002,
                },
                laneLabel: 'Rust kernel heavy',
                runLog: recoveringRun.runLog,
            });
            resumeStaleRetirement.resolve();

            const delayedLease = await delayedAcquisition;
            expect(delayedLease.owner.leaseIdentifier).toBe('delayed-observer');
            expect(recoveringRun.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-released',
                }),
            );
            await delayedLease.release();
            await expectReleased(leaseDirectoryPath);
        }));

    it('releases the lease when the guarded action throws', () =>
        withTemporaryLease(async (leaseDirectoryPath) => {
            vi.spyOn(console, 'log').mockImplementation(() => undefined);
            const run = createRunLog('logs/failing-heavy-run');

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
                    runLog: run.runLog,
                }),
            ).rejects.toThrow('simulated runner failure');

            expect(run.events).toContainEqual(
                expect.objectContaining({
                    eventType: 'heavy-lane-lease-released',
                }),
            );
            await expectReleased(leaseDirectoryPath);
        }));
});
