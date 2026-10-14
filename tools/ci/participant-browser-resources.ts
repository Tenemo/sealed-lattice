import { readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { sampleFileAllocation } from '#tools/ci/file-allocation.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import {
    type CohortState,
    participantMemoryLimit,
} from '#tools/ci/participant-cohort-state.js';
import {
    readProcesses,
    sumProcessTree,
} from '#tools/ci/process-tree-memory.js';
export const startParticipantResourceSampling = ({
    profileDirectory,
    publicDirectory,
    secondRosterDirectory,
    log,
    cleanup,
    browsers,
    originCount,
    browserDetails,
    loggedOpenings,
    browserSessions,
}: Readonly<{
    profileDirectory: string;
    publicDirectory: string;
    secondRosterDirectory: string | undefined;
    log: ActiveLocalRunLog;
    cleanup: CohortState['cleanup'];
    browsers: CohortState['browsers'];
    originCount: number;
    browserDetails: CohortState['browserDetails'];
    loggedOpenings: CohortState['loggedOpenings'];
    browserSessions: CohortState['browserSessions'];
}>) => {
    const allocationSummaries = new Map<
        string,
        {
            samples: number;
            peakFileBytes: number;
            peakAllocatedBytes: number;
            peakIndexedDatabaseFileBytes: number;
            peakIndexedDatabaseAllocatedBytes: number;
            missingEntries: number;
            unreadableEntries: number;
            skippedLinks: number;
            multiplyLinkedFileObservations: number;
        }
    >();
    const sampleStorageFiles = async (phase: 'running' | 'closed') => {
        const directories = [
            ...(await readdir(profileDirectory)).map((name) => ({
                key: name,
                directory: path.join(profileDirectory, name),
            })),
            {
                key: 'public transport',
                directory: path.join(publicDirectory, 'transport'),
            },
            {
                key: 'public with diagnostics',
                directory: publicDirectory,
            },
            ...(secondRosterDirectory === undefined
                ? []
                : [
                      {
                          key: 'second roster transport',
                          directory: path.join(
                              secondRosterDirectory,
                              'transport',
                          ),
                      },
                      {
                          key: 'second roster with diagnostics',
                          directory: secondRosterDirectory,
                      },
                  ]),
        ];
        const started = performance.now();
        const samples = await sampleFileAllocation(
            directories.map(({ directory }) => directory),
        );
        const finished = performance.now();
        for (const [index, sample] of samples.entries()) {
            const { key } = directories[index];
            const summary = allocationSummaries.get(key) ?? {
                samples: 0,
                peakFileBytes: 0,
                peakAllocatedBytes: 0,
                peakIndexedDatabaseFileBytes: 0,
                peakIndexedDatabaseAllocatedBytes: 0,
                missingEntries: 0,
                unreadableEntries: 0,
                skippedLinks: 0,
                multiplyLinkedFileObservations: 0,
            };
            summary.samples++;
            summary.peakFileBytes = Math.max(
                summary.peakFileBytes,
                sample.fileBytes,
            );
            summary.peakAllocatedBytes = Math.max(
                summary.peakAllocatedBytes,
                sample.allocatedBytes,
            );
            summary.peakIndexedDatabaseFileBytes = Math.max(
                summary.peakIndexedDatabaseFileBytes,
                sample.indexedDatabaseFileBytes,
            );
            summary.peakIndexedDatabaseAllocatedBytes = Math.max(
                summary.peakIndexedDatabaseAllocatedBytes,
                sample.indexedDatabaseAllocatedBytes,
            );
            summary.missingEntries += sample.missingEntries;
            summary.unreadableEntries += sample.unreadableEntries;
            summary.skippedLinks += sample.skippedLinks;
            summary.multiplyLinkedFileObservations +=
                sample.multiplyLinkedFiles;
            allocationSummaries.set(key, summary);
            log.writeEvent({
                eventType: 'participant-file-allocation',
                details: { key, phase, started, finished, ...sample },
            });
        }
    };
    cleanup.allocationMonitor = (async () => {
        while (cleanup.sampling) {
            await sampleStorageFiles('running');
            await delay(5000);
        }
    })().catch((error: unknown) => {
        cleanup.guardFailure ??=
            error instanceof Error ? error : new Error(String(error));
    });
    let allocationFinished = false;
    const finishAllocation = async () => {
        if (allocationFinished) return;
        allocationFinished = true;
        cleanup.sampling = false;
        await cleanup.monitor;
        await cleanup.allocationMonitor;
        await browsers.closeAll();
        await sampleStorageFiles('closed');
        await writeFile(
            path.join(log.runDirectoryPath, 'file-allocation-summary.json'),
            JSON.stringify(
                {
                    method:
                        process.platform === 'win32'
                            ? 'FILE_STANDARD_INFO AllocationSize and EndOfFile'
                            : 'lstat size and blocks times 512',
                    scope: 'Per-path default file streams, including browser database journals, Blob files and profile overhead. Transport-only directories are nested within the separately reported diagnostic public directories; those rows must not be added. Samples are not atomic snapshots, do not include volume metadata or filesystem journals, and can miss transient peaks and unlinked open files. Multiple hard links count by path and are reported explicitly.',
                    directories: Object.fromEntries(allocationSummaries),
                },
                null,
                2,
            ) + '\n',
            { flag: 'wx' },
        );
        if (cleanup.guardFailure !== undefined) throw cleanup.guardFailure;
    };
    cleanup.finishAllocation = finishAllocation;
    const peaks = new Array<number>(originCount).fill(0);
    const sampledResources = Array.from({ length: originCount }, () => ({
        browserProcessBytes: 0,
        javaScriptUsedBytes: null as number | null,
        javaScriptBackingBytes: null as number | null,
        originStorageBytes: null as number | null,
        incompleteHeapSamples: 0,
        missingStorageSamples: 0,
    }));
    const copyPeaks = new Map<string, number>();
    // Samples every open browser's process tree against the guard,
    // from one snapshot of the host's processes.
    cleanup.monitor = (async () => {
        while (cleanup.sampling) {
            const processes = await readProcesses();
            for (const { key, browser, sampled } of browsers.launched()) {
                const details = browserDetails.get(key);
                const bytes = sumProcessTree(
                    browser.processIdentifier,
                    processes,
                );
                if (details === undefined || bytes === undefined) continue;
                sampled(bytes);
                const heaps = browser.heaps();
                const storage = browser.storage();
                log.writeEvent({
                    eventType: 'participant-process-memory',
                    details: {
                        ...details,
                        bytes,
                        heaps,
                        storage,
                    },
                });
                // Chrome's own account of opening this launch's
                // IndexedDB stores, logged whenever it changes, so a
                // lost store shows whether Chrome discarded it.
                const openings = browser.backingStoreOpenings();
                const histograms = JSON.stringify(openings.histograms);
                if (
                    openings.reported &&
                    loggedOpenings.get(browser) !== histograms
                ) {
                    loggedOpenings.set(browser, histograms);
                    log.writeEvent({
                        eventType: 'participant-backing-store-openings',
                        details: {
                            ...details,
                            session: browserSessions.get(browser),
                            histograms: openings.histograms,
                        },
                    });
                }
                if (bytes > participantMemoryLimit) {
                    cleanup.guardFailure ??= new Error(
                        'Participant process-tree memory guard exceeded.',
                    );
                    await browsers.crash(key);
                }
                if (details.copy === undefined) {
                    const resources = sampledResources[details.position];
                    resources.browserProcessBytes = Math.max(
                        resources.browserProcessBytes,
                        bytes,
                    );
                    if (heaps.reported > 0) {
                        resources.javaScriptUsedBytes = Math.max(
                            resources.javaScriptUsedBytes ?? 0,
                            heaps.usedBytes,
                        );
                        resources.javaScriptBackingBytes = Math.max(
                            resources.javaScriptBackingBytes ?? 0,
                            heaps.backingBytes,
                        );
                    }
                    if (heaps.reported < heaps.sessions)
                        resources.incompleteHeapSamples++;
                    if (storage.reported)
                        resources.originStorageBytes = Math.max(
                            resources.originStorageBytes ?? 0,
                            storage.usageBytes,
                        );
                    else resources.missingStorageSamples++;
                    peaks[details.position] = Math.max(
                        peaks[details.position],
                        bytes,
                    );
                } else
                    copyPeaks.set(
                        details.copy,
                        Math.max(copyPeaks.get(details.copy) ?? 0, bytes),
                    );
            }
            await delay(2000);
        }
    })().catch((error: unknown) => {
        // Unsampled browsers leave the guard unenforced, so the run
        // fails once its running operations end.
        cleanup.guardFailure ??=
            error instanceof Error ? error : new Error(String(error));
    });
    return { finishAllocation, peaks, sampledResources, copyPeaks };
};
