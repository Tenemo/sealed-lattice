import { createHash, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import type { ActiveLocalRunLog } from './local-run-log.js';

type HeavyLaneLeaseOwner = {
    readonly laneLabel: string;
    readonly leaseIdentifier: string;
    readonly objectVersion: 'sealed-lattice-heavy-lane-lease-owner-v1';
    readonly processIdentifier: number;
    readonly runDirectoryPath: string;
    readonly startedAtIso: string;
};

type HeavyLaneLease = {
    readonly owner: HeavyLaneLeaseOwner;
    release(): Promise<void>;
};

type HeavyLaneLeaseDependencies = {
    readonly beforeCandidatePromotion?: () => Promise<void>;
    readonly beforeStaleRetirement?: (
        owner: HeavyLaneLeaseOwner,
    ) => Promise<void>;
    readonly initializationGraceMilliseconds?: number;
    readonly isProcessAlive?: (processIdentifier: number) => boolean;
    readonly leaseDirectoryPath?: string;
    readonly leaseIdentifier?: () => string;
    readonly now?: () => Date;
    readonly pollIntervalMilliseconds?: number;
    readonly processIdentifier?: number;
    readonly sleep?: (milliseconds: number) => Promise<void>;
    readonly waitDiagnosticIntervalMilliseconds?: number;
};

const ownerFileName = 'owner.json';
const defaultInitializationGraceMilliseconds = 30_000;
const defaultPollIntervalMilliseconds = 1_000;
const defaultWaitDiagnosticIntervalMilliseconds = 60_000;

const defaultHeavyLaneLeaseDirectoryPath = (): string =>
    path.join(os.tmpdir(), 'sealed-lattice-guarded-heavy-lane-v1');

type HeavyLaneLeaseMetadata = {
    readonly generationIdentifier: string;
    readonly owner?: HeavyLaneLeaseOwner;
};

const isNodeErrorWithCode = (error: unknown, code: string): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === code;

const isHeavyLaneLeaseOwner = (
    value: unknown,
): value is HeavyLaneLeaseOwner => {
    if (typeof value !== 'object' || value === null) return false;
    const owner = value as Partial<HeavyLaneLeaseOwner>;

    return (
        owner.objectVersion === 'sealed-lattice-heavy-lane-lease-owner-v1' &&
        typeof owner.laneLabel === 'string' &&
        owner.laneLabel.length > 0 &&
        typeof owner.leaseIdentifier === 'string' &&
        owner.leaseIdentifier.length > 0 &&
        Number.isSafeInteger(owner.processIdentifier) &&
        (owner.processIdentifier ?? 0) > 0 &&
        typeof owner.runDirectoryPath === 'string' &&
        owner.runDirectoryPath.length > 0 &&
        typeof owner.startedAtIso === 'string' &&
        Number.isFinite(Date.parse(owner.startedAtIso))
    );
};

const processIsAlive = (processIdentifier: number): boolean => {
    try {
        process.kill(processIdentifier, 0);
        return true;
    } catch (error) {
        if (isNodeErrorWithCode(error, 'ESRCH')) return false;
        if (isNodeErrorWithCode(error, 'EPERM')) return true;
        throw error;
    }
};

const sleep = (milliseconds: number): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, milliseconds);
    });

const leaseGenerationIdentifier = (value: string): string =>
    createHash('sha256').update(value).digest('hex');

const readLeaseMetadata = async (
    leaseDirectoryPath: string,
): Promise<HeavyLaneLeaseMetadata | undefined> => {
    let ownerText: string;
    try {
        ownerText = await readFile(
            path.join(leaseDirectoryPath, ownerFileName),
            'utf8',
        );
    } catch (error) {
        if (!isNodeErrorWithCode(error, 'ENOENT')) throw error;
        let leaseDirectory: Awaited<ReturnType<typeof stat>>;
        try {
            leaseDirectory = await stat(leaseDirectoryPath);
        } catch (directoryError) {
            if (isNodeErrorWithCode(directoryError, 'ENOENT')) return undefined;
            throw directoryError;
        }
        return {
            generationIdentifier: leaseGenerationIdentifier(
                `missing-owner:${leaseDirectory.birthtimeMs}:${leaseDirectory.mtimeMs}`,
            ),
        };
    }

    try {
        const value: unknown = JSON.parse(ownerText);
        const owner = isHeavyLaneLeaseOwner(value) ? value : undefined;
        return {
            generationIdentifier:
                owner?.leaseIdentifier ?? leaseGenerationIdentifier(ownerText),
            ...(owner === undefined ? {} : { owner }),
        };
    } catch (error) {
        if (error instanceof SyntaxError) {
            return {
                generationIdentifier: leaseGenerationIdentifier(ownerText),
            };
        }
        throw error;
    }
};

const writeLeaseOwner = async (
    leaseDirectoryPath: string,
    owner: HeavyLaneLeaseOwner,
): Promise<void> => {
    const ownerFilePath = path.join(leaseDirectoryPath, ownerFileName);
    const ownerFile = await open(ownerFilePath, 'wx');
    try {
        await ownerFile.writeFile(`${JSON.stringify(owner, null, 2)}\n`, {
            encoding: 'utf8',
        });
        await ownerFile.sync();
    } finally {
        await ownerFile.close();
    }
};

const pathExists = async (targetPath: string): Promise<boolean> => {
    try {
        await stat(targetPath);
        return true;
    } catch (error) {
        if (isNodeErrorWithCode(error, 'ENOENT')) return false;
        throw error;
    }
};

const candidateDirectoryPath = (
    leaseDirectoryPath: string,
    leaseIdentifier: string,
): string =>
    `${leaseDirectoryPath}.candidate-${leaseGenerationIdentifier(leaseIdentifier)}`;

const retiredDirectoryPath = (
    leaseDirectoryPath: string,
    generationIdentifier: string,
): string =>
    `${leaseDirectoryPath}.retired-${leaseGenerationIdentifier(generationIdentifier)}`;

const tryPromoteCandidateDirectory = async (
    candidatePath: string,
    leaseDirectoryPath: string,
): Promise<boolean> => {
    try {
        await rename(candidatePath, leaseDirectoryPath);
        return true;
    } catch (error) {
        if (
            isNodeErrorWithCode(error, 'EEXIST') ||
            isNodeErrorWithCode(error, 'ENOTEMPTY') ||
            (await pathExists(leaseDirectoryPath))
        ) {
            return false;
        }
        throw error;
    }
};

// Retired generation directories are deliberately retained as tiny
// tombstones. Every contender that observed the same old generation targets
// the same destination, so once one contender retires it, a delayed contender
// cannot rename a successor into that destination.
const tryRetireLeaseGeneration = async (
    leaseDirectoryPath: string,
    expectedGenerationIdentifier: string,
): Promise<boolean> => {
    const currentMetadata = await readLeaseMetadata(leaseDirectoryPath);
    if (
        currentMetadata?.generationIdentifier !== expectedGenerationIdentifier
    ) {
        return false;
    }

    const retiredPath = retiredDirectoryPath(
        leaseDirectoryPath,
        expectedGenerationIdentifier,
    );
    try {
        await rename(leaseDirectoryPath, retiredPath);
    } catch (error) {
        if (
            isNodeErrorWithCode(error, 'ENOENT') ||
            (await pathExists(retiredPath))
        ) {
            return false;
        }
        throw error;
    }

    const retiredMetadata = await readLeaseMetadata(retiredPath);
    if (
        retiredMetadata?.generationIdentifier !== expectedGenerationIdentifier
    ) {
        throw new Error(
            'The local guarded heavy-lane lease generation changed while it was being retired.',
        );
    }
    return true;
};

const leaseDirectoryAgeMilliseconds = async (
    leaseDirectoryPath: string,
    now: Date,
): Promise<number | undefined> => {
    try {
        const leaseDirectory = await stat(leaseDirectoryPath);
        return Math.max(0, now.getTime() - leaseDirectory.mtimeMs);
    } catch (error) {
        if (isNodeErrorWithCode(error, 'ENOENT')) return undefined;
        throw error;
    }
};

const formatOwnerDescription = (owner: HeavyLaneLeaseOwner): string =>
    `PID ${owner.processIdentifier}, ${owner.laneLabel}, started ${owner.startedAtIso}, run log ${owner.runDirectoryPath}`;

const reportLeaseMessage = (
    runLog: ActiveLocalRunLog,
    message: string,
): void => {
    console.log(message);
    runLog.writeCombinedOutput(`${message}\n`);
};

export const acquireLocalHeavyLaneLease = async (input: {
    readonly dependencies?: HeavyLaneLeaseDependencies;
    readonly laneLabel: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<HeavyLaneLease> => {
    const dependencies = input.dependencies ?? {};
    const initializationGraceMilliseconds =
        dependencies.initializationGraceMilliseconds ??
        defaultInitializationGraceMilliseconds;
    const isProcessAlive = dependencies.isProcessAlive ?? processIsAlive;
    const leaseDirectoryPath =
        dependencies.leaseDirectoryPath ?? defaultHeavyLaneLeaseDirectoryPath();
    const createLeaseIdentifier = dependencies.leaseIdentifier ?? randomUUID;
    const now = dependencies.now ?? (() => new Date());
    const pollIntervalMilliseconds =
        dependencies.pollIntervalMilliseconds ??
        defaultPollIntervalMilliseconds;
    const ownerProcessIdentifier =
        dependencies.processIdentifier ?? process.pid;
    const wait = dependencies.sleep ?? sleep;
    const waitDiagnosticIntervalMilliseconds =
        dependencies.waitDiagnosticIntervalMilliseconds ??
        defaultWaitDiagnosticIntervalMilliseconds;
    const leaseIdentifier = createLeaseIdentifier();
    const candidatePath = candidateDirectoryPath(
        leaseDirectoryPath,
        leaseIdentifier,
    );
    let lastWaitDiagnosticAt = Number.NEGATIVE_INFINITY;
    const owner: HeavyLaneLeaseOwner = {
        laneLabel: input.laneLabel,
        leaseIdentifier,
        objectVersion: 'sealed-lattice-heavy-lane-lease-owner-v1',
        processIdentifier: ownerProcessIdentifier,
        runDirectoryPath: input.runLog.runDirectoryPath,
        startedAtIso: now().toISOString(),
    };

    await mkdir(candidatePath);
    try {
        await writeLeaseOwner(candidatePath, owner);
        await dependencies.beforeCandidatePromotion?.();

        for (;;) {
            const startedAt = now();
            if (
                await tryPromoteCandidateDirectory(
                    candidatePath,
                    leaseDirectoryPath,
                )
            ) {
                break;
            }

            const existingMetadata =
                await readLeaseMetadata(leaseDirectoryPath);
            if (existingMetadata === undefined) continue;
            const existingOwner = existingMetadata.owner;
            if (existingOwner !== undefined) {
                if (
                    existingOwner.processIdentifier === ownerProcessIdentifier
                ) {
                    throw new Error(
                        `The local guarded heavy-lane lease is already owned by this process (${formatOwnerDescription(existingOwner)}). Nested acquisition is not supported.`,
                    );
                }
                if (!isProcessAlive(existingOwner.processIdentifier)) {
                    await dependencies.beforeStaleRetirement?.(existingOwner);
                    const recovered = await tryRetireLeaseGeneration(
                        leaseDirectoryPath,
                        existingMetadata.generationIdentifier,
                    );
                    if (recovered) {
                        const message = `Recovered stale local guarded heavy-lane lease from ${formatOwnerDescription(existingOwner)}.`;
                        reportLeaseMessage(input.runLog, message);
                        input.runLog.writeEvent({
                            details: {
                                previousLaneLabel: existingOwner.laneLabel,
                                previousProcessIdentifier:
                                    existingOwner.processIdentifier,
                                previousRunDirectoryPath:
                                    existingOwner.runDirectoryPath,
                            },
                            eventType: 'heavy-lane-lease-stale-owner-recovered',
                        });
                    }
                    continue;
                }

                const nowMilliseconds = startedAt.getTime();
                if (
                    nowMilliseconds - lastWaitDiagnosticAt >=
                    waitDiagnosticIntervalMilliseconds
                ) {
                    const message = `Waiting for local guarded heavy-lane lease held by ${formatOwnerDescription(existingOwner)}.`;
                    reportLeaseMessage(input.runLog, message);
                    input.runLog.writeEvent({
                        details: {
                            ownerLaneLabel: existingOwner.laneLabel,
                            ownerProcessIdentifier:
                                existingOwner.processIdentifier,
                            ownerRunDirectoryPath:
                                existingOwner.runDirectoryPath,
                            ownerStartedAtIso: existingOwner.startedAtIso,
                        },
                        eventType: 'heavy-lane-lease-waiting',
                    });
                    lastWaitDiagnosticAt = nowMilliseconds;
                }
                await wait(pollIntervalMilliseconds);
                continue;
            }

            const directoryAgeMilliseconds =
                await leaseDirectoryAgeMilliseconds(
                    leaseDirectoryPath,
                    startedAt,
                );
            if (directoryAgeMilliseconds === undefined) continue;
            if (directoryAgeMilliseconds >= initializationGraceMilliseconds) {
                const recovered = await tryRetireLeaseGeneration(
                    leaseDirectoryPath,
                    existingMetadata.generationIdentifier,
                );
                if (recovered) {
                    const message =
                        'Recovered stale local guarded heavy-lane lease with missing or malformed owner metadata.';
                    reportLeaseMessage(input.runLog, message);
                    input.runLog.writeEvent({
                        details: { directoryAgeMilliseconds },
                        eventType: 'heavy-lane-lease-stale-metadata-recovered',
                    });
                }
                continue;
            }

            if (
                startedAt.getTime() - lastWaitDiagnosticAt >=
                waitDiagnosticIntervalMilliseconds
            ) {
                const message =
                    'Waiting for local guarded heavy-lane lease ownership metadata to finish initializing.';
                reportLeaseMessage(input.runLog, message);
                input.runLog.writeEvent({
                    details: { directoryAgeMilliseconds },
                    eventType: 'heavy-lane-lease-metadata-waiting',
                });
                lastWaitDiagnosticAt = startedAt.getTime();
            }
            await wait(pollIntervalMilliseconds);
        }

        const acquiredMessage = `Acquired local guarded heavy-lane lease for ${input.laneLabel} (PID ${ownerProcessIdentifier}).`;
        reportLeaseMessage(input.runLog, acquiredMessage);
        input.runLog.writeEvent({
            details: {
                laneLabel: input.laneLabel,
                processIdentifier: ownerProcessIdentifier,
            },
            eventType: 'heavy-lane-lease-acquired',
        });

        let releasePromise: Promise<void> | undefined;
        const releaseOwnedGeneration = async (): Promise<void> => {
            const currentMetadata = await readLeaseMetadata(leaseDirectoryPath);
            if (
                currentMetadata?.owner?.leaseIdentifier !==
                owner.leaseIdentifier
            ) {
                throw new Error(
                    `Cannot release the local guarded heavy-lane lease for ${input.laneLabel}: ownership changed or its metadata is unavailable.`,
                );
            }
            const retired = await tryRetireLeaseGeneration(
                leaseDirectoryPath,
                currentMetadata.generationIdentifier,
            );
            if (!retired) {
                throw new Error(
                    `Cannot release the local guarded heavy-lane lease for ${input.laneLabel}: the owned lease generation was already retired or replaced.`,
                );
            }
            const releaseMessage = `Released local guarded heavy-lane lease for ${input.laneLabel} (PID ${ownerProcessIdentifier}).`;
            reportLeaseMessage(input.runLog, releaseMessage);
            input.runLog.writeEvent({
                details: {
                    laneLabel: input.laneLabel,
                    processIdentifier: ownerProcessIdentifier,
                },
                eventType: 'heavy-lane-lease-released',
            });
        };
        return {
            owner,
            release: async (): Promise<void> => {
                releasePromise ??= releaseOwnedGeneration();
                await releasePromise;
            },
        };
    } catch (error) {
        await rm(candidatePath, { force: true, recursive: true });
        throw error;
    }
};

export const withLocalHeavyLaneLease = async <Result>(input: {
    readonly action: () => Promise<Result>;
    readonly dependencies?: HeavyLaneLeaseDependencies;
    readonly environment?: NodeJS.ProcessEnv;
    readonly laneLabel: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<Result> => {
    if ((input.environment ?? process.env).GITHUB_ACTIONS === 'true') {
        input.runLog.writeEvent({
            details: { reason: 'isolated-github-actions-runner' },
            eventType: 'heavy-lane-lease-bypassed',
        });
        return input.action();
    }

    const lease = await acquireLocalHeavyLaneLease({
        dependencies: input.dependencies,
        laneLabel: input.laneLabel,
        runLog: input.runLog,
    });
    try {
        return await input.action();
    } finally {
        await lease.release();
    }
};
