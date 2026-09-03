import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
    stat,
    writeFile,
} from 'node:fs/promises';
import {
    createServer,
    type IncomingMessage,
    type Server,
    type ServerResponse,
} from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
    chromium,
    type BrowserContext,
    type CDPSession,
    type Page,
} from 'playwright';

import { readProcessPrivateMemory } from './process-tree-memory-guard.js';

import {
    compileIndependentPaddedTallyModel,
    parsePaddedTallyTerminal,
} from '#tests/padded-tally-transcript-model.js';

const repositoryRootPath = path.resolve(import.meta.dirname, '..', '..');
const driverSourcePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-ceremony-driver.ts',
);
const runnerSourcePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'run-external-chrome-ceremony.ts',
);
const pageHtmlPath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-ceremony.html',
);
const pageScriptPath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-ceremony.mjs',
);
const workerScriptPath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-ceremony-worker.mjs',
);
const registrySourcePath = path.join(
    repositoryRootPath,
    'tests',
    'manual-evidence-registry.ts',
);
const rootPackageManifestPath = path.join(repositoryRootPath, 'package.json');
const expectedCandidateBuildIdentityHex =
    '98cc57f851e5681c5fc46a555714680ed9cccac494b3645540d6bb7a8ac3a9c11d7049eb0c9b12eca5714f1d6e1d9ef9f1cf065694f4fb7c06fd522533ad812a';
const expectedParameterIdentityHex =
    'c26ef8c3d3091fdcc35d2827cbcbe33c8d22ca725028b2c4384cf8744b09e6eddb634d6ea14173e7d6cc78c662da9c99e73db4e5ad9b6e9841a0111f56f9bd97';
const expectedCandidateArchiveSha256Hex =
    'e25ed026c92c893d2f9991f093fdcd1e8ea26dc0905125fd489c6415189bd75c';
const expectedCandidateKernelSha256Hex =
    'ab896a95ebfe7edc19af3f3fa442f2e0e9ca8111cd0a8460a37e3b97bdbb4af2';
const expectedCandidateSourceCommit =
    '801b929714457c269275cde6ff5558d3bf83c1f7';
const participantCount = 10;
const maximumVisitCount = 10;
const visitForegroundLimitMilliseconds = 15 * 60 * 1_000;
const participantForegroundLimitMilliseconds = 30 * 60 * 1_000;
const ceremonyWallLimitMilliseconds = 5 * 60 * 60 * 1_000;
const publicCorpusLimitByteLength = 2 * 1_024 * 1_024 * 1_024;
const participantTransferLimitByteLength = 2 * 1_024 * 1_024 * 1_024;
const persistentStorageLimitByteLength = 2 * 1_024 * 1_024 * 1_024;
const scratchPlanningTargetByteLength = 256 * 1_024 * 1_024;
const copiedBufferAbsoluteLimitByteLength = 8 * 1_024 * 1_024;
const wasmMemoryPlanningTargetByteLength = 384 * 1_024 * 1_024;
const javascriptHeapPlanningTargetByteLength = 128 * 1_024 * 1_024;
const browserPrivateMemoryPlanningTargetByteLength = 640 * 1_024 * 1_024;
const memorySampleIntervalMilliseconds = 1_000;
const maximumRequestBodyByteLength = 8 * 1_024 * 1_024;
const cpuThrottlingRate = 6;
const wifiProfile = {
    connectionType: 'wifi' as const,
    downloadThroughputBytesPerSecond: 30_000_000 / 8,
    latencyMilliseconds: 20,
    uploadThroughputBytesPerSecond: 15_000_000 / 8,
};
const mobileProfile = {
    deviceScaleFactor: 2.625,
    hasTouch: true,
    height: 915,
    isMobile: true,
    maxTouchPoints: 5,
    width: 412,
};

type CeremonyMode =
    | 'all-abstain'
    | 'empty-usable-ballots'
    | 'pending-private-preparation'
    | 'result';

type Ballot = Readonly<{
    declaration: 'abstain' | 'submit';
    scoreEncodings: readonly number[];
}>;

type ScenarioDefinition = Readonly<{
    ballots: readonly Ballot[];
    identifier: string;
    mode: CeremonyMode;
    recoveryAndHostileCoverage: boolean;
    topCount: number;
}>;

export type ExternalCeremonyVisit = Readonly<{
    action:
        | 'activation'
        | 'evaluation'
        | 'evaluation-repair'
        | 'finality'
        | 'join'
        | 'no-result'
        | 'prepare'
        | 'reclaim'
        | 'source'
        | 'state-loss-probe';
    cleanup?: boolean;
    crashBoundary?:
        | 'preparation-consume'
        | 'source-bind'
        | 'tally-activation-publish'
        | 'tally-chunk-persist'
        | 'tally-evaluation-initialize'
        | 'tally-evaluation-step'
        | 'tally-generation-initialize'
        | 'tally-terminal-persist';
    participantPosition: number;
    pressureByteLength?: number;
    probeCorruptManifest?: boolean;
    probeCorruptSource?: boolean;
    probeFinalityConflict?: boolean;
    probeSourceConflict?: boolean;
    probeThreeCorruptChunks?: boolean;
    expectPendingSourceRefusal?: boolean;
    startChunkOrdinal?: number;
}>;

type DriverArguments = Readonly<{
    candidateArchivePath: string;
    resultFilePath: string;
}>;

type RelayTransfer = {
    candidateDownloadByteLength: number;
    harnessDownloadByteLength: number;
    relayDownloadByteLength: number;
    relayUploadByteLength: number;
    requestCount: number;
};

type RelayServer = Readonly<{
    close(): Promise<void>;
    inventory(): readonly Readonly<{
        byteLength: number;
        objectName: string;
        sha256Hex: string;
    }>[];
    origin: string;
    readRelayObject(objectName: string): Promise<Uint8Array>;
    relayCorpusByteLength(): number;
    transferForVisit(visitToken: string): Readonly<RelayTransfer>;
}>;

type RuntimeSample = Readonly<{
    browserPrivateByteLength: number;
    browserResidentByteLength: number;
    capturedAtMilliseconds: number;
    javascriptHeapTotalByteLength: number;
    javascriptHeapUsedByteLength: number;
    processCount: number;
}>;

type VisitRuntimeMeasurement = Readonly<{
    idleBrowserPrivateByteLength: number;
    idleJavascriptHeapUsedByteLength: number;
    peakBrowserPrivateByteLength: number;
    peakBrowserPrivateMemoryIncreaseByteLength: number;
    peakJavascriptHeapIncreaseByteLength: number;
    peakJavascriptHeapUsedByteLength: number;
    samples: readonly RuntimeSample[];
}>;

type VisitEvidence = Readonly<{
    action: ExternalCeremonyVisit['action'] | 'probe-missing-persistence';
    browserIdentity: unknown;
    browserEncodedDownloadByteLength: number;
    coldNavigation: boolean;
    finishedAtIso: string;
    foregroundMilliseconds: number;
    participantPosition: number;
    pageResult: Readonly<Record<string, unknown>>;
    runtime: VisitRuntimeMeasurement;
    sequence: number;
    startedAtIso: string;
    transfer: Readonly<RelayTransfer>;
    visitToken: string;
}>;

type FileIdentity = Readonly<{
    byteLength: number;
    repositoryRelativePath: string;
    sha256Hex: string;
}>;

const resultBallots = (): Ballot[] =>
    Array.from({ length: participantCount }, (_, participantPosition) => {
        if (participantPosition >= 8) {
            return {
                declaration: 'abstain' as const,
                scoreEncodings: Array.from(
                    { length: participantCount },
                    () => 0,
                ),
            };
        }
        if (participantPosition === 6) {
            return {
                declaration: 'submit' as const,
                scoreEncodings: Array.from(
                    { length: participantCount },
                    () => 0,
                ),
            };
        }
        if (participantPosition === 7) {
            return {
                declaration: 'submit' as const,
                scoreEncodings: Array.from(
                    { length: participantCount },
                    () => 15,
                ),
            };
        }
        return {
            declaration: 'submit' as const,
            scoreEncodings: Array.from(
                { length: participantCount },
                (_unused, optionPosition) =>
                    ((optionPosition + 3 * participantPosition) %
                        participantCount) +
                    1,
            ),
        };
    });

const emptyUsableBallots = (): Ballot[] =>
    Array.from({ length: participantCount }, (_, participantPosition) => ({
        declaration: 'submit' as const,
        scoreEncodings: Array.from({ length: participantCount }, () =>
            participantPosition % 2 === 0 ? 0 : 15,
        ),
    }));

const abstentionBallots = (): Ballot[] =>
    Array.from({ length: participantCount }, () => ({
        declaration: 'abstain' as const,
        scoreEncodings: Array.from({ length: participantCount }, () => 0),
    }));

export const externalCeremonyScenarioDefinitions =
    (): readonly ScenarioDefinition[] => [
        {
            ballots: resultBallots(),
            identifier: 'complete-top-count-10-recovery',
            mode: 'result',
            recoveryAndHostileCoverage: true,
            topCount: 10,
        },
        {
            ballots: resultBallots(),
            identifier: 'complete-top-count-1',
            mode: 'result',
            recoveryAndHostileCoverage: false,
            topCount: 1,
        },
        {
            ballots: emptyUsableBallots(),
            identifier: 'submitted-but-unusable',
            mode: 'empty-usable-ballots',
            recoveryAndHostileCoverage: false,
            topCount: 1,
        },
        {
            ballots: abstentionBallots(),
            identifier: 'all-abstain',
            mode: 'all-abstain',
            recoveryAndHostileCoverage: false,
            topCount: 10,
        },
        {
            ballots: resultBallots(),
            identifier: 'private-preparation-consumption-state-loss',
            mode: 'pending-private-preparation',
            recoveryAndHostileCoverage: false,
            topCount: 1,
        },
    ];

export const buildExternalCeremonyVisitSchedule = (
    scenario: ScenarioDefinition,
): readonly ExternalCeremonyVisit[] => {
    const visits: ExternalCeremonyVisit[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        visits.push({ action: 'join', participantPosition });
    }
    for (
        let participantPosition = 0;
        participantPosition < participantCount - 1;
        participantPosition += 1
    ) {
        visits.push({ action: 'prepare', participantPosition });
    }
    if (scenario.mode === 'pending-private-preparation') {
        visits.push({
            action: 'source',
            crashBoundary: 'preparation-consume',
            participantPosition: 5,
        });
        visits.push({
            action: 'source',
            cleanup: true,
            expectPendingSourceRefusal: true,
            participantPosition: 5,
        });
        return visits;
    }
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        if (scenario.recoveryAndHostileCoverage && participantPosition === 9) {
            visits.push({
                action: 'source',
                crashBoundary: 'source-bind',
                participantPosition,
            });
        }
        visits.push({
            action: 'source',
            participantPosition,
            ...(scenario.recoveryAndHostileCoverage && participantPosition === 7
                ? { probeSourceConflict: true }
                : {}),
        });
    }
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        visits.push({
            action: 'finality',
            participantPosition,
            ...(scenario.recoveryAndHostileCoverage && participantPosition === 8
                ? { probeCorruptSource: true }
                : {}),
            ...(scenario.recoveryAndHostileCoverage && participantPosition === 9
                ? { probeFinalityConflict: true }
                : {}),
        });
    }
    if (scenario.mode === 'all-abstain') {
        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            visits.push({
                action: 'no-result',
                cleanup: true,
                participantPosition,
            });
        }
        return visits;
    }
    const lastChunkOrdinal =
        compileIndependentPaddedTallyModel(scenario.topCount).descriptors
            .length - 1;
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        if (scenario.recoveryAndHostileCoverage && participantPosition === 9) {
            visits.push({
                action: 'activation',
                crashBoundary: 'tally-generation-initialize',
                participantPosition,
            });
        }
        if (scenario.recoveryAndHostileCoverage && participantPosition === 1) {
            visits.push({
                action: 'activation',
                crashBoundary: 'tally-chunk-persist',
                participantPosition,
                startChunkOrdinal: 0,
            });
        }
        if (scenario.recoveryAndHostileCoverage && participantPosition === 2) {
            visits.push({
                action: 'activation',
                crashBoundary: 'tally-activation-publish',
                participantPosition,
                startChunkOrdinal: 0,
            });
        }
        visits.push({
            action: 'activation',
            participantPosition,
            ...(scenario.recoveryAndHostileCoverage && participantPosition === 2
                ? { startChunkOrdinal: lastChunkOrdinal }
                : { startChunkOrdinal: 0 }),
        });
    }
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        if (scenario.recoveryAndHostileCoverage && participantPosition === 9) {
            visits.push({
                action: 'evaluation',
                crashBoundary: 'tally-evaluation-initialize',
                participantPosition,
            });
            visits.push({
                action: 'evaluation-repair',
                participantPosition,
            });
        }
        if (scenario.recoveryAndHostileCoverage && participantPosition === 3) {
            visits.push({
                action: 'evaluation',
                crashBoundary: 'tally-evaluation-step',
                participantPosition,
                startChunkOrdinal: 0,
            });
        }
        if (scenario.recoveryAndHostileCoverage && participantPosition === 4) {
            visits.push({
                action: 'evaluation',
                crashBoundary: 'tally-terminal-persist',
                participantPosition,
                startChunkOrdinal: 0,
            });
        }
        visits.push({
            action: 'evaluation',
            cleanup:
                !scenario.recoveryAndHostileCoverage ||
                participantPosition !== 2,
            participantPosition,
            ...(scenario.recoveryAndHostileCoverage && participantPosition === 9
                ? { startChunkOrdinal: 1 }
                : scenario.recoveryAndHostileCoverage &&
                    participantPosition === 4
                  ? { startChunkOrdinal: lastChunkOrdinal }
                  : { startChunkOrdinal: 0 }),
            ...(scenario.recoveryAndHostileCoverage && participantPosition === 6
                ? {
                      pressureByteLength: scratchPlanningTargetByteLength,
                      probeCorruptManifest: true,
                      probeThreeCorruptChunks: true,
                  }
                : {}),
        });
    }
    if (scenario.recoveryAndHostileCoverage) {
        visits.push({
            action: 'state-loss-probe',
            cleanup: true,
            participantPosition: 2,
        });
        visits.push({ action: 'reclaim', participantPosition: 9 });
    }
    return visits;
};

export const countExternalCeremonyVisits = (
    schedule: readonly ExternalCeremonyVisit[],
): readonly number[] =>
    Array.from(
        { length: participantCount },
        (_, participantPosition) =>
            schedule.filter(
                (visit) => visit.participantPosition === participantPosition,
            ).length,
    );

const parseArguments = (arguments_: readonly string[]): DriverArguments => {
    if (
        arguments_.length !== 4 ||
        arguments_[0] !== '--package' ||
        arguments_[1] === undefined ||
        arguments_[2] !== '--result' ||
        arguments_[3] === undefined
    ) {
        throw new Error(
            'Usage: external-chrome-ceremony-driver.ts --package <candidate.tgz> --result <result.json>.',
        );
    }
    return {
        candidateArchivePath: path.resolve(arguments_[1]),
        resultFilePath: path.resolve(arguments_[3]),
    };
};

const sha256Hex = (bytes: Uint8Array): string =>
    createHash('sha256').update(bytes).digest('hex');

const fileIdentity = (filePath: string, bytes: Uint8Array): FileIdentity => ({
    byteLength: bytes.byteLength,
    repositoryRelativePath: path
        .relative(repositoryRootPath, filePath)
        .split(path.sep)
        .join('/'),
    sha256Hex: sha256Hex(bytes),
});

const readCleanRepositoryCommit = (): string => {
    const commitHash = execFileSync(
        'git',
        ['rev-parse', '--verify', 'HEAD^{commit}'],
        {
            cwd: repositoryRootPath,
            encoding: 'utf8',
            windowsHide: true,
        },
    ).trim();
    const status = execFileSync(
        'git',
        [
            'status',
            '--porcelain=v1',
            '--untracked-files=normal',
            '--ignore-submodules=none',
        ],
        {
            cwd: repositoryRootPath,
            encoding: 'utf8',
            windowsHide: true,
        },
    );
    if (status.length !== 0) {
        throw new Error(
            'The external-Chrome ceremony requires a clean committed worktree.',
        );
    }
    return commitHash;
};

const resolveChromeExecutablePath = (): string => {
    const configuredPath = process.env.SEALED_LATTICE_EXTERNAL_CHROME_PATH;
    const candidates = [
        configuredPath,
        process.platform === 'win32'
            ? path.join(
                  process.env.ProgramFiles ?? 'C:\\Program Files',
                  'Google',
                  'Chrome',
                  'Application',
                  'chrome.exe',
              )
            : undefined,
        process.platform === 'win32'
            ? path.join(
                  process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)',
                  'Google',
                  'Chrome',
                  'Application',
                  'chrome.exe',
              )
            : undefined,
        process.platform === 'darwin'
            ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
            : undefined,
        process.platform === 'linux' ? '/usr/bin/google-chrome' : undefined,
        process.platform === 'linux'
            ? '/usr/bin/google-chrome-stable'
            : undefined,
    ].filter((candidate): candidate is string => candidate !== undefined);
    const resolved = candidates.find((candidate) => existsSync(candidate));
    if (resolved === undefined) {
        throw new Error(
            'External release Chrome was not found. Set SEALED_LATTICE_EXTERNAL_CHROME_PATH.',
        );
    }
    return path.resolve(resolved);
};

const requireRecord = (
    value: unknown,
    name: string,
): Readonly<Record<string, unknown>> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${name} is not an object.`);
    }
    return value as Readonly<Record<string, unknown>>;
};

const requireString = (
    record: Readonly<Record<string, unknown>>,
    name: string,
): string => {
    const value = record[name];
    if (typeof value !== 'string') {
        throw new Error(`${name} is not a string.`);
    }
    return value;
};

const requireNumber = (
    record: Readonly<Record<string, unknown>>,
    name: string,
): number => {
    const value = record[name];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new Error(`${name} is not a nonnegative finite number.`);
    }
    return value;
};

const requireBoolean = (
    record: Readonly<Record<string, unknown>>,
    name: string,
): boolean => {
    const value = record[name];
    if (typeof value !== 'boolean') {
        throw new Error(`${name} is not boolean.`);
    }
    return value;
};

const writeResponse = (
    response: ServerResponse,
    statusCode: number,
    contentType: string,
    body: Uint8Array,
): void => {
    response.writeHead(statusCode, {
        'Cache-Control': 'no-store',
        'Content-Length': body.byteLength,
        'Content-Type': contentType,
        'Cross-Origin-Resource-Policy': 'same-origin',
        'X-Content-Type-Options': 'nosniff',
    });
    response.end(body);
};

const listen = (server: Server): Promise<number> =>
    new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.off('error', reject);
            const address = server.address();
            if (address === null || typeof address === 'string') {
                reject(new Error('The ceremony server omitted its TCP port.'));
                return;
            }
            resolve(address.port);
        });
    });

const closeServer = (server: Server): Promise<void> =>
    new Promise((resolve, reject) => {
        server.close((error) => {
            if (error === undefined) resolve();
            else reject(error);
        });
    });

const readRequestBody = async (request: IncomingMessage): Promise<Buffer> => {
    const chunks: Buffer[] = [];
    let byteLength = 0;
    for await (const chunk of request) {
        const unknownChunk: unknown = chunk;
        if (!(unknownChunk instanceof Uint8Array)) {
            throw new Error('The relay request yielded a non-byte chunk.');
        }
        const bytes = Buffer.from(unknownChunk);
        byteLength += bytes.byteLength;
        if (byteLength > maximumRequestBodyByteLength) {
            throw new Error(
                'The relay request exceeds the copied-buffer bound.',
            );
        }
        chunks.push(bytes);
    }
    return Buffer.concat(chunks, byteLength);
};

const contentTypeForPath = (filePath: string): string => {
    switch (path.extname(filePath)) {
        case '.html':
            return 'text/html; charset=utf-8';
        case '.js':
        case '.mjs':
            return 'text/javascript; charset=utf-8';
        case '.json':
        case '.map':
            return 'application/json; charset=utf-8';
        case '.wasm':
            return 'application/wasm';
        default:
            return 'application/octet-stream';
    }
};

const withinDirectory = (parent: string, candidate: string): boolean => {
    const relative = path.relative(parent, candidate);
    return (
        relative.length > 0 &&
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
};

const createRelayServer = async (input: {
    readonly candidatePackagePath: string;
    readonly pageHtml: Uint8Array;
    readonly pageScript: Uint8Array;
    readonly relayRootPath: string;
    readonly workerScript: Uint8Array;
}): Promise<RelayServer> => {
    const transfers = new Map<string, RelayTransfer>();
    const inventoryByName = new Map<
        string,
        Readonly<{ byteLength: number; sha256Hex: string }>
    >();
    const transfer = (visitToken: string): RelayTransfer => {
        const existing = transfers.get(visitToken);
        if (existing !== undefined) return existing;
        const created = {
            candidateDownloadByteLength: 0,
            harnessDownloadByteLength: 0,
            relayDownloadByteLength: 0,
            relayUploadByteLength: 0,
            requestCount: 0,
        };
        transfers.set(visitToken, created);
        return created;
    };
    const handleRequest = async (
        request: IncomingMessage,
        response: ServerResponse,
    ): Promise<void> => {
        const visitHeader = request.headers['x-sealed-lattice-visit'];
        const visitToken = Array.isArray(visitHeader)
            ? visitHeader[0]
            : visitHeader;
        const counters = transfer(visitToken ?? 'unattributed');
        counters.requestCount += 1;
        try {
            if (request.url === undefined) {
                writeResponse(
                    response,
                    400,
                    'text/plain; charset=utf-8',
                    Buffer.from('Missing URL.'),
                );
                return;
            }
            const url = new URL(request.url, 'http://127.0.0.1');
            if (request.method === 'GET' && url.pathname === '/') {
                counters.harnessDownloadByteLength += input.pageHtml.byteLength;
                writeResponse(
                    response,
                    200,
                    'text/html; charset=utf-8',
                    input.pageHtml,
                );
                return;
            }
            if (
                request.method === 'GET' &&
                url.pathname === '/external-chrome-ceremony.mjs'
            ) {
                counters.harnessDownloadByteLength +=
                    input.pageScript.byteLength;
                writeResponse(
                    response,
                    200,
                    'text/javascript; charset=utf-8',
                    input.pageScript,
                );
                return;
            }
            if (
                request.method === 'GET' &&
                url.pathname === '/external-chrome-ceremony-worker.mjs'
            ) {
                counters.harnessDownloadByteLength +=
                    input.workerScript.byteLength;
                writeResponse(
                    response,
                    200,
                    'text/javascript; charset=utf-8',
                    input.workerScript,
                );
                return;
            }
            if (
                request.method === 'GET' &&
                url.pathname.startsWith('/candidate/')
            ) {
                const relativePath = url.pathname.slice('/candidate/'.length);
                const candidatePath = path.resolve(
                    input.candidatePackagePath,
                    relativePath,
                );
                if (
                    !withinDirectory(input.candidatePackagePath, candidatePath)
                ) {
                    writeResponse(
                        response,
                        404,
                        'text/plain; charset=utf-8',
                        Buffer.from('Not found.'),
                    );
                    return;
                }
                const bytes = Uint8Array.from(await readFile(candidatePath));
                counters.candidateDownloadByteLength += bytes.byteLength;
                writeResponse(
                    response,
                    200,
                    contentTypeForPath(candidatePath),
                    bytes,
                );
                return;
            }
            const relayMatch = /^\/relay\/([a-z0-9-]+)\/(.+)$/u.exec(
                url.pathname,
            );
            if (relayMatch !== null) {
                const scenarioIdentifier = relayMatch[1];
                const objectName = relayMatch[2];
                if (
                    scenarioIdentifier === undefined ||
                    objectName === undefined ||
                    !/^[a-z0-9][a-z0-9./-]*$/u.test(objectName) ||
                    objectName.split('/').includes('..')
                ) {
                    writeResponse(
                        response,
                        400,
                        'text/plain; charset=utf-8',
                        Buffer.from('Invalid relay object.'),
                    );
                    return;
                }
                if (url.searchParams.get('delay') !== null) {
                    const delayMilliseconds = Number(
                        url.searchParams.get('delay'),
                    );
                    if (
                        !Number.isSafeInteger(delayMilliseconds) ||
                        delayMilliseconds < 0 ||
                        delayMilliseconds > 5_000
                    ) {
                        throw new Error('The relay delay is invalid.');
                    }
                    await new Promise((resolve) =>
                        setTimeout(resolve, delayMilliseconds),
                    );
                }
                const scenarioRoot = path.resolve(
                    input.relayRootPath,
                    scenarioIdentifier,
                );
                const objectPath = path.resolve(scenarioRoot, objectName);
                if (!withinDirectory(scenarioRoot, objectPath)) {
                    throw new Error(
                        'The relay path escaped its scenario root.',
                    );
                }
                const inventoryName = `${scenarioIdentifier}/${objectName}`;
                if (request.method === 'PUT') {
                    const bytes = await readRequestBody(request);
                    counters.relayUploadByteLength += bytes.byteLength;
                    await mkdir(path.dirname(objectPath), { recursive: true });
                    try {
                        await writeFile(objectPath, bytes, { flag: 'wx' });
                        inventoryByName.set(inventoryName, {
                            byteLength: bytes.byteLength,
                            sha256Hex: sha256Hex(bytes),
                        });
                    } catch (error: unknown) {
                        if (!(
                            error instanceof Error &&
                            'code' in error &&
                            error.code === 'EEXIST'
                        )) {
                            throw error;
                        }
                        const retained = Uint8Array.from(
                            await readFile(objectPath),
                        );
                        if (
                            retained.byteLength !== bytes.byteLength ||
                            sha256Hex(retained) !== sha256Hex(bytes)
                        ) {
                            writeResponse(
                                response,
                                409,
                                'text/plain; charset=utf-8',
                                Buffer.from(
                                    'The immutable relay object conflicts.',
                                ),
                            );
                            return;
                        }
                    }
                    writeResponse(
                        response,
                        200,
                        'application/octet-stream',
                        new Uint8Array(),
                    );
                    return;
                }
                if (request.method === 'GET') {
                    try {
                        const bytes = Uint8Array.from(
                            await readFile(objectPath),
                        );
                        counters.relayDownloadByteLength += bytes.byteLength;
                        writeResponse(
                            response,
                            200,
                            'application/octet-stream',
                            bytes,
                        );
                    } catch (error: unknown) {
                        if (
                            error instanceof Error &&
                            'code' in error &&
                            error.code === 'ENOENT'
                        ) {
                            writeResponse(
                                response,
                                404,
                                'text/plain; charset=utf-8',
                                Buffer.from('Not found.'),
                            );
                            return;
                        }
                        throw error;
                    }
                    return;
                }
            }
            writeResponse(
                response,
                404,
                'text/plain; charset=utf-8',
                Buffer.from('Not found.'),
            );
        } catch (error: unknown) {
            if (!response.headersSent) {
                writeResponse(
                    response,
                    500,
                    'text/plain; charset=utf-8',
                    Buffer.from(
                        error instanceof Error
                            ? error.message
                            : 'Unknown server error.',
                    ),
                );
            } else {
                response.destroy(error instanceof Error ? error : undefined);
            }
        }
    };
    const server = createServer((request, response) => {
        void handleRequest(request, response);
    });
    const port = await listen(server);
    return {
        close: () => closeServer(server),
        inventory: () =>
            [...inventoryByName.entries()]
                .sort(([left], [right]) => left.localeCompare(right, 'en'))
                .map(([objectName, identity]) => ({ objectName, ...identity })),
        origin: `http://127.0.0.1:${String(port)}`,
        readRelayObject: async (objectName) => {
            const objectPath = path.resolve(input.relayRootPath, objectName);
            if (!withinDirectory(input.relayRootPath, objectPath)) {
                throw new Error('The evidence reader escaped the relay root.');
            }
            return Uint8Array.from(await readFile(objectPath));
        },
        relayCorpusByteLength: () =>
            [...inventoryByName.values()].reduce(
                (sum, entry) => sum + entry.byteLength,
                0,
            ),
        transferForVisit: (visitToken) => ({ ...transfer(visitToken) }),
    };
};

const startRuntimeSampler = (
    browserSession: CDPSession,
    pageSession: CDPSession,
): Readonly<{ finish(): Promise<VisitRuntimeMeasurement> }> => {
    const samples: RuntimeSample[] = [];
    let active = true;
    let sampling: Promise<void> | undefined;
    const sample = async (): Promise<void> => {
        if (!active && samples.length > 0) return;
        const capturedAtMilliseconds = performance.now();
        const [processes, heap] = await Promise.all([
            browserSession.send('SystemInfo.getProcessInfo'),
            pageSession.send('Runtime.getHeapUsage'),
        ]);
        const processInventory = requireRecord(
            processes,
            'Chrome process inventory',
        );
        const rawProcessInfo = processInventory.processInfo;
        if (!Array.isArray(rawProcessInfo)) {
            throw new Error('Chrome omitted its process inventory.');
        }
        const processIdentifiers = rawProcessInfo.map((entry, index) => {
            const record = requireRecord(
                entry,
                `Chrome process ${String(index)}`,
            );
            return requireNumber(record, 'id');
        });
        const memoryRows = await readProcessPrivateMemory(processIdentifiers);
        const heapRecord = requireRecord(heap, 'Chrome heap measurement');
        samples.push({
            browserPrivateByteLength: memoryRows.reduce(
                (sum, row) => sum + row.privateByteLength,
                0,
            ),
            browserResidentByteLength: memoryRows.reduce(
                (sum, row) => sum + row.residentByteLength,
                0,
            ),
            capturedAtMilliseconds,
            javascriptHeapTotalByteLength: requireNumber(
                heapRecord,
                'totalSize',
            ),
            javascriptHeapUsedByteLength: requireNumber(heapRecord, 'usedSize'),
            processCount: memoryRows.length,
        });
    };
    const timer = setInterval(() => {
        if (sampling === undefined) {
            sampling = sample().finally(() => {
                sampling = undefined;
            });
        }
    }, memorySampleIntervalMilliseconds);
    sampling = sample().finally(() => {
        sampling = undefined;
    });
    return {
        finish: async () => {
            active = false;
            clearInterval(timer);
            await sampling;
            await sample();
            const idleBrowserPrivateByteLength =
                samples[0]?.browserPrivateByteLength ?? 0;
            const idleJavascriptHeapUsedByteLength =
                samples[0]?.javascriptHeapUsedByteLength ?? 0;
            const peakBrowserPrivateByteLength = Math.max(
                ...samples.map((entry) => entry.browserPrivateByteLength),
            );
            const peakJavascriptHeapUsedByteLength = Math.max(
                ...samples.map((entry) => entry.javascriptHeapUsedByteLength),
            );
            return {
                idleBrowserPrivateByteLength,
                idleJavascriptHeapUsedByteLength,
                peakBrowserPrivateByteLength,
                peakBrowserPrivateMemoryIncreaseByteLength: Math.max(
                    0,
                    peakBrowserPrivateByteLength - idleBrowserPrivateByteLength,
                ),
                peakJavascriptHeapIncreaseByteLength: Math.max(
                    0,
                    peakJavascriptHeapUsedByteLength -
                        idleJavascriptHeapUsedByteLength,
                ),
                peakJavascriptHeapUsedByteLength,
                samples,
            };
        },
    };
};

const withTimeout = async <Result>(
    operation: Promise<Result>,
    timeoutMilliseconds: number,
): Promise<Result> => {
    let timer: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([
            operation,
            new Promise<never>((_resolve, reject) => {
                timer = setTimeout(
                    () => reject(new Error('The browser visit timed out.')),
                    timeoutMilliseconds,
                );
            }),
        ]);
    } finally {
        if (timer !== undefined) clearTimeout(timer);
    }
};

const configureChromePage = async (
    context: BrowserContext,
    page: Page,
    origin: string,
    permissionMode: 'deny' | 'grant',
): Promise<
    Readonly<{
        browserIdentity: unknown;
        browserSession: CDPSession;
        encodedDownload: Readonly<{ value: number }>;
        pageSession: CDPSession;
    }>
> => {
    const browser = context.browser();
    if (browser === null) {
        throw new Error('The persistent Chrome context has no browser.');
    }
    const pageSession = await context.newCDPSession(page);
    const browserSession = await browser.newBrowserCDPSession();
    if (permissionMode === 'grant') {
        await browserSession.send('Browser.grantPermissions', {
            origin,
            permissions: ['durableStorage'],
        });
    } else {
        await browserSession.send('Browser.setPermission', {
            origin,
            permission: { name: 'persistent-storage' },
            setting: 'denied',
        });
    }
    await pageSession.send('Network.enable');
    await pageSession.send('Network.setCacheDisabled', {
        cacheDisabled: true,
    });
    const userAgent = `Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browser.version()} Mobile Safari/537.36`;
    await pageSession.send('Network.setUserAgentOverride', { userAgent });
    await pageSession.send('Network.emulateNetworkConditions', {
        connectionType: wifiProfile.connectionType,
        downloadThroughput: wifiProfile.downloadThroughputBytesPerSecond,
        latency: wifiProfile.latencyMilliseconds,
        offline: false,
        uploadThroughput: wifiProfile.uploadThroughputBytesPerSecond,
    });
    await pageSession.send('Emulation.setCPUThrottlingRate', {
        rate: cpuThrottlingRate,
    });
    await pageSession.send('Emulation.setTouchEmulationEnabled', {
        enabled: true,
        maxTouchPoints: mobileProfile.maxTouchPoints,
    });
    const encodedDownload = { value: 0 };
    pageSession.on('Network.loadingFinished', (event) => {
        encodedDownload.value += event.encodedDataLength;
    });
    return {
        browserIdentity: await browserSession.send('Browser.getVersion'),
        browserSession,
        encodedDownload,
        pageSession,
    };
};

const launchVisit = async (input: {
    readonly chromeExecutablePath: string;
    readonly configuration: Readonly<Record<string, unknown>>;
    readonly origin: string;
    readonly participantPosition: number;
    readonly permissionMode: 'deny' | 'grant';
    readonly profilePath: string;
    readonly relayServer: RelayServer;
    readonly sequence: number;
    readonly visitToken: string;
}): Promise<VisitEvidence> => {
    const startedAtIso = new Date().toISOString();
    const startedAtMilliseconds = performance.now();
    let context: BrowserContext | undefined;
    try {
        context = await chromium.launchPersistentContext(input.profilePath, {
            deviceScaleFactor: mobileProfile.deviceScaleFactor,
            executablePath: input.chromeExecutablePath,
            hasTouch: mobileProfile.hasTouch,
            headless: true,
            isMobile: mobileProfile.isMobile,
            serviceWorkers: 'block',
            viewport: {
                height: mobileProfile.height,
                width: mobileProfile.width,
            },
        });
        await context.setExtraHTTPHeaders({
            'X-Sealed-Lattice-Visit': input.visitToken,
        });
        const page = context.pages()[0] ?? (await context.newPage());
        const pageDiagnostics: string[] = [];
        page.on('console', (message) => {
            if (
                message.type() === 'error' ||
                message.text().startsWith('[external-ceremony-worker]')
            ) {
                pageDiagnostics.push(`console: ${message.text()}`);
            }
        });
        page.on('pageerror', (error) => {
            pageDiagnostics.push(`pageerror: ${error.message}`);
        });
        page.setDefaultNavigationTimeout(120_000);
        const configured = await configureChromePage(
            context,
            page,
            input.origin,
            input.permissionMode,
        );
        await page.goto(`${input.origin}/?visit=${input.visitToken}`, {
            waitUntil: 'load',
        });
        try {
            await page.waitForFunction(
                () =>
                    typeof (
                        globalThis as typeof globalThis & {
                            runExternalChromeCeremonyVisit?: unknown;
                        }
                    ).runExternalChromeCeremonyVisit === 'function',
                undefined,
                { timeout: 120_000 },
            );
        } catch {
            throw new Error(
                `The ceremony page did not initialize: ${pageDiagnostics.join(' | ') || 'no page diagnostic was emitted'}.`,
            );
        }
        const observation = await page.evaluate(() => ({
            coarsePointer: matchMedia('(pointer: coarse)').matches,
            devicePixelRatio,
            innerHeight,
            innerWidth,
            maxTouchPoints: navigator.maxTouchPoints,
            navigationType:
                performance.getEntriesByType('navigation')[0]?.entryType,
            userAgent: navigator.userAgent,
        }));
        if (
            !observation.coarsePointer ||
            observation.innerHeight !== mobileProfile.height ||
            observation.innerWidth !== mobileProfile.width ||
            observation.maxTouchPoints !== mobileProfile.maxTouchPoints
        ) {
            throw new Error(
                'The external Chrome mobile emulation is incomplete.',
            );
        }
        const sampler = startRuntimeSampler(
            configured.browserSession,
            configured.pageSession,
        );
        let rawResult: unknown;
        let runtime: VisitRuntimeMeasurement;
        try {
            rawResult = await withTimeout(
                page.evaluate(async (configuration) => {
                    const global = globalThis as typeof globalThis & {
                        runExternalChromeCeremonyVisit?: (
                            value: unknown,
                        ) => Promise<unknown>;
                    };
                    if (global.runExternalChromeCeremonyVisit === undefined) {
                        throw new Error(
                            'The ceremony page did not initialize.',
                        );
                    }
                    return global.runExternalChromeCeremonyVisit(configuration);
                }, input.configuration),
                visitForegroundLimitMilliseconds,
            );
        } catch (error) {
            const status = await page
                .locator('#status')
                .textContent()
                .catch(() => undefined);
            const workerDiagnostics = await Promise.all(
                page.workers().map(async (worker) => {
                    try {
                        return await withTimeout(
                            worker.evaluate(async () => ({
                                persisted: await Promise.race([
                                    navigator.storage.persisted(),
                                    new Promise<'timeout'>((resolve) =>
                                        setTimeout(
                                            () => resolve('timeout'),
                                            2_000,
                                        ),
                                    ),
                                ]),
                                resources: performance
                                    .getEntriesByType('resource')
                                    .map((entry) => entry.name),
                            })),
                            5_000,
                        );
                    } catch (workerError) {
                        return {
                            diagnosticError:
                                workerError instanceof Error
                                    ? workerError.message
                                    : 'unknown worker diagnostic failure',
                        };
                    }
                }),
            );
            process.stderr.write(
                `External ceremony visit diagnostic: stage=${status ?? 'unavailable'}; browser=${pageDiagnostics.join(' | ') || 'none'}; workers=${JSON.stringify(workerDiagnostics)}; transfer=${JSON.stringify(input.relayServer.transferForVisit(input.visitToken))}\n`,
            );
            if (error instanceof Error) {
                error.message = `${error.message} Last page stage: ${status ?? 'unavailable'}. Browser diagnostics: ${pageDiagnostics.join(' | ') || 'none'}. Transfer: ${JSON.stringify(input.relayServer.transferForVisit(input.visitToken))}.`;
            }
            throw error;
        } finally {
            runtime = await sampler.finish();
        }
        const pageResult = requireRecord(rawResult, 'Ceremony page result');
        const foregroundMilliseconds =
            performance.now() - startedAtMilliseconds;
        return {
            action: requireString(
                pageResult,
                'action',
            ) as VisitEvidence['action'],
            browserIdentity: configured.browserIdentity,
            browserEncodedDownloadByteLength: configured.encodedDownload.value,
            coldNavigation: observation.navigationType === 'navigate',
            finishedAtIso: new Date().toISOString(),
            foregroundMilliseconds,
            pageResult,
            participantPosition: input.participantPosition,
            runtime,
            sequence: input.sequence,
            startedAtIso,
            transfer: input.relayServer.transferForVisit(input.visitToken),
            visitToken: input.visitToken,
        };
    } finally {
        await context?.close();
    }
};

const deterministicIdentity = (
    runIdentifier: string,
    purpose: string,
): string =>
    createHash('shake256', { outputLength: 64 })
        .update('sealed-lattice/external-chrome-ceremony/identity/v1')
        .update('\0')
        .update(runIdentifier)
        .update('\0')
        .update(purpose)
        .digest('hex');

const expectedDirectResult = (
    ballots: readonly Ballot[],
    topCount: number,
): Readonly<{
    acceptedBallotAuthorshipBitmap: number;
    orderedOptionPositions: readonly number[] | undefined;
}> => {
    const aggregate = Array.from({ length: participantCount }, () => 0);
    let acceptedBallotAuthorshipBitmap = 0;
    for (const [participantPosition, ballot] of ballots.entries()) {
        const accepted =
            ballot.declaration === 'submit' &&
            ballot.scoreEncodings.every((score) => score >= 1 && score <= 10);
        if (!accepted) continue;
        acceptedBallotAuthorshipBitmap |= 1 << participantPosition;
        for (const [optionPosition, score] of ballot.scoreEncodings.entries()) {
            aggregate[optionPosition] =
                (aggregate[optionPosition] ?? 0) + score;
        }
    }
    return {
        acceptedBallotAuthorshipBitmap,
        orderedOptionPositions:
            acceptedBallotAuthorshipBitmap === 0
                ? undefined
                : Array.from({ length: participantCount }, (_, index) => index)
                      .sort(
                          (left, right) =>
                              (aggregate[right] ?? 0) -
                                  (aggregate[left] ?? 0) || left - right,
                      )
                      .slice(0, topCount),
    };
};

const directoryByteLength = async (directoryPath: string): Promise<number> => {
    let total = 0;
    for (const entry of await readdir(directoryPath, { withFileTypes: true })) {
        const entryPath = path.join(directoryPath, entry.name);
        if (entry.isDirectory()) total += await directoryByteLength(entryPath);
        else if (entry.isFile()) total += (await stat(entryPath)).size;
    }
    return total;
};

const validateScenarioTerminal = async (
    relayServer: RelayServer,
    scenario: ScenarioDefinition,
    visitEvidence: readonly VisitEvidence[],
): Promise<Readonly<Record<string, unknown>>> => {
    const terminalVisits = visitEvidence.filter((visit) => {
        const terminal = visit.pageResult.terminal;
        return typeof terminal === 'object' && terminal !== null;
    });
    if (scenario.mode === 'pending-private-preparation') {
        if (terminalVisits.length !== 0) {
            throw new Error(
                'The private-preparation state-loss path produced a terminal.',
            );
        }
        const refusalVisits = visitEvidence.filter((visit) => {
            const refusal = visit.pageResult.pendingSourceRefusal;
            return typeof refusal === 'object' && refusal !== null;
        });
        if (refusalVisits.length !== 1) {
            throw new Error(
                'The private-preparation state-loss path did not produce one source refusal.',
            );
        }
        const refusal = requireRecord(
            refusalVisits[0]?.pageResult.pendingSourceRefusal,
            'Private-preparation pending refusal',
        );
        if (
            requireString(refusal, 'name') !== 'ProtocolRefusal' ||
            !requireString(refusal, 'message').includes(
                'private preparation delivery is not positively resolved',
            )
        ) {
            throw new Error(
                'The private-preparation state-loss path produced the wrong refusal.',
            );
        }
        const relayTerminals = relayServer
            .inventory()
            .filter((entry) =>
                entry.objectName.startsWith(`${scenario.identifier}/terminal/`),
            );
        if (relayTerminals.length !== 0) {
            throw new Error(
                'The private-preparation state-loss path published a terminal.',
            );
        }
        return {
            kind: 'pending',
            reason: 'private-preparation-state-loss',
            terminalCount: 0,
        };
    }
    const expected = expectedDirectResult(scenario.ballots, scenario.topCount);
    if (terminalVisits.length !== participantCount) {
        throw new Error(
            `${scenario.identifier} produced ${String(terminalVisits.length)} terminals.`,
        );
    }
    if (scenario.mode === 'all-abstain') {
        for (const visit of terminalVisits) {
            const terminal = requireRecord(
                visit.pageResult.terminal,
                'Source-empty terminal',
            );
            if (
                requireString(terminal, 'kind') !== 'no-result' ||
                requireString(terminal, 'terminalPath') !== 'source-empty' ||
                requireNumber(terminal, 'acceptedBallotAuthorshipBitmap') !== 0
            ) {
                throw new Error('The all-abstain terminal is inconsistent.');
            }
        }
        return {
            acceptedBallotAuthorshipBitmap: 0,
            kind: 'no-result',
            terminalCount: terminalVisits.length,
            terminalPath: 'source-empty',
        };
    }
    const terminalBodies: Uint8Array[] = [];
    for (
        let participantPosition = 0;
        participantPosition < participantCount;
        participantPosition += 1
    ) {
        terminalBodies.push(
            await relayServer.readRelayObject(
                `${scenario.identifier}/terminal/${String(participantPosition)}/body`,
            ),
        );
    }
    const firstHash = sha256Hex(terminalBodies[0] ?? new Uint8Array());
    if (terminalBodies.some((body) => sha256Hex(body) !== firstHash)) {
        throw new Error(
            'Sequential participants accepted different terminals.',
        );
    }
    const parsed = parsePaddedTallyTerminal(
        terminalBodies[0] ?? new Uint8Array(),
    );
    if (
        parsed.topCount !== scenario.topCount ||
        parsed.acceptedBallotAuthorship.reduce(
            (bitmap, accepted, participantPosition) =>
                accepted ? bitmap | (1 << participantPosition) : bitmap,
            0,
        ) !== expected.acceptedBallotAuthorshipBitmap ||
        JSON.stringify(parsed.orderedOptionPositions) !==
            JSON.stringify(expected.orderedOptionPositions)
    ) {
        throw new Error(
            'The serialized terminal differs from the direct evaluator.',
        );
    }
    const expectedKind =
        expected.orderedOptionPositions === undefined ? 'no-result' : 'result';
    if (parsed.kind !== expectedKind) {
        throw new Error('The serialized terminal has the wrong result kind.');
    }
    return {
        acceptedBallotAuthorshipBitmap: expected.acceptedBallotAuthorshipBitmap,
        kind: parsed.kind,
        orderedOptionPositions: parsed.orderedOptionPositions,
        terminalByteLength: terminalBodies[0]?.byteLength ?? 0,
        terminalCount: terminalBodies.length,
        terminalSha256Hex: firstHash,
    };
};

const extractNumber = (
    value: unknown,
    nestedNames: readonly string[],
): number | undefined => {
    let current = value;
    for (const name of nestedNames) {
        if (typeof current !== 'object' || current === null) return undefined;
        current = (current as Readonly<Record<string, unknown>>)[name];
    }
    return typeof current === 'number' && Number.isFinite(current)
        ? current
        : undefined;
};

const summarizeScenario = (
    schedule: readonly ExternalCeremonyVisit[],
    visits: readonly VisitEvidence[],
    relayCorpusByteLength: number,
    wallMilliseconds: number,
): Readonly<Record<string, unknown>> => {
    const visitCounts = countExternalCeremonyVisits(schedule);
    const participantSummaries = Array.from(
        { length: participantCount },
        (_, participantPosition) => {
            const participantVisits = visits.filter(
                (visit) => visit.participantPosition === participantPosition,
            );
            const uploadByteLength = participantVisits.reduce(
                (sum, visit) => sum + visit.transfer.relayUploadByteLength,
                0,
            );
            const downloadByteLength = participantVisits.reduce(
                (sum, visit) =>
                    sum +
                    visit.transfer.relayDownloadByteLength +
                    visit.transfer.candidateDownloadByteLength +
                    visit.transfer.harnessDownloadByteLength,
                0,
            );
            const foregroundMilliseconds = participantVisits.reduce(
                (sum, visit) => sum + visit.foregroundMilliseconds,
                0,
            );
            const peakStorageUsageByteLength = Math.max(
                0,
                ...participantVisits.flatMap((visit) => [
                    extractNumber(visit.pageResult, [
                        'storageBefore',
                        'usage',
                    ]) ?? 0,
                    extractNumber(visit.pageResult, [
                        'storageAfter',
                        'usage',
                    ]) ?? 0,
                    extractNumber(visit.pageResult, [
                        'storageUnderQuotaPressure',
                        'usage',
                    ]) ?? 0,
                ]),
            );
            const maximumWasmMemoryByteLength = Math.max(
                0,
                ...participantVisits.map(
                    (visit) =>
                        extractNumber(visit.pageResult, [
                            'kernelResources',
                            'wasmMemoryByteLength',
                        ]) ?? 0,
                ),
            );
            const maximumLiveProtocolByteLength = Math.max(
                0,
                ...participantVisits.map(
                    (visit) =>
                        extractNumber(visit.pageResult, [
                            'maximumLiveProtocolByteLength',
                        ]) ?? 0,
                ),
            );
            return {
                downloadByteLength,
                foregroundMilliseconds,
                maximumLiveProtocolByteLength,
                maximumWasmMemoryByteLength,
                participantPosition,
                pass:
                    participantVisits.length <= maximumVisitCount &&
                    foregroundMilliseconds <=
                        participantForegroundLimitMilliseconds &&
                    uploadByteLength <= participantTransferLimitByteLength &&
                    downloadByteLength <= participantTransferLimitByteLength &&
                    peakStorageUsageByteLength <=
                        persistentStorageLimitByteLength &&
                    maximumLiveProtocolByteLength <=
                        copiedBufferAbsoluteLimitByteLength &&
                    maximumWasmMemoryByteLength <=
                        wasmMemoryPlanningTargetByteLength,
                peakStorageUsageByteLength,
                uploadByteLength,
                visitCount: participantVisits.length,
            };
        },
    );
    const longestVisitMilliseconds = Math.max(
        ...visits.map((visit) => visit.foregroundMilliseconds),
    );
    const peakJavascriptHeapIncreaseByteLength = Math.max(
        ...visits.map(
            (visit) => visit.runtime.peakJavascriptHeapIncreaseByteLength,
        ),
    );
    const peakBrowserPrivateMemoryIncreaseByteLength = Math.max(
        ...visits.map(
            (visit) => visit.runtime.peakBrowserPrivateMemoryIncreaseByteLength,
        ),
    );
    const planningVariances = [
        ...(peakJavascriptHeapIncreaseByteLength >
        javascriptHeapPlanningTargetByteLength
            ? [
                  {
                      measuredByteLength: peakJavascriptHeapIncreaseByteLength,
                      name: 'peak JavaScript heap increase',
                      targetByteLength: javascriptHeapPlanningTargetByteLength,
                  },
              ]
            : []),
        ...(peakBrowserPrivateMemoryIncreaseByteLength >
        browserPrivateMemoryPlanningTargetByteLength
            ? [
                  {
                      measuredByteLength:
                          peakBrowserPrivateMemoryIncreaseByteLength,
                      name: 'peak browser-process private-memory increase',
                      targetByteLength:
                          browserPrivateMemoryPlanningTargetByteLength,
                  },
              ]
            : []),
    ];
    return {
        browserPrivateMemoryPlanningTargetByteLength,
        ceremonyWallLimitMilliseconds,
        javascriptHeapPlanningTargetByteLength,
        longestVisitMilliseconds,
        participantForegroundLimitMilliseconds,
        participantSummaries,
        pass:
            participantSummaries.every((entry) => entry.pass) &&
            visits.every(
                (visit) =>
                    visit.coldNavigation &&
                    visit.foregroundMilliseconds <=
                        visitForegroundLimitMilliseconds,
            ) &&
            wallMilliseconds <= ceremonyWallLimitMilliseconds &&
            relayCorpusByteLength <= publicCorpusLimitByteLength &&
            planningVariances.every(
                (variance) =>
                    variance.measuredByteLength <=
                    variance.targetByteLength * 1.5,
            ),
        peakBrowserPrivateMemoryIncreaseByteLength,
        peakJavascriptHeapIncreaseByteLength,
        planningVariances,
        publicCorpusLimitByteLength,
        relayCorpusByteLength,
        visitCounts,
        visitForegroundLimitMilliseconds,
        wallMilliseconds,
    };
};

const assertSchedule = (scenario: ScenarioDefinition): void => {
    const counts = countExternalCeremonyVisits(
        buildExternalCeremonyVisitSchedule(scenario),
    );
    if (counts.some((count) => count > maximumVisitCount)) {
        throw new Error(`${scenario.identifier} exceeds ten visits.`);
    }
    if (scenario.mode === 'pending-private-preparation') {
        const preparationConsumptionCrashes =
            buildExternalCeremonyVisitSchedule(scenario).filter(
                (visit) =>
                    visit.crashBoundary === 'preparation-consume' &&
                    visit.action === 'source',
            );
        const expectedPendingVisits = buildExternalCeremonyVisitSchedule(
            scenario,
        ).filter((visit) => visit.expectPendingSourceRefusal === true);
        if (
            preparationConsumptionCrashes.length !== 1 ||
            expectedPendingVisits.length !== 1 ||
            preparationConsumptionCrashes[0]?.participantPosition !==
                expectedPendingVisits[0]?.participantPosition
        ) {
            throw new Error(
                'The private-preparation state-loss schedule is incomplete.',
            );
        }
    } else if (!scenario.recoveryAndHostileCoverage) {
        const expectedEarlier = scenario.mode === 'all-abstain' ? 5 : 6;
        const expectedLast = scenario.mode === 'all-abstain' ? 4 : 5;
        if (
            counts
                .slice(0, participantCount - 1)
                .some((count) => count !== expectedEarlier) ||
            counts[participantCount - 1] !== expectedLast
        ) {
            throw new Error(
                `${scenario.identifier} does not match the ordinary visit graph.`,
            );
        }
    } else if (counts[participantCount - 1] !== maximumVisitCount) {
        throw new Error('The recovery schedule does not exercise ten visits.');
    }
};

const baseVisitConfiguration = (input: {
    readonly runIdentifier: string;
    readonly scenario: ScenarioDefinition;
    readonly visit: ExternalCeremonyVisit;
    readonly visitToken: string;
}): Readonly<Record<string, unknown>> => ({
    ...input.visit,
    actionDefinitionIdentityHex: deterministicIdentity(
        input.runIdentifier,
        'action-definition',
    ),
    actionProposalIdentityHex: deterministicIdentity(
        input.runIdentifier,
        'action-proposal',
    ),
    ballot: input.scenario.ballots[input.visit.participantPosition],
    candidateBuildIdentityHex: expectedCandidateBuildIdentityHex,
    databaseName: `sealed-lattice-p8-${input.scenario.identifier}-${String(input.visit.participantPosition)}`,
    kernelSha256Hex: expectedCandidateKernelSha256Hex,
    predecessorIdentityHex: deterministicIdentity(
        input.runIdentifier,
        'predecessor',
    ),
    relayPrefix: `/relay/${input.scenario.identifier}`,
    runIdentifier: input.runIdentifier,
    runtimeIdentityHex: deterministicIdentity(input.runIdentifier, 'runtime'),
    sourceDeclarations: input.scenario.ballots.map(
        (ballot) => ballot.declaration,
    ),
    topCount: input.scenario.topCount,
    visitToken: input.visitToken,
});

const validateCandidatePackage = async (
    candidatePackagePath: string,
    archiveBytes: Uint8Array,
): Promise<Readonly<Record<string, unknown>>> => {
    if (sha256Hex(archiveBytes) !== expectedCandidateArchiveSha256Hex) {
        throw new Error('The candidate archive identity changed.');
    }
    const identity = requireRecord(
        JSON.parse(
            await readFile(
                path.join(
                    candidatePackagePath,
                    'candidate',
                    'candidate-build-identity.json',
                ),
                'utf8',
            ),
        ) as unknown,
        'Candidate build identity',
    );
    if (
        requireString(identity, 'identityHex') !==
        expectedCandidateBuildIdentityHex
    ) {
        throw new Error('The candidate content identity changed.');
    }
    const bundle = requireRecord(
        JSON.parse(
            await readFile(
                path.join(
                    candidatePackagePath,
                    'candidate',
                    'candidate-bundle.json',
                ),
                'utf8',
            ),
        ) as unknown,
        'Candidate bundle',
    );
    const identityRules = requireRecord(
        bundle.identityRules,
        'Candidate identity rules',
    );
    const parameterIdentity = requireRecord(
        identityRules.parameterIdentity,
        'Candidate parameter identity',
    );
    if (
        requireString(parameterIdentity, 'identityHex') !==
        expectedParameterIdentityHex
    ) {
        throw new Error('The candidate parameter identity changed.');
    }
    const kernelBytes = Uint8Array.from(
        await readFile(
            path.join(
                candidatePackagePath,
                'dist',
                'sealed-lattice-kernel.wasm',
            ),
        ),
    );
    if (sha256Hex(kernelBytes) !== expectedCandidateKernelSha256Hex) {
        throw new Error('The candidate construction kernel changed.');
    }
    return {
        archiveByteLength: archiveBytes.byteLength,
        archiveSha256Hex: expectedCandidateArchiveSha256Hex,
        candidateBuildIdentityHex: expectedCandidateBuildIdentityHex,
        constructionKernelByteLength: kernelBytes.byteLength,
        constructionKernelSha256Hex: expectedCandidateKernelSha256Hex,
        parameterIdentityHex: expectedParameterIdentityHex,
        sourceCommit: expectedCandidateSourceCommit,
    };
};

const main = async (): Promise<void> => {
    const arguments_ = parseArguments(process.argv.slice(2));
    const repositoryCommitHash = readCleanRepositoryCommit();
    const chromeExecutablePath = resolveChromeExecutablePath();
    const archiveBytes = Uint8Array.from(
        await readFile(arguments_.candidateArchivePath),
    );
    const temporaryParent = path.resolve(tmpdir());
    const temporaryRootPath = await mkdtemp(
        path.join(temporaryParent, 'sealed-lattice-external-ceremony-'),
    );
    if (path.dirname(temporaryRootPath) !== temporaryParent) {
        throw new Error('The ceremony temporary root escaped its parent.');
    }
    const extractionRootPath = path.join(temporaryRootPath, 'candidate');
    const relayRootPath = path.join(temporaryRootPath, 'relay');
    const profilesRootPath = path.join(temporaryRootPath, 'profiles');
    await mkdir(extractionRootPath, { recursive: true });
    await mkdir(relayRootPath, { recursive: true });
    await mkdir(profilesRootPath, { recursive: true });
    execFileSync(
        'tar',
        ['-xf', arguments_.candidateArchivePath, '-C', extractionRootPath],
        { windowsHide: true },
    );
    const candidatePackagePath = path.join(extractionRootPath, 'package');
    const candidatePackageIdentity = await validateCandidatePackage(
        candidatePackagePath,
        archiveBytes,
    );
    const [pageHtml, pageScript, workerScript] = await Promise.all([
        readFile(pageHtmlPath),
        readFile(pageScriptPath),
        readFile(workerScriptPath),
    ]);
    const relayServer = await createRelayServer({
        candidatePackagePath,
        pageHtml,
        pageScript,
        relayRootPath,
        workerScript,
    });
    try {
        const runIdentifier = randomUUID();
        const missingPersistenceProfilePath = path.join(
            profilesRootPath,
            'missing-persistence',
        );
        await mkdir(missingPersistenceProfilePath, { recursive: true });
        const missingPersistenceVisitToken = 'missing-persistence-0';
        const missingPersistence = await launchVisit({
            chromeExecutablePath,
            configuration: {
                action: 'probe-missing-persistence',
                actionDefinitionIdentityHex: deterministicIdentity(
                    runIdentifier,
                    'missing-persistence-action-definition',
                ),
                actionProposalIdentityHex: deterministicIdentity(
                    runIdentifier,
                    'missing-persistence-action-proposal',
                ),
                candidateBuildIdentityHex: expectedCandidateBuildIdentityHex,
                databaseName: 'sealed-lattice-p8-missing-persistence',
                kernelSha256Hex: expectedCandidateKernelSha256Hex,
                participantPosition: 0,
                predecessorIdentityHex: deterministicIdentity(
                    runIdentifier,
                    'missing-persistence-predecessor',
                ),
                relayPrefix: '/relay/missing-persistence',
                runIdentifier,
                runtimeIdentityHex: deterministicIdentity(
                    runIdentifier,
                    'missing-persistence-runtime',
                ),
                sourceDeclarations: Array.from(
                    { length: participantCount },
                    () => 'abstain',
                ),
                topCount: 1,
                visitToken: missingPersistenceVisitToken,
            },
            origin: relayServer.origin,
            participantPosition: 0,
            permissionMode: 'deny',
            profilePath: missingPersistenceProfilePath,
            relayServer,
            sequence: 0,
            visitToken: missingPersistenceVisitToken,
        });
        const missingPersistenceRefusal = requireRecord(
            missingPersistence.pageResult.missingPersistenceRefusal,
            'Missing-persistence refusal',
        );
        if (
            requireString(missingPersistenceRefusal, 'name') !==
            'MissingPersistence'
        ) {
            throw new Error(
                'The participant preflight did not refuse missing persistence.',
            );
        }
        const browserIdentity = missingPersistence.browserIdentity;
        const scenarioEvidence = [];
        for (const scenario of externalCeremonyScenarioDefinitions()) {
            assertSchedule(scenario);
            const scenarioStartedAt = performance.now();
            const schedule = buildExternalCeremonyVisitSchedule(scenario);
            const profiles = await Promise.all(
                Array.from(
                    { length: participantCount },
                    async (_, position) => {
                        const profilePath = path.join(
                            profilesRootPath,
                            `${scenario.identifier}-${String(position)}`,
                        );
                        await mkdir(profilePath, { recursive: true });
                        return profilePath;
                    },
                ),
            );
            const visits: VisitEvidence[] = [];
            for (const [sequence, visit] of schedule.entries()) {
                const visitToken = `${scenario.identifier}-${String(sequence).padStart(3, '0')}-${String(visit.participantPosition)}-${visit.action}`;
                const configuration = baseVisitConfiguration({
                    runIdentifier,
                    scenario,
                    visit,
                    visitToken,
                });
                process.stdout.write(
                    `[${scenario.identifier}] visit ${String(sequence + 1)}/${String(schedule.length)} participant ${String(visit.participantPosition)} ${visit.action}${visit.crashBoundary === undefined ? '' : ` (${visit.crashBoundary})`}\n`,
                );
                const evidence = await launchVisit({
                    chromeExecutablePath,
                    configuration,
                    origin: relayServer.origin,
                    participantPosition: visit.participantPosition,
                    permissionMode: 'grant',
                    profilePath: profiles[visit.participantPosition] ?? '',
                    relayServer,
                    sequence,
                    visitToken,
                });
                visits.push(evidence);
            }
            const wallMilliseconds = performance.now() - scenarioStartedAt;
            const terminal = await validateScenarioTerminal(
                relayServer,
                scenario,
                visits,
            );
            const relayCorpusByteLength = relayServer
                .inventory()
                .filter((entry) =>
                    entry.objectName.startsWith(`${scenario.identifier}/`),
                )
                .reduce((sum, entry) => sum + entry.byteLength, 0);
            const summary = summarizeScenario(
                schedule,
                visits,
                relayCorpusByteLength,
                wallMilliseconds,
            );
            if (!requireBoolean(summary, 'pass')) {
                throw new Error(
                    `${scenario.identifier} failed its runtime bounds.`,
                );
            }
            scenarioEvidence.push({
                definition: scenario,
                profileDiskByteLengthBeforeRemoval: await Promise.all(
                    profiles.map(directoryByteLength),
                ),
                summary,
                terminal,
                visits,
            });
            for (const profilePath of profiles) {
                if (!withinDirectory(profilesRootPath, profilePath)) {
                    throw new Error('A participant profile escaped its root.');
                }
                await rm(profilePath, { force: true, recursive: true });
            }
        }
        const sourceFiles = await Promise.all(
            [
                driverSourcePath,
                runnerSourcePath,
                pageHtmlPath,
                pageScriptPath,
                workerScriptPath,
                registrySourcePath,
                rootPackageManifestPath,
            ].map(async (filePath) => ({
                bytes: Uint8Array.from(await readFile(filePath)),
                filePath,
            })),
        );
        const evidence = {
            browser: {
                executablePath: chromeExecutablePath,
                identityObservedDuringPreflight: browserIdentity,
            },
            candidatePackage: candidatePackageIdentity,
            classification:
                'external release-Chrome mobile-emulation development evidence',
            concurrency: {
                maximumActiveParticipantBrowsers: 1,
                participantsOnlineConcurrently: false,
            },
            environment: {
                cpuThrottlingRate,
                memorySampleIntervalMilliseconds,
                mobileProfile,
                persistentStoragePermission:
                    'CDP durableStorage permission granted to each isolated evidence profile and denied for the refusal preflight',
                wifiProfile,
            },
            exclusions: {
                battery:
                    'The desktop host exposes no meaningful phone battery-use measurement.',
                completeInventoryRollback:
                    'Coherent replay of a complete old browser root and its matching inventory remains the admitted A_STATE exclusion.',
                pristineErasure:
                    'Total erasure to pristine empty state remains indistinguishable from first initialization and is not claimed detected.',
                rootProvenance:
                    'Attacker-controlled synthesis, replacement, or transplantation of a usable nonexportable root remains the admitted A_STATE exclusion.',
            },
            missingPersistencePreflight: missingPersistence,
            pass: scenarioEvidence.every((scenario) =>
                requireBoolean(
                    requireRecord(scenario.summary, 'Scenario summary'),
                    'pass',
                ),
            ),
            relayInventory: relayServer.inventory(),
            repository: {
                commitHash: repositoryCommitHash,
                treeDirty: false,
            },
            runIdentifier,
            scenarios: scenarioEvidence,
            sourceIdentities: Object.fromEntries(
                sourceFiles.map(({ bytes, filePath }) => [
                    path.basename(filePath),
                    fileIdentity(filePath, bytes),
                ]),
            ),
        };
        await writeFile(
            arguments_.resultFilePath,
            `${JSON.stringify(evidence, null, 2)}\n`,
            { encoding: 'utf8', flag: 'wx' },
        );
        process.stdout.write(
            `${JSON.stringify({
                candidateBuildIdentityHex: expectedCandidateBuildIdentityHex,
                pass: evidence.pass,
                repositoryCommitHash,
                scenarios: scenarioEvidence.map((scenario) => ({
                    identifier: scenario.definition.identifier,
                    summary: scenario.summary,
                    terminal: scenario.terminal,
                })),
            })}\n`,
        );
    } finally {
        await relayServer.close();
        await rm(temporaryRootPath, { force: true, recursive: true });
    }
};

if (import.meta.main) await main();
