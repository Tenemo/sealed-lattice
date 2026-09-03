import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { chromium, type BrowserContext } from 'playwright';

import { compileFullTallyResourceModel } from '#tests/full-tally-resource-model.js';
import {
    compileFullTallySecurityLedger,
    type OperationKmacHistogramEntry,
} from '#tests/full-tally-security-ledger.js';
import { readProcessPrivateMemory } from '#tools/ci/process-tree-memory-guard.js';

const repositoryRootPath = path.resolve(import.meta.dirname, '..', '..');
const runnerSourcePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'run-external-chrome-resource-screen.ts',
);
const driverSourcePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-resource-screen-driver.ts',
);
const staticPagePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-resource-screen.html',
);
const staticScriptPath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-resource-screen.mjs',
);
const productionKernelPath = path.join(
    repositoryRootPath,
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const productionKmacSourcePath = path.join(
    repositoryRootPath,
    'crates',
    'sealed-lattice-kernel',
    'src',
    'protocol',
    'padded_continuation.rs',
);
const resourceScreenKernelSourcePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'external-chrome-resource-screen-kernel.rs',
);
const wasmBuildSourcePath = path.join(
    repositoryRootPath,
    'tools',
    'ci',
    'build-wasm-kernel.ts',
);
const rootPackageManifestPath = path.join(repositoryRootPath, 'package.json');
const packageLockPath = path.join(repositoryRootPath, 'pnpm-lock.yaml');
const sdkPackageManifestPath = path.join(
    repositoryRootPath,
    'packages',
    'sdk',
    'package.json',
);
const chunkPayloadByteLength = 480_000;
const foregroundLimitMilliseconds = 15 * 60 * 1_000;
const browserPrivateMemoryPlanningTargetByteLength = 671_088_640;
const processMemorySampleIntervalMilliseconds = 2_000;
const coldReclaimLimitMilliseconds = 120_000;
const coldReclaimPollIntervalMilliseconds = 2_000;
const resourceScreenDatabaseName =
    'sealed-lattice-external-chrome-resource-screen';
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

type DriverArguments = Readonly<{
    resultFilePath: string;
    wasmFilePath: string;
}>;

type ResourceScreenResult = Readonly<{
    storage: Readonly<{
        chunkCount: number;
        chunkPayloadByteLength: number;
        clearAndReclaimMilliseconds: number;
        corpusByteLength: number;
        databasePresentAfterDelete: boolean;
        deleteAndReclaimMilliseconds: number;
        expectedShake256Hex: string;
        fetchAndStoreMilliseconds: number;
        finalChunkByteLength: number;
        initialUsage: number;
        persistedBefore: boolean;
        quotaAfterWrite: number;
        quotaBefore: number;
        readAndDigestMilliseconds: number;
        shake256Hex: string;
        totalForegroundMilliseconds: number;
        usageAfterClear: number;
        usageDetailsAfterClear: Readonly<Record<string, number>>;
        usageAfterDelete: number;
        usageDetailsAfterDelete: Readonly<Record<string, number>>;
        usageAfterWrite: number;
        usageDetailsAfterWrite: Readonly<Record<string, number>>;
        usageBefore: number;
        usageDetailsBefore: Readonly<Record<string, number>>;
    }>;
    work: Readonly<{
        checksum: number;
        histogram: readonly Readonly<
            OperationKmacHistogramEntry & {
                checksum: number;
                elapsedMilliseconds: number;
            }
        >[];
        inputByteLength: number;
        invocationCount: number;
        outputByteLength: number;
        totalForegroundMilliseconds: number;
        wasmMemoryByteLength: number;
    }>;
}>;

type ChromeProcessIdentity = Readonly<{
    processIdentifier: number;
    type: string;
}>;

type ChromePrivateMemorySample = Readonly<{
    capturedAtMilliseconds: number;
    privateByteLength: number;
    residentByteLength: number;
    processCount: number;
    privateByteLengthByType: Readonly<Record<string, number>>;
}>;

type ChromePrivateMemoryEvidence = Readonly<{
    idlePrivateByteLength: number;
    peakPrivateByteLength: number;
    peakPrivateMemoryIncreaseByteLength: number;
    planningTargetByteLength: number;
    sampleIntervalMilliseconds: number;
    samples: readonly ChromePrivateMemorySample[];
    source: string;
}>;

type ColdReclaimEvidence = Readonly<{
    databasePresent: boolean;
    elapsedMilliseconds: number;
    quota: number;
    sampleCount: number;
    usage: number;
    usageDetails: Readonly<Record<string, number>>;
}>;

type FileIdentity = Readonly<{
    byteLength: number;
    repositoryRelativePath: string;
    sha256: string;
}>;

const sha256Hex = (bytes: Uint8Array): string =>
    createHash('sha256').update(bytes).digest('hex');

const fileIdentity = (filePath: string, bytes: Uint8Array): FileIdentity => ({
    byteLength: bytes.byteLength,
    repositoryRelativePath: path
        .relative(repositoryRootPath, filePath)
        .split(path.sep)
        .join('/'),
    sha256: sha256Hex(bytes),
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
            'The external-Chrome resource screen requires a clean committed worktree.',
        );
    }
    return commitHash;
};

const parseArguments = (arguments_: readonly string[]): DriverArguments => {
    if (
        arguments_.length !== 4 ||
        arguments_[0] !== '--wasm' ||
        arguments_[1] === undefined ||
        arguments_[2] !== '--result' ||
        arguments_[3] === undefined
    ) {
        throw new Error(
            'Usage: external-chrome-resource-screen-driver.ts --wasm <path> --result <path>.',
        );
    }
    return {
        resultFilePath: path.resolve(arguments_[3]),
        wasmFilePath: path.resolve(arguments_[1]),
    };
};

const resolveChromeExecutablePath = (): string => {
    const configuredPath = process.env.SEALED_LATTICE_EXTERNAL_CHROME_PATH;
    const candidatePaths = [
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
    const resolvedPath = candidatePaths.find((candidate) =>
        existsSync(candidate),
    );
    if (resolvedPath === undefined) {
        throw new Error(
            'External release Chrome was not found. Set SEALED_LATTICE_EXTERNAL_CHROME_PATH.',
        );
    }
    return path.resolve(resolvedPath);
};

const syntheticChunkDomain = Buffer.from(
    'sealed-lattice/external-chrome-resource-screen/chunk/v1',
    'utf8',
);

const generateSyntheticChunk = (
    ordinal: number,
    byteLength: number,
): Buffer => {
    const encodedOrdinal = Buffer.allocUnsafe(8);
    encodedOrdinal.writeBigUInt64LE(BigInt(ordinal));
    return createHash('shake256', { outputLength: byteLength })
        .update(syntheticChunkDomain)
        .update(encodedOrdinal)
        .digest();
};

const expectedShake256Hex = (
    chunkCount: number,
    finalChunkByteLength: number,
): string => {
    const hasher = createHash('shake256', { outputLength: 64 });
    for (let ordinal = 0; ordinal < chunkCount; ordinal += 1) {
        const byteLength =
            ordinal + 1 === chunkCount
                ? finalChunkByteLength
                : chunkPayloadByteLength;
        hasher.update(generateSyntheticChunk(ordinal, byteLength));
    }
    return hasher.digest('hex');
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
                reject(new Error('The resource server omitted its TCP port.'));
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

const requireRecord = (
    value: unknown,
    name: string,
): Readonly<Record<string, unknown>> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${name} is not an object.`);
    }
    return value as Readonly<Record<string, unknown>>;
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

const requireArray = (value: unknown, name: string): readonly unknown[] => {
    if (!Array.isArray(value)) {
        throw new Error(`${name} is not an array.`);
    }
    return value;
};

const parseNonnegativeNumberRecord = (
    value: unknown,
    name: string,
): Readonly<Record<string, number>> =>
    Object.fromEntries(
        Object.entries(requireRecord(value, name)).map(([key, entry]) => {
            if (
                typeof entry !== 'number' ||
                !Number.isFinite(entry) ||
                entry < 0
            ) {
                throw new Error(`${name}.${key} is not a nonnegative number.`);
            }
            return [key, entry];
        }),
    );

const parseKmacHistogramEntry = (
    value: unknown,
): OperationKmacHistogramEntry & {
    checksum: number;
    elapsedMilliseconds: number;
} => {
    const entry = requireRecord(value, 'KMAC histogram entry');
    const phase = requireString(entry, 'phase');
    const family = requireString(entry, 'family');
    const keyClass = requireString(entry, 'keyClass');
    if (phase !== 'selected-evaluation') {
        throw new Error('The KMAC resource histogram has the wrong phase.');
    }
    if (
        family !== 'local-row' &&
        family !== 'joint-row' &&
        family !== 'continuation-row'
    ) {
        throw new Error('The KMAC resource histogram has an unknown family.');
    }
    if (
        keyClass !== 'independent-label' &&
        keyClass !== 'conditionally-derived-continuation'
    ) {
        throw new Error(
            'The KMAC resource histogram has an unknown key class.',
        );
    }
    return {
        phase,
        family,
        keyClass,
        keyByteLength: requireNumber(entry, 'keyByteLength'),
        messageByteLength: requireNumber(entry, 'messageByteLength'),
        outputByteLength: requireNumber(entry, 'outputByteLength'),
        invocationCount: requireNumber(entry, 'invocationCount'),
        checksum: requireNumber(entry, 'checksum'),
        elapsedMilliseconds: requireNumber(entry, 'elapsedMilliseconds'),
    };
};

const parseResourceScreenResult = (value: unknown): ResourceScreenResult => {
    const result = requireRecord(value, 'resource result');
    const rawStorage = requireRecord(result.storage, 'storage result');
    const rawWork = requireRecord(result.work, 'work result');
    return {
        storage: {
            chunkCount: requireNumber(rawStorage, 'chunkCount'),
            chunkPayloadByteLength: requireNumber(
                rawStorage,
                'chunkPayloadByteLength',
            ),
            clearAndReclaimMilliseconds: requireNumber(
                rawStorage,
                'clearAndReclaimMilliseconds',
            ),
            corpusByteLength: requireNumber(rawStorage, 'corpusByteLength'),
            databasePresentAfterDelete: requireBoolean(
                rawStorage,
                'databasePresentAfterDelete',
            ),
            deleteAndReclaimMilliseconds: requireNumber(
                rawStorage,
                'deleteAndReclaimMilliseconds',
            ),
            expectedShake256Hex: requireString(
                rawStorage,
                'expectedShake256Hex',
            ),
            fetchAndStoreMilliseconds: requireNumber(
                rawStorage,
                'fetchAndStoreMilliseconds',
            ),
            finalChunkByteLength: requireNumber(
                rawStorage,
                'finalChunkByteLength',
            ),
            initialUsage: requireNumber(rawStorage, 'initialUsage'),
            persistedBefore: requireBoolean(rawStorage, 'persistedBefore'),
            quotaAfterWrite: requireNumber(rawStorage, 'quotaAfterWrite'),
            quotaBefore: requireNumber(rawStorage, 'quotaBefore'),
            readAndDigestMilliseconds: requireNumber(
                rawStorage,
                'readAndDigestMilliseconds',
            ),
            usageDetailsAfterClear: parseNonnegativeNumberRecord(
                rawStorage.usageDetailsAfterClear,
                'usageDetailsAfterClear',
            ),
            usageDetailsAfterDelete: parseNonnegativeNumberRecord(
                rawStorage.usageDetailsAfterDelete,
                'usageDetailsAfterDelete',
            ),
            usageDetailsAfterWrite: parseNonnegativeNumberRecord(
                rawStorage.usageDetailsAfterWrite,
                'usageDetailsAfterWrite',
            ),
            usageDetailsBefore: parseNonnegativeNumberRecord(
                rawStorage.usageDetailsBefore,
                'usageDetailsBefore',
            ),
            shake256Hex: requireString(rawStorage, 'shake256Hex'),
            totalForegroundMilliseconds: requireNumber(
                rawStorage,
                'totalForegroundMilliseconds',
            ),
            usageAfterClear: requireNumber(rawStorage, 'usageAfterClear'),
            usageAfterDelete: requireNumber(rawStorage, 'usageAfterDelete'),
            usageAfterWrite: requireNumber(rawStorage, 'usageAfterWrite'),
            usageBefore: requireNumber(rawStorage, 'usageBefore'),
        },
        work: {
            checksum: requireNumber(rawWork, 'checksum'),
            histogram: requireArray(rawWork.histogram, 'KMAC histogram').map(
                parseKmacHistogramEntry,
            ),
            inputByteLength: requireNumber(rawWork, 'inputByteLength'),
            invocationCount: requireNumber(rawWork, 'invocationCount'),
            outputByteLength: requireNumber(rawWork, 'outputByteLength'),
            totalForegroundMilliseconds: requireNumber(
                rawWork,
                'totalForegroundMilliseconds',
            ),
            wasmMemoryByteLength: requireNumber(
                rawWork,
                'wasmMemoryByteLength',
            ),
        },
    };
};

const readChromeProcessIdentities = async (
    browserSession: Awaited<
        ReturnType<
            Awaited<ReturnType<typeof chromium.launch>>['newBrowserCDPSession']
        >
    >,
): Promise<ChromeProcessIdentity[]> => {
    const raw: unknown = await browserSession.send('SystemInfo.getProcessInfo');
    const result = requireRecord(raw, 'Chrome process information');
    return requireArray(result.processInfo, 'Chrome process information list')
        .map((value) => {
            const entry = requireRecord(
                value,
                'Chrome process information entry',
            );
            return {
                processIdentifier: requireNumber(entry, 'id'),
                type: requireString(entry, 'type'),
            };
        })
        .filter(({ processIdentifier }) => processIdentifier > 0);
};

const startChromePrivateMemorySampler = async (
    browserSession: Awaited<
        ReturnType<
            Awaited<ReturnType<typeof chromium.launch>>['newBrowserCDPSession']
        >
    >,
): Promise<
    Readonly<{ finish: () => Promise<ChromePrivateMemoryEvidence> }>
> => {
    const samples: ChromePrivateMemorySample[] = [];
    let active = true;
    let sampling: Promise<void> | undefined;
    const sample = async (): Promise<void> => {
        if (!active || sampling !== undefined) return;
        sampling = (async () => {
            const identities =
                await readChromeProcessIdentities(browserSession);
            const rows = await readProcessPrivateMemory(
                identities.map(({ processIdentifier }) => processIdentifier),
            );
            const typeByIdentifier = new Map(
                identities.map(({ processIdentifier, type }) => [
                    processIdentifier,
                    type,
                ]),
            );
            const privateByteLengthByType: Record<string, number> = {};
            let privateByteLength = 0;
            let residentByteLength = 0;
            for (const row of rows) {
                privateByteLength += row.privateByteLength;
                residentByteLength += row.residentByteLength;
                const type =
                    typeByIdentifier.get(row.processIdentifier) ?? 'unknown';
                privateByteLengthByType[type] =
                    (privateByteLengthByType[type] ?? 0) +
                    row.privateByteLength;
            }
            samples.push({
                capturedAtMilliseconds: performance.now(),
                privateByteLength,
                residentByteLength,
                processCount: rows.length,
                privateByteLengthByType,
            });
        })().finally(() => {
            sampling = undefined;
        });
        await sampling;
    };
    await sample();
    const idlePrivateByteLength = samples[0]?.privateByteLength;
    if (idlePrivateByteLength === undefined || idlePrivateByteLength === 0) {
        throw new Error('Chrome private-memory baseline is unavailable.');
    }
    const timer = setInterval(
        () => void sample(),
        processMemorySampleIntervalMilliseconds,
    );
    return {
        finish: async () => {
            if (sampling !== undefined) await sampling;
            await sample();
            active = false;
            clearInterval(timer);
            const peakPrivateByteLength = samples.reduce(
                (peak, entry) => Math.max(peak, entry.privateByteLength),
                idlePrivateByteLength,
            );
            return {
                idlePrivateByteLength,
                peakPrivateByteLength,
                peakPrivateMemoryIncreaseByteLength: Math.max(
                    0,
                    peakPrivateByteLength - idlePrivateByteLength,
                ),
                planningTargetByteLength:
                    browserPrivateMemoryPlanningTargetByteLength,
                sampleIntervalMilliseconds:
                    processMemorySampleIntervalMilliseconds,
                samples,
                source: 'OS private-memory counters for the process identifiers returned by Chrome SystemInfo.getProcessInfo',
            };
        },
    };
};

const verifyColdPageReclamation = async (
    context: BrowserContext,
    origin: string,
    baselineUsage: number,
): Promise<ColdReclaimEvidence> => {
    const page = context.pages()[0] ?? (await context.newPage());
    page.setDefaultNavigationTimeout(120_000);
    const startedAt = performance.now();
    let sampleCount = 0;
    let lastObservation: Readonly<{
        databasePresent: boolean;
        quota: number;
        usage: number;
        usageDetails: Readonly<Record<string, number>>;
    }> = {
        databasePresent: true,
        quota: 0,
        usage: Number.POSITIVE_INFINITY,
        usageDetails: {},
    };
    try {
        await page.goto(origin, { waitUntil: 'load' });
        while (performance.now() - startedAt < coldReclaimLimitMilliseconds) {
            lastObservation = await page.evaluate(async (databaseName) => {
                const [estimate, databases] = await Promise.all([
                    navigator.storage.estimate(),
                    indexedDB.databases(),
                ]);
                const usageDetails = (
                    estimate as StorageEstimate & {
                        usageDetails?: Readonly<Record<string, unknown>>;
                    }
                ).usageDetails;
                return {
                    databasePresent: databases.some(
                        (entry) => entry.name === databaseName,
                    ),
                    quota: estimate.quota ?? 0,
                    usage: estimate.usage ?? 0,
                    usageDetails: Object.fromEntries(
                        Object.entries(usageDetails ?? {}).filter(
                            (entry): entry is [string, number] =>
                                typeof entry[1] === 'number',
                        ),
                    ),
                };
            }, resourceScreenDatabaseName);
            sampleCount += 1;
            if (
                !lastObservation.databasePresent &&
                lastObservation.usage <= baselineUsage
            ) {
                break;
            }
            if (sampleCount % 5 === 0) {
                await page.reload({ waitUntil: 'load' });
            }
            await new Promise((resolve) =>
                setTimeout(resolve, coldReclaimPollIntervalMilliseconds),
            );
        }
        return {
            ...lastObservation,
            elapsedMilliseconds: performance.now() - startedAt,
            sampleCount,
        };
    } finally {
        await page.close();
    }
};

const main = async (): Promise<void> => {
    const { resultFilePath, wasmFilePath } = parseArguments(
        process.argv.slice(2),
    );
    const repositoryCommitHash = readCleanRepositoryCommit();
    const chromeExecutablePath = resolveChromeExecutablePath();
    const [
        html,
        script,
        wasm,
        productionKernel,
        sdkPackageManifestBytes,
        runnerSource,
        driverSource,
        productionKmacSource,
        resourceScreenKernelSource,
        wasmBuildSource,
        rootPackageManifest,
        packageLock,
    ] = await Promise.all([
        readFile(staticPagePath),
        readFile(staticScriptPath),
        readFile(wasmFilePath),
        readFile(productionKernelPath),
        readFile(sdkPackageManifestPath),
        readFile(runnerSourcePath),
        readFile(driverSourcePath),
        readFile(productionKmacSourcePath),
        readFile(resourceScreenKernelSourcePath),
        readFile(wasmBuildSourcePath),
        readFile(rootPackageManifestPath),
        readFile(packageLockPath),
    ]);
    const sdkPackageManifest = requireRecord(
        JSON.parse(sdkPackageManifestBytes.toString('utf8')) as unknown,
        'SDK package manifest',
    );
    const resourceModel = compileFullTallyResourceModel(10, 10);
    const securityLedger = compileFullTallySecurityLedger(10);
    const selectedEvaluationKmacHistogram =
        securityLedger.honestWork.operationKmacHistogram.filter(
            (entry) => entry.phase === 'selected-evaluation',
        );
    const corpusByteLength = resourceModel.cleanVerifiedDownloadByteLength;
    const chunkCount = Math.ceil(corpusByteLength / chunkPayloadByteLength);
    const finalChunkByteLength =
        corpusByteLength - (chunkCount - 1) * chunkPayloadByteLength;
    const expectedDigest = expectedShake256Hex(
        chunkCount,
        finalChunkByteLength,
    );
    const pageConfiguration = {
        chunkCount,
        chunkPayloadByteLength,
        corpusByteLength,
        expectedShake256Hex: expectedDigest,
        finalChunkByteLength,
        kmacHistogram: selectedEvaluationKmacHistogram,
    };
    const completeConfiguration = {
        browserPrivateMemoryPlanningTargetByteLength,
        coldReclaimLimitMilliseconds,
        coldReclaimPollIntervalMilliseconds,
        cpuThrottlingRate,
        foregroundLimitMilliseconds,
        mobileProfile,
        pageConfiguration,
        processMemorySampleIntervalMilliseconds,
        submittedParticipantCount: 10,
        topCount: 10,
        wifiProfile,
    };
    const completeConfigurationBytes = Buffer.from(
        JSON.stringify(completeConfiguration),
        'utf8',
    );
    const server = createServer((request, response) => {
        if (request.method !== 'GET' || request.url === undefined) {
            writeResponse(
                response,
                405,
                'text/plain; charset=utf-8',
                Buffer.from('Method not allowed.'),
            );
            return;
        }
        const url = new URL(request.url, 'http://127.0.0.1');
        if (url.pathname === '/') {
            writeResponse(response, 200, 'text/html; charset=utf-8', html);
            return;
        }
        if (url.pathname === '/external-chrome-resource-screen.mjs') {
            writeResponse(
                response,
                200,
                'text/javascript; charset=utf-8',
                script,
            );
            return;
        }
        if (url.pathname === '/resource-screen-kernel.wasm') {
            writeResponse(response, 200, 'application/wasm', wasm);
            return;
        }
        const chunkMatch = /^\/synthetic-chunk\/(\d+)$/u.exec(url.pathname);
        const chunkOrdinal = Number(chunkMatch?.[1]);
        if (
            chunkMatch !== null &&
            Number.isSafeInteger(chunkOrdinal) &&
            chunkOrdinal >= 0 &&
            chunkOrdinal < chunkCount
        ) {
            const byteLength =
                chunkOrdinal + 1 === chunkCount
                    ? finalChunkByteLength
                    : chunkPayloadByteLength;
            writeResponse(
                response,
                200,
                'application/octet-stream',
                generateSyntheticChunk(chunkOrdinal, byteLength),
            );
            return;
        }
        writeResponse(
            response,
            404,
            'text/plain; charset=utf-8',
            Buffer.from('Not found.'),
        );
    });
    const port = await listen(server);
    const temporaryDirectoryPath = path.resolve(tmpdir());
    const browserProfilePath = await mkdtemp(
        path.join(
            temporaryDirectoryPath,
            'sealed-lattice-external-chrome-resource-screen-',
        ),
    );
    if (
        path.dirname(path.resolve(browserProfilePath)) !==
        temporaryDirectoryPath
    ) {
        throw new Error(
            'The temporary Chrome profile path escaped its parent.',
        );
    }
    const launchPersistentContext = (): Promise<BrowserContext> =>
        chromium.launchPersistentContext(browserProfilePath, {
            deviceScaleFactor: mobileProfile.deviceScaleFactor,
            executablePath: chromeExecutablePath,
            hasTouch: mobileProfile.hasTouch,
            headless: true,
            isMobile: mobileProfile.isMobile,
            serviceWorkers: 'block',
            viewport: {
                height: mobileProfile.height,
                width: mobileProfile.width,
            },
        });
    let context: BrowserContext | undefined;
    try {
        context = await launchPersistentContext();
        const browser = context.browser();
        if (browser === null) {
            throw new Error('The persistent Chrome context has no browser.');
        }
        const browserVersion = browser.version();
        const userAgent = `Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion} Mobile Safari/537.36`;
        const page = context.pages()[0] ?? (await context.newPage());
        page.setDefaultNavigationTimeout(120_000);
        const session = await context.newCDPSession(page);
        await session.send('Network.enable');
        await session.send('Network.setCacheDisabled', {
            cacheDisabled: true,
        });
        await session.send('Network.setUserAgentOverride', { userAgent });
        await session.send('Network.emulateNetworkConditions', {
            connectionType: wifiProfile.connectionType,
            downloadThroughput: wifiProfile.downloadThroughputBytesPerSecond,
            latency: wifiProfile.latencyMilliseconds,
            offline: false,
            uploadThroughput: wifiProfile.uploadThroughputBytesPerSecond,
        });
        await session.send('Emulation.setCPUThrottlingRate', {
            rate: cpuThrottlingRate,
        });
        await session.send('Emulation.setTouchEmulationEnabled', {
            enabled: true,
            maxTouchPoints: mobileProfile.maxTouchPoints,
        });
        const browserSession = await browser.newBrowserCDPSession();
        const browserIdentity = await browserSession.send('Browser.getVersion');
        const origin = `http://127.0.0.1:${String(port)}/`;
        await page.goto(origin, { waitUntil: 'load' });
        const emulationObservation = await page.evaluate(() => ({
            coarsePointer: matchMedia('(pointer: coarse)').matches,
            devicePixelRatio,
            innerHeight,
            innerWidth,
            maxTouchPoints: navigator.maxTouchPoints,
            userAgent: navigator.userAgent,
        }));
        const privateMemorySampler =
            await startChromePrivateMemorySampler(browserSession);
        let result: ResourceScreenResult;
        let heapUsage: unknown;
        try {
            const rawResult = await page.evaluate(async (configuration) => {
                const run = (
                    globalThis as typeof globalThis & {
                        runExternalChromeResourceScreen?: (
                            input: unknown,
                        ) => Promise<unknown>;
                    }
                ).runExternalChromeResourceScreen;
                if (run === undefined) {
                    throw new Error(
                        'The static resource screen did not initialize.',
                    );
                }
                return run(configuration);
            }, pageConfiguration);
            result = parseResourceScreenResult(rawResult);
            heapUsage = await session.send('Runtime.getHeapUsage');
        } catch (error) {
            await privateMemorySampler.finish();
            throw error;
        }
        const browserPrivateMemory = await privateMemorySampler.finish();
        await context.close();
        context = undefined;
        const coldRestart = await (async () => {
            const restartedContext = await launchPersistentContext();
            try {
                const restartedBrowser = restartedContext.browser();
                if (restartedBrowser === null) {
                    throw new Error(
                        'The restarted persistent Chrome context has no browser.',
                    );
                }
                const restartedBrowserSession =
                    await restartedBrowser.newBrowserCDPSession();
                return {
                    browserIdentity:
                        await restartedBrowserSession.send(
                            'Browser.getVersion',
                        ),
                    reclaim: await verifyColdPageReclamation(
                        restartedContext,
                        origin,
                        result.storage.usageBefore,
                    ),
                };
            } finally {
                await restartedContext.close();
            }
        })();
        const coldReclaim = coldRestart.reclaim;
        const pass =
            result.storage.chunkCount === chunkCount &&
            result.storage.chunkPayloadByteLength === chunkPayloadByteLength &&
            result.storage.corpusByteLength === corpusByteLength &&
            result.storage.finalChunkByteLength === finalChunkByteLength &&
            result.storage.expectedShake256Hex === expectedDigest &&
            result.storage.shake256Hex === expectedDigest &&
            !result.storage.databasePresentAfterDelete &&
            result.storage.usageAfterWrite <= result.storage.quotaAfterWrite &&
            result.storage.usageAfterWrite - result.storage.usageBefore >=
                corpusByteLength &&
            !coldReclaim.databasePresent &&
            coldReclaim.usage <= result.storage.usageBefore &&
            result.storage.totalForegroundMilliseconds <=
                foregroundLimitMilliseconds &&
            result.work.invocationCount ===
                securityLedger.operation
                    .selectedEvaluationKmacInvocationCountPerCompleteInventory &&
            result.work.inputByteLength ===
                securityLedger.honestWork
                    .selectedEvaluationKmacInputByteLengthPerCompleteInventory &&
            result.work.outputByteLength ===
                securityLedger.honestWork
                    .selectedEvaluationKmacOutputByteLengthPerCompleteInventory &&
            result.work.histogram.length ===
                selectedEvaluationKmacHistogram.length &&
            result.work.histogram.every((entry, index) => {
                const expected = selectedEvaluationKmacHistogram[index];
                return (
                    expected !== undefined &&
                    entry.phase === expected.phase &&
                    entry.family === expected.family &&
                    entry.keyClass === expected.keyClass &&
                    entry.keyByteLength === expected.keyByteLength &&
                    entry.messageByteLength === expected.messageByteLength &&
                    entry.outputByteLength === expected.outputByteLength &&
                    entry.invocationCount === expected.invocationCount
                );
            }) &&
            result.work.totalForegroundMilliseconds <=
                foregroundLimitMilliseconds &&
            emulationObservation.coarsePointer &&
            emulationObservation.maxTouchPoints ===
                mobileProfile.maxTouchPoints &&
            emulationObservation.innerWidth === mobileProfile.width &&
            emulationObservation.innerHeight === mobileProfile.height;
        const browserPrivateMemoryDisposition =
            browserPrivateMemory.peakPrivateMemoryIncreaseByteLength <=
            browserPrivateMemoryPlanningTargetByteLength
                ? 'within planning target'
                : browserPrivateMemory.peakPrivateMemoryIncreaseByteLength <=
                    browserPrivateMemoryPlanningTargetByteLength * 1.5
                  ? 'measured planning variance requiring later closure'
                  : 'architecture review required';
        const evidence = {
            browser: {
                executablePath: chromeExecutablePath,
                identity: browserIdentity,
                version: browserVersion,
            },
            browserPrivateMemory,
            browserPrivateMemoryDisposition,
            classification:
                'external-Chrome mobile-emulation development evidence',
            coldReclaim,
            coldRestartBrowserIdentity: coldRestart.browserIdentity,
            configuration: completeConfiguration,
            configurationIdentity: {
                byteLength: completeConfigurationBytes.byteLength,
                sha256: sha256Hex(completeConfigurationBytes),
            },
            emulation: {
                cpuThrottlingRate,
                mobileProfile,
                observation: emulationObservation,
                userAgent,
                wifiProfile,
            },
            foregroundLimitMilliseconds,
            heapUsage,
            packageIdentity: {
                name: requireString(sdkPackageManifest, 'name'),
                packageLock: fileIdentity(packageLockPath, packageLock),
                productionKernel: fileIdentity(
                    productionKernelPath,
                    productionKernel,
                ),
                rootPackageManifest: fileIdentity(
                    rootPackageManifestPath,
                    rootPackageManifest,
                ),
                sdkPackageManifest: fileIdentity(
                    sdkPackageManifestPath,
                    sdkPackageManifestBytes,
                ),
                version: requireString(sdkPackageManifest, 'version'),
            },
            pass,
            repository: {
                commitHash: repositoryCommitHash,
                treeDirty: false,
            },
            result,
            sourceIdentities: {
                buildWasmKernel: fileIdentity(
                    wasmBuildSourcePath,
                    wasmBuildSource,
                ),
                driver: fileIdentity(driverSourcePath, driverSource),
                pageHtml: fileIdentity(staticPagePath, html),
                pageScript: fileIdentity(staticScriptPath, script),
                productionKmac: fileIdentity(
                    productionKmacSourcePath,
                    productionKmacSource,
                ),
                resourceScreenKernel: fileIdentity(
                    resourceScreenKernelSourcePath,
                    resourceScreenKernelSource,
                ),
                runner: fileIdentity(runnerSourcePath, runnerSource),
            },
            wasm: {
                ...fileIdentity(wasmFilePath, wasm),
            },
        };
        await writeFile(
            resultFilePath,
            `${JSON.stringify(evidence, null, 2)}\n`,
            { encoding: 'utf8', flag: 'wx' },
        );
        process.stdout.write(
            `${JSON.stringify({
                browserVersion,
                browserPrivateMemory: {
                    disposition: browserPrivateMemoryDisposition,
                    idlePrivateByteLength:
                        browserPrivateMemory.idlePrivateByteLength,
                    peakPrivateByteLength:
                        browserPrivateMemory.peakPrivateByteLength,
                    peakPrivateMemoryIncreaseByteLength:
                        browserPrivateMemory.peakPrivateMemoryIncreaseByteLength,
                    planningTargetByteLength:
                        browserPrivateMemory.planningTargetByteLength,
                },
                coldReclaim,
                packageIdentity: evidence.packageIdentity,
                pass,
                storage: {
                    corpusByteLength: result.storage.corpusByteLength,
                    totalForegroundMilliseconds:
                        result.storage.totalForegroundMilliseconds,
                },
                work: {
                    histogram: result.work.histogram,
                    totalForegroundMilliseconds:
                        result.work.totalForegroundMilliseconds,
                },
            })}\n`,
        );
        if (!pass) {
            throw new Error(
                'The external-Chrome resource screen failed a proxy criterion.',
            );
        }
    } finally {
        if (context !== undefined) await context.close();
        await rm(browserProfilePath, { force: true, recursive: true });
        await closeServer(server);
    }
};

if (import.meta.main) await main();
