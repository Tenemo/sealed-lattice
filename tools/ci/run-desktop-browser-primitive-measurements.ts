import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium, firefox, type BrowserType } from 'playwright';
import { createServer, type Plugin, type ViteDevServer } from 'vite';

import {
    buildPrimitiveMeasurementWasm,
    primitiveMeasurementWasmOutputFilePath,
} from './build-primitive-measurement-wasm.js';
import { assertDeterministicWasmStackLayout } from './build-wasm-kernel.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    selectedAuthenticatedScratchRecordByteLength,
    validateDesktopBrowserAuthenticatedStorageMeasurement,
    validateDesktopBrowserBoundaryCopyMeasurement,
    validateDesktopBrowserFocusedPrimitiveMeasurementEvidence,
    validateDesktopBrowserPrimitiveMeasurementEvidence,
    vssFusedRadix51ProjectionOwnerCaseIdentifiers,
    type DesktopBrowserAuthenticatedStorageMeasurement,
    type DesktopBrowserBoundaryCopyMeasurement,
    type DesktopBrowserFocusedPrimitiveMeasurementEvidence,
    type DesktopBrowserPrimitiveMeasurementEvidence,
} from './primitive-measurement-evidence.js';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';

const repositoryRootPath = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const browserMeasurementPagePath = '/primitive-measurements/';
const browserMeasurementModulePath =
    '/tools/ci/desktop-browser-primitive-measurement-page.ts';
const browserMeasurementWasmPath =
    '/temp/primitive-measurements/sealed-lattice-kernel-primitive-measurement.wasm';
const browserServerBasePort = 41_130;

type SupportedBrowserEngine = 'chromium' | 'firefox';
type SupportedMeasurementComponent =
    | 'authenticated-storage'
    | 'boundary-copies';

export type DesktopBrowserPrimitiveMeasurementArguments = Readonly<{
    browserEngines: readonly SupportedBrowserEngine[];
    focusedCaseIdentifiers?: readonly number[];
    measurementComponent?: SupportedMeasurementComponent;
    reuseMeasurementWasm?: boolean;
}>;

export const parseDesktopBrowserPrimitiveMeasurementArguments = (
    rawArguments: readonly string[],
): DesktopBrowserPrimitiveMeasurementArguments => {
    const argumentsWithoutSeparator = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (argumentsWithoutSeparator.length === 0) {
        return Object.freeze({
            browserEngines: Object.freeze(['chromium', 'firefox'] as const),
        });
    }
    const browserEngineArgument = argumentsWithoutSeparator[0];
    if (
        browserEngineArgument !== 'chromium' &&
        browserEngineArgument !== 'firefox'
    ) {
        throw new Error(
            'The desktop-browser primitive-measurement runner accepts chromium or firefox.',
        );
    }
    const browserEngine: SupportedBrowserEngine =
        browserEngineArgument === 'chromium' ? 'chromium' : 'firefox';
    const focusedCaseMatch = /^case-(1|2|3|4|5|8|9|10|11|12)$/u.exec(
        argumentsWithoutSeparator[1] ?? '',
    );
    const focusedCaseIdentifiers =
        focusedCaseMatch === null
            ? argumentsWithoutSeparator[1] ===
              'fused-radix-51-projection-owners'
                ? vssFusedRadix51ProjectionOwnerCaseIdentifiers
                : undefined
            : Object.freeze([Number(focusedCaseMatch[1])]);
    if (focusedCaseIdentifiers !== undefined) {
        if (
            argumentsWithoutSeparator.length > 3 ||
            (argumentsWithoutSeparator.length === 3 &&
                argumentsWithoutSeparator[2] !== 'reuse-wasm')
        ) {
            throw new Error(
                'A focused primitive case accepts only an optional reuse-wasm argument.',
            );
        }
        return Object.freeze({
            browserEngines: Object.freeze([browserEngine]),
            focusedCaseIdentifiers,
            ...(argumentsWithoutSeparator[2] === 'reuse-wasm'
                ? { reuseMeasurementWasm: true }
                : {}),
        });
    }
    if (
        argumentsWithoutSeparator.length > 2 ||
        (argumentsWithoutSeparator.length === 2 &&
            argumentsWithoutSeparator[1] !== 'authenticated-storage' &&
            argumentsWithoutSeparator[1] !== 'boundary-copies' &&
            argumentsWithoutSeparator[1] !== 'reuse-wasm')
    ) {
        throw new Error(
            'The desktop-browser primitive-measurement runner accepts chromium or firefox with an optional authenticated-storage, boundary-copies, case-1 through case-5, case-8 through case-12, fused-radix-51-projection-owners, or reuse-wasm selector.',
        );
    }
    return Object.freeze({
        browserEngines: Object.freeze([browserEngine]),
        ...(argumentsWithoutSeparator[1] === undefined
            ? {}
            : argumentsWithoutSeparator[1] === 'reuse-wasm'
              ? { reuseMeasurementWasm: true }
              : {
                    measurementComponent:
                        argumentsWithoutSeparator[1] as SupportedMeasurementComponent,
                }),
    });
};

const measurementPagePlugin = (): Plugin => ({
    name: 'sealed-lattice-primitive-measurement-page',
    configureServer(server): void {
        server.middlewares.use((request, response, next) => {
            const requestUrl = request.url;
            if (
                requestUrl === undefined ||
                new URL(requestUrl, 'http://127.0.0.1').pathname !==
                    browserMeasurementPagePath
            ) {
                next();
                return;
            }
            response.statusCode = 200;
            response.setHeader('Content-Type', 'text/html; charset=utf-8');
            response.setHeader('Cache-Control', 'no-store');
            response.end(
                '<!doctype html><html><head><meta charset="utf-8"><title>Primitive measurements</title></head><body></body></html>',
            );
        });
    },
});

const startBrowserServer = async (): Promise<{
    readonly baseUrl: string;
    readonly server: ViteDevServer;
}> => {
    const server = await createServer({
        appType: 'custom',
        clearScreen: false,
        logLevel: 'error',
        optimizeDeps: { noDiscovery: true },
        plugins: [measurementPagePlugin()],
        resolve: {
            alias: [
                {
                    find: '#packages',
                    replacement: path.resolve(repositoryRootPath, 'packages'),
                },
                {
                    find: '#tests',
                    replacement: path.resolve(repositoryRootPath, 'tests'),
                },
                {
                    find: '#tools',
                    replacement: path.resolve(repositoryRootPath, 'tools'),
                },
            ],
        },
        root: repositoryRootPath,
        server: {
            fs: { allow: [repositoryRootPath] },
            host: '127.0.0.1',
            port: browserServerBasePort,
            strictPort: false,
        },
    });
    try {
        await server.listen();
        const address = server.httpServer?.address();
        if (
            address === null ||
            address === undefined ||
            typeof address === 'string'
        ) {
            throw new Error(
                'Primitive-measurement browser server has no TCP address.',
            );
        }
        return Object.freeze({
            baseUrl: `http://127.0.0.1:${String(address.port)}`,
            server,
        });
    } catch (error) {
        await server.close();
        throw error;
    }
};

const browserTypeFor = (browserEngine: SupportedBrowserEngine): BrowserType =>
    browserEngine === 'chromium' ? chromium : firefox;

const runBrowserMeasurement = async (input: {
    readonly baseUrl: string;
    readonly browserEngine: SupportedBrowserEngine;
}): Promise<DesktopBrowserPrimitiveMeasurementEvidence> => {
    const browser = await browserTypeFor(input.browserEngine).launch({
        headless: true,
    });
    try {
        const context = await browser.newContext();
        try {
            const page = await context.newPage();
            await page.goto(
                new URL(browserMeasurementPagePath, input.baseUrl).href,
                { waitUntil: 'domcontentloaded' },
            );
            const rawEvidence = await page.evaluate(
                async (evaluationInput) => {
                    const loadedModule = (await import(
                        /* @vite-ignore */ evaluationInput.moduleUrl
                    )) as unknown as {
                        runDesktopBrowserPrimitiveMeasurements(input: {
                            browserEngine: 'chromium' | 'firefox';
                            wasmUrl: string;
                        }): Promise<unknown>;
                    };
                    return loadedModule.runDesktopBrowserPrimitiveMeasurements({
                        browserEngine: evaluationInput.browserEngine,
                        wasmUrl: evaluationInput.wasmUrl,
                    });
                },
                {
                    browserEngine: input.browserEngine,
                    moduleUrl: new URL(
                        browserMeasurementModulePath,
                        input.baseUrl,
                    ).href,
                    wasmUrl: new URL(browserMeasurementWasmPath, input.baseUrl)
                        .href,
                },
            );
            return validateDesktopBrowserPrimitiveMeasurementEvidence(
                rawEvidence,
                input.browserEngine,
            );
        } finally {
            await context.close();
        }
    } finally {
        await browser.close();
    }
};

const runBrowserFocusedPrimitiveMeasurements = async (input: {
    readonly baseUrl: string;
    readonly browserEngine: SupportedBrowserEngine;
    readonly caseIdentifiers: readonly number[];
}): Promise<readonly DesktopBrowserFocusedPrimitiveMeasurementEvidence[]> => {
    const browser = await browserTypeFor(input.browserEngine).launch({
        headless: true,
    });
    try {
        const context = await browser.newContext();
        try {
            const page = await context.newPage();
            await page.goto(
                new URL(browserMeasurementPagePath, input.baseUrl).href,
                { waitUntil: 'domcontentloaded' },
            );
            const rawEvidence = await page.evaluate(
                async (evaluationInput) => {
                    const loadedModule = (await import(
                        /* @vite-ignore */ evaluationInput.moduleUrl
                    )) as unknown as {
                        runDesktopBrowserFocusedPrimitiveMeasurements(input: {
                            browserEngine: 'chromium' | 'firefox';
                            caseIdentifiers: readonly number[];
                            wasmUrl: string;
                        }): Promise<readonly unknown[]>;
                    };
                    return loadedModule.runDesktopBrowserFocusedPrimitiveMeasurements(
                        {
                            browserEngine: evaluationInput.browserEngine,
                            caseIdentifiers: evaluationInput.caseIdentifiers,
                            wasmUrl: evaluationInput.wasmUrl,
                        },
                    );
                },
                {
                    browserEngine: input.browserEngine,
                    caseIdentifiers: input.caseIdentifiers,
                    moduleUrl: new URL(
                        browserMeasurementModulePath,
                        input.baseUrl,
                    ).href,
                    wasmUrl: new URL(browserMeasurementWasmPath, input.baseUrl)
                        .href,
                },
            );
            if (
                !Array.isArray(rawEvidence) ||
                rawEvidence.length !== input.caseIdentifiers.length
            ) {
                throw new Error(
                    'Focused desktop-browser primitive measurement returned the wrong case count.',
                );
            }
            return Object.freeze(
                rawEvidence.map((evidence, evidenceIndex) =>
                    validateDesktopBrowserFocusedPrimitiveMeasurementEvidence(
                        evidence,
                        input.browserEngine,
                        input.caseIdentifiers[evidenceIndex],
                    ),
                ),
            );
        } finally {
            await context.close();
        }
    } finally {
        await browser.close();
    }
};

type DesktopBrowserAuthenticatedStorageEvidence = Readonly<{
    browserEngine: SupportedBrowserEngine;
    browserUserAgent: string;
    schemaVersion: 1;
    storage: DesktopBrowserAuthenticatedStorageMeasurement;
}>;

type DesktopBrowserBoundaryCopyEvidence = Readonly<{
    boundaryCopies: DesktopBrowserBoundaryCopyMeasurement;
    browserEngine: SupportedBrowserEngine;
    browserUserAgent: string;
    schemaVersion: 1;
}>;

const runBrowserAuthenticatedStorageMeasurement = async (input: {
    readonly baseUrl: string;
    readonly browserEngine: SupportedBrowserEngine;
}): Promise<DesktopBrowserAuthenticatedStorageEvidence> => {
    const browser = await browserTypeFor(input.browserEngine).launch({
        headless: true,
    });
    try {
        const context = await browser.newContext();
        try {
            const page = await context.newPage();
            await page.goto(
                new URL(browserMeasurementPagePath, input.baseUrl).href,
                { waitUntil: 'domcontentloaded' },
            );
            const rawEvidence = await page.evaluate(
                async (evaluationInput) => {
                    const loadedModule = (await import(
                        /* @vite-ignore */ evaluationInput.moduleUrl
                    )) as unknown as {
                        runDesktopBrowserAuthenticatedStorageMeasurement(
                            recordByteLength: number,
                        ): Promise<unknown>;
                    };
                    return {
                        browserUserAgent: navigator.userAgent,
                        storage:
                            await loadedModule.runDesktopBrowserAuthenticatedStorageMeasurement(
                                evaluationInput.recordByteLength,
                            ),
                    };
                },
                {
                    moduleUrl: new URL(
                        browserMeasurementModulePath,
                        input.baseUrl,
                    ).href,
                    recordByteLength:
                        selectedAuthenticatedScratchRecordByteLength,
                },
            );
            if (
                typeof rawEvidence.browserUserAgent !== 'string' ||
                rawEvidence.browserUserAgent.length === 0 ||
                rawEvidence.browserUserAgent.length > 1_024
            ) {
                throw new Error(
                    'Authenticated-storage browser user agent is invalid.',
                );
            }
            return Object.freeze({
                browserEngine: input.browserEngine,
                browserUserAgent: rawEvidence.browserUserAgent,
                schemaVersion: 1,
                storage: validateDesktopBrowserAuthenticatedStorageMeasurement(
                    rawEvidence.storage,
                    selectedAuthenticatedScratchRecordByteLength,
                ),
            });
        } finally {
            await context.close();
        }
    } finally {
        await browser.close();
    }
};

const runBrowserBoundaryCopyMeasurement = async (input: {
    readonly baseUrl: string;
    readonly browserEngine: SupportedBrowserEngine;
}): Promise<DesktopBrowserBoundaryCopyEvidence> => {
    const browser = await browserTypeFor(input.browserEngine).launch({
        headless: true,
    });
    try {
        const context = await browser.newContext();
        try {
            const page = await context.newPage();
            await page.goto(
                new URL(browserMeasurementPagePath, input.baseUrl).href,
                { waitUntil: 'domcontentloaded' },
            );
            const rawEvidence = await page.evaluate(
                async (evaluationInput) => {
                    const response = await fetch(evaluationInput.wasmUrl, {
                        cache: 'no-store',
                    });
                    if (!response.ok) {
                        throw new Error(
                            `Boundary-copy WASM fetch failed with ${String(response.status)}.`,
                        );
                    }
                    const wasmBytes = await response.arrayBuffer();
                    const loadedModule = (await import(
                        /* @vite-ignore */ evaluationInput.moduleUrl
                    )) as unknown as {
                        runDesktopBrowserBoundaryCopyMeasurement(
                            wasmBytes: ArrayBuffer,
                            byteLength: number,
                        ): Promise<unknown>;
                    };
                    return {
                        boundaryCopies:
                            await loadedModule.runDesktopBrowserBoundaryCopyMeasurement(
                                wasmBytes,
                                evaluationInput.recordByteLength,
                            ),
                        browserUserAgent: navigator.userAgent,
                    };
                },
                {
                    moduleUrl: new URL(
                        browserMeasurementModulePath,
                        input.baseUrl,
                    ).href,
                    recordByteLength:
                        selectedAuthenticatedScratchRecordByteLength,
                    wasmUrl: new URL(browserMeasurementWasmPath, input.baseUrl)
                        .href,
                },
            );
            if (
                typeof rawEvidence.browserUserAgent !== 'string' ||
                rawEvidence.browserUserAgent.length === 0 ||
                rawEvidence.browserUserAgent.length > 1_024
            ) {
                throw new Error('Boundary-copy browser user agent is invalid.');
            }
            return Object.freeze({
                boundaryCopies: validateDesktopBrowserBoundaryCopyMeasurement(
                    rawEvidence.boundaryCopies,
                    selectedAuthenticatedScratchRecordByteLength,
                ),
                browserEngine: input.browserEngine,
                browserUserAgent: rawEvidence.browserUserAgent,
                schemaVersion: 1,
            });
        } finally {
            await context.close();
        }
    } finally {
        await browser.close();
    }
};

export const runDesktopBrowserPrimitiveMeasurements =
    async (): Promise<void> => {
        const commandLineArguments = process.argv.slice(2);
        await runWithLocalRunLog(
            {
                commandLineArguments,
                lanes: ['Desktop-browser primitive measurements'],
                scriptName: 'test:browser:primitive-measurements',
            },
            async (runLog) => {
                const parsedArguments =
                    parseDesktopBrowserPrimitiveMeasurementArguments(
                        commandLineArguments,
                    );
                const measurementWasm =
                    parsedArguments.measurementComponent !==
                    'authenticated-storage'
                        ? await (async () => {
                              const artifact =
                                  parsedArguments.measurementComponent ===
                                      'boundary-copies' ||
                                  parsedArguments.reuseMeasurementWasm === true
                                      ? undefined
                                      : await buildPrimitiveMeasurementWasm();
                              const artifactBytes = await readFile(
                                  primitiveMeasurementWasmOutputFilePath,
                              );
                              assertDeterministicWasmStackLayout(artifactBytes);
                              const rawSha256Hex = createHash('sha256')
                                  .update(artifactBytes)
                                  .digest('hex');
                              const normalizedSha256Hex =
                                  artifact?.normalizedSha256Hex ??
                                  createHash('sha256')
                                      .update(
                                          normalizeTranscriptCoreKernelBytesForHash(
                                              artifactBytes,
                                          ),
                                      )
                                      .digest('hex');
                              runLog.writeEvent({
                                  details: {
                                      byteLength: artifactBytes.byteLength,
                                      normalizedSha256Hex,
                                      rawSha256Hex,
                                  },
                                  eventType:
                                      artifact === undefined
                                          ? 'primitive-measurement-wasm-reused'
                                          : 'primitive-measurement-wasm-built',
                              });
                              return Object.freeze({
                                  byteLength: artifactBytes.byteLength,
                                  normalizedSha256Hex,
                                  rawSha256Hex,
                              });
                          })()
                        : undefined;

                const { baseUrl, server } = await startBrowserServer();
                const browserEvidence: DesktopBrowserPrimitiveMeasurementEvidence[] =
                    [];
                const focusedPrimitiveEvidence: DesktopBrowserFocusedPrimitiveMeasurementEvidence[] =
                    [];
                const authenticatedStorageEvidence: DesktopBrowserAuthenticatedStorageEvidence[] =
                    [];
                const boundaryCopyEvidence: DesktopBrowserBoundaryCopyEvidence[] =
                    [];
                try {
                    for (const browserEngine of parsedArguments.browserEngines) {
                        if (
                            parsedArguments.measurementComponent ===
                            'authenticated-storage'
                        ) {
                            const evidence =
                                await runBrowserAuthenticatedStorageMeasurement(
                                    { baseUrl, browserEngine },
                                );
                            authenticatedStorageEvidence.push(evidence);
                            runLog.writeEvent({
                                details: {
                                    browserEngine,
                                    physicalStoredPeakByteLength:
                                        evidence.storage.physicalAccounting
                                            .physicalStoredPeakByteLength,
                                    physicalWriteByteLength:
                                        evidence.storage.physicalAccounting
                                            .physicalWriteByteLength,
                                },
                                eventType:
                                    'authenticated-storage-browser-measurement-completed',
                            });
                            continue;
                        }
                        if (
                            parsedArguments.measurementComponent ===
                            'boundary-copies'
                        ) {
                            const evidence =
                                await runBrowserBoundaryCopyMeasurement({
                                    baseUrl,
                                    browserEngine,
                                });
                            boundaryCopyEvidence.push(evidence);
                            runLog.writeEvent({
                                details: {
                                    browserEngine,
                                    copyFromWasmElapsedMilliseconds:
                                        evidence.boundaryCopies
                                            .copyFromWasmElapsedMilliseconds,
                                    copyIntoWasmElapsedMilliseconds:
                                        evidence.boundaryCopies
                                            .copyIntoWasmElapsedMilliseconds,
                                },
                                eventType:
                                    'boundary-copy-browser-measurement-completed',
                            });
                            continue;
                        }
                        if (
                            parsedArguments.focusedCaseIdentifiers !== undefined
                        ) {
                            const evidenceSet =
                                await runBrowserFocusedPrimitiveMeasurements({
                                    baseUrl,
                                    browserEngine,
                                    caseIdentifiers:
                                        parsedArguments.focusedCaseIdentifiers,
                                });
                            for (const evidence of evidenceSet) {
                                focusedPrimitiveEvidence.push(evidence);
                                runLog.writeEvent({
                                    details: {
                                        browserEngine,
                                        caseIdentifier:
                                            evidence.primitiveCase.record
                                                .caseIdentifier,
                                        elapsedNanoseconds:
                                            evidence.primitiveCase.record
                                                .elapsedNanoseconds,
                                        wasmMemoryByteLength:
                                            evidence.primitiveCase
                                                .wasmMemoryByteLengthAfter,
                                    },
                                    eventType:
                                        'focused-primitive-measurement-browser-completed',
                                });
                            }
                            continue;
                        }
                        const evidence = await runBrowserMeasurement({
                            baseUrl,
                            browserEngine,
                        });
                        browserEvidence.push(evidence);
                        runLog.writeEvent({
                            details: {
                                browserEngine,
                                maximumWasmMemoryByteLength: Math.max(
                                    ...evidence.primitiveCases.map(
                                        (measurement) =>
                                            measurement.wasmMemoryByteLengthAfter,
                                    ),
                                    evidence.boundaryCopies
                                        .wasmMemoryByteLengthAfter,
                                ),
                                storagePeakByteLength:
                                    evidence.storage.physicalAccounting
                                        .physicalStoredPeakByteLength,
                            },
                            eventType:
                                'primitive-measurement-browser-completed',
                        });
                    }
                } finally {
                    await server.close();
                }

                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'attachments',
                    'primitive-measurements',
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
                const evidenceRecord = Object.freeze({
                    ...(parsedArguments.focusedCaseIdentifiers !== undefined
                        ? {
                              focusedPrimitiveEvidence: Object.freeze(
                                  focusedPrimitiveEvidence,
                              ),
                              measurementWasm,
                          }
                        : parsedArguments.measurementComponent === undefined
                          ? {
                                browserEvidence: Object.freeze(browserEvidence),
                                measurementWasm,
                            }
                          : parsedArguments.measurementComponent ===
                              'authenticated-storage'
                            ? {
                                  authenticatedStorageEvidence: Object.freeze(
                                      authenticatedStorageEvidence,
                                  ),
                                  recordByteLength:
                                      selectedAuthenticatedScratchRecordByteLength,
                              }
                            : {
                                  boundaryCopyEvidence:
                                      Object.freeze(boundaryCopyEvidence),
                                  measurementWasm,
                                  recordByteLength:
                                      selectedAuthenticatedScratchRecordByteLength,
                              }),
                    schemaVersion: 1,
                });
                const attachmentFilePath = path.join(
                    attachmentDirectoryPath,
                    parsedArguments.focusedCaseIdentifiers !== undefined
                        ? parsedArguments.focusedCaseIdentifiers.length === 1
                            ? 'desktop-browser-focused-primitive-measurement.json'
                            : 'desktop-browser-focused-primitive-measurements.json'
                        : parsedArguments.measurementComponent === undefined
                          ? 'desktop-browser-primitive-measurements.json'
                          : parsedArguments.measurementComponent ===
                              'authenticated-storage'
                            ? 'desktop-browser-authenticated-storage-measurement.json'
                            : 'desktop-browser-boundary-copy-measurement.json',
                );
                await writeFile(
                    attachmentFilePath,
                    `${JSON.stringify(evidenceRecord, null, 2)}\n`,
                    'utf8',
                );
                runLog.writeCombinedOutput(
                    `Desktop-browser ${parsedArguments.focusedCaseIdentifiers === undefined ? (parsedArguments.measurementComponent ?? 'primitive measurements') : `primitive cases ${parsedArguments.focusedCaseIdentifiers.join(', ')}`} completed for ${parsedArguments.browserEngines.join(', ')}; evidence: ${attachmentFilePath}\n`,
                );
            },
        );
    };

if (import.meta.main) {
    void runDesktopBrowserPrimitiveMeasurements();
}
