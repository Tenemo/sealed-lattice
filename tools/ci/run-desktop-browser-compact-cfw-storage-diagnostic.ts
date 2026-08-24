import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';
import { createServer, type Plugin, type ViteDevServer } from 'vite';

import {
    buildPrimitiveMeasurementWasm,
    primitiveMeasurementWasmOutputFilePath,
} from './build-primitive-measurement-wasm.js';
import {
    assertDeterministicWasmStackLayout,
    buildWasmKernel,
} from './build-wasm-kernel.js';
import { validateDesktopBrowserCompactCfwStorageDiagnosticEvidence } from './compact-cfw-storage-diagnostic-evidence.js';
import { runWithLocalRunLog } from './local-run-log.js';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';

const repositoryRootPath = path.resolve(
    fileURLToPath(new URL('../../', import.meta.url)),
);
const standardWasmFilePath = path.resolve(
    repositoryRootPath,
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const diagnosticPagePath = '/compact-cfw-storage-diagnostic/';
const diagnosticModulePath =
    '/tools/ci/desktop-browser-compact-cfw-storage-diagnostic-host.ts';
const diagnosticWasmPath =
    '/temp/primitive-measurements/sealed-lattice-kernel-primitive-measurement.wasm';
const browserServerBasePort = 41_131;

export type DesktopBrowserCompactCfwStorageDiagnosticArguments = Readonly<{
    reuseWasm: boolean;
}>;

export const parseDesktopBrowserCompactCfwStorageDiagnosticArguments = (
    rawArguments: readonly string[],
): DesktopBrowserCompactCfwStorageDiagnosticArguments => {
    const argumentsWithoutSeparator = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (
        argumentsWithoutSeparator.length > 1 ||
        (argumentsWithoutSeparator.length === 1 &&
            argumentsWithoutSeparator[0] !== 'reuse-wasm')
    ) {
        throw new Error(
            'The desktop Chromium compact CFW storage diagnostic accepts only an optional reuse-wasm argument.',
        );
    }
    return Object.freeze({
        reuseWasm: argumentsWithoutSeparator[0] === 'reuse-wasm',
    });
};

const diagnosticPagePlugin = (): Plugin => ({
    name: 'sealed-lattice-compact-cfw-storage-diagnostic-page',
    configureServer(server): void {
        server.middlewares.use((request, response, next) => {
            const requestUrl = request.url;
            if (
                requestUrl === undefined ||
                new URL(requestUrl, 'http://127.0.0.1').pathname !==
                    diagnosticPagePath
            ) {
                next();
                return;
            }
            response.statusCode = 200;
            response.setHeader('Content-Type', 'text/html; charset=utf-8');
            response.setHeader('Cache-Control', 'no-store');
            response.end(
                '<!doctype html><html><head><meta charset="utf-8"><title>Compact CFW storage diagnostic</title></head><body></body></html>',
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
        plugins: [diagnosticPagePlugin()],
        resolve: {
            alias: [
                {
                    find: '@sealed-lattice/wasm',
                    replacement: path.resolve(
                        repositoryRootPath,
                        'packages',
                        'wasm',
                        'src',
                        'index.ts',
                    ),
                },
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
                'Compact CFW diagnostic browser server has no TCP address.',
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

const artifactIdentity = async (artifactFilePath: string) => {
    const bytes = await readFile(artifactFilePath);
    assertDeterministicWasmStackLayout(bytes);
    return Object.freeze({
        byteLength: bytes.byteLength,
        normalizedSha256Hex: createHash('sha256')
            .update(normalizeTranscriptCoreKernelBytesForHash(bytes))
            .digest('hex'),
        rawSha256Hex: createHash('sha256').update(bytes).digest('hex'),
    });
};

export const runDesktopBrowserCompactCfwStorageDiagnostic =
    async (): Promise<void> => {
        const commandLineArguments = process.argv.slice(2);
        await runWithLocalRunLog(
            {
                commandLineArguments,
                lanes: ['Desktop Chromium compact CFW storage diagnostic'],
                scriptName: 'test:browser:compact-cfw-storage-diagnostic',
            },
            async (runLog) => {
                const parsedArguments =
                    parseDesktopBrowserCompactCfwStorageDiagnosticArguments(
                        commandLineArguments,
                    );
                if (!parsedArguments.reuseWasm) {
                    await buildWasmKernel();
                    await buildPrimitiveMeasurementWasm();
                }
                const [standardWasm, measurementWasm] = await Promise.all([
                    artifactIdentity(standardWasmFilePath),
                    artifactIdentity(primitiveMeasurementWasmOutputFilePath),
                ]);
                runLog.writeEvent({
                    details: { measurementWasm, standardWasm },
                    eventType: parsedArguments.reuseWasm
                        ? 'compact-cfw-diagnostic-wasm-reused'
                        : 'compact-cfw-diagnostic-wasm-built',
                });

                const { baseUrl, server } = await startBrowserServer();
                let rawEvidence: unknown;
                try {
                    const browser = await chromium.launch({
                        args: ['--enable-precise-memory-info'],
                        headless: true,
                    });
                    try {
                        const context = await browser.newContext();
                        try {
                            const page = await context.newPage();
                            page.setDefaultTimeout(0);
                            page.setDefaultNavigationTimeout(120_000);
                            page.on('console', (message) => {
                                const messageText = message.text();
                                if (
                                    messageText.startsWith(
                                        'Compact CFW storage diagnostic completed',
                                    )
                                ) {
                                    runLog.writeCombinedOutput(
                                        `${messageText}\n`,
                                    );
                                }
                            });
                            await page.goto(
                                new URL(diagnosticPagePath, baseUrl).href,
                                { waitUntil: 'domcontentloaded' },
                            );
                            rawEvidence = await page.evaluate(
                                async (evaluationInput) => {
                                    const loadedModule = (await import(
                                        /* @vite-ignore */ evaluationInput.moduleUrl
                                    )) as unknown as {
                                        runDesktopBrowserCompactCfwStorageDiagnostic(input: {
                                            browserEngine: 'chromium';
                                            wasmUrl: string;
                                        }): Promise<unknown>;
                                    };
                                    return loadedModule.runDesktopBrowserCompactCfwStorageDiagnostic(
                                        {
                                            browserEngine: 'chromium',
                                            wasmUrl: evaluationInput.wasmUrl,
                                        },
                                    );
                                },
                                {
                                    moduleUrl: new URL(
                                        diagnosticModulePath,
                                        baseUrl,
                                    ).href,
                                    wasmUrl: new URL(
                                        diagnosticWasmPath,
                                        baseUrl,
                                    ).href,
                                },
                            );
                        } finally {
                            await context.close();
                        }
                    } finally {
                        await browser.close();
                    }
                } finally {
                    await server.close();
                }

                const evidence =
                    validateDesktopBrowserCompactCfwStorageDiagnosticEvidence(
                        rawEvidence,
                    );
                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'attachments',
                    'compact-cfw-storage-diagnostic',
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
                const attachmentFilePath = path.join(
                    attachmentDirectoryPath,
                    'desktop-chromium-compact-cfw-storage-diagnostic.json',
                );
                await writeFile(
                    attachmentFilePath,
                    `${JSON.stringify(
                        {
                            evidence,
                            measurementWasm,
                            schemaVersion: 1,
                            standardWasm,
                        },
                        null,
                        2,
                    )}\n`,
                    'utf8',
                );
                runLog.writeEvent({
                    details: {
                        observedReadByteLength: evidence.observedReadByteLength,
                        observedTransactionCount:
                            evidence.observedTransactionCount,
                        observedWrittenByteLength:
                            evidence.observedWrittenByteLength,
                        physicalStoredPeakByteLength:
                            evidence.physicalStorageAccountingBeforeCleanup
                                .physicalStoredPeakByteLength,
                        sealCallCount:
                            evidence.physicalStorageAccountingBeforeCleanup
                                .sealCallCount,
                        totalElapsedMilliseconds:
                            evidence.totalElapsedMilliseconds,
                    },
                    eventType:
                        'desktop-chromium-compact-cfw-storage-diagnostic-completed',
                });
                runLog.writeCombinedOutput(
                    `Nonqualifying desktop Chromium compact CFW storage diagnostic completed; evidence: ${attachmentFilePath}\n`,
                );
            },
        );
    };

if (import.meta.main) {
    void runDesktopBrowserCompactCfwStorageDiagnostic();
}
