import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { freemem } from 'node:os';
import path from 'node:path';

import { createBrowserOutputSink } from '#tools/ci/bounded-output-browser-sink.js';
import { browserChunkBytes } from '#tools/ci/bounded-output-browser-transport.mjs';
import { fileDigest } from '#tools/ci/fixture-sources.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { launchChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import type { ChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import { guardProcessTreeMemory } from '#tools/ci/protocol-process-memory.js';

export const boundedBrowserSources = [
    'tools/ci/bounded-output-browser.ts',
    'tools/ci/bounded-output-browser-transport.mjs',
    'tools/ci/bounded-output-browser-worker.mjs',
    'tools/ci/bounded-output-browser-sink.ts',
    'tools/ci/bounded-output-sink.mjs',
    'tools/ci/bounded-output.mjs',
    'tools/ci/scalar-module.mjs',
    'tools/ci/fhe-key-source-scalar.mjs',
    'tools/ci/participant-runtime-chrome.ts',
];

type OutputTarget = {
    file: string;
    expectedBytes: number;
    expectedSha512: string;
};

const page = `<!doctype html><meta charset="utf-8"><title>Bounded operator experiment</title>
<script>
window.runBoundedExperiment = (configuration) => new Promise((resolve, reject) => {
    const worker = new Worker('/bounded-output-browser-worker.mjs', {type: 'module'});
    let finished = false;
    const finish = (error, result) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        worker.terminate();
        if (error) reject(new Error(error));
        else resolve(result);
    };
    window.boundedExperimentProgress = {sequence:0,progress:null};
    const timer = setTimeout(() => finish('The browser experiment worker exceeded its deadline.'), configuration.timeoutMilliseconds);
    worker.onmessage = ({data}) => {
        if (Object.hasOwn(data,'progress')) {
            window.boundedExperimentProgress = {sequence:window.boundedExperimentProgress.sequence+1,progress:data.progress};
        } else finish(data.error, data.result);
    };
    worker.onerror = (event) => finish(event.message || 'The browser experiment worker failed.');
    worker.postMessage(configuration);
});
</script>`;

export const serveBoundedBrowserInputs = async (
    root: string,
    moduleFile: string,
    outputTarget: OutputTarget,
) => {
    const assets = new Map<string, { bytes: Uint8Array; type: string }>([
        ['/', { bytes: Buffer.from(page), type: 'text/html; charset=utf-8' }],
        [
            '/module.wasm',
            { bytes: await readFile(moduleFile), type: 'application/wasm' },
        ],
    ]);
    for (const name of [
        'bounded-output-browser-worker.mjs',
        'bounded-output-browser-transport.mjs',
        'scalar-module.mjs',
        'fhe-key-source-scalar.mjs',
        'bounded-output.mjs',
    ])
        assets.set('/' + name, {
            bytes: await readFile(path.join(root, 'tools/ci', name)),
            type: 'text/javascript',
        });
    const sink = await createBrowserOutputSink(
        outputTarget.file,
        outputTarget.expectedBytes,
        outputTarget.expectedSha512,
    );
    let responsePayloadBytes = 0;
    let receivedUploadPayloadBytes = 0;
    let requests = 0;
    const server = createServer((request, response) => {
        void (async () => {
            response.setHeader('Cache-Control', 'no-store');
            response.setHeader('X-Content-Type-Options', 'nosniff');
            if (++requests > 1024) {
                response.writeHead(400).end();
                return;
            }
            const posted = /^\/output\/(0|[1-9][0-9]*)\/(0|[1-9][0-9]*)$/u.exec(
                request.url ?? '',
            );
            if (request.method === 'POST' && posted) {
                const length = Number(request.headers['content-length']);
                const sha512 = request.headers['x-chunk-sha512'];
                assert.ok(typeof sha512 === 'string');
                const body = async function* () {
                    for await (const chunk of request) {
                        assert.ok(chunk instanceof Uint8Array);
                        receivedUploadPayloadBytes += chunk.length;
                        yield chunk;
                    }
                };
                const received = await sink.receive(
                    Number(posted[1]),
                    Number(posted[2]),
                    length,
                    sha512,
                    body(),
                );
                response
                    .writeHead(204, {
                        'X-Chunk-Sha512': received.sha512,
                        'X-Next-Offset': String(received.nextOffset),
                        'X-Chunk-Index': posted[1],
                        'X-Chunk-Offset': posted[2],
                        'X-Chunk-Length': String(length),
                    })
                    .end();
                return;
            }
            if (request.method !== 'GET') {
                response.writeHead(400).end();
                return;
            }
            const asset = assets.get(request.url ?? '');
            if (!asset) {
                response.writeHead(404).end();
                return;
            }
            response.writeHead(200, {
                'Content-Type': asset.type,
                'Content-Length': asset.bytes.length,
            });
            responsePayloadBytes += asset.bytes.length;
            response.end(asset.bytes);
        })().catch(() => {
            if (!response.headersSent) response.writeHead(500);
            response.end();
        });
    });
    try {
        await new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen(0, '127.0.0.1', resolve);
        });
    } catch (error) {
        await sink.close();
        throw error;
    }
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    return {
        origin: 'http://127.0.0.1:' + address.port,
        moduleBytes: assets.get('/module.wasm')!.bytes.length,
        counters: () => ({
            requests,
            responsePayloadBytes,
            receivedUploadPayloadBytes,
            transferScope:
                'Response payload bytes handed to the HTTP server and upload payload bytes consumed by its sink handler. HTTP headers, link overhead and unread aborted bodies are not measured.',
        }),
        completedOutput: () => sink.result(),
        close: async () => {
            server.closeAllConnections();
            try {
                await new Promise<void>((resolve, reject) =>
                    server.close((error) =>
                        error ? reject(error) : resolve(),
                    ),
                );
            } finally {
                await sink.close();
            }
        },
    };
};

export const runFheKeySourceInChrome = async ({
    root,
    log,
    moduleFile,
    moduleSha512,
    processMemoryLimit,
    linearMemoryLimit,
    outputFile,
    expectedBytes,
    expectedSha512,
}: {
    root: string;
    log: ActiveLocalRunLog;
    moduleFile: string;
    moduleSha512: string;
    processMemoryLimit: number;
    linearMemoryLimit: number;
    outputFile: string;
    expectedBytes: number;
    expectedSha512: string;
}) => {
    const screenKind = 'fhe-key-source';
    const caseIndex = 0;
    const phase = 'operator-screen';
    const output = path.resolve(outputFile);
    assert.ok(
        output.startsWith(path.resolve(log.artifactDirectoryPath) + path.sep),
        'The output must remain in its run artifact directory.',
    );
    const outputTarget: OutputTarget = {
        file: output,
        expectedBytes,
        expectedSha512,
    };
    assert.ok(
        freemem() >= 2 * processMemoryLimit,
        'Insufficient host memory before Chrome execution.',
    );
    await writeFile(
        path.join(
            log.runDirectoryPath,
            'browser-operator-' + caseIndex + '-input-bindings.json',
        ),
        JSON.stringify(
            {
                moduleSha512,
                phase,
                relation: screenKind,
                chunkBytes: browserChunkBytes,
                outputTarget,
                caseIndex,
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
    await mkdir(path.join(root, 'temp'), { recursive: true });
    const profile = await mkdtemp(path.join(root, 'temp/bounded-browser-'));
    let server:
        Awaited<ReturnType<typeof serveBoundedBrowserInputs>> | undefined;
    const controller = new AbortController();
    let chrome: ChromeParticipant | undefined;
    let guard: { stop: () => Promise<void> } | undefined;
    let peakMemory = 0;
    let samples = 0;
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
    const started = performance.now();
    const timeoutMilliseconds = 600_000;
    try {
        const serving = await serveBoundedBrowserInputs(
            root,
            moduleFile,
            outputTarget,
        );
        server = serving;
        chrome = await launchChromeParticipant(profile, serving.origin);
        const browser = chrome;
        log.writeEvent({
            eventType: screenKind + '-browser',
            details: {
                phase,
                relation: screenKind,
                caseIndex,
                version: browser.version,
                launchArguments: browser.launchArguments,
                processIdentifier: browser.processIdentifier,
                processMemoryLimit,
                linearMemoryLimit,
            },
        });
        assert.equal(
            await browser.evaluate('isSecureContext && !crossOriginIsolated'),
            true,
        );
        let fail: (error: unknown) => void = () => undefined;
        const interrupted = new Promise<never>((_resolve, reject) => {
            fail = (error) => {
                const failure =
                    error instanceof Error ? error : new Error(String(error));
                controller.abort(failure);
                reject(failure);
            };
        });
        void interrupted.catch(() => undefined);
        timer = globalThis.setTimeout(
            () =>
                fail(new Error('Chrome ' + phase + ' exceeded its deadline.')),
            timeoutMilliseconds,
        );
        guard = guardProcessTreeMemory({
            processIdentifier: browser.processIdentifier,
            memoryLimit: processMemoryLimit,
            exceededMessage: 'Chrome process-tree memory guard exceeded.',
            onSample: async (bytes) => {
                samples++;
                peakMemory = Math.max(peakMemory, bytes);
                log.writeEvent({
                    eventType: screenKind + '-browser-memory',
                    details: {
                        phase,
                        relation: screenKind,
                        caseIndex,
                        bytes,
                        limit: processMemoryLimit,
                        heaps: browser.heaps(),
                        progress: await browser.evaluate(
                            'window.boundedExperimentProgress',
                        ),
                    },
                });
            },
            abort: fail,
        });
        const configuration = {
            caseIndex,
            timeoutMilliseconds,
            moduleUrl: serving.origin + '/module.wasm',
            moduleBytes: serving.moduleBytes,
            moduleSha512,
            expectedBytes,
            sinkUrl: serving.origin + '/output/',
        };
        const emitted = (await Promise.race([
            browser.evaluate(
                'window.runBoundedExperiment(' +
                    JSON.stringify(configuration) +
                    ')',
            ),
            interrupted,
        ])) as {
            bytes: number;
            maximumLinearMemoryBytes: number;
            caseIndex?: number;
        };
        assert.equal(emitted.bytes, expectedBytes);
        assert.equal(emitted.caseIndex, caseIndex);
        assert.ok(emitted.maximumLinearMemoryBytes <= linearMemoryLimit);
        const artifact = serving.completedOutput();
        assert.equal(await fileDigest(artifact.file), artifact.sha512);
        assert.equal(artifact.sha512, expectedSha512);
        const result: Record<string, unknown> = {
            kind: 'browser-' + screenKind + '-screen',
            caseIndex,
            ...emitted,
            output: artifact,
        };
        log.writeEvent({
            eventType: screenKind + '-browser-output',
            details: { phase, ...result },
        });
        assert.ok(
            samples > 0,
            'No Chrome process-tree memory sample was recorded.',
        );
        return {
            result,
            peakMemory,
            samples,
            milliseconds: performance.now() - started,
            experimentDeadlineMilliseconds: timeoutMilliseconds,
            browser: {
                version: browser.version,
                launchArguments: browser.launchArguments,
            },
            ...serving.counters(),
            unmeasured: {
                physicalPhone: null,
                networkHeaders: null,
                transientMemoryBetweenSamples: null,
            },
        };
    } finally {
        globalThis.clearTimeout(timer);
        await guard?.stop();
        try {
            await chrome?.crash();
        } finally {
            await server?.close();
            const resolved = path.resolve(profile);
            assert.ok(
                resolved.startsWith(path.resolve(root, 'temp') + path.sep),
            );
            await rm(resolved, {
                recursive: true,
                maxRetries: 10,
                retryDelay: 500,
            });
            assert.equal(
                controller.signal.aborted,
                false,
                String(controller.signal.reason),
            );
        }
    }
};
