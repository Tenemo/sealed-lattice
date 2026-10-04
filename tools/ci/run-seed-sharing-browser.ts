import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    open,
    readFile,
    rm,
    writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:http';
import { freemem } from 'node:os';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';

import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { openingShareProbes } from '#tools/ci/opening-share-scalar.mjs';
import { launchChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import type { ChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { seedSharingChunkBytes } from '#tools/ci/seed-sharing-browser-input.mjs';
import { createBrowserOutputSink } from '#tools/ci/seed-sharing-browser-sink.js';
import { fileDigest } from '#tools/ci/seed-sharing-scalar-source.js';
import { seedSharingProbes } from '#tools/ci/seed-sharing-scalar-verifier.mjs';

export const boundedBrowserSources = [
    'tools/ci/run-seed-sharing-browser.ts',
    'tools/ci/seed-sharing-browser-input.mjs',
    'tools/ci/seed-sharing-browser-worker.mjs',
    'tools/ci/seed-sharing-browser-sink.ts',
    'tools/ci/bounded-output-sink.mjs',
    'tools/ci/opening-share-scalar.mjs',
    'tools/ci/scalar-proof-stream.mjs',
    'tools/ci/bounded-output.mjs',
    'tools/ci/scalar-module.mjs',
    'tools/ci/public-operator-scalar.mjs',
    'tools/ci/participant-runtime-chrome.ts',
];

type Proof = Readonly<{
    name: string;
    file: string;
    bytes: number;
    sha512: string;
}>;
type Chunk = Readonly<{ offset: number; bytes: number; sha512: string }>;
type PinnedProof = Proof & Readonly<{ chunks: readonly Chunk[] }>;

export const pinBrowserProofChunks = async (
    proof: Proof,
): Promise<PinnedProof> => {
    const file = await open(proof.file, 'r');
    const digest = createHash('sha512');
    const chunks: Chunk[] = [];
    try {
        assert.equal((await file.stat()).size, proof.bytes);
        for (
            let offset = 0;
            offset < proof.bytes;
            offset += seedSharingChunkBytes
        ) {
            const length = Math.min(
                seedSharingChunkBytes,
                proof.bytes - offset,
            );
            const bytes = new Uint8Array(length);
            let read = 0;
            while (read < length) {
                const { bytesRead } = await file.read(
                    bytes,
                    read,
                    length - read,
                    offset + read,
                );
                assert.ok(
                    bytesRead > 0,
                    'The proof ended while its chunks were pinned.',
                );
                read += bytesRead;
            }
            digest.update(bytes);
            chunks.push({
                offset,
                bytes: length,
                sha512: createHash('sha512').update(bytes).digest('hex'),
            });
        }
        assert.equal(
            digest.digest('hex'),
            proof.sha512,
            'The proof changed before browser transfer.',
        );
        return { ...proof, chunks };
    } finally {
        await file.close();
    }
};

const page = `<!doctype html><meta charset="utf-8"><title>Bounded operator and proof experiment</title>
<script>
window.runBoundedExperiment = (configuration) => new Promise((resolve, reject) => {
    const worker = new Worker('/seed-sharing-browser-worker.mjs', {type: 'module'});
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
    proofs: readonly PinnedProof[],
    outputTarget?: {
        file: string;
        expectedBytes: number;
        expectedSha512: string;
    },
    predecessors: readonly PinnedProof[] = [],
) => {
    const assets = new Map<string, { bytes: Uint8Array; type: string }>([
        ['/', { bytes: Buffer.from(page), type: 'text/html; charset=utf-8' }],
        [
            '/module.wasm',
            { bytes: await readFile(moduleFile), type: 'application/wasm' },
        ],
    ]);
    for (const name of [
        'seed-sharing-browser-worker.mjs',
        'seed-sharing-browser-input.mjs',
        'seed-sharing-scalar-verifier.mjs',
        'opening-share-scalar.mjs',
        'scalar-proof-stream.mjs',
        'scalar-module.mjs',
        'public-operator-scalar.mjs',
        'bounded-output.mjs',
        ...(outputTarget ? ['seed-sharing-scalar-prover.mjs'] : []),
    ])
        assets.set('/' + name, {
            bytes: await readFile(path.join(root, 'tools/ci', name)),
            type: 'text/javascript',
        });
    const sink = outputTarget
        ? await createBrowserOutputSink(
              outputTarget.file,
              outputTarget.expectedBytes,
              outputTarget.expectedSha512,
          )
        : undefined;
    let responsePayloadBytes = 0;
    let receivedUploadPayloadBytes = 0;
    let requests = 0;
    let activeReads = 0;
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
            if (request.method === 'POST' && sink && posted) {
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
            const route = request.url ?? '';
            const asset = assets.get(route);
            if (asset) {
                response.writeHead(200, {
                    'Content-Type': asset.type,
                    'Content-Length': asset.bytes.length,
                });
                responsePayloadBytes += asset.bytes.length;
                response.end(asset.bytes);
                return;
            }
            const match =
                /^\/(proof|predecessor)\/(0|[1-9][0-9]*)\/(0|[1-9][0-9]*)$/u.exec(
                    route,
                );
            const inputs = match?.[1] === 'predecessor' ? predecessors : proofs;
            const proof = match ? inputs[Number(match[2])] : undefined;
            const chunk =
                proof && match ? proof.chunks[Number(match[3])] : undefined;
            if (!proof || !chunk) {
                response.writeHead(404).end();
                return;
            }
            if (activeReads >= 2) {
                response.writeHead(429).end();
                return;
            }
            activeReads++;
            try {
                const file = await open(proof.file, 'r');
                try {
                    const bytes = new Uint8Array(chunk.bytes);
                    let filled = 0;
                    while (filled < bytes.length) {
                        const { bytesRead } = await file.read(
                            bytes,
                            filled,
                            bytes.length - filled,
                            chunk.offset + filled,
                        );
                        assert.ok(
                            bytesRead > 0,
                            'The pinned proof ended during transfer.',
                        );
                        filled += bytesRead;
                    }
                    response.writeHead(200, {
                        'Content-Type': 'application/octet-stream',
                        'Content-Length': bytes.length,
                    });
                    responsePayloadBytes += bytes.length;
                    response.end(bytes);
                } finally {
                    await file.close();
                }
            } finally {
                activeReads--;
            }
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
        await sink?.close();
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
        completedOutput: () => {
            assert.ok(sink);
            return sink.result();
        },
        close: async () => {
            server.closeAllConnections();
            try {
                await new Promise<void>((resolve, reject) =>
                    server.close((error) =>
                        error ? reject(error) : resolve(),
                    ),
                );
            } finally {
                await sink?.close();
            }
        },
    };
};

type ChromeInputs = {
    relation?: 'seed-sharing' | 'opening-share';
    predecessors?: readonly Proof[];
    root: string;
    log: ActiveLocalRunLog;
    moduleFile: string;
    moduleSha512: string;
    processMemoryLimit: number;
    linearMemoryLimit: number;
};
type OutputTarget = {
    file: string;
    expectedBytes: number;
    expectedSha512: string;
};

const runBoundedExperimentInChrome = async ({
    root,
    log,
    moduleFile,
    moduleSha512,
    proofs = [],
    predecessors = [],
    relation = 'seed-sharing',
    outputTarget,
    caseIndex,
    processMemoryLimit,
    linearMemoryLimit,
}: ChromeInputs & {
    proofs?: readonly Proof[];
    outputTarget?: OutputTarget;
    caseIndex?: 0 | 1;
}) => {
    const phase =
        caseIndex !== undefined
            ? 'operator-screen'
            : outputTarget
              ? 'generation'
              : 'verification';
    const operationIdentity =
        caseIndex !== undefined ? 'public-operator' : relation;
    if (caseIndex !== undefined) {
        assert.ok(caseIndex === 0 || caseIndex === 1);
        assert.ok(outputTarget);
        assert.equal(proofs.length, 0);
        assert.equal(predecessors.length, 0);
    } else
        assert.equal(predecessors.length, relation === 'opening-share' ? 2 : 0);
    assert.ok(
        freemem() >= 2 * processMemoryLimit,
        'Insufficient host memory before Chrome execution.',
    );
    const pinned = [];
    for (const proof of proofs) pinned.push(await pinBrowserProofChunks(proof));
    const pinnedPredecessors = [];
    for (const proof of predecessors)
        pinnedPredecessors.push(await pinBrowserProofChunks(proof));
    await writeFile(
        path.join(
            log.runDirectoryPath,
            caseIndex !== undefined
                ? 'browser-operator-' + caseIndex + '-input-bindings.json'
                : outputTarget
                  ? 'browser-generation-input-bindings.json'
                  : 'browser-input-bindings.json',
        ),
        JSON.stringify(
            {
                moduleSha512,
                phase,
                relation: operationIdentity,
                predecessors: pinnedPredecessors,
                chunkBytes: seedSharingChunkBytes,
                proofs: pinned,
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
    let active = false;
    let monitor: Promise<void> | undefined;
    let peakMemory = 0;
    let samples = 0;
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
    const started = performance.now();
    const timeoutMilliseconds = 600_000;
    try {
        const serving = await serveBoundedBrowserInputs(
            root,
            moduleFile,
            pinned,
            outputTarget,
            pinnedPredecessors,
        );
        server = serving;
        chrome = await launchChromeParticipant(profile, serving.origin);
        const browser = chrome;
        log.writeEvent({
            eventType: operationIdentity + '-browser',
            details: {
                phase,
                relation: operationIdentity,
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
        active = true;
        monitor = (async () => {
            while (active) {
                const bytes = await readProtocolProcessTree(
                    browser.processIdentifier,
                );
                if (bytes !== undefined) {
                    samples++;
                    peakMemory = Math.max(peakMemory, bytes);
                    log.writeEvent({
                        eventType: operationIdentity + '-browser-memory',
                        details: {
                            phase,
                            relation: operationIdentity,
                            caseIndex,
                            bytes,
                            limit: processMemoryLimit,
                            heaps: browser.heaps(),
                            ...(outputTarget
                                ? {
                                      progress: await browser.evaluate(
                                          'window.boundedExperimentProgress',
                                      ),
                                  }
                                : {}),
                        },
                    });
                    assert.ok(
                        bytes <= processMemoryLimit,
                        'Chrome process-tree memory guard exceeded.',
                    );
                }
                if (active) await setTimeout(1000);
            }
        })().catch(fail);
        const browserPredecessors = pinnedPredecessors.map((proof, index) => ({
            name: proof.name,
            bytes: proof.bytes,
            sha512: proof.sha512,
            chunks: proof.chunks,
            url: serving.origin + '/predecessor/' + index + '/',
        }));
        let result: Record<string, unknown>;
        if (outputTarget) {
            const configuration = {
                ...(caseIndex === undefined
                    ? {
                          mode: 'generate',
                          relation,
                          predecessors: browserPredecessors,
                      }
                    : { mode: 'operator', caseIndex }),
                timeoutMilliseconds,
                moduleUrl: serving.origin + '/module.wasm',
                moduleBytes: serving.moduleBytes,
                moduleSha512,
                expectedBytes: outputTarget.expectedBytes,
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
            assert.equal(emitted.bytes, outputTarget.expectedBytes);
            if (caseIndex !== undefined)
                assert.equal(emitted.caseIndex, caseIndex);
            assert.ok(emitted.maximumLinearMemoryBytes <= linearMemoryLimit);
            const artifact = serving.completedOutput();
            assert.equal(await fileDigest(artifact.file), artifact.sha512);
            assert.equal(artifact.sha512, outputTarget.expectedSha512);
            result =
                caseIndex === undefined
                    ? {
                          kind: 'browser-' + relation + '-generation',
                          ...emitted,
                          proof: artifact,
                      }
                    : {
                          kind: 'browser-public-operator-screen',
                          caseIndex,
                          ...emitted,
                          output: artifact,
                      };
            log.writeEvent({
                eventType: operationIdentity + '-browser-output',
                details: { phase, ...result },
            });
        } else {
            const results = [];
            for (const probe of relation === 'opening-share'
                ? openingShareProbes
                : seedSharingProbes) {
                const configuration = {
                    relation,
                    predecessors: browserPredecessors,
                    timeoutMilliseconds,
                    moduleUrl: serving.origin + '/module.wasm',
                    moduleBytes: serving.moduleBytes,
                    moduleSha512,
                    proofs: pinned.map((proof, index) => ({
                        name: proof.name,
                        bytes: proof.bytes,
                        sha512: proof.sha512,
                        chunks: proof.chunks,
                        url: serving.origin + '/proof/' + index + '/',
                    })),
                    probe,
                };
                const verified = (await Promise.race([
                    browser.evaluate(
                        'window.runBoundedExperiment(' +
                            JSON.stringify(configuration) +
                            ')',
                    ),
                    interrupted,
                ])) as {
                    name: string;
                    code: number;
                    maximumLinearMemoryBytes: number;
                    proofSha512: string;
                };
                assert.equal(verified.name, probe.name);
                if (probe.expected === undefined)
                    assert.notEqual(verified.code, 0, probe.name);
                else assert.equal(verified.code, probe.expected, probe.name);
                assert.equal(verified.proofSha512, pinned[probe.proof].sha512);
                assert.ok(
                    verified.maximumLinearMemoryBytes <= linearMemoryLimit,
                );
                results.push(verified);
                log.writeEvent({
                    eventType: relation + '-browser-case',
                    details: { phase, ...verified },
                });
            }
            result = { kind: 'browser-' + relation + '-verification', results };
        }
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
        active = false;
        globalThis.clearTimeout(timer);
        await monitor;
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

export const verifyBoundedProofInChrome = (
    input: ChromeInputs & { proofs: readonly Proof[] },
) => runBoundedExperimentInChrome(input);

type OutputInputs = {
    outputFile: string;
    expectedBytes: number;
    expectedSha512: string;
};
const resolveOutputTarget = (
    input: ChromeInputs & OutputInputs,
): OutputTarget => {
    const output = path.resolve(input.outputFile);
    assert.ok(
        output.startsWith(
            path.resolve(input.log.artifactDirectoryPath) + path.sep,
        ),
        'The output must remain in its run artifact directory.',
    );
    return {
        file: output,
        expectedBytes: input.expectedBytes,
        expectedSha512: input.expectedSha512,
    };
};

export const generateBoundedProofInChrome = (
    input: ChromeInputs & OutputInputs,
) =>
    runBoundedExperimentInChrome({
        ...input,
        outputTarget: resolveOutputTarget(input),
    });

export const runPublicOperatorInChrome = (
    input: Omit<ChromeInputs, 'relation' | 'predecessors'> &
        OutputInputs & { caseIndex: 0 | 1 },
) =>
    runBoundedExperimentInChrome({
        ...input,
        outputTarget: resolveOutputTarget(input),
    });
