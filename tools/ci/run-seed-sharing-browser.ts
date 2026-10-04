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
import { launchChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import type { ChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { seedSharingChunkBytes } from '#tools/ci/seed-sharing-browser-input.mjs';
import { seedSharingProbes } from '#tools/ci/seed-sharing-scalar-verifier.mjs';

export const seedSharingBrowserSources = [
    'tools/ci/run-seed-sharing-browser.ts',
    'tools/ci/seed-sharing-browser-input.mjs',
    'tools/ci/seed-sharing-browser-worker.mjs',
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

const page = `<!doctype html><meta charset="utf-8"><title>Seed-sharing verifier</title>
<script>
window.runSeedSharingProbe = (configuration) => new Promise((resolve, reject) => {
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
    const timer = setTimeout(() => finish('The browser verification worker exceeded its deadline.'), 600000);
    worker.onmessage = ({data}) => finish(data.error, data.result);
    worker.onerror = (event) => finish(event.message || 'The browser verification worker failed.');
    worker.postMessage(configuration);
});
</script>`;

export const serveSeedSharingBrowserInputs = async (
    root: string,
    moduleFile: string,
    proofs: readonly PinnedProof[],
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
    ])
        assets.set('/' + name, {
            bytes: await readFile(path.join(root, 'tools/ci', name)),
            type: 'text/javascript',
        });
    let transferredBytes = 0;
    let requests = 0;
    let activeReads = 0;
    const server = createServer((request, response) => {
        void (async () => {
            response.setHeader('Cache-Control', 'no-store');
            response.setHeader('X-Content-Type-Options', 'nosniff');
            if (request.method !== 'GET' || ++requests > 1024) {
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
                transferredBytes += asset.bytes.length;
                response.end(asset.bytes);
                return;
            }
            const match = /^\/proof\/(0|[1-9][0-9]*)\/(0|[1-9][0-9]*)$/u.exec(
                route,
            );
            const proof = match ? proofs[Number(match[1])] : undefined;
            const chunk =
                proof && match ? proof.chunks[Number(match[2])] : undefined;
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
                    transferredBytes += bytes.length;
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
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    return {
        origin: 'http://127.0.0.1:' + address.port,
        moduleBytes: assets.get('/module.wasm')!.bytes.length,
        counters: () => ({ requests, transferredBytes }),
        close: async () => {
            server.closeAllConnections();
            await new Promise<void>((resolve, reject) =>
                server.close((error) => (error ? reject(error) : resolve())),
            );
        },
    };
};

export const verifySeedSharingInChrome = async ({
    root,
    log,
    moduleFile,
    moduleSha512,
    proofs,
    processMemoryLimit,
    linearMemoryLimit,
}: {
    root: string;
    log: ActiveLocalRunLog;
    moduleFile: string;
    moduleSha512: string;
    proofs: readonly Proof[];
    processMemoryLimit: number;
    linearMemoryLimit: number;
}) => {
    assert.ok(
        freemem() >= 2 * processMemoryLimit,
        'Insufficient host memory before Chrome verification.',
    );
    const pinned = [];
    for (const proof of proofs) pinned.push(await pinBrowserProofChunks(proof));
    await writeFile(
        path.join(log.runDirectoryPath, 'browser-input-bindings.json'),
        JSON.stringify(
            { moduleSha512, chunkBytes: seedSharingChunkBytes, proofs: pinned },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
    await mkdir(path.join(root, 'temp'), { recursive: true });
    const profile = await mkdtemp(
        path.join(root, 'temp/seed-sharing-browser-'),
    );
    let server:
        Awaited<ReturnType<typeof serveSeedSharingBrowserInputs>> | undefined;
    const controller = new AbortController();
    let chrome: ChromeParticipant | undefined;
    let active = false;
    let monitor: Promise<void> | undefined;
    let peakMemory = 0;
    let samples = 0;
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined;
    const started = performance.now();
    try {
        const serving = await serveSeedSharingBrowserInputs(
            root,
            moduleFile,
            pinned,
        );
        server = serving;
        chrome = await launchChromeParticipant(profile, serving.origin);
        const browser = chrome;
        log.writeEvent({
            eventType: 'seed-sharing-browser',
            details: {
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
            () => fail(new Error('Chrome verification exceeded its deadline.')),
            600_000,
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
                        eventType: 'seed-sharing-browser-memory',
                        details: {
                            bytes,
                            limit: processMemoryLimit,
                            heaps: browser.heaps(),
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
        const results = [];
        for (const probe of seedSharingProbes) {
            const configuration = {
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
            const result = (await Promise.race([
                browser.evaluate(
                    'window.runSeedSharingProbe(' +
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
            assert.equal(result.name, probe.name);
            if (probe.expected === undefined)
                assert.notEqual(result.code, 0, probe.name);
            else assert.equal(result.code, probe.expected, probe.name);
            assert.equal(result.proofSha512, pinned[probe.proof].sha512);
            assert.ok(result.maximumLinearMemoryBytes <= linearMemoryLimit);
            results.push(result);
            log.writeEvent({
                eventType: 'seed-sharing-browser-case',
                details: result,
            });
        }
        assert.ok(
            samples > 0,
            'No Chrome process-tree memory sample was recorded.',
        );
        return {
            result: { kind: 'browser-seed-sharing-verification', results },
            peakMemory,
            samples,
            milliseconds: performance.now() - started,
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
