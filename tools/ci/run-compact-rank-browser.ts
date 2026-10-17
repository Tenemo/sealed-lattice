import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

import {
    launchChromeParticipant,
    type ChromeParticipant,
} from '#tools/ci/chrome-session.js';
import { harnessPage, harnessPageType } from '#tools/ci/harness-page.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { guardProcessTreeMemory } from '#tools/ci/process-tree-memory.js';
import { screenProcessMemoryLimit } from '#tools/ci/scalar-screen-build.js';

type Case = {
    name: string;
    role: string;
    context: string;
    statement: { file: string };
    proof: { file: string };
    accepted: boolean;
};
export const runCompactRankBrowser = async (
    root: string,
    log: ActiveLocalRunLog,
    moduleFile: string,
    cases: Case[],
) => {
    const page = harnessPage(
        'Compact rank verifier',
        `
window.runRankScreen = () => new Promise((resolve,reject) => {
    const worker=new Worker('/compact-rank-browser-worker.mjs',{type:'module'});
    worker.onmessage=({data})=>{worker.terminate();if(data.error)reject(new Error(data.error));else resolve(data.result);};
    worker.onerror=(event)=>{worker.terminate();reject(new Error(event.message));};
    worker.postMessage({});
});`,
    );
    const assets = new Map<string, { type: string; bytes: Uint8Array }>([
        ['/', { type: harnessPageType, bytes: Buffer.from(page) }],
        [
            '/module.wasm',
            { type: 'application/wasm', bytes: await readFile(moduleFile) },
        ],
    ]);
    for (const name of [
        'compact-rank-browser-worker.mjs',
        'compact-rank-scalar.mjs',
    ])
        assets.set('/' + name, {
            type: 'text/javascript',
            bytes: await readFile(path.join(root, 'tools/ci', name)),
        });
    const manifest = [];
    for (const [index, entry] of cases.entries()) {
        const parts = [
            Buffer.from(entry.role),
            Buffer.from(entry.context),
            await readFile(path.join(root, entry.statement.file)),
            await readFile(path.join(root, entry.proof.file)),
        ];
        const bytes = Buffer.concat(
            parts.flatMap((part) => {
                const word = Buffer.alloc(4);
                word.writeUInt32LE(part.length);
                return [word, part];
            }),
        );
        const url = '/fixture-' + String(index);
        assets.set(url, { type: 'application/octet-stream', bytes });
        manifest.push({ name: entry.name, url, accepted: entry.accepted });
    }
    assets.set('/fixtures.json', {
        type: 'application/json',
        bytes: Buffer.from(JSON.stringify(manifest)),
    });
    let responseBytes = 0;
    const server = createServer((request, response) => {
        const asset = assets.get(request.url ?? '');
        if (request.method !== 'GET' || !asset) {
            response.writeHead(404).end();
            return;
        }
        responseBytes += asset.bytes.length;
        response
            .writeHead(200, {
                'Content-Type': asset.type,
                'Cache-Control': 'no-store',
            })
            .end(asset.bytes);
    });
    const profile = await mkdtemp(
        path.join(root, 'temp/compact-rank-browser-'),
    );
    let browser: ChromeParticipant | undefined;
    let guard: ReturnType<typeof guardProcessTreeMemory> | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let peakMemory = 0,
        samples = 0;
    try {
        await new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen(0, '127.0.0.1', resolve);
        });
        const address = server.address();
        assert.ok(address && typeof address !== 'string');
        browser = await launchChromeParticipant(
            profile,
            'http://127.0.0.1:' + String(address.port),
        );
        assert.equal(
            await browser.evaluate('isSecureContext && !crossOriginIsolated'),
            true,
        );
        let fail: (error: Error) => void = () => undefined;
        let guardFailure: Error | undefined;
        const interruption = new Promise<never>((_resolve, reject) => {
            fail = (error) => {
                guardFailure = error;
                reject(error);
            };
        });
        timer = setTimeout(
            () =>
                fail(
                    new Error('The browser rank screen exceeded its deadline.'),
                ),
            120_000,
        );
        guard = guardProcessTreeMemory({
            processIdentifier: browser.processIdentifier,
            memoryLimit: screenProcessMemoryLimit,
            exceededMessage:
                'The browser rank screen exceeded its process-tree memory limit.',
            abort: (error) =>
                fail(error instanceof Error ? error : new Error(String(error))),
            onSample: (bytes) => {
                samples++;
                peakMemory = Math.max(peakMemory, bytes);
                log.writeEvent({
                    eventType: 'compact-rank-browser-memory',
                    details: { bytes, limit: screenProcessMemoryLimit },
                });
            },
        });
        const result = await Promise.race([
            browser.evaluate('window.runRankScreen()'),
            interruption,
        ]);
        await guard.stop();
        if (guardFailure) throw guardFailure;
        assert.ok(samples > 0);
        return {
            result,
            peakMemory,
            samples,
            responseBytes,
            browser: {
                version: browser.version,
                launchArguments: browser.launchArguments,
            },
        };
    } finally {
        clearTimeout(timer);
        await guard?.stop();
        try {
            await browser?.crash();
        } finally {
            try {
                await new Promise<void>((resolve, reject) =>
                    server.close((error) =>
                        error ? reject(error) : resolve(),
                    ),
                );
            } finally {
                const resolved = path.resolve(profile);
                assert.ok(
                    resolved.startsWith(path.resolve(root, 'temp') + path.sep),
                );
                await rm(resolved, { recursive: true });
            }
        }
    }
};
