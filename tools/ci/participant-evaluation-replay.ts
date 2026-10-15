import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, writeFile, stat, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

import { chromium } from 'playwright';

import { foregroundVisitMilliseconds } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    encodeCandidatePage,
    isCandidateKey,
    isCandidateLocator,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import type { WorkerResult } from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';
import { thresholdProfileFor } from '#tests/threshold-completion-model.js';
import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';
import { runArtifactDirectoryPath } from '#tools/ci/local-run-log.js';
import {
    instrumentEvaluation,
    summarizeEvaluationProfile,
    type EvaluationProfile,
} from '#tools/ci/participant-evaluation-profile.js';
import { participantRelayStore } from '#tools/ci/participant-relay-record.js';

const [source, run, artifacts] = process.argv.slice(2);
assert.ok(source && run && artifacts && process.argv.length === 5);
assert.equal(path.resolve(artifacts), runArtifactDirectoryPath(run));
const fixtureArtifacts = runArtifactDirectoryPath(source);
const [worker, module, manifest, resultText, summaryText] = await Promise.all([
    readFile(path.join(fixtureArtifacts, 'worker.js')),
    readFile(path.join(fixtureArtifacts, 'participant.wasm')),
    readFile(path.join(source, 'source-manifest.json')),
    readFile(path.join(source, 'result.json'), 'utf8'),
    readFile(path.join(source, 'summary.json'), 'utf8'),
]);
assert.equal((JSON.parse(summaryText) as { result: string }).result, 'passed');
const fixture = JSON.parse(resultText) as {
    poll: string;
    runtimeIdentity: string;
    participantCount: number;
    optionCount: number;
    identifiers?: string[];
    result?: { kind: string; identifiers?: string[] };
    workflow?: {
        participants: {
            position: number;
            activeMillisecondsUpperBound: number;
            visits: { stage: string; activeMillisecondsUpperBound: number }[];
        }[];
    };
};
assert.match(fixture.poll, /^[0-9a-f]{128}$/u);
const expectedIdentifiers =
    fixture.identifiers ??
    (fixture.result?.kind === 'no-result' ? [] : fixture.result?.identifiers);
assert.ok(
    Array.isArray(expectedIdentifiers),
    'Select a fixture with a verified terminal outcome.',
);
const expectedHasResult = expectedIdentifiers.length > 0;
const identity = participantRuntimeIdentity(manifest, module, worker);
assert.equal(
    identity.runtime,
    fixture.runtimeIdentity,
    'The fixture runtime differs from its retained artifacts.',
);
const variants = {
    target: instrumentEvaluation(worker, false),
    phases: instrumentEvaluation(worker),
};
for (const [name, variant] of Object.entries(variants))
    await writeFile(path.join(artifacts, `worker-${name}.js`), variant.worker, {
        flag: 'wx',
    });
await writeFile(path.join(artifacts, 'participant.wasm'), module, {
    flag: 'wx',
});
const publicDirectory = path.join(fixtureArtifacts, 'public');
const store = participantRelayStore(path.join(publicDirectory, 'transport'));
let variant: keyof typeof variants = 'target';
let servedBytes = 0;
let requests = 0;
// Serve pinned bytes without interpreting them through a newer manifest
// decoder. Every acceptance decision belongs to the fixture's own runtime.
const server = createServer((request, response) => {
    void (async () => {
        const url = new URL(request.url ?? '/', 'http://127.0.0.1');
        if (request.method !== 'GET') {
            response.writeHead(405).end();
            return;
        }
        const send = (
            bytes: Buffer | Uint8Array,
            type = 'application/octet-stream',
        ) => {
            servedBytes += bytes.length;
            requests++;
            response.setHeader('Content-Type', type);
            response.setHeader('Cache-Control', 'no-store');
            response.end(bytes);
        };
        if (url.pathname === '/') {
            send(
                Buffer.from(
                    '<!doctype html><title>Evaluation diagnostics</title>',
                ),
                'text/html',
            );
            return;
        }
        if (url.pathname === '/worker.js') {
            send(variants[variant].worker, 'text/javascript');
            return;
        }
        if (url.pathname === '/sdk/participant.wasm') {
            send(module, 'application/wasm');
            return;
        }
        if (url.pathname.startsWith('/candidates/')) {
            const key = url.pathname.slice('/candidates/'.length);
            const offset = url.searchParams.get('offset');
            assert.ok(
                isCandidateKey(key) &&
                    offset !== null &&
                    /^(0|[1-9]\d*)$/u.test(offset),
            );
            send(encodeCandidatePage(await store.page(key, Number(offset))));
            return;
        }
        for (const [prefix, directory, file] of [
            ['/candidate/', 'candidates', 'manifest.bin'],
            ['/chunk/', 'chunks', 'body.bin'],
        ]) {
            if (!url.pathname.startsWith(prefix)) continue;
            const locator = url.pathname.slice(prefix.length);
            assert.ok(isCandidateLocator(locator) && url.search === '');
            send(
                await readFile(
                    path.join(
                        publicDirectory,
                        'transport',
                        directory,
                        locator,
                        file,
                    ),
                ),
            );
            return;
        }
        const file = path.resolve(publicDirectory, '.' + url.pathname);
        assert.ok(
            file.startsWith(publicDirectory + path.sep) && url.search === '',
        );
        const information = await stat(file);
        assert.ok(information.isFile());
        servedBytes += information.size;
        requests++;
        response.setHeader('Content-Length', information.size);
        response.setHeader('Content-Type', 'application/octet-stream');
        response.setHeader('Cache-Control', 'no-store');
        createReadStream(file)
            .on('error', () => response.destroy())
            .pipe(response);
    })().catch(() => {
        if (!response.headersSent) response.writeHead(404);
        response.end();
    });
});
await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(43790, '127.0.0.1', resolve);
});
const profileDirectory = path.join(artifacts, 'browser-profile');
let browser:
    Awaited<ReturnType<typeof chromium.launchPersistentContext>> | undefined;
try {
    browser = await chromium.launchPersistentContext(profileDirectory, {
        headless: true,
    });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:43790/');
    const verify = (poll: string) =>
        page.evaluate(
            async ({
                poll: selectedPoll,
                identity: selectedIdentity,
                digest,
            }) => {
                const bytes = new Uint8Array(
                    await (await fetch('/browserWorker.js')).arrayBuffer(),
                );
                const actual = Array.from(
                    new Uint8Array(
                        await crypto.subtle.digest('SHA-512', bytes),
                    ),
                    (value) => value.toString(16).padStart(2, '0'),
                ).join('');
                if (actual !== digest)
                    throw new Error('The diagnostic worker changed.');
                const url = URL.createObjectURL(
                    new Blob([bytes], { type: 'text/javascript' }),
                );
                const browserWorker = new Worker(url, { type: 'module' });
                try {
                    return await new Promise<{
                        result: WorkerResult;
                        profiles: EvaluationProfile[];
                    }>((resolve, reject) => {
                        const profiles: EvaluationProfile[] = [];
                        const timer = setTimeout(
                            () =>
                                reject(
                                    new Error(
                                        'The evaluation replay exceeded its visit limit.',
                                    ),
                                ),
                            900_000,
                        );
                        browserWorker.onerror = (event) => {
                            clearTimeout(timer);
                            reject(new Error(event.message));
                        };
                        browserWorker.onmessage = ({
                            data,
                        }: MessageEvent<
                            | WorkerResult
                            | {
                                  type: 'participant-evaluation-profile';
                                  profile: EvaluationProfile;
                              }
                        >) => {
                            if ('type' in data) {
                                profiles.push(data.profile);
                                return;
                            }
                            clearTimeout(timer);
                            resolve({ result: data, profiles });
                        };
                        browserWorker.postMessage({
                            operation: 'verify-outcome',
                            poll: selectedPoll,
                            relay: location.origin + '/',
                            module: location.origin + '/sdk/participant.wasm',
                            identity: selectedIdentity,
                        });
                    });
                } finally {
                    browserWorker.terminate();
                    URL.revokeObjectURL(url);
                }
            },
            { poll, identity, digest: variants[variant].digest },
        );
    const reports: {
        variant: string;
        milliseconds: number;
        result: Extract<WorkerResult, { status: 'completed' }>;
        profiles: ReturnType<typeof summarizeEvaluationProfile>[];
        servedBytes: number;
        requests: number;
    }[] = [];
    // Reverse the pair to expose order effects. This is not an isolated
    // microbenchmark of instrumentation overhead.
    for (const selected of ['target', 'phases', 'phases', 'target'] as const) {
        variant = selected;
        servedBytes = requests = 0;
        console.log(`Starting ${variant} evaluation ${reports.length + 1}`);
        const started = performance.now();
        const observed = await verify(fixture.poll);
        const milliseconds = performance.now() - started;
        assert.equal(observed.result.status, 'completed');
        assert.ok(observed.result.status === 'completed');
        assert.equal(observed.result.details.hasResult, expectedHasResult);
        assert.deepEqual(
            observed.result.details.identifiers,
            expectedIdentifiers,
        );
        const profiles = observed.profiles.map(summarizeEvaluationProfile);
        assert.equal(profiles.length, 1);
        assert.equal(profiles[0].targetDigests.length, 1);
        const physicalStorage = await page.evaluate(
            async () => (await navigator.storage.estimate()).usage ?? null,
        );
        const report = {
            variant,
            milliseconds,
            result: observed.result,
            profiles,
            servedBytes,
            requests,
            physicalStorage,
        };
        if (reports.length > 0) {
            assert.deepEqual(
                profiles[0].targetDigests,
                reports[0].profiles[0].targetDigests,
                'The canonical evaluation target changed.',
            );
            assert.deepEqual(
                observed.result.details.identifiers,
                reports[0].result.details.identifiers,
            );
            assert.equal(
                observed.result.details.hasResult,
                reports[0].result.details.hasResult,
            );
        }
        reports.push(report);
        await writeFile(
            path.join(run, `evaluation-${reports.length}.json`),
            JSON.stringify(report, null, 2) + '\n',
            { flag: 'wx' },
        );
    }
    const evaluationTimes = reports
        .filter((report) => report.variant === 'phases')
        .map(
            (report) =>
                report.profiles[0].inclusiveMilliseconds[
                    'encrypted-evaluation'
                ] ?? 0,
        );
    const evaluationMilliseconds = Math.min(...evaluationTimes);
    const thresholds = thresholdProfileFor(fixture.participantCount);
    const consumerCounts = {
        allParticipants: fixture.participantCount - 1,
        sufficientContinuers:
            fixture.participantCount -
            thresholds.maximumCorruptParticipantCount -
            1,
    };
    await writeFile(
        path.join(run, 'proving-budget.json'),
        JSON.stringify(
            {
                source,
                evaluationMilliseconds,
                consumerCounts,
                maximumAdditionalCohortWorkMilliseconds: Object.fromEntries(
                    Object.entries(consumerCounts).map(([name, count]) => [
                        name,
                        count * evaluationMilliseconds,
                    ]),
                ),
                optimisticProverVisitHeadroomMilliseconds: Math.max(
                    0,
                    foregroundVisitMilliseconds - evaluationMilliseconds,
                ),
                measuredTargetVisitHeadroom: fixture.workflow?.participants.map(
                    (participant) => ({
                        position: participant.position,
                        milliseconds: Math.max(
                            0,
                            foregroundVisitMilliseconds -
                                Math.max(
                                    ...participant.visits
                                        .filter((visit) =>
                                            visit.stage.includes('target'),
                                        )
                                        .map(
                                            (visit) =>
                                                visit.activeMillisecondsUpperBound,
                                        ),
                                ),
                        ),
                    }),
                ),
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
    const wrongPoll = await verify(
        (fixture.poll.startsWith('00') ? '01' : '00') + fixture.poll.slice(2),
    );
    assert.notEqual(wrongPoll.result.status, 'completed');
    const currentModuleDigest = createHash('sha512')
        .update(await readFile('packages/sdk/dist/participant.wasm'))
        .digest('hex');
    await writeFile(
        path.join(run, 'evaluation.json'),
        JSON.stringify(
            {
                source,
                identity,
                currentModuleMatchesFixture:
                    currentModuleDigest === identity.module,
                participantCount: fixture.participantCount,
                optionCount: fixture.optionCount,
                instrumentedWorkerDigests: Object.fromEntries(
                    Object.entries(variants).map(([name, value]) => [
                        name,
                        value.digest,
                    ]),
                ),
                browser: browser.browser()?.version(),
                pairedPhaseOverheadMilliseconds: [
                    reports[1].milliseconds - reports[0].milliseconds,
                    reports[2].milliseconds - reports[3].milliseconds,
                ],
                reports,
                wrongPoll: wrongPoll.result,
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
} finally {
    await browser?.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const resolved = path.resolve(profileDirectory);
    assert.ok(resolved.startsWith(path.resolve(artifacts) + path.sep));
    await rm(resolved, { recursive: true, force: true });
}
