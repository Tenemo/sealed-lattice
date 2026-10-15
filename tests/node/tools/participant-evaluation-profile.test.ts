import { createHash, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
    evaluationFixtureIdentity,
    instrumentEvaluation,
    instrumentEvaluationSdk,
    summarizeEvaluationProfile,
} from '#tools/ci/participant-evaluation-profile.js';
import type { EvaluationProfile } from '#tools/ci/participant-evaluation-profile.js';

describe('evaluation phase diagnostics', () => {
    it('binds an archived label to the exact retained artifacts', () => {
        const manifest = Buffer.from('fixture manifest');
        const module = Buffer.from('fixture module');
        const label = 'participant-runtime/8';
        const worker = Buffer.from(
            `const participantRuntimeLabel = '${label}';`,
        );
        const expected = createHash('sha512')
            .update(
                Buffer.concat([
                    Buffer.from(label),
                    ...[manifest, module, worker].map((bytes) =>
                        createHash('sha512').update(bytes).digest(),
                    ),
                ]),
            )
            .digest('hex');
        expect(
            evaluationFixtureIdentity(manifest, module, worker).runtime,
        ).toBe(expected);
        expect(
            evaluationFixtureIdentity(manifest, Buffer.from('changed'), worker)
                .runtime,
        ).not.toBe(expected);
        for (const bytes of [Buffer.from(''), Buffer.concat([worker, worker])])
            expect(() =>
                evaluationFixtureIdentity(manifest, module, bytes),
            ).toThrow('one pinned');
    });

    it('finds every boundary in the packaged worker and preserves the SDK lifecycle', async () => {
        const [worker, sdk] = await Promise.all([
            readFile('packages/sdk/dist/participant-worker.js'),
            readFile('packages/sdk/dist/index.js'),
        ]);
        const diagnostic = instrumentEvaluationSdk(sdk, worker);
        expect(diagnostic.sdk.equals(sdk)).toBe(false);
        expect(diagnostic.worker.equals(worker)).toBe(false);
        expect(() => instrumentEvaluation(Buffer.from(''))).toThrow(
            'Expected one',
        );
    });

    it('partitions nested and overlapping work without double counting', () => {
        const summary = summarizeEvaluationProfile({
            bookkeepingMilliseconds: 0.5,
            spans: [
                { phase: 'encrypted-evaluation', started: 0, finished: 20 },
                { phase: 'retrieval', started: 2, finished: 12 },
                { phase: 'retrieval', started: 3, finished: 8 },
                { phase: 'working-storage', started: 7, finished: 15 },
                { phase: 'evaluation-module', started: 10, finished: 11 },
                { phase: 'target-signing', started: 25, finished: 27 },
            ],
        });
        expect(summary.measuredUnionMilliseconds).toBe(22);
        expect(summary.inclusiveMilliseconds).toEqual({
            'encrypted-evaluation': 20,
            retrieval: 10,
            'working-storage': 8,
            'evaluation-module': 1,
            'target-signing': 2,
        });
        expect(summary.partitionMilliseconds).toEqual({
            'encrypted-evaluation': 7,
            'encrypted-evaluation / retrieval': 5,
            'encrypted-evaluation / retrieval + working-storage': 4,
            'encrypted-evaluation / evaluation-module + retrieval + working-storage': 1,
            'encrypted-evaluation / working-storage': 3,
            'target-signing': 2,
        });
    });

    it('preserves values and refusals and sends diagnostics before the result', async () => {
        const names = [
            'verifyCloseBarrier',
            'classifyBallot',
            'evaluate',
            'retainEvaluation',
            'commitTarget',
            'restoreEvaluation',
            'relayWaits',
            'openEvaluationStorage',
            'writeEvaluationStorage',
            'readStoredBlobs',
            'storedBytes',
        ];
        const source =
            names
                .map((name) => `const ${name} = async (value) => value;`)
                .join('\n') +
            `
            const evaluationCommand = value => value;
            const tryEvaluationCommand = () => { throw new Error('Refused input'); };
            const finalityOperation = { signVote: 1 }, finalityCommand = () => 7;
            globalThis.execute = async () => {
                const value = (await evaluate(Uint8Array.of(19)))[0];
                const vote = finalityCommand({}, finalityOperation.signVote, new Uint8Array());
                try { tryEvaluationCommand(); } catch (error) { globalThis.refusal = error.message; }
                self.postMessage({status: 'completed', value, vote});
            };
        `;
        const messages: {
            type?: string;
            profile?: EvaluationProfile;
            status?: string;
            value?: number;
            vote?: number;
        }[] = [];
        const context = {
            performance,
            crypto: webcrypto,
            self: {
                postMessage: (message: (typeof messages)[number]) =>
                    messages.push(message),
            },
            execute: undefined as undefined | (() => Promise<void>),
            refusal: undefined as undefined | string,
        };
        runInNewContext(
            instrumentEvaluation(Buffer.from(source)).worker.toString('utf8'),
            context,
        );
        await context.execute!();
        expect(context.refusal).toBe('Refused input');
        expect(messages[1]).toEqual({
            status: 'completed',
            value: 19,
            vote: 7,
        });
        expect(messages[0].type).toBe('participant-evaluation-profile');
        expect(summarizeEvaluationProfile(messages[0].profile!).calls).toBe(3);
    });

    it('accepts an empty no-work observation and refuses invalid spans', () => {
        expect(
            summarizeEvaluationProfile({
                spans: [],
                bookkeepingMilliseconds: 0,
            }).measuredUnionMilliseconds,
        ).toBe(0);
        for (const span of [
            { phase: 'retrieval', started: 2, finished: 1 },
            { phase: 'unknown', started: 0, finished: 1 },
            { phase: 'retrieval', started: 0, finished: Number.NaN },
        ])
            expect(() =>
                summarizeEvaluationProfile({
                    spans: [span],
                    bookkeepingMilliseconds: 0,
                }),
            ).toThrow();
    });
});
