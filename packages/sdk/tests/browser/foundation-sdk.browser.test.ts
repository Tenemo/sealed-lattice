import { describe, expect, it } from 'vitest';

import type { FoundationWorkerResult } from './foundation-sdk-worker.js';

const runWorker = (
    participantCount: number,
    optionCount: number,
    tamperKernel = false,
) =>
    new Promise<{ result?: FoundationWorkerResult; error?: string }>(
        (resolve, reject) => {
            const worker = new Worker(
                new URL('./foundation-sdk-worker.ts', import.meta.url),
                { type: 'module' },
            );
            const timer = setTimeout(() => {
                worker.terminate();
                reject(new Error('The SDK worker did not finish.'));
            }, 15000);
            worker.onmessage = (
                event: MessageEvent<{
                    result?: FoundationWorkerResult;
                    error?: string;
                }>,
            ) => {
                clearTimeout(timer);
                worker.terminate();
                resolve(event.data);
            };
            worker.onerror = (event) => {
                clearTimeout(timer);
                worker.terminate();
                reject(new Error(event.message));
            };
            worker.postMessage({ participantCount, optionCount, tamperKernel });
        },
    );

describe('public SDK foundation flow in a browser worker', () => {
    it.each([
        [3, 2],
        [10, 10],
        [20, 20],
    ])(
        'binds the %i-participant %i-option context through the real pinned kernel',
        async (participants, options) => {
            const response = await runWorker(participants, options);
            expect(response.error).toBeUndefined();
            const result = response.result!;
            for (const verified of [
                result.manifest,
                result.definition,
                result.policy,
                result.ceremony,
                result.action,
                result.afterInvalid,
            ])
                expect(verified.isValid).toBe(true);
            expect(result.afterInvalid).toEqual(result.action);
            expect(result.replay).toEqual({
                isValid: false,
                refusalReason: 'wrongContext',
            });
            expect(result.wrongSuite).toEqual({
                isValid: false,
                refusalReason: 'wrongContext',
            });
            expect(result.duplicate).toEqual({
                isValid: false,
                refusalReason: 'duplicateIdentity',
            });
            expect(result.truncated).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
            expect(result.oversizedResult.isValid).toBe(options === 20);
        },
    );

    it('refuses a tampered kernel and succeeds in a fresh worker afterward', async () => {
        const failed = await runWorker(10, 10, true);
        expect(failed.result).toBeUndefined();
        expect(failed.error).toContain('failed integrity verification');
        const fresh = await runWorker(10, 10);
        expect(fresh.error).toBeUndefined();
        expect(fresh.result?.action.isValid).toBe(true);
    });
});
