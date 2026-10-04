import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';

export type NativeOperationSamplePhase = 'initial' | 'periodic' | 'final';

// The native operation waits at both boundaries, so a fast operation cannot
// disappear before its process is observed. These are sampled values, not
// an operating-system lifetime peak; short internal peaks can remain unseen.
export const createNativeOperationGuard = (
    input: Readonly<{
        startFile: string;
        finishFile: string;
        memoryLimit: number;
        operation?: 'verifier' | 'operator';
        readMemory: (
            phase: NativeOperationSamplePhase,
        ) => Promise<number | undefined>;
        recordSample: (
            phase: NativeOperationSamplePhase,
            bytes: number,
        ) => void;
    }>,
) => {
    const operation = input.operation ?? 'verifier';
    const elapsedField =
        operation === 'operator'
            ? 'operationMilliseconds'
            : 'verificationMilliseconds';
    let readySeen = false;
    let started = false;
    let completionSeen = false;
    let finishReleased = false;
    let pending = '';
    let readyResolve!: () => void;
    let readyReject!: (reason: Error) => void;
    const ready = new Promise<void>((resolve, reject) => {
        readyResolve = resolve;
        readyReject = reject;
    });
    let completeResolve!: (milliseconds: number) => void;
    let completeReject!: (reason: Error) => void;
    const completed = new Promise<number>((resolve, reject) => {
        completeResolve = resolve;
        completeReject = reject;
    });
    // Either boundary can be cancelled before the monitor reaches its await.
    void ready.catch(() => undefined);
    void completed.catch(() => undefined);
    return {
        observeStdout: (chunk: string) => {
            pending += chunk;
            for (;;) {
                const newline = pending.indexOf('\n');
                if (newline === -1) break;
                const line = pending.slice(0, newline).trim();
                pending = pending.slice(newline + 1);
                if (!line) continue;
                const event = JSON.parse(line) as Record<string, unknown>;
                if (event.event === 'native-' + operation + '-ready') {
                    assert.ok(
                        !readySeen,
                        'The native operation announced readiness twice.',
                    );
                    readySeen = true;
                    readyResolve();
                } else if (
                    event.event ===
                    'native-' + operation + '-completed'
                ) {
                    assert.ok(
                        started && !completionSeen,
                        'The native operation completed outside its guarded operation.',
                    );
                    const milliseconds = event[elapsedField];
                    assert.ok(
                        typeof milliseconds === 'number' &&
                            Number.isFinite(milliseconds) &&
                            milliseconds >= 0,
                    );
                    completionSeen = true;
                    completeResolve(milliseconds);
                }
            }
        },
        stop: () => {
            if (finishReleased) return;
            const error = new Error(
                'The native operation exited before its guard handshake completed.',
            );
            readyReject(error);
            completeReject(error);
        },
        monitor: async () => {
            let peakMemory = 0;
            const samples = { initial: 0, periodic: 0, final: 0 };
            const sample = async (phase: NativeOperationSamplePhase) => {
                const bytes = await input.readMemory(phase);
                assert.ok(
                    bytes !== undefined &&
                        Number.isSafeInteger(bytes) &&
                        bytes > 0,
                    'The waiting native operation was not observed by the process guard.',
                );
                input.recordSample(phase, bytes);
                samples[phase]++;
                peakMemory = Math.max(peakMemory, bytes);
                assert.ok(
                    bytes <= input.memoryLimit,
                    'Native process-tree memory guard exceeded.',
                );
            };
            await ready;
            await sample('initial');
            // File creation can become visible before its promise resolves.
            // This authorization follows the sample, not that callback order.
            started = true;
            await writeFile(input.startFile, new Uint8Array(), { flag: 'wx' });
            for (;;) {
                let timer: ReturnType<typeof setTimeout> | undefined;
                const finished = await Promise.race([
                    completed.then(() => true),
                    new Promise<false>((resolve) => {
                        timer = setTimeout(() => resolve(false), 1000);
                    }),
                ]).finally(() => clearTimeout(timer));
                if (finished) break;
                await sample('periodic');
            }
            const operationMilliseconds = await completed;
            // This observation starts only after the completed event, rather
            // than relabeling a snapshot already in progress when it arrived.
            await sample('final');
            finishReleased = true;
            await writeFile(input.finishFile, new Uint8Array(), { flag: 'wx' });
            return { peakMemory, samples, operationMilliseconds };
        },
    };
};
