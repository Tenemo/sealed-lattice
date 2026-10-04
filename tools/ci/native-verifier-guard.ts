import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';

export type NativeVerifierSamplePhase = 'initial' | 'periodic' | 'final';

// The native reader waits at both boundaries, so a fast verification cannot
// disappear before its process is observed. These are sampled values, not
// an operating-system lifetime peak; short internal peaks can remain unseen.
export const createNativeVerifierGuard = (
    input: Readonly<{
        startFile: string;
        finishFile: string;
        memoryLimit: number;
        readMemory: (
            phase: NativeVerifierSamplePhase,
        ) => Promise<number | undefined>;
        recordSample: (phase: NativeVerifierSamplePhase, bytes: number) => void;
    }>,
) => {
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
                const event = JSON.parse(line) as {
                    event?: string;
                    verificationMilliseconds?: number;
                };
                if (event.event === 'native-verifier-ready') {
                    assert.ok(
                        !readySeen,
                        'The native reader announced readiness twice.',
                    );
                    readySeen = true;
                    readyResolve();
                } else if (event.event === 'native-verifier-completed') {
                    assert.ok(
                        started && !completionSeen,
                        'The native reader completed outside its guarded operation.',
                    );
                    assert.ok(
                        typeof event.verificationMilliseconds === 'number' &&
                            Number.isFinite(event.verificationMilliseconds) &&
                            event.verificationMilliseconds >= 0,
                    );
                    completionSeen = true;
                    completeResolve(event.verificationMilliseconds);
                }
            }
        },
        stop: () => {
            if (finishReleased) return;
            const error = new Error(
                'The native reader exited before its guard handshake completed.',
            );
            readyReject(error);
            completeReject(error);
        },
        monitor: async () => {
            let peakMemory = 0;
            const samples = { initial: 0, periodic: 0, final: 0 };
            const sample = async (phase: NativeVerifierSamplePhase) => {
                const bytes = await input.readMemory(phase);
                assert.ok(
                    bytes !== undefined &&
                        Number.isSafeInteger(bytes) &&
                        bytes > 0,
                    'The waiting native reader was not observed by the process guard.',
                );
                input.recordSample(phase, bytes);
                samples[phase]++;
                peakMemory = Math.max(peakMemory, bytes);
                assert.ok(
                    bytes <= input.memoryLimit,
                    'Verifier process-tree memory guard exceeded.',
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
            const verificationMilliseconds = await completed;
            // This observation starts only after the completed event, rather
            // than relabeling a snapshot already in progress when it arrived.
            await sample('final');
            finishReleased = true;
            await writeFile(input.finishFile, new Uint8Array(), { flag: 'wx' });
            return { peakMemory, samples, verificationMilliseconds };
        },
    };
};
