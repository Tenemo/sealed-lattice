import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
    openParticipant,
    verifyOutcome,
} from '#packages/sdk/src/participant/participant.js';
import { helperRole } from '#packages/sdk/src/participant/worker/module/parallel-helper-instance.js';

type Failure = 'constructor' | 'channel' | 'message' | 'error' | 'messageerror';
let failure: { worker: number; kind: Failure } | undefined;
let attempts = 0;
const workers: TestWorker[] = [];
const ports: { close: ReturnType<typeof vi.fn> }[] = [];
const replies: unknown[] = [];

class TestWorker {
    readonly identifier = ++attempts;
    readonly terminate = vi.fn();
    onmessage: ((event: { data: unknown }) => void) | null = null;
    onerror: ((event: { message: string }) => void) | null = null;
    onmessageerror: (() => void) | null = null;

    constructor() {
        if (this.fails('constructor'))
            throw new Error('Worker construction failed.');
        workers.push(this);
    }

    fails(kind: Failure) {
        return failure?.worker === this.identifier && failure.kind === kind;
    }

    postMessage(command: unknown) {
        if (this.fails('message')) throw new Error('Worker delivery failed.');
        queueMicrotask(() => {
            if (this.terminate.mock.calls.length > 0) return;
            if (this.fails('error'))
                this.onerror?.({ message: 'Worker execution failed.' });
            else if (this.fails('messageerror')) this.onmessageerror?.();
            else
                this.onmessage?.({
                    data:
                        command === helperRole
                            ? true
                            : (replies.shift() ?? {
                                  status: 'completed',
                                  details: { generation: 1 },
                              }),
                });
        });
    }
}

class TestMessageChannel {
    readonly port1: { close: ReturnType<typeof vi.fn> };
    readonly port2: { close: ReturnType<typeof vi.fn> };

    constructor() {
        if (failure?.worker === attempts && failure.kind === 'channel')
            throw new Error('Channel construction failed.');
        this.port1 = { close: vi.fn() };
        this.port2 = { close: vi.fn() };
        ports.push(this.port1, this.port2);
    }
}

beforeEach(() => {
    failure = undefined;
    attempts = 0;
    workers.length = ports.length = replies.length = 0;
    vi.stubGlobal('Worker', TestWorker);
    vi.stubGlobal('MessageChannel', TestMessageChannel);
    vi.stubGlobal('crossOriginIsolated', true);
    vi.stubGlobal('navigator', {
        hardwareConcurrency: 3,
        storage: { persist: () => Promise.resolve(true) },
    });
    vi.stubGlobal('__SEALED_LATTICE_PARTICIPANT_RUNTIME__', {
        worker: 'self.onmessage = () => {};',
        identity: { source: 'source', module: 'module', worker: 'worker' },
    });
});

afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
});

const run = () =>
    openParticipant({
        namespace: 'lifecycle',
        relay: 'https://relay.invalid/',
    }).run({ operation: 'status' });
const expectReleased = () => {
    for (const worker of workers)
        expect(worker.terminate).toHaveBeenCalledOnce();
    for (const port of ports) expect(port.close).toHaveBeenCalledOnce();
};

describe('page worker ownership', () => {
    it.each<Failure>(['constructor', 'channel', 'message', 'error'])(
        'falls back to scalar execution after a helper %s failure',
        async (kind) => {
            failure = { worker: 2, kind };
            expect(await run()).toMatchObject({ status: 'completed' });
            expect(attempts).toBe(3);
            expectReleased();
        },
    );

    it.each<Failure>(['constructor', 'message', 'error', 'messageerror'])(
        'returns pending and releases all helpers after a main worker %s failure',
        async (kind) => {
            failure = { worker: 3, kind };
            expect(await run()).toMatchObject({
                status: 'pending',
                cause: 'worker',
            });
            expectReleased();
        },
    );

    it('releases each completed group before restarting after evaluation', async () => {
        replies.push({ status: 'evaluated', memory: { moduleBytes: 65_536 } });
        expect(await run()).toMatchObject({
            status: 'completed',
            details: {
                evaluationMemory: { moduleBytes: 65_536 },
                isStoragePersistent: true,
            },
        });
        expect(attempts).toBe(6);
        expectReleased();
    });

    it('owns the outcome verifier workers through a failed message delivery', async () => {
        failure = { worker: 3, kind: 'message' };
        expect(
            await verifyOutcome({
                poll: 'ab'.repeat(64),
                relay: 'https://relay.invalid/',
            }),
        ).toMatchObject({ status: 'pending', cause: 'worker' });
        expectReleased();
    });

    it('completes without helpers when isolation is unavailable', async () => {
        vi.stubGlobal('crossOriginIsolated', false);
        expect(await run()).toMatchObject({ status: 'completed' });
        expect(attempts).toBe(1);
        expect(ports).toHaveLength(0);
        expectReleased();
    });
});
