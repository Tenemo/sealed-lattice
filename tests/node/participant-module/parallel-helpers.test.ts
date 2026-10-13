import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { MessageChannel } from 'node:worker_threads';

import binaryen from 'binaryen';
import { describe, expect, it, vi } from 'vitest';

import {
    helperStartMilliseconds,
    startParallelHelpers,
} from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import type { ParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import { ResourceFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import { useHelperWorkers } from '#tests/node/participant-module/helper-workers-fixture.js';
import {
    payload,
    participantModule,
    failureOf,
} from '#tests/node/participant-module/packaged-participant-fixture.js';

const helperWorkers = useHelperWorkers();

// Starts helpers that settle the start only by their answers: the start's
// deadline is held back, and a real-time guard fails the test rather than
// letting it hang.
const realTimeout = setTimeout;

const realClearTimeout = clearTimeout;

const answeredStart = async (
    compiledModule: WebAssembly.Module,
    ports: readonly MessagePort[],
) => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    let guard: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            startParallelHelpers(compiledModule, ports, false),
            new Promise<never>((_resolve, reject) => {
                guard = realTimeout(() => {
                    reject(new Error('No helper answered.'));
                }, 60_000);
            }),
        ]);
    } finally {
        realClearTimeout(guard);
        vi.useRealTimers();
    }
};

// A stand-in module whose jobs complete with eight bytes (kind 3), exhaust
// the helper's memory through the allocator's import (kind 1), trap at once
// (kind 2) or after a long computation (kind 4), or name no job (any other
// kind); its input buffer holds the largest job input. As in the
// participant module, a run that never returned leaves the job's buffers
// held, so clearing them traps.
const standIn = await readFile(
    new URL('./fixtures/helper-jobs.wat', import.meta.url),
    'utf8',
);

// A stand-in whose job of kind 5 outputs the first eight bytes of its
// streamed part, of kind 6 reads one byte beyond that part, and of kind 7
// runs until the first byte of its streamed part is no longer zero, a gate
// the test opens in the arena, and then outputs the part's first eight
// bytes.
const streamingStandIn = await readFile(
    new URL('./fixtures/streamed-helper-jobs.wat', import.meta.url),
    'utf8',
);

const compileText = (text: string) => {
    const parsed = binaryen.parseText(text);
    try {
        if (!parsed.validate()) throw new Error('The stand-in is invalid.');
        return WebAssembly.compile(new Uint8Array(parsed.emitBinary()));
    } finally {
        parsed.dispose();
    }
};

type HostImports = Readonly<{
    submit: (
        kind: number,
        pin: number,
        parts: number,
        count: number,
        output: number,
    ) => number;
    wait: (ticket: number) => void;
    take: (ticket: number, pointer: number) => number;
    share: (pointer: number, length: number) => number;
    release: (handle: number) => void;
    discard: (ticket: number) => void;
    ended: (ticket: number) => number;
}>;

// A gated job of the streaming stand-in, whose streamed part is the gate
// byte and seven bytes it outputs, and which opens once the test sets that
// byte in the arena.
const gatedJob = (
    host: HostImports,
    memory: WebAssembly.Memory,
    arena: Uint8Array,
    output: string,
) => {
    const bytes = new TextEncoder().encode('\0' + output);
    new Uint8Array(memory.buffer).set(bytes, 1024);
    const gate = host.share(1024, bytes.length);
    new Uint32Array(memory.buffer, 0, 3).set([2, gate, 0]);
    const ticket = host.submit(7, 1, 0, 1, 8);
    host.release(gate);
    const at = Buffer.from(arena.buffer).indexOf(bytes);
    expect(at).toBeGreaterThanOrEqual(0);
    return {
        ticket,
        open: () => {
            arena[at] = 1;
        },
    };
};

// The worker's side of the stand-in's jobs, each one sixteen-byte part.
const standInHost = (helpers: ParallelHelpers) => {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const host = helpers.imports(() => memory) as unknown as HostImports;
    return {
        memory,
        host,
        submit: (kind: number, pin: number, output = 8) => {
            new Uint32Array(memory.buffer, 0, 3).set([0, 256, 16]);
            return host.submit(kind, pin, 0, 1, output);
        },
    };
};

describe('parallel job host', () => {
    it('hashes protocol frames in the packaged WebAssembly helper exactly as independent SHAKE256', async () => {
        const helpers = await startParallelHelpers(
            participantModule,
            helperWorkers.ports(2),
            false,
        );
        expect(helpers.count).toBe(2);
        try {
            const { memory, host } = standInHost(helpers);
            const prefix = Buffer.alloc(64);
            prefix.write('sealed-lattice/fixed-hash/v1', 'ascii');
            for (const length of [0, 1, 71, 72, 73, 135, 136, 137, 4097]) {
                const input = payload(length);
                const job = new Uint8Array(10 + input.length);
                job[0] = 1; // Finish a fresh stream.
                job[1] = 0; // The domain-separated protocol digest.
                new DataView(job.buffer).setBigUint64(
                    2,
                    BigInt(length + 1),
                    true,
                );
                job.set(input, 10);
                new Uint8Array(memory.buffer).set(job, 256);
                new Uint32Array(memory.buffer, 0, 3).set([0, 256, job.length]);
                const ticket = host.submit(0x0400, 1, 0, 1, 64);
                host.wait(ticket);
                expect(host.take(ticket, 64)).toBe(0);
                expect(
                    Buffer.from(new Uint8Array(memory.buffer, 64, 64)),
                ).toEqual(
                    createHash('shake256', { outputLength: 64 })
                        .update(prefix)
                        .update(input)
                        .digest(),
                );
            }
        } finally {
            helpers.stop();
        }
    });

    it("reports a job's output, a helper's exhausted memory, a trap that ends its helper's later jobs, and an exhausted arena", async () => {
        const compiledModule = await compileText(standIn);
        const helpers = await startParallelHelpers(
            compiledModule,
            helperWorkers.ports(2),
            false,
        );
        expect(helpers.count).toBe(2);
        try {
            const { memory, host, submit } = standInHost(helpers);
            const completed = submit(3, 1);
            host.wait(completed);
            expect(host.take(completed, 512)).toBe(0);
            expect(
                Buffer.from(new Uint8Array(memory.buffer, 512, 8)).toString(),
            ).toBe('complete');
            const outcome = (kind: number, pin: number) => {
                const failure = failureOf(() => host.wait(submit(kind, pin)));
                expect(failure).toBeInstanceOf(ResourceFailure);
                return (failure as Error).message;
            };
            expect(outcome(1, 1)).toBe(
                'A participant helper exhausted its memory bound.',
            );
            expect(outcome(2, 2)).toBe('A participant helper failed.');
            expect(outcome(3, 1)).toBe(
                'A participant helper exhausted its memory bound.',
            );
            expect(outcome(3, 2)).toBe('A participant helper failed.');
            expect(outcome(9, 0)).toMatch(/^A participant helper /u);
        } finally {
            helpers.stop();
        }
        const arenaHelpers = await startParallelHelpers(
            compiledModule,
            helperWorkers.ports(1),
            false,
        );
        try {
            const { submit } = standInHost(arenaHelpers);
            // Outputs of the largest declared length stay held until their
            // jobs are waited for, taken or discarded.
            let accepted = 0;
            const failure = failureOf(() => {
                for (; accepted < 64; accepted += 1) submit(3, 1, 8 << 20);
            });
            expect(failure).toBeInstanceOf(ResourceFailure);
            expect((failure as Error).message).toBe(
                'The shared arena bound is exhausted.',
            );
            expect(accepted).toBeGreaterThan(0);
        } finally {
            arenaHelpers.stop();
        }
    });

    it("reuses the arena range of an input its helper has copied, so held jobs' inputs may exceed the arena bound", async () => {
        const helpers = await startParallelHelpers(
            await compileText(standIn),
            helperWorkers.ports(1),
            false,
        );
        expect(helpers.count).toBe(1);
        try {
            const memory = new WebAssembly.Memory({ initial: 129 });
            const host = helpers.imports(
                () => memory,
            ) as unknown as HostImports;
            const inputBytes = 8 << 20;
            new Uint32Array(memory.buffer, 0, 3).set([0, 65_536, inputBytes]);
            // Forty such inputs held until their jobs are waited for would
            // exceed the arena's largest length.
            const tickets = Array.from({ length: 40 }, () =>
                host.submit(3, 1, 0, 1, 8),
            );
            expect(helpers.memory().arenaBytes).toBeLessThanOrEqual(32 << 20);
            for (const ticket of tickets) {
                host.wait(ticket);
                expect(host.take(ticket, 512)).toBe(0);
                expect(
                    Buffer.from(
                        new Uint8Array(memory.buffer, 512, 8),
                    ).toString(),
                ).toBe('complete');
            }
        } finally {
            helpers.stop();
        }
    });

    it('grows the arena by what its held outputs lack rather than doubling it', async () => {
        const helpers = await startParallelHelpers(
            await compileText(standIn),
            helperWorkers.ports(1),
            false,
        );
        expect(helpers.count).toBe(1);
        try {
            const { submit } = standInHost(helpers);
            // Five held outputs of eight mebibytes occupy forty beside their
            // small inputs, which a doubled arena would round up to
            // sixty-four.
            for (let job = 0; job < 5; job += 1) submit(3, 1, 8 << 20);
            const { arenaBytes } = helpers.memory();
            expect(arenaBytes).toBeGreaterThanOrEqual(40 << 20);
            expect(arenaBytes).toBeLessThanOrEqual(48 << 20);
        } finally {
            helpers.stop();
        }
    });

    it('releases the inputs of jobs that a trapped helper ended without copying them', async () => {
        const helpers = await startParallelHelpers(
            await compileText(standIn),
            helperWorkers.ports(1),
            false,
        );
        expect(helpers.count).toBe(1);
        try {
            const memory = new WebAssembly.Memory({ initial: 129 });
            const host = helpers.imports(
                () => memory,
            ) as unknown as HostImports;
            new Uint32Array(memory.buffer, 0, 3).set([0, 65_536, 16]);
            // The helper traps only after the worker waits for arena space
            // that the later jobs' inputs hold beyond the soft bound, which
            // it does before it submits them all.
            const trapping = host.submit(4, 1, 0, 1, 8);
            new Uint32Array(memory.buffer, 0, 3).set([0, 65_536, 8 << 20]);
            const waits = vi.spyOn(Atomics, 'wait');
            const tickets = Array.from({ length: 8 }, () =>
                host.submit(3, 1, 0, 1, 8),
            );
            expect(waits).toHaveBeenCalled();
            waits.mockRestore();
            for (const ticket of [trapping, ...tickets]) {
                const failure = failureOf(() => host.wait(ticket));
                expect(failure).toBeInstanceOf(ResourceFailure);
                expect((failure as Error).message).toBe(
                    'A participant helper failed.',
                );
            }
        } finally {
            helpers.stop();
        }
    });

    it('serves a streamed part to its job until the job ends, and fails a job that reads beyond it', async () => {
        const observed = helperWorkers.observedPorts(1);
        const helpers = await startParallelHelpers(
            await compileText(streamingStandIn),
            observed.ports,
            false,
        );
        expect(helpers.count).toBe(1);
        try {
            const memory = new WebAssembly.Memory({ initial: 1 });
            const host = helpers.imports(
                () => memory,
            ) as unknown as HostImports;
            const bytes = new Uint8Array(memory.buffer);
            const text = (offset: number) =>
                Buffer.from(bytes.subarray(offset, offset + 8)).toString();
            // The helper is still busy when the worker releases the part and
            // shares other bytes, which must not take the part's range.
            const busy = gatedJob(
                host,
                memory,
                observed.start().arena,
                'waiting',
            );
            bytes.set(new TextEncoder().encode('streamed'), 1024);
            const streamed = host.share(1024, 8);
            new Uint32Array(memory.buffer, 0, 3).set([2, streamed, 0]);
            const ticket = host.submit(5, 1, 0, 1, 8);
            host.release(streamed);
            bytes.set(new TextEncoder().encode('replaced'), 1024);
            const other = host.share(1024, 8);
            expect(host.ended(busy.ticket)).toBe(0);
            expect(host.ended(ticket)).toBe(0);
            busy.open();
            host.wait(busy.ticket);
            expect(host.take(busy.ticket, 256)).toBe(0);
            expect(text(256)).toBe('\u0001waiting');
            host.wait(ticket);
            expect(host.take(ticket, 512)).toBe(0);
            expect(text(512)).toBe('streamed');
            new Uint32Array(memory.buffer, 0, 3).set([2, other, 0]);
            const beyond = host.submit(6, 1, 0, 1, 8);
            const failure = failureOf(() => host.wait(beyond));
            expect(failure).toBeInstanceOf(ResourceFailure);
            expect((failure as Error).message).toBe(
                'A participant helper failed.',
            );
            // A job streams at most one part.
            new Uint32Array(memory.buffer, 0, 6).set([
                2,
                other,
                0,
                2,
                other,
                0,
            ]);
            expect(() => host.submit(5, 1, 0, 2, 8)).toThrow(
                'A parallel job exceeds its bound.',
            );
            host.release(other);
        } finally {
            helpers.stop();
        }
    });

    it('streams records the worker shares one after another as one part, up to the job bound', async () => {
        const helpers = await startParallelHelpers(
            await compileText(streamingStandIn),
            helperWorkers.ports(1),
            false,
        );
        expect(helpers.count).toBe(1);
        try {
            const memory = new WebAssembly.Memory({ initial: 1 });
            const host = helpers.imports(
                () => memory,
            ) as unknown as HostImports;
            const encoder = new TextEncoder();
            const joined = helpers.shareRecords([
                encoder.encode('str'),
                encoder.encode('eam'),
                encoder.encode('ed'),
            ]);
            new Uint32Array(memory.buffer, 0, 3).set([2, joined, 0]);
            const ticket = host.submit(5, 1, 0, 1, 8);
            host.release(joined);
            host.wait(ticket);
            expect(host.take(ticket, 512)).toBe(0);
            expect(
                Buffer.from(new Uint8Array(memory.buffer, 512, 8)).toString(),
            ).toBe('streamed');
            const half = new Uint8Array(4 << 20);
            host.release(helpers.shareRecords([half, half]));
            expect(() =>
                helpers.shareRecords([half, half, new Uint8Array(1)]),
            ).toThrow('A parallel input exceeds its bound.');
        } finally {
            helpers.stop();
        }
    });

    it('lets the worker await a running job while its other tasks run, and tells whether the job has ended', async () => {
        const observed = helperWorkers.observedPorts(1);
        const helpers = await startParallelHelpers(
            await compileText(streamingStandIn),
            observed.ports,
            false,
        );
        expect(helpers.count).toBe(1);
        try {
            const memory = new WebAssembly.Memory({ initial: 1 });
            const host = helpers.imports(
                () => memory,
            ) as unknown as HostImports;
            // The job runs until a timer the worker starts before it awaits
            // the job opens its gate.
            const gated = gatedJob(
                host,
                memory,
                observed.start().arena,
                'waiting',
            );
            const busy = gated.ticket;
            expect(host.ended(busy)).toBe(0);
            let fired = false;
            setTimeout(() => {
                fired = true;
                gated.open();
            }, 0);
            await helpers.whenEnded(busy);
            expect(fired).toBe(true);
            expect(host.ended(busy)).toBe(1);
            // A job that has ended resolves at once.
            await helpers.whenEnded(busy);
            host.wait(busy);
            expect(host.take(busy, 256)).toBe(0);
            // A taken job is no longer held.
            expect(() => host.ended(busy)).toThrow(
                'The parallel job is unknown.',
            );
            await expect(helpers.whenEnded(busy)).rejects.toThrow(
                'The parallel job is unknown.',
            );
        } finally {
            helpers.stop();
        }
    });

    it('clears the arena once no helper writes into it, so a job that ends after the worker stops leaves nothing there', async () => {
        const observed = helperWorkers.observedPorts(1);
        const helpers = await startParallelHelpers(
            await compileText(streamingStandIn),
            observed.ports,
            false,
        );
        expect(helpers.count).toBe(1);
        const { control, arena, layout } = observed.start();
        const memory = new WebAssembly.Memory({ initial: 1 });
        const host = helpers.imports(() => memory) as unknown as HostImports;
        const gated = gatedJob(host, memory, arena, 'written');
        // The helper runs the job once it has copied the job's input.
        while (Atomics.load(control, layout.copiedWord) === 0)
            expect(
                Atomics.wait(control, layout.copiedWord, 0, 60_000),
            ).not.toBe('timed-out');
        helpers.stop();
        expect(arena.every((byte) => byte === 0)).toBe(true);
        gated.open();
        await helpers.whenEnded(gated.ticket);
        expect(arena.filter((byte) => byte !== 0)).toEqual(new Uint8Array([1]));
    });

    it('refuses shares, jobs and held tickets one unit beyond their bounds, and unknown or released handles', async () => {
        const helpers = await startParallelHelpers(
            await compileText(standIn),
            helperWorkers.ports(2),
            false,
        );
        expect(helpers.count).toBe(2);
        try {
            const jobBytes = 8 << 20;
            const memory = new WebAssembly.Memory({ initial: 130 });
            const host = helpers.imports(
                () => memory,
            ) as unknown as HostImports;
            const exceeds = 'A parallel job exceeds its bound.';
            // Each part is its tag, its pointer or handle, and its length.
            const parts = (...values: number[]) => {
                new Uint32Array(memory.buffer, 0, values.length).set(values);
            };
            const copied = (length: number) => [0, 65_536, length];
            // Ends an accepted job, whatever its outcome, and frees its
            // ticket.
            const settle = (ticket: number) => {
                failureOf(() => {
                    host.wait(ticket);
                });
                host.discard(ticket);
            };
            host.release(host.share(65_536, jobBytes));
            expect(() => host.share(65_536, jobBytes + 1)).toThrow(
                'A parallel input exceeds its bound.',
            );
            const handle = host.share(65_536, 8);
            host.release(handle);
            expect(() => {
                host.release(handle);
            }).toThrow('The shared input is unknown.');
            parts(1, handle, 0);
            expect(() => host.submit(3, 1, 0, 1, 8)).toThrow(
                'The shared input is unknown.',
            );
            parts(3, 0, 0);
            expect(() => host.submit(3, 1, 0, 1, 8)).toThrow(
                'A parallel job part is malformed.',
            );
            parts(...[1, 2, 3, 4, 5].flatMap(() => copied(16)));
            settle(host.submit(3, 1, 0, 4, 8));
            expect(() => host.submit(3, 1, 0, 5, 8)).toThrow(exceeds);
            parts(...copied(16));
            settle(host.submit(3, 2, 0, 1, 8));
            expect(() => host.submit(3, 3, 0, 1, 8)).toThrow(exceeds);
            settle(host.submit(3, 1, 0, 1, jobBytes));
            expect(() => host.submit(3, 1, 0, 1, jobBytes + 1)).toThrow(
                exceeds,
            );
            parts(...copied(jobBytes - 16), ...copied(16));
            settle(host.submit(3, 1, 0, 2, 8));
            parts(...copied(jobBytes - 16), ...copied(17));
            expect(() => host.submit(3, 1, 0, 2, 8)).toThrow(exceeds);
            // A job's output is taken only after the worker waited for it,
            // and a discarded or unknown job's never.
            parts(...copied(16));
            const taken = host.submit(3, 1, 0, 1, 8);
            expect(host.take(taken, 512)).toBe(1);
            host.wait(taken);
            expect(host.take(taken, 512)).toBe(0);
            expect(host.take(taken, 512)).toBe(1);
            const discarded = host.submit(3, 1, 0, 1, 8);
            host.wait(discarded);
            host.discard(discarded);
            expect(host.take(discarded, 512)).toBe(1);
            expect(() => {
                host.wait(discarded);
            }).toThrow('The parallel job is unknown.');
            // The module holds at most 4096 tickets; a discarded one that
            // has ended frees its slot for the next job.
            const held = Array.from({ length: 4096 }, () =>
                host.submit(3, 0, 0, 0, 8),
            );
            expect(() => host.submit(3, 0, 0, 0, 8)).toThrow(
                'Too many parallel jobs are held.',
            );
            host.wait(held[0]);
            host.discard(held[0]);
            settle(host.submit(3, 0, 0, 0, 8));
        } finally {
            helpers.stop();
        }
    });

    it('runs every job in the worker when a helper refuses to start or has not started in time', async () => {
        for (const text of [
            '(module)',
            `(module
  (memory (export "memory") 1)
  (func (export "parallel_reserve") (param i32 i32) (result i32)
    (i32.const 1)))`,
        ]) {
            const helpers = await answeredStart(
                await compileText(text),
                helperWorkers.ports(2),
            );
            expect(helpers.count).toBe(0);
        }
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        const silent = new MessageChannel();
        helperWorkers.retainPort(silent.port2);
        let settled = false;
        const starting = startParallelHelpers(
            await compileText(standIn),
            [...helperWorkers.ports(1), silent.port1 as unknown as MessagePort],
            false,
        ).then((helpers) => {
            settled = true;
            return helpers;
        });
        await vi.advanceTimersByTimeAsync(helperStartMilliseconds - 1);
        expect(settled).toBe(false);
        await vi.advanceTimersByTimeAsync(1);
        expect(settled).toBe(true);
        expect((await starting).count).toBe(0);
    });
});
