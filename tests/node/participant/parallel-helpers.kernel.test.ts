import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { MessageChannel, Worker } from 'node:worker_threads';

import binaryen from 'binaryen';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createCanonicalManifest } from '#packages/sdk/dist/index.js';
import { readParticipantLimits } from '#packages/sdk/src/participant/worker/bounds.js';
import {
    concatenate,
    unsigned16,
    unsigned32,
} from '#packages/sdk/src/participant/worker/bytes.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '#packages/sdk/src/participant/worker/identity.js';
import {
    instantiateParticipantKernel,
    readKernel,
    ResourceFailure,
    writeInput,
} from '#packages/sdk/src/participant/worker/kernel.js';
import {
    helperStartMilliseconds,
    noParallelHelpers,
    startParallelHelpers,
} from '#packages/sdk/src/participant/worker/parallel.js';
import type { ParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import { dataKind } from '#packages/sdk/src/participant/worker/root.js';
import {
    registrationFile,
    registrationPath,
    streamRegistrations,
} from '#packages/sdk/src/participant/worker/roster.js';

// The packaged participant module and worker, whose helper role runs on
// threads here as the page starts it beside an operation's worker in a
// cross-origin isolated browser.
const distribution = new URL('../../../packages/sdk/dist/', import.meta.url);
const moduleBytes = await readFile(new URL('participant.wasm', distribution));
const participantModule = await WebAssembly.compile(moduleBytes);
const helperThread = `
const { parentPort, workerData } = require('node:worker_threads');
globalThis.self = globalThis;
self.postMessage = (message) => parentPort.postMessage(message);
self.close = () => process.exit(0);
import(workerData.source).then(() =>
    self.onmessage({ data: 'helper', ports: [workerData.port] }),
);
`;
const threads: Worker[] = [];
const silentPorts: { close: () => void }[] = [];
// Starts one packaged helper per port and returns the worker's ends.
const helperPorts = (count: number) =>
    Array.from({ length: count }, () => {
        const channel = new MessageChannel();
        threads.push(
            new Worker(helperThread, {
                eval: true,
                workerData: {
                    source: new URL('participant-worker.js', distribution).href,
                    port: channel.port2,
                },
                transferList: [channel.port2],
            }),
        );
        return channel.port1 as unknown as MessagePort;
    });

beforeEach(() => {
    vi.stubGlobal('crossOriginIsolated', true);
});
afterEach(async () => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    for (const port of silentPorts.splice(0)) port.close();
    await Promise.all(threads.splice(0).map((thread) => thread.terminate()));
});

// A custody identity as the foundation framing defines it, encoded here: the
// tuple header (schema 1, version 1, two items), the domain as an ASCII item
// (type 2) and the payload as a raw-bytes item (type 1), each item's length
// before its inner length, hashed with SHAKE256 to 64 bytes.
const independentIdentity = (domain: string, payload: Uint8Array) => {
    const label = Buffer.from(domain, 'ascii');
    const framing = Buffer.alloc(28 + label.length);
    let offset = framing.writeUInt16LE(1, 0);
    offset = framing.writeUInt16LE(1, offset);
    offset = framing.writeUInt32LE(2, offset);
    offset = framing.writeUInt16LE(2, offset);
    offset = framing.writeUInt32LE(4 + label.length, offset);
    offset = framing.writeUInt32LE(label.length, offset);
    offset += label.copy(framing, offset);
    offset = framing.writeUInt16LE(1, offset);
    offset = framing.writeUInt32LE(4 + payload.length, offset);
    framing.writeUInt32LE(payload.length, offset);
    return new Uint8Array(
        createHash('shake256', { outputLength: 64 })
            .update(framing)
            .update(payload)
            .digest(),
    );
};
const rootDomain = 'sealed-lattice/participant-root/v1';
const payload = (length: number) =>
    length === 0
        ? new Uint8Array()
        : new Uint8Array(
              createHash('shake256', { outputLength: length })
                  .update(String(length))
                  .digest(),
          );
// Lengths below, at and above the module's input buffer, and several whole
// buffers.
const payloadLengths = [
    0,
    1,
    65_535,
    65_536,
    65_537,
    1 << 20,
    (3 << 20) + 5,
] as const;

// Starts helpers that settle the start only by their answers: the start's
// deadline is held back, and a real-time guard fails the test rather than
// letting it hang.
const realTimeout = setTimeout;
const realClearTimeout = clearTimeout;
const answeredStart = async (
    module: WebAssembly.Module,
    ports: readonly MessagePort[],
) => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    let guard: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            startParallelHelpers(module, ports, false),
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

// The failure a call ends with, or undefined when it returns.
const failureOf = (call: () => unknown) => {
    try {
        call();
    } catch (error) {
        return error;
    }
    return undefined;
};

describe('participant custody identities', () => {
    it('encode the custody identity framing as its pinned independent vector', () => {
        // SHAKE256 over the empty public-polynomial identity, computed outside
        // the module.
        expect(
            Buffer.from(
                independentIdentity(
                    'sealed-lattice/public-polynomial/v1',
                    new Uint8Array(),
                ),
            ).toString('hex'),
        ).toBe(
            'c43f773788c6d66f30eb39ee7230312ad8dda3e5cbb3205075377d824eaa781d54b6dd3661553cb3c64ece7bd15a6df92fdd901b2ba81ae35334879f69fdf8a4',
        );
    });

    it('return the identities the independent framing yields', async () => {
        const { kernel } = await instantiateParticipantKernel(
            participantModule,
            noParallelHelpers,
        );
        expect(
            payloadLengths.map((length) =>
                custodyIdentity(kernel, custodyPurpose.root, payload(length)),
            ),
        ).toEqual(
            payloadLengths.map((length) =>
                independentIdentity(rootDomain, payload(length)),
            ),
        );
    });
});

// Enrollment inputs as the worker frames them. Every randomness request is
// answered from a SHAKE256 stream of the participant's name and the
// request's index, so an enrollment is a function of its inputs alone.
const shake = (label: string, length: number) =>
    new Uint8Array(
        createHash('shake256', { outputLength: length }).update(label).digest(),
    );
const runtimeIdentity = shake('runtime', 64);
type Enrollment = Readonly<{
    poll: Uint8Array;
    records: ReadonlyMap<number, Uint8Array>;
    requests: number;
}>;
type JoinedPoll = Readonly<{
    poll: Uint8Array;
    definition: Uint8Array;
    signature: Uint8Array;
}>;
type ParticipantInstance = Awaited<
    ReturnType<typeof instantiateParticipantKernel>
>;
// Validates and prepares an enrollment in the instance.
const prepare = (
    { kernel, handlers }: ParticipantInstance,
    name: string,
    joining?: JoinedPoll,
): Enrollment => {
    const username = new TextEncoder().encode(name);
    const input =
        joining === undefined
            ? concatenate(
                  runtimeIdentity,
                  unsigned16(1),
                  unsigned32(manifest.length),
                  manifest,
                  unsigned32(username.length),
                  username,
              )
            : concatenate(
                  joining.poll,
                  runtimeIdentity,
                  unsigned32(joining.definition.length),
                  joining.definition,
                  joining.signature,
                  unsigned32(username.length),
                  username,
              );
    writeInput(kernel, input);
    expect(
        joining === undefined
            ? kernel.validate_creator(input.length)
            : kernel.validate_join(input.length),
    ).toBe(0);
    const parts = new Map<number, Uint8Array[]>();
    handlers.staged = (kind, _offset, bytes) => {
        parts.set(kind, [...(parts.get(kind) ?? []), bytes.slice()]);
    };
    let requests = 0;
    handlers.random = (_source, target) => {
        target.set(shake(name + '/' + String(requests), target.length));
        requests += 1;
    };
    const control = concatenate(input, shake(name + '/data-keys', 64));
    writeInput(kernel, control);
    expect(
        joining === undefined
            ? kernel.prepare_creator(control.length)
            : kernel.prepare_join(control.length),
    ).toBe(0);
    expect(kernel.check_retained()).toBe(0);
    return {
        poll: readKernel(kernel, kernel.poll_identity_pointer(), 64),
        records: new Map(
            [...parts].map(([kind, chunks]) => [kind, concatenate(...chunks)]),
        ),
        requests,
    };
};
const enroll = async (
    helpers: ParallelHelpers,
    name: string,
    joining?: JoinedPoll,
) =>
    prepare(
        await instantiateParticipantKernel(participantModule, helpers),
        name,
        joining,
    );
const manifest = (
    await createCanonicalManifest({
        question: 'Which option leads?',
        options: ['Option 0', 'Option 1'],
    })
).canonicalBytes;

// A roster verifier's verdict on the registrations, streamed as the worker
// streams them from its relay: the proposal body it accepts, or undefined
// when a step or the roster is refused.
const verifyRoster = async (
    helpers: ParallelHelpers,
    poll: JoinedPoll,
    registrations: readonly ReadonlyMap<number, Uint8Array>[],
) => {
    const { kernel } = await instantiateParticipantKernel(
        participantModule,
        helpers,
    );
    const begin = concatenate(
        poll.poll,
        runtimeIdentity,
        unsigned16(registrations.length),
        unsigned32(poll.definition.length),
        poll.definition,
        poll.signature,
    );
    writeInput(kernel, begin);
    expect(kernel.roster_begin(begin.length)).toBe(0);
    const recordIds = registrations.map((_records, position) =>
        String(position).padStart(128, '0'),
    );
    const files = new Map(
        registrations.flatMap((records, position) =>
            (
                [
                    [registrationFile.header, dataKind.header],
                    [registrationFile.signature, dataKind.signature],
                    [registrationFile.publicKey, dataKind.publicKey],
                    [registrationFile.proof, dataKind.proof],
                ] as const
            ).map(([file, kind]) => [
                registrationPath(recordIds[position], file),
                records.get(kind)!,
            ]),
        ),
    );
    const relay = {
        base: 'unused/',
        transcript: {
            read: async (
                name: string,
                maximum: number,
                accept: (bytes: Uint8Array) => void | Promise<void>,
            ) => {
                const bytes = files.get(name)!;
                expect(bytes.length).toBeLessThanOrEqual(maximum);
                for (let offset = 0; offset < bytes.length; offset += 1 << 20)
                    await accept(bytes.subarray(offset, offset + (1 << 20)));
                return bytes.length;
            },
        },
    };
    try {
        await streamRegistrations(
            relay,
            recordIds,
            readParticipantLimits(kernel).registration,
            kernel.roster_open_records(),
            (operation, position, bytes) => {
                writeInput(kernel, bytes);
                return (
                    kernel.roster_record(operation, position, bytes.length) ===
                    0
                );
            },
        );
    } catch {
        return undefined;
    }
    return kernel.roster_finish() === 1
        ? readKernel(
              kernel,
              kernel.roster_body_pointer(),
              kernel.roster_body_length(),
          )
        : undefined;
};
// Runs an operation with three fresh helpers, as each operation's worker
// has its own.
const withHelpers = async <Value>(
    operation: (helpers: ParallelHelpers) => Promise<Value>,
) => {
    const helpers = await startParallelHelpers(
        participantModule,
        helperPorts(3),
        false,
    );
    expect(helpers.count).toBe(3);
    try {
        return await operation(helpers);
    } finally {
        helpers.stop();
    }
};
// A copy of the registrations with one byte of one record changed.
const changed = (
    registrations: readonly ReadonlyMap<number, Uint8Array>[],
    position: number,
    kind: number,
    offset: number,
) =>
    registrations.map((records, index) => {
        if (index !== position) return records;
        const bytes = records.get(kind)!.slice();
        bytes[offset] ^= 1;
        return new Map([...records, [kind, bytes]]);
    });

describe('participant helpers with registration work', () => {
    it('prove the registration the worker proves alone, and verify true and false rosters as it does', async () => {
        const alone = await enroll(noParallelHelpers, 'Organizer');
        const creator = await withHelpers((helpers) =>
            enroll(helpers, 'Organizer'),
        );
        expect(creator.requests).toBe(alone.requests);
        expect(creator.poll).toEqual(alone.poll);
        expect([...creator.records.keys()].sort()).toEqual(
            [...alone.records.keys()].sort(),
        );
        for (const [kind, bytes] of alone.records)
            expect(
                Buffer.from(creator.records.get(kind)!).equals(
                    Buffer.from(bytes),
                ),
                'staged record ' + String(kind),
            ).toBe(true);
        const poll = {
            poll: creator.poll,
            definition: creator.records.get(dataKind.pollDefinition)!,
            signature: creator.records.get(dataKind.pollSignature)!,
        };
        const registrations = [creator.records];
        for (const name of ['First voter', 'Second voter'])
            registrations.push(
                (await withHelpers((helpers) => enroll(helpers, name, poll)))
                    .records,
            );
        const proofBytes = registrations[1].get(dataKind.proof)!.length;
        // The true roster, a proof changed at its middle, a public key
        // coefficient changed and a signature changed.
        for (const [candidate, accepted] of [
            [registrations, true],
            [changed(registrations, 1, dataKind.proof, proofBytes >> 1), false],
            [changed(registrations, 2, dataKind.publicKey, 1000), false],
            [changed(registrations, 0, dataKind.signature, 7), false],
        ] as const) {
            const verdictAlone = await verifyRoster(
                noParallelHelpers,
                poll,
                candidate,
            );
            expect(verdictAlone !== undefined).toBe(accepted);
            expect(
                await withHelpers((helpers) =>
                    verifyRoster(helpers, poll, candidate),
                ),
            ).toEqual(verdictAlone);
        }
    });

    it('end the call whose job failed, and its instance refuses every later call', async () => {
        const helpers = await startParallelHelpers(
            participantModule,
            helperPorts(2),
            false,
        );
        expect(helpers.count).toBe(2);
        // Every job names a kind no helper runs.
        const failing: ParallelHelpers = {
            ...helpers,
            imports: (memory) => {
                const imports = helpers.imports(memory) as Record<
                    string,
                    (...values: number[]) => number
                >;
                return {
                    ...imports,
                    submit: (_kind: number, ...values: number[]) =>
                        imports.submit(0xffff, ...values),
                };
            },
        };
        try {
            const instance = await instantiateParticipantKernel(
                participantModule,
                failing,
            );
            const failure = failureOf(() => prepare(instance, 'Organizer'));
            expect(failure).toBeInstanceOf(ResourceFailure);
            expect((failure as Error).message).toBe(
                'A participant helper failed.',
            );
            expect(
                failureOf(() =>
                    instance.kernel.custody_identity_input_capacity(),
                ),
            ).toBe(failure);
            expect(
                failureOf(() =>
                    instance.kernel.custody_identity_begin(
                        custodyPurpose.root,
                        0,
                    ),
                ),
            ).toBe(failure);
        } finally {
            helpers.stop();
        }
        // A later operation's fresh helpers and instance complete the
        // enrollment.
        await withHelpers((fresh) => enroll(fresh, 'Organizer'));
    });
});

// A stand-in module whose jobs complete with eight bytes (kind 3), exhaust
// the helper's memory through the allocator's import (kind 1), trap at once
// (kind 2) or after a long computation (kind 4), or name no job (any other
// kind); its input buffer holds the largest job input. As in the
// participant module, a run that never returned leaves the job's buffers
// held, so clearing them traps.
const standIn = `(module
  (import "allocator" "exhausted" (func $exhausted (param i32)))
  (memory (export "memory") 130)
  (global $running (mut i32) (i32.const 0))
  (global $steps (mut i32) (i32.const 0))
  (data (i32.const 2048) "complete")
  (func (export "parallel_reserve") (param i32 i32) (result i32)
    (i32.const 0))
  (func (export "parallel_input") (param i32) (result i32)
    (i32.const 65536))
  (func (export "parallel_run") (param $kind i32) (result i32)
    (global.set $running (i32.const 1))
    (if (i32.eq (local.get $kind) (i32.const 1))
      (then (call $exhausted (i32.const 65536))))
    (if (i32.eq (local.get $kind) (i32.const 2))
      (then (unreachable)))
    (if (i32.eq (local.get $kind) (i32.const 4))
      (then
        (global.set $steps (i32.const 0))
        (loop $compute
          (global.set $steps (i32.add (global.get $steps) (i32.const 1)))
          (br_if $compute (i32.lt_u (global.get $steps) (i32.const 1000000000))))
        (unreachable)))
    (global.set $running (i32.const 0))
    (i32.ne (local.get $kind) (i32.const 3)))
  (func (export "parallel_output_length") (result i32)
    (i32.const 8))
  (func (export "parallel_output_pointer") (result i32)
    (i32.const 2048))
  (func (export "parallel_clear")
    (if (global.get $running)
      (then (unreachable)))))`;
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
}>;
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
    it("reports a job's output, a helper's exhausted memory, a trap that ends its helper's later jobs, and an exhausted arena", async () => {
        const module = await compileText(standIn);
        const helpers = await startParallelHelpers(
            module,
            helperPorts(2),
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
            module,
            helperPorts(1),
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
            helperPorts(1),
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

    it('releases the inputs of jobs that a trapped helper ended without copying them', async () => {
        const helpers = await startParallelHelpers(
            await compileText(standIn),
            helperPorts(1),
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
            // that the later jobs' inputs hold beyond the soft bound.
            const trapping = host.submit(4, 1, 0, 1, 8);
            new Uint32Array(memory.buffer, 0, 3).set([0, 65_536, 8 << 20]);
            const tickets = Array.from({ length: 8 }, () =>
                host.submit(3, 1, 0, 1, 8),
            );
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
                helperPorts(2),
            );
            expect(helpers.count).toBe(0);
        }
        vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
        const silent = new MessageChannel();
        silentPorts.push(silent.port2);
        let settled = false;
        const starting = startParallelHelpers(
            await compileText(standIn),
            [...helperPorts(1), silent.port1 as unknown as MessagePort],
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

describe('participant module memory', () => {
    it('ends the call that exhausts the linear-memory bound with a resource failure, and its instance refuses every later call', () => {
        const parsed = binaryen.readBinary(moduleBytes);
        const initialPages = parsed.getMemoryInfo().initial;
        parsed.dispose();
        const source = (name: string) =>
            JSON.stringify(
                pathToFileURL(
                    fileURLToPath(
                        new URL(
                            `../../../packages/sdk/src/participant/worker/${name}`,
                            import.meta.url,
                        ),
                    ),
                ).href,
            );
        // The engine refuses every growth beyond one page, which the
        // instance's first allocation needs.
        const child = spawnSync(
            process.execPath,
            [
                `--wasm-max-mem-pages=${String(initialPages + 1)}`,
                '--import',
                'tsx',
                '--input-type=module',
                '--eval',
                [
                    `const { instantiateParticipantKernel, ResourceFailure } = await import(${source('kernel.ts')});`,
                    `const { noParallelHelpers } = await import(${source('parallel.ts')});`,
                    `const bytes = await (await import('node:fs/promises')).readFile(${JSON.stringify(fileURLToPath(new URL('participant.wasm', distribution)))});`,
                    'const { kernel } = await instantiateParticipantKernel(await WebAssembly.compile(bytes), noParallelHelpers);',
                    'const failureOf = (call) => { try { call(); } catch (error) { return error; } };',
                    'const first = failureOf(() => kernel.custody_identity_begin(0, 0));',
                    'const later = failureOf(() => kernel.custody_identity_input_capacity());',
                    'process.stdout.write(JSON.stringify({ resource: first instanceof ResourceFailure, message: first?.message, same: later === first }));',
                ].join('\n'),
            ],
            { encoding: 'utf8' },
        );
        expect(child.status, child.stderr).toBe(0);
        const outcome = JSON.parse(child.stdout) as {
            resource: boolean;
            message: string;
            same: boolean;
        };
        expect(outcome.resource).toBe(true);
        expect(outcome.message).toMatch(
            /^The participant module exhausted its memory bound, \d+ bytes requested\.$/u,
        );
        expect(outcome.same).toBe(true);
    });
});
