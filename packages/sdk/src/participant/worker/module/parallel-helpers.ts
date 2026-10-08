import { ResourceFailure } from '../shared/failures.js';

import {
    controlLayout,
    done,
    exhausted,
    maximumTickets,
    pageBytes,
    queued,
    slotWords,
} from './parallel-layout.js';
import type { ControlLayout, HelperStart } from './parallel-layout.js';

// Optional helper instances of the participant module. In a cross-origin
// isolated context the page starts one dedicated helper per spare core beside
// each operation's worker, from the same packaged worker source, and hands the
// worker one port to each. The worker sends every helper the same compiled
// module, which the helper instantiates with every host function refused and
// memory bounded to its share of the operation's memory plan, as the worker
// bounds its own instance to what the helpers leave. The module submits
// deterministic jobs through a shared queue and later takes each output of the
// length it declared, so every output equals the one it computes alone; without
// helpers it runs every job itself. The module waits for a job, or leaves the
// worker to await its end while the worker's other tasks run. A job may stream
// one shared part, which its helper reads in pieces as it runs instead of
// copying it with the rest of its input. A job pinned to a helper runs there
// after that helper's earlier pinned jobs, which lets the module keep state on
// a helper between jobs. After startup the worker and its helpers exchange
// only shared memory. The helpers are the page's workers rather than the
// worker's own, so the worker's end never waits for theirs, and the page ends
// them all together. A helper that does not start in time leaves the module to
// run every job itself; a failed job and an exhausted arena end the operation
// as pending.

// The module's job bounds, which the host enforces again.
const maximumJobBytes = 8 << 20;
const maximumJobParts = 4;
// The helpers an operation starts, as many as the module's memory plan
// covers: it divides the absolute linear-memory bound between them and the
// worker.
const maximumHelpers = 8;
/**
 * A helper that has not reported whether it started within this many
 * milliseconds counts as not started, first when the page loads it and then
 * when the worker starts it.
 */
export const helperStartMilliseconds = 10_000;

// Whether every helper answers that it started before the start deadline.
export const allStartedInTime = async (
    answers: readonly Promise<boolean>[],
) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<boolean>((resolve) => {
        timer = setTimeout(() => {
            resolve(false);
        }, helperStartMilliseconds);
    });
    try {
        return await Promise.race([
            Promise.all(answers).then((started) => started.every(Boolean)),
            deadline,
        ]);
    } finally {
        clearTimeout(timer);
    }
};
// The shared bytes the queued jobs, their outputs and the shared inputs may
// occupy together, and the granularity of their blocks. Beyond the soft
// bound the arena grows only when no queued job's input remains for a
// helper to copy and so release.
const initialArenaBytes = 16 << 20;
const softArenaBytes = 32 << 20;
const maximumArenaBytes = 256 << 20;
const blockAlignment = 64;
// The arena grows by what an allocation lacks, in steps of this many bytes:
// its buffer reserves the largest length when it is created, so growing
// copies nothing, and a doubled length would hold memory nothing occupies.
const arenaGrowthBytes = 4 << 20;

export type ParallelHelpers = Readonly<{
    count: number;
    // The module's parallel imports, reading its memory through the getter.
    imports: (memory: () => WebAssembly.Memory) => WebAssembly.ModuleImports;
    // The linear memory the helpers hold together and the largest one's,
    // and the shared arena's length.
    memory: () => Readonly<{
        helperBytes: number;
        largestHelperBytes: number;
        arenaBytes: number;
    }>;
    // Shares records the worker read, one after another, for the module to
    // take by the returned handle; only helpers read shared bytes.
    shareRecords: (records: readonly Uint8Array[]) => number;
    // Resolves once the job of the ticket has ended, without blocking the
    // worker.
    whenEnded: (ticket: number) => Promise<void>;
    stop: () => void;
}>;

const noJobs = () => {
    throw new Error('No parallel job runs without helpers.');
};
// The module runs every job itself.
export const noParallelHelpers: ParallelHelpers = {
    count: 0,
    imports: () => ({
        helpers: () => 0,
        share: noJobs,
        release: noJobs,
        submit: noJobs,
        wait: noJobs,
        take: noJobs,
        discard: noJobs,
        ended: noJobs,
        read: noJobs,
    }),
    memory: () => ({ helperBytes: 0, largestHelperBytes: 0, arenaBytes: 0 }),
    shareRecords: noJobs,
    whenEnded: noJobs,
    stop: () => undefined,
};

/**
 * The helpers this context affords: one per core beside the worker's own,
 * only when shared memory is available.
 */
export const affordedHelpers = () => {
    if (
        !globalThis.crossOriginIsolated ||
        typeof SharedArrayBuffer !== 'function'
    )
        return 0;
    const cores = navigator.hardwareConcurrency;
    return Number.isSafeInteger(cores) && cores > 1
        ? Math.min(cores - 1, maximumHelpers)
        : 0;
};

// Starts the helpers listening on the ports and waits until each has
// instantiated the module, with room for the evaluation's tables and the
// polynomials its multiplications keep when the operation evaluates. Without
// ports, beyond the helper bound, without growable shared memory, or when a
// helper fails to start or has not started in time, the module runs every
// job itself and every started helper stops.
export const startParallelHelpers = async (
    module: WebAssembly.Module,
    ports: readonly MessagePort[],
    evaluation: boolean,
): Promise<ParallelHelpers> => {
    const count = ports.length;
    const arena =
        count === 0 ||
        count > maximumHelpers ||
        !globalThis.crossOriginIsolated ||
        typeof SharedArrayBuffer !== 'function'
            ? undefined
            : new SharedArrayBuffer(initialArenaBytes, {
                  maxByteLength: maximumArenaBytes,
              });
    if (arena === undefined || !arena.growable) {
        for (const port of ports) port.close();
        return noParallelHelpers;
    }
    const layout = controlLayout(count);
    const control = new SharedArrayBuffer(4 * layout.words);
    const started = await allStartedInTime(
        ports.map(
            (port, index) =>
                new Promise<boolean>((resolve) => {
                    port.onmessage = (event: MessageEvent<unknown>) => {
                        resolve(event.data === true);
                    };
                    port.onmessageerror = () => {
                        resolve(false);
                    };
                    const start: HelperStart = {
                        module,
                        control,
                        arena,
                        layout,
                        index,
                        helpers: count,
                        evaluation,
                    };
                    port.postMessage(start);
                }),
        ),
    );
    for (const port of ports) port.close();
    const host = createHost(count, new Int32Array(control), arena, layout);
    if (started) return host;
    host.stop();
    return noParallelHelpers;
};

// An arena range, whose length is a whole number of aligned units.
type Block = Readonly<{ offset: number; length: number }>;
type SharedInput = { block: Block; length: number; references: number };
type Running = {
    slot: number;
    inputs: Block[];
    shared: SharedInput[];
    // The shared input the job streams, which it reads until it ends.
    streamed: SharedInput[];
    // Whether the job's copied input ranges are still held for its helper.
    holding: boolean;
    output: Block | undefined;
    outputLength: number;
    settled: boolean;
};

const createHost = (
    helpers: number,
    control: Int32Array,
    arenaBuffer: SharedArrayBuffer,
    layout: ControlLayout,
): ParallelHelpers => {
    const arena = new Uint8Array(arenaBuffer);
    // Free arena ranges in offset order.
    const free: Block[] = [{ offset: 0, length: arenaBuffer.byteLength }];
    const shares = new Map<number, SharedInput>();
    const tickets = new Map<number, Running>();
    const discarded = new Set<number>();
    // The queued jobs whose input ranges are still held.
    const holding = new Set<Running>();
    const freeSlots = Array.from(
        { length: maximumTickets },
        (_unused, slot) => maximumTickets - 1 - slot,
    );
    let nextShare = 1;
    let nextTicket = 1;
    const stateWord = (slot: number) => layout.slotBase + slot * slotWords;

    // The arena is cleared once when the worker stops its helpers; until
    // then a returned range holds only the operation's own bytes, which the
    // worker and its helpers already share.
    const releaseBlock = (block: Block) => {
        if (block.length === 0) return;
        let index = free.findIndex((range) => range.offset > block.offset);
        if (index < 0) index = free.length;
        free.splice(index, 0, block);
        // Joins the neighbours of the returned range.
        for (const at of [index, index - 1])
            if (
                at >= 0 &&
                at + 1 < free.length &&
                free[at].offset + free[at].length === free[at + 1].offset
            )
                free.splice(at, 2, {
                    offset: free[at].offset,
                    length: free[at].length + free[at + 1].length,
                });
    };
    const firstFit = (length: number): Block | undefined => {
        const index = free.findIndex((range) => range.length >= length);
        if (index < 0) return undefined;
        const range = free[index];
        if (range.length === length) free.splice(index, 1);
        else
            free[index] = {
                offset: range.offset + length,
                length: range.length - length,
            };
        return { offset: range.offset, length };
    };
    // Grows the arena by what a range of the length lacks beyond the free
    // range that ends the arena, in whole steps, up to the soft bound from
    // below it and otherwise up to the largest length.
    const grow = (length: number) => {
        const previous = arenaBuffer.byteLength;
        const last = free.length === 0 ? undefined : free[free.length - 1];
        const tail =
            last !== undefined && last.offset + last.length === previous
                ? last.length
                : 0;
        const steps = Math.max(
            1,
            Math.ceil((length - tail) / arenaGrowthBytes),
        );
        const next = Math.min(
            previous < softArenaBytes ? softArenaBytes : maximumArenaBytes,
            previous + steps * arenaGrowthBytes,
        );
        if (next === previous) return false;
        try {
            arenaBuffer.grow(next);
        } catch {
            throw new ResourceFailure('The shared arena could not grow.');
        }
        releaseBlock({ offset: previous, length: next - previous });
        return true;
    };
    // Releases a job's copied inputs and, once it has ended, the part it
    // streamed.
    const releaseInputs = (running: Running, ended: boolean) => {
        if (running.holding) {
            running.holding = false;
            for (const block of running.inputs) releaseBlock(block);
            for (const input of running.shared) dereference(input);
        }
        if (ended) {
            for (const input of running.streamed) dereference(input);
            running.streamed = [];
        }
        if (running.streamed.length === 0) holding.delete(running);
    };
    // Releases the inputs that helpers have copied or whose jobs have ended.
    const releaseCopied = () => {
        for (const running of holding) {
            const word = stateWord(running.slot);
            const ended = Atomics.load(control, word) !== queued;
            if (
                ended ||
                Atomics.load(control, word + layout.copiedOffset) !== 0
            )
                releaseInputs(running, ended);
        }
    };
    const settle = (running: Running) => {
        if (running.settled) return;
        running.settled = true;
        releaseInputs(running, true);
    };
    const finish = (ticket: number, running: Running) => {
        settle(running);
        if (running.output !== undefined) releaseBlock(running.output);
        freeSlots.push(running.slot);
        tickets.delete(ticket);
        discarded.delete(ticket);
    };
    const dereference = (input: SharedInput) => {
        input.references -= 1;
        if (input.references === 0) releaseBlock(input.block);
    };
    // Finishes the discarded jobs that have ended.
    const sweep = () => {
        for (const ticket of discarded) {
            const running = tickets.get(ticket)!;
            if (Atomics.load(control, stateWord(running.slot)) !== queued)
                finish(ticket, running);
        }
    };
    const allocate = (length: number): Block => {
        const aligned = Math.ceil(length / blockAlignment) * blockAlignment;
        if (aligned === 0) return { offset: 0, length: 0 };
        for (;;) {
            const block = firstFit(aligned);
            if (block !== undefined) return block;
            const copied = Atomics.load(control, layout.copiedWord);
            releaseCopied();
            sweep();
            const retry = firstFit(aligned);
            if (retry !== undefined) return retry;
            // Beyond the soft bound, a queued job's input that its helper
            // will copy frees memory without growing the arena.
            if (arenaBuffer.byteLength >= softArenaBytes && holding.size > 0) {
                Atomics.wait(control, layout.copiedWord, copied);
                continue;
            }
            if (!grow(aligned)) {
                // Only a discarded job still frees memory without the module.
                const [ticket] = discarded;
                if (ticket === undefined)
                    throw new ResourceFailure(
                        'The shared arena bound is exhausted.',
                    );
                awaitEnd(tickets.get(ticket)!.slot);
                sweep();
            }
        }
    };
    // The running job of a ticket the module holds.
    const heldJob = (ticket: number) => {
        const running = tickets.get(ticket);
        if (running === undefined || discarded.has(ticket))
            throw new Error('The parallel job is unknown.');
        return running;
    };
    const awaitEnd = (slot: number) => {
        const word = stateWord(slot);
        for (;;) {
            const state = Atomics.load(control, word);
            if (state !== queued) return state;
            Atomics.wait(control, word, state);
        }
    };
    const wakeHelper = (helper: number) => {
        Atomics.add(control, layout.wakeBase + helper, 1);
        Atomics.notify(control, layout.wakeBase + helper);
    };
    const enqueue = (pin: number, slot: number) => {
        const head =
            pin === 0 ? layout.unpinnedHead : layout.pinnedBase + 2 * (pin - 1);
        const tail = Atomics.load(control, head + 1);
        const entries = layout.entriesBase + pin * layout.queueEntries;
        Atomics.store(
            control,
            entries + (tail & (layout.queueEntries - 1)),
            slot,
        );
        Atomics.store(control, head + 1, tail + 1);
        if (pin === 0)
            for (let helper = 0; helper < helpers; helper += 1)
                wakeHelper(helper);
        else wakeHelper(pin - 1);
    };

    const imports = (memory: () => WebAssembly.Memory) => ({
        helpers: () => helpers,
        share: (pointer: number, length: number) => {
            if (length > maximumJobBytes)
                throw new Error('A parallel input exceeds its bound.');
            const block = allocate(length);
            arena.set(
                new Uint8Array(memory().buffer, pointer >>> 0, length),
                block.offset,
            );
            const handle = nextShare;
            nextShare += 1;
            shares.set(handle, { block, length, references: 1 });
            return handle;
        },
        release: (handle: number) => {
            const input = shares.get(handle);
            if (input === undefined)
                throw new Error('The shared input is unknown.');
            shares.delete(handle);
            dereference(input);
        },
        submit: (
            kind: number,
            pin: number,
            partsPointer: number,
            count: number,
            outputLength: number,
        ) => {
            if (
                count > maximumJobParts ||
                pin > helpers ||
                outputLength > maximumJobBytes
            )
                throw new Error('A parallel job exceeds its bound.');
            const words = new Uint32Array(
                memory().buffer,
                partsPointer >>> 0,
                3 * count,
            ).slice();
            let total = 0;
            let streamedParts = 0;
            for (let part = 0; part < count; part += 1) {
                const tag = words[3 * part];
                if (tag === 0) total += words[3 * part + 2];
                else if (tag === 1 || tag === 2) {
                    const input = shares.get(words[3 * part + 1]);
                    if (input === undefined)
                        throw new Error('The shared input is unknown.');
                    total += input.length;
                    if (tag === 2) streamedParts += 1;
                } else throw new Error('A parallel job part is malformed.');
            }
            if (total > maximumJobBytes || streamedParts > 1)
                throw new Error('A parallel job exceeds its bound.');
            if (tickets.size >= maximumTickets) sweep();
            const slot = freeSlots.pop();
            if (slot === undefined)
                throw new Error('Too many parallel jobs are held.');
            const running: Running = {
                slot,
                inputs: [],
                shared: [],
                streamed: [],
                holding: true,
                output: undefined,
                outputLength,
                settled: false,
            };
            const base = stateWord(slot);
            control[base + layout.streamedOffset] = 0;
            for (let part = 0; part < count; part += 1) {
                let offset: number;
                let length: number;
                if (words[3 * part] === 0) {
                    length = words[3 * part + 2];
                    const block = allocate(length);
                    arena.set(
                        new Uint8Array(
                            memory().buffer,
                            words[3 * part + 1],
                            length,
                        ),
                        block.offset,
                    );
                    running.inputs.push(block);
                    offset = block.offset;
                } else {
                    const input = shares.get(words[3 * part + 1])!;
                    input.references += 1;
                    if (words[3 * part] === 2) {
                        running.streamed.push(input);
                        control[base + layout.streamedOffset] = part + 1;
                    } else running.shared.push(input);
                    offset = input.block.offset;
                    length = input.length;
                }
                control[base + 5 + 2 * part] = offset;
                control[base + 6 + 2 * part] = length;
            }
            if (outputLength > 0) running.output = allocate(outputLength);
            control[base + 1] = kind;
            control[base + 2] = running.output?.offset ?? 0;
            control[base + 3] = outputLength;
            control[base + 4] = count;
            control[base + layout.copiedOffset] = 0;
            Atomics.store(control, base, queued);
            const ticket = nextTicket;
            nextTicket += 1;
            tickets.set(ticket, running);
            if (count > 0) holding.add(running);
            else running.holding = false;
            enqueue(pin, slot);
            return ticket;
        },
        wait: (ticket: number) => {
            const running = heldJob(ticket);
            const state = awaitEnd(running.slot);
            settle(running);
            if (state === exhausted)
                throw new ResourceFailure(
                    'A participant helper exhausted its memory bound.',
                );
            if (state !== done)
                throw new ResourceFailure('A participant helper failed.');
        },
        take: (ticket: number, pointer: number) => {
            const running = tickets.get(ticket);
            if (
                running === undefined ||
                !running.settled ||
                discarded.has(ticket) ||
                Atomics.load(control, stateWord(running.slot)) !== done
            )
                return 1;
            if (running.output !== undefined)
                new Uint8Array(
                    memory().buffer,
                    pointer >>> 0,
                    running.outputLength,
                ).set(
                    arena.subarray(
                        running.output.offset,
                        running.output.offset + running.outputLength,
                    ),
                );
            finish(ticket, running);
            return 0;
        },
        discard: (ticket: number) => {
            const running = tickets.get(ticket);
            if (running === undefined) return;
            discarded.add(ticket);
            sweep();
        },
        ended: (ticket: number) =>
            Atomics.load(control, stateWord(heldJob(ticket).slot)) === queued
                ? 0
                : 1,
        read: () => {
            throw new Error('Only a helper serves a streamed part.');
        },
    });
    return {
        count: helpers,
        imports,
        memory: () => {
            let helperBytes = 0;
            let largestHelperBytes = 0;
            for (let helper = 0; helper < helpers; helper += 1) {
                const bytes =
                    Atomics.load(control, layout.memoryBase + helper) *
                    pageBytes;
                helperBytes += bytes;
                largestHelperBytes = Math.max(largestHelperBytes, bytes);
            }
            return {
                helperBytes,
                largestHelperBytes,
                arenaBytes: arenaBuffer.byteLength,
            };
        },
        shareRecords: (records: readonly Uint8Array[]) => {
            const length = records.reduce(
                (sum, record) => sum + record.length,
                0,
            );
            if (length > maximumJobBytes)
                throw new Error('A parallel input exceeds its bound.');
            const block = allocate(length);
            let offset = block.offset;
            for (const record of records) {
                arena.set(record, offset);
                offset += record.length;
            }
            const handle = nextShare;
            nextShare += 1;
            shares.set(handle, { block, length, references: 1 });
            return handle;
        },
        whenEnded: async (ticket: number) => {
            const word = stateWord(heldJob(ticket).slot);
            for (;;) {
                const state = Atomics.load(control, word);
                if (state !== queued) return;
                const waited = Atomics.waitAsync(control, word, state);
                if (waited.async) await waited.value;
            }
        },
        // Each helper leaves its loop and closes; the page ends its worker.
        // The arena is cleared once no helper writes an output into it: a
        // helper that counts itself as writing only after the stop writes
        // nothing, and a running job's later output is dropped.
        stop: () => {
            Atomics.store(control, layout.stopWord, 1);
            for (let helper = 0; helper < helpers; helper += 1)
                wakeHelper(helper);
            for (;;) {
                const writing = Atomics.load(control, layout.writingWord);
                if (writing === 0) break;
                Atomics.wait(control, layout.writingWord, writing);
            }
            arena.fill(0);
        },
    };
};
