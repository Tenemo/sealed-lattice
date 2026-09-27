// Optional helper instances of the participant module. In a cross-origin
// isolated context the page starts one dedicated helper per spare core
// beside each operation's worker, from the same packaged worker source, and
// hands the worker one port to each. The worker sends every helper the same
// compiled module, which the helper instantiates with every host function
// refused and memory bounded to what one helper needs. The module submits
// deterministic jobs through a shared queue and later takes each output of
// the length it declared, so every output equals the one it computes alone;
// without helpers it runs every job itself. A job pinned to a helper runs
// there after that helper's earlier pinned jobs, which lets the module keep
// state on a helper between jobs. After startup the worker and its helpers
// exchange only shared memory. The helpers are the page's workers rather
// than the worker's own, so the worker's end never waits for theirs, and the
// page ends them all together. A helper that does not start in time leaves
// the module to run every job itself; a failed job and an exhausted arena
// end the operation as pending.

import { ResourceFailure } from './kernel.js';

// The module's job bounds, which the host enforces again.
const maximumJobBytes = 8 << 20;
const maximumJobParts = 4;
// The helpers an operation starts, whose bounded memories together stay
// near the worker's own linear-memory bound.
const maximumHelpers = 8;
/**
 * A helper that has not reported whether it started within this many
 * milliseconds counts as not started, first when the page loads it and then
 * when the worker starts it.
 */
export const helperStartMilliseconds = 10_000;
// The jobs the module may hold tickets for at once, which also bounds each
// queue.
const maximumTickets = 4096;
// The shared bytes the queued jobs, their outputs and the shared inputs may
// occupy together, and the granularity of their blocks.
const initialArenaBytes = 16 << 20;
const maximumArenaBytes = 256 << 20;
const blockAlignment = 64;

// A job slot's state. An exhausted job's helper found no memory within its
// bound.
const queued = 0;
const done = 1;
const failed = 2;
const exhausted = 3;

// The shared control words: a stop flag, one wake word per helper, the
// unpinned queue's head and tail, each helper's pinned queue head and tail,
// the queues' entries, the job slots and each helper's linear-memory pages.
// A slot holds its state, kind, output offset and length, part count and
// each part's offset and length.
const slotWords = 16;
const pageBytes = 65_536;
const controlLayout = (helpers: number) => {
    const wakeBase = 1;
    const unpinnedHead = wakeBase + helpers;
    const pinnedBase = unpinnedHead + 2;
    const entriesBase = pinnedBase + 2 * helpers;
    const slotBase = entriesBase + (helpers + 1) * maximumTickets;
    const memoryBase = slotBase + maximumTickets * slotWords;
    return {
        stopWord: 0,
        wakeBase,
        unpinnedHead,
        pinnedBase,
        entriesBase,
        slotBase,
        slotWords,
        memoryBase,
        queueEntries: maximumTickets,
        words: memoryBase + helpers,
        queued,
        done,
        failed,
        exhausted,
    } as const;
};
type ControlLayout = ReturnType<typeof controlLayout>;

type HelperStart = Readonly<{
    module: WebAssembly.Module;
    control: SharedArrayBuffer;
    arena: SharedArrayBuffer;
    layout: ControlLayout;
    index: number;
    helpers: number;
    evaluation: boolean;
}>;

/** The message with which the page starts a worker as a helper. */
export const helperRole = 'helper';
/** The module exports a helper calls. */
export const helperFunctions = [
    'parallel_reserve',
    'parallel_input',
    'parallel_run',
    'parallel_output_length',
    'parallel_output_pointer',
    'parallel_clear',
] as const;

const refuse = () => {
    throw new Error('A helper has no host functions.');
};
// What the allocator's import throws in a helper once no memory is left.
const exhaustion = new Error('A helper exhausted its memory bound.');

// Instantiates the module with every host function refused, the allocator's
// exhaustion told apart, and bounds its memory; undefined when it cannot.
const instantiateHelper = ({ module, helpers, evaluation }: HelperStart) => {
    const imports: Record<string, Record<string, () => number>> = {};
    for (const entry of WebAssembly.Module.imports(module))
        (imports[entry.module] ??= {})[entry.name] = refuse;
    // A helper has no helpers of its own.
    (imports.parallel ??= {}).helpers = () => 0;
    (imports.allocator ??= {}).exhausted = () => {
        throw exhaustion;
    };
    try {
        const { exports } = new WebAssembly.Instance(module, imports);
        const call = (name: string, ...values: number[]): number =>
            (exports[name] as (...values: number[]) => number)(...values) >>> 0;
        if (call('parallel_reserve', helpers, evaluation ? 1 : 0) !== 0)
            return undefined;
        return {
            call,
            memory: () =>
                new Uint8Array((exports.memory as WebAssembly.Memory).buffer),
        };
    } catch {
        return undefined;
    }
};

// A helper takes the module and the shared buffers, bounds its instance's
// memory, reports on the port whether it started, and runs its pinned jobs
// before unpinned ones until the worker stops it. A trapped instance ends
// every later job as its trap ended the job that trapped.
const runHelper = (port: MessagePort, helperStart: HelperStart) => {
    const { layout, index } = helperStart;
    const control = new Int32Array(helperStart.control);
    const arena = new Uint8Array(helperStart.arena);
    const instance = instantiateHelper(helperStart);
    if (instance === undefined) {
        port.postMessage(false);
        self.close();
        return;
    }
    const { call, memory } = instance;
    // The helper's linear memory, which the worker reports with the
    // operation.
    const memoryWord = layout.memoryBase + index;
    const recordMemory = () => {
        Atomics.store(control, memoryWord, memory().byteLength / pageBytes);
    };
    recordMemory();
    port.postMessage(true);
    const mask = layout.queueEntries - 1;
    const wake = layout.wakeBase + index;
    const pinnedHead = layout.pinnedBase + 2 * index;
    const pinnedEntries =
        layout.entriesBase + (index + 1) * layout.queueEntries;
    // The next pinned job, else an unpinned one another helper has not
    // claimed, else none.
    const next = () => {
        const head = Atomics.load(control, pinnedHead);
        if (head !== Atomics.load(control, pinnedHead + 1)) {
            const slot = Atomics.load(control, pinnedEntries + (head & mask));
            Atomics.store(control, pinnedHead, head + 1);
            return slot;
        }
        for (;;) {
            const shared = Atomics.load(control, layout.unpinnedHead);
            if (shared === Atomics.load(control, layout.unpinnedHead + 1))
                return -1;
            const slot = Atomics.load(
                control,
                layout.entriesBase + (shared & mask),
            );
            if (
                Atomics.compareExchange(
                    control,
                    layout.unpinnedHead,
                    shared,
                    shared + 1,
                ) === shared
            )
                return slot;
        }
    };
    const run = (slot: number) => {
        const base = layout.slotBase + slot * layout.slotWords;
        const kind = control[base + 1];
        const outputOffset = control[base + 2] >>> 0;
        const outputLength = control[base + 3] >>> 0;
        const parts = control[base + 4];
        let length = 0;
        for (let part = 0; part < parts; part += 1)
            length += control[base + 6 + 2 * part] >>> 0;
        const pointer = call('parallel_input', length);
        if (pointer === 0) return false;
        let target = memory();
        let at = pointer;
        for (let part = 0; part < parts; part += 1) {
            const offset = control[base + 5 + 2 * part] >>> 0;
            const partLength = control[base + 6 + 2 * part] >>> 0;
            target.set(arena.subarray(offset, offset + partLength), at);
            at += partLength;
        }
        // A call that ends without returning leaves the instance unusable,
        // so only a job whose calls returned clears its buffers.
        let completed = false;
        if (
            call('parallel_run', kind) === 0 &&
            call('parallel_output_length') === outputLength
        ) {
            target = memory();
            const output = call('parallel_output_pointer');
            arena.set(
                target.subarray(output, output + outputLength),
                outputOffset,
            );
            completed = true;
        }
        call('parallel_clear');
        return completed;
    };
    let trapped: number | undefined;
    for (;;) {
        const seen = Atomics.load(control, wake);
        if (Atomics.load(control, layout.stopWord) !== 0) break;
        const slot = next();
        if (slot < 0) {
            Atomics.wait(control, wake, seen);
            continue;
        }
        let state: number = trapped ?? layout.failed;
        if (trapped === undefined)
            try {
                if (run(slot)) state = layout.done;
            } catch (error) {
                trapped =
                    error === exhaustion ? layout.exhausted : layout.failed;
                state = trapped;
            }
        recordMemory();
        const stateWord = layout.slotBase + slot * layout.slotWords;
        Atomics.store(control, stateWord, state);
        Atomics.notify(control, stateWord);
    }
    self.close();
};

/**
 * Makes this worker a helper that the operation's worker starts on the port
 * the page handed it.
 */
export const listenAsHelper = (port: MessagePort) => {
    port.onmessage = (event: MessageEvent<HelperStart>) => {
        port.onmessage = null;
        runHelper(port, event.data);
    };
    port.onmessageerror = () => {
        port.postMessage(false);
        self.close();
    };
};

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
    }),
    memory: () => ({ helperBytes: 0, largestHelperBytes: 0, arenaBytes: 0 }),
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
// instantiated the module, with room for the evaluation's tables and kept
// keys when the operation evaluates. Without ports, beyond the helper
// bound, without growable shared memory, or when a helper fails to start or
// has not started in time, the module runs every job itself and every
// started helper stops.
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
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<readonly boolean[]>((resolve) => {
        timer = setTimeout(() => {
            resolve([false]);
        }, helperStartMilliseconds);
    });
    const answers = Promise.all(
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
    const started = await Promise.race([answers, deadline]);
    clearTimeout(timer);
    for (const port of ports) port.close();
    const host = createHost(count, new Int32Array(control), arena, layout);
    if (started.every(Boolean)) return host;
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
    const freeSlots = Array.from(
        { length: maximumTickets },
        (_unused, slot) => maximumTickets - 1 - slot,
    );
    let nextShare = 1;
    let nextTicket = 1;
    const stateWord = (slot: number) => layout.slotBase + slot * slotWords;

    // The arena is cleared once when the helpers stop; until then a returned
    // range holds only the operation's own bytes, which the worker and its
    // helpers already share.
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
    // Grows the arena by at least the length, up to its bound.
    const grow = (length: number) => {
        const previous = arenaBuffer.byteLength;
        const next = Math.min(
            maximumArenaBytes,
            Math.max(2 * previous, previous + length),
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
    const settle = (running: Running) => {
        if (running.settled) return;
        running.settled = true;
        for (const block of running.inputs) releaseBlock(block);
        for (const input of running.shared) dereference(input);
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
            sweep();
            const retry = firstFit(aligned);
            if (retry !== undefined) return retry;
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
            for (let part = 0; part < count; part += 1) {
                const tag = words[3 * part];
                if (tag === 0) total += words[3 * part + 2];
                else if (tag === 1) {
                    const input = shares.get(words[3 * part + 1]);
                    if (input === undefined)
                        throw new Error('The shared input is unknown.');
                    total += input.length;
                } else throw new Error('A parallel job part is malformed.');
            }
            if (total > maximumJobBytes)
                throw new Error('A parallel job exceeds its bound.');
            if (tickets.size >= maximumTickets) sweep();
            const slot = freeSlots.pop();
            if (slot === undefined)
                throw new Error('Too many parallel jobs are held.');
            const running: Running = {
                slot,
                inputs: [],
                shared: [],
                output: undefined,
                outputLength,
                settled: false,
            };
            const base = stateWord(slot);
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
                    running.shared.push(input);
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
            Atomics.store(control, base, queued);
            const ticket = nextTicket;
            nextTicket += 1;
            tickets.set(ticket, running);
            enqueue(pin, slot);
            return ticket;
        },
        wait: (ticket: number) => {
            const running = tickets.get(ticket);
            if (running === undefined || discarded.has(ticket))
                throw new Error('The parallel job is unknown.');
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
        // Each helper leaves its loop and closes; the page ends its worker.
        stop: () => {
            Atomics.store(control, layout.stopWord, 1);
            for (let helper = 0; helper < helpers; helper += 1)
                wakeHelper(helper);
            arena.fill(0);
        },
    };
};
