import { pageBytes } from './parallel-layout.js';
import type { HelperStart } from './parallel-layout.js';

// A helper instance of the participant module, which runs the jobs the
// worker's host queues with every host function refused and its memory
// bounded to its share of the operation's memory plan.

/** The message with which the page starts a worker as a helper. */
export const helperRole = 'helper';
/** The module exports a helper calls. */
export const helperFunctions = [
    'parallel_reserve',
    'parallel_input',
    'parallel_streamed',
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

// The arena range of the running job's streamed part.
type StreamedPart = Readonly<{ offset: number; length: number }>;

// Instantiates the module with every host function refused but the reads of
// the running job's streamed part, the allocator's exhaustion told apart,
// and bounds its memory; undefined when it cannot.
const instantiateHelper = (
    { module, helpers, evaluation }: HelperStart,
    arena: Uint8Array,
    streamed: () => StreamedPart | undefined,
) => {
    const imports: Record<
        string,
        Record<string, (...values: number[]) => number | undefined>
    > = {};
    for (const entry of WebAssembly.Module.imports(module))
        (imports[entry.module] ??= {})[entry.name] = refuse;
    let instanceMemory: WebAssembly.Memory | undefined;
    // A helper has no helpers of its own.
    (imports.parallel ??= {}).helpers = () => 0;
    imports.parallel.read = (
        position: number,
        pointer: number,
        length: number,
    ) => {
        const part = streamed();
        const start = position >>> 0;
        const count = length >>> 0;
        if (
            part === undefined ||
            instanceMemory === undefined ||
            start > part.length ||
            count > part.length - start
        )
            throw new Error('A job read beyond its streamed part.');
        new Uint8Array(instanceMemory.buffer, pointer >>> 0, count).set(
            arena.subarray(part.offset + start, part.offset + start + count),
        );
        return undefined;
    };
    (imports.allocator ??= {}).exhausted = () => {
        throw exhaustion;
    };
    try {
        const { exports } = new WebAssembly.Instance(module, imports);
        instanceMemory = exports.memory as WebAssembly.Memory;
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
    let streamed: StreamedPart | undefined;
    const instance = instantiateHelper(helperStart, arena, () => streamed);
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
        const streamedPart = control[base + layout.streamedOffset] - 1;
        let length = 0;
        for (let part = 0; part < parts; part += 1)
            if (part !== streamedPart)
                length += control[base + 6 + 2 * part] >>> 0;
        const pointer = call('parallel_input', length);
        if (pointer === 0) return false;
        let target = memory();
        let at = pointer;
        for (let part = 0; part < parts; part += 1) {
            const offset = control[base + 5 + 2 * part] >>> 0;
            const partLength = control[base + 6 + 2 * part] >>> 0;
            if (part === streamedPart) {
                streamed = { offset, length: partLength };
                if (call('parallel_streamed', partLength) === 0) return false;
                continue;
            }
            target.set(arena.subarray(offset, offset + partLength), at);
            at += partLength;
        }
        // The helper reads the input's arena ranges no more, so the worker
        // may reuse them.
        Atomics.store(control, base + layout.copiedOffset, 1);
        Atomics.add(control, layout.copiedWord, 1);
        Atomics.notify(control, layout.copiedWord);
        // A call that ends without returning leaves the instance unusable,
        // so only a job whose calls returned clears its buffers.
        let completed = false;
        if (
            call('parallel_run', kind) === 0 &&
            call('parallel_output_length') === outputLength
        ) {
            const output = call('parallel_output_pointer');
            target = memory();
            // The worker clears the arena when it stops, once no helper
            // writes into it, so a helper writes its output only while it
            // counts itself as writing and the worker has not stopped.
            Atomics.add(control, layout.writingWord, 1);
            try {
                if (Atomics.load(control, layout.stopWord) === 0) {
                    arena.set(
                        target.subarray(output, output + outputLength),
                        outputOffset,
                    );
                    completed = true;
                }
            } finally {
                Atomics.sub(control, layout.writingWord, 1);
                Atomics.notify(control, layout.writingWord);
            }
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
        streamed = undefined;
        recordMemory();
        const stateWord = layout.slotBase + slot * layout.slotWords;
        Atomics.store(control, stateWord, state);
        Atomics.notify(control, stateWord);
        // A job that ended before its input was copied, or that streamed a
        // part, releases that input now, so a worker waiting for arena space
        // wakes.
        if (
            Atomics.load(control, stateWord + layout.copiedOffset) === 0 ||
            control[stateWord + layout.streamedOffset] !== 0
        ) {
            Atomics.add(control, layout.copiedWord, 1);
            Atomics.notify(control, layout.copiedWord);
        }
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
