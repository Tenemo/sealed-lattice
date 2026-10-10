// The shared control layout of the parallel helpers: the queue and job slot
// words through which the worker's host and its helper instances exchange
// jobs after startup.

// The jobs the module may hold tickets for at once, which also bounds each
// queue.
export const maximumTickets = 4096;

// A job slot's state. An exhausted job's helper found no memory within its
// bound.
export const queued = 0;
export const done = 1;
const failed = 2;
export const exhausted = 3;

// The shared control words: a stop flag, one wake word per helper, the
// unpinned queue's head and tail, each helper's pinned queue head and tail,
// the queues' entries, the job slots, each helper's linear-memory pages, the
// count of inputs the helpers have copied and the count of helpers writing
// an output into the arena. A slot holds its state, kind,
// output offset and length, part count, each part's offset and length,
// whether its helper has copied its input, and one more than the index of
// its streamed part, or zero.
export const slotWords = 16;
const copiedOffset = 13;
const streamedOffset = 14;
export const pageBytes = 65_536;
export const controlLayout = (helpers: number) => {
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
        copiedOffset,
        streamedOffset,
        memoryBase,
        copiedWord: memoryBase + helpers,
        writingWord: memoryBase + helpers + 1,
        queueEntries: maximumTickets,
        words: memoryBase + helpers + 2,
        queued,
        done,
        failed,
        exhausted,
    } as const;
};
export type ControlLayout = ReturnType<typeof controlLayout>;

export type HelperStart = Readonly<{
    module: WebAssembly.Module;
    control: SharedArrayBuffer;
    arena: SharedArrayBuffer;
    layout: ControlLayout;
    index: number;
    helpers: number;
    evaluation: boolean;
}>;
