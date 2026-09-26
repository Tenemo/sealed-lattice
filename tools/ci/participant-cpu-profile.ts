// Summarizes the V8 CPU samples a Chrome trace recorded across its page and
// worker threads: the time each function spent at the top of a sampled stack
// and anywhere on it, counting a recursive function once per sample.
type CallFrame = Readonly<{ functionName?: string; url?: string }>;
type ProfileNode = Readonly<{
    id: number;
    parent?: number;
    callFrame: CallFrame;
}>;
type ProfileChunk = Readonly<{
    name?: unknown;
    pid?: unknown;
    id?: unknown;
    args?: Readonly<{
        data?: Readonly<{
            cpuProfile?: Readonly<{
                nodes?: readonly ProfileNode[];
                samples?: readonly number[];
            }>;
            timeDeltas?: readonly number[];
        }>;
    }>;
}>;

export type CpuProfileSummary = Readonly<{
    sampledMilliseconds: number;
    self: readonly Readonly<{ name: string; milliseconds: number }>[];
    inclusive: readonly Readonly<{ name: string; milliseconds: number }>[];
}>;

// Samples that name no work.
const idleFrames = new Set(['(root)', '(idle)', '(program)']);

const frameName = ({ functionName, url }: CallFrame) =>
    (functionName === undefined || functionName.length === 0
        ? '(anonymous)'
        : functionName) +
    (url === undefined || url.length === 0 || url.startsWith('wasm://')
        ? ''
        : ' ' + url);

const ranked = (totals: ReadonlyMap<string, number>, limit: number) =>
    [...totals]
        .sort((left, right) => right[1] - left[1])
        .slice(0, limit)
        .map(([name, microseconds]) => ({
            name,
            milliseconds: Math.round(microseconds) / 1000,
        }));

export const summarizeCpuTrace = (
    events: readonly unknown[],
    limit: number,
): CpuProfileSummary => {
    // A thread's profile arrives in chunks under one identifier, each adding
    // nodes and the samples that follow the previous chunk's.
    const profiles = new Map<
        string,
        { nodes: Map<number, ProfileNode>; samples: number[]; deltas: number[] }
    >();
    for (const event of events as readonly ProfileChunk[]) {
        if (event.name !== 'ProfileChunk') continue;
        const key = `${String(event.pid)}:${String(event.id)}`;
        let profile = profiles.get(key);
        if (profile === undefined) {
            profile = { nodes: new Map(), samples: [], deltas: [] };
            profiles.set(key, profile);
        }
        const data = event.args?.data;
        for (const node of data?.cpuProfile?.nodes ?? [])
            profile.nodes.set(node.id, node);
        profile.samples.push(...(data?.cpuProfile?.samples ?? []));
        profile.deltas.push(...(data?.timeDeltas ?? []));
    }
    const self = new Map<string, number>();
    const inclusive = new Map<string, number>();
    let sampled = 0;
    for (const { nodes, samples, deltas } of profiles.values())
        for (let index = 0; index < samples.length; index++) {
            // A sample lasts until the next one.
            const microseconds = Math.max(0, deltas[index + 1] ?? 0);
            const leaf = nodes.get(samples[index]);
            if (leaf === undefined || idleFrames.has(frameName(leaf.callFrame)))
                continue;
            sampled += microseconds;
            const leafName = frameName(leaf.callFrame);
            self.set(leafName, (self.get(leafName) ?? 0) + microseconds);
            const onStack = new Set<string>();
            for (
                let node: ProfileNode | undefined = leaf;
                node !== undefined;
                node =
                    node.parent === undefined
                        ? undefined
                        : nodes.get(node.parent)
            ) {
                const name = frameName(node.callFrame);
                if (idleFrames.has(name) || onStack.has(name)) continue;
                onStack.add(name);
                inclusive.set(name, (inclusive.get(name) ?? 0) + microseconds);
            }
        }
    return {
        sampledMilliseconds: Math.round(sampled) / 1000,
        self: ranked(self, limit),
        inclusive: ranked(inclusive, limit),
    };
};
