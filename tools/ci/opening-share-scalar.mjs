import {
    requireProofCondition,
    streamScalarProof,
} from './scalar-proof-stream.mjs';

/** @typedef {import('./scalar-proof-stream.mjs').Proof} Proof */
/** @typedef {import('./scalar-proof-stream.mjs').Probe} Probe */
/** @typedef {{memory:WebAssembly.Memory,opening_input_pointer():number,opening_input_capacity():number,opening_header_length():number,opening_source_begin(slot:number,length:number):number,opening_source_push(length:number):number,opening_source_finish():number,opening_verifier_begin(context:number,length:number):number,opening_verifier_push(length:number):number,opening_verifier_finish():number}} OpeningApi */
/** @type {Probe[]} */
export const openingShareProbes = [
    { name: 'honest', proof: 0, context: 0, expected: 0 },
    { name: 'shifted-share', proof: 1, context: 1, expected: 5 },
    { name: 'wrong-runtime', proof: 0, context: 2, expected: 3 },
    { name: 'wrong-recipient', proof: 0, context: 3, expected: 3 },
    { name: 'reversed-selection', proof: 0, context: 4, expected: 3 },
    { name: 'wrong-purpose', proof: 0, context: 5, expected: 3 },
    { name: 'short-header', proof: 0, context: 0, headerCut: 1, expected: 2 },
    { name: 'truncated', proof: 0, context: 0, truncate: 1 },
    { name: 'trailing', proof: 0, context: 0, append: true },
    { name: 'changed-proof', proof: 0, context: 0, change: true },
    ...[
        'missing-all',
        'missing-second',
        'first-slot-one',
        'repeated-slot',
        'reordered',
        'duplicate',
        'truncated',
        'changed',
    ].map((sourceControl) => ({
        name: 'source-' + sourceControl,
        proof: 0,
        context: 0,
        sourceControl: /** @type {Probe['sourceControl']} */ (sourceControl),
    })),
];

/** @param {OpeningApi} api @param {'source'|'verifier'} role @returns {import('./scalar-proof-stream.mjs').StreamApi} */
const streamApi = (api, role) => ({
    memory: api.memory,
    inputPointer: () => api.opening_input_pointer(),
    inputCapacity: () => api.opening_input_capacity(),
    headerLength: () => api.opening_header_length(),
    begin: (context, length) =>
        role === 'source'
            ? api.opening_source_begin(context, length)
            : api.opening_verifier_begin(context, length),
    push: (length) =>
        role === 'source'
            ? api.opening_source_push(length)
            : api.opening_verifier_push(length),
    finish: () =>
        role === 'source'
            ? api.opening_source_finish()
            : api.opening_verifier_finish(),
});

/** @param {{api:OpeningApi,predecessors:Proof[],readPredecessor:(index:number,length:number,position:number)=>Promise<Uint8Array>,control?:Probe['sourceControl']}} input */
export const admitOpeningSources = async ({
    api,
    predecessors,
    readPredecessor,
    control,
}) => {
    requireProofCondition(
        predecessors.length === 2,
        'The opening fixture requires two predecessor streams.',
    );
    /** @type {Awaited<ReturnType<typeof streamScalarProof>>[]} */
    const results = [];
    const count =
        control === 'missing-all' ? 0 : control === 'missing-second' ? 1 : 2;
    for (let slot = 0; slot < count; slot++) {
        const index =
            control === 'reordered'
                ? 1 - slot
                : control === 'duplicate'
                  ? 0
                  : slot;
        const context =
            control === 'first-slot-one'
                ? 1
                : control === 'repeated-slot'
                  ? 0
                  : slot;
        const result = await streamScalarProof({
            api: streamApi(api, 'source'),
            proof: predecessors[index],
            probe: {
                name: 'source-' + slot,
                proof: index,
                context,
                ...(control === 'truncated' && slot === 0
                    ? { truncate: 1 }
                    : {}),
                ...(control === 'changed' && slot === 1
                    ? { change: true }
                    : {}),
            },
            readExact: (length, position) =>
                readPredecessor(index, length, position),
        });
        results.push(result);
        if (result.code !== 0) break;
    }
    return results;
};

/** @param {{api:OpeningApi,predecessors:Proof[],readPredecessor:(index:number,length:number,position:number)=>Promise<Uint8Array>,proof:Proof,probe:Probe,readExact:(length:number,position:number)=>Promise<Uint8Array>}} input */
export const verifyOpeningShareProof = async ({
    api,
    predecessors,
    readPredecessor,
    proof,
    probe,
    readExact,
}) => {
    const started = performance.now();
    const sourceResults = await admitOpeningSources({
        api,
        predecessors,
        readPredecessor,
        control: probe.sourceControl,
    });
    const result = await streamScalarProof({
        api: streamApi(api, 'verifier'),
        proof,
        probe,
        readExact,
    });
    if (probe.sourceControl !== undefined) {
        const refusal =
            sourceResults.find((source) => source.code !== 0)?.code ?? 6;
        requireProofCondition(
            result.code === refusal,
            'An opening operation lost its invalid or incomplete predecessor refusal.',
        );
    } else
        requireProofCondition(
            sourceResults.length === 2 &&
                sourceResults.every((source) => source.code === 0),
            'An ordinary opening case failed predecessor admission.',
        );
    return {
        ...result,
        sourceResults,
        maximumLinearMemoryBytes: Math.max(
            result.maximumLinearMemoryBytes,
            ...sourceResults.map((source) => source.maximumLinearMemoryBytes),
        ),
        longestCallMilliseconds: Math.max(
            result.longestCallMilliseconds,
            ...sourceResults.map((source) => source.longestCallMilliseconds),
        ),
        milliseconds: performance.now() - started,
    };
};
