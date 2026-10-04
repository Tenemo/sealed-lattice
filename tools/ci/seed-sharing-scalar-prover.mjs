/** @typedef {{index:number,offset:number,length:number}} OutputAcknowledgment */
/** @typedef {{operation:string,phase:number,milliseconds:number}} ProverCall */
/** @typedef {{phase:number,steps:number,bytes:number,chunks:number,lastCall:ProverCall|undefined,maximumLinearMemoryBytes:number}} ProverProgress */
/** @typedef {{memory:WebAssembly.Memory,seed_prover_begin():number,seed_prover_phase():number,seed_prover_step():number,seed_prover_next_output():number,seed_prover_output_pointer():number,seed_prover_output_length():number,seed_prover_output_capacity():number,seed_prover_ack_output():number}} ProverApi */

/** @param {boolean} condition @param {string} message */
const requireCondition = (condition, message) => {
    if (!condition) throw new Error(message);
};

// One fixed synthetic positive proof, never a participant prover API. The
// host authenticates moduleBytes and owns the output sink. Every output span
// has one acknowledged consumer before Rust may release or replace it.
/**
 * @param {{moduleBytes:Uint8Array,expectedBytes:number,emitChunk:(index:number,offset:number,bytes:Uint8Array)=>Promise<OutputAcknowledgment>,onProgress?:(progress:ProverProgress)=>void}} input
 */
export const generateSeedSharingProof = async ({
    moduleBytes,
    expectedBytes,
    emitChunk,
    onProgress,
}) => {
    requireCondition(
        Number.isSafeInteger(expectedBytes) && expectedBytes > 0,
        'The expected proof length is invalid.',
    );
    const started = performance.now();
    const unavailable = (name) => () => {
        throw new Error('Scalar generation invoked ' + name);
    };
    const imports = {
        parallel: {
            helpers: () => 0,
            share: unavailable('parallel.share'),
            release: unavailable('parallel.release'),
            submit: unavailable('parallel.submit'),
            wait: unavailable('parallel.wait'),
            take: unavailable('parallel.take'),
            discard: unavailable('parallel.discard'),
            ended: unavailable('parallel.ended'),
            read: unavailable('parallel.read'),
        },
        // The fixed replay stream lives in Rust. Its host fallback must
        // never be exercised, and no JavaScript randomness substitutes for it.
        word_proof: { fill_random: unavailable('word_proof.fill_random') },
    };
    const compiled = await WebAssembly.compile(moduleBytes);
    for (const entry of WebAssembly.Module.imports(compiled))
        requireCondition(
            entry.kind === 'function' &&
                ((entry.module === 'parallel' &&
                    Object.keys(imports.parallel).includes(entry.name)) ||
                    (entry.module === 'word_proof' &&
                        entry.name === 'fill_random')),
            'Unknown scalar prover import.',
        );
    const instance = await WebAssembly.instantiate(compiled, imports);
    const api = /** @type {ProverApi} */ (
        /** @type {unknown} */ (instance.exports)
    );
    const initializationMilliseconds = performance.now() - started;
    let phase = 0;
    let steps = 0;
    let bytes = 0;
    let chunks = 0;
    let controlCases = 0;
    let maximumLinearMemoryBytes = api.memory.buffer.byteLength;
    /** @type {ProverCall|undefined} */
    let lastCall;
    /** @type {ProverCall|undefined} */
    let longestCall;
    /** @type {Map<string,{operation:string,phase:number,count:number,milliseconds:number,maximumMilliseconds:number}>} */
    const calls = new Map();
    /** @param {string} operation @param {()=>number} invoke */
    const call = (operation, invoke) => {
        const before = performance.now();
        try {
            return invoke();
        } finally {
            const milliseconds = performance.now() - before;
            maximumLinearMemoryBytes = Math.max(
                maximumLinearMemoryBytes,
                api.memory.buffer.byteLength,
            );
            lastCall = { operation, phase, milliseconds };
            if (
                longestCall === undefined ||
                milliseconds > longestCall.milliseconds
            )
                longestCall = lastCall;
            const key = phase + ':' + operation;
            let total = calls.get(key);
            if (total === undefined) {
                total = {
                    operation,
                    phase,
                    count: 0,
                    milliseconds: 0,
                    maximumMilliseconds: 0,
                };
                calls.set(key, total);
            }
            total.count++;
            total.milliseconds += milliseconds;
            total.maximumMilliseconds = Math.max(
                total.maximumMilliseconds,
                milliseconds,
            );
        }
    };
    const progress = () =>
        onProgress?.({
            phase,
            steps,
            bytes,
            chunks,
            lastCall,
            maximumLinearMemoryBytes,
        });
    const readPhase = () => {
        const next = call('phase', () => api.seed_prover_phase());
        requireCondition(
            Number.isInteger(next) && next >= phase && next <= 13,
            'The prover phase moved outside its one-shot sequence.',
        );
        phase = next;
    };
    // These deliberately invalid calls belong to this research fixture.
    // Refusal must preserve its pending bytes, not merely return code six.
    /** @param {string} operation @param {()=>number} invoke @param {Uint8Array|undefined} expected */
    const refusedControl = (operation, invoke, expected) => {
        const before = phase;
        requireCondition(
            call(operation, invoke) === 6,
            'The prover accepted an invalid control call: ' + operation,
        );
        requireCondition(
            call('phase', () => api.seed_prover_phase()) === before,
            'A refused control changed the prover phase: ' + operation,
        );
        const length = call('output_length', () =>
            api.seed_prover_output_length(),
        );
        requireCondition(
            length === (expected?.length ?? 0),
            'A refused control changed the pending output length: ' + operation,
        );
        if (expected !== undefined) {
            const pointer = call('output_pointer', () =>
                api.seed_prover_output_pointer(),
            );
            requireCondition(
                Number.isSafeInteger(pointer) &&
                    pointer >= 0 &&
                    pointer + length <= api.memory.buffer.byteLength,
                'A refused control left output outside memory.',
            );
            const current = new Uint8Array(api.memory.buffer, pointer, length);
            for (let index = 0; index < length; index++)
                requireCondition(
                    current[index] === expected[index],
                    'A refused control changed pending output bytes: ' +
                        operation,
                );
        }
        controlCases++;
    };
    const capacity = call('output_capacity', () =>
        api.seed_prover_output_capacity(),
    );
    requireCondition(
        Number.isSafeInteger(capacity) && capacity > 0 && capacity <= 1_048_576,
        'The prover output capacity exceeds its bound.',
    );
    requireCondition(
        call('begin', () => api.seed_prover_begin()) === 0,
        'The fixed prover could not begin.',
    );
    readPhase();
    requireCondition(
        phase >= 1 && phase <= 11,
        'The prover did not begin at a computational phase.',
    );
    refusedControl(
        'premature_ack_output',
        () => api.seed_prover_ack_output(),
        undefined,
    );
    progress();
    while (phase < 12) {
        requireCondition(
            call('step', () => api.seed_prover_step()) === 0,
            'The prover refused its next computational step.',
        );
        steps++;
        readPhase();
        progress();
        // Give the worker's event loop a real cancellation/progress boundary.
        await new Promise((resolve) => setTimeout(resolve, 0));
    }
    requireCondition(
        phase === 12,
        'The prover finished without an output stream.',
    );
    let lastReportedBytes = 0;
    while (phase === 12) {
        requireCondition(
            call('next_output', () => api.seed_prover_next_output()) === 0,
            'The prover refused its next output span.',
        );
        readPhase();
        const length = call('output_length', () =>
            api.seed_prover_output_length(),
        );
        requireCondition(
            Number.isSafeInteger(length) && length >= 0 && length <= capacity,
            'The prover output span exceeds its bound.',
        );
        if (phase === 13) {
            requireCondition(
                length === 0 && bytes === expectedBytes,
                'The prover finished at the wrong output boundary.',
            );
            break;
        }
        requireCondition(
            phase === 12 && length > 0 && bytes + length <= expectedBytes,
            'The prover output exceeds the pinned positive proof.',
        );
        const pointer = call('output_pointer', () =>
            api.seed_prover_output_pointer(),
        );
        requireCondition(
            Number.isSafeInteger(pointer) &&
                pointer >= 0 &&
                pointer + length <= api.memory.buffer.byteLength,
            'The prover output lies outside its current memory.',
        );
        {
            // A fresh view after every possible growth, then exactly one JS
            // copy. The first copy also checks the hostile control calls;
            // after those, no operation advances before the sink receipt.
            const output = new Uint8Array(
                api.memory.buffer,
                pointer,
                length,
            ).slice();
            if (chunks === 0) {
                refusedControl(
                    'step_with_pending_output',
                    () => api.seed_prover_step(),
                    output,
                );
                refusedControl(
                    'next_with_pending_output',
                    () => api.seed_prover_next_output(),
                    output,
                );
                refusedControl(
                    'rebegin_with_pending_output',
                    () => api.seed_prover_begin(),
                    output,
                );
            }
            const acknowledgment = await emitChunk(chunks, bytes, output);
            requireCondition(
                acknowledgment?.index === chunks &&
                    acknowledgment.offset === bytes &&
                    acknowledgment.length === length,
                'The proof sink acknowledged another output span.',
            );
        }
        requireCondition(
            call('ack_output', () => api.seed_prover_ack_output()) === 0,
            'The prover refused its acknowledged output span.',
        );
        if (chunks === 0)
            refusedControl(
                'duplicate_ack_output',
                () => api.seed_prover_ack_output(),
                undefined,
            );
        bytes += length;
        chunks++;
        if (bytes - lastReportedBytes >= 1_048_576) {
            progress();
            lastReportedBytes = bytes;
        }
    }
    progress();
    return {
        bytes,
        chunks,
        steps,
        controlCases,
        milliseconds: performance.now() - started,
        initializationMilliseconds,
        maximumLinearMemoryBytes,
        longestCall,
        calls: [...calls.values()],
    };
};
