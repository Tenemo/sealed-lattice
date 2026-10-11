/** @typedef {{index:number,offset:number,length:number}} OutputAcknowledgment */
/** @typedef {{operation:string,phase:number,milliseconds:number}} OutputCall */
/** @typedef {{phase:number,steps:number,bytes:number,chunks:number,lastCall:OutputCall|undefined,maximumLinearMemoryBytes:number}} OutputProgress */
/** @typedef {{memory:WebAssembly.Memory,begin():number,phase():number,step():number,next_output():number,output_pointer():number,output_length():number,output_capacity():number,ack_output():number}} OutputApi */
/** @param {boolean} condition @param {string} message */
const requireCondition = (condition, message) => {
    if (!condition) throw new Error(message);
};

// The producer owns its operation and one pending output span. The host
// copies that span once and acknowledges only after the sink completes.
/** @param {{api:OutputApi,expectedBytes:number,emitChunk:(index:number,offset:number,bytes:Uint8Array)=>Promise<OutputAcknowledgment>,onProgress?:(progress:OutputProgress)=>void}} input */
export const driveBoundedOutput = async ({
    api,
    expectedBytes,
    emitChunk,
    onProgress,
}) => {
    requireCondition(
        Number.isSafeInteger(expectedBytes) && expectedBytes > 0,
        'The expected output length is invalid.',
    );
    const started = performance.now();
    let phase = 0;
    let steps = 0;
    let bytes = 0;
    let chunks = 0;
    let controlCases = 0;
    let maximumLinearMemoryBytes = api.memory.buffer.byteLength;
    /** @type {OutputCall|undefined} */
    let lastCall;
    /** @type {OutputCall|undefined} */
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
        const next = call('phase', () => api.phase());
        requireCondition(
            Number.isInteger(next) && next >= phase && next <= 13,
            'The bounded output producer phase moved outside its one-shot sequence.',
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
            'The bounded output producer accepted an invalid control call: ' +
                operation,
        );
        requireCondition(
            call('phase', () => api.phase()) === before,
            'A refused control changed the producer phase: ' + operation,
        );
        const length = call('output_length', () => api.output_length());
        requireCondition(
            length === (expected?.length ?? 0),
            'A refused control changed the pending output length: ' + operation,
        );
        if (expected !== undefined) {
            const pointer = call('output_pointer', () => api.output_pointer());
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
    const capacity = call('output_capacity', () => api.output_capacity());
    requireCondition(
        Number.isSafeInteger(capacity) && capacity > 0 && capacity <= 1_048_576,
        'The bounded output producer output capacity exceeds its bound.',
    );
    requireCondition(
        call('begin', () => api.begin()) === 0,
        'The output producer could not begin.',
    );
    readPhase();
    requireCondition(
        phase >= 1 && phase <= 11,
        'The bounded output producer did not begin at a computational phase.',
    );
    refusedControl('premature_ack_output', () => api.ack_output(), undefined);
    progress();
    while (phase < 12) {
        requireCondition(
            call('step', () => api.step()) === 0,
            'The bounded output producer refused its next computational step.',
        );
        steps++;
        readPhase();
        progress();
        // Give the worker's event loop a real cancellation/progress boundary.
        await new Promise((resolve) => setTimeout(resolve, 0));
    }
    requireCondition(
        phase === 12,
        'The bounded output producer finished without an output stream.',
    );
    let lastReportedBytes = 0;
    while (phase === 12) {
        requireCondition(
            call('next_output', () => api.next_output()) === 0,
            'The bounded output producer refused its next output span.',
        );
        readPhase();
        const length = call('output_length', () => api.output_length());
        requireCondition(
            Number.isSafeInteger(length) && length >= 0 && length <= capacity,
            'The bounded output producer output span exceeds its bound.',
        );
        if (phase === 13) {
            requireCondition(
                length === 0 && bytes === expectedBytes,
                'The bounded output producer finished at the wrong output boundary.',
            );
            break;
        }
        requireCondition(
            phase === 12 && length > 0 && bytes + length <= expectedBytes,
            'The output exceeds its pinned length.',
        );
        const pointer = call('output_pointer', () => api.output_pointer());
        requireCondition(
            Number.isSafeInteger(pointer) &&
                pointer >= 0 &&
                pointer + length <= api.memory.buffer.byteLength,
            'The bounded output producer output lies outside its current memory.',
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
                    () => api.step(),
                    output,
                );
                refusedControl(
                    'next_with_pending_output',
                    () => api.next_output(),
                    output,
                );
                refusedControl(
                    'rebegin_with_pending_output',
                    () => api.begin(),
                    output,
                );
            }
            const acknowledgment = await emitChunk(chunks, bytes, output);
            requireCondition(
                acknowledgment?.index === chunks &&
                    acknowledgment.offset === bytes &&
                    acknowledgment.length === length,
                'The output sink acknowledged another output span.',
            );
        }
        requireCondition(
            call('ack_output', () => api.ack_output()) === 0,
            'The bounded output producer refused its acknowledged output span.',
        );
        if (chunks === 0)
            refusedControl(
                'duplicate_ack_output',
                () => api.ack_output(),
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
        maximumLinearMemoryBytes,
        longestCall,
        calls: [...calls.values()],
    };
};
