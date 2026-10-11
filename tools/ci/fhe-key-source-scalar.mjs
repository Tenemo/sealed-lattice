import { driveBoundedOutput } from './bounded-output.mjs';
import { instantiateScalarModule } from './scalar-module.mjs';

export const fheKeySourcePhases = {
    0: 'initialization',
    1: 'original source',
    2: 'original public coordinate',
    3: 'restore into contribution',
    4: 'first gadget',
    5: 'independent checks and report',
    12: 'report output',
    13: 'complete',
};

/** @param {{moduleBytes:Uint8Array,caseIndex:number,expectedBytes:number,emitChunk:(index:number,offset:number,bytes:Uint8Array)=>Promise<import('./bounded-output.mjs').OutputAcknowledgment>,onProgress?:(progress:import('./bounded-output.mjs').OutputProgress)=>void}} input */
export const runFheKeySourceScreen = async ({
    moduleBytes,
    caseIndex,
    expectedBytes,
    emitChunk,
    onProgress,
}) => {
    if (caseIndex !== 0) throw new Error('Unknown key source screen case.');
    const started = performance.now();
    const instance = await instantiateScalarModule(moduleBytes);
    /** @param {string} name */
    const binding = (name) => {
        const method = instance.exports['key_source_screen_' + name];
        if (typeof method !== 'function')
            throw new Error('The operator screen is missing its bounded ABI.');
        return /** @type {(...values:number[])=>number} */ (method);
    };
    const begin = binding('begin');
    const api = {
        memory: /** @type {WebAssembly.Memory} */ (instance.exports.memory),
        begin: () => begin(caseIndex),
        phase: binding('phase'),
        step: binding('step'),
        next_output: binding('next_output'),
        output_pointer: binding('output_pointer'),
        output_length: binding('output_length'),
        output_capacity: binding('output_capacity'),
        ack_output: binding('ack_output'),
    };
    const initializationMilliseconds = performance.now() - started;
    const result = await driveBoundedOutput({
        api,
        expectedBytes,
        emitChunk,
        onProgress,
    });
    return {
        ...result,
        caseIndex,
        initializationMilliseconds,
        milliseconds: performance.now() - started,
        phaseLabels: fheKeySourcePhases,
    };
};
