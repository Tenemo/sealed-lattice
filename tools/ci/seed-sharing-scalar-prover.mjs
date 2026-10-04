import { driveBoundedOutput } from './bounded-output.mjs';
import { admitOpeningSources } from './opening-share-scalar.mjs';
import { instantiateScalarModule } from './scalar-module.mjs';
/** @typedef {import('./scalar-proof-stream.mjs').Proof} Proof */
/** @typedef {import('./bounded-output.mjs').OutputAcknowledgment} OutputAcknowledgment */
/** @typedef {import('./bounded-output.mjs').OutputProgress} ProverProgress */

/** @param {boolean} condition @param {string} message */
const requireCondition = (condition, message) => {
    if (!condition) throw new Error(message);
};

// One fixed synthetic positive proof, never a participant prover API. The
// host authenticates moduleBytes and owns the output sink. Every output span
// has one acknowledged consumer before Rust may release or replace it.
/**
 * @param {{moduleBytes:Uint8Array,expectedBytes:number,emitChunk:(index:number,offset:number,bytes:Uint8Array)=>Promise<OutputAcknowledgment>,onProgress?:(progress:ProverProgress)=>void,relation?:'seed-sharing'|'opening-share',predecessors?:Proof[],readPredecessor?:(index:number,length:number,position:number)=>Promise<Uint8Array>}} input
 */
export const generateBoundedProof = async ({
    moduleBytes,
    expectedBytes,
    emitChunk,
    onProgress,
    relation = 'seed-sharing',
    predecessors,
    readPredecessor,
}) => {
    requireCondition(
        Number.isSafeInteger(expectedBytes) && expectedBytes > 0,
        'The expected proof length is invalid.',
    );
    const started = performance.now();
    const instance = await instantiateScalarModule(moduleBytes, {
        operation: 'generation',
        allowRandomnessFallback: true,
    });
    let sourceResults;
    if (relation === 'opening-share') {
        if (predecessors === undefined || readPredecessor === undefined)
            throw new Error(
                'The opening prover lacks its predecessor streams.',
            );
        sourceResults = await admitOpeningSources({
            api: /** @type {import('./opening-share-scalar.mjs').OpeningApi} */ (
                /** @type {unknown} */ (instance.exports)
            ),
            predecessors,
            readPredecessor,
        });
        requireCondition(
            sourceResults.length === 2 &&
                sourceResults.every((source) => source.code === 0),
            'The opening prover failed predecessor admission.',
        );
    }
    const prefix =
        relation === 'opening-share' ? 'opening_prover_' : 'seed_prover_';
    /** @param {string} name */
    const binding = (name) => {
        const method = instance.exports[prefix + name];
        requireCondition(
            typeof method === 'function',
            'The prover is missing its bounded ABI.',
        );
        return /** @type {()=>number} */ (method);
    };
    const api = {
        memory: /** @type {WebAssembly.Memory} */ (instance.exports.memory),
        begin: binding('begin'),
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
        ...(sourceResults === undefined ? {} : { sourceResults }),
        initializationMilliseconds,
        milliseconds: performance.now() - started,
        longestUninterruptedCallMilliseconds: Math.max(
            result.longestCall?.milliseconds ?? 0,
            ...(sourceResults?.map(
                (source) => source.longestCallMilliseconds,
            ) ?? []),
        ),
    };
};
