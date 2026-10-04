import { verifyOpeningShareProof } from './opening-share-scalar.mjs';
import { streamScalarProof } from './scalar-proof-stream.mjs';
/** @typedef {{bytes: number, sha512: string}} Proof */
/** @typedef {import('./scalar-proof-stream.mjs').Probe} Probe */
/** @typedef {{name: string, code: number, suppliedBytes: number, maximumLinearMemoryBytes: number, milliseconds: number, proofSha512: string}} ProbeResult */
/** @typedef {{memory: WebAssembly.Memory, seed_verifier_input_capacity(): number, seed_verifier_header_length(): number, seed_verifier_input_pointer(): number, seed_verifier_begin(context: number, length: number): number, seed_verifier_push(length: number): number, seed_verifier_finish(): number}} VerifierApi */

/** @type {Probe[]} */
export const seedSharingProbes = [
    { name: 'honest', proof: 0, context: 0, expected: 0 },
    { name: 'false-seed', proof: 1, context: 1, expected: 5 },
    { name: 'false-share', proof: 2, context: 2, expected: 5 },
    { name: 'other-poll', proof: 0, context: 3, expected: 3 },
    { name: 'short-header', proof: 0, context: 0, headerCut: 1, expected: 2 },
    { name: 'truncated', proof: 0, context: 0, truncate: 1 },
    { name: 'trailing', proof: 0, context: 0, append: true },
    { name: 'changed-proof', proof: 0, context: 0, change: true },
];

/** @param {boolean} condition @param {string} message */
const requireCondition = (condition, message) => {
    if (!condition) throw new Error(message);
};

// The host authenticates module bytes and every read before this pump uses
// them. readExact returns an owned span no larger than the module's bounded
// input buffer. Host/ABI failures throw; only the owning Rust verifier emits
// a refusal code. The caller terminates this worker before the next probe.
/**
 * @param {{moduleBytes: Uint8Array, proof: Proof, probe: Probe, readExact: (length: number, position: number) => Promise<Uint8Array>,relation?:'seed-sharing'|'opening-share',predecessors?:Proof[],readPredecessor?:(index:number,length:number,position:number)=>Promise<Uint8Array>}} input
 * @returns {Promise<ProbeResult>}
 */
export const verifyBoundedProof = async ({
    moduleBytes,
    proof,
    probe,
    readExact,
    relation = 'seed-sharing',
    predecessors,
    readPredecessor,
}) => {
    const compiled = await WebAssembly.compile(moduleBytes);
    const unavailable = (name) => () => {
        throw new Error('Scalar verification invoked ' + name);
    };
    // The actual parallel-work scalar contract asks only for the helper
    // count. Every other host callback must fail without helpers.
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
    };
    for (const entry of WebAssembly.Module.imports(compiled))
        requireCondition(
            entry.kind === 'function' &&
                entry.module === 'parallel' &&
                Object.keys(imports.parallel).includes(entry.name),
            'Unknown scalar import.',
        );
    const instance = await WebAssembly.instantiate(compiled, imports);
    if (relation === 'opening-share') {
        requireCondition(
            predecessors !== undefined && readPredecessor !== undefined,
            'The opening verifier lacks its predecessor streams.',
        );
        return verifyOpeningShareProof({
            api: /** @type {import('./opening-share-scalar.mjs').OpeningApi} */ (
                /** @type {unknown} */ (instance.exports)
            ),
            predecessors: /** @type {Proof[]} */ (predecessors),
            readPredecessor:
                /** @type {(index:number,length:number,position:number)=>Promise<Uint8Array>} */ (
                    readPredecessor
                ),
            proof,
            probe,
            readExact,
        });
    }
    const api = /** @type {VerifierApi} */ (
        /** @type {unknown} */ (instance.exports)
    );
    return streamScalarProof({
        api: {
            memory: api.memory,
            inputCapacity: () => api.seed_verifier_input_capacity(),
            inputPointer: () => api.seed_verifier_input_pointer(),
            headerLength: () => api.seed_verifier_header_length(),
            begin: (context, length) =>
                api.seed_verifier_begin(context, length),
            push: (length) => api.seed_verifier_push(length),
            finish: () => api.seed_verifier_finish(),
        },
        proof,
        probe,
        readExact,
    });
};
