/** @typedef {{bytes: number, sha512: string}} Proof */
/** @typedef {{name: string, proof: number, context: number, expected?: number, headerCut?: number, truncate?: number, append?: boolean, change?: boolean}} Probe */
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
 * @param {{moduleBytes: Uint8Array, proof: Proof, probe: Probe, readExact: (length: number, position: number) => Promise<Uint8Array>}} input
 * @returns {Promise<ProbeResult>}
 */
export const verifySeedSharingProof = async ({
    moduleBytes,
    proof,
    probe,
    readExact,
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
    const api = /** @type {VerifierApi} */ (
        /** @type {unknown} */ (instance.exports)
    );
    const capacity = api.seed_verifier_input_capacity();
    const headerLength = api.seed_verifier_header_length();
    requireCondition(
        capacity > 0 &&
            capacity <= 1_048_576 &&
            headerLength > 0 &&
            headerLength <= capacity,
        'The verifier input layout exceeds its bound.',
    );
    let maximumLinearMemoryBytes = api.memory.buffer.byteLength;
    /** @param {Uint8Array} bytes */
    const transfer = (bytes) => {
        const pointer = api.seed_verifier_input_pointer();
        requireCondition(
            bytes.length <= capacity &&
                pointer >= 0 &&
                pointer + bytes.length <= api.memory.buffer.byteLength,
            'The verifier input lies outside its memory.',
        );
        // Reacquire the view after every call that can grow linear memory.
        new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes);
    };
    /** @param {number} length @param {number} position */
    const read = async (length, position) => {
        requireCondition(
            length > 0 && length <= capacity,
            'A proof read exceeds the input bound.',
        );
        const bytes = await readExact(length, position);
        requireCondition(
            bytes instanceof Uint8Array && bytes.length === length,
            'A bounded proof read returned the wrong length.',
        );
        return bytes;
    };
    const sample = () => {
        maximumLinearMemoryBytes = Math.max(
            maximumLinearMemoryBytes,
            api.memory.buffer.byteLength,
        );
    };
    const started = performance.now();
    let suppliedBytes = 0;
    const readHeader = headerLength - (probe.headerCut ?? 0);
    transfer(await read(readHeader, 0));
    let code = api.seed_verifier_begin(probe.context, readHeader);
    suppliedBytes += readHeader;
    sample();
    const end = proof.bytes - (probe.truncate ?? 0);
    for (let offset = headerLength; code === 0 && offset < end;) {
        const length = Math.min(capacity, end - offset);
        const bytes = await read(length, offset);
        // Mutation follows the host's integrity check and never changes the
        // saved artifact or the browser's authenticated cached chunk.
        if (probe.change && offset + length === end) bytes[length - 1] ^= 1;
        transfer(bytes);
        code = api.seed_verifier_push(length);
        suppliedBytes += length;
        offset += length;
        sample();
    }
    if (code === 0 && probe.append) {
        transfer(new Uint8Array([0]));
        code = api.seed_verifier_push(1);
        suppliedBytes++;
        sample();
    }
    if (code === 0) code = api.seed_verifier_finish();
    sample();
    return {
        name: probe.name,
        code,
        suppliedBytes,
        maximumLinearMemoryBytes,
        milliseconds: performance.now() - started,
        proofSha512: proof.sha512,
    };
};
