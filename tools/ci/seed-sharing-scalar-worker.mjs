import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, readFile } from 'node:fs/promises';
import {
    isMainThread,
    parentPort,
    Worker,
    workerData,
} from 'node:worker_threads';

/** @typedef {{name: string, file: string, bytes: number, sha512: string}} Proof */
/** @typedef {{module: string, moduleSha512: string, proofs: Proof[]}} Configuration */
/** @typedef {{name: string, proof: number, context: number, expected?: number, headerCut?: number, truncate?: number, append?: boolean, change?: boolean}} Probe */
/** @typedef {{name: string, code: number, suppliedBytes: number, maximumLinearMemoryBytes: number, milliseconds: number, proofSha512: string}} ProbeResult */
/** @typedef {{memory: WebAssembly.Memory, seed_verifier_input_capacity(): number, seed_verifier_header_length(): number, seed_verifier_input_pointer(): number, seed_verifier_begin(context: number, length: number): number, seed_verifier_push(length: number): number, seed_verifier_finish(): number}} VerifierApi */

/** @param {string} file */
const digestFile = async (file) => {
    const digest = createHash('sha512');
    for await (const chunk of createReadStream(file)) {
        if (!(chunk instanceof Uint8Array))
            throw new Error('A proof read returned nonbinary data.');
        digest.update(chunk);
    }
    return digest.digest('hex');
};

if (isMainThread) {
    const configuration = /** @type {Configuration} */ (
        JSON.parse(await readFile(process.argv[2], 'utf8'))
    );
    /** @type {Probe[]} */
    const probes = [
        { name: 'honest', proof: 0, context: 0, expected: 0 },
        { name: 'false-seed', proof: 1, context: 1, expected: 5 },
        { name: 'false-share', proof: 2, context: 2, expected: 5 },
        { name: 'other-poll', proof: 0, context: 3, expected: 3 },
        {
            name: 'short-header',
            proof: 0,
            context: 0,
            headerCut: 1,
            expected: 2,
        },
        { name: 'truncated', proof: 0, context: 0, truncate: 1 },
        { name: 'trailing', proof: 0, context: 0, append: true },
        { name: 'changed-proof', proof: 0, context: 0, change: true },
    ];
    const results = [];
    // Each ended worker relinquishes its module and memory before the next
    // probe. No forced collection or shared-memory path is needed.
    for (const probe of probes) {
        /** @type {ProbeResult} */
        const result = await new Promise((resolve, reject) => {
            const worker = new Worker(new URL(import.meta.url), {
                workerData: { ...configuration, probe },
            });
            /** @type {ProbeResult | undefined} */
            let received;
            worker.on('message', (value) => {
                received = /** @type {ProbeResult} */ (value);
            });
            worker.on('error', reject);
            worker.on('exit', (code) => {
                if (code !== 0 || received === undefined)
                    reject(
                        new Error(
                            'The scalar verifier worker did not complete.',
                        ),
                    );
                else resolve(received);
            });
        });
        if (probe.expected === undefined)
            assert.notEqual(result.code, 0, probe.name);
        else assert.equal(result.code, probe.expected, probe.name);
        results.push(result);
    }
    console.log(
        JSON.stringify({ kind: 'scalar-seed-sharing-verification', results }),
    );
} else {
    const {
        module: modulePath,
        moduleSha512,
        proofs,
        probe,
    } = /** @type {Configuration & {probe: Probe}} */ (workerData);
    const proof = proofs[probe.proof];
    assert.equal(await digestFile(proof.file), proof.sha512);
    const bytes = await readFile(modulePath);
    assert.equal(
        createHash('sha512').update(bytes).digest('hex'),
        moduleSha512,
    );
    const compiled = await WebAssembly.compile(bytes);
    const unavailable = (name) => () => {
        throw new Error('Scalar verification invoked ' + name);
    };
    // The real parallel-work scalar contract asks only how many helpers
    // exist. No other host function may succeed without those helpers.
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
        assert.ok(
            entry.kind === 'function' &&
                Object.hasOwn(imports, entry.module) &&
                Object.hasOwn(imports[entry.module], entry.name),
            'Unknown scalar import.',
        );
    const instance = await WebAssembly.instantiate(compiled, imports);
    const api = /** @type {VerifierApi} */ (
        /** @type {unknown} */ (instance.exports)
    );
    const capacity = api.seed_verifier_input_capacity();
    const headerLength = api.seed_verifier_header_length();
    assert.ok(
        capacity > 0 &&
            capacity <= 1_048_576 &&
            headerLength > 0 &&
            headerLength <= capacity,
    );
    const file = await open(proof.file, 'r');
    const buffer = new Uint8Array(capacity);
    /** @param {number} length @param {number} position */
    const readExact = async (length, position) => {
        let filled = 0;
        while (filled < length) {
            const { bytesRead } = await file.read(
                buffer,
                filled,
                length - filled,
                position + filled,
            );
            assert.ok(
                bytesRead > 0,
                'The pinned proof ended during a bounded read.',
            );
            filled += bytesRead;
        }
    };
    let maximumLinearMemoryBytes = api.memory.buffer.byteLength;
    /** @param {number} length */
    const transfer = (length) => {
        const pointer = api.seed_verifier_input_pointer();
        assert.ok(
            pointer >= 0 && pointer + length <= api.memory.buffer.byteLength,
        );
        new Uint8Array(api.memory.buffer, pointer, length).set(
            buffer.subarray(0, length),
        );
    };
    const sample = () => {
        maximumLinearMemoryBytes = Math.max(
            maximumLinearMemoryBytes,
            api.memory.buffer.byteLength,
        );
    };
    const started = performance.now();
    let code;
    let suppliedBytes = 0;
    try {
        const readHeader = headerLength - (probe.headerCut ?? 0);
        await readExact(readHeader, 0);
        transfer(readHeader);
        code = api.seed_verifier_begin(probe.context, readHeader);
        suppliedBytes += readHeader;
        sample();
        const end = proof.bytes - (probe.truncate ?? 0);
        for (let offset = headerLength; code === 0 && offset < end;) {
            const length = Math.min(capacity, end - offset);
            await readExact(length, offset);
            if (probe.change && offset + length === end)
                buffer[length - 1] ^= 1;
            transfer(length);
            code = api.seed_verifier_push(length);
            suppliedBytes += length;
            offset += length;
            sample();
        }
        if (code === 0 && probe.append) {
            buffer[0] = 0;
            transfer(1);
            code = api.seed_verifier_push(1);
            suppliedBytes++;
            sample();
        }
        if (code === 0) code = api.seed_verifier_finish();
        sample();
    } finally {
        await file.close();
    }
    assert.equal(await digestFile(proof.file), proof.sha512);
    parentPort.postMessage({
        name: probe.name,
        code,
        suppliedBytes,
        maximumLinearMemoryBytes,
        milliseconds: performance.now() - started,
        proofSha512: proof.sha512,
    });
}
