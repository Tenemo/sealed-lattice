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

import {
    seedSharingProbes,
    verifySeedSharingProof,
} from './seed-sharing-scalar-verifier.mjs';

/** @typedef {{name: string, file: string, bytes: number, sha512: string}} Proof */
/** @typedef {{module: string, moduleSha512: string, proofs: Proof[]}} Configuration */
/** @typedef {import('./seed-sharing-scalar-verifier.mjs').Probe} Probe */
/** @typedef {import('./seed-sharing-scalar-verifier.mjs').ProbeResult} ProbeResult */

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
    const results = [];
    // Each ended worker relinquishes its module and memory before the next
    // probe. No forced collection or shared-memory path is needed.
    for (const probe of seedSharingProbes) {
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
    const moduleBytes = await readFile(modulePath);
    assert.equal(
        createHash('sha512').update(moduleBytes).digest('hex'),
        moduleSha512,
    );
    const file = await open(proof.file, 'r');
    const buffer = new Uint8Array(1_048_576);
    /** @param {number} length @param {number} position */
    const readExact = async (length, position) => {
        assert.ok(length > 0 && length <= buffer.length);
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
        return buffer.subarray(0, length);
    };
    let result;
    try {
        result = await verifySeedSharingProof({
            moduleBytes,
            proof,
            probe,
            readExact,
        });
    } finally {
        await file.close();
    }
    assert.equal(await digestFile(proof.file), proof.sha512);
    parentPort.postMessage(result);
}
