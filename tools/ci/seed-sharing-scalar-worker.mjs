import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
    isMainThread,
    parentPort,
    Worker,
    workerData,
} from 'node:worker_threads';

import { openingShareProbes } from './opening-share-scalar.mjs';
import { withPinnedProofReaders } from './scalar-proof-file-reader.mjs';
import {
    seedSharingProbes,
    verifyBoundedProof,
} from './seed-sharing-scalar-verifier.mjs';

/** @typedef {{name: string, file: string, bytes: number, sha512: string}} Proof */
/** @typedef {{module: string, moduleSha512: string, proofs: Proof[],relation?:'seed-sharing'|'opening-share',predecessors?:Proof[]}} Configuration */
/** @typedef {import('./seed-sharing-scalar-verifier.mjs').Probe} Probe */
/** @typedef {import('./seed-sharing-scalar-verifier.mjs').ProbeResult} ProbeResult */

if (isMainThread) {
    const configuration = /** @type {Configuration} */ (
        JSON.parse(await readFile(process.argv[2], 'utf8'))
    );
    const results = [];
    // Each ended worker relinquishes its module and memory before the next
    // probe. No forced collection or shared-memory path is needed.
    for (const probe of configuration.relation === 'opening-share'
        ? openingShareProbes
        : seedSharingProbes) {
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
        JSON.stringify({
            kind:
                'scalar-' +
                (configuration.relation ?? 'seed-sharing') +
                '-verification',
            results,
        }),
    );
} else {
    const {
        module: modulePath,
        moduleSha512,
        proofs,
        probe,
        relation,
        predecessors = [],
    } = /** @type {Configuration & {probe: Probe}} */ (workerData);
    const proof = proofs[probe.proof];
    const moduleBytes = await readFile(modulePath);
    assert.equal(
        createHash('sha512').update(moduleBytes).digest('hex'),
        moduleSha512,
    );
    const result = await withPinnedProofReaders(
        [...predecessors, proof],
        (read) =>
            verifyBoundedProof({
                moduleBytes,
                proof,
                probe,
                relation,
                predecessors,
                readPredecessor: read,
                readExact: (length, position) =>
                    read(predecessors.length, length, position),
            }),
    );
    parentPort.postMessage(result);
}
