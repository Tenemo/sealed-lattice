import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
    isMainThread,
    parentPort,
    Worker,
    workerData,
} from 'node:worker_threads';

import { createBoundedOutputSink } from './bounded-output-sink.mjs';
import { withOperatorProcessGates } from './operator-process-gates.mjs';
import {
    runPublicOperatorScreen,
    runFheKeySourceScreen,
} from './public-operator-scalar.mjs';
import { withPinnedProofReaders } from './scalar-proof-file-reader.mjs';
import { generateBoundedProof } from './seed-sharing-scalar-prover.mjs';

/** @typedef {{module:string,moduleSha512:string,outputFile:string,expectedBytes:number,expectedSha512:string,operation?:'public-operator'|'fhe-key-source',caseIndex?:number,relation?:'seed-sharing'|'opening-share',predecessors?:import('./scalar-proof-file-reader.mjs').Proof[]}} Configuration */
/** @typedef {Awaited<ReturnType<typeof import('./bounded-output.mjs').driveBoundedOutput>>} GenerationResult */
/** @typedef {import('./seed-sharing-scalar-prover.mjs').OutputAcknowledgment} OutputAcknowledgment */

if (isMainThread) {
    const configuration = /** @type {Configuration} */ (
        JSON.parse(await readFile(process.argv[2], 'utf8'))
    );
    const run = async () => {
        const sink = await createBoundedOutputSink(
            configuration.outputFile,
            configuration.expectedBytes,
            configuration.expectedSha512,
        );
        const worker = new Worker(new URL(import.meta.url), {
            workerData: configuration,
        });
        /** @type {Promise<void> | undefined} */
        let writing;
        /** @type {GenerationResult | undefined} */
        let generated;
        let failed = false;
        try {
            const result = await new Promise((resolve, reject) => {
                const fail = (error) => {
                    const failure =
                        error instanceof Error
                            ? error
                            : new Error(String(error));
                    failed = true;
                    reject(failure);
                    void worker.terminate().catch(reject);
                };
                worker.on('error', fail);
                worker.on('message', (message) => {
                    try {
                        assert.ok(
                            !failed,
                            'The output worker continued after failure.',
                        );
                        if (message.kind === 'progress') {
                            console.log(
                                JSON.stringify({
                                    event:
                                        configuration.operation !== undefined
                                            ? configuration.operation +
                                              '-progress'
                                            : (configuration.relation ??
                                                  'seed-sharing') +
                                              '-generation-progress',
                                    ...message.progress,
                                }),
                            );
                        } else if (message.kind === 'chunk') {
                            assert.ok(
                                writing === undefined &&
                                    generated === undefined,
                                'The output worker queued an unacknowledged output span.',
                            );
                            const index = message.index;
                            const offset = message.offset;
                            if (
                                typeof index !== 'number' ||
                                typeof offset !== 'number'
                            )
                                throw new Error(
                                    'The output producer emitted an invalid output position.',
                                );
                            const chunk = message.bytes;
                            if (!(chunk instanceof Uint8Array))
                                throw new Error(
                                    'The output producer emitted nonbinary output.',
                                );
                            writing = (async () => {
                                const acknowledgment = await sink.write(
                                    index,
                                    offset,
                                    chunk,
                                );
                                worker.postMessage({
                                    kind: 'ack',
                                    ...acknowledgment,
                                });
                            })()
                                .catch(fail)
                                .finally(() => {
                                    writing = undefined;
                                });
                        } else if (message.kind === 'result') {
                            assert.ok(
                                writing === undefined &&
                                    generated === undefined,
                                'The output worker finished before its sink acknowledgment.',
                            );
                            generated = /** @type {GenerationResult} */ (
                                message.result
                            );
                        } else
                            throw new Error(
                                'The output worker emitted an unknown message.',
                            );
                    } catch (error) {
                        fail(error);
                    }
                });
                worker.on('exit', (code) => {
                    if (
                        code !== 0 ||
                        generated === undefined ||
                        writing !== undefined ||
                        failed
                    )
                        fail(
                            new Error(
                                'The output worker did not complete its acknowledged output.',
                            ),
                        );
                    else resolve(generated);
                });
            });
            const proof = sink.finish();
            console.log(
                JSON.stringify({
                    kind:
                        configuration.operation !== undefined
                            ? 'scalar-' + configuration.operation + '-screen'
                            : 'scalar-' +
                              (configuration.relation ?? 'seed-sharing') +
                              '-generation',
                    ...result,
                    ...(configuration.operation !== undefined
                        ? { output: proof }
                        : { proof }),
                }),
            );
        } finally {
            await worker.terminate();
            await writing;
            await sink.close();
        }
    };
    if (configuration.operation !== undefined)
        await withOperatorProcessGates(process.argv.slice(3), run);
    else {
        assert.equal(process.argv.length, 3);
        await run();
    }
} else {
    const configuration = /** @type {Configuration} */ (workerData);
    const moduleBytes = await readFile(configuration.module);
    assert.equal(
        createHash('sha512').update(moduleBytes).digest('hex'),
        configuration.moduleSha512,
    );
    /** @type {{resolve:(ack:OutputAcknowledgment)=>void,reject:(error:Error)=>void}|undefined} */
    let pending;
    const port = parentPort;
    assert.ok(port);
    const acknowledgment = (message) => {
        if (pending === undefined)
            throw new Error(
                'The output sink sent an unsolicited acknowledgment.',
            );
        const waiting = pending;
        pending = undefined;
        const index = message.index;
        const offset = message.offset;
        const length = message.length;
        if (
            message.kind !== 'ack' ||
            typeof index !== 'number' ||
            typeof offset !== 'number' ||
            typeof length !== 'number'
        )
            waiting.reject(new Error('The output sink sent an unknown reply.'));
        else
            waiting.resolve({
                index,
                offset,
                length,
            });
    };
    port.on('message', acknowledgment);
    try {
        /** @type {Parameters<typeof generateBoundedProof>[0]} */
        const outputInput = {
            moduleBytes,
            expectedBytes: configuration.expectedBytes,
            onProgress: (progress) =>
                port.postMessage({ kind: 'progress', progress }),
            emitChunk: (index, offset, bytes) =>
                new Promise((resolve, reject) => {
                    assert.equal(
                        pending,
                        undefined,
                        'More than one output acknowledgment is pending.',
                    );
                    pending = { resolve, reject };
                    port.postMessage({ kind: 'chunk', index, offset, bytes }, [
                        bytes.buffer,
                    ]);
                }),
        };
        /** @param {((index:number,length:number,position:number)=>Promise<Uint8Array>)|undefined} readPredecessor */
        const generate = (readPredecessor) =>
            generateBoundedProof({
                ...outputInput,
                relation: configuration.relation,
                predecessors: configuration.predecessors,
                readPredecessor,
            });
        const result =
            configuration.operation !== undefined
                ? await (
                      configuration.operation === 'fhe-key-source'
                          ? runFheKeySourceScreen
                          : runPublicOperatorScreen
                  )({
                      ...outputInput,
                      caseIndex: configuration.caseIndex ?? -1,
                  })
                : configuration.relation === 'opening-share'
                  ? await withPinnedProofReaders(
                        configuration.predecessors ?? [],
                        generate,
                    )
                  : await generate(undefined);
        port.postMessage({ kind: 'result', result });
    } finally {
        port.off('message', acknowledgment);
    }
}
