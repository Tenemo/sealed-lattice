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
import { runFheKeySourceScreen } from './fhe-key-source-scalar.mjs';
import { withProcessGates } from './process-gates.mjs';

/** @typedef {{module:string,moduleSha512:string,outputFile:string,expectedBytes:number,expectedSha512:string,operation:'fhe-key-source',caseIndex:number}} Configuration */
/** @typedef {Awaited<ReturnType<typeof runFheKeySourceScreen>>} GenerationResult */
/** @typedef {import('./bounded-output.mjs').OutputAcknowledgment} OutputAcknowledgment */

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
                                        configuration.operation + '-progress',
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
            const output = sink.finish();
            console.log(
                JSON.stringify({
                    kind: 'scalar-' + configuration.operation + '-screen',
                    ...result,
                    output,
                }),
            );
        } finally {
            await worker.terminate();
            await writing;
            await sink.close();
        }
    };
    await withProcessGates(process.argv.slice(3), run);
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
        const result = await runFheKeySourceScreen({
            moduleBytes,
            caseIndex: configuration.caseIndex ?? -1,
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
        });
        port.postMessage({ kind: 'result', result });
    } finally {
        port.off('message', acknowledgment);
    }
}
