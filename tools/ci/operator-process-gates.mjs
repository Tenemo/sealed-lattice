import assert from 'node:assert/strict';
import { watch } from 'node:fs';
import { lstat } from 'node:fs/promises';
import path from 'node:path';

/** @param {string} file @returns {Promise<void>} */
const waitForGate = (file) =>
    new Promise((resolve, reject) => {
        let done = false;
        /** @param {unknown} [error] */
        const finish = (error) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            watcher.close();
            if (error === undefined) resolve();
            else
                reject(
                    error instanceof Error
                        ? error
                        : new Error(
                              typeof error === 'string'
                                  ? error
                                  : 'The operator gate failed.',
                          ),
                );
        };
        const check = async () => {
            try {
                const details = await lstat(file);
                assert.ok(
                    details.isFile() && details.size === 0,
                    'An operation gate is not an empty regular file.',
                );
                finish();
            } catch (error) {
                if (!(
                    error instanceof Error &&
                    'code' in error &&
                    error.code === 'ENOENT'
                ))
                    finish(error);
            }
        };
        const watcher = watch(path.dirname(file), () => {
            void check();
        });
        watcher.on('error', finish);
        const timer = setTimeout(
            () => finish(new Error('The operation gate timed out.')),
            60_000,
        );
        void check();
    });

/** @template T @param {string[]} args @param {()=>Promise<T>} operation */
export const withOperatorProcessGates = async (args, operation) => {
    assert.equal(
        args.length,
        4,
        'The operator host requires its paired process guard gates.',
    );
    assert.equal(args[0], '--guard-start');
    assert.equal(args[2], '--guard-finish');
    const start = path.resolve(args[1]),
        finish = path.resolve(args[3]);
    assert.notEqual(start, finish);
    for (const file of [start, finish])
        await assert.rejects(lstat(file), { code: 'ENOENT' });
    console.log(JSON.stringify({ event: 'native-operator-ready' }));
    await waitForGate(start);
    const began = performance.now();
    const result = await operation();
    console.log(
        JSON.stringify({
            event: 'native-operator-completed',
            operationMilliseconds: performance.now() - began,
        }),
    );
    await waitForGate(finish);
    return result;
};
