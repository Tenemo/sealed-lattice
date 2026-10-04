import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createNativeOperationGuard } from '#tools/ci/native-operation-guard.js';

const deferred = <Value>() => {
    let resolve!: (value: Value) => void;
    const promise = new Promise<Value>((accept) => {
        resolve = accept;
    });
    return { promise, resolve };
};
const scratch = async () => {
    await mkdir('temp', { recursive: true });
    const directory = await mkdtemp(path.resolve('temp/native-guard-test-'));
    return {
        directory,
        startFile: path.join(directory, 'start'),
        finishFile: path.join(directory, 'finish'),
    };
};

describe('native operation sampling handshake', () => {
    it('allows only explicitly listed arithmetic progress while preserving strict JSON events', () => {
        const make = (allowedProgressLines?: readonly string[]) =>
            createNativeOperationGuard({
                startFile: 'unused-start',
                finishFile: 'unused-finish',
                memoryLimit: 1024,
                allowedProgressLines,
                readMemory: () => Promise.resolve(1),
                recordSample: () => undefined,
            });
        const strict = make();
        expect(() =>
            strict.observeStdout('Generated encryption-0\n'),
        ).toThrow();
        strict.stop();
        const screen = make(['Generated encryption-0']);
        expect(() => screen.observeStdout('Generated encrypt')).not.toThrow();
        expect(() => screen.observeStdout('ion-0\n')).not.toThrow();
        expect(() =>
            screen.observeStdout('Generated encryption-1\n'),
        ).toThrow();
        expect(() => screen.observeStdout('{broken event}\n')).toThrow();
        screen.stop();
    });
    it.each(['verifier', 'operator', 'operator host'] as const)(
        'keeps a fast %s child behind initial and final observations without timing sleeps',
        async (name) => {
            const operation = name === 'verifier' ? 'verifier' : 'operator';
            const files = await scratch();
            const initialRequested = deferred<void>();
            const initialSample = deferred<number>();
            const finalRequested = deferred<void>();
            const finalSample = deferred<number>();
            const workStarted = deferred<void>();
            const events: string[] = [];
            const guard = createNativeOperationGuard({
                ...files,
                operation,
                memoryLimit: 1024,
                readMemory: (phase) => {
                    if (phase === 'initial') {
                        initialRequested.resolve();
                        return initialSample.promise;
                    }
                    if (phase === 'final') {
                        finalRequested.resolve();
                        return finalSample.promise;
                    }
                    return Promise.resolve(64);
                },
                recordSample: (phase) => {
                    events.push(phase + '-sample');
                },
            });
            // A real child exits immediately once released. Filesystem events,
            // rather than sleeps or repeated test attempts, drive both gates.
            const child = spawn(
                process.execPath,
                [
                    '--input-type=module',
                    '-e',
                    name === 'operator host'
                        ? `
            import {withOperatorProcessGates} from ${JSON.stringify(pathToFileURL(path.resolve('tools/ci/operator-process-gates.mjs')).href)};
            const [start,finish]=process.argv.slice(1);
            await withOperatorProcessGates(['--guard-start',start,'--guard-finish',finish],async()=>{process.stdout.write(JSON.stringify({event:'work-started'})+'\\n');});
        `
                        : `
            import { existsSync, watch } from 'node:fs';
            import path from 'node:path';
            const [start, finish] = process.argv.slice(1);
            const operation=${JSON.stringify(operation)};
            const emit = (event, extra = {}) => process.stdout.write(JSON.stringify({event, ...extra}) + '\\n');
            const wait = (file) => new Promise((resolve) => {
                const check = () => { if (existsSync(file)) { watcher.close(); resolve(); } };
                const watcher = watch(path.dirname(file), check);
                check();
            });
            emit('native-'+operation+'-ready');
            await wait(start);
            emit('work-started');
            emit('native-'+operation+'-completed', {[operation==='operator'?'operationMilliseconds':'verificationMilliseconds']: 0});
            await wait(finish);
        `,
                    files.startFile,
                    files.finishFile,
                ],
                { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true },
            );
            let output = '';
            child.stdout.setEncoding('utf8');
            child.stdout.on('data', (chunk: string) => {
                guard.observeStdout(chunk);
                output += chunk;
                for (;;) {
                    const newline = output.indexOf('\n');
                    if (newline === -1) break;
                    const event = JSON.parse(output.slice(0, newline)) as {
                        event: string;
                    };
                    output = output.slice(newline + 1);
                    if (event.event === 'work-started') {
                        events.push('work');
                        workStarted.resolve();
                    }
                }
            });
            const exited = new Promise<number | null>((resolve, reject) => {
                child.on('error', reject);
                child.on('exit', (code) => {
                    events.push('exit');
                    guard.stop();
                    resolve(code);
                });
            });
            const monitored = guard.monitor();
            void monitored.catch(() => undefined);
            try {
                await initialRequested.promise;
                expect(events).not.toContain('work');
                await expect(stat(files.startFile)).rejects.toMatchObject({
                    code: 'ENOENT',
                });
                initialSample.resolve(100);
                await workStarted.promise;
                await finalRequested.promise;
                expect(child.exitCode).toBeNull();
                await expect(stat(files.finishFile)).rejects.toMatchObject({
                    code: 'ENOENT',
                });
                finalSample.resolve(128);
                const result = await monitored;
                expect(await exited).toBe(0);
                expect(events.indexOf('initial-sample')).toBeLessThan(
                    events.indexOf('work'),
                );
                expect(events.indexOf('final-sample')).toBeLessThan(
                    events.indexOf('exit'),
                );
                expect(result.samples.initial).toBe(1);
                expect(result.samples.final).toBe(1);
                expect(result.peakMemory).toBe(128);
                expect(result.operationMilliseconds).toBeGreaterThanOrEqual(0);
            } finally {
                guard.stop();
                initialSample.resolve(1);
                finalSample.resolve(1);
                if (child.exitCode === null) child.kill();
                await monitored.catch(() => undefined);
                await exited;
                await rm(files.directory, { recursive: true });
            }
        },
    );

    it('never releases work without a valid under-limit observation', async () => {
        for (const bytes of [undefined, 0, 1025]) {
            const files = await scratch();
            const observed: number[] = [];
            const guard = createNativeOperationGuard({
                ...files,
                memoryLimit: 1024,
                readMemory: () => Promise.resolve(bytes),
                recordSample: (_phase, value) => {
                    observed.push(value);
                },
            });
            try {
                guard.observeStdout('{"event":"native-verifier-ready"}\n');
                await expect(guard.monitor()).rejects.toThrow();
                await expect(stat(files.startFile)).rejects.toMatchObject({
                    code: 'ENOENT',
                });
                expect(observed).toEqual(bytes === 1025 ? [1025] : []);
            } finally {
                guard.stop();
                await rm(files.directory, { recursive: true });
            }
        }
    });
});
