import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
    invalidBallotModulePath,
    invalidBallotWorker,
} from '#tools/ci/participant-invalid-ballot-client.js';

const fixture = Buffer.from(`
globalThis.run = async (command) => {
    const delivered = await deliverModule(command);
    const module = await WebAssembly.compile(delivered.bytes);
    const evaluation = evaluatingOperations.has(command.operation);
    return { module, evaluation };
};
globalThis.verify = async () => {
    const delivered = await deliverModule({ module: 'honest' });
    return await WebAssembly.compile(delivered.bytes);
};`);

describe('corrupt participant module selection', () => {
    it('patches the built operation path while preserving the standalone verifier', async () => {
        const source = await readFile(
            path.resolve('packages/sdk/dist/participant-worker.js'),
        );
        const original = source.toString('utf8');
        const patched = invalidBallotWorker(source).toString('utf8');
        const verification = original.indexOf('const runVerification =');
        expect(verification).toBeGreaterThan(0);
        expect(patched.slice(patched.indexOf('const runVerification ='))).toBe(
            original.slice(verification),
        );
        expect(
            patched.match(/invalid-ballot-participant\.wasm/gu),
        ).toHaveLength(1);
        expect(
            patched.match(/WebAssembly\.compile\(delivered\.bytes\)/gu),
        ).toHaveLength(1);
    });

    it('checks the honest delivery first and compiles only the corrupt operation from the fixture path', async () => {
        const events: string[] = [];
        const honest = Uint8Array.of(1, 2, 3);
        const corrupt = Uint8Array.of(4, 5, 6);
        const context = {
            location: { origin: 'https://participant.test' },
            evaluatingOperations: new Set(['sign-target']),
            deliverModule: () => {
                events.push('honest delivery and runtime identity');
                return { bytes: honest, runtime: 'runtime' };
            },
            fetch: (url: string) => {
                expect(url).toBe(
                    'https://participant.test/' + invalidBallotModulePath,
                );
                events.push('corrupt delivery');
                return { arrayBuffer: () => corrupt.buffer };
            },
            WebAssembly: {
                compile: (bytes: ArrayBuffer | Uint8Array) => {
                    const values = Array.from(new Uint8Array(bytes));
                    events.push('compile ' + values.join(','));
                    return values;
                },
            },
            run: undefined as
                | ((command: unknown) => Promise<{ module: number[] }>)
                | undefined,
            verify: undefined as (() => Promise<number[]>) | undefined,
        };
        runInNewContext(invalidBallotWorker(fixture).toString('utf8'), context);
        expect(
            await context.run!({
                module: 'honest',
                identity: { module: 'digest' },
                operation: 'cast-ballot',
            }),
        ).toEqual({ module: [4, 5, 6], evaluation: false });
        expect(events).toEqual([
            'honest delivery and runtime identity',
            'corrupt delivery',
            'compile 4,5,6',
        ]);
        events.length = 0;
        expect(await context.verify!()).toEqual([1, 2, 3]);
        expect(events).toEqual([
            'honest delivery and runtime identity',
            'compile 1,2,3',
        ]);
    });

    it('refuses an absent or ambiguous participant compilation', () => {
        for (const source of [
            Buffer.from(''),
            Buffer.concat([fixture, fixture]),
        ])
            expect(() => invalidBallotWorker(source)).toThrow(
                'one participant-operation module compilation',
            );
    });
});
