import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
    isMainThread,
    parentPort,
    Worker,
    workerData,
} from 'node:worker_threads';

import { createCompactRankVerifier } from './compact-rank-scalar.mjs';
import { withProcessGates } from './process-gates.mjs';

/** @typedef {{file:string,bytes:number,sha512:string}} Artifact */
/** @typedef {{name:string,role:string,context:string,statement:Artifact,proof:Artifact,accepted:boolean}} Case */
/** @typedef {{host:'native'|'scalar',executable:string,module:Artifact,cases:Case[]}} Configuration */

/** @param {Artifact} artifact */
const readArtifact = async (artifact) => {
    const bytes = await readFile(artifact.file);
    assert.equal(bytes.length, artifact.bytes);
    assert.equal(
        createHash('sha512').update(bytes).digest('hex'),
        artifact.sha512,
    );
    return bytes;
};
/** @param {Uint8Array[]} parts */
const frame = (parts) =>
    Buffer.concat(
        parts.flatMap((part) => {
            const word = Buffer.alloc(4);
            word.writeUInt32LE(part.length);
            return [word, part];
        }),
    );
/** @param {string} executable @param {Uint8Array} input @returns {Promise<{accepted:boolean,refusal?:string}>} */
const runNative = (executable, input) =>
    new Promise((resolve, reject) => {
        const process = spawn(executable, [], {
            windowsHide: true,
            stdio: ['pipe', 'pipe', 'pipe'],
        });
        let output = '',
            errors = '';
        process.on('error', reject);
        process.stdin.on('error', reject);
        process.stdout.on('data', (chunk) => {
            output += chunk;
        });
        process.stderr.on('data', (chunk) => {
            errors += chunk;
        });
        process.on('close', (code) => {
            if (code !== 0) {
                reject(
                    new Error(
                        `The native rank screen exited with ${code}: ${errors}`,
                    ),
                );
                return;
            }
            try {
                const result =
                    /** @type {{accepted:boolean,refusal?:string}} */ (
                        JSON.parse(output)
                    );
                assert.equal(typeof result.accepted, 'boolean');
                assert.ok(
                    result.refusal === undefined ||
                        typeof result.refusal === 'string',
                );
                resolve(result);
            } catch (error) {
                reject(
                    error instanceof Error ? error : new Error(String(error)),
                );
            }
        });
        process.stdin.end(input);
    });

/** @param {Configuration} configuration */
const execute = async (configuration) => {
    const module =
        configuration.host === 'scalar'
            ? await WebAssembly.compile(
                  new Uint8Array(await readArtifact(configuration.module)),
              )
            : undefined;
    let scalar = module ? await createCompactRankVerifier(module) : undefined;
    const cases = [];
    let maximumLinearMemory = 0;
    /** @param {string} name @param {Uint8Array[]} parts @param {boolean} accepted @param {string} [refusal] */
    const check = async (name, parts, accepted, refusal) => {
        const started = performance.now();
        const bytes = frame(parts);
        const result = scalar
            ? scalar.verify(bytes)
            : await runNative(configuration.executable, bytes);
        assert.equal(result.accepted, accepted, name);
        if (refusal) assert.equal(result.refusal, refusal, name);
        if (scalar)
            maximumLinearMemory = Math.max(
                maximumLinearMemory,
                scalar.memoryBytes(),
            );
        cases.push({
            name,
            ...result,
            milliseconds: performance.now() - started,
        });
    };
    for (const entry of configuration.cases) {
        const parts = [
            Buffer.from(entry.role),
            Buffer.from(entry.context),
            await readArtifact(entry.statement),
            await readArtifact(entry.proof),
        ];
        await check(
            entry.name,
            parts,
            entry.accepted,
            entry.name === 'original-input-binding-counterexample'
                ? 'Relation'
                : undefined,
        );
        console.log(
            JSON.stringify({ event: 'rank-proof-checked', name: entry.name }),
        );
    }
    const first = configuration.cases.find((entry) => entry.accepted);
    assert.ok(first);
    const original = [
        Buffer.from(first.role),
        Buffer.from(first.context),
        await readArtifact(first.statement),
        await readArtifact(first.proof),
    ];
    for (const length of [0, 3, 67, original[3].length - 1])
        await check(
            'truncated-proof-' + length,
            [...original.slice(0, 3), original[3].subarray(0, length)],
            false,
            'Encoding',
        );
    await check(
        'trailing-proof',
        [
            ...original.slice(0, 3),
            Buffer.concat([original[3], Buffer.from([0])]),
        ],
        false,
        'Encoding',
    );
    const changes =
        /** @type {[string,number,number,(string|undefined)][]} */ ([
            ['different-role', 0, 0, 'Context'],
            ['different-public-context', 1, 0, 'Context'],
            ['different-recipient', 2, 16, 'Context'],
            ['different-predecessor', 2, 20, 'Context'],
            ['different-source', 2, 116 + 2 * 4096 * 6 + 12 + 1, 'Context'],
            ['different-output', 2, original[2].length - 2, 'Context'],
            ['different-proof-context', 3, 4, 'Context'],
            ['different-root', 3, 68, undefined],
            ['different-path', 3, original[3].length - 1, 'Authentication'],
        ]);
    for (const [name, part, offset, refusal] of changes) {
        const parts = original.map((value) => Buffer.from(value));
        parts[part][offset] ^= 1;
        await check(name, parts, false, refusal);
    }
    const noncanonical = original.map((value) => Buffer.from(value));
    const modulus = (1n << 128n) - (133n << 64n) + 1n;
    noncanonical[3].writeBigUInt64LE(modulus & ((1n << 64n) - 1n), 324);
    noncanonical[3].writeBigUInt64LE(modulus >> 64n, 332);
    await check('noncanonical-proof-field', noncanonical, false, 'Encoding');
    for (const sign of [1, 2]) {
        const parts = original.map((value) => Buffer.from(value));
        parts[2].fill(0, 116, 122);
        parts[2][116] = sign;
        await check(
            sign === 1 ? 'negative-zero-source' : 'noncanonical-source-sign',
            parts,
            false,
            'Statement',
        );
    }
    if (module) scalar = await createCompactRankVerifier(module);
    await check('fresh-instance-replay', original, true);
    return {
        kind: 'compact-rank-proof',
        host: configuration.host,
        cases,
        maximumLinearMemory,
    };
};

if (isMainThread) {
    const configuration = /** @type {Configuration} */ (
        JSON.parse(await readFile(process.argv[2], 'utf8'))
    );
    const result = await withProcessGates(process.argv.slice(3), async () => {
        if (configuration.host === 'native') return execute(configuration);
        const worker = new Worker(new URL(import.meta.url), {
            workerData: configuration,
        });
        try {
            /** @type {Promise<Awaited<ReturnType<typeof execute>>>} */
            const completion = new Promise((resolve, reject) => {
                /** @type {Awaited<ReturnType<typeof execute>> | undefined} */
                let report;
                worker.on('error', reject);
                worker.on('message', (value) => {
                    report =
                        /** @type {Awaited<ReturnType<typeof execute>>} */ (
                            value
                        );
                });
                worker.on('exit', (code) => {
                    if (code === 0 && report) resolve(report);
                    else
                        reject(
                            new Error(
                                'The scalar rank worker failed to return its report.',
                            ),
                        );
                });
            });
            return await completion;
        } finally {
            await worker.terminate();
        }
    });
    console.log(JSON.stringify(result));
} else {
    const configuration = /** @type {Configuration} */ (workerData);
    parentPort.postMessage(await execute(configuration));
}
