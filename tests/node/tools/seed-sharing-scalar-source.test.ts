import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import { inspectSeedSharingScalarModule } from '#tools/ci/run-seed-sharing-scalar.js';
import {
    readSeedSharingNativeSource,
    seedSharingProofNames,
} from '#tools/ci/seed-sharing-scalar-source.js';

const fixture = async () => {
    await mkdir('temp', { recursive: true });
    const root = await mkdtemp(path.resolve('temp/scalar-source-'));
    const source = path.join(root, 'logs/2026-10-04/run');
    const artifacts = path.join(root, 'temp/run-artifacts/2026-10-04/run');
    const archive = path.join(artifacts, 'seed-sharing');
    await mkdir(source, { recursive: true });
    await mkdir(archive, { recursive: true });
    const runtime = Buffer.alloc(64, 9);
    await writeFile(path.join(artifacts, 'runtime.bin'), runtime);
    for (const [index, name] of seedSharingProofNames.entries())
        await writeFile(
            path.join(archive, name),
            Buffer.alloc(4096 + index, index),
        );
    const summary = {
        result: 'passed',
        exitCode: 0,
        scriptName: 'research:protocol',
    };
    const result = {
        case: 'native-seed-sharing',
        participantCount: 4,
        optionCount: 2,
        simulatedHelpers: 0,
        output: archive,
        runtimeIdentity: runtime.toString('hex'),
        result: {
            kind: 'seed-sharing-proof-fragment',
            positive: 1,
            falseWitnesses: 1,
            falseStatements: 1,
            hostileCases: 14,
            participants: 4,
            degree: 256,
            seedBits: 4,
            proofDomain: 262144,
            wordColumns: 35,
            booleanColumns: 9,
            affineRows: 4104,
            proofBytes: [4096, 4097, 4098],
        },
    };
    const manifest = {
        compiler: 'fixture compiler',
        sources: ['fixture', 'layout', 'statement', 'operator', 'witness'].map(
            (name) => ({
                file: `crates/protocol-research/seed-sharing-proof/src/${name}.rs`,
                bytes: 1,
                sha512: 'a'.repeat(128),
            }),
        ),
    };
    const save = async () => {
        for (const [name, value] of [
            ['summary', summary],
            ['result', result],
            ['source-manifest', manifest],
        ] as const)
            await writeFile(
                path.join(source, name + '.json'),
                JSON.stringify(value),
            );
    };
    await save();
    return { root, source, archive, summary, result, manifest, save };
};

describe('scalar seed-sharing evidence inputs', () => {
    it('pins the first-seen archive bytes without rewriting historical diagnostics', async () => {
        const data = await fixture();
        try {
            const before = await readFile(
                path.join(data.source, 'result.json'),
            );
            const selected = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            expect(selected.proofs.map((proof) => proof.bytes)).toEqual([
                4096, 4097, 4098,
            ]);
            expect(selected.proofs[0].sha512).toBe(
                createHash('sha512').update(Buffer.alloc(4096)).digest('hex'),
            );
            expect(selected.sources.size).toBe(5);
            expect(
                await readFile(path.join(data.source, 'result.json')),
            ).toEqual(before);
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
    it('refuses failed runs, wrong fixtures, changed length inventories and missing core sources', async () => {
        const changes = [
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.summary.result = 'failed';
            },
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.result.case = 'native-result';
            },
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.result.result.seedBits = 512;
            },
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.result.result.proofBytes[1]--;
            },
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.manifest.sources.pop();
            },
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.manifest.sources[0].file = '../outside.rs';
            },
            (data: Awaited<ReturnType<typeof fixture>>) => {
                data.result.runtimeIdentity = 'b'.repeat(128);
            },
        ];
        for (const change of changes) {
            const data = await fixture();
            try {
                change(data);
                await data.save();
                await expect(
                    readSeedSharingNativeSource(data.source, data.root),
                ).rejects.toThrow();
            } finally {
                await rm(data.root, { recursive: true });
            }
        }
    });
    it('admits only scalar, bounded, unshared modules with known host imports', async () => {
        const moduleBytes = (
            memory = '(memory (export "memory") 1 10240)',
            extra = '',
        ) => {
            const module = binaryen.parseText(
                `(module ${extra} ${memory} ${['input_pointer', 'input_capacity', 'header_length', 'begin', 'push', 'finish'].map((name) => `(func (export "seed_verifier_${name}") (result i32) (i32.const 0))`).join(' ')})`,
            );
            try {
                return module.emitBinary();
            } finally {
                module.dispose();
            }
        };
        await expect(
            inspectSeedSharingScalarModule(moduleBytes()),
        ).resolves.toMatchObject({ imports: [] });
        await expect(
            inspectSeedSharingScalarModule(
                moduleBytes(
                    undefined,
                    '(import "parallel" "helpers" (func (result i32)))',
                ),
            ),
        ).resolves.toMatchObject({
            imports: [
                { module: 'parallel', name: 'helpers', kind: 'function' },
            ],
        });
        await expect(
            inspectSeedSharingScalarModule(
                moduleBytes(
                    undefined,
                    '(import "word_proof" "fill_random" (func))',
                ),
            ),
        ).rejects.toThrow('unknown host import');
        await expect(
            inspectSeedSharingScalarModule(
                moduleBytes('(memory (export "memory") 1 16384)'),
            ),
        ).rejects.toThrow('bounded unshared');
        await expect(
            inspectSeedSharingScalarModule(
                moduleBytes('(memory (export "memory") 1 10240 shared)'),
            ),
        ).rejects.toThrow('bounded unshared');
        await expect(
            inspectSeedSharingScalarModule(
                moduleBytes(
                    undefined,
                    '(func (drop (v128.const i32x4 0 0 0 0)))',
                ),
            ),
        ).rejects.toThrow('scalar instructions');
    });
});
