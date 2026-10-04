import { createHash } from 'node:crypto';
import {
    copyFile,
    mkdir,
    mkdtemp,
    readFile,
    rm,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import { compileBoundedOpeningShareProofResources } from '#tests/recoverable-setup-resource-model.js';
import { inspectScalarFixtureModule } from '#tools/ci/scalar-fixture-build.js';
import {
    assertOpeningShareSourceStable,
    assertScalarNativeInputs,
    compareNativeReferenceArtifacts,
    openingShareProofNames,
    openingShareStatementNames,
    readOpeningShareNativeSource,
    readSeedSharingNativeSource,
    seedSharingProofNames,
    assertSeedSharingSharedInputs,
    assertSeedSharingSourceStable,
    compareSeedSharingReferenceProofs,
} from '#tools/ci/seed-sharing-scalar-source.js';
import type { NativeReferenceArtifact } from '#tools/ci/seed-sharing-scalar-source.js';

const addFixtureSource = async (
    root: string,
    sources: { file: string; bytes: number; sha512: string }[],
    file: string,
) => {
    const entry = {
        file,
        bytes: 1,
        sha512: createHash('sha512').update('x').digest('hex'),
    };
    sources.push(entry);
    await mkdir(path.dirname(path.join(root, file)), { recursive: true });
    await writeFile(path.join(root, file), 'x');
    return entry;
};

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
                sha512: createHash('sha512').update('x').digest('hex'),
            }),
        ),
    };
    for (const entry of manifest.sources) {
        const file = path.join(root, entry.file);
        await mkdir(path.dirname(file), { recursive: true });
        await writeFile(file, 'x');
    }
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

// These byte arrays are source-reader fixtures, not cryptographic proofs.
// The scalar/native owning verifiers independently check actual run bytes.
const openingFixture = async () => {
    const seed = await fixture();
    Object.assign(seed.result, { compiledInputs: [...seed.manifest.sources] });
    await seed.save();
    const seedSource = await readSeedSharingNativeSource(
        seed.source,
        seed.root,
    );
    const source = path.join(seed.root, 'logs/2026-10-04/opening');
    const artifacts = path.join(
        seed.root,
        'temp/run-artifacts/2026-10-04/opening',
    );
    const archive = path.join(artifacts, 'opening-share');
    await mkdir(source, { recursive: true });
    await mkdir(archive, { recursive: true });
    const runtime = Buffer.alloc(64, 17);
    await writeFile(path.join(artifacts, 'runtime.bin'), runtime);
    const model = compileBoundedOpeningShareProofResources();
    const proofArtifacts: Omit<NativeReferenceArtifact, 'file'>[] = [];
    const statementArtifacts: Omit<NativeReferenceArtifact, 'file'>[] = [];
    for (const [index, name] of [
        ...openingShareProofNames,
        ...openingShareStatementNames,
    ].entries()) {
        const bytes = Buffer.alloc(
            index < 3
                ? 4100 + index
                : Number(
                      index === 3
                          ? model.seedStatementBytes
                          : model.openingStatementBytes,
                  ),
            index + 33,
        );
        await writeFile(path.join(archive, name), bytes);
        (index < 3 ? proofArtifacts : statementArtifacts).push({
            name,
            bytes: bytes.length,
            sha512: createHash('sha512').update(bytes).digest('hex'),
        });
    }
    const summary = { ...seed.summary };
    const own = {
        file: 'crates/protocol-research/opening-share-proof/src/fixture.rs',
        bytes: 1,
        sha512: createHash('sha512').update('o').digest('hex'),
    };
    const manifest = {
        compiler: seed.manifest.compiler,
        sources: [...seed.manifest.sources, own],
    };
    await mkdir(path.dirname(path.join(seed.root, own.file)), {
        recursive: true,
    });
    await writeFile(path.join(seed.root, own.file), 'o');
    const result = {
        case: 'native-opening-share',
        participantCount: 4,
        optionCount: 2,
        simulatedHelpers: 0,
        output: archive,
        runtimeIdentity: runtime.toString('hex'),
        result: {
            kind: 'bounded-opening-share-proof',
            degree: 256,
            participants: 4,
            selected: 2,
            recipient: 2,
            predecessors: 2,
            positive: 1,
            falseStatements: 1,
            hostileCases: 10,
            wordColumns: 9,
            booleanColumns: 4,
            lookupEntries: 10,
            affineRows: 1538,
            proofDomain: 262144,
            statementBytes: Number(model.openingStatementBytes),
            sourceIdentities: ['3'.repeat(128), '4'.repeat(128)],
            secondSourceProofBytes: 4100,
            proofBytes: 4101,
            shiftedProofBytes: 4102,
        },
        proofArtifacts,
        statementArtifacts,
        compiledInputs: [...manifest.sources],
        predecessor: {
            directory: seedSource.directory,
            diagnosticDigests: seedSource.diagnosticDigests,
            proofs: seedSource.proofs,
            sharedInputs: [...seedSource.compiledInputs.keys()].sort(),
        },
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
    return {
        seed,
        root: seed.root,
        source,
        archive,
        summary,
        result,
        manifest,
        save,
    };
};

describe('scalar opening-share evidence inputs', () => {
    it('pins six artifacts and both original outer predecessors without changing diagnostics', async () => {
        const data = await openingFixture();
        try {
            const before = await readFile(
                path.join(data.source, 'result.json'),
            );
            const source = await readOpeningShareNativeSource(
                data.source,
                data.root,
            );
            expect(source.artifacts.map(({ name }) => name)).toEqual([
                ...openingShareProofNames,
                ...openingShareStatementNames,
            ]);
            expect(source.proofs.map(({ name }) => name)).toEqual(
                openingShareProofNames.slice(1),
            );
            expect(source.predecessors.map(({ name }) => name)).toEqual([
                seedSharingProofNames[0],
                openingShareProofNames[0],
            ]);
            expect(source.predecessors[0].file).toBe(
                source.seedSource.proofs[0].file,
            );
            expect(
                await readFile(path.join(data.source, 'result.json')),
            ).toEqual(before);
            await expect(
                assertOpeningShareSourceStable(source, data.root),
            ).resolves.toBeUndefined();
            const output = path.join(data.root, 'fresh-opening');
            await mkdir(output);
            for (const artifact of source.artifacts)
                await copyFile(artifact.file, path.join(output, artifact.name));
            await expect(
                compareNativeReferenceArtifacts(source.artifacts, output),
            ).resolves.toHaveLength(6);
            for (const artifact of source.artifacts) {
                const file = path.join(output, artifact.name);
                const changed = await readFile(file);
                changed[changed.length - 1] ^= 1;
                await writeFile(file, changed);
                await expect(
                    compareNativeReferenceArtifacts(source.artifacts, output),
                ).rejects.toThrow('deterministic reference');
                await copyFile(artifact.file, file);
            }
        } finally {
            await rm(data.root, { recursive: true });
        }
    });

    it('rejects changed opening statements and changes to the captured seed predecessor', async () => {
        const data = await openingFixture();
        try {
            const source = await readOpeningShareNativeSource(
                data.source,
                data.root,
            );
            const file = source.artifacts[4].file;
            const original = await readFile(file);
            const changed = Buffer.from(original);
            changed[0] ^= 1;
            await writeFile(file, changed);
            await expect(
                assertOpeningShareSourceStable(source, data.root),
            ).rejects.toThrow('recorded identities');
            await writeFile(file, original);
            const seedProof = source.predecessors[0].file;
            const proof = await readFile(seedProof);
            proof[0] ^= 1;
            await writeFile(seedProof, proof);
            await expect(
                assertOpeningShareSourceStable(source, data.root),
            ).rejects.toThrow('captured seed predecessor proofs');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });

    it('refuses changed layout, framing, runtime, compiler and incomplete captured compiled closure', async () => {
        const changes = [
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.result.lookupEntries++;
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.result.statementBytes--;
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.result.sourceIdentities[1] =
                    data.result.result.sourceIdentities[0];
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.runtimeIdentity = 'b'.repeat(128);
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.manifest.compiler = 'other compiler';
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.predecessor.sharedInputs.pop();
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.compiledInputs.length = 0;
            },
            (data: Awaited<ReturnType<typeof openingFixture>>) => {
                data.result.predecessor.diagnosticDigests.result = 'f'.repeat(
                    128,
                );
            },
        ];
        for (const change of changes) {
            const data = await openingFixture();
            try {
                change(data);
                await data.save();
                await expect(
                    readOpeningShareNativeSource(data.source, data.root),
                ).rejects.toThrow();
            } finally {
                await rm(data.root, { recursive: true });
            }
        }
    });

    it('does not treat a snapshotted seed file as a compiled predecessor input', async () => {
        const data = await openingFixture();
        try {
            Object.assign(data.seed.result, {
                compiledInputs: data.seed.manifest.sources.slice(1),
            });
            await data.seed.save();
            const seedSource = await readSeedSharingNativeSource(
                data.seed.source,
                data.root,
            );
            data.result.predecessor.diagnosticDigests =
                seedSource.diagnosticDigests;
            await data.save();
            await expect(
                readOpeningShareNativeSource(data.source, data.root),
            ).rejects.toThrow('did not compile the same shared input');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
});

describe('scalar seed-sharing evidence inputs', () => {
    it('refuses truncated and oversized runtime digest artifacts before archive admission', async () => {
        const data = await fixture();
        try {
            const file = path.join(
                data.root,
                'temp/run-artifacts/2026-10-04/run/runtime.bin',
            );
            for (const length of [63, 65]) {
                await writeFile(file, Buffer.alloc(length, 9));
                await expect(
                    readSeedSharingNativeSource(data.source, data.root),
                ).rejects.toThrow('runtime digest has another length');
            }
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
    it('admits only unchanged compiled seed inputs and separately pinned scalar adapters', async () => {
        const data = await fixture();
        try {
            const shared = [
                'crates/protocol-research/Cargo.toml',
                'crates/protocol-research/Cargo.lock',
                'crates/protocol-research/seed-sharing-proof/Cargo.toml',
                'crates/protocol-research/seed-sharing-proof/src/lib.rs',
                'crates/protocol-research/seed-sharing-proof/src/proof.rs',
                'crates/protocol-research/seed-sharing-proof/src/prover.rs',
                'crates/protocol-research/seed-sharing-proof/src/verification.rs',
                'crates/protocol-research/seed-sharing-proof/src/bin/check-seed-sharing-proof.rs',
            ];
            for (const file of shared)
                await addFixtureSource(data.root, data.manifest.sources, file);
            const compiledInputs = [...data.manifest.sources];
            const adapters = [
                'crates/protocol-research/seed-sharing-proof/src/browser.rs',
                'crates/protocol-research/seed-sharing-proof/src/prover-browser.rs',
            ];
            for (const file of adapters)
                await addFixtureSource(data.root, data.manifest.sources, file);
            Object.assign(data.result, { compiledInputs });
            await data.save();
            const source = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            const files = [...source.sources.keys()];
            const inspect = (inputs = files, compiler = source.compiler) =>
                assertScalarNativeInputs(
                    source,
                    inputs,
                    compiler,
                    data.root,
                    'seed-sharing',
                );
            await expect(inspect()).resolves.toEqual({
                unchangedNativeInputs: compiledInputs
                    .map(({ file }) => file)
                    .sort(),
                targetAdapters: adapters,
            });
            await expect(inspect([], source.compiler)).rejects.toThrow(
                'closure is empty',
            );
            await expect(inspect(files, 'other compiler')).rejects.toThrow(
                'another compiler',
            );
            for (const file of [...shared, ...adapters]) {
                await writeFile(path.join(data.root, file), 'y');
                await expect(inspect()).rejects.toThrow('native input changed');
                await writeFile(path.join(data.root, file), 'x');
            }
            const missingCompiled = new Map(source.compiledInputs);
            missingCompiled.delete(shared[6]);
            await expect(
                assertScalarNativeInputs(
                    { ...source, compiledInputs: missingCompiled },
                    files,
                    source.compiler,
                    data.root,
                    'seed-sharing',
                ),
            ).rejects.toThrow('did not compile a scalar shared input');
            const missingAdapter = new Map(source.sources);
            missingAdapter.delete(adapters[1]);
            await expect(
                assertScalarNativeInputs(
                    { ...source, sources: missingAdapter },
                    files,
                    source.compiler,
                    data.root,
                    'seed-sharing',
                ),
            ).rejects.toThrow('did not snapshot a scalar target adapter');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });

    it('has the same compiled-input rule for opening proofs and no generalized browser-file exemption', async () => {
        const data = await openingFixture();
        try {
            const compiled = await addFixtureSource(
                data.root,
                data.manifest.sources,
                'crates/protocol-research/opening-share-proof/src/lib.rs',
            );
            data.result.compiledInputs.push(compiled);
            const adapter = await addFixtureSource(
                data.root,
                data.manifest.sources,
                'crates/protocol-research/opening-share-proof/src/browser.rs',
            );
            await data.save();
            const source = await readOpeningShareNativeSource(
                data.source,
                data.root,
            );
            const files = [...source.compiledInputs.keys(), adapter.file];
            await expect(
                assertScalarNativeInputs(
                    source,
                    files,
                    source.compiler,
                    data.root,
                    'opening-share',
                ),
            ).resolves.toEqual({
                unchangedNativeInputs: [...source.compiledInputs.keys()].sort(),
                targetAdapters: [adapter.file],
            });
            const added = await addFixtureSource(
                data.root,
                data.manifest.sources,
                'crates/protocol-research/word-proof/src/browser.rs',
            );
            source.sources.set(added.file, added);
            await expect(
                assertScalarNativeInputs(
                    source,
                    [...files, added.file],
                    source.compiler,
                    data.root,
                    'opening-share',
                ),
            ).rejects.toThrow('did not compile a scalar shared input');
            await writeFile(path.join(data.root, compiled.file), 'z');
            await expect(
                assertScalarNativeInputs(
                    source,
                    files,
                    source.compiler,
                    data.root,
                    'opening-share',
                ),
            ).rejects.toThrow('native input changed');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });

    it('compares all deterministic reference bytes across chunk boundaries and detects source changes', async () => {
        const data = await fixture();
        try {
            const long = Buffer.alloc((1 << 20) + 7, 31);
            await writeFile(
                path.join(data.archive, seedSharingProofNames[0]),
                long,
            );
            data.result.result.proofBytes[0] = long.length;
            await data.save();
            const source = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            const output = path.join(data.root, 'fresh');
            await mkdir(output);
            for (const proof of source.proofs)
                await copyFile(proof.file, path.join(output, proof.name));
            await expect(
                compareSeedSharingReferenceProofs(source, output),
            ).resolves.toEqual(
                source.proofs.map(({ name, bytes, sha512 }) => ({
                    name,
                    bytes,
                    sha512,
                })),
            );
            for (const proof of source.proofs) {
                const file = path.join(output, proof.name);
                const bytes = await readFile(file);
                bytes[bytes.length - 1] ^= 1;
                await writeFile(file, bytes);
                await expect(
                    compareSeedSharingReferenceProofs(source, output),
                ).rejects.toThrow('differs from its deterministic reference');
                await copyFile(proof.file, file);
            }
            await expect(
                assertSeedSharingSourceStable(source, data.root),
            ).resolves.toBeUndefined();
            long[0] ^= 1;
            await writeFile(source.proofs[0].file, long);
            await expect(
                assertSeedSharingSourceStable(source, data.root),
            ).rejects.toThrow('proofs changed');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
    it('requires the exact shared compiler and input closure without permitting changed proof sources', async () => {
        const data = await fixture();
        try {
            const historical = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            const files = [...historical.sources.keys()];
            await expect(
                assertSeedSharingSharedInputs(
                    historical,
                    files,
                    historical.compiler,
                    data.root,
                ),
            ).rejects.toThrow('did not compile a shared input');
            const compiledInputs = data.manifest.sources.slice(1);
            Object.assign(data.result, { compiledInputs });
            await data.save();
            const incomplete = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            await expect(
                assertSeedSharingSharedInputs(
                    incomplete,
                    files,
                    incomplete.compiler,
                    data.root,
                ),
            ).rejects.toThrow('did not compile a shared input');
            compiledInputs.unshift(data.manifest.sources[0]);
            await data.save();
            const source = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            await expect(
                assertSeedSharingSharedInputs(
                    source,
                    files,
                    source.compiler,
                    data.root,
                ),
            ).resolves.toBeUndefined();
            await expect(
                assertSeedSharingSharedInputs(
                    source,
                    files,
                    'different compiler',
                    data.root,
                ),
            ).rejects.toThrow('another compiler');
            await expect(
                assertSeedSharingSharedInputs(
                    source,
                    [],
                    source.compiler,
                    data.root,
                ),
            ).rejects.toThrow('closure is empty');
            await expect(
                assertSeedSharingSharedInputs(
                    source,
                    ['crates/protocol-research/word-proof/src/new-input.rs'],
                    source.compiler,
                    data.root,
                ),
            ).rejects.toThrow('shared input');
            await writeFile(path.join(data.root, files[0]), 'y');
            await expect(
                assertSeedSharingSharedInputs(
                    source,
                    files,
                    source.compiler,
                    data.root,
                ),
            ).rejects.toThrow('shared native source changed');
            data.summary.exitCode = 1;
            await data.save();
            await expect(
                assertSeedSharingSourceStable(source, data.root),
            ).rejects.toThrow();
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
    it('rejects compiled inventories that differ from their source snapshots', async () => {
        const data = await fixture();
        try {
            Object.assign(data.result, {
                compiledInputs: [
                    { ...data.manifest.sources[0], sha512: 'f'.repeat(128) },
                ],
            });
            await data.save();
            await expect(
                readSeedSharingNativeSource(data.source, data.root),
            ).rejects.toThrow('differs from its source manifest');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
    it('checks recorded proof identities when a fresh native baseline supplies them', async () => {
        const data = await fixture();
        try {
            const source = await readSeedSharingNativeSource(
                data.source,
                data.root,
            );
            const proofArtifacts = source.proofs.map(
                ({ name, bytes, sha512 }) => ({ name, bytes, sha512 }),
            );
            Object.assign(data.result, { proofArtifacts });
            await data.save();
            await expect(
                readSeedSharingNativeSource(data.source, data.root),
            ).resolves.toMatchObject({ proofs: source.proofs });
            proofArtifacts[1].sha512 = 'f'.repeat(128);
            await data.save();
            await expect(
                readSeedSharingNativeSource(data.source, data.root),
            ).rejects.toThrow('recorded identities');
        } finally {
            await rm(data.root, { recursive: true });
        }
    });
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
            generation = false,
        ) => {
            const module = binaryen.parseText(
                `(module ${extra} ${memory} ${['input_pointer', 'input_capacity', 'header_length', 'begin', 'push', 'finish'].map((name) => `(func (export "seed_verifier_${name}") (result i32) (i32.const 0))`).join(' ')} ${generation ? ['begin', 'phase', 'step', 'next_output', 'output_pointer', 'output_length', 'output_capacity', 'ack_output'].map((name) => `(func (export "seed_prover_${name}") (result i32) (i32.const 0))`).join(' ') : ''})`,
            );
            try {
                return module.emitBinary();
            } finally {
                module.dispose();
            }
        };
        await expect(
            inspectScalarFixtureModule(moduleBytes()),
        ).resolves.toMatchObject({ imports: [] });
        await expect(
            inspectScalarFixtureModule(
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
            inspectScalarFixtureModule(
                moduleBytes(
                    undefined,
                    '(import "word_proof" "fill_random" (func))',
                ),
            ),
        ).rejects.toThrow('unknown host import');
        await expect(
            inspectScalarFixtureModule(
                moduleBytes(
                    undefined,
                    '(import "word_proof" "fill_random" (func))',
                    true,
                ),
                true,
            ),
        ).resolves.toMatchObject({
            imports: [
                { module: 'word_proof', name: 'fill_random', kind: 'function' },
            ],
        });
        await expect(
            inspectScalarFixtureModule(moduleBytes(), true),
        ).rejects.toThrow('prover is missing');
        await expect(
            inspectScalarFixtureModule(
                moduleBytes('(memory (export "memory") 1 16384)'),
            ),
        ).rejects.toThrow('bounded unshared');
        await expect(
            inspectScalarFixtureModule(
                moduleBytes('(memory (export "memory") 1 10240 shared)'),
            ),
        ).rejects.toThrow('bounded unshared');
        await expect(
            inspectScalarFixtureModule(
                moduleBytes(
                    undefined,
                    '(func (drop (v128.const i32x4 0 0 0 0)))',
                ),
            ),
        ).rejects.toThrow('scalar instructions');
    });
});
