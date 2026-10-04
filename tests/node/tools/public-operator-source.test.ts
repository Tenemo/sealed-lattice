import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { compilePublicOperatorScreenResources } from '#tests/recoverable-setup-resource-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    assertPublicOperatorSourceStable,
    parsePublicOperatorReport,
    readPublicOperatorNativeSource,
} from '#tools/ci/public-operator-source.js';

const prime = compileSmallLimbProofFieldCensus().modulus;
const digest = (bytes: Uint8Array | string) =>
    createHash('sha512').update(bytes).digest('hex');
const roots: string[] = [];
const word = (bytes: Buffer, offset: number, value: bigint) => {
    bytes.writeBigUInt64LE(value & ((1n << 64n) - 1n), offset);
    bytes.writeBigUInt64LE(value >> 64n, offset + 8);
};

// Small synthetic reports test framing and evidence intake, not a computed
// full-ring operator or its mathematical equivalence. The independent packer
// uses the specified OPR1 byte grammar and the maintained model coordinates.
const reportFixture = (kind: 'seed' | 'opening') => {
    const model = compilePublicOperatorScreenResources(kind);
    const bytes = Buffer.alloc(Number(model.reportBytes));
    bytes.write('OPR1', 0, 'ascii');
    let offset = 4;
    const shape = [
        model.caseId,
        Number(model.degree),
        model.participants,
        model.threshold,
        model.selectedCount,
        Number(model.seedBits),
        model.columns,
        model.queryCount,
    ];
    for (const value of shape) {
        bytes.writeUInt32LE(value, offset);
        offset += 4;
    }
    const fields = [
        model.alpha,
        [prime - 1n, 1n << 100n, 3n],
        [0n, 1n, prime - 2n],
    ];
    const fieldOffsets: number[] = [];
    for (const field of fields)
        for (const value of field) {
            fieldOffsets.push(offset);
            word(bytes, offset, value);
            offset += 16;
        }
    const operatorDigest = Buffer.from(
        Array.from({ length: 64 }, (_unused, index) => index + 1),
    );
    const queryDigest = Buffer.alloc(64, 173);
    operatorDigest.copy(bytes, offset);
    offset += 64;
    queryDigest.copy(bytes, offset);
    offset += 64;
    const countsOffset = offset;
    bytes.writeUInt32LE(model.physicalSamples.length, offset);
    offset += 4;
    bytes.writeUInt32LE(model.querySamples.length, offset);
    offset += 4;
    expect(offset).toBe(Number(model.reportHeaderBytes));
    const sampleOffsets: number[] = [];
    const groups = [model.physicalSamples, model.querySamples].map(
        (samples, group) =>
            samples.map((sample, index) => {
                sampleOffsets.push(offset);
                bytes.writeUInt32LE(sample.column, offset);
                offset += 4;
                bytes.writeUInt32LE(sample.index, offset);
                offset += 4;
                const value = [
                    BigInt(index + 1),
                    (1n << 90n) + BigInt(group + index),
                    prime - BigInt(index + 3),
                ];
                for (const component of value) {
                    fieldOffsets.push(offset);
                    word(bytes, offset, component);
                    offset += 16;
                }
                return { ...sample, value: value.map(String) };
            }),
    );
    expect(offset).toBe(bytes.length);
    return {
        bytes,
        model,
        fieldOffsets,
        sampleOffsets,
        countsOffset,
        expected: {
            kind,
            caseId: model.caseId,
            degree: Number(model.degree),
            participants: model.participants,
            threshold: model.threshold,
            selectedCount: model.selectedCount,
            seedBits: Number(model.seedBits),
            columns: model.columns,
            queryCount: model.queryCount,
            alpha: fields[0].map(String),
            target: fields[1].map(String),
            lookupWeight: fields[2].map(String),
            operatorDigest: operatorDigest.toString('hex'),
            queryDigest: queryDigest.toString('hex'),
            physicalSamples: groups[0],
            querySamples: groups[1],
        },
    };
};

const sourceFixture = async () => {
    await mkdir('temp', { recursive: true });
    const root = await mkdtemp(path.resolve('temp/public-operator-source-'));
    roots.push(root);
    const source = path.join(root, 'logs/2026-10-04/operator');
    const artifacts = path.join(root, 'temp/run-artifacts/2026-10-04/operator');
    const archive = path.join(artifacts, 'public-operator');
    await mkdir(source, { recursive: true });
    await mkdir(archive, { recursive: true });
    const runtime = Buffer.alloc(64, 29);
    await writeFile(path.join(artifacts, 'runtime.bin'), runtime);
    const reports = (['seed', 'opening'] as const).map(reportFixture);
    const inventory = reports.map(({ bytes }, index) => ({
        name: `operator-${index}.bin`,
        bytes: bytes.length,
        sha512: digest(bytes),
    }));
    for (const [index, report] of reports.entries())
        await writeFile(
            path.join(archive, inventory[index].name),
            report.bytes,
        );
    const sources = [
        'crates/protocol-research/public-operator-screen/src/lib.rs',
        'crates/protocol-research/public-operator-screen/src/recipe.rs',
        'crates/protocol-research/public-operator-screen/src/reference.rs',
        'crates/protocol-research/setup-stream-kernel/src/lib.rs',
        'crates/protocol-research/Cargo.toml',
        'crates/protocol-research/Cargo.lock',
    ].map((file, index) => {
        const contents = 'synthetic source ' + String(index);
        return {
            file,
            bytes: Buffer.byteLength(contents),
            sha512: digest(contents),
        };
    });
    for (const [index, entry] of sources.entries()) {
        await mkdir(path.dirname(path.join(root, entry.file)), {
            recursive: true,
        });
        await writeFile(
            path.join(root, entry.file),
            'synthetic source ' + String(index),
        );
    }
    const summary = {
        result: 'passed',
        exitCode: 0,
        scriptName: 'research:protocol',
    };
    const manifest = { compiler: 'synthetic compiler', sources };
    const result = {
        case: 'native-public-operator',
        participantCount: 4,
        optionCount: 2,
        simulatedHelpers: 0,
        output: archive,
        runtimeIdentity: runtime.toString('hex'),
        artifacts: inventory,
        compiledInputs: sources.map((entry) => ({ ...entry })),
        native: reports.map(({ model, bytes }) => ({
            result: {
                kind: 'public-operator-screen',
                case: model.kind,
                reportBytes: bytes.length,
            },
        })),
    };
    const save = async () => {
        for (const [name, value] of [
            ['summary', summary],
            ['source-manifest', manifest],
            ['result', result],
        ] as const)
            await writeFile(
                path.join(source, name + '.json'),
                JSON.stringify(value),
            );
    };
    await save();
    return {
        root,
        source,
        artifacts,
        archive,
        reports,
        summary,
        manifest,
        result,
        save,
    };
};

afterEach(async () => {
    for (const root of roots.splice(0)) {
        const resolved = path.resolve(root);
        assert.ok(resolved.startsWith(path.resolve('temp') + path.sep));
        await rm(resolved, { recursive: true, force: true });
    }
});

describe('public operator report framing', () => {
    it.each(['seed', 'opening'] as const)(
        'preserves every %s coordinate and wide canonical field without numeric rounding',
        (kind) => {
            const fixture = reportFixture(kind);
            expect(parsePublicOperatorReport(fixture.bytes, kind)).toEqual(
                fixture.expected,
            );
            const allocation = Buffer.concat([
                Buffer.alloc(7),
                fixture.bytes,
                Buffer.alloc(11),
            ]);
            expect(
                parsePublicOperatorReport(
                    allocation.subarray(7, 7 + fixture.bytes.length),
                    kind,
                ),
            ).toEqual(fixture.expected);
        },
    );

    it.each(['seed', 'opening'] as const)(
        'rejects wrong %s case, dimensions, challenge, counts and framing',
        (kind) => {
            const fixture = reportFixture(kind);
            expect(() =>
                parsePublicOperatorReport(
                    fixture.bytes,
                    kind === 'seed' ? 'opening' : 'seed',
                ),
            ).toThrow();
            for (let field = 0; field < 8; field++) {
                const changed = Buffer.from(fixture.bytes);
                changed.writeUInt32LE(
                    changed.readUInt32LE(4 + 4 * field) + 1,
                    4 + 4 * field,
                );
                expect(() =>
                    parsePublicOperatorReport(changed, kind),
                ).toThrow();
            }
            for (const field of [0, 1, 2]) {
                const changed = Buffer.from(fixture.bytes);
                word(
                    changed,
                    fixture.fieldOffsets[field],
                    fixture.model.alpha[field] + 1n,
                );
                expect(() =>
                    parsePublicOperatorReport(changed, kind),
                ).toThrow();
            }
            for (const count of [0, 1]) {
                const changed = Buffer.from(fixture.bytes);
                changed.writeUInt32LE(
                    0xffff_ffff,
                    fixture.countsOffset + 4 * count,
                );
                expect(() =>
                    parsePublicOperatorReport(changed, kind),
                ).toThrow();
            }
            const wrongMagic = Buffer.from(fixture.bytes);
            wrongMagic[0] ^= 1;
            const highBitMagic = Buffer.from(fixture.bytes);
            highBitMagic[0] |= 0x80;
            for (const malformed of [
                wrongMagic,
                highBitMagic,
                fixture.bytes.subarray(0, 3),
                fixture.bytes.subarray(0, fixture.countsOffset + 7),
                fixture.bytes.subarray(0, fixture.bytes.length - 1),
                Buffer.concat([fixture.bytes, Buffer.from([0])]),
            ])
                expect(() =>
                    parsePublicOperatorReport(malformed, kind),
                ).toThrow();
        },
    );

    it.each(['seed', 'opening'] as const)(
        'rejects noncanonical %s field components and changed ordered sample coordinates',
        (kind) => {
            const fixture = reportFixture(kind);
            for (const offset of fixture.fieldOffsets) {
                const changed = Buffer.from(fixture.bytes);
                word(changed, offset, prime);
                expect(() =>
                    parsePublicOperatorReport(changed, kind),
                ).toThrow();
            }
            for (const offset of [
                fixture.sampleOffsets[0],
                fixture.sampleOffsets[fixture.model.physicalSamples.length],
                fixture.sampleOffsets[fixture.sampleOffsets.length - 1],
            ]) {
                for (const coordinate of [0, 4]) {
                    const changed = Buffer.from(fixture.bytes);
                    changed.writeUInt32LE(
                        changed.readUInt32LE(offset + coordinate) + 1,
                        offset + coordinate,
                    );
                    expect(() =>
                        parsePublicOperatorReport(changed, kind),
                    ).toThrow();
                }
            }
            const swapped = Buffer.from(fixture.bytes);
            const first = Buffer.from(
                swapped.subarray(
                    fixture.sampleOffsets[0],
                    fixture.sampleOffsets[1],
                ),
            );
            swapped.copy(
                swapped,
                fixture.sampleOffsets[0],
                fixture.sampleOffsets[1],
                fixture.sampleOffsets[2],
            );
            first.copy(swapped, fixture.sampleOffsets[1]);
            expect(() => parsePublicOperatorReport(swapped, kind)).toThrow();
        },
    );
});

describe('public operator native source intake', () => {
    it('pins both exact reports and checks source stability without rewriting historical files', async () => {
        const fixture = await sourceFixture();
        const before = await readFile(path.join(fixture.source, 'result.json'));
        const source = await readPublicOperatorNativeSource(
            fixture.source,
            fixture.root,
        );
        expect(source.reports).toEqual(
            fixture.reports.map(({ expected }) => expected),
        );
        expect(
            source.artifacts.map(({ name, bytes, sha512 }) => ({
                name,
                bytes,
                sha512,
            })),
        ).toEqual(fixture.result.artifacts);
        await expect(
            assertPublicOperatorSourceStable(source, fixture.root),
        ).resolves.toBeUndefined();
        expect(
            await readFile(path.join(fixture.source, 'result.json')),
        ).toEqual(before);
        fixture.manifest.compiler = 'changed compiler';
        await fixture.save();
        await expect(
            assertPublicOperatorSourceStable(source, fixture.root),
        ).rejects.toThrow();
    });

    it('refuses artifact substitution, missing or extra outputs, and recorded digest changes', async () => {
        for (const damage of [
            'bytes',
            'missing',
            'extra',
            'digest',
            'runtime',
        ] as const) {
            const fixture = await sourceFixture();
            await readPublicOperatorNativeSource(fixture.source, fixture.root);
            if (damage === 'bytes') {
                const bytes = Buffer.from(fixture.reports[0].bytes);
                // A canonical value change preserves the size and parser
                // shape; only the recorded artifact identity detects it.
                word(bytes, fixture.reports[0].fieldOffsets[3], 7n);
                await writeFile(
                    path.join(fixture.archive, 'operator-0.bin'),
                    bytes,
                );
            } else if (damage === 'missing')
                await rm(path.join(fixture.archive, 'operator-1.bin'));
            else if (damage === 'extra')
                await writeFile(
                    path.join(fixture.archive, 'unexpected.bin'),
                    Buffer.from([0]),
                );
            else if (damage === 'digest') {
                fixture.result.artifacts[1].sha512 = '0'.repeat(128);
                await fixture.save();
            } else
                await writeFile(
                    path.join(fixture.artifacts, 'runtime.bin'),
                    Buffer.alloc(64, 30),
                );
            await expect(
                readPublicOperatorNativeSource(fixture.source, fixture.root),
            ).rejects.toThrow();
        }
    });

    it('refuses failed runs, wrong guard results and incomplete or inconsistent compiled source evidence', async () => {
        for (const damage of [
            'failed',
            'case',
            'guard-case',
            'guard-size',
            'no-compiled',
            'snapshot-only',
            'compiled-hash',
            'duplicate',
            'traversal',
        ] as const) {
            const fixture = await sourceFixture();
            await readPublicOperatorNativeSource(fixture.source, fixture.root);
            switch (damage) {
                case 'failed':
                    fixture.summary.result = 'failed';
                    break;
                case 'case':
                    fixture.result.case = 'native-seed-sharing';
                    break;
                case 'guard-case':
                    fixture.result.native[0].result.case = 'opening';
                    break;
                case 'guard-size':
                    fixture.result.native[1].result.reportBytes++;
                    break;
                case 'no-compiled':
                    fixture.result.compiledInputs = [];
                    break;
                case 'snapshot-only':
                    fixture.result.compiledInputs.shift();
                    break;
                case 'compiled-hash':
                    fixture.result.compiledInputs[0].sha512 = '0'.repeat(128);
                    break;
                case 'duplicate':
                    fixture.result.compiledInputs.push(
                        fixture.result.compiledInputs[0],
                    );
                    break;
                case 'traversal':
                    fixture.manifest.sources[0].file = '../outside.rs';
                    break;
            }
            await fixture.save();
            await expect(
                readPublicOperatorNativeSource(fixture.source, fixture.root),
            ).rejects.toThrow();
        }
    });
});
