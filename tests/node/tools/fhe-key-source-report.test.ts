import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import {
    assertFheKeySourceStable,
    fheKeySourceProgressLines,
    parseFheKeySourceOutput,
    parseFheKeySourceReport,
    readFheKeySourceNativeSource,
} from '#tools/ci/fhe-key-source-report.js';
import { runArtifactDirectoryPath } from '#tools/ci/local-run-log.js';
import { assertScalarNativeInputs } from '#tools/ci/seed-sharing-scalar-source.js';

const digest = (bytes: Uint8Array | string) =>
    createHash('sha512').update(bytes).digest('hex');
const roots: string[] = [];
const putMagnitude = (
    bytes: Buffer,
    offset: number,
    width: number,
    value: bigint,
) => {
    for (let index = 0; index < width; index++) {
        bytes[offset + index] = Number(value & 255n);
        value >>= 8n;
    }
    expect(value).toBe(0n);
};

// These public framing fixtures exercise the decoder; they are not source
// generation, a computed FHE coordinate or an arithmetic correctness claim.
const reportFixture = () => {
    const model = compileFheKeySourceScreenResources();
    const bytes = Buffer.alloc(Number(model.reportBytes));
    bytes.write('FKS1');
    const dimensions = [
        model.participantCount,
        model.optionCount,
        Number(model.degree),
        Number(model.coefficientBytes - 1n),
        model.commonSampleBits,
        model.samplePositions.length,
    ];
    dimensions.forEach((value, index) =>
        bytes.writeUInt32LE(value, 4 + 4 * index),
    );
    bytes.fill(17, 28, 156);
    const width = Number(model.coefficientBytes - 1n);
    let offset = 156;
    const offsets: number[] = [];
    const samples = model.samplePositions.map((position, index) => {
        offsets.push(offset);
        bytes.writeUInt32LE(position, offset);
        const value =
            index === 0
                ? 0n
                : index === 1
                  ? model.modulus / 2n
                  : index === 2
                    ? -(model.modulus / 2n)
                    : (1n << 70n) + BigInt(index);
        bytes[offset + 4] = value < 0n ? 1 : 0;
        putMagnitude(bytes, offset + 5, width, value < 0n ? -value : value);
        offset += 5 + width;
        return { position, value: value.toString() };
    });
    expect(offset).toBe(bytes.length);
    return {
        model,
        bytes,
        offsets,
        width,
        expected: {
            originalDigest: Buffer.alloc(64, 17).toString('hex'),
            restoredDigest: Buffer.alloc(64, 17).toString('hex'),
            samples,
        },
    };
};

const nativeFixture = async () => {
    await mkdir('temp', { recursive: true });
    const root = await mkdtemp(path.resolve('temp/fhe-source-intake-test-'));
    roots.push(root);
    const source = path.join(
        root,
        'logs/2026-10-04/2026-10-04T00-00-00.000Z-research-protocol',
    );
    const archive = path.join(
        runArtifactDirectoryPath(source),
        'fhe-key-source',
    );
    await mkdir(source, { recursive: true });
    await mkdir(archive, { recursive: true });
    const fixture = reportFixture();
    await writeFile(path.join(archive, 'key-source-0.bin'), fixture.bytes);
    const runtime = Buffer.alloc(64, 19);
    await writeFile(path.join(path.dirname(archive), 'runtime.bin'), runtime);
    const sources = [
        'fhe-key-source',
        'fhe-key-source-screen',
        'contribution',
        'lib',
    ].map((name) => ({
        file: `crates/protocol-research/setup-witness/src/${name}.rs`,
        bytes: 1,
        sha512: digest('x'),
    }));
    for (const entry of sources) {
        await mkdir(path.dirname(path.join(root, entry.file)), {
            recursive: true,
        });
        await writeFile(path.join(root, entry.file), 'x');
    }
    const summary = {
        result: 'passed',
        exitCode: 0,
        scriptName: 'research:protocol',
    };
    const manifest = { compiler: 'synthetic compiler', sources };
    const result = {
        case: 'native-fhe-key-source',
        participantCount: 3,
        optionCount: 2,
        simulatedHelpers: 0,
        output: archive,
        runtimeIdentity: runtime.toString('hex'),
        compiledInputs: [...sources],
        artifacts: [
            {
                name: 'key-source-0.bin',
                bytes: fixture.bytes.length,
                sha512: digest(fixture.bytes),
            },
        ],
        native: [
            {
                result: {
                    kind: 'fhe-key-source-screen',
                    reportBytes: fixture.bytes.length,
                },
            },
        ],
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
    return { root, source, archive, fixture, summary, result, save };
};

afterEach(async () => {
    for (const root of roots.splice(0)) {
        assert.ok(
            path.resolve(root).startsWith(path.resolve('temp') + path.sep),
        );
        await rm(root, { recursive: true });
    }
});

describe('FHE key source report and source intake', () => {
    it('preserves canonical zero, both centered extremes and wide values from a subview', () => {
        const fixture = reportFixture();
        expect(parseFheKeySourceReport(fixture.bytes)).toEqual(
            fixture.expected,
        );
        const framed = Buffer.concat([
            Buffer.alloc(7),
            fixture.bytes,
            Buffer.alloc(11),
        ]);
        expect(
            parseFheKeySourceReport(
                framed.subarray(7, 7 + fixture.bytes.length),
            ),
        ).toEqual(fixture.expected);
    });
    it('rejects altered shape, context-independent digest disagreement and noncanonical public samples', () => {
        const { bytes, offsets, width, model } = reportFixture();
        const changes: ((copy: Buffer) => void)[] = [
            (copy) => {
                copy[0] ^= 1;
            },
            (copy) => {
                copy[92] ^= 1;
            },
            ...Array.from({ length: 6 }, (_, index) => (copy: Buffer) => {
                copy[4 + 4 * index] ^= 1;
            }),
            (copy) => {
                copy[offsets[0]] ^= 1;
            },
            (copy) => {
                copy[offsets[0] + 4] = 1;
            },
            (copy) => {
                copy[offsets[1] + 4] = 2;
            },
            (copy) =>
                putMagnitude(
                    copy,
                    offsets[1] + 5,
                    width,
                    model.modulus / 2n + 1n,
                ),
        ];
        for (const change of changes) {
            const altered = Buffer.from(bytes);
            change(altered);
            expect(() => parseFheKeySourceReport(altered)).toThrow();
        }
        expect(() => parseFheKeySourceReport(bytes.subarray(1))).toThrow();
        expect(() =>
            parseFheKeySourceReport(Buffer.concat([bytes, Buffer.alloc(1)])),
        ).toThrow();
    });
    it('accepts only the named unique native result and known arithmetic progress', () => {
        const result = {
            kind: 'fhe-key-source-screen',
            reportBytes: Number(
                compileFheKeySourceScreenResources().reportBytes,
            ),
        };
        const line = JSON.stringify(result);
        const progress = JSON.stringify({
            event: 'operator-call',
            operation: 'step',
            phase: 1,
            milliseconds: 0,
        });
        expect(
            parseFheKeySourceOutput(
                [...fheKeySourceProgressLines, progress, line].join('\n'),
            ),
        ).toEqual(result);
        for (const output of [
            '',
            line + '\n' + line,
            'Generated encryption-1\n' + line,
            JSON.stringify({
                event: 'operator-call',
                operation: 'step',
                phase: 1,
                milliseconds: -1,
            }) +
                '\n' +
                line,
            JSON.stringify({ event: 'unknown' }) + '\n' + line,
            JSON.stringify({ ...result, kind: 'other' }),
            JSON.stringify({ ...result, reportBytes: result.reportBytes + 1 }),
        ])
            expect(() => parseFheKeySourceOutput(output)).toThrow();
    });
    it('accepts a passed exact native archive and detects diagnostic changes', async () => {
        const fixture = await nativeFixture();
        const source = await readFheKeySourceNativeSource(
            fixture.source,
            fixture.root,
        );
        expect(source.reports).toEqual([fixture.fixture.expected]);
        await expect(
            assertFheKeySourceStable(source, fixture.root),
        ).resolves.toBeUndefined();
        fixture.result.native[0].result.reportBytes++;
        await fixture.save();
        await expect(
            assertFheKeySourceStable(source, fixture.root),
        ).rejects.toThrow();
    });
    it('rejects failed runs, missing compiled owners and unrecorded artifacts', async () => {
        const fixture = await nativeFixture();
        fixture.summary.result = 'failed';
        await fixture.save();
        await expect(
            readFheKeySourceNativeSource(fixture.source, fixture.root),
        ).rejects.toThrow();
        fixture.summary.result = 'passed';
        const source = fixture.result.compiledInputs.pop()!;
        await fixture.save();
        await expect(
            readFheKeySourceNativeSource(fixture.source, fixture.root),
        ).rejects.toThrow();
        fixture.result.compiledInputs.push(source);
        await fixture.save();
        await writeFile(path.join(fixture.archive, 'extra.bin'), 'extra');
        await expect(
            readFheKeySourceNativeSource(fixture.source, fixture.root),
        ).rejects.toThrow();
    });
    it('pins only the exact browser entropy adapter while requiring the screen arithmetic in the native closure', async () => {
        const fixture = await nativeFixture();
        const source = await readFheKeySourceNativeSource(
            fixture.source,
            fixture.root,
        );
        const adapter = {
            file: 'crates/protocol-research/setup-witness/src/browser_random.rs',
            bytes: 1,
            sha512: digest('x'),
        };
        source.sources.set(adapter.file, adapter);
        await writeFile(path.join(fixture.root, adapter.file), 'x');
        const files = [...source.compiledInputs.keys(), adapter.file];
        await expect(
            assertScalarNativeInputs(
                source,
                files,
                source.compiler,
                fixture.root,
                'fhe-key-source',
            ),
        ).resolves.toEqual({
            unchangedNativeInputs: [...source.compiledInputs.keys()].sort(),
            targetAdapters: [adapter.file],
        });
        const unrelated = {
            ...adapter,
            file: 'crates/protocol-research/setup-witness/src/browser.rs',
        };
        source.sources.set(unrelated.file, unrelated);
        await writeFile(path.join(fixture.root, unrelated.file), 'x');
        await expect(
            assertScalarNativeInputs(
                source,
                [...files, unrelated.file],
                source.compiler,
                fixture.root,
                'fhe-key-source',
            ),
        ).rejects.toThrow('did not compile a scalar shared input');
        source.compiledInputs.delete(
            'crates/protocol-research/setup-witness/src/fhe-key-source-screen.rs',
        );
        await expect(
            assertScalarNativeInputs(
                source,
                files,
                source.compiler,
                fixture.root,
                'fhe-key-source',
            ),
        ).rejects.toThrow('did not compile a scalar shared input');
    });
});
