import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { open, readdir } from 'node:fs/promises';
import path from 'node:path';

import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import { readNativeSourceMetadata } from '#tools/ci/seed-sharing-scalar-source.js';

export const fheKeySourceProgressLines = [
    'Generated encryption-0',
    'Generated first-relinearization-0',
    'Generated second-relinearization-0',
    'Generated automorphism-0',
] as const;

export const parseFheKeySourceOutput = (output: string) => {
    const records = output
        .trim()
        .split(/\r?\n/u)
        .filter(Boolean)
        .flatMap((line) => {
            if (fheKeySourceProgressLines.some((allowed) => line === allowed))
                return [];
            const value = JSON.parse(line) as Record<string, unknown>;
            assert.ok(value !== null && typeof value === 'object');
            if (typeof value.kind === 'string') return [value];
            assert.ok(
                value.event === 'native-operator-ready' ||
                    value.event === 'native-operator-completed' ||
                    value.event === 'operator-call',
                'The key source screen emitted an unknown diagnostic.',
            );
            if (value.event === 'operator-call') {
                assert.ok(
                    value.operation === 'step' || value.operation === 'output',
                );
                assert.ok(
                    Number.isInteger(value.phase) &&
                        Number(value.phase) >= 1 &&
                        Number(value.phase) <= 12,
                );
                assert.ok(
                    typeof value.milliseconds === 'number' &&
                        Number.isFinite(value.milliseconds) &&
                        value.milliseconds >= 0,
                );
            }
            return [];
        });
    assert.equal(
        records.length,
        1,
        'The key source screen must emit exactly one result.',
    );
    const result = records[0];
    assert.equal(result.kind, 'fhe-key-source-screen');
    assert.equal(
        result.reportBytes,
        Number(compileFheKeySourceScreenResources().reportBytes),
    );
    return result;
};

// Only public-coordinate equality and the exact report grammar are checked
// here. The native/Wasm source screen owns its independent arithmetic checks.
export const parseFheKeySourceReport = (bytes: Uint8Array) => {
    const model = compileFheKeySourceScreenResources();
    assert.equal(BigInt(bytes.byteLength), model.reportBytes);
    const input = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;
    const take = (length: number) => {
        const value = input.subarray(offset, offset + length);
        assert.equal(value.length, length);
        offset += length;
        return value;
    };
    const integer = () => take(4).readUInt32LE();
    assert.ok(take(4).equals(Buffer.from('FKS1', 'ascii')));
    const dimensions = Array.from({ length: 6 }, integer);
    assert.deepEqual(dimensions, [
        model.participantCount,
        model.optionCount,
        Number(model.degree),
        Number(model.coefficientBytes - 1n),
        model.commonSampleBits,
        model.samplePositions.length,
    ]);
    const originalDigest = take(64).toString('hex');
    const restoredDigest = take(64).toString('hex');
    assert.equal(
        restoredDigest,
        originalDigest,
        'The restored public coordinate differs.',
    );
    const samples = model.samplePositions.map((position) => {
        assert.equal(integer(), position);
        const sign = take(1)[0];
        assert.ok(
            sign === 0 || sign === 1,
            'A key source sample sign is not canonical.',
        );
        const encoded = take(Number(model.coefficientBytes - 1n));
        let magnitude = 0n;
        for (let index = encoded.length - 1; index >= 0; index--)
            magnitude = (magnitude << 8n) | BigInt(encoded[index]);
        assert.ok(
            magnitude <= model.modulus / 2n,
            'A key source sample is not centered.',
        );
        assert.ok(
            sign === 0 || magnitude !== 0n,
            'A key source sample encodes negative zero.',
        );
        return {
            position,
            value: (sign === 0 ? magnitude : -magnitude).toString(),
        };
    });
    assert.equal(offset, input.length);
    return { originalDigest, restoredDigest, samples };
};

export const readFheKeySourceNativeSource = async (
    source: string,
    root: string,
) => {
    const { report, artifactDirectory, ...base } =
        await readNativeSourceMetadata(source, root, 'native-fhe-key-source');
    const archive = path.join(artifactDirectory, 'fhe-key-source');
    assert.equal(path.resolve(String(report.output)), archive);
    const name = 'key-source-0.bin';
    assert.deepEqual(await readdir(archive), [name]);
    assert.ok(Array.isArray(report.native));
    assert.equal(report.native.length, 1);
    const native = report.native[0] as { result: Record<string, unknown> };
    parseFheKeySourceOutput(JSON.stringify(native.result));
    const file = path.join(archive, name);
    const handle = await open(file, 'r');
    const model = compileFheKeySourceScreenResources();
    let bytes: Buffer;
    try {
        const details = await handle.stat();
        assert.ok(details.isFile());
        assert.equal(BigInt(details.size), model.reportBytes);
        const buffer = Buffer.alloc(Number(model.reportBytes) + 1);
        let read = 0;
        while (read < buffer.length) {
            const { bytesRead } = await handle.read(
                buffer,
                read,
                buffer.length - read,
                read,
            );
            if (bytesRead === 0) break;
            read += bytesRead;
        }
        assert.equal(read, Number(model.reportBytes));
        bytes = buffer.subarray(0, read);
    } finally {
        await handle.close();
    }
    const reports = [parseFheKeySourceReport(bytes)];
    const artifacts = [
        {
            name,
            file,
            bytes: bytes.length,
            sha512: createHash('sha512').update(bytes).digest('hex'),
        },
    ];
    assert.deepEqual(
        report.artifacts,
        artifacts.map((artifact) => ({
            name: artifact.name,
            bytes: artifact.bytes,
            sha512: artifact.sha512,
        })),
    );
    for (const owner of [
        'fhe-key-source',
        'fhe-key-source-screen',
        'contribution',
        'lib',
    ])
        assert.ok(
            base.compiledInputs.has(
                `crates/protocol-research/setup-witness/src/${owner}.rs`,
            ),
            'The key source native closure lacks an owning input.',
        );
    return { ...base, archive, artifacts, reports };
};

export const assertFheKeySourceStable = async (
    source: Pick<
        Awaited<ReturnType<typeof readFheKeySourceNativeSource>>,
        'directory' | 'diagnosticDigests' | 'artifacts'
    >,
    root: string,
) => {
    const current = await readFheKeySourceNativeSource(source.directory, root);
    assert.deepEqual(current.diagnosticDigests, source.diagnosticDigests);
    assert.deepEqual(current.artifacts, source.artifacts);
};
