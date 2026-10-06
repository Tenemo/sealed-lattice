import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { open, readFile, readdir, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import { fileDigest } from '#tools/ci/fixture-sources.js';
import { runArtifactDirectoryPath } from '#tools/ci/local-run-log.js';

type NativeSourceEntry = Readonly<{
    file: string;
    sha512: string;
    bytes: number;
}>;

type NativeReferenceArtifact = Readonly<{
    name: string;
    file: string;
    bytes: number;
    sha512: string;
}>;

// Diagnostics describe only this recorded native run. A consuming build
// separately checks its actual compiled inputs against this recorded closure.
const readNativeSourceMetadata = async (source: string, root: string) => {
    const directory = path.resolve(source);
    const relative = path.relative(path.join(root, 'logs'), directory);
    assert.ok(
        relative && !relative.startsWith('..') && !path.isAbsolute(relative),
        'The source must be a repository run directory.',
    );
    const readJson = async (name: string) => {
        const file = path.join(directory, name);
        assert.ok(
            (await stat(file)).size <= 16 * 1024 * 1024,
            'The source diagnostic is oversized.',
        );
        const bytes = await readFile(file);
        return {
            value: JSON.parse(bytes.toString('utf8')) as Record<
                string,
                unknown
            >,
            sha512: createHash('sha512').update(bytes).digest('hex'),
        };
    };
    const summary = await readJson('summary.json');
    const result = await readJson('result.json');
    const manifest = await readJson('source-manifest.json');
    assert.equal(summary.value.result, 'passed');
    assert.equal(summary.value.exitCode, 0);
    assert.equal(summary.value.scriptName, 'research:protocol');
    assert.equal(result.value.case, 'native-fhe-key-source');
    assert.equal(result.value.participantCount, 3);
    assert.equal(result.value.optionCount, 2);
    assert.equal(result.value.simulatedHelpers, 0);
    const artifactDirectory = runArtifactDirectoryPath(directory);
    assert.match(String(result.value.runtimeIdentity), /^[0-9a-f]{128}$/u);
    const expectedRuntimeBytes =
        String(result.value.runtimeIdentity).length / 2;
    const runtime = await open(
        path.join(artifactDirectory, 'runtime.bin'),
        'r',
    );
    try {
        const details = await runtime.stat();
        assert.ok(details.isFile());
        assert.equal(
            details.size,
            expectedRuntimeBytes,
            'The recorded runtime digest has another length.',
        );
        const buffer = Buffer.alloc(expectedRuntimeBytes + 1);
        let read = 0;
        while (read < buffer.length) {
            const { bytesRead } = await runtime.read(
                buffer,
                read,
                buffer.length - read,
                read,
            );
            if (bytesRead === 0) break;
            read += bytesRead;
        }
        assert.equal(
            read,
            expectedRuntimeBytes,
            'The runtime digest length changed while reading.',
        );
        assert.equal(
            buffer.subarray(0, read).toString('hex'),
            result.value.runtimeIdentity,
        );
    } finally {
        await runtime.close();
    }
    assert.ok(
        typeof manifest.value.compiler === 'string' &&
            Array.isArray(manifest.value.sources),
    );
    const sources = new Map<string, NativeSourceEntry>();
    for (const entry of manifest.value.sources as NativeSourceEntry[]) {
        assert.equal(typeof entry.file, 'string');
        const file = entry.file.replace(/\\/gu, '/');
        assert.ok(
            !path.isAbsolute(file) &&
                !file.split('/').includes('..') &&
                !sources.has(file),
        );
        assert.match(entry.sha512, /^[0-9a-f]{128}$/u);
        assert.ok(Number.isSafeInteger(entry.bytes) && entry.bytes > 0);
        sources.set(file, { ...entry, file });
    }
    const compiledInputs = new Map<string, NativeSourceEntry>();
    if (result.value.compiledInputs !== undefined) {
        assert.ok(Array.isArray(result.value.compiledInputs));
        for (const entry of result.value
            .compiledInputs as NativeSourceEntry[]) {
            assert.equal(typeof entry.file, 'string');
            const file = entry.file.replace(/\\/gu, '/');
            assert.ok(
                !compiledInputs.has(file),
                'A native compiled input is duplicated.',
            );
            const snapshot = sources.get(file);
            assert.ok(
                snapshot,
                'A native compiled input is absent from its source manifest.',
            );
            assert.deepEqual(
                { file, bytes: entry.bytes, sha512: entry.sha512 },
                snapshot,
                'A native compiled input differs from its source manifest.',
            );
            compiledInputs.set(file, snapshot);
        }
    }
    return {
        directory,
        artifactDirectory,
        report: result.value,
        sources,
        compiledInputs,
        compiler: manifest.value.compiler,
        nativeExecutableSha512: String(result.value.runtimeIdentity),
        diagnosticDigests: {
            summary: summary.sha512,
            result: result.sha512,
            manifest: manifest.sha512,
        },
    };
};

// The scalar-only entropy adapter has no native binary compilation claim.
// Pin its exact bytes separately; every other Rust input, including
// manifests and native wrappers, must belong to the native compiled closure.
export const assertScalarNativeInputs = async (
    source: Pick<
        Awaited<ReturnType<typeof readNativeSourceMetadata>>,
        'compiler' | 'sources' | 'compiledInputs'
    >,
    files: readonly string[],
    compiler: string,
    root: string,
) => {
    assert.equal(
        compiler,
        source.compiler,
        'The native source used another compiler.',
    );
    const adapters = new Set([
        'crates/protocol-research/setup-witness/src/browser_random.rs',
    ]);
    const rustInputs = [
        ...new Set(files.map((file) => file.replace(/\\/gu, '/'))),
    ]
        .filter((file) => file.startsWith('crates/'))
        .sort();
    assert.ok(rustInputs.length > 0, 'The scalar Rust input closure is empty.');
    const targetAdapters: string[] = [];
    const unchangedNativeInputs: string[] = [];
    for (const file of rustInputs) {
        const adapter = adapters.has(file);
        const previous = adapter
            ? source.sources.get(file)
            : source.compiledInputs.get(file);
        assert.ok(
            previous,
            adapter
                ? 'The native source did not snapshot a scalar target adapter: ' +
                      file
                : 'The native source did not compile a scalar shared input: ' +
                      file,
        );
        const bytes = await readFile(path.join(root, file));
        assert.equal(
            bytes.length,
            previous.bytes,
            'A native input changed: ' + file,
        );
        assert.equal(
            createHash('sha512').update(bytes).digest('hex'),
            previous.sha512,
            'A native input changed: ' + file,
        );
        (adapter ? targetAdapters : unchangedNativeInputs).push(file);
    }
    return { unchangedNativeInputs, targetAdapters };
};

// A native archive is a deterministic comparison vector here. Its old
// shared sources do not authorize a newly compiled consumer.
export const compareNativeReferenceArtifacts = async (
    artifacts: readonly NativeReferenceArtifact[],
    output: string,
) => {
    const comparisons = [];
    for (const proof of artifacts) {
        const currentFile = path.join(output, proof.name);
        assert.equal((await stat(currentFile)).size, proof.bytes);
        const historical = await open(proof.file, 'r');
        let current: FileHandle | undefined;
        try {
            current = await open(currentFile, 'r');
            const left = Buffer.alloc(1 << 20);
            const right = Buffer.alloc(left.length);
            for (let offset = 0; offset < proof.bytes;) {
                const length = Math.min(left.length, proof.bytes - offset);
                for (const [file, buffer] of [
                    [historical, left],
                    [current, right],
                ] as const) {
                    let read = 0;
                    while (read < length) {
                        const { bytesRead } = await file.read(
                            buffer,
                            read,
                            length - read,
                            offset + read,
                        );
                        assert.ok(
                            bytesRead > 0,
                            'A deterministic reference proof was truncated.',
                        );
                        read += bytesRead;
                    }
                }
                assert.ok(
                    left.subarray(0, length).equals(right.subarray(0, length)),
                    'A freshly generated proof differs from its deterministic reference: ' +
                        proof.name,
                );
                offset += length;
            }
        } finally {
            try {
                await current?.close();
            } finally {
                await historical.close();
            }
        }
        const sha512 = await fileDigest(currentFile);
        assert.equal(sha512, proof.sha512);
        assert.equal(
            await fileDigest(proof.file),
            proof.sha512,
            'A historical reference changed during comparison.',
        );
        comparisons.push({ name: proof.name, bytes: proof.bytes, sha512 });
    }
    return comparisons;
};

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
        await readNativeSourceMetadata(source, root);
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
