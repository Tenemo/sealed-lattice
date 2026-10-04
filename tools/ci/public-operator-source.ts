import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { open, readdir } from 'node:fs/promises';
import path from 'node:path';

import { compilePublicOperatorScreenResources } from '#tests/recoverable-setup-resource-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { proofCompilerCaps } from '#tests/wide-challenge-compiler-model.js';
import { readNativeSourceMetadata } from '#tools/ci/seed-sharing-scalar-source.js';
import type { NativeReferenceArtifact } from '#tools/ci/seed-sharing-scalar-source.js';

type OperatorKind = 'seed' | 'opening';

// This decodes the bounded report and checks its independently modelled
// inventory. The native screen owns the mathematical comparisons; neither
// parsing nor a producer-supplied digest grants a protocol capability.
export const parsePublicOperatorReport = (
    bytes: Uint8Array,
    kind: OperatorKind,
) => {
    const resources = compilePublicOperatorScreenResources(kind);
    const field = compileSmallLimbProofFieldCensus();
    assert.equal(
        BigInt(bytes.byteLength),
        resources.reportBytes,
        'The public operator report has the wrong length.',
    );
    const input = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 0;
    const take = (length: number) => {
        const result = input.subarray(offset, offset + length);
        assert.equal(
            result.length,
            length,
            'The operator report is truncated.',
        );
        offset += length;
        return result;
    };
    const integer = () => take(4).readUInt32LE();
    const element = () =>
        Array.from({ length: Number(field.extensionDegree) }, () => {
            const encoded = take(Number(field.packedFieldElementByteLength));
            let value = 0n;
            for (let index = encoded.length - 1; index >= 0; index--)
                value = (value << 8n) | BigInt(encoded[index]);
            assert.ok(
                value < field.modulus,
                'An operator report field coordinate is not canonical.',
            );
            return value.toString();
        });
    assert.ok(take(4).equals(Buffer.from('OPR1', 'ascii')));
    const shape = {
        caseId: integer(),
        degree: integer(),
        participants: integer(),
        threshold: integer(),
        selectedCount: integer(),
        seedBits: integer(),
        columns: integer(),
        queryCount: integer(),
    };
    assert.deepEqual(
        shape,
        {
            caseId: resources.caseId,
            degree: Number(resources.degree),
            participants: resources.participants,
            threshold: resources.threshold,
            selectedCount: resources.selectedCount,
            seedBits: Number(resources.seedBits),
            columns: resources.columns,
            queryCount: resources.queryCount,
        },
        'The operator report does not match its modelled case and shape.',
    );
    const alpha = element();
    assert.deepEqual(alpha, resources.alpha.map(String));
    const target = element();
    const lookupWeight = element();
    const digestBytes = Number(proofCompilerCaps.tagBits / 8n);
    const operatorDigest = take(digestBytes).toString('hex');
    const queryDigest = take(digestBytes).toString('hex');
    assert.equal(integer(), resources.physicalSamples.length);
    assert.equal(integer(), resources.querySamples.length);
    const samples = (
        expected: readonly Readonly<{ column: number; index: number }>[],
    ) =>
        expected.map((location) => {
            const actual = { column: integer(), index: integer() };
            assert.deepEqual(
                actual,
                location,
                'The operator report sample inventory or order differs.',
            );
            return { ...actual, value: element() };
        });
    const physicalSamples = samples(resources.physicalSamples);
    const querySamples = samples(resources.querySamples);
    assert.equal(
        offset,
        input.length,
        'The operator report has trailing bytes.',
    );
    return {
        kind,
        ...shape,
        alpha,
        target,
        lookupWeight,
        operatorDigest,
        queryDigest,
        physicalSamples,
        querySamples,
    };
};

export const readPublicOperatorNativeSource = async (
    source: string,
    root: string,
) => {
    const { report, artifactDirectory, ...base } =
        await readNativeSourceMetadata(source, root, 'native-public-operator');
    const archive = path.join(artifactDirectory, 'public-operator');
    assert.equal(path.resolve(String(report.output)), archive);
    const names = ['operator-0.bin', 'operator-1.bin'];
    assert.deepEqual((await readdir(archive)).sort(), names);
    assert.ok(Array.isArray(report.native));
    assert.equal(report.native.length, names.length);
    const artifacts: NativeReferenceArtifact[] = [];
    const reports: ReturnType<typeof parsePublicOperatorReport>[] = [];
    for (const [index, kind] of (['seed', 'opening'] as const).entries()) {
        const resources = compilePublicOperatorScreenResources(kind);
        const native = report.native[index] as Record<string, unknown>;
        assert.ok(native !== null && typeof native === 'object');
        const result = native.result as Record<string, unknown>;
        assert.ok(result !== null && typeof result === 'object');
        assert.equal(result.kind, 'public-operator-screen');
        assert.equal(result.case, kind);
        assert.equal(result.reportBytes, Number(resources.reportBytes));
        const name = names[index];
        const file = path.join(archive, name);
        const handle = await open(file, 'r');
        let bytes: Buffer;
        try {
            const details = await handle.stat();
            assert.ok(details.isFile());
            assert.equal(
                BigInt(details.size),
                resources.reportBytes,
                'The operator source artifact length differs from its model.',
            );
            // Bound the allocation and reads even if a source file changes
            // after stat. The extra byte detects growth without reading it all.
            const buffer = Buffer.alloc(Number(resources.reportBytes) + 1);
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
            assert.equal(read, Number(resources.reportBytes));
            bytes = buffer.subarray(0, read);
        } finally {
            await handle.close();
        }
        reports.push(parsePublicOperatorReport(bytes, kind));
        artifacts.push({
            name,
            file,
            bytes: bytes.length,
            sha512: createHash('sha512').update(bytes).digest('hex'),
        });
    }
    assert.deepEqual(
        report.artifacts,
        artifacts.map(({ name, bytes, sha512 }) => ({ name, bytes, sha512 })),
        'The native operator archive differs from its recorded identities.',
    );
    for (const name of ['lib', 'recipe', 'reference'])
        assert.ok(
            base.compiledInputs.has(
                `crates/protocol-research/public-operator-screen/src/${name}.rs`,
            ),
            'The native operator compiled input closure lacks an owning input.',
        );
    return { ...base, archive, artifacts, reports };
};

export const assertPublicOperatorSourceStable = async (
    source: Pick<
        Awaited<ReturnType<typeof readPublicOperatorNativeSource>>,
        'directory' | 'diagnosticDigests' | 'artifacts'
    >,
    root: string,
) => {
    const current = await readPublicOperatorNativeSource(
        source.directory,
        root,
    );
    assert.deepEqual(
        current.diagnosticDigests,
        source.diagnosticDigests,
        'The native operator diagnostics changed during the run.',
    );
    assert.deepEqual(
        current.artifacts,
        source.artifacts,
        'The native operator artifacts changed during the run.',
    );
};
