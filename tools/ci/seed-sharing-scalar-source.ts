import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import { compileRecoverableSeedSharingProofResources } from '#tests/recoverable-setup-resource-model.js';
import { runArtifactDirectoryPath } from '#tools/ci/local-run-log.js';

export const seedSharingProofNames = [
    'proof-honest.bin',
    'proof-false-seed.bin',
    'proof-false-share.bin',
] as const;

export const fileDigest = async (file: string): Promise<string> => {
    const digest = createHash('sha512');
    for await (const chunk of createReadStream(file))
        digest.update(chunk as Buffer);
    return digest.digest('hex');
};

export type SeedSharingSourceEntry = Readonly<{
    file: string;
    sha512: string;
    bytes: number;
}>;

// Only a completed native fixture run supplies these inputs. Its old record
// names proof lengths but no proof hashes: first-seen digests below belong to
// the new scalar run and never modify or strengthen that historical record.
export const readSeedSharingNativeSource = async (
    source: string,
    root: string,
) => {
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
    assert.equal(result.value.case, 'native-seed-sharing');
    assert.equal(result.value.participantCount, 4);
    assert.equal(result.value.optionCount, 2);
    assert.equal(result.value.simulatedHelpers, 0);
    const native = result.value.result as Record<string, unknown>;
    const resources = compileRecoverableSeedSharingProofResources(
        4,
        2,
        256n,
        4n,
    );
    assert.equal(native.kind, 'seed-sharing-proof-fragment');
    assert.equal(native.positive, 1);
    assert.equal(native.falseWitnesses, 1);
    assert.equal(native.falseStatements, 1);
    assert.equal(native.hostileCases, 14);
    assert.equal(native.participants, 4);
    assert.equal(native.degree, 256);
    assert.equal(native.seedBits, 4);
    assert.equal(native.proofDomain, Number(resources.verificationDomainSize));
    assert.equal(native.wordColumns, resources.relation.wordColumns);
    assert.equal(native.booleanColumns, resources.relation.booleanColumns);
    assert.equal(native.affineRows, Number(resources.relation.affineRows));
    assert.ok(
        Array.isArray(native.proofBytes) &&
            native.proofBytes.length === seedSharingProofNames.length,
    );
    const artifacts = runArtifactDirectoryPath(directory);
    const archive = path.join(artifacts, 'seed-sharing');
    assert.equal(path.resolve(String(result.value.output)), archive);
    assert.match(String(result.value.runtimeIdentity), /^[0-9a-f]{128}$/u);
    assert.equal(
        (await readFile(path.join(artifacts, 'runtime.bin'))).toString('hex'),
        result.value.runtimeIdentity,
    );
    assert.deepEqual(
        (await readdir(archive)).sort(),
        [...seedSharingProofNames].sort(),
    );
    const proofs = [];
    for (const [index, name] of seedSharingProofNames.entries()) {
        const file = path.join(archive, name);
        const details = await stat(file);
        assert.ok(
            details.isFile() &&
                details.size > Number(resources.layout.headerBytes) &&
                BigInt(details.size) <= resources.layout.maximumMultiproofBytes,
            'The source proof length is outside the fixture bound.',
        );
        assert.equal(details.size, native.proofBytes[index]);
        proofs.push({
            name,
            file,
            bytes: details.size,
            sha512: await fileDigest(file),
        });
    }
    assert.ok(
        typeof manifest.value.compiler === 'string' &&
            Array.isArray(manifest.value.sources),
    );
    const sources = new Map<string, SeedSharingSourceEntry>();
    for (const entry of manifest.value.sources as SeedSharingSourceEntry[]) {
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
    for (const name of [
        'fixture',
        'layout',
        'statement',
        'operator',
        'witness',
    ])
        assert.ok(
            sources.has(
                `crates/protocol-research/seed-sharing-proof/src/${name}.rs`,
            ),
            'The native fixture source is missing.',
        );
    return {
        directory,
        archive,
        proofs,
        sources,
        nativeExecutableSha512: String(result.value.runtimeIdentity),
        diagnosticDigests: {
            summary: summary.sha512,
            result: result.sha512,
            manifest: manifest.sha512,
        },
    };
};
