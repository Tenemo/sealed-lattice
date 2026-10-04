import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, readFile, readdir, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import {
    compileBoundedOpeningShareProofResources,
    compileRecoverableSeedSharingProofResources,
} from '#tests/recoverable-setup-resource-model.js';
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

type SeedSharingSourceEntry = Readonly<{
    file: string;
    sha512: string;
    bytes: number;
}>;

export type NativeReferenceArtifact = Readonly<{
    name: string;
    file: string;
    bytes: number;
    sha512: string;
}>;

// Diagnostics describe only this recorded native run. A consuming build
// separately checks its actual compiled inputs against this recorded closure.
const readNativeSourceMetadata = async (
    source: string,
    root: string,
    expectedCase: 'native-seed-sharing' | 'native-opening-share',
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
    assert.equal(result.value.case, expectedCase);
    assert.equal(result.value.participantCount, 4);
    assert.equal(result.value.optionCount, 2);
    assert.equal(result.value.simulatedHelpers, 0);
    const artifactDirectory = runArtifactDirectoryPath(directory);
    assert.match(String(result.value.runtimeIdentity), /^[0-9a-f]{128}$/u);
    assert.equal(
        (await readFile(path.join(artifactDirectory, 'runtime.bin'))).toString(
            'hex',
        ),
        result.value.runtimeIdentity,
    );
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
    const compiledInputs = new Map<string, SeedSharingSourceEntry>();
    if (result.value.compiledInputs !== undefined) {
        assert.ok(Array.isArray(result.value.compiledInputs));
        for (const entry of result.value
            .compiledInputs as SeedSharingSourceEntry[]) {
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

const artifactIdentity = ({
    name,
    bytes,
    sha512,
}: NativeReferenceArtifact) => ({
    name,
    bytes,
    sha512,
});

const readNativeArtifact = async (
    archive: string,
    name: string,
    declared: unknown,
    minimumExclusive: bigint,
    maximum: bigint,
): Promise<NativeReferenceArtifact> => {
    const file = path.join(archive, name);
    const details = await stat(file);
    assert.ok(
        details.isFile() &&
            BigInt(details.size) > minimumExclusive &&
            BigInt(details.size) <= maximum,
        'The source artifact length is outside the fixture bound.',
    );
    assert.equal(details.size, declared);
    return { name, file, bytes: details.size, sha512: await fileDigest(file) };
};

// Historical seed runs may lack proof hashes or compiled-input records;
// they remain comparison vectors, never authority for unrecorded inputs.
export const readSeedSharingNativeSource = async (
    source: string,
    root: string,
) => {
    const { report, artifactDirectory, ...base } =
        await readNativeSourceMetadata(source, root, 'native-seed-sharing');
    const native = report.result as Record<string, unknown>;
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
    const archive = path.join(artifactDirectory, 'seed-sharing');
    assert.equal(path.resolve(String(report.output)), archive);
    assert.deepEqual(
        (await readdir(archive)).sort(),
        [...seedSharingProofNames].sort(),
    );
    const proofs = [];
    for (const [index, name] of seedSharingProofNames.entries())
        proofs.push(
            await readNativeArtifact(
                archive,
                name,
                native.proofBytes[index],
                resources.layout.headerBytes,
                resources.layout.maximumMultiproofBytes,
            ),
        );
    if (report.proofArtifacts !== undefined)
        assert.deepEqual(
            report.proofArtifacts,
            proofs.map(artifactIdentity),
            'The native proof archive differs from its recorded identities.',
        );
    for (const name of [
        'fixture',
        'layout',
        'statement',
        'operator',
        'witness',
    ])
        assert.ok(
            base.sources.has(
                `crates/protocol-research/seed-sharing-proof/src/${name}.rs`,
            ),
            'The native fixture source is missing.',
        );
    return { ...base, archive, proofs };
};

export const openingShareProofNames = [
    'proof-second-source.bin',
    'proof-opening-honest.bin',
    'proof-opening-shifted.bin',
] as const;
export const openingShareStatementNames = [
    'statement-second-source.bin',
    'statement-opening-honest.bin',
    'statement-opening-shifted.bin',
] as const;

// This reader pins evidence bytes and their source closure. The scalar
// owning verifiers still consume both outer proofs before any opening proof.
export const readOpeningShareNativeSource = async (
    source: string,
    root: string,
) => {
    const { report, artifactDirectory, ...base } =
        await readNativeSourceMetadata(source, root, 'native-opening-share');
    const native = report.result as Record<string, unknown>;
    const resources = compileBoundedOpeningShareProofResources();
    const { seed, opening } = resources;
    assert.equal(native.kind, 'bounded-opening-share-proof');
    assert.equal(native.positive, 1);
    assert.equal(native.falseStatements, 1);
    assert.equal(native.hostileCases, 10);
    assert.equal(native.participants, 4);
    assert.equal(native.degree, Number(opening.physicalDegree));
    assert.equal(native.selected, opening.parameters.selectedCount);
    assert.equal(native.recipient, 2);
    assert.equal(native.predecessors, opening.parameters.selectedCount);
    assert.equal(native.proofDomain, Number(seed.verificationDomainSize));
    assert.equal(native.wordColumns, opening.wordColumns);
    assert.equal(native.booleanColumns, opening.booleanColumns);
    assert.equal(native.lookupEntries, opening.lookupEntries);
    assert.equal(native.affineRows, Number(opening.affineRows));
    assert.equal(
        native.statementBytes,
        Number(resources.openingStatementBytes),
    );
    assert.ok(Array.isArray(native.sourceIdentities));
    const sourceIdentities = native.sourceIdentities as unknown[];
    assert.equal(sourceIdentities.length, opening.parameters.selectedCount);
    assert.equal(
        new Set(sourceIdentities).size,
        opening.parameters.selectedCount,
    );
    assert.ok(
        sourceIdentities.every(
            (identity): identity is string =>
                typeof identity === 'string' &&
                /^[0-9a-f]{128}$/u.test(identity),
        ),
    );
    const archive = path.join(artifactDirectory, 'opening-share');
    assert.equal(path.resolve(String(report.output)), archive);
    assert.deepEqual(
        (await readdir(archive)).sort(),
        [...openingShareProofNames, ...openingShareStatementNames].sort(),
    );
    const proofArtifacts = [];
    for (const [name, declared, layout] of [
        [openingShareProofNames[0], native.secondSourceProofBytes, seed.layout],
        [openingShareProofNames[1], native.proofBytes, opening.layout],
        [openingShareProofNames[2], native.shiftedProofBytes, opening.layout],
    ] as const)
        proofArtifacts.push(
            await readNativeArtifact(
                archive,
                name,
                declared,
                layout.headerBytes,
                layout.maximumMultiproofBytes,
            ),
        );
    const statementArtifacts = [];
    for (const [name, length] of [
        [openingShareStatementNames[0], resources.seedStatementBytes],
        [openingShareStatementNames[1], resources.openingStatementBytes],
        [openingShareStatementNames[2], resources.openingStatementBytes],
    ] as const)
        statementArtifacts.push(
            await readNativeArtifact(
                archive,
                name,
                Number(length),
                length - 1n,
                length,
            ),
        );
    assert.deepEqual(
        report.proofArtifacts,
        proofArtifacts.map(artifactIdentity),
        'The native opening proofs differ from their recorded identities.',
    );
    assert.deepEqual(
        report.statementArtifacts,
        statementArtifacts.map(artifactIdentity),
        'The native opening statements differ from their recorded identities.',
    );

    assert.ok(
        typeof report.predecessor === 'object' && report.predecessor !== null,
    );
    const captured = report.predecessor as Record<string, unknown>;
    assert.equal(typeof captured.directory, 'string');
    const seedSource = await readSeedSharingNativeSource(
        captured.directory as string,
        root,
    );
    assert.equal(seedSource.directory, captured.directory);
    assert.deepEqual(
        seedSource.diagnosticDigests,
        captured.diagnosticDigests,
        'The captured seed predecessor diagnostics changed.',
    );
    assert.deepEqual(
        seedSource.proofs,
        captured.proofs,
        'The captured seed predecessor proofs changed.',
    );
    assert.equal(
        base.compiler,
        seedSource.compiler,
        'The predecessor used another compiler.',
    );
    assert.ok(
        base.compiledInputs.size > 0,
        'The opening compiled input closure is empty.',
    );
    const sharedInputs = [...base.compiledInputs.keys()]
        .filter(
            (file) =>
                !file.startsWith(
                    'crates/protocol-research/opening-share-proof/',
                ),
        )
        .sort();
    assert.ok(
        sharedInputs.length > 0 &&
            sharedInputs.length < base.compiledInputs.size,
        'The opening compiled input closure lacks shared or owning inputs.',
    );
    assert.deepEqual(
        captured.sharedInputs,
        sharedInputs,
        'The captured shared compiled input closure differs.',
    );
    for (const file of sharedInputs)
        assert.deepEqual(
            base.compiledInputs.get(file),
            seedSource.compiledInputs.get(file),
            'The seed predecessor did not compile the same shared input: ' +
                file,
        );
    return {
        ...base,
        archive,
        seedSource,
        sourceIdentities,
        artifacts: [...proofArtifacts, ...statementArtifacts],
        proofs: proofArtifacts.slice(1),
        predecessors: [seedSource.proofs[0], proofArtifacts[0]],
    };
};

type SeedSharingNativeSource = Awaited<
    ReturnType<typeof readSeedSharingNativeSource>
>;

// Scalar-only ABI adapters have no native binary compilation claim. Pin
// their exact bytes separately; every other Rust input, including manifests
// and native wrappers, must belong to the native compiled closure.
export const assertScalarNativeInputs = async (
    source: Pick<
        SeedSharingNativeSource,
        'compiler' | 'sources' | 'compiledInputs'
    >,
    files: readonly string[],
    compiler: string,
    root: string,
    relation: 'seed-sharing' | 'opening-share',
) => {
    assert.equal(
        compiler,
        source.compiler,
        'The native source used another compiler.',
    );
    const prefix = 'crates/protocol-research/' + relation + '-proof/';
    const adapters = new Set([
        prefix + 'src/browser.rs',
        ...(relation === 'seed-sharing'
            ? [prefix + 'src/prover-browser.rs']
            : []),
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

// A historical archive is a deterministic comparison vector here. Its old
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

export const compareSeedSharingReferenceProofs = (
    reference: SeedSharingNativeSource,
    output: string,
) => compareNativeReferenceArtifacts(reference.proofs, output);

export const assertOpeningShareSourceStable = async (
    source: Awaited<ReturnType<typeof readOpeningShareNativeSource>>,
    root: string,
) => {
    const current = await readOpeningShareNativeSource(source.directory, root);
    assert.deepEqual(
        current.diagnosticDigests,
        source.diagnosticDigests,
        'The native opening diagnostics changed during the run.',
    );
    assert.deepEqual(
        current.artifacts,
        source.artifacts,
        'The native opening artifacts changed during the run.',
    );
    assert.deepEqual(
        current.predecessors,
        source.predecessors,
        'The native opening predecessors changed during the run.',
    );
};

export const assertSeedSharingSourceStable = async (
    source: SeedSharingNativeSource,
    root: string,
) => {
    const current = await readSeedSharingNativeSource(source.directory, root);
    assert.deepEqual(
        current.diagnosticDigests,
        source.diagnosticDigests,
        'The native source diagnostics changed during the run.',
    );
    assert.deepEqual(
        current.proofs,
        source.proofs,
        'The native source proofs changed during the run.',
    );
};

// The caller supplies the compiler's shared input closure. The new consuming
// relation is snapshotted separately; no changed shared input is exempted.
export const assertSeedSharingSharedInputs = async (
    source: SeedSharingNativeSource,
    files: readonly string[],
    compiler: string,
    root: string,
) => {
    assert.equal(
        compiler,
        source.compiler,
        'The native source used another compiler.',
    );
    assert.ok(files.length > 0, 'The shared compiled input closure is empty.');
    for (const file of files) {
        const previous = source.compiledInputs.get(file);
        assert.ok(
            previous,
            'The native source did not compile a shared input: ' + file,
        );
        const bytes = await readFile(path.join(root, file));
        assert.equal(
            bytes.length,
            previous.bytes,
            'A shared native source changed: ' + file,
        );
        assert.equal(
            createHash('sha512').update(bytes).digest('hex'),
            previous.sha512,
            'A shared native source changed: ' + file,
        );
    }
};
