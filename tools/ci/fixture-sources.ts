import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    compiledRustSources,
    requireCheckoutBytes,
} from '#tools/ci/compiled-inputs.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';

type SourceEntry = Readonly<{ file: string; bytes: number; sha512: string }>;

export const fileDigest = async (file: string): Promise<string> => {
    const digest = createHash('sha512');
    for await (const chunk of createReadStream(file))
        digest.update(chunk as Buffer);
    return digest.digest('hex');
};

const snapshotFixtureFiles = async (
    log: ActiveLocalRunLog,
    root: string,
    files: readonly string[],
) => {
    const sources: SourceEntry[] = [];
    for (const file of [...new Set(files)].sort()) {
        assert.ok(
            file &&
                !path.isAbsolute(file) &&
                !file.split(/[\\/]/u).includes('..'),
        );
        const bytes = await readFile(path.join(root, file));
        const destination = path.join(log.runDirectoryPath, 'sources', file);
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, bytes, { flag: 'wx' });
        sources.push({
            file: file.replace(/\\/gu, '/'),
            bytes: bytes.length,
            sha512: createHash('sha512').update(bytes).digest('hex'),
        });
    }
    return sources;
};

// The pre-build archive also contains uncompiled files; only the compiler's
// recorded closure below can admit shared inputs to a later consuming run.
export const snapshotResearchSources = async (
    log: ActiveLocalRunLog,
    root: string,
    extras: readonly string[],
) => {
    const files = [...extras];
    const visit = async (directory: string): Promise<void> => {
        for (const entry of await readdir(directory, { withFileTypes: true })) {
            if (entry.name === 'target' || entry.name === '.git') continue;
            const file = path.join(directory, entry.name);
            if (entry.isDirectory()) await visit(file);
            else {
                assert.ok(
                    entry.isFile(),
                    'Research sources must be ordinary files.',
                );
                files.push(path.relative(root, file).replace(/\\/gu, '/'));
            }
        }
    };
    await visit(path.join(root, 'crates/protocol-research'));
    return snapshotFixtureFiles(log, root, files);
};

export const compiledFixtureFiles = async (
    dependencyFile: string,
    available: readonly SourceEntry[],
) => {
    const compiled = await compiledRustSources(dependencyFile);
    const present = new Set(
        available.map((source) => source.file.replace(/\\/gu, '/')),
    );
    const files = new Set([...compiled, 'crates/protocol-research/Cargo.lock']);
    for (const file of compiled) {
        let directory = path.posix.dirname(file);
        while (directory.startsWith('crates/protocol-research')) {
            const manifest = path.posix.join(directory, 'Cargo.toml');
            if (present.has(manifest)) files.add(manifest);
            directory = path.posix.dirname(directory);
        }
    }
    requireCheckoutBytes([...files]);
    return [...files].sort();
};

export const checkFixtureSources = async (
    root: string,
    sources: readonly SourceEntry[],
    files: readonly string[] = sources.map((source) => source.file),
) => {
    const entries = new Map(
        sources.map((source) => [source.file.replace(/\\/gu, '/'), source]),
    );
    const checked = [];
    for (const file of files) {
        const source = entries.get(file);
        assert.ok(
            source,
            'A compiled input was absent from the pre-build source snapshot: ' +
                file,
        );
        assert.equal(
            await fileDigest(path.join(root, file)),
            source.sha512,
            'A fixture source changed: ' + file,
        );
        checked.push(source);
    }
    return checked;
};
