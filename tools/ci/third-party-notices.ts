import { spawnSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { repositoryRoot } from './command-line.js';
import { rustToolchain } from './rust-toolchain.js';

type CargoPackage = Readonly<{
    id: string;
    license: string | null;
    license_file: string | null;
    manifest_path: string;
    name: string;
    targets: readonly Readonly<{ kind: readonly string[] }>[];
    version: string;
}>;

export type CargoMetadata = Readonly<{
    packages: readonly CargoPackage[];
    resolve: Readonly<{
        nodes: readonly Readonly<{
            id: string;
            deps: readonly Readonly<{
                pkg: string;
                dep_kinds: readonly Readonly<{ kind: string | null }>[];
            }>[];
        }>[];
    }>;
    workspace_members: readonly string[];
}>;

const licenseFileName = /^(?:copying|copyright|licen[cs]e|notice)/iu;

// The protocol workspace's resolved crates on the participant module's
// target.
export const readParticipantCrateMetadata = (): CargoMetadata => {
    const result = spawnSync(
        'cargo',
        [
            rustToolchain,
            'metadata',
            '--locked',
            '--offline',
            '--format-version',
            '1',
            '--filter-platform',
            'wasm32-unknown-unknown',
        ],
        {
            cwd: path.join(repositoryRoot, 'crates', 'protocol-research'),
            encoding: 'utf8',
            maxBuffer: 64 << 20,
            windowsHide: true,
        },
    );
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0)
        throw new Error('The protocol workspace metadata could not be read.');
    return JSON.parse(result.stdout) as CargoMetadata;
};

// The license files of the third-party crates compiled into the participant
// module, each text once, and the terms of the Rust standard library. The
// crates are the module's normal dependencies, without the workspace's own
// crates and the procedural macros, which run only in the compiler.
export const thirdPartyNotices = async (
    metadata: CargoMetadata,
): Promise<string> => {
    const packages = new Map(
        metadata.packages.map((entry) => [entry.id, entry]),
    );
    const packageOf = (id: string) => {
        const entry = packages.get(id);
        if (entry === undefined)
            throw new Error(`The crate metadata omits ${id}.`);
        return entry;
    };
    const dependencies = new Map(
        metadata.resolve.nodes.map((node) => [node.id, node.deps]),
    );
    const module = metadata.packages.find(
        (entry) =>
            entry.name === 'participant-module' &&
            metadata.workspace_members.includes(entry.id),
    );
    if (module === undefined)
        throw new Error('The protocol workspace has no participant module.');
    const reached = new Set([module.id]);
    // A set's iteration visits the entries added during it.
    for (const id of reached)
        for (const dependency of dependencies.get(id) ?? [])
            if (
                dependency.dep_kinds.some(({ kind }) => kind === null) &&
                !packageOf(dependency.pkg).targets.some(({ kind }) =>
                    kind.includes('proc-macro'),
                )
            )
                reached.add(dependency.pkg);
    const crates = [...reached]
        .filter((id) => !metadata.workspace_members.includes(id))
        .map(packageOf)
        .sort(
            (left, right) =>
                left.name.localeCompare(right.name, 'en') ||
                left.version.localeCompare(right.version, 'en'),
        );

    const listing: string[] = [];
    const texts = new Map<string, string[]>();
    for (const crate of crates) {
        const name = `${crate.name} ${crate.version}`;
        const directory = path.dirname(crate.manifest_path);
        const files = new Set(
            (await readdir(directory))
                .filter((file) => licenseFileName.test(file))
                .map((file) => path.join(directory, file)),
        );
        if (crate.license_file !== null)
            files.add(path.resolve(directory, crate.license_file));
        if (files.size === 0)
            throw new Error(`The crate ${name} ships no license file.`);
        listing.push(
            crate.license === null ? name : `${name} (${crate.license})`,
        );
        for (const file of [...files].sort()) {
            const text = (await readFile(file, 'utf8'))
                .replace(/\r\n?/gu, '\n')
                .trim();
            texts.set(text, [
                ...(texts.get(text) ?? []),
                `${name} ${path.basename(file)}`,
            ]);
        }
    }

    const rustVersion = rustToolchain.slice(1);
    return [
        'Third-party notices',
        '',
        `dist/participant.wasm compiles in the Rust standard library ${rustVersion} (MIT OR Apache-2.0, with the library notices at https://github.com/rust-lang/rust/blob/${rustVersion}/COPYRIGHT) and these crates, whose license files follow, each text once:`,
        '',
        ...listing,
        ...[...texts].flatMap(([text, sources]) => [
            '',
            '='.repeat(80),
            ...sources,
            '='.repeat(80),
            '',
            text,
        ]),
        '',
    ].join('\n');
};
