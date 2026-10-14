import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    thirdPartyNotices,
    type CargoMetadata,
} from '#tools/ci/third-party-notices';

type Crate = Readonly<{
    name: string;
    member?: boolean;
    procedural?: boolean;
    files?: Readonly<Record<string, string>>;
    dependencies?: readonly (readonly [string, string | null])[];
}>;

// Writes each crate's license files and returns the workspace metadata that
// names them.
const writeWorkspace = async (
    root: string,
    crates: readonly Crate[],
): Promise<CargoMetadata> => {
    const id = (name: string) => `registry#${name}@1.0.0`;
    for (const crate of crates) {
        const directory = path.join(root, crate.name);
        await mkdir(directory);
        for (const [file, text] of Object.entries(crate.files ?? {}))
            await writeFile(path.join(directory, file), text, 'utf8');
    }
    return {
        packages: crates.map((crate) => ({
            id: id(crate.name),
            license: crate.member === true ? null : 'MIT',
            license_file: null,
            manifest_path: path.join(root, crate.name, 'Cargo.toml'),
            name: crate.name,
            targets: [
                { kind: [crate.procedural === true ? 'proc-macro' : 'lib'] },
            ],
            version: '1.0.0',
        })),
        resolve: {
            nodes: crates.map((crate) => ({
                id: id(crate.name),
                deps: (crate.dependencies ?? []).map(([name, kind]) => ({
                    pkg: id(name),
                    dep_kinds: [{ kind }],
                })),
            })),
        },
        workspace_members: crates
            .filter((crate) => crate.member === true)
            .map((crate) => id(crate.name)),
    };
};

describe('third-party notices', () => {
    it('lists the crates the participant module compiles in, each license text once', async () => {
        const root = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-notices-'),
        );
        try {
            const notices = await thirdPartyNotices(
                await writeWorkspace(root, [
                    {
                        name: 'participant-module',
                        member: true,
                        dependencies: [
                            ['parallel-work', null],
                            ['alpha', null],
                            ['derive', null],
                            ['tester', 'dev'],
                            ['generator', 'build'],
                        ],
                    },
                    {
                        name: 'parallel-work',
                        member: true,
                        dependencies: [['beta', null]],
                    },
                    {
                        name: 'alpha',
                        files: { 'LICENSE-MIT': 'Shared text\r\n' },
                    },
                    {
                        name: 'beta',
                        files: {
                            LICENSE: 'Shared text\n',
                            NOTICE: 'Beta notice\n',
                            'README.md': 'Not a license\n',
                        },
                    },
                    {
                        name: 'derive',
                        procedural: true,
                        dependencies: [['parser', null]],
                    },
                    { name: 'parser', files: { LICENSE: 'Parser text\n' } },
                    { name: 'tester', files: { LICENSE: 'Tester text\n' } },
                    {
                        name: 'generator',
                        files: { LICENSE: 'Generator text\n' },
                    },
                ]),
            );
            const separator = '='.repeat(80);
            expect(notices).toContain(
                [
                    'alpha 1.0.0 (MIT)',
                    'beta 1.0.0 (MIT)',
                    '',
                    separator,
                    'alpha 1.0.0 LICENSE-MIT',
                    'beta 1.0.0 LICENSE',
                    separator,
                    '',
                    'Shared text',
                    '',
                    separator,
                    'beta 1.0.0 NOTICE',
                    separator,
                    '',
                    'Beta notice',
                    '',
                ].join('\n'),
            );
            for (const absent of [
                'participant-module',
                'parallel-work',
                'derive',
                'parser',
                'tester',
                'generator',
                'Not a license',
            ])
                expect(notices).not.toContain(absent);
        } finally {
            await rm(root, { force: true, recursive: true });
        }
    });

    it('refuses a compiled-in crate without a license file', async () => {
        const root = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-notices-'),
        );
        try {
            const metadata = await writeWorkspace(root, [
                {
                    name: 'participant-module',
                    member: true,
                    dependencies: [['unlicensed', null]],
                },
                { name: 'unlicensed', files: { 'README.md': 'Readme\n' } },
            ]);
            await expect(thirdPartyNotices(metadata)).rejects.toThrow(
                'The crate unlicensed 1.0.0 ships no license file.',
            );
        } finally {
            await rm(root, { force: true, recursive: true });
        }
    });
});
