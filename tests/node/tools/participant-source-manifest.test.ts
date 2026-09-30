import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { participantSourceManifest } from '#tools/ci/build-participant-module.js';
import {
    compiledRustSources,
    requireCheckoutBytes,
} from '#tools/ci/compiled-inputs.js';

type Manifest = {
    tools: Record<string, string>;
    files: { file: string; sha512: string; bytes: number }[];
};

const fixtureBuild = (sources: readonly string[]) => ({
    compiler: 'fixture compiler',
    flags: [],
    module: Buffer.alloc(0),
    sources,
});

describe('participant source identity', () => {
    it('binds the compiled sources, their Cargo manifests, the build definitions and the tools', async () => {
        const manifest = JSON.parse(
            await participantSourceManifest(
                fixtureBuild([
                    'crates/protocol-research/registration-enrollment/src/lib.rs',
                    'crates/sealed-lattice-kernel/src/foundation/hash.rs',
                ]),
                [
                    'packages/sdk/src/participant/participant.ts',
                    'packages/wasm/src/foundation-contract.ts',
                ],
            ),
        ) as Manifest;
        // The page controller and the bridge come from the bundles, the Rust
        // sources from the compiler, and the manifests above them define
        // their packages and workspaces.
        for (const file of [
            'packages/sdk/src/participant/participant.ts',
            'packages/wasm/src/foundation-contract.ts',
            'crates/protocol-research/registration-enrollment/src/lib.rs',
            'crates/protocol-research/registration-enrollment/Cargo.toml',
            'crates/protocol-research/Cargo.toml',
            'crates/protocol-research/Cargo.lock',
            'crates/sealed-lattice-kernel/Cargo.toml',
            'Cargo.toml',
            'Cargo.lock',
            'rust-toolchain.toml',
            'tools/ci/sdk-package-tsdown.config.ts',
        ]) {
            const source = await readFile(file);
            expect(
                manifest.files.find((entry) => entry.file === file),
                file,
            ).toEqual({
                file,
                sha512: createHash('sha512').update(source).digest('hex'),
                bytes: source.length,
            });
        }
        // Documentation, tests, other crates and the workspace's own lockfile
        // are not compiled into the packaged runtime.
        for (const file of [
            'README.md',
            'crates/protocol-research/README.md',
            'crates/protocol-research/native-ceremony/Cargo.toml',
            'package.json',
            'pnpm-lock.yaml',
            'tests/node/tools/participant-source-manifest.test.ts',
        ])
            expect(
                manifest.files.some((entry) => entry.file === file),
                file,
            ).toBe(false);
        expect(Object.keys(manifest.tools)).toEqual([
            'binaryen',
            'rolldown',
            'tsdown',
            'typescript',
        ]);
    });

    it('reads a dependency-information rule into repository files', async () => {
        const directory = await mkdtemp(path.join(tmpdir(), 'dependency-'));
        try {
            const root = path.resolve('.');
            const dependencyInformation = path.join(directory, 'module.d');
            await writeFile(
                dependencyInformation,
                path.join(root, 'target', 'module.wasm') +
                    ': ' +
                    [
                        path.join(root, 'crates', 'a', 'src', '..', 'b.rs'),
                        // The rule escapes a space in a path.
                        path.join(root, 'crates', 'with') + '\\ space.rs',
                    ].join(' ') +
                    '\n\n' +
                    path.join(root, 'crates', 'a', 'src', '..', 'b.rs') +
                    ':\n',
            );
            expect(await compiledRustSources(dependencyInformation)).toEqual([
                'crates/a/b.rs',
                'crates/with space.rs',
            ]);
            await writeFile(
                dependencyInformation,
                path.join(root, 'target', 'module.wasm') +
                    ': ' +
                    path.join(path.dirname(root), 'elsewhere.rs') +
                    '\n',
            );
            await expect(
                compiledRustSources(dependencyInformation),
            ).rejects.toThrow('outside the repository');
        } finally {
            await rm(directory, { recursive: true, force: true });
        }
    });

    it('refuses sources a checkout would not reproduce byte for byte', async () => {
        const directory = await mkdtemp(path.join(tmpdir(), 'checkout-'));
        const git = (...argumentsList: string[]) => {
            const result = spawnSync('git', argumentsList, {
                cwd: directory,
                encoding: 'utf8',
                windowsHide: true,
            });
            expect(result.status, result.stderr).toBe(0);
        };
        try {
            git('init', '--quiet');
            git('config', 'core.autocrlf', 'false');
            await writeFile(
                path.join(directory, '.gitattributes'),
                '* text=auto eol=lf\n',
            );
            await writeFile(path.join(directory, '.gitignore'), 'ignored.rs\n');
            await writeFile(path.join(directory, 'committed.rs'), 'a\nb\n');
            await writeFile(path.join(directory, 'converted.rs'), 'a\r\nb\r\n');
            await writeFile(path.join(directory, 'mixed.rs'), 'a\r\nb\n');
            await writeFile(path.join(directory, 'untracked.rs'), 'a\nb\n');
            await writeFile(path.join(directory, 'ignored.rs'), 'a\nb\n');
            await writeFile(
                path.join(directory, 'table.bin'),
                Buffer.from([0, 13, 10, 255]),
            );
            git('add', 'committed.rs', 'converted.rs', 'mixed.rs', 'table.bin');
            requireCheckoutBytes(
                ['committed.rs', 'untracked.rs', 'table.bin'],
                directory,
            );
            for (const [file, refusal] of [
                ['converted.rs', 'line endings'],
                ['mixed.rs', 'line endings'],
                ['ignored.rs', 'ignored by git or missing'],
                ['absent.rs', 'ignored by git or missing'],
            ])
                expect(() => requireCheckoutBytes([file], directory)).toThrow(
                    refusal,
                );
        } finally {
            await rm(directory, { recursive: true, force: true });
        }
    });
});
