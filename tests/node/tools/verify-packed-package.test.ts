import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    createDryRunPackArguments,
    createPackageManagerSpawnCommand,
    createInstallArguments,
    createPackArguments,
    detectPackageManager,
    getPackageManagerExecutableName,
    getPublicPackageDirectory,
    parsePackDryRunFilePaths,
    parsePackageManagerOverride,
    resolvePackageManagerRunner,
    validatePublishedPackageFilePaths,
} from '../../../tools/ci/verify-packed-package';

describe('packed package smoke helpers', () => {
    it('resolves the public package directory', () => {
        expect(getPublicPackageDirectory('/repo/root')).toBe(
            path.resolve('/repo/root', 'packages', 'sdk'),
        );
    });

    it('parses explicit package manager overrides', () => {
        expect(parsePackageManagerOverride(['--package-manager', 'npm'])).toBe(
            'npm',
        );
        expect(parsePackageManagerOverride(['--package-manager', 'pnpm'])).toBe(
            'pnpm',
        );
        expect(parsePackageManagerOverride([])).toBeUndefined();
    });

    it('rejects unsupported package manager overrides', () => {
        expect(() =>
            parsePackageManagerOverride(['--package-manager', 'yarn']),
        ).toThrow('Unsupported package manager override: yarn');
        expect(() =>
            parsePackageManagerOverride(['--package-manager']),
        ).toThrow('--package-manager requires a value');
    });

    it('detects the invoking package manager from npm_execpath', () => {
        expect(
            detectPackageManager('/usr/local/lib/node_modules/pnpm/pnpm.cjs'),
        ).toBe('pnpm');
        expect(
            detectPackageManager('/usr/local/lib/node_modules/npm/npm-cli.js'),
        ).toBe('npm');
    });

    it('derives package manager executables for each platform', () => {
        expect(getPackageManagerExecutableName('npm', 'win32')).toBe('npm.cmd');
        expect(getPackageManagerExecutableName('pnpm', 'win32')).toBe(
            'pnpm.cmd',
        );
        expect(getPackageManagerExecutableName('npm', 'linux')).toBe('npm');
        expect(getPackageManagerExecutableName('pnpm', 'darwin')).toBe('pnpm');
    });

    it('builds package manager arguments for pack and install commands', () => {
        expect(createPackArguments('/tmp/pack')).toEqual([
            'pack',
            '--pack-destination',
            '/tmp/pack',
        ]);
        expect(createDryRunPackArguments()).toEqual([
            'pack',
            '--dry-run',
            '--json',
            '--ignore-scripts',
        ]);
        expect(createInstallArguments('pnpm', '/tmp/pkg.tgz')).toEqual([
            'add',
            '--ignore-scripts',
            '--silent',
            '/tmp/pkg.tgz',
        ]);
        expect(createInstallArguments('npm', '/tmp/pkg.tgz')).toEqual([
            'install',
            '--ignore-scripts',
            '--silent',
            '/tmp/pkg.tgz',
        ]);
    });

    it('builds a Windows-safe spawn command for package manager shims', () => {
        expect(
            createPackageManagerSpawnCommand(
                {
                    command: 'npm.cmd',
                    commandArgsPrefix: [],
                    kind: 'npm',
                },
                ['install', '--silent', 'C:\\Temp\\with space\\pkg.tgz'],
                'C:\\Windows\\System32\\cmd.exe',
            ),
        ).toEqual({
            command: 'C:\\Windows\\System32\\cmd.exe',
            args: [
                '/d',
                '/s',
                '/c',
                'npm.cmd',
                'install',
                '--silent',
                'C:\\Temp\\with space\\pkg.tgz',
            ],
            description:
                'npm.cmd install --silent C:\\Temp\\with space\\pkg.tgz',
        });
    });

    it('resolves the default invoking package manager runner', () => {
        expect(resolvePackageManagerRunner([], '/tools/pnpm.cjs')).toEqual({
            command: process.execPath,
            commandArgsPrefix: ['/tools/pnpm.cjs'],
            kind: 'pnpm',
        });
    });

    it('prefers an explicit package manager override', () => {
        expect(
            resolvePackageManagerRunner(
                ['--package-manager', 'npm'],
                '/tools/pnpm.cjs',
            ),
        ).toEqual({
            command: getPackageManagerExecutableName('npm'),
            commandArgsPrefix: [],
            kind: 'npm',
        });
    });

    it('requires npm_execpath when no override is provided', () => {
        const originalPackageManagerEntryPointPath = process.env.npm_execpath;

        delete process.env.npm_execpath;

        try {
            expect(() => resolvePackageManagerRunner([])).toThrow(
                'npm_execpath is required to run package manager commands when --package-manager is not provided',
            );
        } finally {
            if (originalPackageManagerEntryPointPath === undefined) {
                delete process.env.npm_execpath;
            } else {
                process.env.npm_execpath = originalPackageManagerEntryPointPath;
            }
        }
    });

    it('parses npm dry-run metadata into published file paths', () => {
        expect(
            parsePackDryRunFilePaths(
                JSON.stringify([
                    {
                        files: [
                            { path: 'dist/index.js' },
                            { path: 'LICENSE' },
                            { path: 'README.md' },
                        ],
                    },
                ]),
            ),
        ).toEqual(['dist/index.js', 'LICENSE', 'README.md']);
    });

    it('rejects invalid npm dry-run metadata', () => {
        expect(() => parsePackDryRunFilePaths('{}')).toThrow(
            'npm pack --dry-run --json returned an unexpected shape',
        );
    });

    it('flags missing license text and leaked TypeScript build metadata', () => {
        expect(
            validatePublishedPackageFilePaths([
                'README.md',
                'dist/index.js',
                'dist/tsconfig.tsbuildinfo',
            ]),
        ).toEqual([
            'Published package is missing LICENSE',
            'Published package must not include TypeScript build metadata: dist/tsconfig.tsbuildinfo',
        ]);
    });

    it('accepts the intended published package file layout', () => {
        expect(
            validatePublishedPackageFilePaths([
                'LICENSE',
                'README.md',
                'dist/index.d.ts',
                'dist/index.js',
                'dist/index.js.map',
                'package.json',
            ]),
        ).toEqual([]);
    });
});
