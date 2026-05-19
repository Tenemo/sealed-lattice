import { describe, expect, it } from 'vitest';

import {
    createPackageManagerSpawnCommand,
    detectPackageManager,
    extractPublishedKernelDigest,
    getPackageManagerExecutableName,
    hashPublishedKernelBytesSha256Hex,
    parsePackDryRunFilePaths,
    parsePackageManagerOverride,
    resolvePackageManagerRunner,
    validatePublishedKernelIntegrity,
    validatePublishedPackageMetadata,
    validatePublishedPackageFilePaths,
} from '../../../tools/ci/verify-packed-package';

describe('packed package smoke helpers', () => {
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
                'dist/internal/election-foundation/plaintext-oracle/index.js',
                'dist/internal/election-foundation/target-acceptance/index.js',
                'dist/tsconfig.tsbuildinfo',
            ]),
        ).toEqual([
            'Published package is missing required file: LICENSE',
            'Published package is missing required file: dist/kernel.js',
            'Published package is missing required file: dist/sealed-lattice-kernel.wasm',
            'Published package is missing required file: dist/internal/board-target.d.ts',
            'Published package is missing required file: dist/internal/lifecycle.d.ts',
            'Published package is missing required file: dist/internal/plaintext-oracle.d.ts',
            'Published package is missing required file: dist/internal/protocol-digest.d.ts',
            'Published package is missing required file: dist/internal/protocol-objects.d.ts',
            'Published package is missing required file: dist/internal/roster-recovery.d.ts',
            'Published package is missing required file: dist/internal/transcript-core.d.ts',
            'Published package is missing required file: public-surface.json',
            'Published package must not include TypeScript build metadata: dist/tsconfig.tsbuildinfo',
            'Published package must not include internal protocol runtime: dist/internal/election-foundation/plaintext-oracle/index.js',
            'Published package must not include internal protocol runtime: dist/internal/election-foundation/target-acceptance/index.js',
        ]);
    });

    it('rejects public package description metadata', () => {
        expect(
            validatePublishedPackageMetadata({
                name: 'sealed-lattice',
                description: 'temporary package summary',
                devDependencies: {
                    '@sealed-lattice/types': 'workspace:*',
                },
                scripts: {
                    build: 'pnpm run build',
                },
            }),
        ).toEqual([
            'Published package metadata must not include a description field',
            'Published package metadata must not include devDependencies',
            'Published package metadata must not include scripts',
        ]);
        expect(
            validatePublishedPackageMetadata({
                name: 'sealed-lattice',
            }),
        ).toEqual([]);
    });

    it('accepts the intended published package file layout', () => {
        expect(
            validatePublishedPackageFilePaths([
                'LICENSE',
                'README.md',
                'dist/index.d.ts',
                'dist/index.js',
                'dist/index.js.map',
                'dist/kernel.js',
                'dist/internal/board-target.d.ts',
                'dist/internal/lifecycle.d.ts',
                'dist/internal/plaintext-oracle.d.ts',
                'dist/internal/protocol-digest.d.ts',
                'dist/internal/protocol-objects.d.ts',
                'dist/internal/roster-recovery.d.ts',
                'dist/internal/transcript-core.d.ts',
                'dist/sealed-lattice-kernel.wasm',
                'package.json',
                'public-surface.json',
            ]),
        ).toEqual([]);
    });

    it('validates the published kernel digest pin against the packaged WASM bytes', () => {
        const kernelBytes = Uint8Array.from([0]);
        const digest = hashPublishedKernelBytesSha256Hex(kernelBytes);
        const kernelRuntimeText = `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${digest}';`;

        expect(extractPublishedKernelDigest(kernelRuntimeText)).toBe(digest);
        expect(
            validatePublishedKernelIntegrity(kernelRuntimeText, kernelBytes),
        ).toEqual([]);
    });

    it('rejects unpinned and mismatched published kernel digest metadata', () => {
        const kernelBytes = Uint8Array.from([0]);
        const wrongDigest = '0'.repeat(64);

        expect(
            validatePublishedKernelIntegrity(
                'const packagedTranscriptCoreKernelNormalizedSha256Hex = undefined;',
                kernelBytes,
            ),
        ).toEqual([
            'Published package kernel loader must pin the packaged transcript-core WASM digest',
        ]);
        expect(
            validatePublishedKernelIntegrity(
                `const packagedTranscriptCoreKernelNormalizedSha256Hex = '${wrongDigest}';`,
                kernelBytes,
            ),
        ).toEqual([
            `Published package kernel digest mismatch: expected ${wrongDigest}, received ${hashPublishedKernelBytesSha256Hex(kernelBytes)}`,
        ]);
    });
});
