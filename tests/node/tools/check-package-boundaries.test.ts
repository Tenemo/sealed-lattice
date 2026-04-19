import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    collectInternalDependencies,
    extractImportSpecifiers,
    findDependencyCycleFailures,
    validateDeclaredInternalDependencies,
    validateImportBoundaries,
    type ImportObservation,
    type WorkspacePackage,
} from '../../../tools/ci/check-package-boundaries';

const createWorkspacePackage = (
    name: WorkspacePackage['name'],
    directoryPath: string,
    internalDependencies: readonly string[] = [],
): WorkspacePackage => ({
    directoryPath,
    internalDependencies,
    name,
});

const repoRoot = path.resolve('C:\\repo\\sealed-lattice');

describe('package boundary helpers', () => {
    it('collects internal dependencies from package manifests', () => {
        expect(
            collectInternalDependencies(
                {
                    name: '@sealed-lattice/testkit',
                    dependencies: {
                        '@sealed-lattice/crypto': 'workspace:*',
                        react: '^19.0.0',
                    },
                    devDependencies: {
                        'sealed-lattice': 'workspace:*',
                    },
                },
                [
                    'sealed-lattice',
                    '@sealed-lattice/protocol',
                    '@sealed-lattice/crypto',
                    '@sealed-lattice/wasm',
                    '@sealed-lattice/testkit',
                ],
            ),
        ).toEqual(['@sealed-lattice/crypto', 'sealed-lattice']);
    });

    it('handles package manifests with no dependency sections', () => {
        expect(
            collectInternalDependencies(
                {
                    name: '@sealed-lattice/protocol',
                },
                ['@sealed-lattice/protocol'],
            ),
        ).toEqual([]);
    });

    it('extracts static, side-effect, and dynamic import specifiers', () => {
        const sourceText = `
            import 'sealed-lattice';
            import { loadPlaceholderKernel } from '@sealed-lattice/wasm';
            export { something } from '@sealed-lattice/crypto';
            const moduleName = await import('@sealed-lattice/testkit');
        `;

        expect(extractImportSpecifiers(sourceText).sort()).toEqual([
            '@sealed-lattice/crypto',
            '@sealed-lattice/testkit',
            '@sealed-lattice/wasm',
            'sealed-lattice',
        ]);
    });

    it('returns an empty import list when a file has no imports', () => {
        expect(extractImportSpecifiers('const value = 1;')).toEqual([]);
    });

    it('rejects forbidden declared dependencies into the public package', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/protocol',
                path.join(repoRoot, 'packages', 'protocol'),
                ['sealed-lattice'],
            ),
        ];

        expect(validateDeclaredInternalDependencies(workspacePackages)).toEqual(
            [
                '@sealed-lattice/protocol declares forbidden internal dependency sealed-lattice',
            ],
        );
    });

    it('allows declared dependencies that follow the workspace direction', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/testkit',
                path.join(repoRoot, 'packages', 'testkit'),
                ['@sealed-lattice/crypto'],
            ),
        ];

        expect(validateDeclaredInternalDependencies(workspacePackages)).toEqual(
            [],
        );
    });

    it('falls back to an empty allow-list for unknown package names', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/unknown',
                path.join(repoRoot, 'packages', 'unknown'),
            ),
        ];

        expect(validateDeclaredInternalDependencies(workspacePackages)).toEqual(
            [],
        );
    });

    it('detects dependency cycles', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/protocol',
                path.join(repoRoot, 'packages', 'protocol'),
                ['@sealed-lattice/crypto'],
            ),
            createWorkspacePackage(
                '@sealed-lattice/crypto',
                path.join(repoRoot, 'packages', 'crypto'),
                ['@sealed-lattice/protocol'],
            ),
        ];

        expect(findDependencyCycleFailures(workspacePackages)).toEqual([
            '@sealed-lattice/protocol -> @sealed-lattice/crypto -> @sealed-lattice/protocol',
        ]);
    });

    it('rejects deep imports, undeclared package imports, and cross-package relative imports', () => {
        const workspacePackages = [
            createWorkspacePackage(
                'sealed-lattice',
                path.join(repoRoot, 'packages', 'sdk'),
            ),
            createWorkspacePackage(
                '@sealed-lattice/protocol',
                path.join(repoRoot, 'packages', 'protocol'),
            ),
            createWorkspacePackage(
                '@sealed-lattice/crypto',
                path.join(repoRoot, 'packages', 'crypto'),
            ),
        ];
        const importObservations: ImportObservation[] = [
            {
                filePath: path.join(
                    repoRoot,
                    'packages',
                    'protocol',
                    'src',
                    'index.ts',
                ),
                packageName: '@sealed-lattice/protocol',
                specifier: '@sealed-lattice/crypto/src/index.js',
            },
            {
                filePath: path.join(
                    repoRoot,
                    'packages',
                    'protocol',
                    'src',
                    'index.ts',
                ),
                packageName: '@sealed-lattice/protocol',
                specifier: 'sealed-lattice',
            },
            {
                filePath: path.join(
                    repoRoot,
                    'packages',
                    'protocol',
                    'src',
                    'index.ts',
                ),
                packageName: '@sealed-lattice/protocol',
                specifier: '../../crypto/src/index.ts',
            },
        ];

        const failures = validateImportBoundaries(
            workspacePackages,
            importObservations,
        );

        expect(failures).toHaveLength(3);
        expect(failures).toEqual(
            expect.arrayContaining([
                expect.stringContaining(
                    '@sealed-lattice/protocol deep-imports @sealed-lattice/crypto/src/index.js',
                ),
                expect.stringContaining(
                    '@sealed-lattice/protocol imports undeclared internal package sealed-lattice',
                ),
                expect.stringContaining(
                    '@sealed-lattice/protocol uses cross-package relative import ../../crypto/src/index.ts',
                ),
            ]),
        );
    });

    it('allows self-imports by package name inside the same package', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/crypto',
                path.join(repoRoot, 'packages', 'crypto'),
            ),
        ];
        const importObservations: ImportObservation[] = [
            {
                filePath: path.join(
                    repoRoot,
                    'packages',
                    'crypto',
                    'src',
                    'index.ts',
                ),
                packageName: '@sealed-lattice/crypto',
                specifier: '@sealed-lattice/crypto',
            },
        ];

        expect(
            validateImportBoundaries(workspacePackages, importObservations),
        ).toEqual([]);
    });

    it('allows declared internal imports and same-package relative imports', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/testkit',
                path.join(repoRoot, 'packages', 'testkit'),
                ['@sealed-lattice/crypto'],
            ),
            createWorkspacePackage(
                '@sealed-lattice/crypto',
                path.join(repoRoot, 'packages', 'crypto'),
            ),
        ];
        const importObservations: ImportObservation[] = [
            {
                filePath: path.join(
                    repoRoot,
                    'packages',
                    'testkit',
                    'src',
                    'index.ts',
                ),
                packageName: '@sealed-lattice/testkit',
                specifier: '@sealed-lattice/crypto',
            },
            {
                filePath: path.join(
                    repoRoot,
                    'packages',
                    'testkit',
                    'src',
                    'index.ts',
                ),
                packageName: '@sealed-lattice/testkit',
                specifier: './helpers.ts',
            },
        ];

        expect(
            validateImportBoundaries(workspacePackages, importObservations),
        ).toEqual([]);
    });

    it('ignores observations whose source package is outside the workspace map', () => {
        const workspacePackages = [
            createWorkspacePackage(
                '@sealed-lattice/crypto',
                path.join(repoRoot, 'packages', 'crypto'),
            ),
        ];
        const importObservations: ImportObservation[] = [
            {
                filePath: path.join(repoRoot, 'outside.ts'),
                packageName: '@sealed-lattice/protocol',
                specifier: '@sealed-lattice/crypto',
            },
        ];

        expect(
            validateImportBoundaries(workspacePackages, importObservations),
        ).toEqual([]);
    });
});
