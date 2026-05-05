import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
    deriveArtifactArchiveRelativePaths,
    extractWithListValues,
    extractWithScalarValue,
    extractWorkflowJobBlock,
    findArtifactStepBlock,
    findReleaseWorkflowContractFailures,
    getReleaseWorkflowPath,
    normalizeWorkflowPath,
    simulateDownloadedArtifactPaths,
} from '../../../tools/ci/verify-release-workflow';

const createReleaseWorkflowFixture = (
    pushReleaseDownloadPath: string,
    publishNpmDownloadPath: string,
): string => `
jobs:
    prepare-release:
        steps:
            - uses: actions/upload-artifact@v7.0.1
              with:
                  name: release-package
                  path: |
                      packages/sdk/package.json
                      packages/sdk/dist

    push-release:
        steps:
            - uses: actions/download-artifact@v8.0.1
              with:
                  name: release-package
                  path: ${pushReleaseDownloadPath}

    publish-npm:
        steps:
            - uses: actions/download-artifact@v8.0.1
              with:
                  name: release-package
                  path: ${publishNpmDownloadPath}
`;

describe('release workflow helpers', () => {
    it('normalizes workflow paths and simulates release artifact downloads', () => {
        const uploadPaths = [
            'packages\\sdk\\package.json',
            './packages/sdk/dist/',
        ];

        expect(uploadPaths.map(normalizeWorkflowPath)).toEqual([
            'packages/sdk/package.json',
            'packages/sdk/dist',
        ]);
        expect(deriveArtifactArchiveRelativePaths(uploadPaths)).toEqual([
            'package.json',
            'dist',
        ]);
        expect(simulateDownloadedArtifactPaths(uploadPaths, '.')).toEqual([
            'package.json',
            'dist',
        ]);
        expect(
            simulateDownloadedArtifactPaths(uploadPaths, 'packages/sdk'),
        ).toEqual(['packages/sdk/package.json', 'packages/sdk/dist']);
    });

    it('extracts release artifact step metadata from the workflow', () => {
        const workflowText = createReleaseWorkflowFixture(
            'packages/sdk',
            'packages/sdk',
        );
        const prepareReleaseJobBlock = extractWorkflowJobBlock(
            workflowText,
            'prepare-release',
        );
        const uploadArtifactStepBlock = findArtifactStepBlock(
            prepareReleaseJobBlock,
            'actions/upload-artifact@v7.0.1',
            'release-package',
        );

        expect(uploadArtifactStepBlock).toBeDefined();
        expect(extractWithScalarValue(uploadArtifactStepBlock!, 'name')).toBe(
            'release-package',
        );
        expect(extractWithListValues(uploadArtifactStepBlock!, 'path')).toEqual(
            ['packages/sdk/package.json', 'packages/sdk/dist'],
        );
    });

    it('flags release artifact downloads that would flatten package paths', () => {
        const failures = findReleaseWorkflowContractFailures(
            createReleaseWorkflowFixture('.', '.'),
        );

        expect(failures).toEqual(
            expect.arrayContaining([
                expect.stringContaining(
                    'push-release downloads release-package to .',
                ),
                expect.stringContaining(
                    'publish-npm downloads release-package to .',
                ),
            ]),
        );
    });

    it('accepts the checked-in release workflow contract', () => {
        const workflowText = readFileSync(getReleaseWorkflowPath(), 'utf8');

        expect(findReleaseWorkflowContractFailures(workflowText)).toEqual([]);
    });
});
