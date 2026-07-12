import { Buffer } from 'node:buffer';

import { describe, expect, it } from 'vitest';

import {
    isDocumentationOnlyCiPath,
    parseNullDelimitedGitNameStatus,
    shouldRunHeavyCiLanes,
} from '#tools/ci/classify-ci-changes';

describe('CI heavy-lane change classification', () => {
    it('skips heavy lanes only for explicitly recognized documentation', () => {
        const documentationPaths = [
            'README.md',
            'packages/protocol/README.md',
            'SECURITY.md',
            'LICENSE',
            'reference-documents/paper.txt',
        ];

        expect(documentationPaths.every(isDocumentationOnlyCiPath)).toBe(true);
        expect(shouldRunHeavyCiLanes(documentationPaths)).toBe(false);
    });

    it('runs heavy lanes for source, locks, manifests, workflows, and unknown paths', () => {
        for (const changedPath of [
            'packages/sdk/src/index.ts',
            'packages/sdk/package.json',
            'pnpm-lock.yaml',
            '.github/workflows/ci.yml',
            'packages/sdk/src/license.ts',
            'packages/sdk/src/notice.js',
            'unclassified/generated.txt',
            '../outside.md',
        ]) {
            expect(shouldRunHeavyCiLanes([changedPath])).toBe(true);
        }
    });

    it('runs heavy lanes for empty and mixed change sets', () => {
        expect(shouldRunHeavyCiLanes([])).toBe(true);
        expect(
            shouldRunHeavyCiLanes([
                'README.md',
                'packages/protocol/src/index.ts',
            ]),
        ).toBe(true);
    });

    it('parses null-delimited git statuses and retains both rename paths', () => {
        const changedPaths = parseNullDelimitedGitNameStatus(
            Buffer.from(
                'M\0README.md\0R100\0packages/protocol/src/old.ts\0reference-documents/paper notes.txt\0',
            ),
        );
        expect(changedPaths).toEqual([
            'README.md',
            'packages/protocol/src/old.ts',
            'reference-documents/paper notes.txt',
        ]);
        expect(shouldRunHeavyCiLanes(changedPaths)).toBe(true);
        expect(() =>
            parseNullDelimitedGitNameStatus(Buffer.from('R100\0README.md\0')),
        ).toThrow('missing a path');
    });
});
