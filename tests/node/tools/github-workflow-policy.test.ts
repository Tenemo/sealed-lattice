import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { format } from 'prettier';
import { describe, expect, it } from 'vitest';

const repositoryRoot = process.cwd();
const workflowPath = (fileName: string): string =>
    path.join(repositoryRoot, '.github', 'workflows', fileName);

describe('GitHub workflow policy', () => {
    it.each(['ci.yml', 'release.yml'])(
        'parses %s as YAML',
        async (fileName) => {
            const workflow = await readFile(workflowPath(fileName), 'utf8');

            await expect(
                format(workflow, { parser: 'yaml' }),
            ).resolves.toContain('name:');
        },
    );

    it('keeps the release workflow stable, tag-built, and credential-minimal', async () => {
        const workflow = await readFile(workflowPath('release.yml'), 'utf8');
        const releaseInputStart = workflow.indexOf('release_type:');
        const releaseInputEnd = workflow.indexOf('\npermissions:');
        const releaseInput = workflow.slice(releaseInputStart, releaseInputEnd);

        expect(releaseInputStart).toBeGreaterThanOrEqual(0);
        expect(releaseInputEnd).toBeGreaterThan(releaseInputStart);
        expect(releaseInput.match(/- patch/gu)).toHaveLength(1);
        expect(releaseInput.match(/- minor/gu)).toHaveLength(1);
        expect(releaseInput).not.toMatch(/major|beta|prerelease/iu);

        expect(workflow).not.toContain('persist-credentials: true');
        expect(workflow).toContain('gh auth setup-git');
        expect(workflow.indexOf('gh auth setup-git')).toBeGreaterThan(
            workflow.indexOf('Commit and tag release metadata'),
        );
        expect(workflow.match(/--tag latest/gu)?.length).toBeGreaterThanOrEqual(
            2,
        );
        expect(workflow).not.toContain('--prerelease');
        expect(workflow).not.toContain('upload-artifact');
        expect(workflow).not.toContain('download-artifact');
        expect(workflow).toContain(
            'ref: ${{ needs.prepare-release.outputs.tag }}',
        );
    });
});
