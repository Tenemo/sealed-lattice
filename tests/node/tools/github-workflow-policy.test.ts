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
        expect(workflow).not.toContain('download-artifact');
        expect(workflow).not.toContain('retention-days:');
        expect(workflow.match(/actions\/upload-artifact@/gu)).toHaveLength(4);
        expect(workflow).toContain(
            'prepare-release-logs-${{ github.run_id }}-${{ github.run_attempt }}',
        );
        expect(workflow).toContain(
            'push-release-logs-${{ github.run_id }}-${{ github.run_attempt }}',
        );
        expect(workflow).toContain(
            'publish-npm-logs-${{ github.run_id }}-${{ github.run_attempt }}',
        );
        expect(workflow).toContain(
            'create-github-release-logs-${{ github.run_id }}-${{ github.run_attempt }}',
        );
        expect(workflow.match(/if-no-files-found: warn/gu)).toHaveLength(4);
        expect(workflow).toContain(
            'ref: ${{ needs.prepare-release.outputs.tag }}',
        );
    });

    it('preserves test diagnostics with timeout headroom and non-cancellable expensive lanes', async () => {
        const workflow = await readFile(workflowPath('ci.yml'), 'utf8');

        expect(workflow).not.toMatch(/^concurrency:/mu);
        expect(workflow).not.toContain('retention-days:');
        expect(workflow.match(/if-no-files-found: warn/gu)).toHaveLength(7);
        expect(workflow.match(/if: \$\{\{ always\(\) \}\}/gu)).toHaveLength(8);
        expect(workflow).toContain(
            'static-verification-logs-${{ github.run_id }}-${{ github.run_attempt }}',
        );
        for (const lane of [
            'rust-heavy',
            'rust-accepted-setup',
            'node-kernel-heavy',
        ]) {
            const laneStart = workflow.indexOf(`    ${lane}:`);
            const remainingWorkflow = workflow.slice(laneStart + 1);
            const nextLaneMatch = /\n {4}[a-z][a-z0-9-]*:\r?\n/u.exec(
                remainingWorkflow,
            );
            const nextLaneStart =
                nextLaneMatch?.index === undefined
                    ? -1
                    : laneStart + 1 + nextLaneMatch.index;
            const laneBlock = workflow.slice(
                laneStart,
                nextLaneStart === -1 ? undefined : nextLaneStart,
            );
            expect(laneBlock).toContain('cancel-in-progress: false');
        }
        expect(workflow).toContain('timeout-minutes: 350');
        expect(workflow).toContain('timeout-minutes: 370');
    });
});
