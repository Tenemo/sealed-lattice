import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

const repositoryRoot = process.cwd();
const workflowPath = (fileName: string): string =>
    path.join(repositoryRoot, '.github', 'workflows', fileName);

const getJobBlock = (workflow: string, jobName: string): string => {
    const jobStart = workflow.indexOf(`    ${jobName}:`);
    expect(jobStart).toBeGreaterThanOrEqual(0);
    const remainingWorkflow = workflow.slice(jobStart + 1);
    const nextJob = /\n {4}[a-z][a-z0-9-]*:\r?\n/u.exec(remainingWorkflow);
    return workflow.slice(
        jobStart,
        nextJob === null ? undefined : jobStart + 1 + nextJob.index,
    );
};

describe('GitHub workflow policy', () => {
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
        expect(workflow).toMatch(
            /npm publish[^\n]+--provenance[^\n]+--tag latest/u,
        );
        expect(workflow).not.toContain('--prerelease');
        expect(workflow).toContain(
            'ref: ${{ needs.prepare-release.outputs.tag }}',
        );
    });

    it('runs ordinary verification and gates expensive proof lanes by classification', async () => {
        const workflow = await readFile(workflowPath('ci.yml'), 'utf8');

        expect(workflow).toContain(
            "format('ci-ten-participant-accepted-setup-evidence-{0}', github.ref)",
        );
        expect(workflow).toContain(
            "format('ci-{0}-{1}', github.workflow, github.ref)",
        );
        expect(workflow).toContain(
            "cancel-in-progress: ${{ !(github.event_name == 'workflow_dispatch' && inputs.ten_participant_accepted_setup_evidence) }}",
        );
        expect(workflow).toMatch(/^concurrency:\r?\n {4}group:/mu);
        expect(workflow.match(/concurrency:/gu)).toHaveLength(1);

        const changesJob = getJobBlock(workflow, 'changes');
        expect(changesJob).toContain('node ./tools/ci/classify-ci-changes.mjs');
        expect(changesJob).not.toContain('bootstrap-pnpm');

        const ordinaryCommands = new Map([
            ['static-build', 'pnpm run build:verify-reproducible'],
            ['rust-fast', 'pnpm run test:rust:kernel'],
            ['node', 'pnpm run test:node'],
            ['browser', 'pnpm run test:browser'],
        ]);
        for (const [jobName, command] of ordinaryCommands) {
            expect(getJobBlock(workflow, jobName)).toContain(command);
        }

        const heavyCommands = new Map([
            ['rust-heavy', 'pnpm run test:rust:kernel:heavy'],
            [
                'rust-accepted-setup',
                'pnpm run test:rust:kernel:accepted-setup -- --ci',
            ],
            ['node-kernel-heavy', 'pnpm run test:node:kernel:heavy'],
        ]);
        for (const [jobName, command] of heavyCommands) {
            const job = getJobBlock(workflow, jobName);
            expect(job).toContain(
                "if: ${{ needs.changes.outputs.run_heavy == 'true' }}",
            );
            expect(job).toContain(command);
            expect(job).toContain('if: ${{ always() }}');
            expect(job).toContain('actions/upload-artifact@');
        }

        const tenParticipantEvidenceJob = getJobBlock(
            workflow,
            'rust-ten-participant-accepted-setup-evidence',
        );
        expect(tenParticipantEvidenceJob).toContain(
            "if: ${{ github.event_name == 'workflow_dispatch' && inputs.ten_participant_accepted_setup_evidence }}",
        );
        expect(tenParticipantEvidenceJob).toContain(
            'pnpm run test:rust:kernel:accepted-setup:ten-participant-evidence',
        );
        expect(tenParticipantEvidenceJob).toContain('if: ${{ always() }}');
        expect(tenParticipantEvidenceJob).toContain('actions/upload-artifact@');

        expect(getJobBlock(workflow, 'rust-fast')).toContain(
            'if: ${{ failure() }}',
        );
        for (const jobName of ['static-build', 'node', 'browser']) {
            expect(getJobBlock(workflow, jobName)).not.toContain(
                'actions/upload-artifact@',
            );
        }

        const verifyJob = getJobBlock(workflow, 'verify');
        expect(verifyJob).toContain("process.env.RUN_HEAVY === 'false'");
        for (const jobName of heavyCommands.keys()) {
            expect(verifyJob).toContain(`allowedSkippedJobs.add('${jobName}')`);
        }
        expect(verifyJob).toContain(
            "allowedSkippedJobs.add('rust-ten-participant-accepted-setup-evidence')",
        );
    });
});
