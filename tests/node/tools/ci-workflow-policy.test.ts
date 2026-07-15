import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const workflowDirectoryUrl = new URL(
    '../../../.github/workflows/',
    import.meta.url,
);
const ciWorkflowPath = fileURLToPath(new URL('ci.yml', workflowDirectoryUrl));
const tenParticipantEvidenceWorkflowPath = fileURLToPath(
    new URL(
        'ten-participant-accepted-setup-evidence.yml',
        workflowDirectoryUrl,
    ),
);

describe('CI workflow policy', () => {
    it('runs routine JavaScript and WASM checks after one workspace build', async () => {
        const ciWorkflow = await readFile(ciWorkflowPath, 'utf8');
        const workspaceBuildCommands = ciWorkflow.match(
            /^ {14}run: pnpm run build\r?$/gmu,
        );

        expect(workspaceBuildCommands).toHaveLength(1);
        expect(ciWorkflow).toMatch(/^ {4}routine:\r?$/mu);
        expect(ciWorkflow).toContain('run: pnpm run test:node:built');
        expect(ciWorkflow).toContain('run: pnpm run test:browser:built');
    });

    it('keeps ten-participant accepted-setup evidence out of pull request CI', async () => {
        const [ciWorkflow, tenParticipantEvidenceWorkflow] = await Promise.all([
            readFile(ciWorkflowPath, 'utf8'),
            readFile(tenParticipantEvidenceWorkflowPath, 'utf8'),
        ]);

        expect(ciWorkflow).not.toContain(
            'rust-ten-participant-accepted-setup-evidence',
        );
        expect(ciWorkflow).not.toContain(
            'test:rust:kernel:accepted-setup:ten-participant-evidence',
        );
        expect(tenParticipantEvidenceWorkflow).toMatch(
            /^on:\r?\n {4}workflow_dispatch:[ \t]*\r?$/mu,
        );
        expect(tenParticipantEvidenceWorkflow).not.toMatch(
            /^ {4}(?:pull_request|push):/mu,
        );
        expect(tenParticipantEvidenceWorkflow).toContain(
            'run: pnpm run test:rust:kernel:accepted-setup:ten-participant-evidence',
        );
        expect(tenParticipantEvidenceWorkflow).toContain(
            'cancel-in-progress: false',
        );
    });
});
