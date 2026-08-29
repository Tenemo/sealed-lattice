import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const workflowDirectoryUrl = new URL(
    '../../../.github/workflows/',
    import.meta.url,
);
const ciWorkflowPath = fileURLToPath(new URL('ci.yml', workflowDirectoryUrl));
const releaseWorkflowPath = fileURLToPath(
    new URL('release.yml', workflowDirectoryUrl),
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

    it('waits for exact-source CI before releasing without repeating the CI graph', async () => {
        const releaseWorkflow = await readFile(releaseWorkflowPath, 'utf8');

        expect(releaseWorkflow).toMatch(
            /^ {4}validate-source:\r?\n(?:.|\r?\n)*?^ {8}timeout-minutes: 360$/mu,
        );
        expect(releaseWorkflow).toContain(
            '- name: Wait for successful CI for the exact source',
        );
        expect(releaseWorkflow).toContain(
            'run: pnpm exec tsx ./tools/ci/release-gates.ts await-ci',
        );
        expect(releaseWorkflow).not.toContain('pnpm run check');
    });

    it('uses the repository deploy key for the protected release push', async () => {
        const releaseWorkflow = await readFile(releaseWorkflowPath, 'utf8');
        const pushReleaseStart = releaseWorkflow.indexOf('    push-release:');
        const publishNpmStart = releaseWorkflow.indexOf('    publish-npm:');

        expect(pushReleaseStart).toBeGreaterThan(-1);
        expect(publishNpmStart).toBeGreaterThan(pushReleaseStart);

        const pushReleaseJob = releaseWorkflow.slice(
            pushReleaseStart,
            publishNpmStart,
        );

        expect(pushReleaseJob).toContain('            contents: read');
        expect(pushReleaseJob).not.toContain('contents: write');
        expect(pushReleaseJob).toContain(
            'RELEASE_DEPLOY_KEY: ${{ secrets.RELEASE_DEPLOY_KEY }}',
        );
        expect(pushReleaseJob).toContain('persist-credentials: true');
        expect(pushReleaseJob).toContain(
            'ssh-key: ${{ secrets.RELEASE_DEPLOY_KEY }}',
        );
        expect(pushReleaseJob).toContain(
            'git remote set-url origin "git@github.com:${GITHUB_REPOSITORY}.git"',
        );
        expect(pushReleaseJob).toContain('git push --atomic origin');
        expect(pushReleaseJob).not.toContain('GH_TOKEN');
        expect(pushReleaseJob).not.toContain('gh auth setup-git');
    });
});
