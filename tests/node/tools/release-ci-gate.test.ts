import { describe, expect, it } from 'vitest';

import {
    waitForSuccessfulExactSourceCi,
    type GitHubCommandExecutor,
    type GitHubCommandInvocation,
} from '#tools/ci/release-ci-gate.js';
import type { ReleaseCommandProbe } from '#tools/ci/release-policy.js';

const repository = 'Tenemo/sealed-lattice';
const sourceRevision = 'exact-source-revision';
const runIdentifier = 123_456;
const runUrl = `https://github.com/${repository}/actions/runs/${String(runIdentifier)}`;

const successfulProbe = (stdout: string): ReleaseCommandProbe => ({
    exitCode: 0,
    stderr: '',
    stdout,
});

const listedRun = (input: {
    readonly conclusion: string;
    readonly headRevision?: string;
    readonly status: string;
}): Record<string, unknown> => ({
    conclusion: input.conclusion,
    databaseId: runIdentifier,
    headSha: input.headRevision ?? sourceRevision,
    status: input.status,
    url: runUrl,
});

const viewedRun = (input: {
    readonly conclusion: string;
    readonly headRevision?: string;
    readonly status: string;
    readonly verifyConclusion?: string;
}): Record<string, unknown> => ({
    ...listedRun(input),
    jobs:
        input.verifyConclusion === undefined
            ? []
            : [
                  {
                      conclusion: input.verifyConclusion,
                      name: 'verify',
                  },
              ],
});

const isRunList = (invocation: GitHubCommandInvocation): boolean =>
    invocation.arguments[0] === 'run' && invocation.arguments[1] === 'list';

describe('release CI gate', () => {
    it('accepts an existing successful exact-source run with a successful verify job', async () => {
        const invocations: GitHubCommandInvocation[] = [];
        const executor: GitHubCommandExecutor = (invocation) => {
            invocations.push(invocation);
            return successfulProbe(
                JSON.stringify(
                    isRunList(invocation)
                        ? [
                              listedRun({
                                  conclusion: 'success',
                                  status: 'completed',
                              }),
                          ]
                        : viewedRun({
                              conclusion: 'success',
                              status: 'completed',
                              verifyConclusion: 'success',
                          }),
                ),
            );
        };

        await expect(
            waitForSuccessfulExactSourceCi({
                executor,
                repository,
                sourceRevision,
            }),
        ).resolves.toEqual({ runIdentifier, url: runUrl });
        expect(invocations).toHaveLength(2);
        expect(invocations[0]?.arguments).toContain(repository);
        expect(invocations[0]?.arguments).toContain(sourceRevision);
        expect(invocations[0]?.arguments).toContain('ci.yml');
    });

    it('waits for run registration and queued execution before accepting CI', async () => {
        let listCallCount = 0;
        let viewCallCount = 0;
        const delays: number[] = [];
        const executor: GitHubCommandExecutor = (invocation) => {
            if (isRunList(invocation)) {
                listCallCount += 1;
                return successfulProbe(
                    JSON.stringify(
                        listCallCount === 1
                            ? []
                            : [
                                  listedRun({
                                      conclusion: '',
                                      status: 'queued',
                                  }),
                              ],
                    ),
                );
            }
            viewCallCount += 1;
            return successfulProbe(
                JSON.stringify(
                    viewCallCount === 1
                        ? viewedRun({ conclusion: '', status: 'in_progress' })
                        : viewedRun({
                              conclusion: 'success',
                              status: 'completed',
                              verifyConclusion: 'success',
                          }),
                ),
            );
        };

        await expect(
            waitForSuccessfulExactSourceCi({
                delay: (durationMilliseconds) => {
                    delays.push(durationMilliseconds);
                    return Promise.resolve();
                },
                executor,
                repository,
                sourceRevision,
            }),
        ).resolves.toEqual({ runIdentifier, url: runUrl });
        expect(listCallCount).toBe(2);
        expect(viewCallCount).toBe(2);
        expect(delays).toEqual([5_000, 30_000]);
    });

    it('rejects a completed failing CI run without waiting again', async () => {
        const executor: GitHubCommandExecutor = (invocation) =>
            successfulProbe(
                JSON.stringify(
                    isRunList(invocation)
                        ? [
                              listedRun({
                                  conclusion: 'failure',
                                  status: 'completed',
                              }),
                          ]
                        : viewedRun({
                              conclusion: 'failure',
                              status: 'completed',
                          }),
                ),
            );

        await expect(
            waitForSuccessfulExactSourceCi({
                executor,
                repository,
                sourceRevision,
            }),
        ).rejects.toThrow('conclusion failure');
    });

    it('rejects successful CI that lacks the final verify authority', async () => {
        const executor: GitHubCommandExecutor = (invocation) =>
            successfulProbe(
                JSON.stringify(
                    isRunList(invocation)
                        ? [
                              listedRun({
                                  conclusion: 'success',
                                  status: 'completed',
                              }),
                          ]
                        : viewedRun({
                              conclusion: 'success',
                              status: 'completed',
                          }),
                ),
            );

        await expect(
            waitForSuccessfulExactSourceCi({
                executor,
                repository,
                sourceRevision,
            }),
        ).rejects.toThrow('without a successful verify job');
    });

    it('rejects a run whose returned source revision does not match the release source', async () => {
        const executor: GitHubCommandExecutor = () =>
            successfulProbe(
                JSON.stringify([
                    listedRun({
                        conclusion: 'success',
                        headRevision: 'different-source-revision',
                        status: 'completed',
                    }),
                ]),
            );

        await expect(
            waitForSuccessfulExactSourceCi({
                executor,
                repository,
                sourceRevision,
            }),
        ).rejects.toThrow('not exact source');
    });

    it('fails after the bounded registration wait when no exact-source CI run appears', async () => {
        let listCallCount = 0;
        let delayCallCount = 0;
        const executor: GitHubCommandExecutor = () => {
            listCallCount += 1;
            return successfulProbe('[]');
        };

        await expect(
            waitForSuccessfulExactSourceCi({
                delay: () => {
                    delayCallCount += 1;
                    return Promise.resolve();
                },
                executor,
                repository,
                sourceRevision,
            }),
        ).rejects.toThrow('No CI run exists for exact source');
        expect(listCallCount).toBe(12);
        expect(delayCallCount).toBe(11);
    });
});
