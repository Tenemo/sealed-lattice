import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { createLocalRunLog } from '#tools/ci/local-run-log';
import { runCheckGraph, type CheckGraph, type Lane } from '#tools/ci/run-check';

const nodeLane = (
    name: string,
    source: string,
    limitMilliseconds = 120_000,
): Lane => ({
    commands: [
        {
            args: ['--eval', source],
            command: process.execPath,
            description: name,
            logFileSlug: name.toLowerCase().replace(/[^a-z0-9]+/gu, '-'),
        },
    ],
    limitMilliseconds,
    name,
});
const passingLane = (name: string): Lane => nodeLane(name, 'process.exit(0)');
const failingLane = (name: string, exitCode: number): Lane =>
    nodeLane(
        name,
        `console.log(${JSON.stringify(`${name} output`)}); process.exit(${String(exitCode)});`,
    );
const hangingLane = (name: string, limitMilliseconds?: number): Lane =>
    nodeLane(name, 'setTimeout(() => {}, 120_000);', limitMilliseconds);

const runGraph = async (graph: CheckGraph, continuousIntegration = false) => {
    const temporaryDirectoryPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-run-check-'),
    );
    try {
        const runLog = await createLocalRunLog({
            commandLineArguments: [],
            lanes: [],
            rootDirectoryPath: path.join(temporaryDirectoryPath, 'logs'),
            scriptName: 'check graph',
        });
        const stepSummaryPath = path.join(
            temporaryDirectoryPath,
            'step-summary.md',
        );
        let output = '';
        const outcome = await runCheckGraph(graph, {
            continuousIntegration,
            runLog,
            ...(continuousIntegration ? { stepSummaryPath } : {}),
            write: (text) => {
                output += text;
            },
        });
        await runLog.finish({ exitCode: outcome.exitCode });
        return {
            ...outcome,
            output,
            runSummary: JSON.parse(
                await readFile(
                    path.join(runLog.runDirectoryPath, 'summary.json'),
                    'utf8',
                ),
            ) as { readonly failedCommandId?: string },
            stepSummary: continuousIntegration
                ? await readFile(stepSummaryPath, 'utf8')
                : undefined,
        };
    } finally {
        await rm(temporaryDirectoryPath, { force: true, recursive: true });
    }
};

const statuses = (results: readonly { name: string; status: string }[]) =>
    Object.fromEntries(results.map((result) => [result.name, result.status]));

describe('check graph', () => {
    it('stops at the first failed gating lane before the parallel lanes', async () => {
        const outcome = await runGraph({
            gating: [passingLane('Build'), failingLane('Type check', 4)],
            parallel: [passingLane('Lint')],
        });

        expect(outcome.results.map((result) => result.name)).toEqual([
            'Build',
            'Type check',
        ]);
        expect(statuses(outcome.results)).toEqual({
            Build: 'passed',
            'Type check': 'failed',
        });
        expect(outcome.exitCode).toBe(4);
        expect(outcome.output).toContain('Failure detail: Type check');
        expect(outcome.output).toContain('Type check output');
        expect(outcome.output).not.toContain('Lint');
        expect(outcome.runSummary.failedCommandId).toBe('type-check');
    });

    it('stops the running siblings at the first parallel failure and skips the desktop lane', async () => {
        const startedAt = Date.now();
        const outcome = await runGraph({
            desktopBrowser: passingLane('Desktop browser'),
            gating: [],
            parallel: [failingLane('Lint', 3), hangingLane('Node tests')],
        });

        expect(statuses(outcome.results)).toEqual({
            Lint: 'failed',
            'Node tests': 'stopped',
        });
        expect(outcome.exitCode).toBe(3);
        expect(Date.now() - startedAt).toBeLessThan(60_000);
        expect(outcome.output).toContain(
            'Failed: Lint (1 other lane(s) stopped early).',
        );
        expect(outcome.output).not.toContain('Failure detail: Node tests');
        expect(outcome.runSummary.failedCommandId).toBe('lint');
    });

    it('runs the desktop browser lane last, after every other lane passed', async () => {
        const outcome = await runGraph({
            desktopBrowser: passingLane('Desktop browser'),
            gating: [passingLane('Build')],
            parallel: [passingLane('Lint'), passingLane('Rust')],
        });

        expect(outcome.results.map((result) => result.name)).toHaveLength(4);
        expect(outcome.results[0]?.name).toBe('Build');
        expect(outcome.results[3]?.name).toBe('Desktop browser');
        expect(
            outcome.results.every((result) => result.status === 'passed'),
        ).toBe(true);
        expect(outcome.exitCode).toBe(0);
        expect(outcome.output).toContain('All validation lanes passed.');
    });

    it('fails a lane at its limit under continuous integration and reports it', async () => {
        const outcome = await runGraph(
            {
                gating: [],
                parallel: [
                    hangingLane('Rust, fmt: clippy', 1_000),
                    hangingLane('Node tests'),
                ],
            },
            true,
        );

        const timedOut = outcome.results.find(
            (result) => result.name === 'Rust, fmt: clippy',
        );
        expect(timedOut).toMatchObject({ status: 'failed', timedOut: true });
        expect(statuses(outcome.results)['Node tests']).toBe('stopped');
        expect(outcome.exitCode).not.toBe(0);
        expect(outcome.output).toContain(
            '::error title=Rust%2C fmt%3A clippy failed::Exceeded its limit after ',
        );
        expect(outcome.output).toContain(
            '::group::Failure detail: Rust, fmt: clippy\n',
        );
        expect(outcome.output).toContain('::endgroup::\n');
        expect(outcome.stepSummary).toContain(
            '| Rust, fmt: clippy | Failed (limit exceeded) |',
        );
        expect(outcome.stepSummary).toContain('| Node tests | Stopped |');
        expect(outcome.stepSummary).toContain('Failed: Rust, fmt: clippy.');
        expect(outcome.runSummary.failedCommandId).toBe('rust-fmt-clippy');
    });

    it('applies no lane limit outside continuous integration', async () => {
        const outcome = await runGraph({
            gating: [
                nodeLane(
                    'Build',
                    'setTimeout(() => process.exit(0), 1_500);',
                    100,
                ),
            ],
            parallel: [],
        });

        expect(outcome.results).toMatchObject([
            { name: 'Build', status: 'passed', timedOut: false },
        ]);
        expect(outcome.output).not.toContain('::');
    });
});
