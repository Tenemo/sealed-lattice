import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { repositoryRoot } from '#tools/ci/command-line.js';
import { importClosure } from '#tools/ci/import-closure.js';
import { selectProtocolResearchCase } from '#tools/ci/protocol-research-registry.js';
import { rustToolchain } from '#tools/ci/rust-toolchain.js';

type Step = Readonly<{
    run?: string;
    uses?: string;
    with?: Readonly<Record<string, unknown>>;
}>;
type Job = Readonly<{
    needs?: readonly string[];
    steps?: readonly Step[];
    strategy?: Readonly<{ matrix: Readonly<{ case: readonly string[] }> }>;
}>;
type Workflow = Readonly<{
    jobs: Readonly<Record<string, Job>>;
    on: Readonly<
        Record<string, Readonly<{ paths?: readonly string[] }> | null>
    >;
}>;

const readYaml = async <Document>(file: string): Promise<Document> =>
    parse(await readFile(path.join(repositoryRoot, file), 'utf8')) as Document;
const readWorkflow = (name: string) =>
    readYaml<Workflow>(`.github/workflows/${name}.yml`);
const readToolchainAction = () =>
    readYaml<{
        inputs: Readonly<Record<string, Readonly<{ required?: boolean }>>>;
        runs: Readonly<{ steps: readonly Step[] }>;
    }>('.github/actions/rust-toolchain/action.yml');

// GitHub's path filter: the last matching pattern decides, and a leading `!`
// excludes.
const matchesPathFilter = (file: string, patterns: readonly string[]) =>
    patterns.reduce(
        (included, pattern) =>
            pattern.startsWith('!')
                ? included && !path.posix.matchesGlob(file, pattern.slice(1))
                : included || path.posix.matchesGlob(file, pattern),
        false,
    );

describe('workflow policy', () => {
    it('restores the Rust cache before fetching, with each job naming its cache workspaces', async () => {
        const { inputs, runs } = await readToolchainAction();
        const cache = runs.steps.findIndex((step) =>
            step.uses?.startsWith('Swatinem/rust-cache@'),
        );
        const fetch = runs.steps.findIndex((step) =>
            step.run?.startsWith('cargo fetch --locked'),
        );
        expect(cache).toBeGreaterThan(0);
        expect(fetch).toBeGreaterThan(cache);
        expect(inputs['cache-workspaces'].required).toBe(true);
        const steps = (
            await Promise.all(['ci', 'release', 'research'].map(readWorkflow))
        ).flatMap(({ jobs }) =>
            Object.values(jobs).flatMap((job) => job.steps ?? []),
        );
        expect(
            steps.filter((step) =>
                step.uses?.startsWith('Swatinem/rust-cache@'),
            ),
        ).toEqual([]);
        const toolchainSteps = steps.filter(
            (step) => step.uses === './.github/actions/rust-toolchain',
        );
        expect(toolchainSteps.length).toBeGreaterThan(0);
        for (const step of toolchainSteps)
            expect(step.with?.['cache-workspaces']).toEqual(expect.any(String));
    });

    it('installs the toolchain the protocol workspace selects', async () => {
        const toolchain = await readFile(
            path.join(
                repositoryRoot,
                'crates/protocol-research/rust-toolchain.toml',
            ),
            'utf8',
        );
        const channel = /^channel = "(?<channel>[^"]+)"$/mu.exec(toolchain)
            ?.groups?.channel;
        const install = (await readToolchainAction()).runs.steps.find((step) =>
            step.uses?.startsWith('dtolnay/rust-toolchain@'),
        );
        expect(channel).toEqual(expect.any(String));
        expect(install?.with?.toolchain).toBe(channel);
        expect(rustToolchain).toBe(`+${String(channel)}`);
    });

    it('runs every research case on any change to a file the runner imports', async () => {
        const research = await readWorkflow('research');
        const cases = research.jobs.research.strategy?.matrix.case ?? [];
        expect(cases.length).toBeGreaterThan(0);
        for (const entry of cases)
            expect(() =>
                selectProtocolResearchCase(entry.split(' ')),
            ).not.toThrow();
        const paths = research.on.pull_request?.paths ?? [];
        expect(research.on.push?.paths).toEqual(paths);
        const closure = await importClosure([
            'tools/ci/run-protocol-research.ts',
        ]);
        expect(
            closure.filter((file) => !matchesPathFilter(file, paths)),
        ).toEqual([]);
    });

    it('publishes with the pinned Node release and npm and the package the tag job retained', async () => {
        const { jobs } = await readWorkflow('release');
        const steps = jobs['publish-npm'].steps ?? [];
        const setupNode = steps.findIndex((step) =>
            step.uses?.startsWith('actions/setup-node@'),
        );
        const publish = steps.findIndex((step) =>
            step.run?.startsWith('npm publish'),
        );
        const npm = steps.findIndex((step) =>
            /^npm install --global npm@\d+\.\d+\.\d+$/u.test(step.run ?? ''),
        );
        expect(setupNode).toBeGreaterThan(0);
        expect(steps[setupNode].with?.['node-version-file']).toBe('.nvmrc');
        expect(npm).toBeGreaterThan(setupNode);
        expect(publish).toBeGreaterThan(npm);
        const upload = jobs.package.steps?.find((step) =>
            step.uses?.startsWith('actions/upload-artifact@'),
        );
        const download = steps.find((step) =>
            step.uses?.startsWith('actions/download-artifact@'),
        );
        // A re-run of the failed jobs must find the artifact by its name.
        const name = upload?.with?.name;
        expect(name).toEqual(expect.any(String));
        expect(name).not.toContain('run_attempt');
        expect(download?.with?.name).toBe(name);
    });

    it('requires every CI job before the verify status', async () => {
        const { jobs } = await readWorkflow('ci');
        expect([...(jobs.verify.needs ?? [])].sort()).toEqual(
            Object.keys(jobs)
                .filter((name) => name !== 'verify')
                .sort(),
        );
    });
});
