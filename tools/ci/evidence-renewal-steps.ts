import { existsSync } from 'node:fs';
import path from 'node:path';

import { repositoryRoot } from '#tools/ci/command-line.js';
import { selectParticipantBrowserOptions } from '#tools/ci/participant-browser-options.js';
import { selectProtocolResearchCase } from '#tools/ci/protocol-research-registry.js';

// An argument naming the run directory an earlier step created, after an
// optional prefix such as `--foreign-poll=`.
type RunReference = Readonly<{ run: string; prefix?: string }>;

export type EvidenceRenewalStep = Readonly<{
    name: string;
    description: string;
    // A package script run in the renewed checkout, or a repository tool run
    // from this checkout against the renewal's record, and with the renewed
    // checkout when the tool compares it.
    command:
        | Readonly<{
              script: string;
              arguments?: readonly (string | RunReference)[];
          }>
        | Readonly<{
              tool: string;
              checkout?: true;
              requires: readonly string[];
          }>;
    // The script name of the one run the step must create.
    run?: string;
    // The renewal's placement option that holds the step's processes.
    placement?: 'background' | 'timing';
    // A host-contention monitor runs beside the step under its placement.
    monitored?: true;
    // The step prepares the checkout for the others, so every invocation
    // runs it again instead of carrying an earlier record.
    preparesCheckout?: true;
}>;

const participantScript = 'research:participant:built';
const protocolScript = 'research:protocol';

const protocolCase = (
    name: string,
    description: string,
    caseArguments: readonly (string | RunReference)[],
): EvidenceRenewalStep => ({
    name,
    description,
    command: { script: protocolScript, arguments: caseArguments },
    run: protocolScript,
});

// One named lifecycle case, run as a participant cohort. Consecutive cohorts
// alternate between two port ranges, so a cohort never meets the origins of
// the one before it.
const cohort = (
    name: string,
    description: string,
    cohortArguments: readonly (string | RunReference)[],
    options: Pick<EvidenceRenewalStep, 'monitored' | 'placement'> = {},
): EvidenceRenewalStep => ({
    name,
    description,
    command: { script: participantScript, arguments: cohortArguments },
    run: 'research:participant',
    ...options,
});

// The complete named lifecycle matrix, the paired completion-profile
// workloads and the largest departure cohort. The audit names each case by
// its description.
const lifecycleMatrixSteps: readonly EvidenceRenewalStep[] = [
    cohort('recovery', 'Small scalar recovery', [
        '3',
        '2',
        'plain',
        '--scalar',
        '--sequential',
        '--recovery',
        '--top-count=2',
        '--base-port=42380',
    ]),
    cohort(
        'result',
        'Result, hostile inputs, protected ballots, interruptions and state loss',
        ['4', '2', '--scalar', '--base-port=45200'],
    ),
    cohort('no-result', 'Below-turnout no result and cross-poll refusals', [
        '4',
        '2',
        'no-result',
        '--scalar',
        { run: 'result', prefix: '--foreign-poll=' },
        '--base-port=42380',
    ]),
    cohort('empty', 'Empty close', [
        '3',
        '2',
        'empty',
        '--scalar',
        '--base-port=45200',
    ]),
    cohort('rosters', 'Split rosters and cross-roster refusals', [
        '4',
        '2',
        'rosters',
        '--scalar',
        '--base-port=42380',
    ]),
    cohort('setup-departure', 'Combined preparation departures', [
        '7',
        '2',
        '--setup-departure',
        '--scalar',
        '--base-port=45200',
    ]),
    cohort(
        'unselected',
        'Unselected original checkpoint and damaged-state refusal',
        ['4', '2', '--unselected-checkpoint', '--scalar', '--base-port=42380'],
    ),
    cohort('selection', 'Losing endorsement and certified-winner activation', [
        '4',
        '2',
        '--selection-fork',
        '--scalar',
        '--base-port=45200',
    ]),
    cohort(
        'publication',
        'Publication faults, incomplete responses and original-body forwarding',
        [
            '4',
            '2',
            'plain',
            '--publication-faults',
            '--scalar',
            '--base-port=42380',
        ],
    ),
    cohort(
        'preparation',
        'Preparation recovery, source custody and required-state loss',
        ['3', '2', 'preparation', '--scalar', '--base-port=45200'],
    ),
    cohort(
        'combined',
        'Combined preclose departure, omission and postclose organizer departure',
        ['7', '2', '--scalar', '--base-port=42380'],
    ),
    cohort(
        'departures',
        'Every tolerated member departing between roster publication and the target vote',
        ['7', '2', 'plain', '--departures', '--scalar', '--base-port=45200'],
    ),
    cohort(
        'ordinary',
        'Ten-participant ordinary scalar workflow',
        [
            '10',
            '10',
            'plain',
            '--scalar',
            '--sequential',
            '--top-count=10',
            '--base-port=42380',
        ],
        { monitored: true, placement: 'timing' },
    ),
    cohort(
        'completion-recovery',
        'Ten-participant scalar recovery and standalone retrieval',
        [
            '10',
            '10',
            'plain',
            '--scalar',
            '--sequential',
            '--recovery',
            '--top-count=10',
            '--base-port=45200',
        ],
        { monitored: true, placement: 'timing' },
    ),
    cohort(
        'largest-departures',
        'Six of twenty members departing between roster publication and the target vote',
        ['20', '2', 'plain', '--departures', '--scalar', '--base-port=42380'],
        { placement: 'background' },
    ),
];

export const lifecycleMatrixStepNames = lifecycleMatrixSteps.map(
    (step) => step.name,
);

// Every step of an evidence renewal, in the order it runs them.
export const evidenceRenewalSteps: readonly EvidenceRenewalStep[] = [
    {
        name: 'build',
        description: 'Build the workspace packages',
        command: { script: 'build' },
        preparesCheckout: true,
    },
    {
        name: 'rust-fast',
        description: 'Fast Rust tests',
        command: { script: 'test:rust:fast' },
        run: 'test:rust:fast',
    },
    {
        name: 'participant-module',
        description: 'Participant-module Node tests',
        command: { script: 'test:node:participant-module:built' },
    },
    {
        name: 'smoke-pack',
        description: 'Packed-package smoke test',
        command: { script: 'smoke:pack:npm:built' },
        run: 'smoke:pack:npm',
    },
    {
        name: 'reproducible',
        description: 'Reproducible build',
        command: { script: 'build:verify-reproducible' },
        run: 'build:verify-reproducible',
    },
    protocolCase('protocol-check', 'Protocol research build check', ['check']),
    protocolCase('native-result', 'Native result ceremony', [
        'native-result',
        '3',
        '2',
    ]),
    protocolCase('native-empty', 'Native empty ceremony', [
        'native-empty',
        '3',
        '2',
    ]),
    protocolCase('native-invalid-only', 'Native invalid-only ceremony', [
        'native-invalid-only',
        '3',
        '2',
    ]),
    protocolCase('native-requested-output', 'Native requested-output probe', [
        'native-requested-output',
    ]),
    protocolCase('native-setup-departure', 'Native setup departure', [
        'native-setup-departure',
    ]),
    protocolCase('native-selection-fork', 'Native selection fork', [
        'native-selection-fork',
    ]),
    protocolCase('native-fhe-key-source', 'Native FHE key source screen', [
        'native-fhe-key-source',
    ]),
    protocolCase('scalar-fhe-key-source', 'Scalar FHE key source screen', [
        'scalar-fhe-key-source',
        { run: 'native-fhe-key-source' },
    ]),
    protocolCase('browser-fhe-key-source', 'Browser FHE key source screen', [
        'browser-fhe-key-source',
        { run: 'native-fhe-key-source' },
    ]),
    ...lifecycleMatrixSteps,
    {
        name: 'desktop-check',
        description: 'Desktop check',
        command: { script: 'check:desktop' },
        run: 'check:desktop',
    },
    {
        name: 'audit',
        description: 'Lifecycle matrix audit',
        command: {
            tool: 'tools/ci/audit-renewed-lifecycle-matrix.ts',
            checkout: true,
            requires: [...lifecycleMatrixStepNames, 'desktop-check'],
        },
        run: 'audit-renewed-lifecycle-matrix',
    },
    {
        name: 'projection',
        description: 'Desktop-to-phone tolerance projection',
        command: {
            tool: 'tools/ci/project-participant-phone-time.ts',
            requires: ['ordinary'],
        },
        run: 'project-phone-time',
    },
];

const runReferences = (step: EvidenceRenewalStep): readonly RunReference[] =>
    'script' in step.command
        ? (step.command.arguments ?? []).filter(
              (argument): argument is RunReference =>
                  typeof argument !== 'string',
          )
        : [];

// The steps whose records a step needs: those whose runs its arguments name,
// or those a tool reads.
export const requiredSteps = (step: EvidenceRenewalStep): readonly string[] =>
    'tool' in step.command
        ? step.command.requires
        : runReferences(step).map((reference) => reference.run);

// The step's script arguments, with each reference replaced by its run.
export const stepScriptArguments = (
    step: EvidenceRenewalStep,
    runOf: (name: string) => string,
): readonly string[] =>
    'script' in step.command
        ? (step.command.arguments ?? []).map((argument) =>
              typeof argument === 'string'
                  ? argument
                  : (argument.prefix ?? '') + runOf(argument.run),
          )
        : [];

// Refuses a step list whose names, order, references, placements, tools or
// research arguments are inconsistent, listing every problem.
export const validateEvidenceRenewalSteps = (
    steps: readonly EvidenceRenewalStep[],
): void => {
    const problems: string[] =
        steps.length === 0 ? ['The evidence renewal has no steps.'] : [];
    const earlier = new Map<string, EvidenceRenewalStep>();
    for (const step of steps) {
        if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(step.name))
            problems.push(`${step.name}: a step name is kebab-case.`);
        if (earlier.has(step.name))
            problems.push(`${step.name}: the name repeats.`);
        if (
            step.preparesCheckout === true &&
            [...earlier.values()].some(
                (previous) => previous.preparesCheckout !== true,
            )
        )
            problems.push(
                `${step.name}: a step that prepares the checkout precedes every other step.`,
            );
        for (const required of requiredSteps(step))
            if (!earlier.has(required))
                problems.push(
                    `${step.name}: needs ${required}, which does not precede it.`,
                );
        for (const reference of runReferences(step))
            if (
                earlier.has(reference.run) &&
                earlier.get(reference.run)?.run === undefined
            )
                problems.push(
                    `${step.name}: names the run of ${reference.run}, which creates none.`,
                );
        if (step.monitored === true && step.placement !== 'timing')
            problems.push(`${step.name}: only a timing step is monitored.`);
        if (
            'tool' in step.command &&
            !existsSync(path.join(repositoryRoot, step.command.tool))
        )
            problems.push(
                `${step.name}: the tool ${step.command.tool} does not exist.`,
            );
        if ('script' in step.command) {
            const scriptArguments = stepScriptArguments(
                step,
                (name) => `logs/earlier-run/${name}`,
            );
            try {
                if (step.command.script === participantScript)
                    selectParticipantBrowserOptions(scriptArguments);
                if (step.command.script === protocolScript)
                    selectProtocolResearchCase(scriptArguments);
            } catch (error) {
                problems.push(
                    `${step.name}: ${error instanceof Error ? error.message : String(error)}`,
                );
            }
        }
        earlier.set(step.name, step);
    }
    if (problems.length > 0)
        throw new Error(
            `The evidence renewal steps are inconsistent:\n${problems.join('\n')}`,
        );
};
