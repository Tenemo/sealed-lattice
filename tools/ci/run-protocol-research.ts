import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
    stat,
    writeFile,
} from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileClearPreparationResources } from '#tests/clear-preparation-resource-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/command-runner.js';
import { snapshotResearchSources } from '#tools/ci/fixture-sources.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { guardProcessTreeMemory } from '#tools/ci/process-tree-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectProtocolResearchCase } from '#tools/ci/protocol-research-registry.js';
import { deriveResearchScenario } from '#tools/ci/protocol-research-scenario.js';
import { runFheKeySourceScreen } from '#tools/ci/run-fhe-key-source-screen.js';
import { runRegistrationSession } from '#tools/ci/run-registration-session.js';
import {
    rustCompilerCommit,
    rustToolchain,
    workspaceCargoEnvironment,
} from '#tools/ci/rust-toolchain.js';

type NativeResult = {
    kind: string;
    accepted?: number[];
    invalid?: number[];
    conflicting?: number[];
    signers?: number[];
    identifiers?: string[];
    releaseSubsets?: number;
    departureSets?: number;
    departed?: number[];
    corrupt?: number[];
    selectedAuthors?: number[];
    cases?: {
        milliseconds: number;
        result: {
            participants: number;
            options: number;
            topCount: number;
            inputIdentity: string;
            optionPositions: number[];
        };
    }[];
};
const selected = selectProtocolResearchCase(process.argv.slice(2));
if (selected.name === 'registration-session') {
    await runRegistrationSession();
    process.exit(process.exitCode ?? 0);
}
if (
    selected.name === 'native-fhe-key-source' ||
    selected.name === 'scalar-fhe-key-source' ||
    selected.name === 'browser-fhe-key-source'
) {
    await runFheKeySourceScreen(
        selected.name.startsWith('native-')
            ? 'native'
            : selected.name.startsWith('scalar-')
              ? 'scalar'
              : 'browser',
        'source' in selected ? selected.source : undefined,
    );
    process.exit(process.exitCode ?? 0);
}

const requestedOutputCase = selected.name === 'native-requested-output';
// The ceremony's roles and expected outcome for the selected profile.
const scenario = deriveResearchScenario(
    selected.participantCount,
    selected.optionCount,
    selected.name === 'native-setup-departure',
    selected.name === 'native-selection-fork',
);
// The requested-output probe's profiles, each with its complete ordering
// and then a shorter prefix.
const requestedOutputProfiles = [
    { participantCount: 3, optionCount: 2, topCounts: [2, 1] },
    { participantCount: 10, optionCount: 10, topCounts: [10, 3] },
    { participantCount: 20, optionCount: 20, topCounts: [20, 1] },
];
const root = path.resolve('.');
const workspace = path.join(root, 'crates/protocol-research');
const memoryLimit = 1_073_741_824;
// Every build, lint and test step finishes within this bound, except a cold
// compile of the unit-test binaries, which has its own.
const stepTimeoutMilliseconds = 600_000;
const compileTimeoutMilliseconds = 1_800_000;
// The unit tests, with or without simulated helpers, stay below this
// process-tree memory, which leaves room above their recorded peaks for
// slower hosts.
const unitTestMemoryLimit = 2_147_483_648;
// Native threads that take the browser module's path with helpers; only
// the runner names their count, so every run records it.
const simulatedHelpersVariable = 'SEALED_LATTICE_SIMULATED_HELPERS';
// The unit tests run alone and then with this many simulated helpers.
const unitSimulatedHelpers = 3;
// The proof crates' unit tests also run with this many, whose proof rows
// hold two residue classes of each coset, which fewer helpers never reach.
const proofSimulatedHelpers = 8;
const proofCrates = ['word-proof', 'ballot-proof', 'linked-release-proof'];
// A native ceremony generates and proves one contribution per participant,
// which dominates its duration.
const executionTimeout = requestedOutputCase
    ? 3_600_000
    : 900_000 * selected.participantCount;

await runWithLocalRunLog(
    {
        commandLineArguments: [
            selected.name,
            ...(selected.name === 'native-setup-departure' ||
            selected.name === 'native-selection-fork'
                ? []
                : [
                      String(selected.participantCount),
                      String(selected.optionCount),
                  ]),
            ...(selected.simulatedHelpers === 0
                ? []
                : ['--simulated-helpers', String(selected.simulatedHelpers)]),
        ],
        lanes: [
            'Pinned protocol research build',
            ...(selected.execution
                ? [
                      requestedOutputCase
                          ? 'Encrypted requested-output gates'
                          : 'Native original-credential completion',
                  ]
                : []),
        ],
        scriptName: 'research:protocol',
    },
    async (log) => {
        const releaseLock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            root,
        );
        try {
            const inherited: NodeJS.ProcessEnv = { ...process.env };
            delete inherited[simulatedHelpersVariable];
            const environment = workspaceCargoEnvironment(workspace, inherited);
            const withSimulatedHelpers = (count: number): NodeJS.ProcessEnv =>
                count === 0
                    ? environment
                    : {
                          ...environment,
                          [simulatedHelpersVariable]: String(count),
                      };
            // A step runs for at most its timeout. A guarded step also records
            // its process tree's memory every second and stops at the limit.
            const execute = async (
                command: string,
                args: string[],
                name: string,
                env = environment,
                {
                    timeoutMilliseconds = stepTimeoutMilliseconds,
                    guardedMemoryLimit,
                }: {
                    timeoutMilliseconds?: number;
                    guardedMemoryLimit?: number;
                } = {},
            ) => {
                const controller = new AbortController();
                let guard: { stop: () => Promise<void> } | undefined;
                try {
                    const result = await runCommandAndCaptureOutput(
                        {
                            command,
                            args,
                            env,
                            workingDirectoryPath: workspace,
                            description: name,
                            logFileSlug: name,
                        },
                        {
                            runLog: log,
                            echoOutput: true,
                            signal: AbortSignal.any([
                                controller.signal,
                                AbortSignal.timeout(timeoutMilliseconds),
                            ]),
                            onCommandStart: ({ processIdentifier }) => {
                                if (guardedMemoryLimit === undefined) return;
                                assert.ok(processIdentifier);
                                guard = guardProcessTreeMemory({
                                    processIdentifier,
                                    memoryLimit: guardedMemoryLimit,
                                    exceededMessage:
                                        'Unit-test process-tree memory guard exceeded.',
                                    onSample: (bytes) => {
                                        log.writeEvent({
                                            eventType:
                                                'unit-test-process-memory',
                                            details: {
                                                step: name,
                                                bytes,
                                                memoryLimit: guardedMemoryLimit,
                                            },
                                        });
                                    },
                                    abort: (reason) => {
                                        controller.abort(reason);
                                    },
                                });
                            },
                        },
                    );
                    assert.equal(
                        controller.signal.aborted,
                        false,
                        String(controller.signal.reason),
                    );
                    assert.equal(result.exitCode, 0, name);
                    assert.equal(result.terminationSignal, null, name);
                    return result.stdout;
                } finally {
                    await guard?.stop();
                }
            };
            const compiler = await execute(
                'rustc',
                [rustToolchain, '-Vv'],
                'compiler',
            );
            assert.ok(compiler.includes('commit-hash: ' + rustCompilerCommit));
            // The research crates implement every supported profile; the
            // native ceremony runs the selected one.
            const profile = deriveSupportedProfile(
                selected.participantCount,
                selected.optionCount,
            );
            const contribution = compileContributionBodyCensus(profile);
            const aggregate = compileSetupAggregateResources(profile);
            const enrollment = compileRegistrationEnrollmentCensus();
            const ballot = compileBallotBodyCensus(profile);
            const participants = BigInt(contribution.participantCount);
            const contributors = BigInt(contribution.setupContributorCount);
            const registration = compileRecipientKeyCensus();
            const preparation = compileClearPreparationResources(profile);
            const roster = compileRosterProposalCensus(Number(participants));
            const close = compileCloseWireCensus(profile);
            const release = compileLinkedReleaseWordProofLayout(profile);
            const degree = fixedModulusBfvInputs.polynomialDegree;
            const coefficientBytes =
                1n +
                BigInt(
                    Math.ceil(profile.release.modulus.toString(2).length / 8),
                );
            const releaseBody =
                12n +
                198n +
                degree * coefficientBytes +
                release.maximumMultiproofBytes;
            // Eligible authors may publish a contribution body, and
            // native setup verification keeps each selected author's running
            // aggregate. The native close records every response, the late
            // control response and an index line of at most 128 bytes per
            // stored submission.
            const closeRecordBound =
                close.maximumRosterCloseMetadataBytes +
                close.maximumResponsePacketBytes +
                128n * close.maximumRosterListedEnvelopes +
                4096n;
            const sourceBound =
                closeRecordBound +
                preparation.maximumEligibleOfferBytes +
                participants *
                    (registration.publicKeyBytes +
                        enrollment.maximumHeaderBytes +
                        enrollment.signatureBytes) +
                preparation.selectionProposalBytes +
                (selected.name === 'native-selection-fork'
                    ? preparation.selectionProposalBytes +
                      preparation.quorumEndorsementPacketBytes
                    : 0n) +
                preparation.maximumEndorsementPacketBytes +
                2n * preparation.certificateBytes +
                64n * BigInt(preparation.eligibleCount) +
                enrollment.maximumPollDefinitionBytes +
                2n * enrollment.signatureBytes +
                roster.proposalBytes +
                128n +
                64n +
                2n * ballot.maximumSignedBodyBytes +
                64n +
                enrollment.signingPublicKeyBytes +
                ballot.envelopeBytes +
                enrollment.signatureBytes +
                BigInt(scenario.accepted.length + scenario.omitted.length - 1) *
                    (ballot.maximumSignedBodyBytes +
                        ballot.envelopeBytes +
                        enrollment.signatureBytes);
            const publicPayloadBound =
                sourceBound +
                2048n +
                2n * degree * coefficientBytes +
                participants *
                    (2n +
                        64n +
                        enrollment.signatureBytes +
                        releaseBody +
                        270n +
                        enrollment.signatureBytes) +
                enrollment.maximumPollDefinitionBytes;
            const diagnosticBound =
                publicPayloadBound +
                contributors *
                    aggregate.aggregateBytes *
                    (selected.name === 'native-selection-fork' ? 2n : 1n) +
                ballot.maximumProofBytes;
            assert.equal(participants, BigInt(selected.participantCount));
            assert.ok(
                freemem() >= 2 * memoryLimit,
                'Insufficient host memory before research execution.',
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'resource-inputs.json'),
                JSON.stringify(
                    {
                        participantCount: selected.participantCount,
                        optionCount: selected.optionCount,
                        publicPayloadBound: String(publicPayloadBound),
                        diagnosticBound: String(diagnosticBound),
                        memoryLimit,
                        memoryKind:
                            process.platform === 'win32'
                                ? 'process-tree private bytes'
                                : 'process-tree resident bytes',
                        unmeasured: {
                            physicalStorage: null,
                            participantVisits: null,
                            networkTransfers: null,
                            recoveryWork: null,
                        },
                    },
                    (_key, value: unknown) =>
                        typeof value === 'bigint' ? String(value) : value,
                ) + '\n',
                { flag: 'wx' },
            );
            const sources = await snapshotResearchSources(log, root, [
                'tools/ci/fixture-sources.ts',
            ]);
            await writeFile(
                path.join(log.runDirectoryPath, 'source-manifest.json'),
                JSON.stringify({ compiler, sources }, null, 2) + '\n',
                { flag: 'wx' },
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'runner.ts'),
                await readFile(import.meta.filename),
                { flag: 'wx' },
            );
            // Every workspace member.
            await execute(
                'cargo',
                [rustToolchain, 'fmt', '--all', '--', '--check'],
                'format',
            );
            await execute(
                'cargo',
                [
                    rustToolchain,
                    'clippy',
                    '--offline',
                    '--locked',
                    '--no-default-features',
                    '--workspace',
                    '--all-targets',
                    '--',
                    '-D',
                    'warnings',
                ],
                'clippy',
            );
            // The numerical probes decrypt synthetic test ciphertexts, so only
            // their explicit feature compiles them; lint that build as well.
            await execute(
                'cargo',
                [
                    rustToolchain,
                    'clippy',
                    '--offline',
                    '--locked',
                    '--no-default-features',
                    '-p',
                    'rns-arithmetic-probe',
                    '--features',
                    'numerical-probes',
                    '--all-targets',
                    '--',
                    '-D',
                    'warnings',
                ],
                'clippy-numerical-probes',
            );
            // A corrupt participant's browser module signs false ballot
            // statements only under its explicit feature; lint that build.
            await execute(
                'cargo',
                [
                    rustToolchain,
                    'clippy',
                    '--offline',
                    '--locked',
                    '--target',
                    'wasm32-unknown-unknown',
                    '-p',
                    'registration-enrollment',
                    '--features',
                    'invalid-ballot',
                    '--lib',
                    '--',
                    '-D',
                    'warnings',
                ],
                'clippy-invalid-ballot',
            );
            // The participant module is a wasm32 cdylib whose host supplies
            // randomness, so its dependency graph must build there without an
            // operating-system generator.
            await execute(
                'cargo',
                [
                    rustToolchain,
                    'check',
                    '--offline',
                    '--locked',
                    '--target',
                    'wasm32-unknown-unknown',
                    '-p',
                    'registration-enrollment',
                    '--lib',
                ],
                'browser-target',
            );
            // Unit tests of every member, including the ceremony's
            // profile-derived roles, alone and then with every job on a
            // simulated helper.
            const unitTests = [
                rustToolchain,
                'test',
                '--offline',
                '--locked',
                '--workspace',
                '--lib',
                '--bins',
            ];
            // Compiling the test binaries is not part of a test step, so a
            // cold build has its own longer bound and the guarded steps
            // measure only the tests.
            await execute(
                'cargo',
                [...unitTests, '--no-run'],
                'unit-verification-build',
                environment,
                { timeoutMilliseconds: compileTimeoutMilliseconds },
            );
            await execute(
                'cargo',
                unitTests,
                'unit-verification',
                environment,
                {
                    guardedMemoryLimit: unitTestMemoryLimit,
                },
            );
            await execute(
                'cargo',
                unitTests,
                'unit-verification-simulated-helpers',
                withSimulatedHelpers(unitSimulatedHelpers),
                { guardedMemoryLimit: unitTestMemoryLimit },
            );
            await execute(
                'cargo',
                [
                    ...unitTests.filter(
                        (argument) => argument !== '--workspace',
                    ),
                    ...proofCrates.flatMap((name) => ['-p', name]),
                ],
                'unit-verification-proof-helpers',
                withSimulatedHelpers(proofSimulatedHelpers),
                { guardedMemoryLimit: unitTestMemoryLimit },
            );
            await execute(
                'cargo',
                [
                    rustToolchain,
                    'build',
                    '--offline',
                    '--locked',
                    '--release',
                    '--no-default-features',
                    ...['native-ceremony', 'rns-arithmetic-probe'].flatMap(
                        (name) => ['-p', name],
                    ),
                    ...(requestedOutputCase
                        ? [
                              '--features',
                              'rns-arithmetic-probe/numerical-probes',
                          ]
                        : []),
                    '--bins',
                ],
                'build-native',
            );
            const executable = path.join(
                workspace,
                'target/release/' +
                    (requestedOutputCase
                        ? 'check-requested-output'
                        : 'native-ceremony') +
                    (process.platform === 'win32' ? '.exe' : ''),
            );
            const runtime = createHash('sha512')
                .update(await readFile(executable))
                .digest();
            if (!selected.execution) {
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify({
                        case: selected.name,
                        executableSha512: runtime.toString('hex'),
                        unitSimulatedHelpers,
                        unmeasured: {
                            completion: null,
                            peakMemory: null,
                            storage: null,
                            transfers: null,
                            recovery: null,
                        },
                    }) + '\n',
                    { flag: 'wx' },
                );
                return;
            }
            // The runtime identity file and the executable's records are the
            // run's artifacts.
            await mkdir(log.artifactDirectoryPath, { recursive: true });
            const runtimeFile = path.join(
                log.artifactDirectoryPath,
                'runtime.bin',
            );
            await writeFile(runtimeFile, runtime, { flag: 'wx' });
            const scratch = requestedOutputCase
                ? undefined
                : await mkdtemp(path.join(root, 'temp/protocol-research-'));
            const output = path.join(
                log.artifactDirectoryPath,
                requestedOutputCase ? 'requested-output' : 'ceremony',
            );
            const controller = new AbortController();
            let guard: { stop: () => Promise<void> } | undefined,
                peakMemory = 0,
                samples = 0;
            const started = performance.now();
            let exitCode: number;
            try {
                exitCode = await runCommandsInSeries(
                    [
                        {
                            command: executable,
                            args: requestedOutputCase
                                ? [output]
                                : [
                                      output,
                                      runtimeFile,
                                      scratch!,
                                      String(selected.participantCount),
                                      String(selected.optionCount),
                                      ...(selected.name ===
                                      'native-selection-fork'
                                          ? ['selection-fork']
                                          : selected.name ===
                                              'native-setup-departure'
                                            ? ['setup-departure']
                                            : selected.name ===
                                                'native-invalid-only'
                                              ? ['invalid-only']
                                              : selected.noResult
                                                ? ['empty']
                                                : []),
                                  ],
                            env: withSimulatedHelpers(
                                selected.simulatedHelpers,
                            ),
                            description: requestedOutputCase
                                ? 'Verify encrypted requested-output coefficients'
                                : 'Execute original credentials through terminal verification',
                            logFileSlug: 'completion',
                        },
                    ],
                    {
                        runLog: log,
                        outputMode: 'inherit',
                        signal: AbortSignal.any([
                            controller.signal,
                            AbortSignal.timeout(executionTimeout),
                        ]),
                        observer: {
                            onCommandStart({ processIdentifier }) {
                                assert.ok(processIdentifier);
                                guard = guardProcessTreeMemory({
                                    processIdentifier,
                                    memoryLimit,
                                    exceededMessage:
                                        'Protocol process-tree memory guard exceeded.',
                                    onSample: (bytes) => {
                                        samples++;
                                        peakMemory = Math.max(
                                            peakMemory,
                                            bytes,
                                        );
                                        log.writeEvent({
                                            eventType:
                                                'protocol-process-memory',
                                            details: { bytes, memoryLimit },
                                        });
                                    },
                                    abort: (reason) => {
                                        controller.abort(reason);
                                    },
                                });
                            },
                            onCommandExit() {
                                void guard?.stop();
                            },
                        },
                    },
                );
            } finally {
                await guard?.stop();
                // The ceremony's working values and key records in its
                // scratch directory outlive no run, whether it passed or not.
                if (scratch !== undefined)
                    await rm(scratch, {
                        recursive: true,
                        maxRetries: 10,
                        retryDelay: 500,
                    });
            }
            assert.equal(
                controller.signal.aborted,
                false,
                String(controller.signal.reason),
            );
            assert.equal(exitCode, 0);
            assert.ok(samples > 0);
            const result = JSON.parse(
                await readFile(
                    path.join(
                        output,
                        requestedOutputCase
                            ? 'result.json'
                            : 'completion/result.json',
                    ),
                    'utf8',
                ),
            ) as NativeResult;
            if (requestedOutputCase) {
                assert.equal(result.kind, 'requested-output');
                assert.ok(result.cases);
                const cases = result.cases.map((value) => value.result);
                assert.deepEqual(
                    cases.map((value) => [
                        value.participants,
                        value.options,
                        value.topCount,
                    ]),
                    requestedOutputProfiles.flatMap((value) =>
                        value.topCounts.map((topCount) => [
                            value.participantCount,
                            value.optionCount,
                            topCount,
                        ]),
                    ),
                );
                // Each shorter prefix decrypts from the same inputs as the
                // complete ordering and lists its leading options.
                for (let index = 0; index < cases.length; index += 2) {
                    const [complete, prefix] = [cases[index], cases[index + 1]];
                    assert.equal(complete.inputIdentity, prefix.inputIdentity);
                    assert.equal(
                        complete.optionPositions.length,
                        complete.options,
                    );
                    assert.deepEqual(
                        [...complete.optionPositions].sort((a, b) => a - b),
                        Array.from(
                            { length: complete.options },
                            (_unused, option) => option,
                        ),
                    );
                    assert.deepEqual(
                        prefix.optionPositions,
                        complete.optionPositions.slice(0, prefix.topCount),
                    );
                }
            } else {
                assert.equal(
                    result.kind,
                    selected.noResult ? 'no-result' : 'result',
                );
                assert.deepEqual(
                    result.accepted,
                    selected.noResult ? [] : scenario.accepted,
                );
                assert.deepEqual(
                    result.invalid,
                    selected.name === 'native-invalid-only'
                        ? [0]
                        : selected.noResult
                          ? []
                          : scenario.invalid,
                );
                assert.deepEqual(
                    result.conflicting,
                    selected.noResult ? [] : scenario.conflicting,
                );
                assert.deepEqual(
                    result.signers,
                    selected.noResult
                        ? Array.from(
                              { length: Number(participants) },
                              (_unused, position) => position,
                          )
                        : scenario.signers,
                );
                // The Rust close messages match the independent wire model.
                const records = path.join(output, 'close');
                assert.equal(
                    BigInt((await stat(path.join(records, 'intent.bin'))).size),
                    close.intentPacketBytes,
                );
                assert.equal(
                    BigInt(
                        (await stat(path.join(records, 'proposal.bin'))).size,
                    ),
                    close.proposalPacketBytes,
                );
                const responseFiles = (await readdir(records)).filter((name) =>
                    /^response-[0-9]+\.bin$/u.test(name),
                );
                assert.deepEqual(
                    responseFiles.sort(),
                    [...scenario.responseFiles].sort(),
                    'The native close response inventory differs from the active original participants.',
                );
                for (const name of scenario.responseFiles) {
                    const bytes = BigInt(
                        (await stat(path.join(records, name))).size,
                    );
                    assert.ok(
                        bytes >=
                            close.minimumResponseBodyBytes +
                                4n +
                                enrollment.signatureBytes &&
                            bytes <= close.maximumResponsePacketBytes,
                    );
                }
            }
            if (!requestedOutputCase && !selected.noResult) {
                // The reference ranking of the accepted ballots; ties go to
                // the lower option position.
                assert.deepEqual(result.identifiers, scenario.identifiers);
                assert.equal(result.releaseSubsets, scenario.releaseSubsets);
                assert.equal(result.departureSets, scenario.departureSets);
                if (
                    selected.name === 'native-setup-departure' ||
                    selected.name === 'native-selection-fork'
                ) {
                    assert.deepEqual(result.departed, scenario.departed);
                    assert.deepEqual(result.corrupt, scenario.corrupt);
                    assert.deepEqual(
                        result.selectedAuthors,
                        scenario.selectedAuthors,
                    );
                    const files = await readdir(output, { recursive: true });
                    const names = files.map((file) =>
                        file.replace(/\\/gu, '/'),
                    );
                    assert.ok(
                        names.includes('participant-1/registration-header.bin'),
                    );
                    for (const name of selected.name ===
                    'native-setup-departure'
                        ? [
                              'contribution-1',
                              'selection-endorsement-1.bin',
                              'close/response-1.bin',
                              'ballot/envelope-1.bin',
                              'completion/target-vote-1.bin',
                              'completion/release-1.bin',
                              'completion/release-envelope-1.bin',
                          ]
                        : ['selection-endorsement-1.bin'])
                        assert.ok(
                            !names.includes(name),
                            'The scenario emitted a forbidden participant record: ' +
                                name,
                        );
                    if (selected.name === 'native-selection-fork') {
                        for (const name of [
                            'losing-selection.bin',
                            'losing-selection-endorsement-1.bin',
                            'ballot/envelope-1.bin',
                            'completion/target-vote-1.bin',
                            'completion/release-1.bin',
                        ])
                            assert.ok(names.includes(name));
                    }
                }
            }
            const countFiles = async (directory: string): Promise<number> => {
                let bytes = 0;
                for (const entry of await readdir(directory, {
                    withFileTypes: true,
                })) {
                    const file = path.join(directory, entry.name);
                    bytes += entry.isDirectory()
                        ? await countFiles(file)
                        : (await stat(file)).size;
                }
                return bytes;
            };
            const publicDiagnosticBytes = await countFiles(output);
            assert.ok(
                BigInt(publicDiagnosticBytes) <=
                    (requestedOutputCase ? 16_384n : diagnosticBound),
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        case: selected.name,
                        participantCount: selected.participantCount,
                        optionCount: selected.optionCount,
                        simulatedHelpers: selected.simulatedHelpers,
                        unitSimulatedHelpers,
                        output,
                        runtimeIdentity: runtime.toString('hex'),
                        result,
                        milliseconds: performance.now() - started,
                        peakMemory,
                        samples,
                        publicDiagnosticBytes,
                        unmeasured: {
                            physicalStorage: null,
                            browserCompletion: null,
                            actualDepartureChronology: null,
                            participantVisits: null,
                            networkTransfers: null,
                            recoveryWork: null,
                        },
                        scope: requestedOutputCase
                            ? 'Real full-degree BFV coefficient-selection operations on deterministic synthetic ciphertexts encrypting known rank powers. A test-only secret decoder checks every plaintext coefficient against direct interpolation, including all omitted ranks and padding. No participant, ballot proof, certificate, release share or terminal is created.'
                            : selected.noResult
                              ? 'Fresh native certified no-result execution using original credentials. No release shares are generated. This is not durable browser participation, security admission or physical qualification.'
                              : 'Fresh native cryptographic execution using tracked sources and original credentials. Subset controls run after share generation. This is not durable browser participation, security admission or physical qualification.',
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            await releaseLock();
        }
    },
);
