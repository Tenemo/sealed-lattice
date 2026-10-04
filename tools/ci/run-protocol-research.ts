import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    copyFile,
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
import { setTimeout } from 'node:timers/promises';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import {
    compileBoundedOpeningShareProofResources,
    compileRecoverableSeedSharingProofResources,
} from '#tests/recoverable-setup-resource-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import {
    snapshotResearchSources,
    compiledFixtureFiles,
    checkFixtureSources,
} from '#tools/ci/fixture-sources.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectProtocolResearchCase } from '#tools/ci/protocol-research-registry.js';
import { deriveResearchScenario } from '#tools/ci/protocol-research-scenario.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';
import { runPublicOperatorFixture } from '#tools/ci/run-public-operator-screen.js';
import { runRegistrationSession } from '#tools/ci/run-registration-session.js';
import { runScalarProofFixture } from '#tools/ci/run-seed-sharing-scalar.js';
import {
    assertSeedSharingSourceStable,
    assertSeedSharingSharedInputs,
    compareNativeReferenceArtifacts,
    assertOpeningShareSourceStable,
    readOpeningShareNativeSource,
    fileDigest,
    readSeedSharingNativeSource,
} from '#tools/ci/seed-sharing-scalar-source.js';

type NativeResult = {
    kind: string;
    positive?: number;
    falseWitnesses?: number;
    falseStatements?: number;
    hostileCases?: number;
    participants?: number;
    degree?: number;
    seedBits?: number;
    proofDomain?: number;
    wordColumns?: number;
    booleanColumns?: number;
    lookupEntries?: number;
    affineRows?: number;
    statementBytes?: number;
    proofBytes?: number[] | number;
    selected?: number;
    recipient?: number;
    predecessors?: number;
    sourceIdentities?: string[];
    secondSourceProofBytes?: number;
    shiftedProofBytes?: number;
    accepted?: number[];
    invalid?: number[];
    conflicting?: number[];
    signers?: number[];
    identifiers?: string[];
    releaseSubsets?: number;
    departureSets?: number;
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
    selected.name === 'native-public-operator' ||
    selected.name === 'scalar-public-operator' ||
    selected.name === 'browser-public-operator'
) {
    await runPublicOperatorFixture(
        selected.name === 'native-public-operator'
            ? 'native'
            : selected.name === 'scalar-public-operator'
              ? 'node'
              : 'chrome',
        'source' in selected ? selected.source : undefined,
    );
    process.exit(process.exitCode ?? 0);
}

if ('source' in selected && selected.name !== 'native-opening-share') {
    await runScalarProofFixture(
        selected.source,
        selected.name.startsWith('browser-') ? 'chrome' : 'node',
        selected.name.endsWith('-generation') ? 'generate' : 'verify',
        selected.name.includes('opening-share')
            ? 'opening-share'
            : 'seed-sharing',
    );
    // The selected runner has finished its diagnostics and process cleanup.
    process.exit(process.exitCode ?? 0);
}
const prefixCase = selected.name === 'native-prefix';
const seedSharingCase = selected.name === 'native-seed-sharing';
const openingShareCase = selected.name === 'native-opening-share';
const fragmentCase = seedSharingCase || openingShareCase;
const fragmentPackage = openingShareCase
    ? 'opening-share-proof'
    : 'seed-sharing-proof';
const fragmentBinary = 'check-' + fragmentPackage;
const referenceDirectory =
    'reference' in selected ? selected.reference : undefined;
const seedSharingResources = fragmentCase
    ? compileRecoverableSeedSharingProofResources(
          selected.participantCount,
          selected.optionCount,
          256n,
          4n,
      )
    : undefined;
const openingShareResources = openingShareCase
    ? compileBoundedOpeningShareProofResources()
    : undefined;
// The ceremony's roles and expected outcome for the selected profile.
const scenario = deriveResearchScenario(
    selected.participantCount,
    selected.optionCount,
);
// The requested-output probe's profiles, each with its complete ordering
// and then a shorter prefix.
const prefixProfiles = [
    { participantCount: 3, optionCount: 2, topCounts: [2, 1] },
    { participantCount: 10, optionCount: 10, topCounts: [10, 3] },
    { participantCount: 20, optionCount: 20, topCounts: [20, 1] },
];
const root = path.resolve('.');
const workspace = path.join(root, 'crates/protocol-research');
const memoryLimit = 1_073_741_824;
// Native threads that take the browser module's path with helpers; only
// the runner names their count, so every run records it.
const simulatedHelpersVariable = 'SEALED_LATTICE_SIMULATED_HELPERS';
// The unit tests run alone and then with this many simulated helpers.
const unitSimulatedHelpers = 3;
// The proof crates' unit tests also run with this many, whose proof rows
// hold two residue classes of each coset, which fewer helpers never reach.
const proofSimulatedHelpers = 8;
const proofCrates = [
    'word-proof',
    'registration-proof',
    'ballot-proof',
    'linked-release-proof',
    'contribution-prover',
];
// A native ceremony generates and proves one contribution per participant,
// which dominates its duration.
const executionTimeout =
    prefixCase || fragmentCase
        ? 3_600_000
        : 900_000 * selected.participantCount;

await runWithLocalRunLog(
    {
        commandLineArguments: [
            selected.name,
            ...(openingShareCase
                ? [selected.source]
                : seedSharingCase
                  ? []
                  : [
                        String(selected.participantCount),
                        String(selected.optionCount),
                    ]),
            ...(referenceDirectory === undefined
                ? []
                : ['--compare-reference', referenceDirectory]),
            ...(selected.simulatedHelpers === 0
                ? []
                : ['--simulated-helpers', String(selected.simulatedHelpers)]),
        ],
        lanes: [
            'Pinned protocol research build',
            ...(selected.execution
                ? [
                      fragmentCase
                          ? openingShareCase
                              ? 'Bounded opening-share proof gates'
                              : 'Bounded seed-sharing proof gates'
                          : prefixCase
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
            const openingReference =
                referenceDirectory !== undefined && openingShareCase
                    ? await readOpeningShareNativeSource(
                          referenceDirectory,
                          root,
                      )
                    : undefined;
            const seedReference =
                referenceDirectory !== undefined && !openingShareCase
                    ? await readSeedSharingNativeSource(
                          referenceDirectory,
                          root,
                      )
                    : undefined;
            const reference = openingReference ?? seedReference;
            const predecessor = openingShareCase
                ? await readSeedSharingNativeSource(selected.source, root)
                : undefined;
            for (const [name, source] of [
                ['deterministic-reference', reference],
                ['predecessor', predecessor],
            ] as const) {
                if (source === undefined) continue;
                await writeFile(
                    path.join(log.runDirectoryPath, name + '-inputs.json'),
                    JSON.stringify(
                        {
                            directory: source.directory,
                            diagnosticDigests: source.diagnosticDigests,
                            artifacts:
                                name === 'deterministic-reference' &&
                                openingReference !== undefined
                                    ? openingReference.artifacts
                                    : source.proofs,
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
            }
            const inherited: NodeJS.ProcessEnv = { ...process.env };
            delete inherited[simulatedHelpersVariable];
            const environment: NodeJS.ProcessEnv = {
                ...inherited,
                RUSTFLAGS: '',
                CARGO_TARGET_DIR: path.join(workspace, 'target'),
            };
            const withSimulatedHelpers = (count: number): NodeJS.ProcessEnv =>
                count === 0
                    ? environment
                    : {
                          ...environment,
                          [simulatedHelpersVariable]: String(count),
                      };
            const execute = async (
                command: string,
                args: string[],
                name: string,
                env = environment,
            ) => {
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
                        signal: AbortSignal.timeout(600_000),
                    },
                );
                assert.equal(result.exitCode, 0, name);
                assert.equal(result.terminationSignal, null, name);
                return result.stdout;
            };
            const compiler = await execute(
                'rustc',
                ['+1.95.0', '-Vv'],
                'compiler',
            );
            assert.match(
                compiler,
                /commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860/u,
            );
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
            const registration = compileRegistrationKeyRelationCensus();
            const authentication = compileContributionAuthenticationCensus(
                Number(participants),
            );
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
            // Only the setup contributors publish a contribution body, and
            // the native setup verification keeps each contributor's running
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
                contributors * contribution.maximumBodyBytes +
                participants *
                    (registration.maximumProofBytes +
                        registration.publicKeyBytes +
                        enrollment.maximumHeaderBytes +
                        enrollment.signatureBytes) +
                authentication.allConfirmationPayloadBytes +
                authentication.allOpeningHeaderPayloadBytes +
                authentication.inventoryBodyBytes +
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
            const publicPayloadBound = openingShareResources
                ? openingShareResources.maximumNewArtifactBytes
                : seedSharingResources
                  ? 3n * seedSharingResources.layout.maximumMultiproofBytes
                  : sourceBound +
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
            const diagnosticBound = seedSharingResources
                ? publicPayloadBound
                : publicPayloadBound +
                  contributors * aggregate.aggregateBytes +
                  ballot.maximumProofBytes;
            if (seedSharingResources)
                assert.ok(
                    seedSharingResources.nativeProofPlanningBytes <
                        BigInt(memoryLimit),
                    'The seed-sharing proof planning screen exceeds the memory guard.',
                );
            if (openingShareResources)
                assert.ok(
                    openingShareResources.nativeProofPlanningBytes <
                        BigInt(memoryLimit),
                    'The opening-share proof planning screen exceeds the memory guard.',
                );
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
                        ...(seedSharingResources
                            ? { seedSharingResources }
                            : {}),
                        ...(openingShareResources
                            ? { openingShareResources }
                            : {}),
                        publicPayloadBound: String(publicPayloadBound),
                        diagnosticBound: String(diagnosticBound),
                        copiedPredecessorBytes:
                            predecessor?.proofs.reduce(
                                (sum, proof) => sum + proof.bytes,
                                0,
                            ) ?? 0,
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
                ...(fragmentCase
                    ? [
                          'tools/ci/protocol-research-registry.ts',
                          'tools/ci/seed-sharing-scalar-source.ts',
                          'tools/ci/compiled-inputs.ts',
                          'tests/recoverable-setup-resource-model.ts',
                          'tests/recoverable-opening-share-model.ts',
                      ]
                    : []),
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
            if (fragmentCase) {
                const fixturePackage = ['-p', fragmentPackage];
                await execute(
                    'cargo',
                    ['+1.95.0', 'fmt', ...fixturePackage, '--', '--check'],
                    'format',
                );
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
                        'clippy',
                        '--offline',
                        '--locked',
                        '--no-default-features',
                        ...fixturePackage,
                        '--features',
                        'native-fixture',
                        '--all-targets',
                        '--',
                        '-D',
                        'warnings',
                    ],
                    'clippy',
                );
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
                        'test',
                        '--offline',
                        '--locked',
                        ...fixturePackage,
                        '--lib',
                    ],
                    'unit-verification',
                );
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
                        'build',
                        '--offline',
                        '--locked',
                        '--release',
                        '--no-default-features',
                        ...fixturePackage,
                        '--features',
                        'native-fixture',
                        '--bin',
                        fragmentBinary,
                    ],
                    'build-native',
                );
            } else {
                // Every workspace member.
                await execute(
                    'cargo',
                    ['+1.95.0', 'fmt', '--all', '--', '--check'],
                    'format',
                );
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
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
                        '+1.95.0',
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
                        '+1.95.0',
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
                        '+1.95.0',
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
                    '+1.95.0',
                    'test',
                    '--offline',
                    '--locked',
                    '--workspace',
                    '--lib',
                    '--bins',
                ];
                await execute('cargo', unitTests, 'unit-verification');
                await execute(
                    'cargo',
                    unitTests,
                    'unit-verification-simulated-helpers',
                    withSimulatedHelpers(unitSimulatedHelpers),
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
                );
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
                        'build',
                        '--offline',
                        '--locked',
                        '--release',
                        '--no-default-features',
                        ...['native-ceremony', 'rns-arithmetic-probe'].flatMap(
                            (name) => ['-p', name],
                        ),
                        ...(prefixCase
                            ? [
                                  '--features',
                                  'rns-arithmetic-probe/numerical-probes',
                              ]
                            : []),
                        '--bins',
                    ],
                    'build-native',
                );
            }
            let compiledInputs: {
                file: string;
                sha512: string;
                bytes: number;
            }[] = [];
            let sharedInputs: string[] = [];
            if (fragmentCase) {
                const files = await compiledFixtureFiles(
                    path.join(
                        workspace,
                        'target/release/' + fragmentBinary + '.d',
                    ),
                    sources,
                );
                compiledInputs = await checkFixtureSources(
                    root,
                    sources,
                    files,
                );
                sharedInputs = files.filter(
                    (file) =>
                        !file.startsWith(
                            'crates/protocol-research/opening-share-proof/',
                        ),
                );
                if (predecessor !== undefined)
                    await assertSeedSharingSharedInputs(
                        predecessor,
                        sharedInputs,
                        compiler,
                        root,
                    );
            }
            const executable = path.join(
                workspace,
                'target/release/' +
                    (fragmentCase
                        ? fragmentBinary
                        : prefixCase
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
            const predecessorDirectory =
                predecessor === undefined
                    ? undefined
                    : path.join(
                          log.artifactDirectoryPath,
                          'seed-sharing-predecessors',
                      );
            if (
                predecessor !== undefined &&
                predecessorDirectory !== undefined
            ) {
                await mkdir(predecessorDirectory);
                for (const proof of predecessor.proofs) {
                    const file = path.join(predecessorDirectory, proof.name);
                    await copyFile(proof.file, file);
                    assert.equal(
                        await fileDigest(file),
                        proof.sha512,
                        'A predecessor proof changed while it was copied.',
                    );
                    assert.equal((await stat(file)).size, proof.bytes);
                }
            }
            const scratch =
                prefixCase || fragmentCase
                    ? undefined
                    : await mkdtemp(path.join(root, 'temp/protocol-research-'));
            const output = path.join(
                log.artifactDirectoryPath,
                fragmentCase
                    ? openingShareCase
                        ? 'opening-share'
                        : 'seed-sharing'
                    : prefixCase
                      ? 'requested-output'
                      : 'ceremony',
            );
            if (fragmentCase) await mkdir(output);
            const controller = new AbortController();
            let seedSharingOutput = '';
            let active = false,
                monitor: Promise<void> | undefined,
                peakMemory = 0,
                samples = 0;
            const started = performance.now();
            let exitCode: number;
            try {
                exitCode = await runCommandsInSeries(
                    [
                        {
                            command: executable,
                            args: openingShareCase
                                ? [predecessorDirectory!, output]
                                : prefixCase || seedSharingCase
                                  ? [output]
                                  : [
                                        output,
                                        runtimeFile,
                                        scratch!,
                                        String(selected.participantCount),
                                        String(selected.optionCount),
                                        ...(selected.name ===
                                        'native-invalid-only'
                                            ? ['invalid-only']
                                            : selected.noResult
                                              ? ['empty']
                                              : []),
                                    ],
                            env: withSimulatedHelpers(
                                selected.simulatedHelpers,
                            ),
                            description: fragmentCase
                                ? openingShareCase
                                    ? 'Verify predecessors and prove bounded opening shares'
                                    : 'Prove and reject bounded seed-sharing statements'
                                : prefixCase
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
                            onCommandOutput({ chunk, streamName }) {
                                if (!fragmentCase || streamName !== 'stdout')
                                    return;
                                seedSharingOutput += chunk;
                                if (seedSharingOutput.length > 1_048_576)
                                    controller.abort(
                                        new Error(
                                            'Proof fixture diagnostic output exceeds its bound.',
                                        ),
                                    );
                            },
                            onCommandStart({ processIdentifier }) {
                                assert.ok(processIdentifier);
                                active = true;
                                monitor = (async () => {
                                    while (active) {
                                        const bytes =
                                            await readProtocolProcessTree(
                                                processIdentifier,
                                            );
                                        if (bytes !== undefined) {
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
                                            if (bytes > memoryLimit)
                                                throw new Error(
                                                    'Protocol process-tree memory guard exceeded.',
                                                );
                                        }
                                        if (active) await setTimeout(1000);
                                    }
                                })().catch((error: unknown) => {
                                    controller.abort(error);
                                });
                            },
                            onCommandExit() {
                                active = false;
                            },
                        },
                    },
                );
            } finally {
                active = false;
                await monitor;
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
                fragmentCase
                    ? seedSharingOutput.trim().split(/\r?\n/u).pop()!
                    : await readFile(
                          path.join(
                              output,
                              prefixCase
                                  ? 'result.json'
                                  : 'completion/result.json',
                          ),
                          'utf8',
                      ),
            ) as NativeResult;
            const proofArtifacts: {
                name: string;
                bytes: number;
                sha512: string;
            }[] = [];
            const statementArtifacts: {
                name: string;
                bytes: number;
                sha512: string;
            }[] = [];
            if (seedSharingCase && seedSharingResources) {
                assert.equal(result.kind, 'seed-sharing-proof-fragment');
                assert.equal(result.positive, 1);
                assert.equal(result.falseWitnesses, 1);
                assert.equal(result.falseStatements, 1);
                assert.equal(result.participants, selected.participantCount);
                assert.equal(
                    result.degree,
                    Number(seedSharingResources.polynomialDegree),
                );
                assert.equal(
                    result.seedBits,
                    Number(seedSharingResources.seedBits),
                );
                assert.equal(
                    result.proofDomain,
                    Number(seedSharingResources.verificationDomainSize),
                );
                assert.equal(result.hostileCases, 14);
                assert.equal(
                    result.wordColumns,
                    seedSharingResources.relation.wordColumns,
                );
                assert.equal(
                    result.booleanColumns,
                    seedSharingResources.relation.booleanColumns,
                );
                assert.equal(
                    result.affineRows,
                    Number(seedSharingResources.relation.affineRows),
                );
                assert.ok(Array.isArray(result.proofBytes));
                assert.equal(result.proofBytes.length, 3);
                const proofFiles = [
                    'proof-honest.bin',
                    'proof-false-seed.bin',
                    'proof-false-share.bin',
                ];
                assert.deepEqual(
                    (await readdir(output)).sort(),
                    [...proofFiles].sort(),
                );
                for (const [index, name] of proofFiles.entries()) {
                    const bytes = (await stat(path.join(output, name))).size;
                    assert.ok(
                        bytes > 0 &&
                            BigInt(bytes) <=
                                seedSharingResources.layout
                                    .maximumMultiproofBytes,
                    );
                    assert.equal(result.proofBytes[index], bytes);
                    proofArtifacts.push({
                        name,
                        bytes,
                        sha512: await fileDigest(path.join(output, name)),
                    });
                }
            } else if (openingShareResources) {
                const { seed, opening } = openingShareResources;
                assert.equal(result.kind, 'bounded-opening-share-proof');
                assert.equal(result.positive, 1);
                assert.equal(result.falseStatements, 1);
                assert.equal(result.hostileCases, 10);
                assert.equal(result.participants, selected.participantCount);
                assert.equal(result.degree, Number(opening.physicalDegree));
                assert.equal(result.selected, opening.parameters.selectedCount);
                assert.equal(result.recipient, 2);
                assert.equal(
                    result.predecessors,
                    opening.parameters.selectedCount,
                );
                assert.equal(
                    result.proofDomain,
                    Number(seed.verificationDomainSize),
                );
                assert.equal(result.wordColumns, opening.wordColumns);
                assert.equal(result.booleanColumns, opening.booleanColumns);
                assert.equal(result.lookupEntries, opening.lookupEntries);
                assert.equal(result.affineRows, Number(opening.affineRows));
                assert.equal(
                    result.statementBytes,
                    Number(openingShareResources.openingStatementBytes),
                );
                assert.ok(Array.isArray(result.sourceIdentities));
                assert.equal(
                    result.sourceIdentities.length,
                    opening.parameters.selectedCount,
                );
                assert.equal(
                    new Set(result.sourceIdentities).size,
                    opening.parameters.selectedCount,
                );
                for (const identity of result.sourceIdentities)
                    assert.match(identity, /^[0-9a-f]{128}$/u);
                const proofFiles = [
                    [
                        'proof-second-source.bin',
                        result.secondSourceProofBytes,
                        seed.layout.headerBytes,
                        seed.layout.maximumMultiproofBytes,
                    ],
                    [
                        'proof-opening-honest.bin',
                        result.proofBytes,
                        opening.layout.headerBytes,
                        opening.layout.maximumMultiproofBytes,
                    ],
                    [
                        'proof-opening-shifted.bin',
                        result.shiftedProofBytes,
                        opening.layout.headerBytes,
                        opening.layout.maximumMultiproofBytes,
                    ],
                ] as const;
                const statementFiles = [
                    [
                        'statement-second-source.bin',
                        openingShareResources.seedStatementBytes,
                    ],
                    [
                        'statement-opening-honest.bin',
                        openingShareResources.openingStatementBytes,
                    ],
                    [
                        'statement-opening-shifted.bin',
                        openingShareResources.openingStatementBytes,
                    ],
                ] as const;
                assert.deepEqual(
                    (await readdir(output)).sort(),
                    [
                        ...proofFiles.map(([name]) => name),
                        ...statementFiles.map(([name]) => name),
                    ].sort(),
                );
                for (const [name, declared, header, maximum] of proofFiles) {
                    const file = path.join(output, name);
                    const bytes = (await stat(file)).size;
                    assert.ok(
                        BigInt(bytes) > header && BigInt(bytes) <= maximum,
                    );
                    assert.equal(bytes, declared);
                    proofArtifacts.push({
                        name,
                        bytes,
                        sha512: await fileDigest(file),
                    });
                }
                for (const [name, expected] of statementFiles) {
                    const file = path.join(output, name);
                    const bytes = (await stat(file)).size;
                    assert.equal(BigInt(bytes), expected);
                    statementArtifacts.push({
                        name,
                        bytes,
                        sha512: await fileDigest(file),
                    });
                }
            } else if (prefixCase) {
                assert.equal(result.kind, 'requested-output');
                assert.ok(result.cases);
                const cases = result.cases.map((value) => value.result);
                assert.deepEqual(
                    cases.map((value) => [
                        value.participants,
                        value.options,
                        value.topCount,
                    ]),
                    prefixProfiles.flatMap((value) =>
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
                for (
                    let position = 0;
                    position < Number(participants);
                    position++
                ) {
                    const bytes = BigInt(
                        (
                            await stat(
                                path.join(
                                    records,
                                    'response-' + position + '.bin',
                                ),
                            )
                        ).size,
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
            if (!prefixCase && !fragmentCase && !selected.noResult) {
                // The reference ranking of the accepted ballots; ties go to
                // the lower option position.
                assert.deepEqual(result.identifiers, scenario.identifiers);
                assert.equal(result.releaseSubsets, scenario.releaseSubsets);
                assert.equal(result.departureSets, scenario.departureSets);
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
                    (prefixCase ? 16_384n : diagnosticBound),
            );
            const deterministicReference =
                reference === undefined
                    ? undefined
                    : {
                          directory: reference.directory,
                          diagnosticDigests: reference.diagnosticDigests,
                          artifacts: await compareNativeReferenceArtifacts(
                              openingReference?.artifacts ?? reference.proofs,
                              output,
                          ),
                      };
            if (openingReference !== undefined)
                await assertOpeningShareSourceStable(openingReference, root);
            if (seedReference !== undefined)
                await assertSeedSharingSourceStable(seedReference, root);
            if (
                predecessor !== undefined &&
                predecessorDirectory !== undefined
            ) {
                await assertSeedSharingSourceStable(predecessor, root);
                for (const proof of predecessor.proofs)
                    assert.equal(
                        await fileDigest(
                            path.join(predecessorDirectory, proof.name),
                        ),
                        proof.sha512,
                        'A pinned predecessor changed during execution.',
                    );
            }
            for (const file of compiledInputs)
                assert.equal(
                    await fileDigest(path.join(root, file.file)),
                    file.sha512,
                    'A compiled source changed during execution: ' + file.file,
                );
            if (fragmentCase)
                assert.equal(
                    await fileDigest(executable),
                    runtime.toString('hex'),
                    'The native executable changed during execution.',
                );
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        case: selected.name,
                        participantCount: selected.participantCount,
                        optionCount: selected.optionCount,
                        simulatedHelpers: selected.simulatedHelpers,
                        ...(fragmentCase ? {} : { unitSimulatedHelpers }),
                        output,
                        runtimeIdentity: runtime.toString('hex'),
                        result,
                        ...(fragmentCase ? { proofArtifacts } : {}),
                        ...(openingShareCase ? { statementArtifacts } : {}),
                        ...(deterministicReference === undefined
                            ? {}
                            : { deterministicReference }),
                        ...(fragmentCase ? { compiledInputs } : {}),
                        ...(predecessor === undefined
                            ? {}
                            : {
                                  predecessor: {
                                      directory: predecessor.directory,
                                      diagnosticDigests:
                                          predecessor.diagnosticDigests,
                                      proofs: predecessor.proofs,
                                      sharedInputs,
                                  },
                              }),
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
                        scope: openingShareCase
                            ? 'Reduced public opening-share relation for one fixed recipient and two distinct verified seed-sharing records. The native fixture verifies its original outer predecessor, generates and verifies the second, then accepts the honest batched opening and rejects a fresh proof of an unsatisfiable shifted share. Exact source statements and proof bytes are retained. The externally fixed selection descriptor creates no broadcast decision, registered-key capability, disclosure authorization, sealed-body acceptance, participant state or complete recovery protocol.'
                            : seedSharingCase
                              ? 'Reduced seed-sharing relation over a 256-coefficient physical ring and four synthetic seed bits with the unchanged word-proof domain and four-recipient profile. Real proof generation and verification cover one valid case, one false supplied seed witness and one provably unsatisfiable ciphertext statement. Both fresh negative proofs must fail the relation check. This creates no setup capability, distributed recovery, participant state or terminal, and establishes no complete protocol security or browser qualification.'
                              : prefixCase
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
