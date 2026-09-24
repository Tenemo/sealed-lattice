import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    mkdir,
    mkdtemp,
    readFile,
    readdir,
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
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectProtocolResearchCase } from '#tools/ci/protocol-research-registry.js';
import { deriveResearchScenario } from '#tools/ci/protocol-research-scenario.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';

type NativeResult = {
    kind: string;
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
const prefixCase = selected.name === 'native-prefix';
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
// A native ceremony generates and proves one contribution per participant,
// which dominates its duration.
const executionTimeout = prefixCase
    ? 3_600_000
    : 900_000 * selected.participantCount;

await runWithLocalRunLog(
    {
        commandLineArguments: [
            selected.name,
            String(selected.participantCount),
            String(selected.optionCount),
        ],
        lanes: [
            'Pinned protocol research build',
            ...(selected.execution
                ? [
                      prefixCase
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
            const environment = {
                ...process.env,
                RUSTFLAGS: '',
                CARGO_TARGET_DIR: path.join(workspace, 'target'),
            };
            const execute = async (
                command: string,
                args: string[],
                name: string,
            ) => {
                const result = await runCommandAndCaptureOutput(
                    {
                        command,
                        args,
                        env: environment,
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
            const protoc = await execute(
                process.env.PROTOC ?? 'protoc',
                ['--version'],
                'protobuf-compiler',
            );
            assert.equal(protoc.trim(), 'libprotoc 36.1');
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
            // The native close records every response, the late control
            // response and an index line of at most 128 bytes per archived
            // submission.
            const closeRecordBound =
                close.maximumRosterCloseMetadataBytes +
                close.maximumResponsePacketBytes +
                128n * close.maximumRosterListedEnvelopes +
                4096n;
            const sourceBound =
                closeRecordBound +
                participants *
                    (contribution.maximumBodyBytes +
                        registration.maximumProofBytes +
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
                participants * aggregate.aggregateBytes +
                ballot.maximumProofBytes;
            assert.equal(participants, BigInt(selected.participantCount));
            assert.ok(
                freemem() >= 2 * memoryLimit,
                'Insufficient host memory before research execution.',
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'resource-inputs.json'),
                JSON.stringify({
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
                }) + '\n',
                { flag: 'wx' },
            );
            const sources: { file: string; sha512: string; bytes: number }[] =
                [];
            const snapshot = async (directory: string): Promise<void> => {
                for (const entry of await readdir(directory, {
                    withFileTypes: true,
                })) {
                    if (entry.name === 'target' || entry.name === '.git')
                        continue;
                    const file = path.join(directory, entry.name);
                    if (entry.isDirectory()) {
                        await snapshot(file);
                        continue;
                    }
                    assert.ok(
                        entry.isFile(),
                        'Research sources must be ordinary files.',
                    );
                    const relative = path.relative(root, file);
                    assert.ok(
                        !relative.startsWith('..') &&
                            !path.isAbsolute(relative),
                    );
                    const bytes = await readFile(file),
                        destination = path.join(
                            log.runDirectoryPath,
                            'sources',
                            relative,
                        );
                    await mkdir(path.dirname(destination), { recursive: true });
                    await writeFile(destination, bytes, { flag: 'wx' });
                    sources.push({
                        file: relative,
                        sha512: createHash('sha512')
                            .update(bytes)
                            .digest('hex'),
                        bytes: bytes.length,
                    });
                }
            };
            await snapshot(workspace);
            await snapshot(
                path.join(root, 'crates/sealed-lattice-kernel/src/foundation'),
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'source-manifest.json'),
                JSON.stringify({ compiler, protoc, sources }, null, 2) + '\n',
                { flag: 'wx' },
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'runner.ts'),
                await readFile(import.meta.filename),
                { flag: 'wx' },
            );
            // Every workspace member; the vendored crates are excluded.
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
            // The browser participant and completion modules are wasm32
            // cdylibs whose host supplies randomness, so their dependency
            // graphs must build there without an operating-system generator.
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
                    'evaluation-target',
                    '--features',
                    'browser',
                    '--lib',
                ],
                'browser-completion-target',
            );
            // Unit tests of every member, including the ceremony's
            // profile-derived roles.
            await execute(
                'cargo',
                [
                    '+1.95.0',
                    'test',
                    '--offline',
                    '--locked',
                    '--workspace',
                    '--lib',
                    '--bins',
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
            const executable = path.join(
                workspace,
                'target/release/' +
                    (prefixCase
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
            const runtimeFile = path.join(log.runDirectoryPath, 'runtime.bin');
            await writeFile(runtimeFile, runtime, { flag: 'wx' });
            const scratch = prefixCase
                ? undefined
                : await mkdtemp(path.join(root, 'temp/protocol-research-'));
            const output = path.join(
                log.runDirectoryPath,
                prefixCase ? 'requested-output' : 'ceremony',
            );
            const controller = new AbortController();
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
                            args: prefixCase
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
                            env: environment,
                            description: prefixCase
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
                        prefixCase ? 'result.json' : 'completion/result.json',
                    ),
                    'utf8',
                ),
            ) as NativeResult;
            if (prefixCase) {
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
            if (!prefixCase && !selected.noResult) {
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
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        case: selected.name,
                        participantCount: selected.participantCount,
                        optionCount: selected.optionCount,
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
                            archiveDelivery: null,
                            participantVisits: null,
                            networkTransfers: null,
                            recoveryWork: null,
                        },
                        scope: prefixCase
                            ? 'Real full-degree BFV coefficient-selection operations on deterministic synthetic ciphertexts encrypting known rank powers. A test-only secret decoder checks every plaintext coefficient against direct interpolation, including all omitted ranks and padding. No participant, ballot proof, certificate, release share or terminal is created.'
                            : selected.noResult
                              ? 'Fresh native certified no-result execution using original credentials. No release shares are generated. This is not durable browser participation, archive availability, security admission or physical qualification.'
                              : 'Fresh native cryptographic execution using tracked sources and original credentials. Subset controls run after share generation. This is not durable browser participation, archive availability, security admission or physical qualification.',
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
