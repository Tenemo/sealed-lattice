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
import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import { compileSlotPublicationResourceCensus } from '#tests/slot-publication-resource-model.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectProtocolResearchCase } from '#tools/ci/protocol-research-registry.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';

type NativeResult = {
    kind: string;
    accepted?: number[];
    invalid?: number[];
    releaseSubsets?: number;
    departureSets?: number;
    cases?: {
        milliseconds: number;
        result: {
            topCount: number;
            inputIdentity: string;
            optionPositions: number[];
        };
    }[];
};
const selected = selectProtocolResearchCase(process.argv.slice(2));
const prefixCase = selected.name === 'native-prefix';
const root = path.resolve('.');
const workspace = path.join(root, 'crates/protocol-research');
const memoryLimit = 1_073_741_824;

await runWithLocalRunLog(
    {
        commandLineArguments: [selected.name],
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
            const contribution = compileContributionBodyCensus();
            const aggregate = compileSetupAggregateResources();
            const enrollment = compileRegistrationEnrollmentCensus();
            const ballot = compileBallotBodyCensus();
            const participants = BigInt(contribution.participantCount);
            const registration = compileRegistrationKeyRelationCensus();
            const authentication = compileContributionAuthenticationCensus(
                Number(participants),
            );
            const roster = compileRosterProposalCensus(Number(participants));
            const publication = compileSlotPublicationResourceCensus(
                Number(participants),
            );
            const release = compileLinkedReleaseWordProofLayout();
            const degree = fixedModulusBfvInputs.polynomialDegree;
            const coefficientBytes =
                1n +
                BigInt(
                    Math.ceil(
                        fixedModulusBfvInputs.releaseModulus.toString(2)
                            .length / 8,
                    ),
                );
            const releaseBody =
                12n +
                198n +
                degree * coefficientBytes +
                release.maximumMultiproofBytes;
            const sourceBound =
                publication.maximumEvidenceMetadataBytes +
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
                enrollment.signatureBytes;
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
            assert.equal(participants, 10n);
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
            const members = [
                'native-ceremony',
                'registration-enrollment',
                'registration-credentials',
                'evaluation-target',
                'contribution-prover',
                'setup-aggregate',
                'opened-contribution',
                'ballot-proof',
                'linked-release-proof',
                'rns-arithmetic-probe',
            ];
            await execute(
                'cargo',
                [
                    '+1.95.0',
                    'fmt',
                    ...members.flatMap((name) => ['-p', name]),
                    '--',
                    '--check',
                ],
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
                    ...members.flatMap((name) => ['-p', name]),
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
                    '-p',
                    'registration-credentials',
                    '-p',
                    'evaluation-target',
                    '-p',
                    'linked-release-proof',
                    '-p',
                    'rns-arithmetic-probe',
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
                    ...[
                        'native-ceremony',
                        'contribution-prover',
                        'setup-aggregate',
                        'opened-contribution',
                        'ballot-proof',
                        'rns-arithmetic-probe',
                    ].flatMap((name) => ['-p', name]),
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
                            AbortSignal.timeout(3_600_000),
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
                assert.deepEqual(
                    result.cases.map((value) => value.result.topCount),
                    [10, 3],
                );
                assert.equal(
                    result.cases[0].result.inputIdentity,
                    result.cases[1].result.inputIdentity,
                );
                assert.deepEqual(
                    result.cases[1].result.optionPositions,
                    [4, 1, 8],
                );
            } else {
                assert.equal(
                    result.kind,
                    selected.noResult ? 'no-result' : 'result',
                );
                assert.deepEqual(result.accepted, selected.noResult ? [] : [0]);
                assert.deepEqual(
                    result.invalid,
                    selected.name === 'native-invalid-only'
                        ? [0]
                        : selected.noResult
                          ? []
                          : [1, 2],
                );
            }
            if (!prefixCase && !selected.noResult) {
                assert.equal(result.releaseSubsets, 210);
                assert.equal(result.departureSets, 176);
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
