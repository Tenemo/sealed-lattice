import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import binaryen from 'binaryen';
import { build } from 'tsdown';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotRandomnessBudget } from '#tests/ballot-randomness-budget-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import { compileParticipantCustodyCensus } from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import {
    ballotScoreRange,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import type { ParticipantDescriptor } from '#tools/ci/participant-runtime/descriptor.js';
import { runCommandAndCaptureOutput } from '#tools/ci/run-command.js';

// The participant module's linear memory never exceeds the absolute bound.
const maximumMemoryBytes = 671_088_640;
const rustflagSeparator = '\x1f';
const root = path.resolve('.');
const workspace = path.join(root, 'crates/protocol-research');
const runtimeSources = path.join(root, 'tools/ci/participant-runtime');

const number = (value: bigint) => {
    const converted = Number(value);
    assert.ok(Number.isSafeInteger(converted) && BigInt(converted) === value);
    return converted;
};

// Every bound the worker enforces, derived from the profile's owning models.
export const deriveParticipantDescriptor = (
    participantCount: number,
    optionCount: number,
): ParticipantDescriptor => {
    const profile = deriveSupportedProfile(participantCount, optionCount);
    const key = compileRegistrationKeyRelationCensus();
    const enrollment = compileRegistrationEnrollmentCensus();
    const custody = compileParticipantCustodyCensus(profile);
    const body = compileContributionBodyCensus(profile);
    const checkpoint = compileFirstOracleCheckpointCensus(profile);
    const relation = compileSetupContributionRelationCensus(profile);
    const authentication =
        compileContributionAuthenticationCensus(participantCount);
    const ballotBody = compileBallotBodyCensus(profile);
    const ballotCustody = compileParticipantBallotCustody(profile);
    const randomness = compileBallotRandomnessBudget(profile);
    const closeWire = compileCloseWireCensus(profile);
    const closeCustody = compileParticipantCloseCustody(profile);
    const targetState = compileTargetSigningStateCensus();
    const releaseCustody = compileParticipantReleaseCustody(profile);
    return {
        participantCount,
        optionCount,
        registration: {
            publicKeyBytes: number(key.publicKeyBytes),
            maximumProofBytes: number(key.maximumProofBytes),
            maximumHeaderBytes: number(enrollment.maximumHeaderBytes),
            maximumPollDefinitionBytes: number(
                enrollment.maximumPollDefinitionBytes,
            ),
            maximumUsernameIngressBytes: number(
                enrollment.maximumUsernameIngressBytes,
            ),
            signatureBytes: number(enrollment.signatureBytes),
            recipientCapsuleBytes: number(enrollment.recipientCapsuleBytes),
            signingCapsuleBytes: number(enrollment.signingCapsuleBytes),
            maximumProposalBytes: number(
                compileRosterProposalCensus(participantCount).proposalBytes,
            ),
        },
        root: {
            maximumRecords: number(custody.maximumRootRecords),
            maximumRootBytes: number(custody.maximumRootBytes),
            setupReferenceBytes: number(custody.setupReferenceBytes),
        },
        contribution: {
            expandedPolynomials: number(
                relation.expandedStatementPolynomialCount,
            ),
            firstOracleColumns: relation.wordColumns + relation.booleanColumns,
            statementBytes: number(relation.expandedStatementByteLength),
            saltBytes: number(body.saltBytes),
            bodyHeaderBytes: number(body.headerBytes),
            proofHeaderBytes: number(
                compileFullWordProofLayout(profile).headerBytes,
            ),
            minimumProofBytes: number(body.minimumProofBytes),
            maximumProofBytes: number(body.maximumProofBytes),
            maximumStateBytes: number(custody.maximumMetadataBytes),
            maximumCheckpointHeaderBytes: number(checkpoint.maximumHeaderBytes),
            confirmationBodyBytes: number(authentication.confirmationBodyBytes),
            openingBodyBytes: number(authentication.openingBodyBytes),
            confirmationPacketBytes: number(
                authentication.confirmationPacketBytes,
            ),
            requiredStorageBytes: number(custody.maximumRetainedPayloadBytes),
            polynomials: body.polynomials.map((polynomial) => ({
                expandedIndex: polynomial.expandedIndex,
                bytes: number(polynomial.bytes),
                coefficients: number(polynomial.coefficients),
            })),
            publicRecords: custody.publicRecords.map((record) => ({
                object: record.object,
                offset: number(record.offset),
                length: number(record.length),
            })),
            checkpointLengths: custody.checkpointLengths.map(number),
        },
        ballot: {
            minimumScore: ballotScoreRange.minimum,
            maximumScore: ballotScoreRange.maximum,
            recordBytes: number(randomness.recordBytes),
            randomBudgets: [
                number(randomness.maximumEncryptionBytes),
                number(randomness.maximumProofBytes),
            ],
            journalRecords: number(randomness.recordCount),
            maximumStateBytes: number(ballotCustody.maximumStateBytes),
            headerBytes: number(ballotBody.headerBytes),
            minimumBodyBytes: number(
                ballotBody.headerBytes +
                    ballotBody.ciphertextBytes +
                    ballotBody.minimumProofBytes,
            ),
            maximumBodyBytes: number(ballotBody.maximumBodyBytes),
            envelopeBytes: number(ballotBody.envelopeBytes),
            requiredStorageBytes: number(
                ballotCustody.maximumJournalAndBodyBytes +
                    ballotCustody.maximumStateBytes +
                    custody.maximumRootBytes,
            ),
        },
        close: {
            quorum: number(closeWire.closeQuorum),
            submissionBytes: number(closeWire.submissionBytes),
            intentBodyBytes: number(closeWire.intentBodyBytes),
            minimumResponseBodyBytes: number(
                closeWire.minimumResponseBodyBytes,
            ),
            maximumResponseBodyBytes: number(
                closeWire.maximumResponseBodyBytes,
            ),
            proposalBodyBytes: number(closeWire.proposalBodyBytes),
            maximumResponseRecordBytes: number(
                closeWire.maximumResponsePacketBytes +
                    closeWire.maximumResponseEntries *
                        closeWire.submissionBytes,
            ),
            maximumEvents: number(closeCustody.maximumEvents),
            maximumRecords: number(closeCustody.maximumRecords),
            maximumStateBytes: number(closeCustody.maximumStateBytes),
        },
        target: {
            maximumBodyBytes: number(targetState.maximumBodyBytes),
            votePacketBytes: number(targetState.packetBytes),
            maximumStateBytes: number(targetState.maximumStateBytes),
        },
        release: {
            recordBytes: number(releaseCustody.recordBytes),
            journalBytes: number(releaseCustody.totalRandomBytes),
            journalRecords: number(releaseCustody.journalRecords),
            bodyHeaderBytes: number(releaseCustody.bodyHeaderBytes),
            minimumBodyBytes: number(releaseCustody.minimumBodyBytes),
            maximumBodyBytes: number(releaseCustody.maximumBodyBytes),
            envelopeBytes: number(releaseCustody.envelopeBytes),
            maximumStateBytes: number(releaseCustody.maximumStateBytes),
        },
        evaluation: {
            polynomialDegree: number(fixedModulusBfvInputs.polynomialDegree),
            // Whole 64-bit words of the ciphertext modulus's bit length.
            storedCoefficientBytes:
                8 *
                Math.ceil(profile.ciphertext.modulus.toString(2).length / 64),
        },
    };
};

// The imports the participant module may declare, by module and name.
const allowedImports = [
    'ballot.fill_random',
    'ballot_proof.public_chunk',
    'contribution.public_chunk',
    'enrollment.fill_random',
    'enrollment.staged_chunk',
    'setup_witness.fill_random',
    'word_proof.fill_random',
];

export type ParticipantRuntime = Readonly<{
    module: Buffer;
    worker: Buffer;
    descriptor: ParticipantDescriptor;
    identity: Readonly<{
        runtime: string;
        source: string;
        module: string;
        worker: string;
    }>;
}>;

const sha512 = (bytes: Uint8Array | string) =>
    createHash('sha512').update(bytes).digest('hex');

// Snapshots one source tree into the run directory and lists each file's
// digest, so the runtime identity binds the exact sources.
const snapshotSources = async (
    runLog: ActiveLocalRunLog,
    directory: string,
    files: { file: string; sha512: string; bytes: number }[],
): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
        if (entry.name === 'target' || entry.name === '.git') continue;
        const file = path.join(directory, entry.name);
        if (entry.isDirectory()) {
            await snapshotSources(runLog, file, files);
            continue;
        }
        assert.ok(entry.isFile(), 'Runtime sources must be ordinary files.');
        const relative = path.relative(root, file).split(path.sep).join('/');
        const bytes = await readFile(file);
        const destination = path.join(
            runLog.runDirectoryPath,
            'sources',
            relative,
        );
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, bytes, { flag: 'wx' });
        files.push({
            file: relative,
            sha512: sha512(bytes),
            bytes: bytes.length,
        });
    }
};

// Builds the scalar participant module and the bundled worker from tracked
// sources, checks the module's scalar code, imports and memory, and computes
// the runtime identity the worker recomputes.
export const assembleParticipantRuntime = async (
    runLog: ActiveLocalRunLog,
    descriptor: ParticipantDescriptor,
): Promise<ParticipantRuntime> => {
    const execute = async (
        command: string,
        args: string[],
        name: string,
        environment: NodeJS.ProcessEnv = process.env,
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
            { runLog, signal: AbortSignal.timeout(1_800_000) },
        );
        assert.equal(result.exitCode, 0, name);
        assert.equal(result.terminationSignal, null, name);
        return result.stdout;
    };
    const compiler = await execute('rustc', ['+1.95.0', '-Vv'], 'compiler');
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
    const cargoHome = path.resolve(
        process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'),
    );
    const flags = [
        '--remap-path-prefix',
        `${root}=/workspace`,
        '--remap-path-prefix',
        `${cargoHome}=/cargo`,
        '-C',
        'target-feature=-simd128',
        '-C',
        `link-arg=--max-memory=${String(maximumMemoryBytes)}`,
    ];
    const targetDirectory = path.join(root, 'temp/participant-runtime-target');
    const { RUSTFLAGS: _ignored, ...inherited } = process.env;
    await execute(
        'cargo',
        [
            '+1.95.0',
            'build',
            '--offline',
            '--locked',
            '--release',
            '-p',
            'registration-enrollment',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
        ],
        'participant-module',
        {
            ...inherited,
            CARGO_ENCODED_RUSTFLAGS: flags.join(rustflagSeparator),
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: targetDirectory,
        },
    );
    const module = await readFile(
        path.join(
            targetDirectory,
            'wasm32-unknown-unknown/release/registration_enrollment.wasm',
        ),
    );
    const inspected = binaryen.readBinary(module);
    try {
        assert.equal(
            /\b(?:v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\./u.test(
                inspected.emitText(),
            ),
            false,
            'The participant module contains vector instructions.',
        );
        const memory = inspected.getMemoryInfo();
        assert.ok(
            !memory.shared &&
                !memory.is64 &&
                memory.max === maximumMemoryBytes / 65_536,
            'The participant module memory is not the bounded scalar memory.',
        );
    } finally {
        inspected.dispose();
    }
    const compiled = await WebAssembly.compile(module);
    const imports = WebAssembly.Module.imports(compiled);
    assert.ok(
        imports.every(
            (value) =>
                value.kind === 'function' &&
                allowedImports.includes(value.module + '.' + value.name),
        ),
        'The participant module declares an unexpected import.',
    );
    const bundle = path.join(root, 'temp/participant-runtime-bundle');
    await rm(bundle, { recursive: true, force: true });
    await build({
        config: false,
        clean: true,
        cwd: root,
        dts: false,
        entry: { worker: path.join(runtimeSources, 'worker.ts') },
        failOnWarn: true,
        format: 'esm',
        logLevel: 'warn',
        minify: false,
        outDir: bundle,
        outputOptions: { codeSplitting: false },
        platform: 'browser',
        report: false,
        sourcemap: false,
        target: 'es2022',
        treeshake: true,
        tsconfig: path.join(root, 'tsconfig.tools.json'),
    });
    const outputs = (await readdir(bundle)).filter((name) =>
        /\.m?js$/u.test(name),
    );
    assert.equal(outputs.length, 1, 'The worker bundle is not one file.');
    const worker = await readFile(path.join(bundle, outputs[0]));
    const files: { file: string; sha512: string; bytes: number }[] = [];
    await snapshotSources(runLog, workspace, files);
    await snapshotSources(runLog, runtimeSources, files);
    for (const file of [
        'tools/ci/participant-runtime-assembly.ts',
        'tools/ci/protocol-participant-predecessor.ts',
        'tools/ci/protocol-participant-state-transaction.ts',
        'tools/ci/protocol-participant-stop.ts',
    ]) {
        const bytes = await readFile(path.join(root, file));
        const destination = path.join(runLog.runDirectoryPath, 'sources', file);
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, bytes, { flag: 'wx' });
        files.push({ file, sha512: sha512(bytes), bytes: bytes.length });
    }
    files.sort((left, right) => (left.file < right.file ? -1 : 1));
    const sourceManifest = JSON.stringify({ compiler, protoc, flags, files });
    await writeFile(
        path.join(runLog.runDirectoryPath, 'source-manifest.json'),
        sourceManifest + '\n',
        { flag: 'wx' },
    );
    const source = sha512(sourceManifest);
    const identity = {
        source,
        module: sha512(module),
        worker: sha512(worker),
    };
    const runtime = createHash('sha512')
        .update('participant-runtime/7')
        .update(Buffer.from(identity.source, 'hex'))
        .update(Buffer.from(identity.module, 'hex'))
        .update(Buffer.from(identity.worker, 'hex'))
        .update(
            createHash('sha512').update(JSON.stringify(descriptor)).digest(),
        )
        .digest('hex');
    for (const [name, bytes] of [
        ['participant.wasm', module],
        ['worker.js', worker],
        ['descriptor.json', Buffer.from(JSON.stringify(descriptor) + '\n')],
    ] as const)
        await writeFile(path.join(runLog.runDirectoryPath, name), bytes, {
            flag: 'wx',
        });
    return {
        module,
        worker,
        descriptor,
        identity: { runtime, ...identity },
    };
};
