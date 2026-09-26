import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { ParticipantDescriptor } from '#packages/sdk/src/participant/worker/descriptor.js';
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
import { buildParticipantModule } from '#tools/ci/build-participant-module.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';

const root = path.resolve('.');
const packageOutput = path.join(root, 'packages/sdk/dist');

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

// A corrupt participant's client claims the honest runtime: its worker
// fetches and hashes the honest module as the honest worker does, then
// compiles the module at the client's own path, which signs authentic invalid
// ballots. Its page checks the patched worker's digest instead.
export type CorruptParticipantClient = Readonly<{
    feature: string;
    path: string;
    module: Buffer;
    worker: Buffer;
    moduleDigest: string;
    workerDigest: string;
}>;

// Takes the participant module, worker and source manifest the SDK build
// packaged, copies every listed source into the run directory after checking
// its digest, and computes the runtime identity the worker recomputes. When
// requested, it also builds the invalid-ballot client from the same sources.
export const assembleParticipantRuntime = async (
    runLog: ActiveLocalRunLog,
    descriptor: ParticipantDescriptor,
    invalidBallot: boolean,
): Promise<
    Readonly<{
        runtime: ParticipantRuntime;
        invalidBallotClient: CorruptParticipantClient | undefined;
    }>
> => {
    const [module, worker, sourceManifest] = await Promise.all(
        [
            'participant.wasm',
            'participant-worker.js',
            'participant-source-manifest.json',
        ].map((name) => readFile(path.join(packageOutput, name))),
    );
    const listed = (
        JSON.parse(sourceManifest.toString('utf8')) as {
            files: { file: string; sha512: string; bytes: number }[];
        }
    ).files;
    for (const { file, sha512: digest } of listed) {
        const bytes = await readFile(path.join(root, file));
        assert.equal(
            sha512(bytes),
            digest,
            'The packaged participant runtime was built from other sources: ' +
                file,
        );
        const destination = path.join(runLog.runDirectoryPath, 'sources', file);
        await mkdir(path.dirname(destination), { recursive: true });
        await writeFile(destination, bytes, { flag: 'wx' });
    }
    await writeFile(
        path.join(runLog.runDirectoryPath, 'source-manifest.json'),
        sourceManifest,
        { flag: 'wx' },
    );
    const identity = {
        source: sha512(sourceManifest),
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
    const invalidBallotModule = invalidBallot
        ? (await buildParticipantModule('invalid-ballot')).module
        : undefined;
    const invalidBallotClient =
        invalidBallotModule === undefined
            ? undefined
            : (() => {
                  const clientPath = 'invalid-ballot-participant.wasm';
                  const honestCompile =
                      'await WebAssembly.compile(new Uint8Array(moduleBytes))';
                  const bundled = worker.toString('utf8');
                  assert.equal(
                      bundled.split(honestCompile).length,
                      2,
                      'The worker bundle does not compile its module once.',
                  );
                  // The replacement names only globals, so it holds whatever
                  // names the bundler chose.
                  const patched = Buffer.from(
                      bundled.replace(
                          honestCompile,
                          'await WebAssembly.compile(await (await fetch(location.origin + "/' +
                              clientPath +
                              '")).arrayBuffer())',
                      ),
                  );
                  const client = {
                      feature: 'invalid-ballot',
                      path: clientPath,
                      module: invalidBallotModule,
                      worker: patched,
                      moduleDigest: sha512(invalidBallotModule),
                      workerDigest: sha512(patched),
                  };
                  assert.notEqual(
                      client.moduleDigest,
                      identity.module,
                      'The invalid-ballot module equals the honest module.',
                  );
                  return client;
              })();
    for (const [name, bytes] of [
        ['participant.wasm', module],
        ['worker.js', worker],
        ['descriptor.json', Buffer.from(JSON.stringify(descriptor) + '\n')],
        ...(invalidBallotClient === undefined
            ? []
            : ([
                  [invalidBallotClient.path, invalidBallotClient.module],
                  ['invalid-ballot-worker.js', invalidBallotClient.worker],
              ] as const)),
    ] as const)
        await writeFile(path.join(runLog.runDirectoryPath, name), bytes, {
            flag: 'wx',
        });
    return {
        runtime: {
            module,
            worker,
            descriptor,
            identity: { runtime, ...identity },
        },
        invalidBallotClient,
    };
};
