import type {
    ActionContext,
    AggregateContribution,
    ClaimBearingBallotPackage,
    ProtocolSignatureEnvelope,
    ShareCommitmentMessageBoundCert,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { registerAggregateBridgeEncryptionTest } from './aggregate-derivation-proof/bridge-encryption.js';

import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolHash,
} from '#packages/crypto/src/index';
import { createPendingBridgeProofRecordFromBridgeEvidence } from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import {
    aggregateWitnessFromReceiverPlaintext,
    buildAggregateDerivationProofInput,
    buildAggregateDerivationStatement,
    createAggregateContributionFromBridgeProofRecord,
    createAggregateDerivationComponent,
    createAggregateReadyRecord,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    selectFirstValidAggregateContributions,
    sumAggregateDerivationWitnesses,
    verifyAggregateDerivationComponentStructure,
    verifyAggregateReadyRecordStructure,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    createMandatoryProfileBallotProofRecordBenchmarkFixture,
    createWasmBallotProofRecordGenerationFixture,
} from '#tests/support/ballot-privacy-proof-record-generation-fixtures';

const hash = (label: string): string =>
    `${label.padEnd(64, '0').slice(0, 64)}${label.padEnd(64, '1').slice(0, 64)}`.replace(
        /[^a-f0-9]/gu,
        'a',
    );
const forbiddenBridgeWitnessFieldNames = [
    'aggregateHistogram',
    'aggregateIntegerShareVector',
    'aggregateOpeningRandomness',
    'aggregateScore',
    'aggregateScoreBits',
    'plaintextComparisonInputs',
    'plaintextScoreBitInputs',
    'proofWitness',
    'rawAggregateWitness',
    'receiverPlaintext',
    'sourceWitnessCoefficients',
    'aggregateInputPlaintext',
    'tPvss',
    't_pvss',
    'witness',
] as const;

const createFixtureBallotPackage = (input: {
    readonly fixture: ReturnType<
        typeof createWasmBallotProofRecordGenerationFixture
    >;
    readonly generation: Record<string, unknown>;
}): ClaimBearingBallotPackage =>
    ({
        objectType: 'ClaimBearingBallotPackage',
        objectVersion: 1,
        ballotPackageHash: input.fixture.request.statement.ballotPackageHash,
        ballotProofStatement: input.fixture.request.statement,
        ballotProof: input.generation
            .ballotProof as ClaimBearingBallotPackage['ballotProof'],
        proofBytesHex: input.generation.proofBytesHex as string,
        linearStatement: input.fixture.request.linearStatement,
        parameterSet: input.generation.parameterSet,
        proofEncoding: input.generation.proofEncoding,
        publicRandomnessHex: input.fixture.request.publicRandomnessHex,
        componentBundleStatement:
            input.fixture.request.componentBundleStatement,
        componentProofBundle: input.generation
            .componentProofBundle as ClaimBearingBallotPackage['componentProofBundle'],
        componentProofInputs: input.generation
            .componentProofInputs as ClaimBearingBallotPackage['componentProofInputs'],
        receiverKeyProofRootEvidence:
            input.fixture.receiverKeyProofRootEvidence,
        receiverPayloads: input.fixture.claimBearingReceiverPayloads,
        shareCommitments: input.fixture.claimBearingShareCommitments,
    }) as unknown as ClaimBearingBallotPackage;

const receiverWitness = (
    fixture: ReturnType<typeof createWasmBallotProofRecordGenerationFixture>,
    receiverRosterPosition = 1,
): AggregateDerivationWitnessInput => {
    const receiverPayloadPlaintext =
        fixture.projectionWitness.receiverPayloadPlaintexts?.find(
            (plaintext) =>
                plaintext.receiverRosterPosition === receiverRosterPosition,
        );
    const shareCommitmentOpening =
        fixture.projectionWitness.shareCommitmentOpenings.find(
            (opening) =>
                opening.receiverRosterPosition === receiverRosterPosition,
        );
    if (
        receiverPayloadPlaintext === undefined ||
        shareCommitmentOpening === undefined
    ) {
        throw new Error(
            `Fixture should include receiver-${receiverRosterPosition} witness material.`,
        );
    }

    return aggregateWitnessFromReceiverPlaintext({
        openingRandomness: shareCommitmentOpening.openingRandomness,
        receiverShareVector: receiverPayloadPlaintext.receiverShareVector,
    });
};

const fixtureCertificate = (
    fixture: ReturnType<typeof createWasmBallotProofRecordGenerationFixture>,
): ShareCommitmentMessageBoundCert => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: fixture.relationInput.optionCount,
    });

    return createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
};

const certificateThatPermitsWraparound = (
    certificate: ShareCommitmentMessageBoundCert,
): ShareCommitmentMessageBoundCert => {
    const certificatePayload = {
        ...certificate,
        commitmentMessageBound: '1',
        noWraparoundCondition: {
            maximumAggregateIntegerLessThanCommitmentMessageBound: false,
            openingRandomnessAggregateBoundMatchesTurnout: true,
        },
    };
    const { shareCommitmentMessageBoundCertHash, ...withoutHash } =
        certificatePayload;
    void shareCommitmentMessageBoundCertHash;

    return {
        ...withoutHash,
        shareCommitmentMessageBoundCertHash: deriveProtocolHash(
            'ShareCommitmentMessageBoundCertHash',
            withoutHash,
        ),
    } as unknown as ShareCommitmentMessageBoundCert;
};

const createPostCloseEvidence = (input: {
    readonly ceremonyId: string;
    readonly contributorIdentity: string;
    readonly electionManifestHash: string;
    readonly rosterExternalAcceptanceHash: string;
    readonly votingClosedBoardHeadHash: string;
}): {
    readonly closeRecord: Record<string, unknown>;
    readonly contributorActionContext: Record<string, unknown>;
    readonly closeRecordHash: string;
    readonly postVotingClosedContextHash: string;
} => {
    const closeRecordPayload = {
        boardPosition: 0,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        closeKind: 'VotingClosed',
        closedBoardHeadHash: input.votingClosedBoardHeadHash,
        electionManifestHash: input.electionManifestHash,
        objectType: 'CloseRecord',
        objectVersion: 1,
        organizerIdentity: 'organizer-1',
    };
    const closeRecordHash = deriveProtocolHash(
        'CloseRecordHash',
        closeRecordPayload,
    );
    const postVotingClosedContextHash = deriveProtocolHash(
        'PostVotingClosedContextHash',
        {
            ceremonyId: input.ceremonyId,
            closeRecordHash,
            electionManifestHash: input.electionManifestHash,
            votingClosedBoardHeadHash: input.votingClosedBoardHeadHash,
        },
    );
    const contributorActionContextPayload = {
        acceptedRecoveryEpochUpdateHash: null,
        actionSequence: 1,
        boardHeadHash: input.votingClosedBoardHeadHash,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        contextHash: postVotingClosedContextHash,
        deviceEpoch: 0,
        electionManifestHash: input.electionManifestHash,
        recoveryEpoch: 0,
        recoveryPolicyHash: hash('recovery-policy'),
        rosterExternalAcceptanceHash: input.rosterExternalAcceptanceHash,
        signerIdentity: input.contributorIdentity,
    };
    const contributorActionContextHash = deriveProtocolHash(
        'ActionContextHash',
        contributorActionContextPayload,
    );

    return {
        closeRecord: {
            ...closeRecordPayload,
            closeRecordHash,
            postVotingClosedContextHash,
        },
        closeRecordHash,
        contributorActionContext: {
            ...contributorActionContextPayload,
            actionContextHash: contributorActionContextHash,
        },
        postVotingClosedContextHash,
    };
};

const aggregateFastStepTimeoutMs = 5 * 60_000;
const aggregateHeavyStepTimeoutMs = 20 * 60_000;
const aggregateBallotProofPackageTimeoutMs = 30 * 60_000;

type TranscriptCoreKernel = Awaited<
    ReturnType<typeof loadTranscriptCoreKernel>
>;
type AggregateFixture = ReturnType<
    typeof createWasmBallotProofRecordGenerationFixture
>;
type PostCloseEvidence = ReturnType<typeof createPostCloseEvidence>;
type AggregateStatementInput = Parameters<
    typeof buildAggregateDerivationStatement
>[0];
type AggregateStatementBuild = ReturnType<
    typeof buildAggregateDerivationStatement
>;
type AggregateProofBuild = ReturnType<
    typeof buildAggregateDerivationProofInput
>;
type AggregateWitness = ReturnType<typeof sumAggregateDerivationWitnesses>;
type AggregateProofGeneration = ReturnType<
    TranscriptCoreKernel['generateAggregateDerivationProof']
>;
type AggregateComponent = ReturnType<typeof createAggregateDerivationComponent>;

type BallotPackageContext = {
    readonly ballotPackage: ClaimBearingBallotPackage;
    readonly ballotPackageWithoutProofBytes: ClaimBearingBallotPackage;
    readonly certificate: ShareCommitmentMessageBoundCert;
    readonly fixture: AggregateFixture;
    readonly kernel: TranscriptCoreKernel;
    readonly postCloseEvidence: PostCloseEvidence;
    readonly statementInput: AggregateStatementInput;
};

type AggregateStatementContext = BallotPackageContext &
    AggregateStatementBuild & {
        readonly witness: AggregateWitness;
    };

type AggregateComponentContext = AggregateStatementContext & {
    readonly component: AggregateComponent;
    readonly generatedAggregateProof: AggregateProofGeneration;
    readonly proofBuild: AggregateProofBuild;
};
type BridgeContributorContext = {
    readonly bridgeEncryption: Record<string, unknown>;
    readonly bridgeVerification: Record<string, unknown>;
    readonly componentContext: AggregateComponentContext;
};

const runAggregateTestStep = async <T>(
    name: string,
    action: () => T | Promise<T>,
): Promise<T> => {
    const writeTimingLine = (line: string): void => {
        process.stdout.write(`${line}\n`);
    };
    const isGitHubActions = process.env.GITHUB_ACTIONS === 'true';
    const startedAtMilliseconds = Date.now();
    if (isGitHubActions) {
        writeTimingLine(`::group::Aggregate derivation: ${name}`);
    }
    writeTimingLine(`Aggregate derivation step started: ${name}`);
    try {
        return await action();
    } finally {
        const elapsedSeconds = (
            (Date.now() - startedAtMilliseconds) /
            1000
        ).toFixed(1);
        writeTimingLine(
            `Aggregate derivation step finished: ${name} (${elapsedSeconds}s)`,
        );
        if (isGitHubActions) {
            writeTimingLine('::endgroup::');
        }
    }
};

const runAggregateSubcase = async <T>(
    name: string,
    action: () => T | Promise<T>,
): Promise<T> => runAggregateTestStep(`subcase: ${name}`, action);

const requireBallotPackageContext = (
    context: BallotPackageContext | undefined,
): BallotPackageContext => {
    if (context === undefined) {
        throw new Error('The ballot proof package step did not complete.');
    }

    return context;
};

const requireAggregateStatementContext = (
    context: AggregateStatementContext | undefined,
): AggregateStatementContext => {
    if (context === undefined) {
        throw new Error('The aggregate statement step did not complete.');
    }

    return context;
};

const requireAggregateComponentContext = (
    context: AggregateComponentContext | undefined,
): AggregateComponentContext => {
    if (context === undefined) {
        throw new Error('The aggregate proof component step did not complete.');
    }

    return context;
};

const createAggregateComponentContextForReceiver = (input: {
    readonly ballotPackageContext: BallotPackageContext;
    readonly contributorRosterPosition: number;
    readonly proverRandomnessHex: string;
}): AggregateComponentContext => {
    const contributorIdentity = `receiver-${input.contributorRosterPosition}`;
    const postCloseEvidence = createPostCloseEvidence({
        ceremonyId: input.ballotPackageContext.fixture.statement.ceremonyId,
        contributorIdentity,
        electionManifestHash:
            input.ballotPackageContext.fixture.statement.manifestHash,
        rosterExternalAcceptanceHash:
            input.ballotPackageContext.fixture.statement
                .rosterExternalAcceptanceHash,
        votingClosedBoardHeadHash: hash('closed-board-head'),
    });
    const statementInput = {
        ballotPackages: [input.ballotPackageContext.ballotPackage],
        closeRecordHash: postCloseEvidence.closeRecordHash,
        contributorActionContextHash: postCloseEvidence.contributorActionContext
            .actionContextHash as string,
        contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            input.ballotPackageContext.fixture.statement
                .rosterExternalAcceptanceHash,
        contributorRosterPosition: input.contributorRosterPosition,
        postVotingClosedContextHash:
            postCloseEvidence.postVotingClosedContextHash,
        casualMicroRosterAcknowledged: false,
        votingClosedBoardHeadHash: postCloseEvidence.closeRecord
            .closedBoardHeadHash as string,
    } satisfies AggregateStatementInput;
    const { aggregateCommitment, statement } =
        buildAggregateDerivationStatement(statementInput);
    const witness = sumAggregateDerivationWitnesses({
        witnesses: [
            receiverWitness(
                input.ballotPackageContext.fixture,
                input.contributorRosterPosition,
            ),
        ],
    });
    const proofBuild = buildAggregateDerivationProofInput({
        aggregateCommitment,
        statement,
        witness,
    });
    const generatedAggregateProof =
        input.ballotPackageContext.kernel.generateAggregateDerivationProof({
            proofInput: proofBuild.proofInput,
            proverRandomnessHex: input.proverRandomnessHex,
            secretState: proofBuild.secretState,
        });
    if (generatedAggregateProof.ok !== true) {
        throw new Error(
            `Aggregate derivation proof generation failed for ${contributorIdentity}: ${JSON.stringify(generatedAggregateProof)}`,
        );
    }
    const component = createAggregateDerivationComponent({
        aggregateCommitment,
        proofBytesHex: String(generatedAggregateProof.proofBytesHex),
        proofInput: proofBuild.proofInput,
        shareCommitmentMessageBoundCert: input.ballotPackageContext.certificate,
        statement,
    });
    const componentVerification =
        verifyAggregateDerivationComponentStructure(component);
    if (!componentVerification.ok) {
        throw new Error(
            `Aggregate component structure rejected for ${contributorIdentity}: ${JSON.stringify(componentVerification)}`,
        );
    }

    return {
        ...input.ballotPackageContext,
        aggregateCommitment,
        component,
        generatedAggregateProof,
        postCloseEvidence,
        proofBuild,
        statement,
        statementInput,
        witness,
    };
};

const deriveSharedBridgeSupportHashes = (input: {
    readonly ballotSetHash: string;
    readonly ceremonyId: string;
    readonly setupPackageHash: string;
}): {
    readonly aggregateSelectionPolicyHash: string;
    readonly bridgeWitnessPrivacyProfileHash: string;
    readonly heParamHash: string;
} => ({
    aggregateSelectionPolicyHash: deriveProtocolHash('ChallengeDomainHash', {
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        purpose: 'accepted-encrypted-aggregate-evaluator-selection-policy-v1',
        setupPackageHash: input.setupPackageHash,
    }),
    bridgeWitnessPrivacyProfileHash: deriveProtocolHash('ChallengeDomainHash', {
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        purpose: 'accepted-encrypted-aggregate-evaluator-witness-privacy-v1',
        setupPackageHash: input.setupPackageHash,
    }),
    heParamHash: deriveProtocolHash('ChallengeDomainHash', {
        ballotSetHash: input.ballotSetHash,
        ceremonyId: input.ceremonyId,
        purpose: 'accepted-encrypted-aggregate-evaluator-he-param-v1',
        setupPackageHash: input.setupPackageHash,
    }),
});

const createAggregateContributionSignature = (input: {
    readonly actionContext: ActionContext;
    readonly aggregateContributionHash: string;
    readonly manifestHash: string;
}): ProtocolSignatureEnvelope => {
    const keyFixture = createMlDsaKeyPairFixture(
        `aggregate-ready-${input.actionContext.signerIdentity}`,
    );

    return createProtocolSignatureFixture({
        profile: createMlDsaSignatureProfileFixture(),
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        publicKeyHash: keyFixture.publicKeyHash,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            boardHeadHash: input.actionContext.boardHeadHash,
            byteLength: 64,
            ceremonyId: input.actionContext.ceremonyId,
            chunkMerkleRoot: null,
            contextHash: input.actionContext.contextHash,
            deviceEpoch: input.actionContext.deviceEpoch,
            manifestHash: input.manifestHash,
            objectRoot: input.aggregateContributionHash,
            objectType: 'AggregateContribution',
            objectVersion: 1,
            recoveryEpoch: input.actionContext.recoveryEpoch,
            signerIdentity: input.actionContext.signerIdentity,
            signerRole: 'Trustee',
        },
    });
};

const createCurrentRecoveryEpochMap = (
    contributions: readonly AggregateContribution[],
): Record<
    string,
    {
        readonly currentDeviceEpoch: number;
        readonly currentRecoveryEpoch: number;
        readonly signerIdentity: string;
    }
> =>
    Object.fromEntries(
        contributions.map((contribution) => [
            contribution.contributorIdentity,
            {
                currentDeviceEpoch: contribution.deviceEpoch,
                currentRecoveryEpoch: contribution.recoveryEpoch,
                signerIdentity: contribution.contributorIdentity,
            },
        ]),
    );

describe.sequential(
    'aggregate derivation proof through the transcript-core kernel',
    () => {
        let ballotPackageContext: BallotPackageContext | undefined;
        let aggregateStatementContext: AggregateStatementContext | undefined;
        let aggregateComponentContext: AggregateComponentContext | undefined;

        it(
            'generates the ballot proof package',
            async () => {
                ballotPackageContext = await runAggregateTestStep(
                    'Generate ballot proof package',
                    async () => {
                        const kernel = await loadTranscriptCoreKernel();
                        const fixture =
                            createMandatoryProfileBallotProofRecordBenchmarkFixture();
                        const ballotProofGeneration =
                            kernel.generateBallotProofRecord(fixture.request);
                        expect(ballotProofGeneration).toMatchObject({
                            ok: true,
                            generatedProofBytes: true,
                            operation: 'generateBallotProofRecord',
                            unresolvedReason: null,
                        });
                        const ballotPackage = createFixtureBallotPackage({
                            fixture,
                            generation: ballotProofGeneration,
                        });
                        const certificate = fixtureCertificate(fixture);
                        expect(
                            certificate.shareCommitmentMessageBoundCertHash,
                        ).toBe(
                            fixture.statement
                                .shareCommitmentMessageBoundCertHash,
                        );
                        const postCloseEvidence = createPostCloseEvidence({
                            ceremonyId: fixture.statement.ceremonyId,
                            contributorIdentity: 'receiver-1',
                            electionManifestHash:
                                fixture.statement.manifestHash,
                            rosterExternalAcceptanceHash:
                                fixture.statement.rosterExternalAcceptanceHash,
                            votingClosedBoardHeadHash:
                                hash('closed-board-head'),
                        });
                        const {
                            proofBytesHex: omittedProofBytesHex,
                            ...ballotPackageWithoutProofBytes
                        } = ballotPackage;
                        void omittedProofBytesHex;
                        const statementInput = {
                            ballotPackages: [ballotPackage],
                            closeRecordHash: postCloseEvidence.closeRecordHash,
                            contributorActionContextHash: postCloseEvidence
                                .contributorActionContext
                                .actionContextHash as string,
                            contributorIdentity: 'receiver-1',
                            contributorRosterExternalAcceptanceHash:
                                fixture.statement.rosterExternalAcceptanceHash,
                            contributorRosterPosition: 1,
                            postVotingClosedContextHash:
                                postCloseEvidence.postVotingClosedContextHash,
                            casualMicroRosterAcknowledged: false,
                            votingClosedBoardHeadHash: postCloseEvidence
                                .closeRecord.closedBoardHeadHash as string,
                        } satisfies AggregateStatementInput;

                        return {
                            ballotPackage,
                            ballotPackageWithoutProofBytes:
                                ballotPackageWithoutProofBytes,
                            certificate,
                            fixture,
                            kernel,
                            postCloseEvidence,
                            statementInput,
                        };
                    },
                );
            },
            aggregateBallotProofPackageTimeoutMs,
        );

        it(
            'rejects malformed aggregate statement inputs',
            async () => {
                await runAggregateTestStep(
                    'Reject malformed aggregate statement inputs',
                    () => {
                        const {
                            ballotPackage,
                            ballotPackageWithoutProofBytes,
                            statementInput,
                        } = requireBallotPackageContext(ballotPackageContext);

                        expect(() =>
                            buildAggregateDerivationStatement({
                                ...statementInput,
                                casualMicroRosterAcknowledged: true,
                            }),
                        ).toThrow(
                            /casual micro-roster acknowledgement is only valid/u,
                        );
                        expect(() =>
                            buildAggregateDerivationStatement({
                                ...statementInput,
                                ballotPackages: [ballotPackage, ballotPackage],
                            }),
                        ).toThrow(/duplicates/u);
                        expect(() =>
                            buildAggregateDerivationStatement({
                                ...statementInput,
                                ballotPackages: [
                                    ballotPackageWithoutProofBytes,
                                ],
                            }),
                        ).toThrow(/proof-byte-bearing/u);
                    },
                );
            },
            aggregateFastStepTimeoutMs,
        );

        it(
            'builds the aggregate statement and rejects a mismatched witness',
            async () => {
                aggregateStatementContext = await runAggregateTestStep(
                    'Build aggregate statement and reject mismatched witness',
                    () => {
                        const context =
                            requireBallotPackageContext(ballotPackageContext);
                        const { aggregateCommitment, statement } =
                            buildAggregateDerivationStatement(
                                context.statementInput,
                            );
                        const witness = sumAggregateDerivationWitnesses({
                            witnesses: [receiverWitness(context.fixture)],
                        });
                        const wrongWitness = {
                            ...witness,
                            aggregateIntegerShareVector:
                                witness.aggregateIntegerShareVector.map(
                                    (coordinate, coordinateIndex) =>
                                        coordinateIndex === 0
                                            ? coordinate + 1
                                            : coordinate,
                                ),
                        };
                        const wrongProofBuild =
                            buildAggregateDerivationProofInput({
                                aggregateCommitment,
                                statement,
                                witness: wrongWitness,
                            });
                        expect(
                            context.kernel.generateAggregateDerivationProof({
                                proofInput: wrongProofBuild.proofInput,
                                proverRandomnessHex: '66'.repeat(32),
                                secretState: wrongProofBuild.secretState,
                            }),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPackageInvalid',
                        });

                        return {
                            ...context,
                            aggregateCommitment,
                            statement,
                            witness,
                        };
                    },
                );
            },
            aggregateHeavyStepTimeoutMs,
        );

        it(
            'generates the aggregate derivation proof component',
            async () => {
                aggregateComponentContext = await runAggregateTestStep(
                    'Generate aggregate derivation proof and component',
                    () => {
                        const context = requireAggregateStatementContext(
                            aggregateStatementContext,
                        );
                        const proofBuild = buildAggregateDerivationProofInput({
                            aggregateCommitment: context.aggregateCommitment,
                            statement: context.statement,
                            witness: context.witness,
                        });
                        const generatedAggregateProof =
                            context.kernel.generateAggregateDerivationProof({
                                proofInput: proofBuild.proofInput,
                                proverRandomnessHex: '66'.repeat(32),
                                secretState: proofBuild.secretState,
                            });
                        expect(generatedAggregateProof.refusedObjects).toEqual(
                            [],
                        );
                        expect(generatedAggregateProof).toMatchObject({
                            ok: true,
                            backendAvailable: true,
                            generatedProofBytes: true,
                            operation: 'generateAggregateDerivationProof',
                            unresolvedReason: null,
                        });
                        expect(generatedAggregateProof.statusLabels).toEqual([
                            'AggregateDerivationProofGenerated',
                        ]);
                        const component = createAggregateDerivationComponent({
                            aggregateCommitment: context.aggregateCommitment,
                            proofBytesHex: String(
                                generatedAggregateProof.proofBytesHex,
                            ),
                            proofInput: proofBuild.proofInput,
                            shareCommitmentMessageBoundCert:
                                context.certificate,
                            statement: context.statement,
                        });

                        expect(
                            verifyAggregateDerivationComponentStructure(
                                component,
                            ),
                        ).toMatchObject({
                            ok: true,
                            aggregateDerivationComponentHash:
                                component.aggregateDerivationComponentHash,
                        });
                        expect(JSON.stringify(component)).not.toMatch(
                            /aggregateHistogram|aggregateIntegerShareVector|aggregateOpeningRandomness|aggregateScore|aggregateScoreBits|plaintextComparisonInputs|plaintextScoreBitInputs|proofWitness|rawAggregateWitness|receiverPlaintext|sourceWitnessCoefficients|aggregateInputPlaintext|tPvss|t_pvss/u,
                        );

                        return {
                            ...context,
                            component,
                            generatedAggregateProof,
                            proofBuild,
                        };
                    },
                );
            },
            aggregateHeavyStepTimeoutMs,
        );

        it(
            'verifies the aggregate derivation proof and malformed verification contexts',
            async () => {
                await runAggregateTestStep(
                    'Verify aggregate derivation proof and malformed verification contexts',
                    async () => {
                        const {
                            ballotPackage,
                            component,
                            kernel,
                            postCloseEvidence,
                        } = requireAggregateComponentContext(
                            aggregateComponentContext,
                        );
                        const verifyAggregateSubcase = async (
                            name: string,
                            request: Parameters<
                                typeof kernel.verifyAggregateDerivationProof
                            >[0],
                            expected: Record<string, unknown>,
                        ): Promise<void> => {
                            await runAggregateSubcase(name, () => {
                                expect(
                                    kernel.verifyAggregateDerivationProof(
                                        request,
                                    ),
                                    name,
                                ).toMatchObject(expected);
                            });
                        };
                        const verification = await runAggregateSubcase(
                            'accepted aggregate derivation proof',
                            () =>
                                kernel.verifyAggregateDerivationProof({
                                    closeRecord: postCloseEvidence.closeRecord,
                                    component,
                                    contributorActionContext:
                                        postCloseEvidence.contributorActionContext,
                                    countedBallotPackages: [ballotPackage],
                                }),
                        );
                        expect(verification).toMatchObject({
                            ok: true,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                            unresolvedReason: null,
                        });
                        expect(verification.statusLabels).toEqual([
                            'AggregateDerivationRelationChecked',
                            'AggregateDerivationFullVerificationChecked',
                            'AggregateDerivationProofVerified',
                        ]);
                        await verifyAggregateSubcase(
                            'missing counted ballot package list',
                            {
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                            },
                            {
                                ok: false,
                                backendAvailable: true,
                                operation: 'verifyAggregateDerivationProof',
                            },
                        );
                        await verifyAggregateSubcase(
                            'mismatched contributor action signer',
                            {
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext: {
                                    ...postCloseEvidence.contributorActionContext,
                                    signerIdentity: 'receiver-2',
                                },
                                countedBallotPackages: [ballotPackage],
                            },
                            {
                                ok: false,
                                unresolvedReason: 'BallotPackageInvalid',
                            },
                        );

                        await verifyAggregateSubcase(
                            'mutated aggregate relation proof bytes',
                            {
                                closeRecord: postCloseEvidence.closeRecord,
                                component: {
                                    ...component,
                                    proofInput: {
                                        ...component.proofInput,
                                        proofBytesHex: `00${component.proofInput.proofBytesHex.slice(2)}`,
                                    },
                                },
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [ballotPackage],
                            },
                            {
                                ok: false,
                                backendAvailable: true,
                                operation: 'verifyAggregateDerivationProof',
                            },
                        );

                        await verifyAggregateSubcase(
                            'mutated aggregate relation public randomness',
                            {
                                closeRecord: postCloseEvidence.closeRecord,
                                component: {
                                    ...component,
                                    proofInput: {
                                        ...component.proofInput,
                                        publicRandomnessHex: '00'.repeat(32),
                                    },
                                },
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [ballotPackage],
                            },
                            {
                                ok: false,
                                backendAvailable: true,
                                operation: 'verifyAggregateDerivationProof',
                            },
                        );

                        const commitmentPolynomialVector =
                            component.aggregateCommitment.commitmentPolynomialVector.map(
                                (polynomial, polynomialIndex) =>
                                    polynomialIndex === 0
                                        ? polynomial.map(
                                              (
                                                  coefficient,
                                                  coefficientIndex,
                                              ) =>
                                                  coefficientIndex === 0
                                                      ? coefficient === '0'
                                                          ? '1'
                                                          : '0'
                                                      : coefficient,
                                          )
                                        : polynomial,
                            );
                        await verifyAggregateSubcase(
                            'mutated aggregate commitment polynomial',
                            {
                                closeRecord: postCloseEvidence.closeRecord,
                                component: {
                                    ...component,
                                    aggregateCommitment: {
                                        ...component.aggregateCommitment,
                                        commitmentPolynomialVector,
                                    },
                                },
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [ballotPackage],
                            },
                            {
                                ok: false,
                                backendAvailable: true,
                                operation: 'verifyAggregateDerivationProof',
                            },
                        );
                    },
                );
            },
            aggregateHeavyStepTimeoutMs,
        );

        registerAggregateBridgeEncryptionTest({
            aggregateHeavyStepTimeoutMs,
            getAggregateComponentContext: () =>
                requireAggregateComponentContext(aggregateComponentContext),
            runAggregateTestStep,
        });

        it(
            'builds aggregate-ready record from proof-checked bridge contributions',
            async () => {
                await runAggregateTestStep(
                    'Build aggregate-ready record from checked bridge contributions',
                    async () => {
                        const firstComponentContext =
                            requireAggregateComponentContext(
                                aggregateComponentContext,
                            );
                        const completedBallotPackageContext =
                            requireBallotPackageContext(ballotPackageContext);
                        const secondComponentContext =
                            createAggregateComponentContextForReceiver({
                                ballotPackageContext:
                                    completedBallotPackageContext,
                                contributorRosterPosition: 2,
                                proverRandomnessHex: '67'.repeat(32),
                            });
                        const { kernel, statement } = firstComponentContext;
                        const setupPackage = await runAggregateSubcase(
                            'generate shared BGV setup package',
                            () =>
                                kernel.generateBgvPassiveSetup({
                                    ceremonyId: statement.ceremonyId,
                                    manifestHash: statement.manifestHash,
                                    participants: Array.from(
                                        { length: statement.participantCount },
                                        (_unusedValue, participantIndex) => ({
                                            boardPosition: participantIndex + 3,
                                            rosterPosition: participantIndex,
                                            trusteeIdentity: `receiver-${participantIndex}`,
                                        }),
                                    ),
                                    rosterHash: statement.rosterHash,
                                    setupSeed:
                                        'accepted-encrypted-aggregate-evaluator-test-seed',
                                    thresholdProfileHash:
                                        statement.thresholdProfileHash,
                                }),
                        );
                        const {
                            aggregateSelectionPolicyHash,
                            bridgeWitnessPrivacyProfileHash,
                            heParamHash,
                        } = deriveSharedBridgeSupportHashes({
                            ballotSetHash: statement.ballotSetHash,
                            ceremonyId: statement.ceremonyId,
                            setupPackageHash: setupPackage.setupPackageHash,
                        });
                        type PendingBridgeProofRecordInput = Parameters<
                            typeof createPendingBridgeProofRecordFromBridgeEvidence
                        >[0];
                        const createBridgeContributor = async (
                            componentContext: AggregateComponentContext,
                        ): Promise<
                            BridgeContributorContext & {
                                readonly contribution: AggregateContribution;
                            }
                        > => {
                            const bridgeEncryption = (await runAggregateSubcase(
                                `generate bridge proof for ${componentContext.statement.contributorIdentity}`,
                                () =>
                                    kernel.generateAggregateBridgeEncryption({
                                        aggregateDerivationComponent:
                                            componentContext.component,
                                        aggregateSelectionPolicyHash,
                                        aggregateWitness:
                                            componentContext.witness,
                                        bridgeWitnessPrivacyProfileHash,
                                        closeRecord:
                                            componentContext.postCloseEvidence
                                                .closeRecord,
                                        contributorActionContext:
                                            componentContext.postCloseEvidence
                                                .contributorActionContext,
                                        countedBallotPackages: [
                                            completedBallotPackageContext.ballotPackage,
                                        ],
                                        heParamHash,
                                        includeCanonicalBytesHex: true,
                                        setupPackage,
                                    }),
                            )) as Record<string, unknown>;
                            expect(bridgeEncryption).toMatchObject({
                                bridgeProofVerificationStatus:
                                    'BridgeProofRelationChecked',
                                developmentKeyOnly: false,
                                encryptionRandomnessSeedSource: 'fresh-csprng',
                                ok: true,
                                operation: 'generateAggregateBridgeEncryption',
                                proverRandomnessSource: 'fresh-csprng',
                                aggregateDerivationVerificationScope:
                                    'AggregateDerivationFullVerificationChecked',
                                randomnessSourceEvidence: {
                                    callerSuppliedDevelopmentRandomness: false,
                                    claimBearingEntropyEvidence: false,
                                },
                            });

                            const bridgeVerification =
                                (await runAggregateSubcase(
                                    `verify bridge proof for ${componentContext.statement.contributorIdentity}`,
                                    () =>
                                        kernel.verifyAggregateBridgeEncryption({
                                            aggregateDerivationComponent:
                                                componentContext.component,
                                            aggregateSelectionPolicyHash,
                                            bridgeEncryption,
                                            bridgeWitnessPrivacyProfileHash,
                                            closeRecord:
                                                componentContext
                                                    .postCloseEvidence
                                                    .closeRecord,
                                            contributorActionContext:
                                                componentContext
                                                    .postCloseEvidence
                                                    .contributorActionContext,
                                            countedBallotPackages: [
                                                completedBallotPackageContext.ballotPackage,
                                            ],
                                            heParamHash,
                                            setupPackage,
                                        }),
                                )) as Record<string, unknown>;
                            expect(bridgeVerification).toMatchObject({
                                bridgeProofVerificationStatus:
                                    'BridgeProofRelationChecked',
                                developmentKeyOnly: false,
                                encryptionRandomnessSeedSource: 'fresh-csprng',
                                ok: true,
                                operation: 'verifyAggregateBridgeEncryption',
                                proverRandomnessSource: 'fresh-csprng',
                                aggregateDerivationVerificationScope:
                                    'AggregateDerivationFullVerificationChecked',
                                randomnessSourceEvidence: {
                                    callerSuppliedDevelopmentRandomness: false,
                                    claimBearingEntropyEvidence: false,
                                },
                            });

                            const bridgeProofRecord =
                                createPendingBridgeProofRecordFromBridgeEvidence(
                                    {
                                        aggregateDerivationComponent:
                                            componentContext.component,
                                        aggregateSelectionPolicyHash,
                                        bridgeEncryptionEvidence:
                                            bridgeEncryption as PendingBridgeProofRecordInput['bridgeEncryptionEvidence'],
                                        bridgeEvidenceVerification:
                                            bridgeVerification as PendingBridgeProofRecordInput['bridgeEvidenceVerification'],
                                        bridgeWitnessPrivacyProfileHash,
                                        heParamHash,
                                        setupPackage,
                                    },
                                );
                            const actionContext = componentContext
                                .postCloseEvidence
                                .contributorActionContext as ActionContext;
                            const contribution =
                                createAggregateContributionFromBridgeProofRecord(
                                    {
                                        actionContext,
                                        boardPosition:
                                            componentContext.statement
                                                .contributorRosterPosition,
                                        bridgeProofRecord,
                                        closeRecordHash:
                                            componentContext.postCloseEvidence
                                                .closeRecordHash,
                                        signature: ({
                                            aggregateContributionHash,
                                        }) =>
                                            createAggregateContributionSignature(
                                                {
                                                    actionContext,
                                                    aggregateContributionHash,
                                                    manifestHash:
                                                        componentContext
                                                            .statement
                                                            .manifestHash,
                                                },
                                            ),
                                    },
                                );

                            return {
                                bridgeEncryption,
                                bridgeVerification,
                                componentContext,
                                contribution,
                            };
                        };
                        const bridgeContributors = [
                            await createBridgeContributor(
                                firstComponentContext,
                            ),
                            await createBridgeContributor(
                                secondComponentContext,
                            ),
                        ];
                        const contributions = bridgeContributors.map(
                            (bridgeContributor) =>
                                bridgeContributor.contribution,
                        );
                        const selection =
                            selectFirstValidAggregateContributions({
                                aggregateContributionQuorum: 2,
                                contributions,
                                currentRecoveryEpochMap:
                                    createCurrentRecoveryEpochMap(
                                        contributions,
                                    ),
                                expectedAggregateSelectionPolicyHash:
                                    aggregateSelectionPolicyHash,
                                requiredPostVotingClosedContextHash:
                                    firstComponentContext.statement
                                        .postVotingClosedContextHash,
                            });
                        expect(selection.ok).toBe(true);
                        expect(selection.refusedObjects).toEqual([]);
                        expect(
                            selection.selectedContributions.map(
                                (contribution) =>
                                    contribution.contributorRosterPosition,
                            ),
                        ).toEqual([1, 2]);
                        const aggregateReadyRecord = createAggregateReadyRecord(
                            {
                                aggregateContributionQuorum: 2,
                                firstValidOrderHash:
                                    selection.firstValidOrderHash ?? '',
                                rosterSize: statement.participantCount,
                                selectedContributions:
                                    selection.selectedContributions,
                            },
                        );
                        const aggregateReadyVerification =
                            verifyAggregateReadyRecordStructure(
                                aggregateReadyRecord,
                            );
                        expect(aggregateReadyVerification).toMatchObject({
                            aggregateReadyRecordHash:
                                aggregateReadyRecord.aggregateReadyRecordHash,
                            ok: true,
                        });
                        expect(
                            aggregateReadyVerification.statusLabels,
                        ).toContain('AggregateReadyRecordVerified');
                    },
                );
            },
            aggregateBallotProofPackageTimeoutMs,
        );

        it(
            'rejects public witness leakage and wraparound certificates',
            async () => {
                await runAggregateTestStep(
                    'Reject public witness leakage and wraparound certificates',
                    async () => {
                        const {
                            aggregateCommitment,
                            ballotPackage,
                            certificate,
                            component,
                            generatedAggregateProof,
                            kernel,
                            postCloseEvidence,
                            proofBuild,
                            statement,
                            witness,
                        } = requireAggregateComponentContext(
                            aggregateComponentContext,
                        );
                        const componentWithLeakedWitness = {
                            ...component,
                            witness,
                        };
                        await runAggregateSubcase(
                            'component structure rejects leaked witness object',
                            () => {
                                expect(
                                    verifyAggregateDerivationComponentStructure(
                                        componentWithLeakedWitness,
                                    ),
                                ).toMatchObject({
                                    ok: false,
                                    unresolvedReason: 'BallotPackageInvalid',
                                });
                            },
                        );
                        await runAggregateSubcase(
                            'kernel verifier rejects leaked witness object',
                            () => {
                                expect(
                                    kernel.verifyAggregateDerivationProof({
                                        closeRecord:
                                            postCloseEvidence.closeRecord,
                                        component: componentWithLeakedWitness,
                                        contributorActionContext:
                                            postCloseEvidence.contributorActionContext,
                                        countedBallotPackages: [ballotPackage],
                                    }),
                                ).toMatchObject({
                                    ok: false,
                                    unresolvedReason: 'BallotPackageInvalid',
                                });
                            },
                        );
                        for (const publicWitnessFieldName of forbiddenBridgeWitnessFieldNames) {
                            const componentWithPublicWitness = {
                                ...component,
                                [publicWitnessFieldName]: {
                                    fieldName: publicWitnessFieldName,
                                    leaked: true,
                                },
                            };

                            expect(
                                verifyAggregateDerivationComponentStructure(
                                    componentWithPublicWitness,
                                ),
                                publicWitnessFieldName,
                            ).toMatchObject({
                                ok: false,
                                unresolvedReason: 'BallotPackageInvalid',
                            });
                        }
                        await runAggregateSubcase(
                            'kernel verifier rejects representative public witness field',
                            () => {
                                const publicWitnessFieldName =
                                    forbiddenBridgeWitnessFieldNames[0];
                                const componentWithPublicWitness = {
                                    ...component,
                                    [publicWitnessFieldName]: {
                                        fieldName: publicWitnessFieldName,
                                        leaked: true,
                                    },
                                };

                                expect(
                                    kernel.verifyAggregateDerivationProof({
                                        closeRecord:
                                            postCloseEvidence.closeRecord,
                                        component: componentWithPublicWitness,
                                        contributorActionContext:
                                            postCloseEvidence.contributorActionContext,
                                        countedBallotPackages: [ballotPackage],
                                    }),
                                    publicWitnessFieldName,
                                ).toMatchObject({
                                    ok: false,
                                    unresolvedReason: 'BallotPackageInvalid',
                                });
                            },
                        );

                        const componentWithWraparoundCertificate =
                            createAggregateDerivationComponent({
                                aggregateCommitment,
                                proofBytesHex: String(
                                    generatedAggregateProof.proofBytesHex,
                                ),
                                proofInput: proofBuild.proofInput,
                                shareCommitmentMessageBoundCert:
                                    certificateThatPermitsWraparound(
                                        certificate,
                                    ),
                                statement,
                            });
                        await runAggregateSubcase(
                            'component structure rejects wraparound certificate',
                            () => {
                                expect(
                                    verifyAggregateDerivationComponentStructure(
                                        componentWithWraparoundCertificate,
                                    ),
                                ).toMatchObject({
                                    ok: false,
                                    unresolvedReason:
                                        'BallotPrivacyProfileInvalid',
                                });
                            },
                        );
                        await runAggregateSubcase(
                            'kernel verifier rejects wraparound certificate',
                            () => {
                                expect(
                                    kernel.verifyAggregateDerivationProof({
                                        closeRecord:
                                            postCloseEvidence.closeRecord,
                                        component:
                                            componentWithWraparoundCertificate,
                                        contributorActionContext:
                                            postCloseEvidence.contributorActionContext,
                                        countedBallotPackages: [ballotPackage],
                                    }),
                                ).toMatchObject({
                                    ok: false,
                                    unresolvedReason: 'BallotPackageInvalid',
                                });
                            },
                        );
                    },
                );
            },
            aggregateHeavyStepTimeoutMs,
        );
    },
);
