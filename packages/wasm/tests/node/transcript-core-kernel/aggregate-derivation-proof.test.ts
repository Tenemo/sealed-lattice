import type {
    ClaimBearingBallotPackage,
    ShareCommitmentMessageBoundCert,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification';
import {
    aggregateWitnessFromReceiverPlaintext,
    buildAggregateDerivationProofInput,
    buildAggregateDerivationStatement,
    createAggregateDerivationComponent,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    sumAggregateDerivationWitnesses,
    verifyAggregateDerivationComponentStructure,
    type AggregateDerivationWitnessInput,
} from '#packages/protocol/src/ballot-privacy/index';
import {
    createMandatoryProfileBallotProofRecordBenchmarkFixture,
    createWasmBallotProofRecordGenerationFixture,
} from '#tests/support/ballot-privacy-proof-record-generation-fixtures';

const digest = (label: string): string =>
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
        ballotPackageDigest:
            input.fixture.request.statement.ballotPackageDigest,
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
): AggregateDerivationWitnessInput => {
    const receiverPayloadPlaintext =
        fixture.projectionWitness.receiverPayloadPlaintexts?.find(
            (plaintext) => plaintext.receiverRosterPosition === 1,
        );
    const shareCommitmentOpening =
        fixture.projectionWitness.shareCommitmentOpenings.find(
            (opening) => opening.receiverRosterPosition === 1,
        );
    if (
        receiverPayloadPlaintext === undefined ||
        shareCommitmentOpening === undefined
    ) {
        throw new Error('Fixture should include receiver-1 witness material.');
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
    const { shareCommitmentMessageBoundCertDigest, ...withoutDigest } =
        certificatePayload;
    void shareCommitmentMessageBoundCertDigest;

    return {
        ...withoutDigest,
        shareCommitmentMessageBoundCertDigest: deriveProtocolDigest(
            'ShareCommitmentMessageBoundCertDigest',
            withoutDigest,
        ),
    } as unknown as ShareCommitmentMessageBoundCert;
};

const createPostCloseEvidence = (input: {
    readonly ceremonyId: string;
    readonly contributorIdentity: string;
    readonly electionManifestDigest: string;
    readonly rosterExternalAcceptanceDigest: string;
    readonly votingClosedBoardHeadDigest: string;
}): {
    readonly closeRecord: Record<string, unknown>;
    readonly contributorActionContext: Record<string, unknown>;
    readonly closeRecordDigest: string;
    readonly postVotingClosedContextDigest: string;
} => {
    const closeRecordPayload = {
        boardPosition: 0,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        closeKind: 'VotingClosed',
        closedBoardHeadDigest: input.votingClosedBoardHeadDigest,
        electionManifestDigest: input.electionManifestDigest,
        objectType: 'CloseRecord',
        objectVersion: 1,
        organizerIdentity: 'organizer-1',
    };
    const closeRecordDigest = deriveProtocolDigest(
        'CloseRecordDigest',
        closeRecordPayload,
    );
    const postVotingClosedContextDigest = deriveProtocolDigest(
        'PostVotingClosedContextDigest',
        {
            ceremonyId: input.ceremonyId,
            closeRecordDigest,
            electionManifestDigest: input.electionManifestDigest,
            votingClosedBoardHeadDigest: input.votingClosedBoardHeadDigest,
        },
    );
    const contributorActionContextPayload = {
        acceptedRecoveryEpochUpdateDigest: null,
        actionSequence: 1,
        boardHeadDigest: input.votingClosedBoardHeadDigest,
        boardSequence: 7,
        ceremonyId: input.ceremonyId,
        contextDigest: postVotingClosedContextDigest,
        deviceEpoch: 0,
        electionManifestDigest: input.electionManifestDigest,
        recoveryEpoch: 0,
        recoveryPolicyDigest: digest('recovery-policy'),
        rosterExternalAcceptanceDigest: input.rosterExternalAcceptanceDigest,
        signerIdentity: input.contributorIdentity,
    };
    const contributorActionContextDigest = deriveProtocolDigest(
        'ActionContextDigest',
        contributorActionContextPayload,
    );

    return {
        closeRecord: {
            ...closeRecordPayload,
            closeRecordDigest,
            postVotingClosedContextDigest,
        },
        closeRecordDigest,
        contributorActionContext: {
            ...contributorActionContextPayload,
            actionContextDigest: contributorActionContextDigest,
        },
        postVotingClosedContextDigest,
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

const runAggregateTestStep = async <T>(
    name: string,
    action: () => T | Promise<T>,
): Promise<T> => {
    const isGitHubActions = process.env.GITHUB_ACTIONS === 'true';
    const startedAtMilliseconds = Date.now();
    if (isGitHubActions) {
        console.log(`::group::Aggregate derivation: ${name}`);
    }
    console.log(`Aggregate derivation step started: ${name}`);
    try {
        return await action();
    } finally {
        const elapsedSeconds = (
            (Date.now() - startedAtMilliseconds) /
            1000
        ).toFixed(1);
        console.log(
            `Aggregate derivation step finished: ${name} (${elapsedSeconds}s)`,
        );
        if (isGitHubActions) {
            console.log('::endgroup::');
        }
    }
};

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
                            generation: ballotProofGeneration as Record<
                                string,
                                unknown
                            >,
                        });
                        const certificate = fixtureCertificate(fixture);
                        expect(
                            certificate.shareCommitmentMessageBoundCertDigest,
                        ).toBe(
                            fixture.statement
                                .shareCommitmentMessageBoundCertDigest,
                        );
                        const postCloseEvidence = createPostCloseEvidence({
                            ceremonyId: fixture.statement.ceremonyId,
                            contributorIdentity: 'receiver-1',
                            electionManifestDigest:
                                fixture.statement.manifestDigest,
                            rosterExternalAcceptanceDigest:
                                fixture.statement
                                    .rosterExternalAcceptanceDigest,
                            votingClosedBoardHeadDigest:
                                digest('closed-board-head'),
                        });
                        const {
                            proofBytesHex: omittedProofBytesHex,
                            ...ballotPackageWithoutProofBytes
                        } = ballotPackage;
                        void omittedProofBytesHex;
                        const statementInput = {
                            ballotPackages: [ballotPackage],
                            closeRecordDigest:
                                postCloseEvidence.closeRecordDigest,
                            contributorActionContextDigest: postCloseEvidence
                                .contributorActionContext
                                .actionContextDigest as string,
                            contributorIdentity: 'receiver-1',
                            contributorRosterExternalAcceptanceDigest:
                                fixture.statement
                                    .rosterExternalAcceptanceDigest,
                            contributorRosterPosition: 1,
                            postVotingClosedContextDigest:
                                postCloseEvidence.postVotingClosedContextDigest,
                            unsafeSmallRosterAcknowledged: false,
                            votingClosedBoardHeadDigest: postCloseEvidence
                                .closeRecord.closedBoardHeadDigest as string,
                        } satisfies AggregateStatementInput;

                        return {
                            ballotPackage,
                            ballotPackageWithoutProofBytes:
                                ballotPackageWithoutProofBytes as ClaimBearingBallotPackage,
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
                                unsafeSmallRosterAcknowledged: true,
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
                            aggregateDerivationComponentDigest:
                                component.aggregateDerivationComponentDigest,
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
                    () => {
                        const {
                            ballotPackage,
                            ballotPackageWithoutProofBytes,
                            component,
                            kernel,
                            postCloseEvidence,
                        } = requireAggregateComponentContext(
                            aggregateComponentContext,
                        );
                        const verification =
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [ballotPackage],
                            });
                        expect(verification).toMatchObject({
                            ok: true,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                            unresolvedReason: null,
                        });
                        expect(verification.statusLabels).toEqual([
                            'AggregateDerivationRelationChecked',
                            'AggregateDerivationProofClaimClosureMissing',
                        ]);
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                            }),
                        ).toMatchObject({
                            ok: false,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [],
                            }),
                        ).toMatchObject({
                            ok: false,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [
                                    ballotPackage,
                                    ballotPackage,
                                ],
                            }),
                        ).toMatchObject({
                            ok: false,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [
                                    ballotPackageWithoutProofBytes,
                                ],
                            }),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPackageInvalid',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: {
                                    ...postCloseEvidence.closeRecord,
                                    closeKind: 'RegistrationClosed',
                                },
                                component,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [ballotPackage],
                            }),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPackageInvalid',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component,
                                contributorActionContext: {
                                    ...postCloseEvidence.contributorActionContext,
                                    signerIdentity: 'receiver-2',
                                },
                                countedBallotPackages: [ballotPackage],
                            }),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPackageInvalid',
                        });

                        expect(
                            kernel.verifyAggregateDerivationProof({
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
                            }),
                        ).toMatchObject({
                            ok: false,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                        });

                        expect(
                            kernel.verifyAggregateDerivationProof({
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
                            }),
                        ).toMatchObject({
                            ok: false,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                        });

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
                        expect(
                            kernel.verifyAggregateDerivationProof({
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
                            }),
                        ).toMatchObject({
                            ok: false,
                            backendAvailable: true,
                            operation: 'verifyAggregateDerivationProof',
                        });
                    },
                );
            },
            aggregateHeavyStepTimeoutMs,
        );

        it(
            'generates M9 bridge encryption evidence without public witness material',
            async () => {
                await runAggregateTestStep(
                    'Generate M9 bridge encryption evidence',
                    () => {
                        const { component, kernel, statement, witness } =
                            requireAggregateComponentContext(
                                aggregateComponentContext,
                            );
                        const setupPackage = kernel.generateBgvPassiveSetup({
                            ceremonyId: statement.ceremonyId,
                            manifestDigest: statement.manifestDigest,
                            participants: [
                                {
                                    boardPosition: 3,
                                    rosterPosition: 0,
                                    trusteeIdentity: 'receiver-0',
                                },
                                {
                                    boardPosition: 4,
                                    rosterPosition: 1,
                                    trusteeIdentity: 'receiver-1',
                                },
                                {
                                    boardPosition: 5,
                                    rosterPosition: 2,
                                    trusteeIdentity: 'receiver-2',
                                },
                            ],
                            rosterDigest: statement.rosterDigest,
                            setupSeed: 'm9-bridge-test-seed',
                            thresholdProfileDigest:
                                statement.thresholdProfileDigest,
                        });
                        const aggregateSelectionPolicyDigest =
                            deriveProtocolDigest(
                                'AggregateSelectionPolicyDigest',
                                {
                                    purpose:
                                        'm9-kernel-bridge-test-selection-policy',
                                    statementDigest:
                                        statement.aggregateDerivationStatementDigest,
                                },
                            );
                        const bridgeWitnessPrivacyProfileDigest =
                            deriveProtocolDigest(
                                'BridgeWitnessPrivacyProfileDigest',
                                {
                                    purpose:
                                        'm9-kernel-bridge-test-witness-privacy',
                                    statementDigest:
                                        statement.aggregateDerivationStatementDigest,
                                },
                            );
                        const heParamDigest = deriveProtocolDigest(
                            'HEParamDigest',
                            {
                                purpose: 'm9-kernel-bridge-test-he-param',
                                statementDigest:
                                    statement.aggregateDerivationStatementDigest,
                            },
                        );
                        const bridgeEncryption =
                            kernel.generateAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest,
                                aggregateDerivationComponent: component,
                                aggregateWitness: witness,
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest,
                                includeCanonicalBytesHex: true,
                                proverRandomnessHex: '77'.repeat(32),
                                setupPackage,
                            }) as Record<string, unknown>;

                        expect(bridgeEncryption).toMatchObject({
                            bridgeProofVerificationStatus:
                                'BridgeProofBackendPending',
                            ok: true,
                            operation: 'generateAggregateBridgeEncryption',
                        });
                        expect(bridgeEncryption.statusLabels).toEqual([
                            'M9BridgePlaintextAssembled',
                            'M9BridgeCiphertextGenerated',
                            'CollectivePublicKeyRootBound',
                            'CoefficientDomainCanonical',
                            'BridgeProofBackendStillRequired',
                        ]);
                        expect(
                            String(
                                bridgeEncryption.encryptedAggregateShareCiphertextRoot,
                            ),
                        ).toHaveLength(128);
                        expect(
                            String(bridgeEncryption.bridgeProofProfileDigest),
                        ).toHaveLength(128);
                        expect(
                            String(bridgeEncryption.bridgeProofStatementDigest),
                        ).toHaveLength(128);
                        expect(
                            String(
                                bridgeEncryption.bridgeProofTargetContractDigest,
                            ),
                        ).toHaveLength(128);
                        const bridgeProofPayload = JSON.parse(
                            Buffer.from(
                                String(bridgeEncryption.bridgeProofBytesHex),
                                'hex',
                            ).toString('utf8'),
                        ) as Record<string, unknown>;
                        const bridgeProofStatement =
                            bridgeProofPayload.bridgeProofStatement as Record<
                                string,
                                unknown
                            >;
                        const bridgeProofTargetContract =
                            bridgeProofStatement.bridgeProofTargetContract as Record<
                                string,
                                unknown
                            >;
                        expect(
                            bridgeProofPayload.bridgeProofProfileDigest,
                        ).toBe(bridgeEncryption.bridgeProofProfileDigest);
                        expect(
                            bridgeProofPayload.bridgeProofStatementDigest,
                        ).toBe(bridgeEncryption.bridgeProofStatementDigest);
                        expect(
                            bridgeProofPayload.bridgeProofTargetContractDigest,
                        ).toBe(
                            bridgeEncryption.bridgeProofTargetContractDigest,
                        );
                        expect(bridgeProofPayload).toMatchObject({
                            aggregateQuotientCoordinateCount: 220,
                            aggregateReducedCoordinateCount: 220,
                            aggregateRelationChallengeHex: expect.any(
                                String,
                            ) as string,
                            aggregateRelationCommitmentDigest: expect.any(
                                String,
                            ) as string,
                            aggregateRelationSubproofSizeBytes: expect.any(
                                Number,
                            ) as number,
                        });
                        expect(
                            String(
                                bridgeProofPayload.aggregateRelationChallengeHex,
                            ),
                        ).toHaveLength(48);
                        expect(
                            String(
                                bridgeProofPayload.aggregateRelationCommitmentDigest,
                            ),
                        ).toHaveLength(128);
                        expect(
                            bridgeProofPayload.bridgeProofStatement,
                        ).toMatchObject({
                            aggregateDerivationComponentDigest:
                                component.aggregateDerivationComponentDigest,
                            aggregateShareCommitmentDigest:
                                component.aggregateCommitment
                                    .aggregateShareCommitmentDigest,
                            aggregateSelectionPolicyDigest,
                            bgvEncryptionProofSubrelation:
                                'SealedLatticeBoundedEncryptionRelation',
                            bridgeWitnessPrivacyProfileDigest,
                            bridgeProofTargetContractDigest:
                                bridgeEncryption.bridgeProofTargetContractDigest,
                            heParamDigest,
                            objectType: 'AggregateBridgeProofStatement',
                            bridgeProofTargetContract: {
                                ciphertextCoefficientEquationCount: 1_048_576,
                                dataPrimeCount: 16,
                                naiveLinearExpansionBackendStatus:
                                    'InfeasibleForClaimBearingM9',
                                plaintextRootProofBindingStatus:
                                    'PlaintextRootProofBindingPending',
                                proofFriendlyPlaintextBindingRequired: true,
                                publicPlaintextRootAcceptedAsClosureEvidence: false,
                                sameWitnessLinkageModel:
                                    'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired',
                                sampledDiagnosticsAcceptedForVerification: false,
                                separateSubproofsAcceptedForClosure: false,
                                separateSubproofsClosureStatus:
                                    'RejectedForM9Closure',
                                sharedWitnessLayout: {
                                    aggregateIntegerShareCoordinateCount: 220,
                                    aggregateQuotientCoordinateCount: 220,
                                    aggregateReducedCoordinateCount: 220,
                                    aggregateRelationRowCount: 224,
                                    bgvCiphertextEquationRowCount: 1_048_576,
                                    bridgeProofProfileId:
                                        'EncryptedAggregateBridge-v1',
                                    commitmentOpeningCoordinateCount: 64,
                                    encryptionErrorCoefficientCount: 65_536,
                                    encryptionRandomizerCoefficientCount: 32_768,
                                    layoutModel:
                                        'single-shared-response-vector-v1',
                                    objectType:
                                        'AggregateBridgeSharedWitnessLayout',
                                    objectVersion: 1,
                                    plaintextCoefficientColumnRole:
                                        'bgv-batch-encoding-and-bgv-encryption-message',
                                    plaintextCoefficientCount: 32_768,
                                    plaintextEncodingQuotientCount: 32_768,
                                    plaintextEncodingRelationRowCount: 32_768,
                                    sameWitnessLinkageModel:
                                        'SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired',
                                    separateSubproofsAcceptedForClosure: false,
                                    sharedReducedCoordinateColumnRole:
                                        'aggregate-reduction-and-bgv-plaintext-slot',
                                    sharedResponseScalarCount: 164_564,
                                },
                                sharedWitnessLayoutDigest: expect.any(
                                    String,
                                ) as string,
                            },
                            sampledPublicRelationCheckPolicyDigest: expect.any(
                                String,
                            ) as string,
                            relationRequirements: {
                                sampledOnlyBridgeVerificationAccepted: false,
                                sharedWitnessBindingRequired: true,
                            },
                        });
                        expect(
                            bridgeEncryption.sampledPublicRelationCheckPolicy,
                        ).toMatchObject({
                            acceptedForBridgeProofVerification: false,
                            diagnosticOnly: true,
                            fullBridgeProofRequired: true,
                            sampledOnlyBridgeVerificationAccepted: false,
                        });
                        expect(
                            bridgeProofPayload.scopedBridgeRelationClosure,
                        ).toBe(false);
                        expect(JSON.stringify(bridgeEncryption)).not.toMatch(
                            /aggregateIntegerShareVector|aggregateOpeningRandomness|layoutPlaintextWitness|bgvPlaintext|encryptionRandomness|encryptionError|sourceWitnessCoefficients/u,
                        );
                        expect(
                            kernel.validateBgvCiphertextObject({
                                canonicalBytesHex: String(
                                    bridgeEncryption.canonicalBytesHex,
                                ),
                                expectedCiphertextRoot: String(
                                    bridgeEncryption.ciphertextRoot,
                                ),
                            }),
                        ).toMatchObject({
                            ok: true,
                            objectKind: 'ciphertext',
                        });
                        const bridgeVerification =
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest,
                                aggregateDerivationComponent: component,
                                bridgeEncryption,
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest,
                                setupPackage,
                            }) as Record<string, unknown>;
                        expect(bridgeVerification).toMatchObject({
                            backendAvailable: true,
                            bridgeEvidenceVerificationStatus:
                                'BridgeProofEvidenceChecked',
                            bridgeProofVerificationStatus:
                                'BridgeProofBackendPending',
                            ok: true,
                            operation: 'verifyAggregateBridgeEncryption',
                        });
                        expect(bridgeVerification.statusLabels).toEqual([
                            'BridgeProofEvidenceChecked',
                            'BridgeProofBackendStillRequired',
                            'FinalBridgeTheoremPending',
                        ]);
                        expect(String(bridgeVerification.bridgeProofRoot)).toBe(
                            String(bridgeEncryption.bridgeProofRoot),
                        );
                        expect(
                            String(
                                bridgeVerification.bridgeProofTargetContractDigest,
                            ),
                        ).toBe(
                            String(
                                bridgeEncryption.bridgeProofTargetContractDigest,
                            ),
                        );
                        const pendingBridgeProofRecord =
                            createPendingBridgeProofRecordFromBridgeEvidence({
                                aggregateDerivationComponent: component,
                                aggregateSelectionPolicyDigest,
                                bridgeEncryptionEvidence:
                                    bridgeEncryption as PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'],
                                bridgeEvidenceVerification:
                                    bridgeVerification as PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'],
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest,
                                setupPackage:
                                    setupPackage as PendingBridgeProofRecordFromEvidenceInput['setupPackage'],
                            });
                        expect(pendingBridgeProofRecord).toMatchObject({
                            bridgeProofTargetContractDigest:
                                bridgeEncryption.bridgeProofTargetContractDigest,
                            bridgeProofVerificationStatus:
                                'BridgeProofBackendPending',
                            encryptedAggregateShareCiphertextRoot:
                                bridgeEncryption.encryptedAggregateShareCiphertextRoot,
                            proofRoot: bridgeVerification.bridgeProofRoot,
                            proofStatementDigest:
                                bridgeVerification.bridgeProofStatementDigest,
                        });

                        const expectBridgeVerificationRejected = (
                            mutatedBridgeEncryption: Record<string, unknown>,
                        ): void => {
                            expect(
                                kernel.verifyAggregateBridgeEncryption({
                                    aggregateSelectionPolicyDigest,
                                    aggregateDerivationComponent: component,
                                    bridgeEncryption: mutatedBridgeEncryption,
                                    bridgeWitnessPrivacyProfileDigest,
                                    heParamDigest,
                                    setupPackage,
                                }),
                            ).toMatchObject({
                                ok: false,
                                operation: 'verifyAggregateBridgeEncryption',
                            });
                        };
                        const replaceLastHexDigit = (
                            value: unknown,
                        ): string => {
                            const hex = String(value);
                            const replacement = hex.endsWith('0') ? '1' : '0';

                            return `${hex.slice(0, -1)}${replacement}`;
                        };
                        const bridgeEncryptionWithUpdatedProofPayload = (
                            proofOverrides: Record<string, unknown>,
                            bridgeOverrides: Record<string, unknown>,
                        ): Record<string, unknown> => {
                            const proofPayload = {
                                ...(JSON.parse(
                                    Buffer.from(
                                        String(
                                            bridgeEncryption.bridgeProofBytesHex,
                                        ),
                                        'hex',
                                    ).toString('utf8'),
                                ) as Record<string, unknown>),
                                ...proofOverrides,
                            };
                            const bridgePayload = {
                                ...bridgeEncryption,
                                ...bridgeOverrides,
                            };
                            const bridgeProofBytesHex = Buffer.from(
                                canonicalJson(proofPayload),
                                'utf8',
                            ).toString('hex');
                            const bridgeProofBytesDigest = deriveProtocolDigest(
                                'ProofBytesDigest',
                                {
                                    proofBytesHex: bridgeProofBytesHex,
                                    purpose:
                                        'm9-bridge-encryption-proof-bytes-v1',
                                },
                            );
                            const bridgeProofRoot = deriveProtocolDigest(
                                'BridgeProofRecordDigest',
                                {
                                    aggregateDerivationComponentDigest:
                                        component.aggregateDerivationComponentDigest,
                                    aggregateDerivationStatementDigest:
                                        statement.aggregateDerivationStatementDigest,
                                    bridgeProofProfileDigest:
                                        bridgePayload.bridgeProofProfileDigest,
                                    bridgeProofStatementDigest:
                                        bridgePayload.bridgeProofStatementDigest,
                                    bgvPublicKeyRoot:
                                        bridgePayload.bgvPublicKeyRoot,
                                    collectivePublicKeyRoot:
                                        bridgePayload.collectivePublicKeyRoot,
                                    encryptedAggregateShareCiphertextRoot:
                                        bridgePayload.encryptedAggregateShareCiphertextRoot,
                                    proofBytesDigest: bridgeProofBytesDigest,
                                    purpose:
                                        'm9-bridge-encryption-proof-root-v1',
                                },
                            );

                            return {
                                ...bridgePayload,
                                bridgeProofBytesDigest,
                                bridgeProofBytesHex,
                                bridgeProofRoot,
                            };
                        };
                        expect(
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest:
                                    deriveProtocolDigest(
                                        'AggregateSelectionPolicyDigest',
                                        {
                                            purpose:
                                                'm9-kernel-bridge-test-wrong-selection-policy',
                                            statementDigest:
                                                statement.aggregateDerivationStatementDigest,
                                        },
                                    ),
                                aggregateDerivationComponent: component,
                                bridgeEncryption,
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest,
                                setupPackage,
                            }),
                        ).toMatchObject({
                            ok: false,
                            operation: 'verifyAggregateBridgeEncryption',
                        });
                        expect(
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest,
                                aggregateDerivationComponent: component,
                                bridgeEncryption,
                                bridgeWitnessPrivacyProfileDigest:
                                    deriveProtocolDigest(
                                        'BridgeWitnessPrivacyProfileDigest',
                                        {
                                            purpose:
                                                'm9-kernel-bridge-test-wrong-witness-privacy',
                                            statementDigest:
                                                statement.aggregateDerivationStatementDigest,
                                        },
                                    ),
                                heParamDigest,
                                setupPackage,
                            }),
                        ).toMatchObject({
                            ok: false,
                            operation: 'verifyAggregateBridgeEncryption',
                        });
                        expect(
                            kernel.verifyAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest,
                                aggregateDerivationComponent: component,
                                bridgeEncryption,
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest: deriveProtocolDigest(
                                    'HEParamDigest',
                                    {
                                        purpose:
                                            'm9-kernel-bridge-test-wrong-he-param',
                                        statementDigest:
                                            statement.aggregateDerivationStatementDigest,
                                    },
                                ),
                                setupPackage,
                            }),
                        ).toMatchObject({
                            ok: false,
                            operation: 'verifyAggregateBridgeEncryption',
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            bgvPlaintext: [1, 2, 3],
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            bridgeProofVerificationStatus:
                                'BridgeProofRelationChecked',
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            privateMaterialDisclosure: {
                                ...(bridgeEncryption.privateMaterialDisclosure as Record<
                                    string,
                                    unknown
                                >),
                                encryptionRandomizerMaterialExported: true,
                            },
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            bridgeProofBytesDigest: '0'.repeat(128),
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            bridgeProofStatementDigest: '0'.repeat(128),
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            bridgeProofTargetContractDigest: '0'.repeat(128),
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            bridgeProofBytesHex: replaceLastHexDigit(
                                bridgeEncryption.bridgeProofBytesHex,
                            ),
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            canonicalBytesHex: replaceLastHexDigit(
                                bridgeEncryption.canonicalBytesHex,
                            ),
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            collectivePublicKeyRoot: '0'.repeat(128),
                        });
                        expectBridgeVerificationRejected({
                            ...bridgeEncryption,
                            profileDigest: '0'.repeat(128),
                        });
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    plaintextRoot: '0'.repeat(128),
                                },
                                {
                                    plaintextRoot: '0'.repeat(128),
                                },
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    bridgeProofStatementDigest: '0'.repeat(128),
                                },
                                {
                                    bridgeProofStatementDigest: '0'.repeat(128),
                                },
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    bridgeProofStatement: {
                                        ...(bridgeProofPayload.bridgeProofStatement as Record<
                                            string,
                                            unknown
                                        >),
                                        postVotingClosedContextDigest:
                                            '0'.repeat(128),
                                    },
                                },
                                {},
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    bridgeProofStatement: {
                                        ...bridgeProofStatement,
                                        bridgeProofTargetContract: {
                                            ...bridgeProofTargetContract,
                                            sampledDiagnosticsAcceptedForVerification: true,
                                        },
                                    },
                                },
                                {},
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    aggregateRelationChallengeHex: '0'.repeat(
                                        48,
                                    ),
                                },
                                {},
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    aggregateRelationCommitmentDigest:
                                        '0'.repeat(128),
                                },
                                {},
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    aggregateRelationSubproofSizeBytes: 1,
                                },
                                {},
                            ),
                        );
                        expectBridgeVerificationRejected(
                            bridgeEncryptionWithUpdatedProofPayload(
                                {
                                    aggregateReducedCoordinateCount: 219,
                                },
                                {},
                            ),
                        );

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
                        expect(
                            kernel.generateAggregateBridgeEncryption({
                                aggregateSelectionPolicyDigest,
                                aggregateDerivationComponent: component,
                                aggregateWitness: wrongWitness,
                                bridgeWitnessPrivacyProfileDigest,
                                heParamDigest,
                                proverRandomnessHex: '77'.repeat(32),
                                setupPackage,
                            }),
                        ).toMatchObject({
                            ok: false,
                            operation: 'generateAggregateBridgeEncryption',
                            unresolvedReason: 'BallotPackageInvalid',
                        });
                    },
                );
            },
            aggregateHeavyStepTimeoutMs,
        );

        it(
            'rejects public witness leakage and wraparound certificates',
            async () => {
                await runAggregateTestStep(
                    'Reject public witness leakage and wraparound certificates',
                    () => {
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
                        expect(
                            verifyAggregateDerivationComponentStructure(
                                componentWithLeakedWitness,
                            ),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPackageInvalid',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component: componentWithLeakedWitness,
                                contributorActionContext:
                                    postCloseEvidence.contributorActionContext,
                                countedBallotPackages: [ballotPackage],
                            }),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPackageInvalid',
                        });
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
                            expect(
                                kernel.verifyAggregateDerivationProof({
                                    closeRecord: postCloseEvidence.closeRecord,
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
                        }

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
                        expect(
                            verifyAggregateDerivationComponentStructure(
                                componentWithWraparoundCertificate,
                            ),
                        ).toMatchObject({
                            ok: false,
                            unresolvedReason: 'BallotPrivacyProfileInvalid',
                        });
                        expect(
                            kernel.verifyAggregateDerivationProof({
                                closeRecord: postCloseEvidence.closeRecord,
                                component: componentWithWraparoundCertificate,
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
            aggregateHeavyStepTimeoutMs,
        );
    },
);
