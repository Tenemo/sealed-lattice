import type {
    ClaimBearingBallotPackage,
    ShareCommitmentMessageBoundCert,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '../../../src/index';

import { deriveProtocolDigest } from '#packages/crypto/src/index';
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
