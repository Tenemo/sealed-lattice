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

describe('aggregate derivation proof through the transcript-core kernel', () => {
    it('generates and verifies a witness-clean aggregate derivation component', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixture =
            createMandatoryProfileBallotProofRecordBenchmarkFixture();
        const ballotProofGeneration = kernel.generateBallotProofRecord(
            fixture.request,
        );
        expect(ballotProofGeneration).toMatchObject({
            ok: true,
            generatedProofBytes: true,
            operation: 'generateBallotProofRecord',
            unresolvedReason: null,
        });
        const ballotPackage = createFixtureBallotPackage({
            fixture,
            generation: ballotProofGeneration as Record<string, unknown>,
        });
        const certificate = fixtureCertificate(fixture);
        expect(certificate.shareCommitmentMessageBoundCertDigest).toBe(
            fixture.statement.shareCommitmentMessageBoundCertDigest,
        );
        const postCloseEvidence = createPostCloseEvidence({
            ceremonyId: fixture.statement.ceremonyId,
            contributorIdentity: 'receiver-1',
            electionManifestDigest: fixture.statement.manifestDigest,
            rosterExternalAcceptanceDigest:
                fixture.statement.rosterExternalAcceptanceDigest,
            votingClosedBoardHeadDigest: digest('closed-board-head'),
        });
        const statementInput = {
            ballotPackages: [ballotPackage],
            closeRecordDigest: postCloseEvidence.closeRecordDigest,
            contributorActionContextDigest: postCloseEvidence
                .contributorActionContext.actionContextDigest as string,
            contributorIdentity: 'receiver-1',
            contributorRosterExternalAcceptanceDigest:
                fixture.statement.rosterExternalAcceptanceDigest,
            contributorRosterPosition: 1,
            postVotingClosedContextDigest:
                postCloseEvidence.postVotingClosedContextDigest,
            unsafeSmallRosterAcknowledged: false,
            votingClosedBoardHeadDigest: postCloseEvidence.closeRecord
                .closedBoardHeadDigest as string,
        };
        expect(() =>
            buildAggregateDerivationStatement({
                ...statementInput,
                unsafeSmallRosterAcknowledged: true,
            }),
        ).toThrow(/casual micro-roster acknowledgement is only valid/u);
        expect(() =>
            buildAggregateDerivationStatement({
                ...statementInput,
                ballotPackages: [ballotPackage, ballotPackage],
            }),
        ).toThrow(/duplicates/u);
        const {
            proofBytesHex: omittedProofBytesHex,
            ...packageWithoutProofBytes
        } = ballotPackage;
        void omittedProofBytesHex;
        expect(() =>
            buildAggregateDerivationStatement({
                ...statementInput,
                ballotPackages: [
                    packageWithoutProofBytes as ClaimBearingBallotPackage,
                ],
            }),
        ).toThrow(/proof-byte-bearing/u);
        const { aggregateCommitment, statement } =
            buildAggregateDerivationStatement(statementInput);
        const witness = sumAggregateDerivationWitnesses({
            witnesses: [receiverWitness(fixture)],
        });
        const wrongWitness = {
            ...witness,
            aggregateIntegerShareVector:
                witness.aggregateIntegerShareVector.map(
                    (coordinate, coordinateIndex) =>
                        coordinateIndex === 0 ? coordinate + 1 : coordinate,
                ),
        };
        const wrongProofBuild = buildAggregateDerivationProofInput({
            aggregateCommitment,
            statement,
            witness: wrongWitness,
        });
        expect(
            kernel.generateAggregateDerivationProof({
                proofInput: wrongProofBuild.proofInput,
                proverRandomnessHex: '66'.repeat(32),
                secretState: wrongProofBuild.secretState,
            }),
        ).toMatchObject({
            ok: false,
            unresolvedReason: 'BallotPackageInvalid',
        });

        const proofBuild = buildAggregateDerivationProofInput({
            aggregateCommitment,
            statement,
            witness,
        });
        const generatedAggregateProof = kernel.generateAggregateDerivationProof(
            {
                proofInput: proofBuild.proofInput,
                proverRandomnessHex: '66'.repeat(32),
                secretState: proofBuild.secretState,
            },
        );
        expect(generatedAggregateProof.refusedObjects).toEqual([]);
        expect(generatedAggregateProof).toMatchObject({
            ok: true,
            backendAvailable: true,
            generatedProofBytes: true,
            operation: 'generateAggregateDerivationProof',
            unresolvedReason: null,
        });
        expect(generatedAggregateProof.statusLabels).toContain('pending');
        const component = createAggregateDerivationComponent({
            aggregateCommitment,
            proofBytesHex: String(generatedAggregateProof.proofBytesHex),
            proofInput: proofBuild.proofInput,
            shareCommitmentMessageBoundCert: certificate,
            statement,
        });

        expect(
            verifyAggregateDerivationComponentStructure(component),
        ).toMatchObject({
            ok: true,
            aggregateDerivationComponentDigest:
                component.aggregateDerivationComponentDigest,
        });
        expect(JSON.stringify(component)).not.toMatch(
            /aggregateHistogram|aggregateIntegerShareVector|aggregateOpeningRandomness|aggregateScore|aggregateScoreBits|plaintextComparisonInputs|plaintextScoreBitInputs|proofWitness|rawAggregateWitness|receiverPlaintext|sourceWitnessCoefficients|aggregateInputPlaintext|tPvss|t_pvss/u,
        );

        const verification = kernel.verifyAggregateDerivationProof({
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
        expect(verification.statusLabels).toContain('pending');
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
                countedBallotPackages: [ballotPackage, ballotPackage],
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
                    packageWithoutProofBytes as ClaimBearingBallotPackage,
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
                        ? polynomial.map((coefficient, coefficientIndex) =>
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
                proofBytesHex: String(generatedAggregateProof.proofBytesHex),
                proofInput: proofBuild.proofInput,
                shareCommitmentMessageBoundCert:
                    certificateThatPermitsWraparound(certificate),
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
    }, 1_800_000);
});
