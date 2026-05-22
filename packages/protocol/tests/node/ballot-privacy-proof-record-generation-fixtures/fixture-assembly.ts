import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { BallotProofStatement } from '@sealed-lattice/types';

import {
    buildBallotProofComponentBundleStatement,
    buildBallotProofComponentLinearProofProjection,
    buildBallotProofComponentProofStatementPlans,
    buildBallotProofRecordGenerationRequest,
    buildBallotProofSparseComponentLinearProofStatement,
    buildBallotProofStructuredReceiverEncryptionProofStatement,
    buildEncodedScoreFieldLinearProofProjection,
    buildPackedFieldSparseComponentLinearProofStatement,
    type BallotProofComponentProjectionWitness,
    type BallotProofRecordGenerationProofContracts,
    type BallotProofRecordGenerationRandomness,
} from '../../../src/ballot-privacy/ballot-proof-linear-statement';
import { type BallotPrivacyRelationCompilerInput } from '../../../src/ballot-privacy/index';
import {
    ballotPrivacyBackendProofComponentOrder,
    lowerBallotPrivacyRelationToBackendStatement,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyRelationBackendPublicContext,
} from '../../../src/ballot-privacy/relation-backend-lowering';

import type {
    BallotProofRecordGenerationFixture,
    BallotProofRecordGenerationFixtureOptions,
    BallotProofRecordGenerationStatementContextOptions,
    ProofEncoding,
    ProofParameterSet,
} from './fixture-inputs.js';
import {
    ballotProofStatement,
    casualMicroRosterRelationInput,
    claimBearingReceiverPayloadShells,
    claimBearingShareCommitmentShells,
    cloneJsonValue,
    mandatoryProfileRelationInput,
    publicContextAndProjectionWitness,
    receiverKeyProofRootEvidence,
} from './fixture-inputs.js';

import ballotFieldLinearProofBackendVectorsJson from '#test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json';

const createProofEncoding = (input: {
    readonly profileId: string;
    readonly shortResponseVectorLength: number;
    readonly source: string;
}): ProofEncoding => {
    const baseEncoding = cloneJsonValue(
        (
            ballotFieldLinearProofBackendVectorsJson as {
                readonly proofEncoding: Record<string, unknown>;
            }
        ).proofEncoding,
    );
    delete baseEncoding.expectedProofSizeBytes;

    return {
        ...baseEncoding,
        profileId: input.profileId,
        shortResponseVectorLength: input.shortResponseVectorLength,
        source: input.source,
    };
};

const createParameterSet = (input: {
    readonly coefficientModulus: string;
    readonly profileId: string;
    readonly ringDegree: number;
    readonly source: string;
    readonly statementColumns: number;
    readonly statementRows: number;
    readonly witnessL2BoundSquared: number;
}): ProofParameterSet => ({
    coefficientModulus: input.coefficientModulus,
    profileId: input.profileId,
    proofSystemRingDegree: 64,
    relation: 'A*w + t = 0',
    ringDegree: input.ringDegree,
    source: input.source,
    statementColumns: input.statementColumns,
    statementRows: input.statementRows,
    witnessL2BoundSquared: input.witnessL2BoundSquared,
});

const componentParameterProfileIds: Readonly<
    Record<BallotPrivacyBackendProofComponentId, string>
> = {
    'payload-plaintext-field-component':
        'payload-plaintext-field-linear-compatibility-v1',
    'receiver-encryption-component':
        'receiver-encryption-linear-compatibility-v1',
    'receiver-key-binding-component':
        'receiver-key-binding-linear-compatibility-v1',
    'score-and-shamir-field-component':
        'encoded-score-field-linear-compatibility-v1',
    'share-commitment-component': 'share-commitment-linear-compatibility-v1',
};

const componentEncodingProfileIds: Readonly<
    Record<BallotPrivacyBackendProofComponentId, string>
> = {
    'payload-plaintext-field-component':
        'payload-plaintext-field-linear-proof-encoding-v1',
    'receiver-encryption-component':
        'receiver-encryption-linear-proof-encoding-v1',
    'receiver-key-binding-component':
        'receiver-encryption-linear-proof-encoding-v1',
    'score-and-shamir-field-component':
        'encoded-score-field-linear-proof-encoding-v1',
    'share-commitment-component': 'share-commitment-linear-proof-encoding-v1',
};

const componentProofContracts = (input: {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly statement: BallotProofStatement;
}): BallotProofRecordGenerationProofContracts => {
    const loweringResult = lowerBallotPrivacyRelationToBackendStatement({
        publicContext: input.publicContext,
        relationInput: input.relationInput,
    });
    if (!loweringResult.ok) {
        throw new Error('Fixture relation should lower.');
    }
    const componentBundleStatement = buildBallotProofComponentBundleStatement({
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        loweredStatement: loweringResult.statement,
    });
    const componentPlans = buildBallotProofComponentProofStatementPlans({
        ballotProofStatementDigest: input.statement.ballotProofStatementDigest,
        componentBundleStatement,
        loweredStatement: loweringResult.statement,
    });
    const componentStatementById = new Map(
        componentBundleStatement.componentStatements.map(
            (componentStatement) => [
                componentStatement.componentId,
                componentStatement,
            ],
        ),
    );
    const componentPlanById = new Map(
        componentPlans.map((componentPlan) => [
            componentPlan.componentId,
            componentPlan,
        ]),
    );
    const proofEncodings = {} as Record<
        BallotPrivacyBackendProofComponentId,
        ProofEncoding
    >;
    const proofParameterSets = {} as Record<
        BallotPrivacyBackendProofComponentId,
        ProofParameterSet
    >;
    const putContract = (
        componentId: BallotPrivacyBackendProofComponentId,
        inputContract: {
            readonly coefficientModulus: string;
            readonly ringDegree: number;
            readonly statementColumns: number;
            readonly statementRows: number;
            readonly witnessL2BoundSquared: number;
        },
    ): void => {
        proofParameterSets[componentId] = createParameterSet({
            coefficientModulus: inputContract.coefficientModulus,
            profileId: componentParameterProfileIds[componentId],
            ringDegree: inputContract.ringDegree,
            source: `sealed-lattice/linear-proof/${componentId}-parameters-v1`,
            statementColumns: inputContract.statementColumns,
            statementRows: inputContract.statementRows,
            witnessL2BoundSquared: inputContract.witnessL2BoundSquared,
        });
        proofEncodings[componentId] = createProofEncoding({
            profileId: componentEncodingProfileIds[componentId],
            shortResponseVectorLength:
                inputContract.statementColumns *
                    (inputContract.ringDegree / 64) +
                1,
            source: `sealed-lattice/linear-proof/${componentId}-encoding-v1`,
        });
    };
    const scoreComponentPlan = componentPlanById.get(
        'score-and-shamir-field-component',
    );
    if (scoreComponentPlan === undefined) {
        throw new Error('Score/Shamir component plan should exist.');
    }
    if (
        scoreComponentPlan.proofStatementFormat !==
        'sparse-polynomial-matrix-linear-proof-v1'
    ) {
        const scoreProjection = buildEncodedScoreFieldLinearProofProjection({
            ballotProofStatementDigest:
                input.statement.ballotProofStatementDigest,
            loweredStatement: loweringResult.statement,
            parameterProfileId:
                componentParameterProfileIds[
                    'score-and-shamir-field-component'
                ],
            relationInput: input.relationInput,
            sourceRingDegree: 64,
            witnessL2BoundSquared: '65536',
        });
        putContract('score-and-shamir-field-component', {
            coefficientModulus:
                scoreProjection.linearStatement.coefficientModulus,
            ringDegree: scoreProjection.linearStatement.ringDegree,
            statementColumns: scoreProjection.linearStatement.statementColumns,
            statementRows: scoreProjection.linearStatement.statementRows,
            witnessL2BoundSquared: Number(
                scoreProjection.linearStatement.witnessL2BoundSquared,
            ),
        });
    } else {
        const scoreSparseStatement =
            buildPackedFieldSparseComponentLinearProofStatement({
                ballotProofStatementDigest:
                    input.statement.ballotProofStatementDigest,
                componentId: 'score-and-shamir-field-component',
                loweredStatement: loweringResult.statement,
                parameterProfileId:
                    componentParameterProfileIds[
                        'score-and-shamir-field-component'
                    ],
                relationInput: input.relationInput,
                sourceRingDegree: 64,
                witnessL2BoundSquared: '65536',
            });
        putContract('score-and-shamir-field-component', {
            coefficientModulus: scoreSparseStatement.coefficientModulus,
            ringDegree: scoreSparseStatement.sourceRingDegree,
            statementColumns: scoreSparseStatement.statementColumns,
            statementRows: scoreSparseStatement.statementRows,
            witnessL2BoundSquared: Number(
                scoreSparseStatement.witnessL2BoundSquared,
            ),
        });
    }
    for (const componentId of [
        'payload-plaintext-field-component',
        'share-commitment-component',
    ] as const) {
        const ringDegree = 64;
        const witnessL2BoundSquared =
            componentId === 'payload-plaintext-field-component'
                ? '65536'
                : '1048576';
        const sparseStatement =
            componentId === 'payload-plaintext-field-component' &&
            input.relationInput.optionCount > 1
                ? buildPackedFieldSparseComponentLinearProofStatement({
                      ballotProofStatementDigest:
                          input.statement.ballotProofStatementDigest,
                      componentId,
                      loweredStatement: loweringResult.statement,
                      parameterProfileId:
                          componentParameterProfileIds[componentId],
                      relationInput: input.relationInput,
                      sourceRingDegree: 64,
                      witnessL2BoundSquared,
                  })
                : buildBallotProofSparseComponentLinearProofStatement({
                      ballotProofStatementDigest:
                          input.statement.ballotProofStatementDigest,
                      componentId,
                      loweredStatement: loweringResult.statement,
                      parameterProfileId:
                          componentParameterProfileIds[componentId],
                      sourceRingDegree: ringDegree,
                      witnessL2BoundSquared,
                  });
        if (input.relationInput.optionCount === 1) {
            buildBallotProofComponentLinearProofProjection({
                ballotProofStatementDigest:
                    input.statement.ballotProofStatementDigest,
                componentId,
                loweredStatement: loweringResult.statement,
                parameterProfileId: componentParameterProfileIds[componentId],
                projectionWitness: input.projectionWitness,
                relationInput: input.relationInput,
                sourceRingDegree: ringDegree,
                witnessL2BoundSquared,
            });
        }
        putContract(componentId, {
            coefficientModulus: sparseStatement.coefficientModulus,
            ringDegree: sparseStatement.sourceRingDegree,
            statementColumns: sparseStatement.statementColumns,
            statementRows: sparseStatement.statementRows,
            witnessL2BoundSquared: Number(
                sparseStatement.witnessL2BoundSquared,
            ),
        });
    }
    const receiverEncryptionStatement =
        buildBallotProofStructuredReceiverEncryptionProofStatement({
            ballotProofStatementDigest:
                input.statement.ballotProofStatementDigest,
            componentStatement:
                componentStatementById.get('receiver-encryption-component') ??
                (() => {
                    throw new Error(
                        'Receiver-encryption component statement should exist.',
                    );
                })(),
            loweredStatement: loweringResult.statement,
            parameterProfileId:
                componentParameterProfileIds['receiver-encryption-component'],
            witnessL2BoundSquared: '65536',
        });
    putContract('receiver-encryption-component', {
        coefficientModulus: receiverEncryptionStatement.coefficientModulus,
        ringDegree: receiverEncryptionStatement.sourceRingDegree,
        statementColumns: receiverEncryptionStatement.statementColumns,
        statementRows: receiverEncryptionStatement.statementRows,
        witnessL2BoundSquared: Number(
            receiverEncryptionStatement.witnessL2BoundSquared,
        ),
    });
    const receiverKeyPlan = componentPlanById.get(
        'receiver-key-binding-component',
    );
    if (receiverKeyPlan === undefined) {
        throw new Error('Receiver-key component plan should exist.');
    }
    putContract('receiver-key-binding-component', {
        coefficientModulus: receiverKeyPlan.coefficientModulus,
        ringDegree: 64,
        statementColumns: 1,
        statementRows: 1,
        witnessL2BoundSquared: 65_536,
    });

    return {
        ballotProofEncoding: createProofEncoding({
            profileId: 'full-encoded-score-ballot-linear-proof-encoding-v1',
            shortResponseVectorLength: 2,
            source: 'sealed-lattice/linear-proof/full-ballot-binding-encoding-v1',
        }),
        ballotProofParameterSet: createParameterSet({
            coefficientModulus: '65537',
            profileId: 'full-encoded-score-ballot-linear-compatibility-v1',
            ringDegree: 64,
            source: 'sealed-lattice/linear-proof/full-ballot-binding-parameters-v1',
            statementColumns: 1,
            statementRows: 1,
            witnessL2BoundSquared: 65_536,
        }),
        componentProofEncodings: proofEncodings,
        componentProofParameterSets: proofParameterSets,
    };
};

const deterministicRandomnessHex = (input: {
    readonly randomnessSeedLabel: string;
    readonly randomnessPurpose: string;
}): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-record-generation-fixture-randomness',
        randomnessPurpose: input.randomnessPurpose,
        randomnessSeedLabel: input.randomnessSeedLabel,
    }).slice(0, 64);

const deterministicRandomness = (
    randomnessSeedLabel = 'default-ballot-proof-record-generation-fixture',
): BallotProofRecordGenerationRandomness => ({
    componentProverRandomnessHexes: {
        'payload-plaintext-field-component': deterministicRandomnessHex({
            randomnessPurpose:
                'payload-plaintext-field-component-prover-randomness',
            randomnessSeedLabel,
        }),
        'receiver-encryption-component': deterministicRandomnessHex({
            randomnessPurpose:
                'receiver-encryption-component-prover-randomness',
            randomnessSeedLabel,
        }),
        'score-and-shamir-field-component': deterministicRandomnessHex({
            randomnessPurpose: 'score-and-shamir-component-prover-randomness',
            randomnessSeedLabel,
        }),
        'share-commitment-component': deterministicRandomnessHex({
            randomnessPurpose: 'share-commitment-component-prover-randomness',
            randomnessSeedLabel,
        }),
    },
    componentPublicRandomnessHexes: {
        'payload-plaintext-field-component': deterministicRandomnessHex({
            randomnessPurpose:
                'payload-plaintext-field-component-public-randomness',
            randomnessSeedLabel,
        }),
        'receiver-encryption-component': deterministicRandomnessHex({
            randomnessPurpose:
                'receiver-encryption-component-public-randomness',
            randomnessSeedLabel,
        }),
        'receiver-key-binding-component': deterministicRandomnessHex({
            randomnessPurpose:
                'receiver-key-binding-component-public-randomness',
            randomnessSeedLabel,
        }),
        'score-and-shamir-field-component': deterministicRandomnessHex({
            randomnessPurpose: 'score-and-shamir-component-public-randomness',
            randomnessSeedLabel,
        }),
        'share-commitment-component': deterministicRandomnessHex({
            randomnessPurpose: 'share-commitment-component-public-randomness',
            randomnessSeedLabel,
        }),
    },
    proverRandomnessHex: deterministicRandomnessHex({
        randomnessPurpose: 'top-level-prover-randomness',
        randomnessSeedLabel,
    }),
    publicRandomnessHex: deterministicRandomnessHex({
        randomnessPurpose: 'top-level-public-randomness',
        randomnessSeedLabel,
    }),
});

const createBallotProofRecordGenerationFixtureWithOptions = (
    options: BallotProofRecordGenerationFixtureOptions,
): BallotProofRecordGenerationFixture => {
    const relationInput = options.relationInput;
    const { projectionWitness, publicContext: contextWithoutStatement } =
        publicContextAndProjectionWitness(
            relationInput,
            options.statementContext,
        );
    const claimBearingReceiverPayloads = claimBearingReceiverPayloadShells(
        contextWithoutStatement,
    );
    const claimBearingShareCommitments = claimBearingShareCommitmentShells(
        contextWithoutStatement,
    );
    const receiverKeyEvidence = receiverKeyProofRootEvidence(
        contextWithoutStatement,
    );
    const statement = ballotProofStatement({
        claimBearingReceiverPayloads,
        claimBearingShareCommitments,
        publicContext: contextWithoutStatement,
        relationInput,
        receiverKeyProofRootEvidence: receiverKeyEvidence,
        statementContext: options.statementContext,
        topOptionCount: options.topOptionCount,
    });
    const publicContext = {
        ...contextWithoutStatement,
        ballotProofStatementDigest: statement.ballotProofStatementDigest,
    };
    const proofContracts = componentProofContracts({
        projectionWitness,
        publicContext,
        relationInput,
        statement,
    });
    const randomness = deterministicRandomness(options.randomnessSeedLabel);
    const request = {
        ...buildBallotProofRecordGenerationRequest({
            proofContracts,
            projectionWitness,
            publicContext,
            randomness,
            relationInput,
            statement,
        }),
        ...(options.casualMicroRosterAcknowledged === undefined
            ? {}
            : {
                  casualMicroRosterAcknowledged:
                      options.casualMicroRosterAcknowledged,
              }),
        ...(options.unsafeSmallRosterAcknowledged === undefined
            ? {}
            : {
                  unsafeSmallRosterAcknowledged:
                      options.unsafeSmallRosterAcknowledged,
              }),
    };

    if (
        request.componentProofInputs.length !==
        ballotPrivacyBackendProofComponentOrder.length
    ) {
        throw new Error('Fixture request should include all components.');
    }

    return {
        claimBearingReceiverPayloads,
        claimBearingShareCommitments,
        proofContracts,
        projectionWitness,
        publicContext,
        randomness,
        receiverKeyProofRootEvidence: receiverKeyEvidence,
        relationInput,
        request,
        statement,
    };
};

export const createMicroRosterBallotProofRecordGenerationFixture = (
    rosterSize: number,
): BallotProofRecordGenerationFixture =>
    createBallotProofRecordGenerationFixtureWithOptions({
        casualMicroRosterAcknowledged: true,
        relationInput: casualMicroRosterRelationInput(rosterSize),
        topOptionCount: 2,
        unsafeSmallRosterAcknowledged: true,
    });

export const createBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createMicroRosterBallotProofRecordGenerationFixture(3);

type MandatoryProfileBallotProofRecordGenerationFixtureOptions = {
    readonly normalizedScores?: readonly number[];
    readonly randomnessSeedLabel?: string;
    readonly statementContext?: BallotProofRecordGenerationStatementContextOptions;
};

export const createMandatoryProfileBallotProofRecordGenerationFixture = (
    options: MandatoryProfileBallotProofRecordGenerationFixtureOptions = {},
): BallotProofRecordGenerationFixture =>
    createBallotProofRecordGenerationFixtureWithOptions({
        randomnessSeedLabel: options.randomnessSeedLabel,
        relationInput: mandatoryProfileRelationInput({
            normalizedScores: options.normalizedScores,
        }),
        statementContext: options.statementContext,
        topOptionCount: 20,
    });

export const createMandatoryProfileBallotProofRecordBenchmarkFixture =
    (): BallotProofRecordGenerationFixture =>
        createMandatoryProfileBallotProofRecordGenerationFixture();

export const createWasmBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixture();
