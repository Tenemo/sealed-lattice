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
    ProofEncoding,
    ProofParameterSet,
} from './fixture-inputs.js';
import {
    ballotProofStatement,
    claimBearingReceiverPayloadShells,
    claimBearingShareCommitmentShells,
    cloneJsonValue,
    mandatoryProfileRelationInput,
    publicContextAndProjectionWitness,
    receiverKeyProofRootEvidence,
    smallUnsafeRelationInput,
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

const deterministicRandomness = (): BallotProofRecordGenerationRandomness => ({
    componentProverRandomnessHexes: {
        'payload-plaintext-field-component': 'a2'.repeat(32),
        'receiver-encryption-component': 'a4'.repeat(32),
        'score-and-shamir-field-component': '07'.repeat(32),
        'share-commitment-component': '0c'.repeat(32),
    },
    componentPublicRandomnessHexes: {
        'payload-plaintext-field-component': '22'.repeat(32),
        'receiver-encryption-component': '44'.repeat(32),
        'receiver-key-binding-component': '55'.repeat(32),
        'score-and-shamir-field-component': '11'.repeat(32),
        'share-commitment-component': '33'.repeat(32),
    },
    proverRandomnessHex: '07'.repeat(32),
    publicRandomnessHex: '00'.repeat(32),
});

const createBallotProofRecordGenerationFixtureWithOptions = (
    options: BallotProofRecordGenerationFixtureOptions,
): BallotProofRecordGenerationFixture => {
    const relationInput = options.relationInput;
    const { projectionWitness, publicContext: contextWithoutStatement } =
        publicContextAndProjectionWitness(relationInput);
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
    const randomness = deterministicRandomness();
    const request = {
        ...buildBallotProofRecordGenerationRequest({
            proofContracts,
            projectionWitness,
            publicContext,
            randomness,
            relationInput,
            statement,
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

export const createBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixtureWithOptions({
            relationInput: smallUnsafeRelationInput(),
            topOptionCount: 2,
            unsafeSmallRosterAcknowledged: true,
        });

export const createMandatoryProfileBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixtureWithOptions({
            relationInput: mandatoryProfileRelationInput(),
            topOptionCount: 20,
        });

export const createMandatoryProfileBallotProofRecordBenchmarkFixture =
    (): BallotProofRecordGenerationFixture =>
        createMandatoryProfileBallotProofRecordGenerationFixture();

export const createWasmBallotProofRecordGenerationFixture =
    (): BallotProofRecordGenerationFixture =>
        createBallotProofRecordGenerationFixture();
