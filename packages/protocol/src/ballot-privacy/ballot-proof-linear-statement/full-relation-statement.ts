import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofStatement,
    ProtocolDigest,
} from '@sealed-lattice/types';

import {
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    receiverPayloadPlaintextBits,
    receiverReferenceKey,
    validateSourceRingDegree,
} from './component-bundle.js';
import {
    requireContractDecimalStringField,
    requireContractIntegerField,
} from './receiver-encryption-proof-statement.js';
import type {
    BallotProofComponentBundleStatement,
    BallotProofComponentProjectionWitness,
    BallotProofComponentProofStatementPlan,
    BallotProofComponentStatement,
    BallotProofFullRelationLinearProofStatement,
    BallotProofRecordGenerationSecretState,
    BallotProofStructuredReceiverEncryptionProofStatement,
    DensePolynomial,
    DensePolynomialVector,
} from './statement-contracts.js';
import {
    fullBallotProofParameterProfileId,
    linearProofRelation,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
} from './statement-contracts.js';
import {
    deriveLinearStatementDigest,
    deriveStatementMatrixDigest,
    deriveTargetVectorDigest,
} from './statement-digests.js';
import {
    constantPolynomial,
    decimalBigInt,
    receiverEncryptionChunkWitness,
    signedConstantPolynomial,
    signedPolynomialCoefficient,
    zeroPolynomial,
} from './witness-accessors.js';

const witnessBoundSquaredFromParameterSet = (
    parameterSet: unknown,
    label: string,
): string =>
    requireContractDecimalStringField({
        contract: parameterSet,
        fieldName: 'witnessL2BoundSquared',
        label,
    });

const sourceRingDegreeFromParameterSet = (
    parameterSet: unknown,
    label: string,
): number =>
    requireContractIntegerField({
        contract: parameterSet,
        fieldName: 'ringDegree',
        label,
    });

const coefficientModulusFromParameterSet = (
    parameterSet: unknown,
    label: string,
): bigint =>
    decimalBigInt(
        requireContractDecimalStringField({
            contract: parameterSet,
            fieldName: 'coefficientModulus',
            label,
        }),
        `${label}.coefficientModulus`,
    );

const requireMatchingDigest = (input: {
    readonly actual: ProtocolDigest | undefined;
    readonly expected: ProtocolDigest;
    readonly label: string;
}): void => {
    if (input.actual !== input.expected) {
        throw new Error(`${input.label} does not match the ballot statement.`);
    }
};

const assertReceiverReferencesMatch = (input: {
    readonly contextReferences: readonly {
        readonly receiverIdentity: string;
        readonly receiverRosterPosition: number;
        readonly [key: string]: unknown;
    }[];
    readonly digestFieldName: string;
    readonly label: string;
    readonly statementReferences: readonly {
        readonly receiverIdentity: string;
        readonly receiverRosterPosition: number;
        readonly [key: string]: unknown;
    }[];
}): void => {
    const contextReferenceByKey = new Map(
        input.contextReferences.map((reference) => [
            receiverReferenceKey(reference),
            reference,
        ]),
    );
    if (input.statementReferences.length !== input.contextReferences.length) {
        throw new Error(
            `${input.label} references must match the relation public context.`,
        );
    }
    for (const statementReference of input.statementReferences) {
        const contextReference = contextReferenceByKey.get(
            receiverReferenceKey(statementReference),
        );
        if (contextReference === undefined) {
            throw new Error(
                `${input.label} reference is missing from the relation public context.`,
            );
        }
        if (
            statementReference[input.digestFieldName] !==
            contextReference[input.digestFieldName]
        ) {
            throw new Error(
                `${input.label} digest does not match the relation public context.`,
            );
        }
    }
};

const assertBallotStatementMatchesPublicContext = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly statement: BallotProofStatement;
}): void => {
    const statement = input.statement;
    const publicContext = input.publicContext;
    requireMatchingDigest({
        actual: publicContext.ballotProofStatementDigest,
        expected: statement.ballotProofStatementDigest,
        label: 'Relation public context ballot proof statement digest',
    });
    requireMatchingDigest({
        actual: publicContext.manifestDigest,
        expected: statement.manifestDigest,
        label: 'Manifest digest',
    });
    requireMatchingDigest({
        actual: publicContext.rosterDigest,
        expected: statement.rosterDigest,
        label: 'Roster digest',
    });
    requireMatchingDigest({
        actual: publicContext.pollSpecDigest,
        expected: statement.pollSpecDigest,
        label: 'Poll spec digest',
    });
    requireMatchingDigest({
        actual: publicContext.actionContextDigest,
        expected: statement.actionContextDigest,
        label: 'Action context digest',
    });
    requireMatchingDigest({
        actual: publicContext.rosterExternalAcceptanceDigest,
        expected: statement.rosterExternalAcceptanceDigest,
        label: 'Roster acceptance digest',
    });
    requireMatchingDigest({
        actual: publicContext.receiverKeyRoot,
        expected: statement.receiverKeyRoot,
        label: 'Receiver key root',
    });
    requireMatchingDigest({
        actual: publicContext.receiverKeyProofRoot,
        expected: statement.receiverKeyProofRoot,
        label: 'Receiver key proof root',
    });
    requireMatchingDigest({
        actual: publicContext.shareCommitmentProfileDigest,
        expected: statement.shareCommitmentProfileDigest,
        label: 'Share commitment profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.receiverEncryptionProfileDigest,
        expected: statement.receiverEncryptionProfileDigest,
        label: 'Receiver encryption profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.ballotProofProfileDigest,
        expected: statement.ballotProofProfileDigest,
        label: 'Ballot proof profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.scoreMembershipProfileDigest,
        expected: statement.scoreMembershipProfileDigest,
        label: 'Score membership profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.ballotScoreEncodingProfileDigest,
        expected: statement.ballotScoreEncodingProfileDigest,
        label: 'Ballot score encoding profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.ballotShareLayoutProfileDigest,
        expected: statement.ballotShareLayoutProfileDigest,
        label: 'Ballot share layout profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.aggregateInputEncodingProfileDigest,
        expected: statement.aggregateInputEncodingProfileDigest,
        label: 'Aggregate input encoding profile digest',
    });
    requireMatchingDigest({
        actual: publicContext.encodedShareVectorLayoutDigest,
        expected: statement.encodedShareVectorLayoutDigest,
        label: 'Encoded share vector layout digest',
    });
    requireMatchingDigest({
        actual: publicContext.encodedAggregateLayoutDigest,
        expected: statement.encodedAggregateLayoutDigest,
        label: 'Encoded aggregate layout digest',
    });
    requireMatchingDigest({
        actual: publicContext.shareCommitmentMessageBoundCertDigest,
        expected: statement.shareCommitmentMessageBoundCertDigest,
        label: 'Share commitment message-bound certificate digest',
    });
    if (statement.optionCount !== input.relationInput.optionCount) {
        throw new Error(
            'Ballot proof statement option count must match the relation input.',
        );
    }
    if (statement.shareVectorWidth !== input.relationInput.optionCount * 11) {
        throw new Error(
            'Ballot proof statement share vector width must match the encoded score layout.',
        );
    }
    assertReceiverReferencesMatch({
        contextReferences: publicContext.receiverPublicKeys,
        digestFieldName: 'receiverPublicKeyDigest',
        label: 'Receiver public-key',
        statementReferences: statement.receiverPublicKeys,
    });
    assertReceiverReferencesMatch({
        contextReferences: publicContext.receiverPayloads,
        digestFieldName: 'receiverPayloadDigest',
        label: 'Receiver payload',
        statementReferences: statement.receiverPayloads,
    });
    assertReceiverReferencesMatch({
        contextReferences: publicContext.shareCommitments,
        digestFieldName: 'shareCommitmentDigest',
        label: 'Share commitment',
        statementReferences: statement.shareCommitments,
    });
};

const assertFullReceiverPayloadsAreExplicit = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): void => {
    const expectedPlaintextBitLength =
        input.relationInput.optionCount *
            11 *
            receiverShareRepresentativeBitLength +
        64 * receiverOpeningRandomnessBitLength;
    const expectedCiphertextChunkCount = Math.ceil(
        expectedPlaintextBitLength / receiverEncryptionModuleDegree,
    );
    const payloadsByReceiver = new Map(
        input.publicContext.receiverPayloads.map((payload) => [
            receiverReferenceKey(payload),
            payload,
        ]),
    );

    for (const receiver of input.relationInput.receivers) {
        const payload = payloadsByReceiver.get(receiverReferenceKey(receiver));
        if (
            payload?.ciphertextChunks === undefined ||
            payload.ciphertextChunkCount === undefined ||
            payload.plaintextBitLength === undefined
        ) {
            throw new Error(
                'Full ballot proof record generation requires explicit receiver payload ciphertext chunks and plaintext bit lengths.',
            );
        }
        if (payload.plaintextBitLength !== expectedPlaintextBitLength) {
            throw new Error(
                'Full ballot proof record generation requires the full encoded-score receiver payload bit length.',
            );
        }
        if (
            payload.ciphertextChunkCount !== expectedCiphertextChunkCount ||
            payload.ciphertextChunks.length !== expectedCiphertextChunkCount
        ) {
            throw new Error(
                'Full ballot proof record generation requires the canonical receiver payload ciphertext chunk count.',
            );
        }
    }
};

const deriveFullRelationBindingDigest = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        componentBundleStatementDigest:
            input.componentBundleStatement.componentBundleStatementDigest,
        proofComponentsDigest:
            input.loweredStatement.backendStatement.proofComponentsDigest,
        purpose: 'ballot-proof-full-relation-binding-v1',
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
    });

const fullRelationBindingWitnessScalar = (
    relationBindingDigest: ProtocolDigest,
): bigint => 1n + (BigInt(`0x${relationBindingDigest.slice(0, 16)}`) % 127n);

const buildFullRelationLinearProofStatement = (input: {
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterSet: unknown;
}): {
    readonly linearStatement: BallotProofFullRelationLinearProofStatement;
    readonly secretState: BallotProofRecordGenerationSecretState;
} => {
    const sourceRingDegree = sourceRingDegreeFromParameterSet(
        input.parameterSet,
        'ballot proof parameter set',
    );
    validateSourceRingDegree(sourceRingDegree);
    const coefficientModulus = coefficientModulusFromParameterSet(
        input.parameterSet,
        'ballot proof parameter set',
    );
    const witnessL2BoundSquared = witnessBoundSquaredFromParameterSet(
        input.parameterSet,
        'ballot proof parameter set',
    );
    const relationBindingDigest = deriveFullRelationBindingDigest(input);
    const bindingScalar = fullRelationBindingWitnessScalar(
        relationBindingDigest,
    );
    const statementMatrixCoefficients = [
        [
            constantPolynomial({
                coefficient: 1n,
                coefficientModulus,
                sourceRingDegree,
            }),
        ],
    ];
    const targetVectorCoefficients = [
        constantPolynomial({
            coefficient: -bindingScalar,
            coefficientModulus,
            sourceRingDegree,
        }),
    ];
    const statementMatrixDigest = deriveStatementMatrixDigest(
        statementMatrixCoefficients,
    );
    const targetVectorDigest = deriveTargetVectorDigest(
        targetVectorCoefficients,
    );
    const statementPayload: Omit<
        BallotProofFullRelationLinearProofStatement,
        'statementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.loweredStatement.publicContext.ballotProofStatementDigest ===
        undefined
            ? {}
            : {
                  ballotProofStatementDigest:
                      input.loweredStatement.publicContext
                          .ballotProofStatementDigest,
              }),
        coefficientModulus: coefficientModulus.toString(),
        componentBundleStatementDigest:
            input.componentBundleStatement.componentBundleStatementDigest,
        objectType: 'BallotProofLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: fullBallotProofParameterProfileId,
        projectionCoverage: 'full-encoded-score-ballot-relation',
        relation: linearProofRelation,
        relationBindingDigest,
        relationBindingKind: 'component-bundle-and-lowered-relation',
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        ringDegree: sourceRingDegree,
        statementColumns: 1,
        statementMatrixCoefficients,
        statementMatrixDigest,
        statementRows: 1,
        matrixCoefficientRepresentation: 'canonicalUnsignedSourceModulus',
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorCoefficients,
        targetVectorDigest,
        witnessL2BoundSquared,
    };

    return {
        linearStatement: {
            ...statementPayload,
            statementDigest: deriveLinearStatementDigest(statementPayload),
        },
        secretState: {
            sourceWitnessCoefficients: [
                signedConstantPolynomial({
                    coefficient: bindingScalar,
                    sourceRingDegree,
                }),
            ],
        },
    };
};

const signedNumberPolynomial = (input: {
    readonly coefficients: readonly number[];
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    if (input.coefficients.length !== input.sourceRingDegree) {
        throw new Error(
            'Structured receiver-encryption witness polynomial has the wrong degree.',
        );
    }

    return input.coefficients.map((coefficient) => {
        if (!Number.isSafeInteger(coefficient)) {
            throw new Error(
                'Structured receiver-encryption witness coefficient must be a safe integer.',
            );
        }

        return signedPolynomialCoefficient(BigInt(coefficient));
    });
};

const plaintextChunkPolynomial = (input: {
    readonly chunkIndex: number;
    readonly plaintextBits: readonly number[];
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    const polynomial = zeroPolynomial(input.sourceRingDegree);
    const chunkOffset = input.chunkIndex * input.sourceRingDegree;
    for (
        let coefficientIndex = 0;
        coefficientIndex < input.sourceRingDegree;
        coefficientIndex += 1
    ) {
        polynomial[coefficientIndex] =
            input.plaintextBits[chunkOffset + coefficientIndex] ?? 0;
    }

    return polynomial;
};

const secretStateForStructuredReceiverEncryptionStatement = (input: {
    readonly projectionWitness: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly structuredStatement: BallotProofStructuredReceiverEncryptionProofStatement;
}): BallotProofRecordGenerationSecretState => {
    const sourceWitnessCoefficients: (DensePolynomial | undefined)[] =
        Array.from(
            { length: input.structuredStatement.statementColumns },
            () => undefined,
        );
    const writeWitnessPolynomial = (
        columnIndex: number,
        polynomial: DensePolynomial,
    ): void => {
        if (
            !Number.isSafeInteger(columnIndex) ||
            columnIndex < 0 ||
            columnIndex >= sourceWitnessCoefficients.length
        ) {
            throw new Error(
                'Structured receiver-encryption witness column is outside the statement shape.',
            );
        }
        if (sourceWitnessCoefficients[columnIndex] !== undefined) {
            throw new Error(
                'Structured receiver-encryption witness column is duplicated.',
            );
        }
        sourceWitnessCoefficients[columnIndex] = polynomial;
    };

    for (const receiverRow of input.structuredStatement.receiverRows) {
        const plaintextBits = receiverPayloadPlaintextBits({
            plaintextBitLength: receiverRow.plaintextBitLength,
            projectionWitness: input.projectionWitness,
            receiverRosterPosition: receiverRow.receiverRosterPosition,
            relationInput: input.relationInput,
        });
        for (const ciphertextChunk of receiverRow.ciphertextChunks) {
            const chunkWitness = receiverEncryptionChunkWitness(
                input.projectionWitness,
                receiverRow.receiverRosterPosition,
                ciphertextChunk.chunkIndex,
            );
            for (
                let vectorIndex = 0;
                vectorIndex < receiverEncryptionModuleRank;
                vectorIndex += 1
            ) {
                writeWitnessPolynomial(
                    ciphertextChunk.randomnessPolynomialColumnIndices[
                        vectorIndex
                    ] ??
                        (() => {
                            throw new Error(
                                'Structured receiver-encryption randomness column is missing.',
                            );
                        })(),
                    signedNumberPolynomial({
                        coefficients:
                            chunkWitness.encryptionRandomnessVector[
                                vectorIndex
                            ] ??
                            (() => {
                                throw new Error(
                                    'Structured receiver-encryption randomness witness is missing.',
                                );
                            })(),
                        sourceRingDegree:
                            input.structuredStatement.sourceRingDegree,
                    }),
                );
                writeWitnessPolynomial(
                    ciphertextChunk.firstNoisePolynomialColumnIndices[
                        vectorIndex
                    ] ??
                        (() => {
                            throw new Error(
                                'Structured receiver-encryption first-noise column is missing.',
                            );
                        })(),
                    signedNumberPolynomial({
                        coefficients:
                            chunkWitness.firstNoiseVector[vectorIndex] ??
                            (() => {
                                throw new Error(
                                    'Structured receiver-encryption first-noise witness is missing.',
                                );
                            })(),
                        sourceRingDegree:
                            input.structuredStatement.sourceRingDegree,
                    }),
                );
            }
            writeWitnessPolynomial(
                ciphertextChunk.secondNoiseColumnIndex,
                signedNumberPolynomial({
                    coefficients: chunkWitness.secondNoisePolynomial,
                    sourceRingDegree:
                        input.structuredStatement.sourceRingDegree,
                }),
            );
            writeWitnessPolynomial(
                ciphertextChunk.plaintextPolynomialColumnIndex,
                plaintextChunkPolynomial({
                    chunkIndex: ciphertextChunk.chunkIndex,
                    plaintextBits,
                    sourceRingDegree:
                        input.structuredStatement.sourceRingDegree,
                }),
            );
        }
    }

    if (
        sourceWitnessCoefficients.some(
            (witnessPolynomial) => witnessPolynomial === undefined,
        )
    ) {
        throw new Error(
            'Structured receiver-encryption witness did not fill every statement column.',
        );
    }

    return {
        sourceWitnessCoefficients:
            sourceWitnessCoefficients as DensePolynomialVector,
    };
};

const componentStatementById = (
    componentBundleStatement: BallotProofComponentBundleStatement,
): ReadonlyMap<
    BallotPrivacyBackendProofComponentId,
    BallotProofComponentStatement
> =>
    new Map(
        componentBundleStatement.componentStatements.map(
            (componentStatement) => [
                componentStatement.componentId,
                componentStatement,
            ],
        ),
    );

const componentPlanById = (
    componentStatementPlans: readonly BallotProofComponentProofStatementPlan[],
): ReadonlyMap<
    BallotPrivacyBackendProofComponentId,
    BallotProofComponentProofStatementPlan
> =>
    new Map(
        componentStatementPlans.map((componentStatementPlan) => [
            componentStatementPlan.componentId,
            componentStatementPlan,
        ]),
    );

const requiredComponentStatement = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly componentStatementsById: ReadonlyMap<
        BallotPrivacyBackendProofComponentId,
        BallotProofComponentStatement
    >;
}): BallotProofComponentStatement => {
    const componentStatement = input.componentStatementsById.get(
        input.componentId,
    );
    if (componentStatement === undefined) {
        throw new Error(
            `Component statement ${input.componentId} is missing from the full bundle.`,
        );
    }

    return componentStatement;
};

const requiredComponentStatementPlan = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly componentPlansById: ReadonlyMap<
        BallotPrivacyBackendProofComponentId,
        BallotProofComponentProofStatementPlan
    >;
}): BallotProofComponentProofStatementPlan => {
    const componentStatementPlan = input.componentPlansById.get(
        input.componentId,
    );
    if (componentStatementPlan === undefined) {
        throw new Error(
            `Component proof statement plan ${input.componentId} is missing from the full bundle.`,
        );
    }

    return componentStatementPlan;
};

export {
    witnessBoundSquaredFromParameterSet,
    sourceRingDegreeFromParameterSet,
    assertBallotStatementMatchesPublicContext,
    assertFullReceiverPayloadsAreExplicit,
    buildFullRelationLinearProofStatement,
    secretStateForStructuredReceiverEncryptionStatement,
    componentStatementById,
    componentPlanById,
    requiredComponentStatement,
    requiredComponentStatementPlan,
};
