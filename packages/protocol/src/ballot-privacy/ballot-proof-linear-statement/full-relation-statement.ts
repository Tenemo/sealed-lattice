import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { BallotProofStatement, ProtocolHash } from '@sealed-lattice/types';

import {
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
    type BallotPrivacyRelationBackendPublicContext,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    receiverReferenceKey,
    validateSourceRingDegree,
} from './component-bundle.js';
import {
    requireContractDecimalStringField,
    requireContractIntegerField,
} from './proof-contract-validation.js';
import { secretStateForStructuredReceiverEncryptionStatement } from './receiver-encryption-secret-state.js';
import type {
    BallotProofComponentBundleStatement,
    BallotProofComponentProofStatementDescriptor,
    BallotProofComponentStatement,
    BallotProofFullRelationLinearProofStatement,
    BallotProofRecordGenerationSecretState,
} from './statement-contracts.js';
import {
    fullBallotProofParameterProfileId,
    linearProofRelation,
    receiverEncryptionModuleDegree,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
} from './statement-contracts.js';
import {
    deriveLinearStatementHash,
    deriveStatementMatrixHash,
    deriveTargetVectorHash,
} from './statement-hashes.js';
import {
    constantPolynomial,
    decimalBigInt,
    signedConstantPolynomial,
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

const requireMatchingHash = (input: {
    readonly actual: ProtocolHash | undefined;
    readonly expected: ProtocolHash;
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
    readonly hashFieldName: string;
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
            statementReference[input.hashFieldName] !==
            contextReference[input.hashFieldName]
        ) {
            throw new Error(
                `${input.label} hash does not match the relation public context.`,
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
    requireMatchingHash({
        actual: publicContext.ballotProofStatementHash,
        expected: statement.ballotProofStatementHash,
        label: 'Relation public context ballot proof statement hash',
    });
    requireMatchingHash({
        actual: publicContext.manifestHash,
        expected: statement.manifestHash,
        label: 'Manifest hash',
    });
    requireMatchingHash({
        actual: publicContext.rosterHash,
        expected: statement.rosterHash,
        label: 'Roster hash',
    });
    requireMatchingHash({
        actual: publicContext.pollSpecHash,
        expected: statement.pollSpecHash,
        label: 'Poll spec hash',
    });
    requireMatchingHash({
        actual: publicContext.actionContextHash,
        expected: statement.actionContextHash,
        label: 'Action context hash',
    });
    requireMatchingHash({
        actual: publicContext.rosterExternalAcceptanceHash,
        expected: statement.rosterExternalAcceptanceHash,
        label: 'Roster acceptance hash',
    });
    requireMatchingHash({
        actual: publicContext.receiverKeyRoot,
        expected: statement.receiverKeyRoot,
        label: 'Receiver key root',
    });
    requireMatchingHash({
        actual: publicContext.receiverKeyProofRoot,
        expected: statement.receiverKeyProofRoot,
        label: 'Receiver key proof root',
    });
    requireMatchingHash({
        actual: publicContext.shareCommitmentProfileHash,
        expected: statement.shareCommitmentProfileHash,
        label: 'Share commitment profile hash',
    });
    requireMatchingHash({
        actual: publicContext.receiverEncryptionProfileHash,
        expected: statement.receiverEncryptionProfileHash,
        label: 'Receiver encryption profile hash',
    });
    requireMatchingHash({
        actual: publicContext.ballotProofProfileHash,
        expected: statement.ballotProofProfileHash,
        label: 'Ballot proof profile hash',
    });
    requireMatchingHash({
        actual: publicContext.scoreMembershipProfileHash,
        expected: statement.scoreMembershipProfileHash,
        label: 'Score membership profile hash',
    });
    requireMatchingHash({
        actual: publicContext.ballotScoreEncodingProfileHash,
        expected: statement.ballotScoreEncodingProfileHash,
        label: 'Ballot score encoding profile hash',
    });
    requireMatchingHash({
        actual: publicContext.ballotShareLayoutProfileHash,
        expected: statement.ballotShareLayoutProfileHash,
        label: 'Ballot share layout profile hash',
    });
    requireMatchingHash({
        actual: publicContext.aggregateInputEncodingProfileHash,
        expected: statement.aggregateInputEncodingProfileHash,
        label: 'Aggregate input encoding profile hash',
    });
    requireMatchingHash({
        actual: publicContext.encodedShareVectorLayoutHash,
        expected: statement.encodedShareVectorLayoutHash,
        label: 'Encoded share vector layout hash',
    });
    requireMatchingHash({
        actual: publicContext.encodedAggregateLayoutHash,
        expected: statement.encodedAggregateLayoutHash,
        label: 'Encoded aggregate layout hash',
    });
    requireMatchingHash({
        actual: publicContext.shareCommitmentMessageBoundCertHash,
        expected: statement.shareCommitmentMessageBoundCertHash,
        label: 'Share commitment message-bound certificate hash',
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
        hashFieldName: 'receiverPublicKeyHash',
        label: 'Receiver public-key',
        statementReferences: statement.receiverPublicKeys,
    });
    assertReceiverReferencesMatch({
        contextReferences: publicContext.receiverPayloads,
        hashFieldName: 'receiverPayloadHash',
        label: 'Receiver payload',
        statementReferences: statement.receiverPayloads,
    });
    assertReceiverReferencesMatch({
        contextReferences: publicContext.shareCommitments,
        hashFieldName: 'shareCommitmentHash',
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

const deriveFullRelationBindingHash = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        componentBundleStatementHash:
            input.componentBundleStatement.componentBundleStatementHash,
        proofComponentsHash:
            input.loweredStatement.backendStatement.proofComponentsHash,
        purpose: 'ballot-proof-full-relation-binding-v1',
        relationStatementHash: input.loweredStatement.relationStatementHash,
    });

const fullRelationBindingWitnessScalar = (
    relationBindingHash: ProtocolHash,
): bigint => 1n + (BigInt(`0x${relationBindingHash.slice(0, 16)}`) % 127n);

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
    const relationBindingHash = deriveFullRelationBindingHash(input);
    const bindingScalar = fullRelationBindingWitnessScalar(relationBindingHash);
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
    const statementMatrixHash = deriveStatementMatrixHash(
        statementMatrixCoefficients,
    );
    const targetVectorHash = deriveTargetVectorHash(targetVectorCoefficients);
    const statementPayload: Omit<
        BallotProofFullRelationLinearProofStatement,
        'statementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.loweredStatement.publicContext.ballotProofStatementHash ===
        undefined
            ? {}
            : {
                  ballotProofStatementHash:
                      input.loweredStatement.publicContext
                          .ballotProofStatementHash,
              }),
        coefficientModulus: coefficientModulus.toString(),
        componentBundleStatementHash:
            input.componentBundleStatement.componentBundleStatementHash,
        objectType: 'BallotProofLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: fullBallotProofParameterProfileId,
        projectionCoverage: 'full-encoded-score-ballot-relation',
        relation: linearProofRelation,
        relationBindingHash,
        relationBindingKind: 'component-bundle-and-lowered-relation',
        relationStatementHash: input.loweredStatement.relationStatementHash,
        ringDegree: sourceRingDegree,
        statementColumns: 1,
        statementMatrixCoefficients,
        statementMatrixHash,
        statementRows: 1,
        matrixCoefficientRepresentation: 'canonicalUnsignedSourceModulus',
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorCoefficients,
        targetVectorHash,
        witnessL2BoundSquared,
    };

    return {
        linearStatement: {
            ...statementPayload,
            statementHash: deriveLinearStatementHash(statementPayload),
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

const componentDescriptorById = (
    componentStatementDescriptors: readonly BallotProofComponentProofStatementDescriptor[],
): ReadonlyMap<
    BallotPrivacyBackendProofComponentId,
    BallotProofComponentProofStatementDescriptor
> =>
    new Map(
        componentStatementDescriptors.map((componentStatementDescriptor) => [
            componentStatementDescriptor.componentId,
            componentStatementDescriptor,
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

const requiredComponentStatementDescriptor = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly componentDescriptorsById: ReadonlyMap<
        BallotPrivacyBackendProofComponentId,
        BallotProofComponentProofStatementDescriptor
    >;
}): BallotProofComponentProofStatementDescriptor => {
    const componentStatementDescriptor = input.componentDescriptorsById.get(
        input.componentId,
    );
    if (componentStatementDescriptor === undefined) {
        throw new Error(
            `Component proof statement descriptor ${input.componentId} is missing from the full bundle.`,
        );
    }

    return componentStatementDescriptor;
};

export {
    witnessBoundSquaredFromParameterSet,
    sourceRingDegreeFromParameterSet,
    assertBallotStatementMatchesPublicContext,
    assertFullReceiverPayloadsAreExplicit,
    buildFullRelationLinearProofStatement,
    secretStateForStructuredReceiverEncryptionStatement,
    componentStatementById,
    componentDescriptorById,
    requiredComponentStatement,
    requiredComponentStatementDescriptor,
};
