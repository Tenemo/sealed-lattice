import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    ProtocolHash,
} from '@sealed-lattice/types';

import {
    ballotPrivacyBackendProofComponentOrder,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import {
    denseCoefficientCountForComponentProofStatement,
    proofBytesAvailabilityForStatementFormat,
    proofStatementFormatForComponent,
    proofSystemRingDegreeForComponentProofStatement,
    rowBatchTermCount,
    sourceRingDegreeForComponentProofStatement,
    structuredReceiverEncryptionWitnessTermCounts,
} from './component-proof-plan-policy.js';
import {
    buildComponentStatement,
    rowBatchesForComponent,
} from './component-statement-builder.js';
import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentBundleCoverage,
    BallotProofComponentBundleStatement,
    BallotProofComponentProjectionWitness,
    BallotProofComponentProofBundlePayload,
    BallotProofComponentProofRecordPayload,
    BallotProofComponentProofStatementPlan,
    BallotProofComponentStatement,
    BallotProofExplicitComponentId,
    DensePolynomialMatrix,
    DensePolynomialVector,
} from './statement-contracts.js';
import {
    linearProofRelation,
    positiveModulo,
    positiveModuloBigInt,
    receiverEncryptionModulus,
    receiverOpeningRandomnessBitLength,
    receiverPayloadOpeningEncodingOffset,
    receiverShareRepresentativeBitLength,
} from './statement-contracts.js';
import {
    deriveComponentBundleStatementHash,
    deriveComponentProofBundleHash,
    deriveComponentProofRecordHash,
    deriveComponentProofStatementHash,
} from './statement-hashes.js';
import {
    centeredFieldRepresentative,
    componentById,
    polynomialCoefficientBigInt,
    receiverPayloadPlaintextOpeningValue,
    receiverPayloadPlaintextShareValue,
} from './witness-accessors.js';

const resolveBundleCoverage = (
    componentStatements: readonly BallotProofComponentStatement[],
): BallotProofComponentBundleCoverage => {
    const hasCompleteOrderedComponentSet =
        componentStatements.length ===
            ballotPrivacyBackendProofComponentOrder.length &&
        componentStatements.every(
            (componentStatement, componentIndex) =>
                componentStatement.componentId ===
                ballotPrivacyBackendProofComponentOrder[componentIndex],
        );
    const allComponentsLowered = componentStatements.every(
        (componentStatement) =>
            componentStatement.proofLoweringStatus === 'explicitRowsAvailable',
    );

    return hasCompleteOrderedComponentSet && allComponentsLowered
        ? 'full-encoded-score-ballot-relation'
        : 'component-bundle-incomplete';
};

export const buildBallotProofComponentBundleStatement = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentBundleStatement => {
    const statementComponentById = new Map(
        input.loweredStatement.backendStatement.proofComponents.map(
            (component) => [component.componentId, component],
        ),
    );
    const componentStatements = ballotPrivacyBackendProofComponentOrder.flatMap(
        (componentId) => {
            const component = statementComponentById.get(componentId);

            return component === undefined
                ? []
                : [
                      buildComponentStatement({
                          ballotProofStatementHash:
                              input.ballotProofStatementHash,
                          component,
                          loweredStatement: input.loweredStatement,
                      }),
                  ];
        },
    );
    const statementPayload: Omit<
        BallotProofComponentBundleStatement,
        'componentBundleStatementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.ballotProofStatementHash === undefined
            ? {}
            : {
                  ballotProofStatementHash: input.ballotProofStatementHash,
              }),
        bundleCoverage: resolveBundleCoverage(componentStatements),
        componentStatements,
        objectType: 'BallotProofComponentBundleStatement',
        objectVersion: 1,
        relationLabel: 'BallotPrivacyPvssRelation',
        relationStatementHash: input.loweredStatement.relationStatementHash,
        requiredComponentIds: ballotPrivacyBackendProofComponentOrder,
    };

    return {
        ...statementPayload,
        componentBundleStatementHash:
            deriveComponentBundleStatementHash(statementPayload),
    };
};

const buildBallotProofComponentProofStatementPlan = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly componentStatement: BallotProofComponentStatement;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentProofStatementPlan => {
    const component = componentById({
        componentId: input.componentStatement.componentId,
        loweredStatement: input.loweredStatement,
    });
    const rowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const proofStatementFormat = proofStatementFormatForComponent({
        component,
        rowBatches,
    });
    const sourceRingDegree = sourceRingDegreeForComponentProofStatement(
        component.componentId,
    );
    const structuredCounts = rowBatches
        .filter(
            (
                rowBatch,
            ): rowBatch is Extract<
                BackendRowBatchForComponentStatement,
                {
                    readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows';
                }
            > =>
                rowBatch.batchKind ===
                'StructuredModuleLweReceiverEncryptionRows',
        )
        .map(structuredReceiverEncryptionWitnessTermCounts);
    const rowBatchTermCounts = rowBatches.map((rowBatch) =>
        rowBatchTermCount(rowBatch).toString(),
    );
    const sparseTermCount =
        proofStatementFormat === 'sparse-polynomial-matrix-linear-proof-v1' ||
        proofStatementFormat === 'structured-module-sis-share-commitment-v1'
            ? rowBatches
                  .reduce(
                      (termCount, rowBatch) =>
                          termCount + rowBatchTermCount(rowBatch),
                      0n,
                  )
                  .toString()
            : null;
    const structuredWitnessTermCount =
        proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
            ? structuredCounts
                  .reduce(
                      (termCount, counts) =>
                          termCount + counts.witnessTermCount,
                      0n,
                  )
                  .toString()
            : null;
    const statementPayload: Omit<
        BallotProofComponentProofStatementPlan,
        'componentProofStatementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.ballotProofStatementHash === undefined
            ? {}
            : {
                  ballotProofStatementHash: input.ballotProofStatementHash,
              }),
        coefficientModulus: component.coefficientModulus,
        componentId: component.componentId,
        componentStatementHash: input.componentStatement.componentStatementHash,
        denseCoefficientCount: denseCoefficientCountForComponentProofStatement({
            rowCount: component.rowCount,
            sourceRingDegree,
            variableColumnCount: component.variableColumnCount,
        }),
        matrixHash: input.componentStatement.matrixHash,
        objectType: 'BallotProofComponentProofStatementPlan',
        objectVersion: 1,
        proofBytesAvailability:
            proofBytesAvailabilityForStatementFormat(proofStatementFormat),
        proofLoweringStatus: component.proofLoweringStatus,
        proofStatementFormat,
        proofSystemRingDegree: proofSystemRingDegreeForComponentProofStatement(
            component.componentId,
        ),
        relation: linearProofRelation,
        relationStatementHash: input.loweredStatement.relationStatementHash,
        rowBatchMatrixHashes: input.componentStatement.rowBatchMatrixHashes,
        rowBatchNames: component.rowBatchNames,
        rowBatchTargetVectorHashes:
            input.componentStatement.rowBatchTargetVectorHashes,
        rowBatchTermCounts,
        rowCount: component.rowCount,
        sparseTermCount,
        sourceRingDegree,
        structuredCiphertextChunkCount:
            proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
                ? structuredCounts.reduce(
                      (count, counts) => count + counts.ciphertextChunkCount,
                      0,
                  )
                : null,
        structuredReceiverCount:
            proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
                ? structuredCounts.reduce(
                      (count, counts) => count + counts.receiverCount,
                      0,
                  )
                : null,
        structuredWitnessTermCount,
        targetVectorHash: input.componentStatement.targetVectorHash,
        variableColumnCount: component.variableColumnCount,
        variableColumnIndices: component.variableColumnIndices,
    };

    return {
        ...statementPayload,
        componentProofStatementHash:
            deriveComponentProofStatementHash(statementPayload),
    };
};

export const buildBallotProofComponentProofStatementPlans = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): readonly BallotProofComponentProofStatementPlan[] => {
    if (
        input.componentBundleStatement.backendStatementHash !==
            input.loweredStatement.backendStatement.backendStatementHash ||
        input.componentBundleStatement.relationStatementHash !==
            input.loweredStatement.relationStatementHash
    ) {
        throw new Error(
            'Component proof statement plans require a bundle statement bound to the lowered relation.',
        );
    }

    return input.componentBundleStatement.componentStatements.map(
        (componentStatement) =>
            buildBallotProofComponentProofStatementPlan({
                ballotProofStatementHash: input.ballotProofStatementHash,
                componentStatement,
                loweredStatement: input.loweredStatement,
            }),
    );
};

export const createBallotProofComponentProofRecord = (input: {
    readonly backendStatementHash: ProtocolHash;
    readonly ballotProofStatementHash: ProtocolHash;
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementHash: ProtocolHash;
    readonly componentStatementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly proofRoot: ProtocolHash;
    readonly proofSizeBytes: number;
    readonly publicRandomnessHash: ProtocolHash;
    readonly relationStatementHash: ProtocolHash;
}): BallotProofComponentProofRecord => {
    const proofRecordPayload: BallotProofComponentProofRecordPayload = {
        backendStatementHash: input.backendStatementHash,
        ballotProofStatementHash: input.ballotProofStatementHash,
        componentId: input.componentId,
        componentProofStatementHash: input.componentProofStatementHash,
        componentStatementHash: input.componentStatementHash,
        objectType: 'BallotProofComponentProofRecord',
        objectVersion: 1,
        proofBackend: 'LocalLinearLatticeRelation',
        proofBytesHash: input.proofBytesHash,
        proofEncodingProfileHash: input.proofEncodingProfileHash,
        proofParameterSetHash: input.proofParameterSetHash,
        proofRoot: input.proofRoot,
        proofSizeBytes: input.proofSizeBytes,
        publicRandomnessHash: input.publicRandomnessHash,
        relationStatementHash: input.relationStatementHash,
    };

    return {
        ...proofRecordPayload,
        componentProofRecordHash:
            deriveComponentProofRecordHash(proofRecordPayload),
    };
};

export const createBallotProofComponentProofBundle = (input: {
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly componentProofs: readonly BallotProofComponentProofRecord[];
}): BallotProofComponentProofBundle => {
    if (
        input.componentBundleStatement.bundleCoverage !==
        'full-encoded-score-ballot-relation'
    ) {
        throw new Error(
            'Component proof bundles require full encoded-score ballot relation coverage.',
        );
    }
    if (input.componentBundleStatement.ballotProofStatementHash === undefined) {
        throw new Error(
            'Component proof bundles require a ballot proof statement hash.',
        );
    }

    const proofBundlePayload: BallotProofComponentProofBundlePayload = {
        backendStatementHash:
            input.componentBundleStatement.backendStatementHash,
        ballotProofStatementHash:
            input.componentBundleStatement.ballotProofStatementHash,
        bundleCoverage: input.componentBundleStatement.bundleCoverage,
        componentBundleStatementHash:
            input.componentBundleStatement.componentBundleStatementHash,
        componentProofs: input.componentProofs,
        objectType: 'BallotProofComponentProofBundle',
        objectVersion: 1,
        relationStatementHash:
            input.componentBundleStatement.relationStatementHash,
        requiredComponentIds: input.componentBundleStatement
            .requiredComponentIds as readonly BallotProofComponentId[],
    };

    return {
        ...proofBundlePayload,
        componentProofBundleHash:
            deriveComponentProofBundleHash(proofBundlePayload),
    };
};

const assertProjectionSatisfiesRows = (input: {
    readonly coefficientModulus: bigint;
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly matrix: DensePolynomialMatrix;
    readonly targetVector: DensePolynomialVector;
    readonly witnessVector: DensePolynomialVector;
}): void => {
    for (let rowIndex = 0; rowIndex < input.matrix.length; rowIndex += 1) {
        let rowSum = polynomialCoefficientBigInt(
            input.targetVector[rowIndex]?.[0],
        );
        const matrixRow = input.matrix[rowIndex] ?? [];
        for (
            let columnIndex = 0;
            columnIndex < matrixRow.length;
            columnIndex += 1
        ) {
            rowSum +=
                polynomialCoefficientBigInt(matrixRow[columnIndex]?.[0]) *
                polynomialCoefficientBigInt(
                    input.witnessVector[columnIndex]?.[0],
                );
        }

        if (positiveModuloBigInt(rowSum, input.coefficientModulus) !== 0n) {
            throw new Error(
                `Proof component ${input.componentId} row ${rowIndex.toString()} is not satisfied by the private witness.`,
            );
        }
    }
};

const validateSourceRingDegree = (sourceRingDegree: number): void => {
    if (
        !Number.isSafeInteger(sourceRingDegree) ||
        sourceRingDegree <= 0 ||
        !Number.isInteger(Math.log2(sourceRingDegree))
    ) {
        throw new Error('Source ring degree must be a positive power of two.');
    }
};

const projectedWitnessValue = (input: {
    readonly componentId: BallotProofExplicitComponentId;
    readonly rawWitnessValue: bigint;
}): bigint => {
    if (input.componentId !== 'score-and-shamir-field-component') {
        return input.rawWitnessValue;
    }
    if (
        input.rawWitnessValue < BigInt(Number.MIN_SAFE_INTEGER) ||
        input.rawWitnessValue > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
        throw new Error(
            'Encoded-score field witness must fit in a safe integer.',
        );
    }

    return BigInt(centeredFieldRepresentative(Number(input.rawWitnessValue)));
};

const receiverReferenceKey = (receiver: {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
}): string => `${receiver.receiverRosterPosition}:${receiver.receiverIdentity}`;

const receiverPayloadPlaintextBits = (input: {
    readonly plaintextBitLength: number;
    readonly projectionWitness:
        | BallotProofComponentProjectionWitness
        | undefined;
    readonly receiverRosterPosition: number;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): readonly number[] => {
    const bits: number[] = [];
    const pushUnsignedBits = (value: bigint, bitLength: number): void => {
        if (value < 0n || value >= 1n << BigInt(bitLength)) {
            throw new Error(
                'Receiver payload plaintext value does not fit its bit width.',
            );
        }
        for (let bitIndex = 0; bitIndex < bitLength; bitIndex += 1) {
            bits.push(Number((value >> BigInt(bitIndex)) & 1n));
        }
    };
    const receiver = input.relationInput.receivers.find(
        (candidate) =>
            candidate.receiverRosterPosition === input.receiverRosterPosition,
    );
    if (receiver === undefined) {
        throw new Error('Receiver share witness is missing.');
    }

    for (
        let encodedCoordinateIndex = 0;
        encodedCoordinateIndex < receiver.receiverShareVector.length;
        encodedCoordinateIndex += 1
    ) {
        pushUnsignedBits(
            receiverPayloadPlaintextShareValue(
                input.relationInput,
                input.projectionWitness,
                input.receiverRosterPosition,
                encodedCoordinateIndex,
            ),
            receiverShareRepresentativeBitLength,
        );
    }
    for (
        let openingCoordinateIndex = 0;
        openingCoordinateIndex < 64;
        openingCoordinateIndex += 1
    ) {
        pushUnsignedBits(
            receiverPayloadPlaintextOpeningValue(
                input.projectionWitness,
                input.receiverRosterPosition,
                openingCoordinateIndex,
            ) + BigInt(receiverPayloadOpeningEncodingOffset),
            receiverOpeningRandomnessBitLength,
        );
    }
    if (bits.length < input.plaintextBitLength) {
        throw new Error(
            'Receiver payload plaintext bits do not cover the structured encryption statement.',
        );
    }

    return bits.slice(0, input.plaintextBitLength);
};

const numberVectorCoefficient = (input: {
    readonly coefficientIndex: number;
    readonly vector: readonly (readonly number[])[];
    readonly vectorIndex: number;
}): number => {
    const coefficient =
        input.vector[input.vectorIndex]?.[input.coefficientIndex];
    if (coefficient === undefined || !Number.isSafeInteger(coefficient)) {
        throw new Error(
            'Receiver encryption vector coordinate is missing or non-canonical.',
        );
    }

    return coefficient;
};

const numberPolynomialCoefficient = (input: {
    readonly coefficientIndex: number;
    readonly polynomial: readonly number[];
}): number => {
    const coefficient = input.polynomial[input.coefficientIndex];
    if (coefficient === undefined || !Number.isSafeInteger(coefficient)) {
        throw new Error(
            'Receiver encryption polynomial coordinate is missing or non-canonical.',
        );
    }

    return coefficient;
};

const addModularProduct = (input: {
    readonly coefficient: number;
    readonly currentValue: number;
    readonly witness: number;
}): number =>
    positiveModulo(
        input.currentValue + input.coefficient * input.witness,
        receiverEncryptionModulus,
    );

export {
    assertProjectionSatisfiesRows,
    validateSourceRingDegree,
    projectedWitnessValue,
    receiverReferenceKey,
    receiverPayloadPlaintextBits,
    numberVectorCoefficient,
    numberPolynomialCoefficient,
    addModularProduct,
};
