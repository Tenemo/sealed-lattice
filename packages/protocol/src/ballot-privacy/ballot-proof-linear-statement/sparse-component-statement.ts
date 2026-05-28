import type { ProtocolHash } from '@sealed-lattice/types';

import { type BallotPrivacyLoweredLinearRelationStatement } from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import { validateSourceRingDegree } from './component-bundle.js';
import { buildStructuredShareCommitmentSparseStatement } from './component-projections.js';
import { rowBatchesForComponent } from './component-statement-builder.js';
import type {
    BallotProofSparseComponentLinearProofStatement,
    BallotProofStructuredShareCommitmentProofStatement,
    ConstantSparseMatrixEntry,
    ConstantSparseTargetVectorEntry,
    DensePolynomial,
    FieldVariableColumn,
    PackedFieldSourceColumn,
    SparseMatrixEntry,
    SparseTargetVectorEntry,
} from './statement-contracts.js';
import {
    linearProofRelation,
    polynomialCoefficient,
    positiveModuloBigInt,
} from './statement-contracts.js';
import {
    deriveSparseLinearStatementHash,
    deriveSparseStatementMatrixHash,
    deriveSparseTargetVectorHash,
} from './statement-hashes.js';
import {
    componentById,
    decimalBigInt,
    explicitRowBatchesForComponent,
    projectionCoverageForComponent,
    usedBackendColumnIndices,
} from './witness-accessors.js';

export const buildBallotProofSparseComponentLinearProofStatement = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly componentId:
        | 'score-and-shamir-field-component'
        | 'payload-plaintext-field-component'
        | 'share-commitment-component';
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}):
    | BallotProofSparseComponentLinearProofStatement
    | BallotProofStructuredShareCommitmentProofStatement => {
    validateSourceRingDegree(input.sourceRingDegree);
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    const componentRowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    if (
        input.componentId === 'share-commitment-component' &&
        componentRowBatches.some(
            (rowBatch) =>
                rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows',
        )
    ) {
        return buildStructuredShareCommitmentSparseStatement({
            ballotProofStatementHash: input.ballotProofStatementHash,
            component,
            loweredStatement: input.loweredStatement,
            parameterProfileId: input.parameterProfileId,
            sourceRingDegree: input.sourceRingDegree,
            witnessL2BoundSquared: input.witnessL2BoundSquared,
        });
    }
    const rowBatches = explicitRowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const coefficientModulus = decimalBigInt(
        component.coefficientModulus,
        'component coefficient modulus',
    );
    const invalidModulusBatch = rowBatches.find(
        (rowBatch) => rowBatch.modulus !== component.coefficientModulus,
    );
    if (invalidModulusBatch !== undefined) {
        throw new Error(
            `Proof component ${input.componentId} row batch ${invalidModulusBatch.batchName} uses a mismatched modulus.`,
        );
    }
    const explicitRows = rowBatches.flatMap((rowBatch) => rowBatch.rows);
    const sourceBackendColumnIndices = usedBackendColumnIndices(explicitRows);
    const projectedColumnByBackendColumn = new Map(
        sourceBackendColumnIndices.map((backendColumnIndex, projectedIndex) => [
            backendColumnIndex,
            projectedIndex,
        ]),
    );
    const matrixCoefficientByPosition = new Map<
        string,
        {
            readonly columnIndex: number;
            coefficient: bigint;
            readonly rowIndex: number;
        }
    >();
    const targetCoefficientByRow = new Map<number, bigint>();

    for (const fieldRow of explicitRows) {
        const targetCoefficient = positiveModuloBigInt(
            -decimalBigInt(fieldRow.target, 'linear row target'),
            coefficientModulus,
        );
        if (targetCoefficient !== 0n) {
            targetCoefficientByRow.set(fieldRow.rowIndex, targetCoefficient);
        }
        for (const term of fieldRow.terms) {
            const projectedColumn = projectedColumnByBackendColumn.get(
                term.columnIndex,
            );
            if (projectedColumn === undefined) {
                throw new Error(
                    'Sparse projection column lookup is incomplete.',
                );
            }
            const positionKey = `${fieldRow.rowIndex}:${projectedColumn}`;
            const existingCoefficient =
                matrixCoefficientByPosition.get(positionKey);
            const nextCoefficient = positiveModuloBigInt(
                (existingCoefficient?.coefficient ?? 0n) +
                    decimalBigInt(term.coefficient, 'linear term coefficient'),
                coefficientModulus,
            );
            if (nextCoefficient === 0n) {
                matrixCoefficientByPosition.delete(positionKey);
            } else if (existingCoefficient === undefined) {
                matrixCoefficientByPosition.set(positionKey, {
                    coefficient: nextCoefficient,
                    columnIndex: projectedColumn,
                    rowIndex: fieldRow.rowIndex,
                });
            } else {
                existingCoefficient.coefficient = nextCoefficient;
            }
        }
    }

    const sparseStatementMatrixEntries = [
        ...matrixCoefficientByPosition.values(),
    ]
        .sort((left, right) =>
            left.rowIndex === right.rowIndex
                ? left.columnIndex - right.columnIndex
                : left.rowIndex - right.rowIndex,
        )
        .map(
            (entry): ConstantSparseMatrixEntry => ({
                columnIndex: entry.columnIndex,
                constantCoefficient: polynomialCoefficient({
                    coefficient: entry.coefficient,
                    coefficientModulus,
                }),
                rowIndex: entry.rowIndex,
            }),
        );
    const targetVectorEntries = [...targetCoefficientByRow.entries()]
        .sort(([leftRowIndex], [rightRowIndex]) => leftRowIndex - rightRowIndex)
        .map(
            ([rowIndex, coefficient]): ConstantSparseTargetVectorEntry => ({
                constantCoefficient: polynomialCoefficient({
                    coefficient,
                    coefficientModulus,
                }),
                rowIndex,
            }),
        );
    const sparseStatementMatrixHash = deriveSparseStatementMatrixHash(
        sparseStatementMatrixEntries,
    );
    const targetVectorHash = deriveSparseTargetVectorHash(targetVectorEntries);
    const projectionCoverage = projectionCoverageForComponent(
        input.componentId,
    );
    if (
        projectionCoverage !== 'encoded-score-field-rows-only' &&
        projectionCoverage !== 'payload-plaintext-field-rows-only' &&
        projectionCoverage !== 'share-commitment-rows-only'
    ) {
        throw new Error(
            `Proof component ${input.componentId} is not a sparse component.`,
        );
    }
    const statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
        'statementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.ballotProofStatementHash === undefined
            ? {}
            : {
                  ballotProofStatementHash: input.ballotProofStatementHash,
              }),
        coefficientModulus: component.coefficientModulus,
        objectType: 'BallotProofSparseComponentLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        projectionCoverage,
        relation: linearProofRelation,
        relationStatementHash: input.loweredStatement.relationStatementHash,
        sourceBackendColumnIndices,
        sourceRingDegree: input.sourceRingDegree,
        sparseStatementMatrixHash,
        sparseStatementMatrixEntries,
        sparseStatementTermCount:
            sparseStatementMatrixEntries.length.toString(),
        statementColumns: sourceBackendColumnIndices.length,
        statementRows: explicitRows.length,
        matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorHash,
        targetVectorEntries,
        targetVectorEntryCount: targetVectorEntries.length.toString(),
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        ...statementPayload,
        statementHash: deriveSparseLinearStatementHash(statementPayload),
    };
};

type PackedFieldStatementAccumulator = {
    readonly addMatrixTerm: (input: {
        readonly coefficient: bigint;
        readonly columnIndex: number;
        readonly monomialDegree: number;
        readonly rowIndex: number;
    }) => void;
    readonly addPackedColumn: (input: {
        readonly bindings: readonly {
            readonly backendColumnIndex: number;
            readonly coefficientIndex: number;
        }[];
        readonly packingKind: string;
    }) => number;
    readonly addTargetTerm: (input: {
        readonly coefficient: bigint;
        readonly coefficientIndex: number;
        readonly rowIndex: number;
    }) => void;
    readonly matrixEntries: () => readonly SparseMatrixEntry[];
    readonly sourceBackendColumnIndices: () => readonly number[];
    readonly sourceColumnPackings: () => readonly PackedFieldSourceColumn[];
    readonly statementColumns: () => number;
    readonly targetEntries: () => readonly SparseTargetVectorEntry[];
};

const createPackedFieldStatementAccumulator = (input: {
    readonly coefficientModulus: bigint;
    readonly sourceRingDegree: number;
    readonly variableColumnByBackendColumn: ReadonlyMap<
        number,
        FieldVariableColumn
    >;
}): PackedFieldStatementAccumulator => {
    const matrixPolynomialByPosition = new Map<string, bigint[]>();
    const targetPolynomialByRow = new Map<number, bigint[]>();
    const sourceColumnPackings: PackedFieldSourceColumn[] = [];
    const sourceBackendColumnIndices = new Set<number>();
    const zeroPolynomialBigInt = (): bigint[] =>
        Array.from({ length: input.sourceRingDegree }, () => 0n);
    const addPolynomialTerm = (
        polynomial: bigint[],
        coefficientIndex: number,
        coefficient: bigint,
    ): void => {
        if (
            !Number.isSafeInteger(coefficientIndex) ||
            coefficientIndex < 0 ||
            coefficientIndex >= input.sourceRingDegree
        ) {
            throw new Error(
                'Packed field statement coefficient index is outside the source ring.',
            );
        }
        polynomial[coefficientIndex] = positiveModuloBigInt(
            polynomial[coefficientIndex] + coefficient,
            input.coefficientModulus,
        );
    };
    const densePolynomialFromBigInt = (
        polynomial: readonly bigint[],
    ): DensePolynomial =>
        polynomial.map((coefficient) =>
            polynomialCoefficient({
                coefficient,
                coefficientModulus: input.coefficientModulus,
            }),
        );
    const isZeroPolynomial = (polynomial: readonly bigint[]): boolean =>
        polynomial.every((coefficient) => coefficient === 0n);
    const sparseMatrixEntry = (
        rowIndex: number,
        columnIndex: number,
        polynomial: readonly bigint[],
    ): SparseMatrixEntry => {
        const nonzeroIndices = polynomial.flatMap((coefficient, index) =>
            coefficient === 0n ? [] : [index],
        );
        if (nonzeroIndices.length === 1 && nonzeroIndices[0] === 0) {
            return {
                columnIndex,
                constantCoefficient: polynomialCoefficient({
                    coefficient: polynomial[0] ?? 0n,
                    coefficientModulus: input.coefficientModulus,
                }),
                rowIndex,
            };
        }

        return {
            columnIndex,
            polynomialCoefficients: densePolynomialFromBigInt(polynomial),
            rowIndex,
        };
    };
    const sparseTargetEntry = (
        rowIndex: number,
        polynomial: readonly bigint[],
    ): SparseTargetVectorEntry => {
        const nonzeroIndices = polynomial.flatMap((coefficient, index) =>
            coefficient === 0n ? [] : [index],
        );
        if (nonzeroIndices.length === 1 && nonzeroIndices[0] === 0) {
            return {
                constantCoefficient: polynomialCoefficient({
                    coefficient: polynomial[0] ?? 0n,
                    coefficientModulus: input.coefficientModulus,
                }),
                rowIndex,
            };
        }

        return {
            polynomialCoefficients: densePolynomialFromBigInt(polynomial),
            rowIndex,
        };
    };

    return {
        addMatrixTerm: (termInput) => {
            const coefficient = positiveModuloBigInt(
                termInput.coefficient,
                input.coefficientModulus,
            );
            if (coefficient === 0n) {
                return;
            }
            const positionKey = `${termInput.rowIndex}:${termInput.columnIndex}`;
            const polynomial =
                matrixPolynomialByPosition.get(positionKey) ??
                zeroPolynomialBigInt();
            addPolynomialTerm(
                polynomial,
                termInput.monomialDegree,
                coefficient,
            );
            if (isZeroPolynomial(polynomial)) {
                matrixPolynomialByPosition.delete(positionKey);
            } else {
                matrixPolynomialByPosition.set(positionKey, polynomial);
            }
        },
        addPackedColumn: (columnInput) => {
            const columnIndex = sourceColumnPackings.length;
            const seenCoefficientIndices = new Set<number>();
            const bindings = columnInput.bindings
                .map((binding) => {
                    const variableColumn =
                        input.variableColumnByBackendColumn.get(
                            binding.backendColumnIndex,
                        );
                    if (variableColumn === undefined) {
                        throw new Error(
                            'Packed field source column references an unknown backend column.',
                        );
                    }
                    if (
                        !Number.isSafeInteger(binding.coefficientIndex) ||
                        binding.coefficientIndex < 0 ||
                        binding.coefficientIndex >= input.sourceRingDegree
                    ) {
                        throw new Error(
                            'Packed field source column coefficient index is outside the source ring.',
                        );
                    }
                    if (!seenCoefficientIndices.add(binding.coefficientIndex)) {
                        throw new Error(
                            'Packed field source column contains a duplicate coefficient slot.',
                        );
                    }
                    sourceBackendColumnIndices.add(binding.backendColumnIndex);

                    return {
                        backendColumnIndex: binding.backendColumnIndex,
                        coefficientIndex: binding.coefficientIndex,
                        variableName: variableColumn.variableName,
                        variableRole: variableColumn.variableRole,
                    };
                })
                .sort(
                    (left, right) =>
                        left.coefficientIndex - right.coefficientIndex,
                );
            sourceColumnPackings.push({
                bindings,
                columnIndex,
                packingKind: columnInput.packingKind,
            });

            return columnIndex;
        },
        addTargetTerm: (targetInput) => {
            const coefficient = positiveModuloBigInt(
                targetInput.coefficient,
                input.coefficientModulus,
            );
            if (coefficient === 0n) {
                return;
            }
            const polynomial =
                targetPolynomialByRow.get(targetInput.rowIndex) ??
                zeroPolynomialBigInt();
            addPolynomialTerm(
                polynomial,
                targetInput.coefficientIndex,
                coefficient,
            );
            if (isZeroPolynomial(polynomial)) {
                targetPolynomialByRow.delete(targetInput.rowIndex);
            } else {
                targetPolynomialByRow.set(targetInput.rowIndex, polynomial);
            }
        },
        matrixEntries: () =>
            [...matrixPolynomialByPosition.entries()]
                .map(([positionKey, polynomial]) => {
                    const [rowIndexString, columnIndexString] =
                        positionKey.split(':');
                    return sparseMatrixEntry(
                        Number(rowIndexString),
                        Number(columnIndexString),
                        polynomial,
                    );
                })
                .sort((left, right) =>
                    left.rowIndex === right.rowIndex
                        ? left.columnIndex - right.columnIndex
                        : left.rowIndex - right.rowIndex,
                ),
        sourceBackendColumnIndices: () =>
            [...sourceBackendColumnIndices].sort((left, right) => left - right),
        sourceColumnPackings: () => sourceColumnPackings,
        statementColumns: () => sourceColumnPackings.length,
        targetEntries: () =>
            [...targetPolynomialByRow.entries()]
                .map(([rowIndex, polynomial]) =>
                    sparseTargetEntry(rowIndex, polynomial),
                )
                .sort((left, right) => left.rowIndex - right.rowIndex),
    };
};

const fieldVariableKey = (variableColumn: FieldVariableColumn): string =>
    [
        variableColumn.variableRole,
        variableColumn.receiverRosterPosition ?? '',
        variableColumn.encodedCoordinateIndex ?? '',
        variableColumn.openingCoordinateIndex ?? '',
        variableColumn.bitIndex ?? '',
        variableColumn.coefficientDegree ?? '',
        variableColumn.optionIndex ?? '',
        variableColumn.scoreBucketValue ?? '',
    ].join('|');

const requiredFieldVariableColumn = (input: {
    readonly key: string;
    readonly label: string;
    readonly variableColumnByKey: ReadonlyMap<string, FieldVariableColumn>;
}): FieldVariableColumn => {
    const variableColumn = input.variableColumnByKey.get(input.key);
    if (variableColumn === undefined) {
        throw new Error(
            `Packed field statement is missing variable column ${input.label}.`,
        );
    }

    return variableColumn;
};

const fieldVariableLookupKey = (input: {
    readonly bitIndex?: number;
    readonly coefficientDegree?: number;
    readonly encodedCoordinateIndex?: number;
    readonly openingCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly receiverRosterPosition?: number;
    readonly scoreBucketValue?: number;
    readonly variableRole: string;
}): string =>
    [
        input.variableRole,
        input.receiverRosterPosition ?? '',
        input.encodedCoordinateIndex ?? '',
        input.openingCoordinateIndex ?? '',
        input.bitIndex ?? '',
        input.coefficientDegree ?? '',
        input.optionIndex ?? '',
        input.scoreBucketValue ?? '',
    ].join('|');

const encodedCoordinateCountForRelation = (
    relationInput: BallotPrivacyRelationCompilerInput,
): number => relationInput.optionCount * 11;

const encodedCoordinateChunkCount = (input: {
    readonly encodedCoordinateCount: number;
    readonly sourceRingDegree: number;
}): number => Math.ceil(input.encodedCoordinateCount / input.sourceRingDegree);

export {
    createPackedFieldStatementAccumulator,
    fieldVariableKey,
    requiredFieldVariableColumn,
    fieldVariableLookupKey,
    encodedCoordinateCountForRelation,
    encodedCoordinateChunkCount,
};
export type { PackedFieldStatementAccumulator };
