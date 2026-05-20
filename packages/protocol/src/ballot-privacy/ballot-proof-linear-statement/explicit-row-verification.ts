import {
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import { verifyStructuredReceiverEncryptionRowBatch } from './component-projections.js';
import { rowBatchesForComponent } from './component-statement-builder.js';
import type {
    BallotProofComponentProjectionWitness,
    BallotProofExplicitComponentWitnessVerification,
} from './statement-contracts.js';
import {
    linearProofRelation,
    positiveModuloBigInt,
} from './statement-contracts.js';
import { witnessValueForVariable } from './statement-witness-values.js';
import {
    componentById,
    decimalBigInt,
    fieldVariableColumns,
} from './witness-accessors.js';

const verifyBallotProofComponentExplicitRows = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): BallotProofExplicitComponentWitnessVerification => {
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    if (component.proofLoweringStatus !== 'explicitRowsAvailable') {
        throw new Error(
            `Proof component ${component.componentId} is not fully lowered to explicit rows.`,
        );
    }
    const rowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const coefficientModulus = decimalBigInt(
        component.coefficientModulus,
        'component coefficient modulus',
    );
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    let checkedRowCount = 0;

    for (const rowBatch of rowBatches) {
        if (rowBatch.batchKind === 'DigestExpandedRows') {
            throw new Error(
                `Proof component ${input.componentId} is not fully lowered to explicit rows.`,
            );
        }
        if (
            rowBatch.batchKind === 'StructuredModuleLweReceiverEncryptionRows'
        ) {
            checkedRowCount += verifyStructuredReceiverEncryptionRowBatch({
                loweredStatement: input.loweredStatement,
                projectionWitness: input.projectionWitness,
                relationInput: input.relationInput,
                rowBatch,
                startingRowIndex: checkedRowCount,
            });
            continue;
        }
        if (rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows') {
            checkedRowCount += rowBatch.rowCount;
            continue;
        }
        if (rowBatch.modulus !== component.coefficientModulus) {
            throw new Error(
                `Proof component ${input.componentId} row batch ${rowBatch.batchName} uses a mismatched modulus.`,
            );
        }
        for (const row of rowBatch.rows) {
            let rowSum = -decimalBigInt(row.target, 'linear row target');
            for (const term of row.terms) {
                const variableColumn = variableColumnByBackendColumn.get(
                    term.columnIndex,
                );
                if (variableColumn === undefined) {
                    throw new Error(
                        'Explicit row variable lookup is incomplete.',
                    );
                }
                rowSum +=
                    decimalBigInt(term.coefficient, 'linear term coefficient') *
                    witnessValueForVariable(
                        input.relationInput,
                        input.projectionWitness,
                        variableColumn,
                    );
            }
            if (positiveModuloBigInt(rowSum, coefficientModulus) !== 0n) {
                throw new Error(
                    `Proof component ${input.componentId} row ${checkedRowCount.toString()} is not satisfied by the private witness.`,
                );
            }
            checkedRowCount += 1;
        }
    }

    return {
        checkedRowBatchNames: rowBatches.map((rowBatch) => rowBatch.batchName),
        componentId: input.componentId,
        objectType: 'BallotProofExplicitComponentWitnessVerification',
        objectVersion: 1,
        relation: linearProofRelation,
        rowCount: checkedRowCount,
        verificationStatus: 'explicitRowsSatisfied',
    };
};

export { verifyBallotProofComponentExplicitRows };
