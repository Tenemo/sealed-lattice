import type { ProtocolDigest } from '@sealed-lattice/types';

import type {
    BallotPrivacyBackendProofComponent,
    BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';

import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentStatement,
} from './statement-contracts.js';
import {
    deriveComponentMatrixDigest,
    deriveComponentStatementDigest,
    deriveComponentTargetVectorDigest,
} from './statement-digests.js';

const rowBatchesForComponent = (input: {
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): readonly BackendRowBatchForComponentStatement[] => {
    const rowBatchByName = new Map(
        input.loweredStatement.backendStatement.rowBatches.map((rowBatch) => [
            rowBatch.batchName,
            rowBatch,
        ]),
    );

    return input.component.rowBatchNames.map((rowBatchName) => {
        const rowBatch = rowBatchByName.get(rowBatchName);
        if (rowBatch === undefined) {
            throw new Error(
                `Proof component ${input.component.componentId} references missing row batch ${rowBatchName}.`,
            );
        }

        return rowBatch;
    });
};

const buildComponentStatement = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentStatement => {
    const componentRowBatches = rowBatchesForComponent(input);
    const rowBatchMatrixDigests = componentRowBatches.map(
        (rowBatch) => rowBatch.matrixDigest,
    );
    const rowBatchTargetVectorDigests = componentRowBatches.map(
        (rowBatch) => rowBatch.targetVectorDigest,
    );
    const matrixDigest = deriveComponentMatrixDigest({
        componentId: input.component.componentId,
        rowBatchMatrixDigests,
    });
    const targetVectorDigest = deriveComponentTargetVectorDigest({
        componentId: input.component.componentId,
        rowBatchTargetVectorDigests,
    });
    const statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        coefficientModulus: input.component.coefficientModulus,
        componentDigest: input.component.componentDigest,
        componentId: input.component.componentId,
        matrixDigest,
        objectType: 'BallotProofComponentStatement',
        objectVersion: 1,
        proofLoweringStatus: input.component.proofLoweringStatus,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        rowBatchMatrixDigests,
        rowBatchNames: input.component.rowBatchNames,
        rowBatchTargetVectorDigests,
        rowCount: input.component.rowCount,
        rowKinds: input.component.rowKinds,
        targetVectorDigest,
        variableColumnCount: input.component.variableColumnCount,
        variableColumnIndices: input.component.variableColumnIndices,
    };

    return {
        ...statementPayload,
        componentStatementDigest:
            deriveComponentStatementDigest(statementPayload),
    };
};

export { rowBatchesForComponent, buildComponentStatement };
