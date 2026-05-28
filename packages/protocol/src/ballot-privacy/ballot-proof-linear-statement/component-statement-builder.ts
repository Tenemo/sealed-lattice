import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    BallotPrivacyBackendProofComponent,
    BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';

import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentStatement,
} from './statement-contracts.js';
import {
    deriveComponentMatrixHash,
    deriveComponentStatementHash,
    deriveComponentTargetVectorHash,
} from './statement-hashes.js';

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
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentStatement => {
    const componentRowBatches = rowBatchesForComponent(input);
    const rowBatchMatrixHashes = componentRowBatches.map(
        (rowBatch) => rowBatch.matrixHash,
    );
    const rowBatchTargetVectorHashes = componentRowBatches.map(
        (rowBatch) => rowBatch.targetVectorHash,
    );
    const matrixHash = deriveComponentMatrixHash({
        componentId: input.component.componentId,
        rowBatchMatrixHashes,
    });
    const targetVectorHash = deriveComponentTargetVectorHash({
        componentId: input.component.componentId,
        rowBatchTargetVectorHashes,
    });
    const statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.ballotProofStatementHash === undefined
            ? {}
            : {
                  ballotProofStatementHash: input.ballotProofStatementHash,
              }),
        coefficientModulus: input.component.coefficientModulus,
        componentHash: input.component.componentHash,
        componentId: input.component.componentId,
        matrixHash,
        objectType: 'BallotProofComponentStatement',
        objectVersion: 1,
        proofLoweringStatus: input.component.proofLoweringStatus,
        relationStatementHash: input.loweredStatement.relationStatementHash,
        rowBatchMatrixHashes,
        rowBatchNames: input.component.rowBatchNames,
        rowBatchTargetVectorHashes,
        rowCount: input.component.rowCount,
        rowKinds: input.component.rowKinds,
        targetVectorHash,
        variableColumnCount: input.component.variableColumnCount,
        variableColumnIndices: input.component.variableColumnIndices,
    };

    return {
        ...statementPayload,
        componentStatementHash: deriveComponentStatementHash(statementPayload),
    };
};

export { rowBatchesForComponent, buildComponentStatement };
