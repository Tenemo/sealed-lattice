import type { PublicProfileContext } from '../../module/context.js';
import {
    readModuleMemory,
    writeSetupInput,
} from '../../module/participant-module.js';
import { PublicInputFailure } from '../../shared/failures.js';

export const selectionOperation = {
    unsignedBody: 0,
    signProposal: 1,
    endorse: 2,
    restoreProposal: 3,
    restoreEndorsement: 4,
    endorsementBody: 5,
    retainCollection: 6,
    restoreCollection: 7,
    retainAggregateData: 8,
    restoreAggregateData: 9,
} as const;

export const publicOperation = {
    beginCollection: 1,
    beginCollectedOffer: 2,
    collectPolynomial: 3,
    finishCollectedOffer: 4,
    sealCollection: 5,
    beginAggregate: 6,
    aggregatePolynomial: 7,
    beginEvaluation: 8,
    evaluationProof: 9,
    finishEvaluation: 10,
    finishAggregate: 11,
    beginEvaluationJob: 12,
    beginJobPolynomial: 13,
    jobPolynomial: 14,
    finishJobPolynomial: 15,
    nextJobOutput: 16,
    compactAvailable: 17,
    finishAggregateCache: 18,
} as const;

const publicOutput = ({ module }: PublicProfileContext) =>
    readModuleMemory(
        module,
        module.setup_public_output_pointer(),
        module.setup_public_output_length(),
    );

export const publicStep = (
    context: PublicProfileContext,
    operation: number,
    bytes: Uint8Array = new Uint8Array(),
    index = 0,
    offset = 0,
) => {
    writeSetupInput(context.module, bytes);
    if (
        context.module.setup_public_work(
            operation,
            index,
            offset,
            bytes.length,
        ) !== 0
    )
        throw new PublicInputFailure('A public setup operation was refused.');
};

export const publicWork = (
    context: PublicProfileContext,
    operation: number,
    bytes: Uint8Array = new Uint8Array(),
    index = 0,
    offset = 0,
) => {
    publicStep(context, operation, bytes, index, offset);
    return publicOutput(context);
};
