import {
    compileIndependentPaddedTallyModel,
    projectIndependentPaddedTallyWidth,
} from './padded-tally-transcript-model.js';

import { actionSignatureCarrierByteLength } from '#packages/wasm/src/preparation-parent-runtime.js';
import { privatePreparationBodyByteLength } from '#packages/wasm/src/private-preparation-body-runtime.js';
import { completionRosterByteLength } from '#packages/wasm/src/roster-runtime.js';
import {
    abstentionSourceBodyByteLength,
    submittedSourceBodyByteLength,
} from '#packages/wasm/src/source-runtime.js';

const participantCount = 10;
const finalityQuorum = 8;
const preparationParentBodyByteLength = 8_502;

export type FullTallyResourceModel = Readonly<{
    activationChunkCorpusByteLength: number;
    activationInventoryByteLength: number;
    cleanVerifiedDownloadByteLength: number;
    maximumConstructionCommandRequestByteLength: number;
    maximumChunkEvaluationRequestByteLength: number;
    maximumChunkGenerationRequestByteLength: number;
    maximumPrivatePreparationRecipientByteLength: number;
    preparationParentInventoryByteLength: number;
    sourceInventoryByteLength: number;
}>;

export const compileFullTallyResourceModel = (
    topCount: number,
    submittedParticipantCount: number,
): FullTallyResourceModel => {
    if (
        !Number.isSafeInteger(submittedParticipantCount) ||
        submittedParticipantCount < 0 ||
        submittedParticipantCount > participantCount
    ) {
        throw new RangeError('submittedParticipantCount is invalid.');
    }
    const tally = compileIndependentPaddedTallyModel(topCount);
    const commandProjection = projectIndependentPaddedTallyWidth(tally, 40);
    const activationChunkCorpusByteLength =
        participantCount *
        tally.descriptors.reduce(
            (sum, descriptor) => sum + descriptor.chunkByteLength,
            0,
        );
    const manifestByteLength = 176 + 78 * tally.descriptors.length;
    const activationInventoryByteLength =
        participantCount *
        (manifestByteLength + actionSignatureCarrierByteLength);
    const maximumPrivatePreparationRecipientByteLength =
        (participantCount - 1) *
        (preparationParentBodyByteLength +
            actionSignatureCarrierByteLength +
            privatePreparationBodyByteLength);
    const preparationParentInventoryByteLength =
        participantCount *
        (preparationParentBodyByteLength + actionSignatureCarrierByteLength);
    const sourceInventoryByteLength =
        submittedParticipantCount *
            (submittedSourceBodyByteLength + actionSignatureCarrierByteLength) +
        (participantCount - submittedParticipantCount) *
            (abstentionSourceBodyByteLength + actionSignatureCarrierByteLength);
    const quorumFinalityInventoryByteLength =
        finalityQuorum * actionSignatureCarrierByteLength;
    const cleanVerifiedDownloadByteLength =
        5 * completionRosterByteLength +
        maximumPrivatePreparationRecipientByteLength +
        2 * preparationParentInventoryByteLength +
        2 * sourceInventoryByteLength +
        2 * quorumFinalityInventoryByteLength +
        activationInventoryByteLength +
        activationChunkCorpusByteLength;

    return {
        activationChunkCorpusByteLength,
        activationInventoryByteLength,
        cleanVerifiedDownloadByteLength,
        maximumConstructionCommandRequestByteLength: Math.max(
            commandProjection.maximumChunkGenerationRequestByteLength,
            commandProjection.maximumChunkEvaluationRequestByteLength,
        ),
        maximumChunkEvaluationRequestByteLength:
            commandProjection.maximumChunkEvaluationRequestByteLength,
        maximumChunkGenerationRequestByteLength:
            commandProjection.maximumChunkGenerationRequestByteLength,
        maximumPrivatePreparationRecipientByteLength,
        preparationParentInventoryByteLength,
        sourceInventoryByteLength,
    };
};
