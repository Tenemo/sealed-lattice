import type {
    CommonProofExternalMemoryRequest,
    CommonProofGenerationCheckpoint,
} from '@sealed-lattice/wasm';

import type { CommonProofBrowserCustody } from '#packages/protocol/src/runtime/common-proof-browser-custody';

export type ReplaceableCommonProofBrowserCustody = Readonly<{
    custody: CommonProofBrowserCustody;
    currentCustody(): CommonProofBrowserCustody;
    replaceAfterAuthenticatedSuspension(
        resumedCustody: CommonProofBrowserCustody,
    ): void;
}>;

const requireCheckpointCustody = (
    custody: CommonProofBrowserCustody,
): NonNullable<CommonProofBrowserCustody['checkpointCustody']> => {
    if (custody.checkpointCustody === undefined) {
        throw new Error(
            'A resumed production common-proof measurement requires authenticated checkpoint custody.',
        );
    }
    return custody.checkpointCustody;
};

/**
 * Keeps the recorder-facing custody object stable while an authenticated
 * checkpoint closes the fresh custody and the exact resumed custody takes
 * ownership. Replacement is possible only after a successful suspension.
 */
export const createReplaceableCommonProofBrowserCustody = (
    initialCustody: CommonProofBrowserCustody,
): ReplaceableCommonProofBrowserCustody => {
    requireCheckpointCustody(initialCustody);
    let currentCustody = initialCustody;
    let replacementAllowed = false;

    const requireCurrentCustody = (): CommonProofBrowserCustody =>
        currentCustody;
    const custody: CommonProofBrowserCustody = Object.freeze({
        armApplicationHandoff: () =>
            requireCurrentCustody().armApplicationHandoff(),
        checkpointCustody: Object.freeze({
            publishAuthenticatedCheckpoint: (
                checkpoint: CommonProofGenerationCheckpoint,
            ) =>
                requireCheckpointCustody(
                    requireCurrentCustody(),
                ).publishAuthenticatedCheckpoint(checkpoint),
            restoreAuthenticatedCheckpointState: () =>
                requireCheckpointCustody(
                    requireCurrentCustody(),
                ).restoreAuthenticatedCheckpointState(),
        }),
        completeVerifiedOutput: () =>
            requireCurrentCustody().completeVerifiedOutput(),
        copyCheckpointResumeDescriptor: () =>
            requireCurrentCustody().copyCheckpointResumeDescriptor(),
        externalMemory: Object.freeze({
            executeTransaction: (request: CommonProofExternalMemoryRequest) =>
                requireCurrentCustody().externalMemory.executeTransaction(
                    request,
                ),
        }),
        prefixReplayExternalMemory: Object.freeze({
            executeDeterministicPrefixReplayTransaction: (
                request: CommonProofExternalMemoryRequest,
            ) =>
                requireCurrentCustody().prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                    request,
                ),
        }),
        outputStore: Object.freeze({
            commitChunk: (
                chunkIndex: number,
                chunkBytes: Uint8Array<ArrayBuffer>,
            ) =>
                requireCurrentCustody().outputStore.commitChunk(
                    chunkIndex,
                    chunkBytes,
                ),
            readChunk: (chunkIndex: number, exactByteLength: number) =>
                requireCurrentCustody().outputStore.readChunk(
                    chunkIndex,
                    exactByteLength,
                ),
        }),
        authenticatedOutput: () =>
            requireCurrentCustody().authenticatedOutput(),
        releaseExternalMemory: () =>
            requireCurrentCustody().releaseExternalMemory(),
        retire: () => requireCurrentCustody().retire(),
        sealCanonicalOutput: () =>
            requireCurrentCustody().sealCanonicalOutput(),
        suspendForAuthenticatedResume: async () => {
            if (replacementAllowed) {
                throw new Error(
                    'The production common-proof custody is already suspended.',
                );
            }
            await requireCurrentCustody().suspendForAuthenticatedResume();
            replacementAllowed = true;
        },
    });

    return Object.freeze({
        custody,
        currentCustody: () => currentCustody,
        replaceAfterAuthenticatedSuspension: (resumedCustody) => {
            if (!replacementAllowed) {
                throw new Error(
                    'Production common-proof custody may be replaced only after authenticated suspension.',
                );
            }
            if (
                resumedCustody === currentCustody ||
                resumedCustody === custody
            ) {
                throw new Error(
                    'The resumed common-proof custody must be a new storage authority.',
                );
            }
            requireCheckpointCustody(resumedCustody);
            currentCustody = resumedCustody;
            replacementAllowed = false;
        },
    });
};
