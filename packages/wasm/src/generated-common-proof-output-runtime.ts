import {
    CanonicalStreamInternalError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from './canonical-stream-runtime.js';
import type { CommonProofCanonicalOutputStore } from './common-proof-worker-runtime/runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

/** Tracks the canonical output shape while preserving the caller's store. */
export const trackCanonicalCommonProofOutputChunks = (
    outputStore: CommonProofCanonicalOutputStore,
): Readonly<{
    outputChunkByteLengths: readonly number[];
    outputStore: CommonProofCanonicalOutputStore;
}> => {
    const outputChunkByteLengths: number[] = [];
    return Object.freeze({
        outputChunkByteLengths,
        outputStore: Object.freeze({
            commitChunk: async (
                chunkIndex: number,
                chunkBytes: Uint8Array<ArrayBuffer>,
            ): Promise<void> => {
                if (chunkIndex !== outputChunkByteLengths.length) {
                    throw new CanonicalStreamInternalError(
                        'The common-proof generator committed output outside canonical chunk order.',
                    );
                }
                await outputStore.commitChunk(chunkIndex, chunkBytes);
                outputChunkByteLengths.push(chunkBytes.byteLength);
            },
            readChunk: (chunkIndex: number, exactByteLength: number) =>
                outputStore.readChunk(chunkIndex, exactByteLength),
        }),
    });
};

/**
 * Recomputes a generated proof descriptor from the exact committed chunks.
 * The descriptor is transport metadata only; Rust still binds and verifies
 * the proof bytes against the exact family statement and board object.
 */
export const deriveGeneratedCommonProofDescriptor = async (input: {
    kernel: TranscriptCoreKernel;
    outputChunkByteLengths: readonly number[];
    outputStore: CommonProofCanonicalOutputStore;
    proofFamilyLabel: string;
    streamDomain: CanonicalStreamDomain;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const totalByteLength = input.outputChunkByteLengths.reduce(
        (total, chunkByteLength) => {
            if (
                !Number.isSafeInteger(chunkByteLength) ||
                chunkByteLength <= 0 ||
                !Number.isSafeInteger(total + chunkByteLength)
            ) {
                throw new CanonicalStreamInternalError(
                    `The generated ${input.proofFamilyLabel} proof has invalid canonical output accounting.`,
                );
            }
            return total + chunkByteLength;
        },
        0,
    );
    if (totalByteLength === 0) {
        throw new CanonicalStreamInternalError(
            `The generated ${input.proofFamilyLabel} proof has no canonical output.`,
        );
    }
    const writer = openCanonicalStreamWorkerRuntime({
        kernel: input.kernel,
    }).openWriter({
        streamDomain: input.streamDomain,
        totalByteLength,
    });
    let completed = false;
    try {
        for (
            let chunkIndex = 0;
            chunkIndex < input.outputChunkByteLengths.length;
            chunkIndex += 1
        ) {
            const expectedByteLength = input.outputChunkByteLengths[chunkIndex];
            if (expectedByteLength === undefined) {
                throw new CanonicalStreamInternalError(
                    `The generated ${input.proofFamilyLabel} proof output catalog changed during descriptor derivation.`,
                );
            }
            const storedBytes = await input.outputStore.readChunk(
                chunkIndex,
                expectedByteLength,
            );
            const ownedBytes = Uint8Array.from(storedBytes);
            try {
                if (ownedBytes.byteLength !== expectedByteLength) {
                    throw new CanonicalStreamInternalError(
                        `The generated ${input.proofFamilyLabel} proof store returned a truncated canonical output chunk.`,
                    );
                }
                writer.absorbChunk(chunkIndex, ownedBytes.buffer);
            } finally {
                ownedBytes.fill(0);
                storedBytes.fill(0);
            }
        }
        const descriptorBytes = Uint8Array.from(writer.finish());
        completed = true;
        return descriptorBytes;
    } finally {
        if (!completed && writer.state() === 'active') {
            writer.cancel();
        }
    }
};
