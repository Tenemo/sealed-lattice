import { foundationProfile } from '@sealed-lattice/types';

type CanonicalStreamChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

type CanonicalStreamChunkSink = (input: {
    readonly abortSignal?: AbortSignal;
    readonly bytes: ArrayBuffer;
    readonly chunkIndex: number;
}) => Promise<void>;

type CanonicalStreamChunkPumpLease<Result> = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(chunkIndex: number, bytes: ArrayBuffer): void;
    finish(): Result;
}>;

type CanonicalStreamChunkPumpInput<Result> = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly consumeChunk?: CanonicalStreamChunkSink;
    createCancellationError(): Error;
    readonly lease: CanonicalStreamChunkPumpLease<Result>;
    readonly pullChunk: CanonicalStreamChunkPull;
}>;

const throwIfCancelled = (
    abortSignal: AbortSignal | undefined,
    createCancellationError: () => Error,
): void => {
    if (abortSignal?.aborted === true) {
        throw createCancellationError();
    }
};

const releaseBuffer = (buffer: ArrayBuffer): void => {
    if (buffer.byteLength > 0) {
        new Uint8Array(buffer).fill(0);
    }
};

const expectedChunkByteLength = <Result>(
    lease: CanonicalStreamChunkPumpLease<Result>,
    chunkIndex: number,
): number => {
    if (chunkIndex + 1 < lease.chunkCount) {
        return foundationProfile.streamChunkByteLength;
    }
    return (
        lease.totalByteLength -
        (lease.chunkCount - 1) * foundationProfile.streamChunkByteLength
    );
};

export const pumpCanonicalStreamChunks = async <Result>(
    input: CanonicalStreamChunkPumpInput<Result>,
): Promise<Result> => {
    for (
        let chunkIndex = 0;
        chunkIndex < input.lease.chunkCount;
        chunkIndex += 1
    ) {
        throwIfCancelled(input.abortSignal, input.createCancellationError);
        const bytes = await input.pullChunk({
            ...(input.abortSignal === undefined
                ? {}
                : { abortSignal: input.abortSignal }),
            chunkIndex,
            expectedByteLength: expectedChunkByteLength(
                input.lease,
                chunkIndex,
            ),
        });
        if (bytes === undefined) {
            throwIfCancelled(input.abortSignal, input.createCancellationError);
            return input.lease.finish();
        }
        try {
            throwIfCancelled(input.abortSignal, input.createCancellationError);
            input.lease.absorbChunk(chunkIndex, bytes);
            await input.consumeChunk?.({
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                bytes,
                chunkIndex,
            });
        } finally {
            releaseBuffer(bytes);
        }
    }

    const trailingBytes = await input.pullChunk({
        ...(input.abortSignal === undefined
            ? {}
            : { abortSignal: input.abortSignal }),
        chunkIndex: input.lease.chunkCount,
        expectedByteLength: 0,
    });
    if (trailingBytes !== undefined) {
        try {
            throwIfCancelled(input.abortSignal, input.createCancellationError);
            input.lease.absorbChunk(input.lease.chunkCount, trailingBytes);
        } finally {
            releaseBuffer(trailingBytes);
        }
    } else {
        throwIfCancelled(input.abortSignal, input.createCancellationError);
    }
    return input.lease.finish();
};
