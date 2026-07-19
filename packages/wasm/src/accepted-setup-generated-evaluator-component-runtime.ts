import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { foundationProfile } from '@sealed-lattice/types';

import {
    createAcceptedSetupEvaluatorComponentBacking,
    releaseUnretainedAcceptedSetupEvaluatorComponentBackings,
    type AcceptedSetupEvaluatorComponentBacking,
} from './accepted-setup-assembly-runtime.js';
import {
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    deriveCanonicalStreamChunkCount,
} from './canonical-stream-runtime.js';
import type { CommonProofCanonicalOutputStore } from './common-proof-worker-runtime/runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

const hashByteLength = 64;

/** Durable browser storage transferred into evaluator-source catalog custody. */
export type GeneratedEvaluatorComponentStore = CommonProofCanonicalOutputStore &
    Readonly<{
        release(): void;
    }>;

/** Canonical public bindings for replaying one generated evaluator component. */
export type GeneratedEvaluatorComponentDescription = Readonly<{
    materialRoot: Uint8Array<ArrayBuffer>;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}>;

type DecodedComponentDescription = Readonly<{
    chunkByteLengths: readonly number[];
    fullObjectDigest: Uint8Array<ArrayBuffer>;
    totalByteLength: number;
}>;

export type GeneratedEvaluatorComponentReadback = Readonly<{
    componentCount(): number;
    copyDescriptor(componentOrdinal: number): Uint8Array<ArrayBuffer>;
    copyMaterialRoot(componentOrdinal: number): Uint8Array<ArrayBuffer>;
    readChunk(
        componentOrdinal: number,
        chunkIndex: number,
        chunkByteLength: number,
    ): Uint8Array<ArrayBuffer>;
    totalByteLength(componentOrdinal: number): bigint;
}>;

const decodeComponentDescription = (input: {
    kernel: TranscriptCoreKernel;
    streamDescriptorBytes: Uint8Array<ArrayBuffer>;
}): DecodedComponentDescription => {
    let decoded;
    try {
        decoded = input.kernel.decodeStreamDescriptor({
            canonicalBytesHex: bytesToHex(input.streamDescriptorBytes),
        }).value;
    } catch (error) {
        throw new CanonicalStreamInternalError(
            'Rust returned a malformed generated evaluator component descriptor.',
            { cause: error },
        );
    }
    const totalByteLength = Number(decoded.totalByteLength);
    if (
        !Number.isSafeInteger(totalByteLength) ||
        totalByteLength <= 0 ||
        totalByteLength > foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new CanonicalStreamInternalError(
            'A generated evaluator component is outside the canonical stream bounds.',
        );
    }
    const chunkCount = deriveCanonicalStreamChunkCount(totalByteLength);
    if (decoded.orderedChunkDigests.length !== chunkCount) {
        throw new CanonicalStreamInternalError(
            'A generated evaluator component has the wrong canonical chunk count.',
        );
    }
    const fullObjectDigest = Uint8Array.from(
        hexToBytes(decoded.fullObjectDigest),
    );
    if (fullObjectDigest.byteLength !== hashByteLength) {
        throw new CanonicalStreamInternalError(
            'A generated evaluator component has the wrong stream-digest length.',
        );
    }
    return Object.freeze({
        chunkByteLengths: Object.freeze(
            Array.from({ length: chunkCount }, (_, chunkIndex) =>
                Math.min(
                    foundationProfile.streamChunkByteLength,
                    totalByteLength -
                        chunkIndex * foundationProfile.streamChunkByteLength,
                ),
            ),
        ),
        fullObjectDigest,
        totalByteLength,
    });
};

const readExactStoreRange = async (input: {
    chunkByteLengths: readonly number[];
    exactByteLength: number;
    sourceByteOffset: bigint;
    store: GeneratedEvaluatorComponentStore;
    totalByteLength: number;
}): Promise<Uint8Array<ArrayBuffer>> => {
    if (
        typeof input.sourceByteOffset !== 'bigint' ||
        input.sourceByteOffset < 0n ||
        !Number.isSafeInteger(input.exactByteLength) ||
        input.exactByteLength <= 0
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const sourceByteOffset = Number(input.sourceByteOffset);
    if (
        !Number.isSafeInteger(sourceByteOffset) ||
        sourceByteOffset + input.exactByteLength > input.totalByteLength
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const output = new Uint8Array(input.exactByteLength);
    let outputOffset = 0;
    let absoluteOffset = sourceByteOffset;
    while (outputOffset < output.byteLength) {
        const chunkIndex = Math.floor(
            absoluteOffset / foundationProfile.streamChunkByteLength,
        );
        const chunkByteOffset =
            absoluteOffset % foundationProfile.streamChunkByteLength;
        const expectedChunkByteLength = input.chunkByteLengths[chunkIndex];
        if (expectedChunkByteLength === undefined) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        const chunk = await input.store.readChunk(
            chunkIndex,
            expectedChunkByteLength,
        );
        if (
            !(chunk instanceof Uint8Array) ||
            chunk.byteLength !== expectedChunkByteLength
        ) {
            throw new CanonicalStreamRefusalError('wrongHashOrRoot');
        }
        const copiedByteLength = Math.min(
            chunk.byteLength - chunkByteOffset,
            output.byteLength - outputOffset,
        );
        output.set(
            chunk.subarray(chunkByteOffset, chunkByteOffset + copiedByteLength),
            outputOffset,
        );
        outputOffset += copiedByteLength;
        absoluteOffset += copiedByteLength;
    }
    return output;
};

export const readCompleteGeneratedEvaluatorComponent = async (input: {
    component: GeneratedEvaluatorComponentDescription;
    kernel: TranscriptCoreKernel;
    store: GeneratedEvaluatorComponentStore;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const decoded = decodeComponentDescription({
        kernel: input.kernel,
        streamDescriptorBytes: input.component.streamDescriptorBytes,
    });
    return readExactStoreRange({
        chunkByteLengths: decoded.chunkByteLengths,
        exactByteLength: decoded.totalByteLength,
        sourceByteOffset: 0n,
        store: input.store,
        totalByteLength: decoded.totalByteLength,
    });
};

export const persistGeneratedEvaluatorComponents = async (input: {
    expectedComponentCount: number;
    kernel: TranscriptCoreKernel;
    readback: GeneratedEvaluatorComponentReadback;
    stores: readonly GeneratedEvaluatorComponentStore[];
}): Promise<
    Readonly<{
        backings: readonly AcceptedSetupEvaluatorComponentBacking[];
        components: readonly GeneratedEvaluatorComponentDescription[];
    }>
> => {
    const componentCount = input.readback.componentCount();
    if (
        componentCount !== input.expectedComponentCount ||
        input.stores.length !== componentCount
    ) {
        throw new CanonicalStreamRefusalError('wrongTypeOrLength');
    }
    const backings: AcceptedSetupEvaluatorComponentBacking[] = [];
    const components: GeneratedEvaluatorComponentDescription[] = [];
    const adoptedStores = new Set<number>();
    let operationFailure: unknown;
    try {
        for (
            let componentOrdinal = 0;
            componentOrdinal < componentCount;
            componentOrdinal += 1
        ) {
            const store = input.stores[componentOrdinal];
            if (
                store === undefined ||
                typeof store.commitChunk !== 'function' ||
                typeof store.readChunk !== 'function' ||
                typeof store.release !== 'function'
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            const streamDescriptorBytes =
                input.readback.copyDescriptor(componentOrdinal);
            const materialRoot =
                input.readback.copyMaterialRoot(componentOrdinal);
            if (materialRoot.byteLength !== hashByteLength) {
                throw new CanonicalStreamInternalError(
                    'Rust returned a generated evaluator material root with the wrong length.',
                );
            }
            const decoded = decodeComponentDescription({
                kernel: input.kernel,
                streamDescriptorBytes,
            });
            if (
                input.readback.totalByteLength(componentOrdinal) !==
                BigInt(decoded.totalByteLength)
            ) {
                throw new CanonicalStreamInternalError(
                    'Generated evaluator component readback disagrees with its descriptor.',
                );
            }
            for (
                let chunkIndex = 0;
                chunkIndex < decoded.chunkByteLengths.length;
                chunkIndex += 1
            ) {
                const chunkByteLength = decoded.chunkByteLengths[chunkIndex];
                const chunk = input.readback.readChunk(
                    componentOrdinal,
                    chunkIndex,
                    chunkByteLength,
                );
                try {
                    await store.commitChunk(chunkIndex, chunk);
                } finally {
                    chunk.fill(0);
                }
            }
            const backing = createAcceptedSetupEvaluatorComponentBacking({
                authenticatedByteLength: BigInt(decoded.totalByteLength),
                fullObjectDigest: decoded.fullObjectDigest,
                kernel: input.kernel,
                materialRoot,
                readExactRange: (sourceByteOffset, exactByteLength) =>
                    readExactStoreRange({
                        chunkByteLengths: decoded.chunkByteLengths,
                        exactByteLength,
                        sourceByteOffset,
                        store,
                        totalByteLength: decoded.totalByteLength,
                    }),
                release: () => store.release(),
            });
            adoptedStores.add(componentOrdinal);
            backings.push(backing);
            components.push(
                Object.freeze({ materialRoot, streamDescriptorBytes }),
            );
        }
        return Object.freeze({
            backings: Object.freeze(backings),
            components: Object.freeze(components),
        });
    } catch (error) {
        operationFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    if (backings.length > 0) {
        try {
            releaseUnretainedAcceptedSetupEvaluatorComponentBackings(
                backings,
                input.kernel,
            );
        } catch (cleanupFailure) {
            cleanupFailures.push(cleanupFailure);
        }
    }
    input.stores.forEach((store, componentOrdinal) => {
        if (!adoptedStores.has(componentOrdinal)) {
            try {
                store.release();
            } catch (cleanupFailure) {
                cleanupFailures.push(cleanupFailure);
            }
        }
    });
    if (cleanupFailures.length > 0) {
        throw new CanonicalStreamInternalError(
            'Generated evaluator component persistence failed to retire browser storage.',
            Object.freeze({ cleanupFailures, operationFailure }),
        );
    }
    throw operationFailure;
};
