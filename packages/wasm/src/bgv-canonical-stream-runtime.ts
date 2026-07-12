import type { RefusalReason } from '@sealed-lattice/types';
import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import {
    canonicalStreamDomains,
    canonicalStreamKernelContext,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
    type CanonicalStreamKernelContext,
    type CanonicalStreamLeaseState,
    type FillRandomValues,
} from './canonical-stream-runtime.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

const capabilityByteLength = 32;
const materialRootByteLength = 64;
const wasm32WordByteLength = 4;
const runtimeInternalFailureStatus = 0xffff_ffff;
const runtimeInvalidSessionStatus = 0xffff_fffe;

export const bgvCanonicalStreamFamilies = Object.freeze({
    vssOpeningCarry: 1,
    vssShareLinkage: 2,
    sameSecretBridge: 3,
    publicKeyShare: 4,
    trusteeEvaluationKey: 5,
    relinearizationComponent: 6,
    galoisComponent: 7,
} as const);

export type BgvCanonicalStreamFamily =
    (typeof bgvCanonicalStreamFamilies)[keyof typeof bgvCanonicalStreamFamilies];

export type BgvCanonicalStreamVerifierLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(chunkIndex: number, bytes: ArrayBuffer): void;
    cancel(): void;
    finish(): void;
    state(): CanonicalStreamLeaseState;
}>;

export type BgvCanonicalStreamRuntime = Readonly<{
    openVerifier(input: {
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): BgvCanonicalStreamVerifierLease;
    stage(input: {
        readonly chunks: readonly ArrayBuffer[];
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): Uint8Array;
}>;

type ActiveLease = {
    capabilityPointer: number;
    chunkCount: number;
    handle: number;
    state: CanonicalStreamLeaseState;
    totalByteLength: number;
};

const refusalReasonByCode = new Map<number, RefusalReason>(
    Object.entries(refusalReasonCodes).map(([reason, code]) => [
        code,
        reason as RefusalReason,
    ]),
);

const familyDomain = new Map<BgvCanonicalStreamFamily, CanonicalStreamDomain>([
    [
        bgvCanonicalStreamFamilies.vssOpeningCarry,
        canonicalStreamDomains.dealerVssShareLinkageProof,
    ],
    [
        bgvCanonicalStreamFamilies.vssShareLinkage,
        canonicalStreamDomains.dealerVssShareLinkageProof,
    ],
    [
        bgvCanonicalStreamFamilies.sameSecretBridge,
        canonicalStreamDomains.sameSecretProof,
    ],
    [
        bgvCanonicalStreamFamilies.publicKeyShare,
        canonicalStreamDomains.publicKeyShareProof,
    ],
    [
        bgvCanonicalStreamFamilies.trusteeEvaluationKey,
        canonicalStreamDomains.evaluatorKeyAggregateProof,
    ],
    [
        bgvCanonicalStreamFamilies.relinearizationComponent,
        canonicalStreamDomains.evaluatorKeyStore,
    ],
    [
        bgvCanonicalStreamFamilies.galoisComponent,
        canonicalStreamDomains.evaluatorKeyStore,
    ],
]);

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
    Object.prototype.toString.call(value) === '[object ArrayBuffer]';

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const materialRootBytes = (materialRoot: string): Uint8Array => {
    if (!/^[0-9a-f]{128}$/u.test(materialRoot)) {
        throw new CanonicalStreamRefusalError('malformedEncoding');
    }
    const bytes = new Uint8Array(materialRootByteLength);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            materialRoot.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const defaultFillRandomValues: FillRandomValues = (destination): void => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new CanonicalStreamInternalError(
            'Web Crypto getRandomValues is required for stream capabilities.',
        );
    }
    cryptoProvider.getRandomValues(destination);
};

class BgvCanonicalStreamRuntimeImplementation implements BgvCanonicalStreamRuntime {
    readonly #context: CanonicalStreamKernelContext;
    readonly #fillRandomValues: FillRandomValues;
    readonly #kernel: TranscriptCoreKernel;
    #activeLease: ActiveLease | undefined;

    public constructor(
        kernel: TranscriptCoreKernel,
        context: CanonicalStreamKernelContext,
        fillRandomValues: FillRandomValues,
    ) {
        this.#kernel = kernel;
        this.#context = context;
        this.#fillRandomValues = fillRandomValues;
        this.#requireBoundary();
    }

    public openVerifier(input: {
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): BgvCanonicalStreamVerifierLease {
        this.#prepareBegin(input.family);
        if (!isUint8Array(input.descriptorBytes)) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        if (
            input.descriptorBytes.byteLength === 0 ||
            input.descriptorBytes.byteLength >
                foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new CanonicalStreamResourceError(
                'The canonical stream descriptor exceeds the binary metadata profile.',
            );
        }
        const rootBytes = materialRootBytes(input.materialRoot);
        const capabilityPointer = this.#createCapability();
        let descriptorPointer = 0;
        let handle = 0;
        let metadataPointer = 0;
        let rootPointer = 0;
        let sessionActivated = false;
        try {
            rootPointer = this.#copyMetadataIntoWasm(rootBytes);
            descriptorPointer = this.#copyMetadataIntoWasm(
                input.descriptorBytes,
            );
            metadataPointer = this.#allocateMetadata(3);
            handle = this.#context.runExclusive(
                'BGV canonical stream begin',
                () =>
                    this.#context.bgvBegin!(
                        input.family,
                        rootPointer,
                        rootBytes.byteLength,
                        descriptorPointer,
                        input.descriptorBytes.byteLength,
                        capabilityPointer,
                        capabilityByteLength,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                        metadataPointer + 2 * wasm32WordByteLength,
                    ),
            );
            const [status, totalByteLength, chunkCount] = this.#readWords(
                metadataPointer,
                3,
            );
            this.#throwStatus(status);
            if (handle === 0 || totalByteLength === 0 || chunkCount === 0) {
                throw new CanonicalStreamInternalError(
                    'The BGV canonical stream returned malformed begin metadata.',
                );
            }
            const lease: ActiveLease = {
                capabilityPointer,
                chunkCount,
                handle,
                state: 'active',
                totalByteLength,
            };
            this.#activeLease = lease;
            sessionActivated = true;
            return this.#lease(lease);
        } catch (error) {
            if (handle !== 0) {
                this.#cancelUnactivated(handle, capabilityPointer, error);
            }
            throw error;
        } finally {
            rootBytes.fill(0);
            this.#zeroAndDeallocate(rootPointer, rootBytes.byteLength);
            this.#zeroAndDeallocate(
                descriptorPointer,
                input.descriptorBytes.byteLength,
            );
            if (metadataPointer !== 0) {
                this.#context.deallocate(
                    metadataPointer,
                    3 * wasm32WordByteLength,
                );
            }
            if (!sessionActivated) {
                this.#zeroAndDeallocate(
                    capabilityPointer,
                    capabilityByteLength,
                );
            }
        }
    }

    public stage(input: {
        readonly chunks: readonly ArrayBuffer[];
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): Uint8Array {
        const streamDomain = familyDomain.get(input.family);
        if (streamDomain === undefined) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
        if (
            Object.prototype.toString.call(input.chunks) !== '[object Array]' ||
            input.chunks.length === 0
        ) {
            throw new CanonicalStreamRefusalError('wrongTypeOrLength');
        }
        let totalByteLength = 0;
        for (const chunk of input.chunks) {
            if (!isArrayBuffer(chunk) || chunk.byteLength === 0) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            totalByteLength += chunk.byteLength;
            if (
                !Number.isSafeInteger(totalByteLength) ||
                totalByteLength > 0xffff_ffff
            ) {
                throw new CanonicalStreamResourceError();
            }
        }

        const writerRuntime = openCanonicalStreamWorkerRuntime({
            fillRandomValues: this.#fillRandomValues,
            kernel: this.#kernel,
        });
        const writer = writerRuntime.openWriter({
            streamDomain,
            totalByteLength,
        });
        let descriptorBytes: Uint8Array;
        try {
            if (writer.chunkCount !== input.chunks.length) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            input.chunks.forEach((chunk, chunkIndex) => {
                writer.absorbChunk(chunkIndex, chunk);
            });
            descriptorBytes = writer.finish();
        } catch (error) {
            writer.cancel();
            throw error;
        }

        const verifier = this.openVerifier({
            descriptorBytes,
            family: input.family,
            materialRoot: input.materialRoot,
        });
        try {
            input.chunks.forEach((chunk, chunkIndex) => {
                verifier.absorbChunk(chunkIndex, chunk);
            });
            verifier.finish();
            return descriptorBytes;
        } catch (error) {
            verifier.cancel();
            throw error;
        }
    }

    #lease(lease: ActiveLease): BgvCanonicalStreamVerifierLease {
        return Object.freeze({
            absorbChunk: (chunkIndex: number, bytes: ArrayBuffer): void =>
                this.#absorbChunk(lease, chunkIndex, bytes),
            cancel: (): void => this.#cancel(lease),
            chunkCount: lease.chunkCount,
            finish: (): void => this.#finish(lease),
            state: (): CanonicalStreamLeaseState => lease.state,
            totalByteLength: lease.totalByteLength,
        });
    }

    #absorbChunk(
        lease: ActiveLease,
        chunkIndex: number,
        bytes: ArrayBuffer,
    ): void {
        try {
            this.#requireActive(lease);
            if (
                !Number.isSafeInteger(chunkIndex) ||
                chunkIndex < 0 ||
                chunkIndex > 0xffff_ffff ||
                !isArrayBuffer(bytes) ||
                bytes.byteLength === 0
            ) {
                throw new CanonicalStreamRefusalError('wrongTypeOrLength');
            }
            if (bytes.byteLength > foundationProfile.streamChunkByteLength) {
                throw new CanonicalStreamResourceError(
                    'A BGV stream payload exceeds the canonical chunk bound.',
                );
            }
            const chunkPointer = this.#copyPayloadIntoWasm(bytes);
            try {
                const status = this.#context.runExclusive(
                    'BGV canonical stream chunk',
                    () =>
                        this.#context.bgvAbsorbChunk!(
                            lease.handle,
                            lease.capabilityPointer,
                            capabilityByteLength,
                            chunkIndex,
                            chunkPointer,
                            bytes.byteLength,
                        ),
                );
                this.#throwStatus(status);
            } finally {
                this.#context.deallocate(chunkPointer, bytes.byteLength);
            }
        } catch (error) {
            this.#fail(lease, error);
        }
    }

    #finish(lease: ActiveLease): void {
        try {
            this.#requireActive(lease);
            const status = this.#context.runExclusive(
                'BGV canonical stream finish',
                () =>
                    this.#context.bgvFinish!(
                        lease.handle,
                        lease.capabilityPointer,
                        capabilityByteLength,
                    ),
            );
            this.#throwStatus(status);
            lease.state = 'completed';
            this.#release(lease);
        } catch (error) {
            this.#fail(lease, error);
        }
    }

    #cancel(lease: ActiveLease): void {
        if (lease.state !== 'active') {
            return;
        }
        try {
            const status = this.#context.runExclusive(
                'BGV canonical stream cancellation',
                () =>
                    this.#context.bgvCancel!(
                        lease.handle,
                        lease.capabilityPointer,
                        capabilityByteLength,
                    ),
            );
            this.#throwStatus(status);
            lease.state = 'cancelled';
            this.#release(lease);
        } catch (error) {
            lease.state = 'failed';
            this.#release(lease);
            throw error;
        }
    }

    #fail(lease: ActiveLease, operationFailure: unknown): never {
        let cleanupFailure: unknown;
        if (lease.state === 'active') {
            try {
                const status = this.#context.runExclusive(
                    'BGV canonical stream failure cleanup',
                    () =>
                        this.#context.bgvCancel!(
                            lease.handle,
                            lease.capabilityPointer,
                            capabilityByteLength,
                        ),
                );
                this.#throwStatus(status);
            } catch (error) {
                cleanupFailure = error;
            }
        }
        lease.state = 'failed';
        this.#release(lease);
        if (cleanupFailure !== undefined) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }

    #cancelUnactivated(
        handle: number,
        capabilityPointer: number,
        operationFailure: unknown,
    ): never {
        try {
            const status = this.#context.runExclusive(
                'BGV canonical stream begin failure cleanup',
                () =>
                    this.#context.bgvCancel!(
                        handle,
                        capabilityPointer,
                        capabilityByteLength,
                    ),
            );
            this.#throwStatus(status);
        } catch (cleanupFailure) {
            throw new CanonicalStreamCleanupError(
                operationFailure,
                cleanupFailure,
            );
        }
        throw operationFailure;
    }

    #prepareBegin(family: number): void {
        if (this.#activeLease !== undefined) {
            this.#cancel(this.#activeLease);
            throw new CanonicalStreamResourceError(
                'Only one BGV canonical stream may be active in a WASM instance.',
            );
        }
        if (!familyDomain.has(family as BgvCanonicalStreamFamily)) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
    }

    #requireBoundary(): void {
        if (
            this.#context.bgvAbsorbChunk === undefined ||
            this.#context.bgvBegin === undefined ||
            this.#context.bgvCancel === undefined ||
            this.#context.bgvFinish === undefined
        ) {
            throw new CanonicalStreamInternalError(
                'The transcript-core kernel has no BGV canonical stream boundary.',
            );
        }
    }

    #requireActive(lease: ActiveLease): void {
        if (lease.state !== 'active' || this.#activeLease !== lease) {
            throw new CanonicalStreamInternalError(
                'The BGV canonical stream lease is no longer active.',
            );
        }
    }

    #release(lease: ActiveLease): void {
        if (this.#activeLease === lease) {
            this.#activeLease = undefined;
        }
        this.#zeroAndDeallocate(lease.capabilityPointer, capabilityByteLength);
        lease.capabilityPointer = 0;
    }

    #createCapability(): number {
        const capability = new Uint8Array(capabilityByteLength);
        try {
            this.#fillRandomValues(capability);
            if (capability.every((byte) => byte === 0)) {
                throw new CanonicalStreamInternalError(
                    'The stream capability entropy source returned an invalid value.',
                );
            }
            return this.#copyMetadataIntoWasm(capability);
        } catch (error) {
            if (error instanceof CanonicalStreamInternalError) {
                throw error;
            }
            throw new CanonicalStreamInternalError(
                'The stream capability entropy source failed.',
                error,
            );
        } finally {
            capability.fill(0);
        }
    }

    #copyMetadataIntoWasm(bytes: Uint8Array): number {
        const pointer = this.#allocate(bytes.byteLength);
        new Uint8Array(this.#context.memory.buffer).set(bytes, pointer);
        return pointer;
    }

    #copyPayloadIntoWasm(bytes: ArrayBuffer): number {
        const pointer = this.#allocate(bytes.byteLength);
        new Uint8Array(this.#context.memory.buffer).set(
            new Uint8Array(bytes),
            pointer,
        );
        return pointer;
    }

    #allocateMetadata(wordCount: number): number {
        const byteLength = wordCount * wasm32WordByteLength;
        const pointer = this.#allocate(byteLength);
        new Uint8Array(this.#context.memory.buffer, pointer, byteLength).fill(
            0,
        );
        return pointer;
    }

    #allocate(byteLength: number): number {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength <= 0 ||
            byteLength > foundationProfile.maximumCopiedBufferByteLength ||
            this.#context.memory.buffer.byteLength >
                foundationProfile.maximumWasmMemoryByteLength - byteLength
        ) {
            throw new CanonicalStreamResourceError(
                'The BGV canonical stream allocation exceeds the WASM profile.',
            );
        }
        const pointer = this.#context.allocate(byteLength) >>> 0;
        if (
            pointer === 0 ||
            pointer + byteLength > this.#context.memory.buffer.byteLength
        ) {
            throw new CanonicalStreamInternalError(
                'The WASM allocator returned an invalid BGV stream range.',
            );
        }
        return pointer;
    }

    #readWords(pointer: number, wordCount: number): readonly number[] {
        const byteLength = wordCount * wasm32WordByteLength;
        if (
            pointer === 0 ||
            pointer + byteLength > this.#context.memory.buffer.byteLength
        ) {
            throw new CanonicalStreamInternalError(
                'The BGV stream metadata range is invalid.',
            );
        }
        const view = new DataView(
            this.#context.memory.buffer,
            pointer,
            byteLength,
        );
        return Array.from({ length: wordCount }, (_, wordIndex) =>
            view.getUint32(wordIndex * wasm32WordByteLength, true),
        );
    }

    #zeroAndDeallocate(pointer: number, byteLength: number): void {
        if (pointer === 0) {
            return;
        }
        new Uint8Array(this.#context.memory.buffer, pointer, byteLength).fill(
            0,
        );
        this.#context.deallocate(pointer, byteLength);
    }

    #throwStatus(status: number): void {
        if (status === 0) {
            return;
        }
        if (
            status === runtimeInternalFailureStatus ||
            status === runtimeInvalidSessionStatus
        ) {
            throw new CanonicalStreamInternalError(
                'The WASM BGV canonical stream session failed internally.',
            );
        }
        const refusalReason = refusalReasonByCode.get(status);
        if (refusalReason === undefined) {
            throw new CanonicalStreamInternalError(
                'The WASM BGV canonical stream returned an unknown status code.',
            );
        }
        if (refusalReason === 'outsideSupportedProfile') {
            throw new CanonicalStreamResourceError();
        }
        throw new CanonicalStreamRefusalError(refusalReason);
    }
}

export const openBgvCanonicalStreamRuntime = (input: {
    readonly fillRandomValues?: FillRandomValues;
    readonly kernel: TranscriptCoreKernel;
}): BgvCanonicalStreamRuntime => {
    const context = canonicalStreamKernelContext(input.kernel);
    if (context === undefined) {
        throw new CanonicalStreamInternalError(
            'The transcript-core kernel has no registered stream boundary.',
        );
    }
    return Object.freeze(
        new BgvCanonicalStreamRuntimeImplementation(
            input.kernel,
            context,
            input.fillRandomValues ?? defaultFillRandomValues,
        ),
    );
};
