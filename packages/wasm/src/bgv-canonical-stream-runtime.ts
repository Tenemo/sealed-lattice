import { foundationProfile } from '@sealed-lattice/types';

import { beginAcceptedSetupCanonicalStream } from './accepted-setup-session-runtime.js';
import {
    canonicalStreamDomains,
    canonicalStreamKernelContext,
    CanonicalStreamCancellationError,
    CanonicalStreamCleanupError,
    CanonicalStreamInternalError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
    type CanonicalStreamChunkPull,
    type CanonicalStreamChunkSink,
    type CanonicalStreamKernelContext,
    type CanonicalStreamLeaseState,
    type CanonicalStreamWriterLease,
} from './canonical-stream-runtime.js';
import { refusalReasonByCode } from './transcript-core-bridge/kernel-errors.js';
import type {
    TranscriptCoreKernelContextOwner,
    AcceptedSetupSession,
} from './transcript-core-bridge/kernel-types.js';

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
    publicKeyShareMaterial: 9,
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
    writeMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly emitChunk: CanonicalStreamChunkSink;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): Promise<Uint8Array>;
    writeSourceMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly emitChunk: CanonicalStreamChunkSink;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly totalByteLength: number;
    }): Promise<Uint8Array>;
    readMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: CanonicalStreamChunkPull;
    }): Promise<void>;
    stageSourceMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly totalByteLength: number;
    }): Promise<void>;
    openVerifier(input: {
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): BgvCanonicalStreamVerifierLease;
}>;

type ActiveLease = {
    chunkCount: number;
    handle: number;
    kind: 'material-reader' | 'verifier';
    state: CanonicalStreamLeaseState;
    totalByteLength: number;
};

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
    [
        bgvCanonicalStreamFamilies.publicKeyShareMaterial,
        canonicalStreamDomains.publicKeyShareMaterial,
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

class BgvCanonicalStreamRuntimeImplementation implements BgvCanonicalStreamRuntime {
    readonly #acceptedSetupSession: AcceptedSetupSession | undefined;
    readonly #context: CanonicalStreamKernelContext;
    readonly #kernel: TranscriptCoreKernelContextOwner;
    #activeLease: ActiveLease | undefined;

    public constructor(
        kernel: TranscriptCoreKernelContextOwner,
        context: CanonicalStreamKernelContext,
        acceptedSetupSession: AcceptedSetupSession | undefined,
    ) {
        this.#kernel = kernel;
        this.#context = context;
        this.#acceptedSetupSession = acceptedSetupSession;
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
        let descriptorPointer = 0;
        let handle = 0;
        let metadataPointer = 0;
        let rootPointer = 0;
        try {
            rootPointer = this.#copyMetadataIntoWasm(rootBytes);
            descriptorPointer = this.#copyMetadataIntoWasm(
                input.descriptorBytes,
            );
            metadataPointer = this.#allocateMetadata(3);
            handle = this.#context.runExclusive(
                'BGV canonical stream begin',
                () =>
                    this.#acceptedSetupSession === undefined
                        ? this.#context.bgvBegin!(
                              input.family,
                              rootPointer,
                              rootBytes.byteLength,
                              descriptorPointer,
                              input.descriptorBytes.byteLength,
                              metadataPointer,
                              metadataPointer + wasm32WordByteLength,
                              metadataPointer + 2 * wasm32WordByteLength,
                          )
                        : beginAcceptedSetupCanonicalStream(
                              this.#acceptedSetupSession,
                              {
                                  chunkCountPointer:
                                      metadataPointer +
                                      2 * wasm32WordByteLength,
                                  descriptorLength:
                                      input.descriptorBytes.byteLength,
                                  descriptorPointer,
                                  familyCode: input.family,
                                  materialRootLength: rootBytes.byteLength,
                                  materialRootPointer: rootPointer,
                                  statusPointer: metadataPointer,
                                  totalByteLengthPointer:
                                      metadataPointer + wasm32WordByteLength,
                              },
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
            if (
                this.#context.memory.buffer.byteLength >
                foundationProfile.maximumWasmMemoryByteLength - totalByteLength
            ) {
                throw new CanonicalStreamResourceError(
                    'Retaining the BGV canonical material would exceed the remaining WASM memory profile.',
                );
            }
            const lease: ActiveLease = {
                chunkCount,
                handle,
                kind: 'verifier',
                state: 'active',
                totalByteLength,
            };
            this.#activeLease = lease;
            return this.#lease(lease);
        } catch (error) {
            if (handle !== 0) {
                this.#cancelUnactivated(handle, error);
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
        }
    }

    public async writeMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly emitChunk: CanonicalStreamChunkSink;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
    }): Promise<Uint8Array> {
        this.#prepareBegin(input.family);
        this.#requireMaterialReaderBoundary();
        const streamDomain = familyDomain.get(input.family);
        if (streamDomain === undefined) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
        const rootBytes = materialRootBytes(input.materialRoot);
        let handle = 0;
        let metadataPointer = 0;
        let rootPointer = 0;
        let readerLease: ActiveLease | undefined;
        let writer: CanonicalStreamWriterLease | undefined;
        try {
            rootPointer = this.#copyMetadataIntoWasm(rootBytes);
            metadataPointer = this.#allocateMetadata(3);
            handle = this.#context.runExclusive(
                'BGV canonical material reader begin',
                () =>
                    this.#context.bgvMaterialReaderBegin!(
                        input.family,
                        rootPointer,
                        rootBytes.byteLength,
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
            if (
                handle === 0 ||
                totalByteLength === 0 ||
                chunkCount === 0 ||
                chunkCount !==
                    Math.ceil(
                        totalByteLength /
                            foundationProfile.streamChunkByteLength,
                    )
            ) {
                throw new CanonicalStreamInternalError(
                    'The BGV material reader returned malformed begin metadata.',
                );
            }
            readerLease = {
                chunkCount,
                handle,
                kind: 'material-reader',
                state: 'active',
                totalByteLength,
            };
            this.#activeLease = readerLease;

            writer = openCanonicalStreamWorkerRuntime({
                kernel: this.#kernel,
            }).openWriter({ streamDomain, totalByteLength });
            if (writer.chunkCount !== chunkCount) {
                throw new CanonicalStreamInternalError(
                    'The material reader and canonical writer disagree on chunk count.',
                );
            }
            for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
                this.#throwIfCancelled(input.abortSignal);
                const consumedByteLength =
                    chunkIndex * foundationProfile.streamChunkByteLength;
                const chunkByteLength = Math.min(
                    foundationProfile.streamChunkByteLength,
                    totalByteLength - consumedByteLength,
                );
                let chunk: ArrayBuffer;
                const outputPointer = this.#allocate(chunkByteLength);
                try {
                    const readStatus = this.#context.runExclusive(
                        'BGV canonical material reader chunk',
                        () =>
                            this.#context.bgvMaterialReaderReadChunk!(
                                handle,
                                chunkIndex,
                                outputPointer,
                                chunkByteLength,
                            ),
                    );
                    this.#throwStatus(readStatus);
                    chunk = new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        chunkByteLength,
                    ).slice().buffer;
                } finally {
                    this.#zeroAndDeallocate(outputPointer, chunkByteLength);
                }
                try {
                    this.#throwIfCancelled(input.abortSignal);
                    writer.absorbChunk(chunkIndex, chunk);
                    await input.emitChunk({
                        ...(input.abortSignal === undefined
                            ? {}
                            : { abortSignal: input.abortSignal }),
                        bytes: chunk,
                        chunkIndex,
                    });
                } finally {
                    this.#releaseBuffer(chunk);
                }
            }
            this.#throwIfCancelled(input.abortSignal);
            const finishStatus = this.#context.runExclusive(
                'BGV canonical material reader finish',
                () => this.#context.bgvMaterialReaderFinish!(handle),
            );
            this.#throwStatus(finishStatus);
            readerLease.state = 'completed';
            this.#release(readerLease);
            readerLease = undefined;
            const descriptorBytes = writer.finish();
            writer = undefined;

            return descriptorBytes;
        } catch (operationFailure) {
            let cleanupFailure: unknown;
            if (writer?.state() === 'active') {
                try {
                    writer.cancel();
                } catch (error) {
                    cleanupFailure = error;
                }
            }
            if (readerLease?.state === 'active') {
                try {
                    const cancelStatus = this.#context.runExclusive(
                        'BGV canonical material reader failure cleanup',
                        () =>
                            this.#context.bgvMaterialReaderCancel!(
                                readerLease!.handle,
                            ),
                    );
                    if (cancelStatus >>> 0 !== runtimeInvalidSessionStatus) {
                        this.#throwStatus(cancelStatus);
                    }
                } catch (error) {
                    cleanupFailure ??= error;
                }
                readerLease.state = 'failed';
                this.#release(readerLease);
                readerLease = undefined;
            } else if (handle !== 0 && this.#activeLease === undefined) {
                try {
                    const cancelStatus = this.#context.runExclusive(
                        'BGV canonical material reader begin cleanup',
                        () => this.#context.bgvMaterialReaderCancel!(handle),
                    );
                    if (cancelStatus >>> 0 !== runtimeInvalidSessionStatus) {
                        this.#throwStatus(cancelStatus);
                    }
                } catch (error) {
                    cleanupFailure ??= error;
                }
            }
            if (cleanupFailure !== undefined) {
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
            throw operationFailure;
        } finally {
            rootBytes.fill(0);
            this.#zeroAndDeallocate(rootPointer, rootBytes.byteLength);
            if (metadataPointer !== 0) {
                this.#context.deallocate(
                    metadataPointer,
                    3 * wasm32WordByteLength,
                );
            }
        }
    }

    public async writeSourceMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly emitChunk: CanonicalStreamChunkSink;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly totalByteLength: number;
    }): Promise<Uint8Array> {
        this.#prepareBegin(input.family);
        const streamDomain = familyDomain.get(input.family);
        if (streamDomain === undefined) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
        const rootBytes = materialRootBytes(input.materialRoot);
        try {
            return await openCanonicalStreamWorkerRuntime({
                kernel: this.#kernel,
            }).write({
                ...(input.abortSignal === undefined
                    ? {}
                    : { abortSignal: input.abortSignal }),
                emitChunk: input.emitChunk,
                pullChunk: input.pullChunk,
                streamDomain,
                totalByteLength: input.totalByteLength,
            });
        } finally {
            rootBytes.fill(0);
        }
    }

    public async readMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly descriptorBytes: Uint8Array;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: CanonicalStreamChunkPull;
    }): Promise<void> {
        const verifier = this.openVerifier(input);
        let operationFailure: unknown;
        let operationFailed = false;
        let sourceEndedBeforeTrailingCheck = false;
        try {
            for (
                let chunkIndex = 0;
                chunkIndex < verifier.chunkCount;
                chunkIndex += 1
            ) {
                this.#throwIfCancelled(input.abortSignal);
                const bytes = await input.pullChunk({
                    ...(input.abortSignal === undefined
                        ? {}
                        : { abortSignal: input.abortSignal }),
                    chunkIndex,
                    expectedByteLength: this.#expectedChunkByteLength(
                        verifier,
                        chunkIndex,
                    ),
                });
                if (bytes === undefined) {
                    this.#throwIfCancelled(input.abortSignal);
                    verifier.finish();
                    sourceEndedBeforeTrailingCheck = true;
                    break;
                }
                try {
                    this.#throwIfCancelled(input.abortSignal);
                    verifier.absorbChunk(chunkIndex, bytes);
                } finally {
                    this.#releaseBuffer(bytes);
                }
            }
            if (!sourceEndedBeforeTrailingCheck) {
                const trailingBytes = await input.pullChunk({
                    ...(input.abortSignal === undefined
                        ? {}
                        : { abortSignal: input.abortSignal }),
                    chunkIndex: verifier.chunkCount,
                    expectedByteLength: 0,
                });
                if (trailingBytes !== undefined) {
                    try {
                        this.#throwIfCancelled(input.abortSignal);
                        verifier.absorbChunk(
                            verifier.chunkCount,
                            trailingBytes,
                        );
                    } finally {
                        this.#releaseBuffer(trailingBytes);
                    }
                } else {
                    this.#throwIfCancelled(input.abortSignal);
                }
                verifier.finish();
            }
        } catch (error) {
            operationFailure = error;
            operationFailed = true;
        }

        let cleanupFailure: unknown;
        let cleanupFailed = false;
        try {
            verifier.cancel();
        } catch (error) {
            cleanupFailure = error;
            cleanupFailed = true;
        }
        if (cleanupFailed) {
            if (operationFailed) {
                throw new CanonicalStreamCleanupError(
                    operationFailure,
                    cleanupFailure,
                );
            }
            throw cleanupFailure;
        }
        if (operationFailed) {
            throw operationFailure;
        }
    }

    public async stageSourceMaterial(input: {
        readonly abortSignal?: AbortSignal;
        readonly family: BgvCanonicalStreamFamily;
        readonly materialRoot: string;
        readonly pullChunk: CanonicalStreamChunkPull;
        readonly totalByteLength: number;
    }): Promise<void> {
        const descriptorBytes = await this.writeSourceMaterial({
            ...(input.abortSignal === undefined
                ? {}
                : { abortSignal: input.abortSignal }),
            emitChunk: (): Promise<void> => Promise.resolve(),
            family: input.family,
            materialRoot: input.materialRoot,
            pullChunk: input.pullChunk,
            totalByteLength: input.totalByteLength,
        });
        await this.readMaterial({
            ...(input.abortSignal === undefined
                ? {}
                : { abortSignal: input.abortSignal }),
            descriptorBytes,
            family: input.family,
            materialRoot: input.materialRoot,
            pullChunk: input.pullChunk,
        });
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
            if (lease.kind !== 'verifier') {
                throw new CanonicalStreamInternalError(
                    'A material-reader lease cannot absorb verifier chunks.',
                );
            }
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
            if (lease.kind !== 'verifier') {
                throw new CanonicalStreamInternalError(
                    'A material-reader lease cannot finish as a verifier.',
                );
            }
            const status = this.#context.runExclusive(
                'BGV canonical stream finish',
                () => this.#context.bgvFinish!(lease.handle),
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
                    lease.kind === 'material-reader'
                        ? this.#context.bgvMaterialReaderCancel!(lease.handle)
                        : this.#context.bgvCancel!(lease.handle),
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
                    () => this.#context.bgvCancel!(lease.handle),
                );
                if (status >>> 0 !== runtimeInvalidSessionStatus) {
                    this.#throwStatus(status);
                }
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

    #cancelUnactivated(handle: number, operationFailure: unknown): never {
        try {
            const status = this.#context.runExclusive(
                'BGV canonical stream begin failure cleanup',
                () => this.#context.bgvCancel!(handle),
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
            throw new CanonicalStreamResourceError(
                'Only one BGV canonical stream may be active in a WASM instance.',
            );
        }
        if (!familyDomain.has(family as BgvCanonicalStreamFamily)) {
            throw new CanonicalStreamRefusalError('malformedEncoding');
        }
    }

    #throwIfCancelled(abortSignal: AbortSignal | undefined): void {
        if (abortSignal?.aborted === true) {
            throw new CanonicalStreamCancellationError();
        }
    }

    #expectedChunkByteLength(
        lease: BgvCanonicalStreamVerifierLease,
        chunkIndex: number,
    ): number {
        if (chunkIndex + 1 < lease.chunkCount) {
            return foundationProfile.streamChunkByteLength;
        }
        return (
            lease.totalByteLength -
            (lease.chunkCount - 1) * foundationProfile.streamChunkByteLength
        );
    }

    #releaseBuffer(buffer: ArrayBuffer): void {
        if (buffer.byteLength > 0) {
            new Uint8Array(buffer).fill(0);
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

    #requireMaterialReaderBoundary(): void {
        if (
            this.#context.bgvMaterialReaderBegin === undefined ||
            this.#context.bgvMaterialReaderCancel === undefined ||
            this.#context.bgvMaterialReaderFinish === undefined ||
            this.#context.bgvMaterialReaderReadChunk === undefined
        ) {
            throw new CanonicalStreamInternalError(
                'The transcript-core kernel has no BGV canonical material-reader boundary.',
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
        const normalizedStatus = status >>> 0;
        if (normalizedStatus === 0) {
            return;
        }
        if (
            normalizedStatus === runtimeInternalFailureStatus ||
            normalizedStatus === runtimeInvalidSessionStatus
        ) {
            throw new CanonicalStreamInternalError(
                'The WASM BGV canonical stream session failed internally.',
            );
        }
        const refusalReason = refusalReasonByCode.get(normalizedStatus);
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
    readonly acceptedSetupSession?: AcceptedSetupSession;
    readonly kernel: TranscriptCoreKernelContextOwner;
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
            input.acceptedSetupSession,
        ),
    );
};
