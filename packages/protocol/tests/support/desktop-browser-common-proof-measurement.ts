import { sha512 } from '@noble/hashes/sha2.js';
import { foundationProfile } from '@sealed-lattice/types';
import type {
    AuthenticatedCommonProofInputStore,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofGenerationCheckpoint,
} from '@sealed-lattice/wasm';

import type {
    CommonProofBrowserCustody,
    CommonProofCheckpointResumeDescriptor,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import { requireDesktopBrowserCommonProofMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-case-identifier';
import {
    requireProductionDesktopBrowserMeasurementIdentity,
    type ProductionDesktopBrowserMeasurementIdentity,
} from '#packages/protocol/tests/support/desktop-browser-production-measurement-identity';

export type DesktopBrowserProofExecutionKind = 'fresh' | 'resumed';

export type DesktopBrowserCommonProofMeasurementWorkerSession = Readonly<{
    /** Releases resources after the measured execution, including failures. */
    close(): Promise<void>;
    custody: CommonProofBrowserCustody;
    /**
     * Runs production proof generation and terminal verification through the
     * instrumented custody, leaving its sealed authenticated output readable
     * until the recorder hashes it before close settles the custody.
     */
    execute(input: {
        custody: CommonProofBrowserCustody;
        yieldControl(): Promise<void>;
    }): Promise<void>;
    measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
    wasmMemory: WebAssembly.Memory;
}>;

export type ProductionDesktopBrowserCommonProofMeasurementCase = Readonly<{
    caseIdentifier: string;
    executionKind: DesktopBrowserProofExecutionKind;
    /** Opens resources but does not begin proof work or checkpoint replay. */
    open(): Promise<DesktopBrowserCommonProofMeasurementWorkerSession>;
}>;

export type DesktopBrowserCommonProofMeasurement = Readonly<{
    boundaryBufferTraffic: Readonly<{
        bufferCount: number;
        maximumBufferByteLength: number;
        totalByteLength: number;
    }>;
    canonicalOutputTraffic: Readonly<{
        authenticatedInputReadByteLength: number;
        authenticatedInputReadCount: number;
        authenticatedInputRequestedByteLength: number;
        committedByteLength: number;
        committedChunkCount: number;
        outputReadByteLength: number;
        outputReadCount: number;
        outputRequestedByteLength: number;
        sealCount: number;
    }>;
    caseIdentifier: string;
    checkpointTraffic: Readonly<{
        copiedResumeDescriptorByteLength: number;
        copiedResumeDescriptorCount: number;
        publishedCanonicalStateByteLength: number;
        publishedCheckpointCount: number;
        publishedCursorManifestByteLength: number;
        publishedPrivateRandomnessIdentifierByteLength: number;
        publishedStableBindingByteLength: number;
        restoredCanonicalStateByteLength: number;
        restoredCheckpointCount: number;
    }>;
    elapsedMilliseconds: number;
    executionKind: DesktopBrowserProofExecutionKind;
    externalMemoryTraffic: Readonly<{
        appendByteLength: number;
        appendOperationCount: number;
        createOperationCount: number;
        createdDeclaredByteLength: number;
        deleteOperationCount: number;
        operationCount: number;
        peakLiveDeclaredByteLength: number;
        prefixReplayTransactionCount: number;
        readOperationCount: number;
        requestedReadByteLength: number;
        returnedReadByteLength: number;
        sealOperationCount: number;
        transactionCount: number;
    }>;
    handoffTraffic: Readonly<{
        armedHandoffCount: number;
        returnedMarkerByteLength: number;
    }>;
    measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
    publicOutputHashes: Readonly<{
        canonicalProofStreamSha512: string;
    }>;
    wasmMemory: Readonly<{
        finalByteLength: number;
        growthByteLength: number;
        growthObservationCount: number;
        initialByteLength: number;
        observationCount: number;
        peakByteLength: number;
    }>;
}>;

const checkedAdd = (
    currentValue: number,
    addedValue: number,
    label: string,
): number => {
    const sum = currentValue + addedValue;
    if (
        !Number.isSafeInteger(currentValue) ||
        !Number.isSafeInteger(addedValue) ||
        addedValue < 0 ||
        !Number.isSafeInteger(sum)
    ) {
        throw new Error(`${label} exceeds the exact integer range.`);
    }
    return sum;
};

const exactNumberFromBigInt = (value: bigint, label: string): number => {
    const numberValue = Number(value);
    if (
        value < 0n ||
        !Number.isSafeInteger(numberValue) ||
        BigInt(numberValue) !== value
    ) {
        throw new Error(`${label} exceeds the exact integer range.`);
    }
    return numberValue;
};

const requireByteLength = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${label} is not an exact byte length.`);
    }
    return value;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hashCanonicalProofStream = async (
    custody: CommonProofBrowserCustody,
): Promise<string> => {
    const inputStore = custody.authenticatedOutput();
    const declaredByteLength = requireByteLength(
        inputStore.declaredByteLength,
        'Canonical proof-stream length',
    );
    if (
        declaredByteLength === 0 ||
        declaredByteLength > foundationProfile.maximumCanonicalStreamByteLength
    ) {
        throw new Error(
            'The production common-proof measurement produced an invalid canonical proof-stream length.',
        );
    }
    const hasher = sha512.create();
    const chunkCount = Math.ceil(
        declaredByteLength / foundationProfile.streamChunkByteLength,
    );
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const exactByteLength = Math.min(
            foundationProfile.streamChunkByteLength,
            declaredByteLength -
                chunkIndex * foundationProfile.streamChunkByteLength,
        );
        const returnedBytes = await inputStore.readCommittedChunk(
            chunkIndex,
            exactByteLength,
        );
        if (
            !(returnedBytes instanceof Uint8Array) ||
            returnedBytes.byteLength !== exactByteLength ||
            !(returnedBytes.buffer instanceof ArrayBuffer) ||
            returnedBytes.byteOffset !== 0 ||
            returnedBytes.byteLength !== returnedBytes.buffer.byteLength
        ) {
            if (returnedBytes instanceof Uint8Array) {
                returnedBytes.fill(0);
            }
            throw new Error(
                'The production common-proof output store returned malformed canonical bytes for evidence hashing.',
            );
        }
        try {
            hasher.update(returnedBytes);
        } finally {
            returnedBytes.fill(0);
        }
    }
    return bytesToHex(hasher.digest());
};

const checkpointPublishedBuffers = (
    checkpoint: CommonProofGenerationCheckpoint,
): readonly Uint8Array[] => [
    checkpoint.canonicalStateBytes,
    checkpoint.privateRandomCursorManifestBytes,
    ...(checkpoint.privateRandomnessStreamAttemptIdentifier === undefined
        ? []
        : [checkpoint.privateRandomnessStreamAttemptIdentifier]),
    checkpoint.stableAttemptBindingHash,
];

const checkpointResumeDescriptorBuffers = (
    descriptor: CommonProofCheckpointResumeDescriptor,
): readonly Uint8Array[] => [
    descriptor.checkpointLineageIdentifier,
    descriptor.commonProofEnvironmentIdentifier,
    descriptor.privateRandomCursorManifestBytes,
    ...(descriptor.privateRandomnessStreamAttemptIdentifier === undefined
        ? []
        : [descriptor.privateRandomnessStreamAttemptIdentifier]),
    descriptor.stableAttemptBindingHash,
];

class DesktopBrowserCommonProofRecorder {
    readonly #liveExternalMemoryObjects = new Map<number, number>();
    readonly #wasmMemory: WebAssembly.Memory;
    #appendByteLength = 0;
    #appendOperationCount = 0;
    #armedHandoffCount = 0;
    #authenticatedInputReadByteLength = 0;
    #authenticatedInputReadCount = 0;
    #authenticatedInputRequestedByteLength = 0;
    #boundaryBufferCount = 0;
    #boundaryBufferTotalByteLength = 0;
    #committedByteLength = 0;
    #committedChunkCount = 0;
    #copiedResumeDescriptorByteLength = 0;
    #copiedResumeDescriptorCount = 0;
    #createOperationCount = 0;
    #createdDeclaredByteLength = 0;
    #currentLiveDeclaredByteLength = 0;
    #deleteOperationCount = 0;
    #externalMemoryOperationCount = 0;
    #externalMemoryTransactionCount = 0;
    #growthObservationCount = 0;
    #initialWasmMemoryByteLength: number;
    #lastObservedWasmMemoryByteLength: number;
    #maximumBoundaryBufferByteLength = 0;
    #outputReadByteLength = 0;
    #outputReadCount = 0;
    #outputRequestedByteLength = 0;
    #peakLiveDeclaredByteLength = 0;
    #peakWasmMemoryByteLength: number;
    #prefixReplayTransactionCount = 0;
    #publishedCanonicalStateByteLength = 0;
    #publishedCheckpointCount = 0;
    #publishedCursorManifestByteLength = 0;
    #publishedPrivateRandomnessIdentifierByteLength = 0;
    #publishedStableBindingByteLength = 0;
    #readOperationCount = 0;
    #requestedReadByteLength = 0;
    #restoredCanonicalStateByteLength = 0;
    #restoredCheckpointCount = 0;
    #returnedMarkerByteLength = 0;
    #returnedReadByteLength = 0;
    #sealOperationCount = 0;
    #sealedOutputCount = 0;
    #wasmMemoryObservationCount = 0;

    public constructor(wasmMemory: WebAssembly.Memory) {
        if (!(wasmMemory instanceof WebAssembly.Memory)) {
            throw new Error(
                'The production measurement session did not provide WASM memory.',
            );
        }
        this.#wasmMemory = wasmMemory;
        const initialByteLength = requireByteLength(
            wasmMemory.buffer.byteLength,
            'Initial WASM memory length',
        );
        this.#initialWasmMemoryByteLength = initialByteLength;
        this.#lastObservedWasmMemoryByteLength = initialByteLength;
        this.#peakWasmMemoryByteLength = initialByteLength;
        this.observeWasmMemory();
    }

    public measuredCustody(
        custody: CommonProofBrowserCustody,
    ): CommonProofBrowserCustody {
        const checkpointCustody = custody.checkpointCustody;
        return Object.freeze({
            armApplicationHandoff: async () => {
                const handoff = await this.observeAsync(() =>
                    custody.armApplicationHandoff(),
                );
                this.#armedHandoffCount = checkedAdd(
                    this.#armedHandoffCount,
                    1,
                    'Armed handoff count',
                );
                this.#returnedMarkerByteLength = checkedAdd(
                    this.#returnedMarkerByteLength,
                    handoff.canonicalMarkerRecordBytes.byteLength,
                    'Returned handoff marker length',
                );
                this.observeBoundaryBuffer(handoff.canonicalMarkerRecordBytes);
                return handoff;
            },
            ...(checkpointCustody === undefined
                ? {}
                : {
                      checkpointCustody: Object.freeze({
                          publishAuthenticatedCheckpoint: async (
                              checkpoint: CommonProofGenerationCheckpoint,
                          ) => {
                              await this.observeAsync(() =>
                                  checkpointCustody.publishAuthenticatedCheckpoint(
                                      checkpoint,
                                  ),
                              );
                              this.observePublishedCheckpoint(checkpoint);
                          },
                          restoreAuthenticatedCheckpointState: async () => {
                              const bytes = await this.observeAsync(() =>
                                  checkpointCustody.restoreAuthenticatedCheckpointState(),
                              );
                              this.#restoredCheckpointCount = checkedAdd(
                                  this.#restoredCheckpointCount,
                                  1,
                                  'Restored checkpoint count',
                              );
                              this.#restoredCanonicalStateByteLength =
                                  checkedAdd(
                                      this.#restoredCanonicalStateByteLength,
                                      bytes.byteLength,
                                      'Restored checkpoint state length',
                                  );
                              this.observeBoundaryBuffer(bytes);
                              return bytes;
                          },
                      }),
                  }),
            completeVerifiedOutput: () =>
                this.observeAsync(() => custody.completeVerifiedOutput()),
            copyCheckpointResumeDescriptor: () => {
                this.observeWasmMemory();
                const descriptor = custody.copyCheckpointResumeDescriptor();
                this.observeWasmMemory();
                if (descriptor !== undefined) {
                    this.#copiedResumeDescriptorCount = checkedAdd(
                        this.#copiedResumeDescriptorCount,
                        1,
                        'Copied checkpoint resume descriptor count',
                    );
                    for (const buffer of checkpointResumeDescriptorBuffers(
                        descriptor,
                    )) {
                        this.#copiedResumeDescriptorByteLength = checkedAdd(
                            this.#copiedResumeDescriptorByteLength,
                            buffer.byteLength,
                            'Copied checkpoint resume descriptor length',
                        );
                        this.observeBoundaryBuffer(buffer);
                    }
                }
                return descriptor;
            },
            externalMemory: Object.freeze({
                executeTransaction: async (
                    request: CommonProofExternalMemoryRequest,
                ) => {
                    const results = await this.observeAsync(() =>
                        custody.externalMemory.executeTransaction(request),
                    );
                    this.observeExternalMemoryTransaction(
                        request,
                        results,
                        false,
                    );
                    return results;
                },
            }),
            prefixReplayExternalMemory: Object.freeze({
                executeDeterministicPrefixReplayTransaction: async (
                    request: CommonProofExternalMemoryRequest,
                ) => {
                    const results = await this.observeAsync(() =>
                        custody.prefixReplayExternalMemory.executeDeterministicPrefixReplayTransaction(
                            request,
                        ),
                    );
                    this.observeExternalMemoryTransaction(
                        request,
                        results,
                        true,
                    );
                    return results;
                },
            }),
            outputStore: Object.freeze({
                commitChunk: async (
                    chunkIndex: number,
                    chunkBytes: Uint8Array<ArrayBuffer>,
                ) => {
                    await this.observeAsync(() =>
                        custody.outputStore.commitChunk(chunkIndex, chunkBytes),
                    );
                    this.#committedChunkCount = checkedAdd(
                        this.#committedChunkCount,
                        1,
                        'Committed output chunk count',
                    );
                    this.#committedByteLength = checkedAdd(
                        this.#committedByteLength,
                        chunkBytes.byteLength,
                        'Committed output length',
                    );
                    this.observeBoundaryBuffer(chunkBytes);
                },
                readChunk: async (
                    chunkIndex: number,
                    exactByteLength: number,
                ) => {
                    const bytes = await this.observeAsync(() =>
                        custody.outputStore.readChunk(
                            chunkIndex,
                            exactByteLength,
                        ),
                    );
                    this.#outputReadCount = checkedAdd(
                        this.#outputReadCount,
                        1,
                        'Output read count',
                    );
                    this.#outputRequestedByteLength = checkedAdd(
                        this.#outputRequestedByteLength,
                        requireByteLength(
                            exactByteLength,
                            'Requested output read length',
                        ),
                        'Requested output read length',
                    );
                    this.#outputReadByteLength = checkedAdd(
                        this.#outputReadByteLength,
                        bytes.byteLength,
                        'Returned output read length',
                    );
                    this.observeBoundaryBuffer(bytes);
                    return bytes;
                },
            }),
            authenticatedOutput: () =>
                this.measuredAuthenticatedOutput(custody.authenticatedOutput()),
            releaseExternalMemory: () =>
                this.observeAsync(() => custody.releaseExternalMemory()),
            retire: () => this.observeAsync(() => custody.retire()),
            sealCanonicalOutput: () => {
                this.observeWasmMemory();
                custody.sealCanonicalOutput();
                this.#sealedOutputCount = checkedAdd(
                    this.#sealedOutputCount,
                    1,
                    'Sealed output count',
                );
                this.observeWasmMemory();
            },
            suspendForAuthenticatedResume: () =>
                this.observeAsync(() =>
                    custody.suspendForAuthenticatedResume(),
                ),
        });
    }

    public async yieldControl(): Promise<void> {
        this.observeWasmMemory();
        await new Promise<void>((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = () => {
                channel.port1.close();
                channel.port2.close();
                resolve();
            };
            channel.port2.postMessage(undefined);
        });
        this.observeWasmMemory();
    }

    public finish(input: {
        caseIdentifier: string;
        elapsedMilliseconds: number;
        executionKind: DesktopBrowserProofExecutionKind;
        measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
        canonicalProofStreamSha512: string;
    }): DesktopBrowserCommonProofMeasurement {
        this.observeWasmMemory();
        const finalWasmMemoryByteLength = requireByteLength(
            this.#wasmMemory.buffer.byteLength,
            'Final WASM memory length',
        );
        return Object.freeze({
            boundaryBufferTraffic: Object.freeze({
                bufferCount: this.#boundaryBufferCount,
                maximumBufferByteLength: this.#maximumBoundaryBufferByteLength,
                totalByteLength: this.#boundaryBufferTotalByteLength,
            }),
            canonicalOutputTraffic: Object.freeze({
                authenticatedInputReadByteLength:
                    this.#authenticatedInputReadByteLength,
                authenticatedInputReadCount: this.#authenticatedInputReadCount,
                authenticatedInputRequestedByteLength:
                    this.#authenticatedInputRequestedByteLength,
                committedByteLength: this.#committedByteLength,
                committedChunkCount: this.#committedChunkCount,
                outputReadByteLength: this.#outputReadByteLength,
                outputReadCount: this.#outputReadCount,
                outputRequestedByteLength: this.#outputRequestedByteLength,
                sealCount: this.#sealedOutputCount,
            }),
            caseIdentifier: input.caseIdentifier,
            checkpointTraffic: Object.freeze({
                copiedResumeDescriptorByteLength:
                    this.#copiedResumeDescriptorByteLength,
                copiedResumeDescriptorCount: this.#copiedResumeDescriptorCount,
                publishedCanonicalStateByteLength:
                    this.#publishedCanonicalStateByteLength,
                publishedCheckpointCount: this.#publishedCheckpointCount,
                publishedCursorManifestByteLength:
                    this.#publishedCursorManifestByteLength,
                publishedPrivateRandomnessIdentifierByteLength:
                    this.#publishedPrivateRandomnessIdentifierByteLength,
                publishedStableBindingByteLength:
                    this.#publishedStableBindingByteLength,
                restoredCanonicalStateByteLength:
                    this.#restoredCanonicalStateByteLength,
                restoredCheckpointCount: this.#restoredCheckpointCount,
            }),
            elapsedMilliseconds: input.elapsedMilliseconds,
            executionKind: input.executionKind,
            externalMemoryTraffic: Object.freeze({
                appendByteLength: this.#appendByteLength,
                appendOperationCount: this.#appendOperationCount,
                createOperationCount: this.#createOperationCount,
                createdDeclaredByteLength: this.#createdDeclaredByteLength,
                deleteOperationCount: this.#deleteOperationCount,
                operationCount: this.#externalMemoryOperationCount,
                peakLiveDeclaredByteLength: this.#peakLiveDeclaredByteLength,
                prefixReplayTransactionCount:
                    this.#prefixReplayTransactionCount,
                readOperationCount: this.#readOperationCount,
                requestedReadByteLength: this.#requestedReadByteLength,
                returnedReadByteLength: this.#returnedReadByteLength,
                sealOperationCount: this.#sealOperationCount,
                transactionCount: this.#externalMemoryTransactionCount,
            }),
            handoffTraffic: Object.freeze({
                armedHandoffCount: this.#armedHandoffCount,
                returnedMarkerByteLength: this.#returnedMarkerByteLength,
            }),
            measurementIdentity: input.measurementIdentity,
            publicOutputHashes: Object.freeze({
                canonicalProofStreamSha512: input.canonicalProofStreamSha512,
            }),
            wasmMemory: Object.freeze({
                finalByteLength: finalWasmMemoryByteLength,
                growthByteLength:
                    finalWasmMemoryByteLength -
                    this.#initialWasmMemoryByteLength,
                growthObservationCount: this.#growthObservationCount,
                initialByteLength: this.#initialWasmMemoryByteLength,
                observationCount: this.#wasmMemoryObservationCount,
                peakByteLength: this.#peakWasmMemoryByteLength,
            }),
        });
    }

    private measuredAuthenticatedOutput(
        inputStore: AuthenticatedCommonProofInputStore,
    ): AuthenticatedCommonProofInputStore {
        return Object.freeze({
            declaredByteLength: inputStore.declaredByteLength,
            readCommittedChunk: async (
                chunkIndex: number,
                exactByteLength: number,
            ) => {
                const bytes = await this.observeAsync(() =>
                    inputStore.readCommittedChunk(chunkIndex, exactByteLength),
                );
                this.#authenticatedInputReadCount = checkedAdd(
                    this.#authenticatedInputReadCount,
                    1,
                    'Authenticated input read count',
                );
                this.#authenticatedInputRequestedByteLength = checkedAdd(
                    this.#authenticatedInputRequestedByteLength,
                    requireByteLength(
                        exactByteLength,
                        'Requested authenticated input length',
                    ),
                    'Requested authenticated input length',
                );
                this.#authenticatedInputReadByteLength = checkedAdd(
                    this.#authenticatedInputReadByteLength,
                    bytes.byteLength,
                    'Returned authenticated input length',
                );
                this.observeBoundaryBuffer(bytes);
                return bytes;
            },
        });
    }

    private observeBoundaryBuffer(bytes: Uint8Array): void {
        const byteLength = requireByteLength(
            bytes.byteLength,
            'Observed boundary buffer length',
        );
        this.#boundaryBufferCount = checkedAdd(
            this.#boundaryBufferCount,
            1,
            'Boundary buffer count',
        );
        this.#boundaryBufferTotalByteLength = checkedAdd(
            this.#boundaryBufferTotalByteLength,
            byteLength,
            'Boundary buffer traffic',
        );
        this.#maximumBoundaryBufferByteLength = Math.max(
            this.#maximumBoundaryBufferByteLength,
            byteLength,
        );
    }

    private observeExternalMemoryTransaction(
        request: CommonProofExternalMemoryRequest,
        results: readonly CommonProofExternalMemoryReadResult[],
        prefixReplay: boolean,
    ): void {
        this.#externalMemoryTransactionCount = checkedAdd(
            this.#externalMemoryTransactionCount,
            1,
            'External-memory transaction count',
        );
        if (prefixReplay) {
            this.#prefixReplayTransactionCount = checkedAdd(
                this.#prefixReplayTransactionCount,
                1,
                'Prefix-replay transaction count',
            );
        }
        this.observeBoundaryBuffer(request.requestDigest);
        this.observeBoundaryBuffer(request.runtimeBindingHash);
        for (const operation of request.operations) {
            this.#externalMemoryOperationCount = checkedAdd(
                this.#externalMemoryOperationCount,
                1,
                'External-memory operation count',
            );
            switch (operation.operationKind) {
                case 'create': {
                    if (
                        this.#liveExternalMemoryObjects.has(
                            operation.objectOrdinal,
                        )
                    ) {
                        throw new Error(
                            'The measured external-memory schedule recreated a live object.',
                        );
                    }
                    const declaredByteLength = exactNumberFromBigInt(
                        operation.exactByteLength,
                        'External-memory declared length',
                    );
                    this.#liveExternalMemoryObjects.set(
                        operation.objectOrdinal,
                        declaredByteLength,
                    );
                    this.#createOperationCount = checkedAdd(
                        this.#createOperationCount,
                        1,
                        'External-memory create count',
                    );
                    this.#createdDeclaredByteLength = checkedAdd(
                        this.#createdDeclaredByteLength,
                        declaredByteLength,
                        'External-memory created declared length',
                    );
                    this.#currentLiveDeclaredByteLength = checkedAdd(
                        this.#currentLiveDeclaredByteLength,
                        declaredByteLength,
                        'External-memory live declared length',
                    );
                    this.#peakLiveDeclaredByteLength = Math.max(
                        this.#peakLiveDeclaredByteLength,
                        this.#currentLiveDeclaredByteLength,
                    );
                    break;
                }
                case 'append':
                    this.#appendOperationCount = checkedAdd(
                        this.#appendOperationCount,
                        1,
                        'External-memory append count',
                    );
                    this.#appendByteLength = checkedAdd(
                        this.#appendByteLength,
                        operation.bytes.byteLength,
                        'External-memory append length',
                    );
                    this.observeBoundaryBuffer(operation.bytes);
                    break;
                case 'seal':
                    this.#sealOperationCount = checkedAdd(
                        this.#sealOperationCount,
                        1,
                        'External-memory seal count',
                    );
                    break;
                case 'read':
                    this.#readOperationCount = checkedAdd(
                        this.#readOperationCount,
                        1,
                        'External-memory read count',
                    );
                    this.#requestedReadByteLength = checkedAdd(
                        this.#requestedReadByteLength,
                        requireByteLength(
                            operation.byteLength,
                            'Requested external-memory read length',
                        ),
                        'Requested external-memory read length',
                    );
                    break;
                case 'delete': {
                    const declaredByteLength =
                        this.#liveExternalMemoryObjects.get(
                            operation.objectOrdinal,
                        );
                    if (declaredByteLength === undefined) {
                        throw new Error(
                            'The measured external-memory schedule deleted an unknown object.',
                        );
                    }
                    this.#liveExternalMemoryObjects.delete(
                        operation.objectOrdinal,
                    );
                    this.#deleteOperationCount = checkedAdd(
                        this.#deleteOperationCount,
                        1,
                        'External-memory delete count',
                    );
                    this.#currentLiveDeclaredByteLength -= declaredByteLength;
                    break;
                }
            }
        }
        for (const result of results) {
            this.#returnedReadByteLength = checkedAdd(
                this.#returnedReadByteLength,
                result.bytes.byteLength,
                'Returned external-memory read length',
            );
            this.observeBoundaryBuffer(result.bytes);
        }
    }

    private observePublishedCheckpoint(
        checkpoint: CommonProofGenerationCheckpoint,
    ): void {
        this.#publishedCheckpointCount = checkedAdd(
            this.#publishedCheckpointCount,
            1,
            'Published checkpoint count',
        );
        this.#publishedCanonicalStateByteLength = checkedAdd(
            this.#publishedCanonicalStateByteLength,
            checkpoint.canonicalStateBytes.byteLength,
            'Published checkpoint state length',
        );
        this.#publishedCursorManifestByteLength = checkedAdd(
            this.#publishedCursorManifestByteLength,
            checkpoint.privateRandomCursorManifestBytes.byteLength,
            'Published checkpoint cursor-manifest length',
        );
        this.#publishedStableBindingByteLength = checkedAdd(
            this.#publishedStableBindingByteLength,
            checkpoint.stableAttemptBindingHash.byteLength,
            'Published checkpoint stable-binding length',
        );
        if (checkpoint.privateRandomnessStreamAttemptIdentifier !== undefined) {
            this.#publishedPrivateRandomnessIdentifierByteLength = checkedAdd(
                this.#publishedPrivateRandomnessIdentifierByteLength,
                checkpoint.privateRandomnessStreamAttemptIdentifier.byteLength,
                'Published checkpoint private-randomness identifier length',
            );
        }
        for (const buffer of checkpointPublishedBuffers(checkpoint)) {
            this.observeBoundaryBuffer(buffer);
        }
    }

    private observeWasmMemory(): void {
        const byteLength = requireByteLength(
            this.#wasmMemory.buffer.byteLength,
            'Observed WASM memory length',
        );
        this.#wasmMemoryObservationCount = checkedAdd(
            this.#wasmMemoryObservationCount,
            1,
            'WASM memory observation count',
        );
        if (byteLength < this.#lastObservedWasmMemoryByteLength) {
            throw new Error('The observed WASM memory length decreased.');
        }
        if (byteLength > this.#lastObservedWasmMemoryByteLength) {
            this.#growthObservationCount = checkedAdd(
                this.#growthObservationCount,
                1,
                'WASM memory growth observation count',
            );
            this.#lastObservedWasmMemoryByteLength = byteLength;
        }
        this.#peakWasmMemoryByteLength = Math.max(
            this.#peakWasmMemoryByteLength,
            byteLength,
        );
    }

    private async observeAsync<Value>(
        operation: () => Promise<Value>,
    ): Promise<Value> {
        this.observeWasmMemory();
        try {
            return await operation();
        } finally {
            this.observeWasmMemory();
        }
    }
}

const requireCaseIdentifier = (
    caseIdentifier: string,
    observedIdentifiers: Set<string>,
): void => {
    requireDesktopBrowserCommonProofMeasurementCaseIdentifier(caseIdentifier);
    if (observedIdentifiers.has(caseIdentifier)) {
        throw new Error(
            'Production desktop-browser measurement case identifiers must be unique.',
        );
    }
    observedIdentifiers.add(caseIdentifier);
};

export const measureProductionDesktopBrowserCommonProofCase = async (
    measurementCases: readonly ProductionDesktopBrowserCommonProofMeasurementCase[],
    selectedCaseIdentifier: string,
): Promise<DesktopBrowserCommonProofMeasurement> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new Error(
            'Production desktop-browser common-proof measurement must execute inside its dedicated worker.',
        );
    }
    if (measurementCases.length === 0) {
        throw new Error(
            'No production desktop-browser common-proof measurement cases are registered.',
        );
    }
    const requiredSelectedCaseIdentifier =
        requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
            selectedCaseIdentifier,
        );
    const observedIdentifiers = new Set<string>();
    let selectedCase:
        | ProductionDesktopBrowserCommonProofMeasurementCase
        | undefined;
    for (const measurementCase of measurementCases) {
        requireCaseIdentifier(
            measurementCase.caseIdentifier,
            observedIdentifiers,
        );
        if (
            measurementCase.executionKind !== 'fresh' &&
            measurementCase.executionKind !== 'resumed'
        ) {
            throw new Error(
                'A production desktop-browser measurement case has an invalid execution kind.',
            );
        }
        if (measurementCase.caseIdentifier === requiredSelectedCaseIdentifier) {
            selectedCase = measurementCase;
        }
    }
    if (selectedCase === undefined) {
        throw new Error(
            `The selected production desktop-browser common-proof measurement case is not registered: ${requiredSelectedCaseIdentifier}.`,
        );
    }

    const session = await selectedCase.open();
    try {
        const measurementIdentity =
            requireProductionDesktopBrowserMeasurementIdentity(
                session.measurementIdentity,
            );
        const recorder = new DesktopBrowserCommonProofRecorder(
            session.wasmMemory,
        );
        const measuredCustody = recorder.measuredCustody(session.custody);
        const startedAtMilliseconds = performance.now();
        await session.execute({
            custody: measuredCustody,
            yieldControl: () => recorder.yieldControl(),
        });
        const elapsedMilliseconds = performance.now() - startedAtMilliseconds;
        const canonicalProofStreamSha512 = await hashCanonicalProofStream(
            session.custody,
        );
        return recorder.finish({
            caseIdentifier: selectedCase.caseIdentifier,
            elapsedMilliseconds,
            executionKind: selectedCase.executionKind,
            measurementIdentity,
            canonicalProofStreamSha512,
        });
    } finally {
        await session.close();
    }
};
