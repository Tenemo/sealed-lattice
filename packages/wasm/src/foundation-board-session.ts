import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';
import { foundationProfile, refusalReasonCodes } from '@sealed-lattice/types';

import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

const foundationBoardConfigurationVersion = 1;
const foundationBoardCapabilityByteLength = 32;
const foundationBoardCandidateHashByteLength = 64;
const publicSetupSeedAnchorMask = 1 << 0;
const verifiedSetupSourceAnchorMask = 1 << 1;
const fixedConfigurationByteLength =
    2 + 3 * foundationBoardCandidateHashByteLength + 4 * 4 + 2 + 4;
const wasm32WordByteLength = 4;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

declare const foundationBoardCandidateBrand: unique symbol;

/** A carrier accepted by the fixed verifier route selected inside the kernel. */
export type FoundationBoardCandidate = Readonly<{
    readonly [foundationBoardCandidateBrand]: true;
}>;

export type FoundationBoardIngestionLimits = Readonly<{
    maximumCarrierByteLength: number;
    maximumCarrierCount: number;
    maximumRetainedCarrierByteLength: number;
    maximumUnresolvedDependencyCount: number;
}>;

export type FoundationBoardSessionInput = Readonly<{
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    limits: FoundationBoardIngestionLimits;
    publicSetupSeedObjectHash?: Uint8Array;
    suiteIdentifier: Uint8Array;
    verifiedSetupSourceObjectHash?: Uint8Array;
}>;

export type FoundationBoardSessionState = 'active' | 'cancelled';

export type FoundationBoardSession = Readonly<{
    cancel(): void;
    ingest(
        canonicalCarrierBytes: Uint8Array,
    ): VerificationResult<FoundationBoardCandidate>;
    requireCompleteCarrierGraph(): VerificationResult<undefined>;
    state(): FoundationBoardSessionState;
}>;

export class FoundationBoardInternalError extends Error {
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause?: unknown) {
        super(message);
        this.name = 'FoundationBoardInternalError';
        this.failureCause = failureCause;
    }
}

export class FoundationBoardRefusalError extends Error {
    public readonly refusalReason: RefusalReason;

    public constructor(refusalReason: RefusalReason) {
        super(`The foundation board operation was refused: ${refusalReason}.`);
        this.name = 'FoundationBoardRefusalError';
        this.refusalReason = refusalReason;
    }
}

export type FoundationBoardKernelContext = Readonly<{
    allocate(length: number): number;
    begin(
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ): number;
    cancel(
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ): number;
    deallocate(pointer: number, length: number): void;
    ingest(
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
        canonicalCarrierPointer: number,
        canonicalCarrierLength: number,
        candidateHashPointer: number,
        candidateHashLength: number,
    ): number;
    memory: WebAssembly.Memory;
    requireCompleteCarrierGraph(
        handle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ): number;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
}>;

const contexts = new WeakMap<
    TranscriptCoreKernel,
    FoundationBoardKernelContext
>();

export const registerFoundationBoardKernelContext = (
    kernel: TranscriptCoreKernel,
    context: FoundationBoardKernelContext,
): void => {
    contexts.set(kernel, context);
};

const candidateHashes = new WeakMap<object, Uint8Array>();

export const foundationBoardCandidateObjectHash = (
    candidate: FoundationBoardCandidate,
): Uint8Array => {
    const objectHash = candidateHashes.get(candidate);
    if (objectHash === undefined) {
        throw new FoundationBoardInternalError(
            'The foundation board candidate was not issued by this runtime.',
        );
    }
    return Uint8Array.from(objectHash);
};

const refusalReasonByCode = new Map<number, RefusalReason>(
    Object.entries(refusalReasonCodes).map(([reason, code]) => [
        code,
        reason as RefusalReason,
    ]),
);

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const decodeStatus = (status: number): RefusalReason | undefined => {
    if (status === 0) {
        return undefined;
    }
    const refusalReason = refusalReasonByCode.get(status);
    if (refusalReason === undefined) {
        throw new FoundationBoardInternalError(
            'The WASM foundation board returned an unknown status code.',
        );
    }
    return refusalReason;
};

const requireHash = (value: Uint8Array, label: string): Uint8Array => {
    if (
        !isUint8Array(value) ||
        value.byteLength !== foundationBoardCandidateHashByteLength
    ) {
        throw new FoundationBoardRefusalError('wrongTypeOrLength');
    }
    if (value.buffer.byteLength === 0) {
        throw new FoundationBoardInternalError(
            `${label} has no backing bytes.`,
        );
    }
    return value;
};

const requireUnsigned32 = (value: number): number => {
    if (
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new FoundationBoardRefusalError('outsideSupportedProfile');
    }
    return value;
};

const encodeConfiguration = (
    input: FoundationBoardSessionInput,
): Uint8Array => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new FoundationBoardRefusalError('wrongTypeOrLength');
    }
    const suiteIdentifier = requireHash(
        input.suiteIdentifier,
        'suite identifier',
    );
    const ceremonyContextHash = requireHash(
        input.ceremonyContextHash,
        'ceremony context hash',
    );
    const actionContextHash = requireHash(
        input.actionContextHash,
        'action context hash',
    );
    const publicSetupSeedObjectHash =
        input.publicSetupSeedObjectHash === undefined
            ? undefined
            : requireHash(
                  input.publicSetupSeedObjectHash,
                  'public setup seed object hash',
              );
    const verifiedSetupSourceObjectHash =
        input.verifiedSetupSourceObjectHash === undefined
            ? undefined
            : requireHash(
                  input.verifiedSetupSourceObjectHash,
                  'verified setup source object hash',
              );
    if (
        !isUint8Array(input.canonicalRosterBytes) ||
        input.canonicalRosterBytes.byteLength === 0
    ) {
        throw new FoundationBoardRefusalError('wrongTypeOrLength');
    }
    if (
        typeof input.limits !== 'object' ||
        input.limits === null ||
        Array.isArray(input.limits)
    ) {
        throw new FoundationBoardRefusalError('wrongTypeOrLength');
    }
    const maximumCarrierCount = requireUnsigned32(
        input.limits.maximumCarrierCount,
    );
    const maximumCarrierByteLength = requireUnsigned32(
        input.limits.maximumCarrierByteLength,
    );
    const maximumRetainedCarrierByteLength = requireUnsigned32(
        input.limits.maximumRetainedCarrierByteLength,
    );
    const maximumUnresolvedDependencyCount = requireUnsigned32(
        input.limits.maximumUnresolvedDependencyCount,
    );
    const anchorByteLength =
        (publicSetupSeedObjectHash === undefined ? 0 : 64) +
        (verifiedSetupSourceObjectHash === undefined ? 0 : 64);
    const configurationByteLength =
        fixedConfigurationByteLength +
        anchorByteLength +
        input.canonicalRosterBytes.byteLength;
    if (
        configurationByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        configurationByteLength > maximumWasm32UnsignedInteger
    ) {
        throw new FoundationBoardRefusalError('outsideSupportedProfile');
    }

    const configuration = new Uint8Array(configurationByteLength);
    const view = new DataView(configuration.buffer);
    let offset = 0;
    view.setUint16(offset, foundationBoardConfigurationVersion, true);
    offset += 2;
    configuration.set(suiteIdentifier, offset);
    offset += suiteIdentifier.byteLength;
    configuration.set(ceremonyContextHash, offset);
    offset += ceremonyContextHash.byteLength;
    configuration.set(actionContextHash, offset);
    offset += actionContextHash.byteLength;
    for (const limit of [
        maximumCarrierByteLength,
        maximumCarrierCount,
        maximumRetainedCarrierByteLength,
        maximumUnresolvedDependencyCount,
    ]) {
        view.setUint32(offset, limit, true);
        offset += wasm32WordByteLength;
    }
    let anchorMask = 0;
    if (publicSetupSeedObjectHash !== undefined) {
        anchorMask |= publicSetupSeedAnchorMask;
    }
    if (verifiedSetupSourceObjectHash !== undefined) {
        anchorMask |= verifiedSetupSourceAnchorMask;
    }
    view.setUint16(offset, anchorMask, true);
    offset += 2;
    if (publicSetupSeedObjectHash !== undefined) {
        configuration.set(publicSetupSeedObjectHash, offset);
        offset += publicSetupSeedObjectHash.byteLength;
    }
    if (verifiedSetupSourceObjectHash !== undefined) {
        configuration.set(verifiedSetupSourceObjectHash, offset);
        offset += verifiedSetupSourceObjectHash.byteLength;
    }
    view.setUint32(offset, input.canonicalRosterBytes.byteLength, true);
    offset += wasm32WordByteLength;
    configuration.set(input.canonicalRosterBytes, offset);
    return configuration;
};

function zeroMemory(
    context: FoundationBoardKernelContext,
    pointer: number,
    byteLength: number,
): void {
    if (
        pointer !== 0 &&
        pointer + byteLength <= context.memory.buffer.byteLength
    ) {
        new Uint8Array(context.memory.buffer, pointer, byteLength).fill(0);
    }
}

function allocate(
    context: FoundationBoardKernelContext,
    byteLength: number,
): number {
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength <= 0 ||
        byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new FoundationBoardRefusalError('outsideSupportedProfile');
    }
    if (
        context.memory.buffer.byteLength >
        foundationProfile.maximumWasmMemoryByteLength - byteLength
    ) {
        throw new FoundationBoardRefusalError('outsideSupportedProfile');
    }
    const pointer = context.allocate(byteLength) >>> 0;
    if (
        pointer === 0 ||
        pointer + byteLength > context.memory.buffer.byteLength
    ) {
        throw new FoundationBoardInternalError(
            'The WASM foundation board allocator returned an invalid range.',
        );
    }
    return pointer;
}

function allocateZeroed(
    context: FoundationBoardKernelContext,
    byteLength: number,
): number {
    const pointer = allocate(context, byteLength);
    zeroMemory(context, pointer, byteLength);
    return pointer;
}

function allocateAndCopy(
    context: FoundationBoardKernelContext,
    bytes: Uint8Array,
): number {
    const pointer = allocate(context, bytes.byteLength);
    try {
        new Uint8Array(context.memory.buffer).set(bytes, pointer);
        return pointer;
    } catch (error) {
        context.deallocate(pointer, bytes.byteLength);
        throw new FoundationBoardInternalError(
            'The foundation board input could not be copied into WASM memory.',
            error,
        );
    }
}

class FoundationBoardSessionImplementation implements FoundationBoardSession {
    readonly #context: FoundationBoardKernelContext;
    #capabilityPointer: number;
    readonly #handle: number;
    #state: FoundationBoardSessionState = 'active';

    public constructor(
        context: FoundationBoardKernelContext,
        handle: number,
        capabilityPointer: number,
    ) {
        this.#context = context;
        this.#handle = handle;
        this.#capabilityPointer = capabilityPointer;
    }

    public ingest(
        canonicalCarrierBytes: Uint8Array,
    ): VerificationResult<FoundationBoardCandidate> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            !isUint8Array(canonicalCarrierBytes) ||
            canonicalCarrierBytes.byteLength === 0
        ) {
            return refused('wrongTypeOrLength');
        }
        if (
            canonicalCarrierBytes.byteLength >
            foundationProfile.maximumCopiedBufferByteLength
        ) {
            return refused('outsideSupportedProfile');
        }

        let carrierPointer = 0;
        let candidateHashPointer = 0;
        try {
            carrierPointer = allocateAndCopy(
                this.#context,
                canonicalCarrierBytes,
            );
            candidateHashPointer = allocateZeroed(
                this.#context,
                foundationBoardCandidateHashByteLength,
            );
            const status = this.#context.runExclusive(
                'foundation board carrier ingestion',
                () =>
                    this.#context.ingest(
                        this.#handle,
                        this.#capabilityPointer,
                        foundationBoardCapabilityByteLength,
                        carrierPointer,
                        canonicalCarrierBytes.byteLength,
                        candidateHashPointer,
                        foundationBoardCandidateHashByteLength,
                    ),
            );
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            const objectHash = Uint8Array.from(
                new Uint8Array(
                    this.#context.memory.buffer,
                    candidateHashPointer,
                    foundationBoardCandidateHashByteLength,
                ),
            );
            const candidate = Object.freeze(
                Object.create(null) as FoundationBoardCandidate,
            );
            candidateHashes.set(candidate, objectHash);
            return valid(candidate);
        } finally {
            if (carrierPointer !== 0) {
                this.#context.deallocate(
                    carrierPointer,
                    canonicalCarrierBytes.byteLength,
                );
            }
            if (candidateHashPointer !== 0) {
                zeroMemory(
                    this.#context,
                    candidateHashPointer,
                    foundationBoardCandidateHashByteLength,
                );
                this.#context.deallocate(
                    candidateHashPointer,
                    foundationBoardCandidateHashByteLength,
                );
            }
        }
    }

    public requireCompleteCarrierGraph(): VerificationResult<undefined> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        const status = this.#context.runExclusive(
            'foundation board carrier graph verification',
            () =>
                this.#context.requireCompleteCarrierGraph(
                    this.#handle,
                    this.#capabilityPointer,
                    foundationBoardCapabilityByteLength,
                ),
        );
        const refusalReason = decodeStatus(status);
        return refusalReason === undefined
            ? valid(undefined)
            : refused(refusalReason);
    }

    public cancel(): void {
        if (this.#state !== 'active') {
            return;
        }
        try {
            const status = this.#context.runExclusive(
                'foundation board cancellation',
                () =>
                    this.#context.cancel(
                        this.#handle,
                        this.#capabilityPointer,
                        foundationBoardCapabilityByteLength,
                    ),
            );
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                throw new FoundationBoardRefusalError(refusalReason);
            }
            this.#state = 'cancelled';
        } finally {
            if (this.#state === 'cancelled') {
                zeroMemory(
                    this.#context,
                    this.#capabilityPointer,
                    foundationBoardCapabilityByteLength,
                );
                this.#context.deallocate(
                    this.#capabilityPointer,
                    foundationBoardCapabilityByteLength,
                );
                this.#capabilityPointer = 0;
            }
        }
    }

    public state(): FoundationBoardSessionState {
        return this.#state;
    }
}

const createCapability = (context: FoundationBoardKernelContext): number => {
    const randomBytes = new Uint8Array(
        new ArrayBuffer(foundationBoardCapabilityByteLength),
    );
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new FoundationBoardInternalError(
            'Web Crypto getRandomValues is required for board capabilities.',
        );
    }
    try {
        cryptoProvider.getRandomValues(randomBytes);
        if (randomBytes.every((byte) => byte === 0)) {
            cryptoProvider.getRandomValues(randomBytes);
        }
        if (randomBytes.every((byte) => byte === 0)) {
            throw new FoundationBoardInternalError(
                'Web Crypto produced an invalid all-zero board capability.',
            );
        }
        return allocateAndCopy(context, randomBytes);
    } finally {
        randomBytes.fill(0);
    }
};

export const openFoundationBoardSession = (input: {
    readonly configuration: FoundationBoardSessionInput;
    readonly kernel: TranscriptCoreKernel;
}): VerificationResult<FoundationBoardSession> => {
    const context = contexts.get(input.kernel);
    if (context === undefined) {
        throw new FoundationBoardInternalError(
            'The transcript-core kernel has no registered foundation board boundary.',
        );
    }
    let configuration: Uint8Array;
    try {
        configuration = encodeConfiguration(input.configuration);
    } catch (error) {
        if (error instanceof FoundationBoardRefusalError) {
            return refused(error.refusalReason);
        }
        throw error;
    }

    let capabilityPointer = 0;
    let configurationPointer = 0;
    let handle = 0;
    let statusPointer = 0;
    let sessionActivated = false;
    try {
        capabilityPointer = createCapability(context);
        configurationPointer = allocateAndCopy(context, configuration);
        statusPointer = allocateZeroed(context, wasm32WordByteLength);
        handle = context.runExclusive('foundation board begin', () =>
            context.begin(
                configurationPointer,
                configuration.byteLength,
                capabilityPointer,
                foundationBoardCapabilityByteLength,
                statusPointer,
            ),
        );
        const status = new DataView(
            context.memory.buffer,
            statusPointer,
            wasm32WordByteLength,
        ).getUint32(0, true);
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            if (handle !== 0) {
                const cancellationStatus = context.runExclusive(
                    'foundation board refused-begin cleanup',
                    () =>
                        context.cancel(
                            handle,
                            capabilityPointer,
                            foundationBoardCapabilityByteLength,
                        ),
                );
                const cancellationRefusal = decodeStatus(cancellationStatus);
                if (cancellationRefusal !== undefined) {
                    throw new FoundationBoardInternalError(
                        'The refused foundation board session could not be cleaned up.',
                        new FoundationBoardRefusalError(cancellationRefusal),
                    );
                }
                handle = 0;
            }
            return refused(refusalReason);
        }
        if (handle === 0) {
            throw new FoundationBoardInternalError(
                'The WASM foundation board returned an invalid session handle.',
            );
        }
        sessionActivated = true;
        return valid(
            Object.freeze(
                new FoundationBoardSessionImplementation(
                    context,
                    handle,
                    capabilityPointer,
                ),
            ),
        );
    } catch (operationFailure) {
        if (!sessionActivated && handle !== 0 && capabilityPointer !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'foundation board begin failure cleanup',
                    () =>
                        context.cancel(
                            handle,
                            capabilityPointer,
                            foundationBoardCapabilityByteLength,
                        ),
                );
                const cleanupRefusal = decodeStatus(cleanupStatus);
                if (cleanupRefusal !== undefined) {
                    throw new FoundationBoardRefusalError(cleanupRefusal);
                }
            } catch (cleanupFailure) {
                throw new FoundationBoardInternalError(
                    'The foundation board begin operation and its cleanup both failed.',
                    Object.freeze({ cleanupFailure, operationFailure }),
                );
            }
        }
        throw operationFailure;
    } finally {
        configuration.fill(0);
        if (configurationPointer !== 0) {
            zeroMemory(context, configurationPointer, configuration.byteLength);
            context.deallocate(configurationPointer, configuration.byteLength);
        }
        if (statusPointer !== 0) {
            context.deallocate(statusPointer, wasm32WordByteLength);
        }
        if (!sessionActivated && capabilityPointer !== 0) {
            zeroMemory(
                context,
                capabilityPointer,
                foundationBoardCapabilityByteLength,
            );
            context.deallocate(
                capabilityPointer,
                foundationBoardCapabilityByteLength,
            );
        }
    }
};
