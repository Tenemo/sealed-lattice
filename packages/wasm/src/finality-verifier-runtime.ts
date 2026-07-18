import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';
import { foundationProfile } from '@sealed-lattice/types';

import { isUint8Array } from './byte-array.js';
import {
    resolveVerifiedTranscriptObjectKernelAuthorization,
    type VerifiedTranscriptObject,
} from './canonical-board-runtime.js';
import { decodeWasmRefusalStatus } from './transcript-core-bridge/kernel-errors.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

const finalityVerifierConfigurationVersion = 1;
const finalityVerifierCapabilityByteLength = 32;
const hashByteLength = 64;
const wasm32WordByteLength = 4;
const verifiedFinalityDescriptionByteLength =
    2 + hashByteLength + hashByteLength + wasm32WordByteLength;
const maximumWasm32UnsignedInteger = 0xffff_ffff;

export type FinalityVerifierKernelContext = Readonly<{
    allocate(length: number): number;
    begin(
        configurationPointer: number,
        configurationLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ): number;
    cancel(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ): number;
    deallocate(pointer: number, length: number): void;
    describe(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedFinalityHandle: number,
        outputPointer: number,
        outputLength: number,
    ): number;
    memory: WebAssembly.Memory;
    release(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedFinalityHandle: number,
    ): number;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
    verify(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedEvaluatorReplayHandle: number,
        boardSessionHandle: number,
        boardCapabilityPointer: number,
        boardCapabilityLength: number,
        verifiedFinalityObjectHandlesPointer: number,
        verifiedFinalityObjectHandlesLength: number,
        canonicalStatementPointer: number,
        canonicalStatementLength: number,
        canonicalCertificatePointer: number,
        canonicalCertificateLength: number,
        statusPointer: number,
    ): number;
}>;

const contexts = new WeakMap<
    TranscriptCoreKernel,
    FinalityVerifierKernelContext
>();

export const registerFinalityVerifierKernelContext = (
    kernel: TranscriptCoreKernel,
    context: FinalityVerifierKernelContext,
): void => {
    contexts.set(kernel, context);
};

declare const verifiedEvaluatorReplayBrand: unique symbol;
declare const verifiedFinalityBrand: unique symbol;

/** Opaque output of the deterministic evaluator-replay verifier. */
export type VerifiedEvaluatorReplay = Readonly<{
    readonly [verifiedEvaluatorReplayBrand]: true;
}>;

/** Opaque finality capability; downstream release code resolves it in WASM. */
export type VerifiedFinality = Readonly<{
    readonly [verifiedFinalityBrand]: true;
}>;

export type VerifiedFinalityDescription = Readonly<{
    acceptedSignerCount: number;
    evaluatorReplayObjectHash: Uint8Array;
    finalityHash: Uint8Array;
}>;

export type FinalityVerifierConfiguration = Readonly<{
    actionContextHash: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    ceremonyContextHash: Uint8Array;
    suiteIdentifier: Uint8Array;
}>;

export type FinalityVerification = Readonly<{
    canonicalCertificate: Uint8Array;
    canonicalStatement: Uint8Array;
    verifiedEvaluatorReplay: VerifiedEvaluatorReplay;
    verifiedFinalityObjects: readonly VerifiedTranscriptObject[];
}>;

export type FinalityVerifierSession = Readonly<{
    cancel(): void;
    describe(
        verifiedFinality: VerifiedFinality,
    ): VerificationResult<VerifiedFinalityDescription>;
    release(verifiedFinality: VerifiedFinality): VerificationResult<undefined>;
    state(): 'active' | 'cancelled';
    verify(input: FinalityVerification): VerificationResult<VerifiedFinality>;
}>;

type VerifiedEvaluatorReplayRecord = {
    active: boolean;
    handle: number;
    kernel: TranscriptCoreKernel;
    release(handle: number): number;
};

type VerifiedFinalityRecord = {
    active: boolean;
    handle: number;
    session: FinalityVerifierSessionImplementation;
};

export type VerifiedFinalityKernelAuthorization = Readonly<{
    capabilityMemory: WebAssembly.Memory;
    capabilityPointer: number;
    finalityHandle: number;
    sessionHandle: number;
}>;

const verifiedEvaluatorReplayRecords = new WeakMap<
    object,
    VerifiedEvaluatorReplayRecord
>();
const verifiedFinalityRecords = new WeakMap<object, VerifiedFinalityRecord>();

export const resolveVerifiedFinalityKernelAuthorization = (
    verifiedFinality: VerifiedFinality,
    kernel: TranscriptCoreKernel,
): VerifiedFinalityKernelAuthorization => {
    if (
        (typeof verifiedFinality !== 'object' &&
            typeof verifiedFinality !== 'function') ||
        verifiedFinality === null
    ) {
        throw new TypeError(
            'The verified finality was not issued by the WASM finality verifier.',
        );
    }
    const record = verifiedFinalityRecords.get(verifiedFinality);
    if (record === undefined || !record.active) {
        throw new TypeError(
            'The verified finality is unavailable or was not issued by the WASM finality verifier.',
        );
    }
    return record.session.kernelAuthorization(record, kernel);
};

class FinalityVerifierInternalError extends Error {
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause?: unknown) {
        super(message);
        this.name = 'FinalityVerifierInternalError';
        this.failureCause = failureCause;
    }
}

class FinalityVerifierRefusalError extends Error {
    public constructor(public readonly refusalReason: RefusalReason) {
        super(`The finality verifier operation was refused: ${refusalReason}.`);
        this.name = 'FinalityVerifierRefusalError';
    }
}

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const decodeStatus = (status: number): RefusalReason | undefined => {
    return decodeWasmRefusalStatus(
        status,
        FinalityVerifierInternalError,
        'The WASM finality verifier returned an unknown status code.',
    );
};

const requireWasm32Handle = (value: unknown, label: string): void => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value <= 0 ||
        value > maximumWasm32UnsignedInteger
    ) {
        throw new TypeError(`The ${label} is invalid.`);
    }
};

/**
 * Mints the TypeScript wrapper only from a verifier-owned replay handle
 * produced in the same WASM worker. This is an internal package seam and is
 * deliberately not re-exported from the public package entry point.
 */
export const createVerifiedEvaluatorReplayKernelAuthority = (input: {
    handle: number;
    kernel: TranscriptCoreKernel;
    release(handle: number): number;
}): VerifiedEvaluatorReplay => {
    requireWasm32Handle(input.handle, 'verified evaluator replay handle');
    if (typeof input.release !== 'function') {
        throw new TypeError(
            'The verified evaluator replay release operation is invalid.',
        );
    }
    const capability = Object.freeze(Object.create(null) as object);
    verifiedEvaluatorReplayRecords.set(capability, {
        active: true,
        handle: input.handle,
        kernel: input.kernel,
        release: input.release,
    });
    return capability as VerifiedEvaluatorReplay;
};

/** Releases one live replay capability after finality no longer needs it. */
export const releaseVerifiedEvaluatorReplay = (
    verifiedEvaluatorReplay: VerifiedEvaluatorReplay,
): void => {
    const record = verifiedEvaluatorReplayRecords.get(verifiedEvaluatorReplay);
    if (record === undefined || !record.active) {
        throw new FinalityVerifierRefusalError('consumedState');
    }
    const refusalReason = decodeStatus(record.release(record.handle));
    if (refusalReason !== undefined) {
        throw new FinalityVerifierRefusalError(refusalReason);
    }
    record.active = false;
};

const requireBytes = (
    value: unknown,
    expectedByteLength?: number,
): RefusalReason | undefined => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        (expectedByteLength !== undefined &&
            value.byteLength !== expectedByteLength)
    ) {
        return 'wrongTypeOrLength';
    }
    if (
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength ||
        value.byteLength > maximumWasm32UnsignedInteger
    ) {
        return 'outsideSupportedProfile';
    }
    return undefined;
};

const encodeConfiguration = (
    input: FinalityVerifierConfiguration,
): Uint8Array<ArrayBuffer> => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new FinalityVerifierRefusalError('wrongTypeOrLength');
    }
    const hashes = [
        input.suiteIdentifier,
        input.ceremonyContextHash,
        input.actionContextHash,
    ];
    for (const hash of hashes) {
        const refusalReason = requireBytes(hash, hashByteLength);
        if (refusalReason !== undefined) {
            throw new FinalityVerifierRefusalError(refusalReason);
        }
    }
    const rosterRefusal = requireBytes(input.canonicalRosterBytes);
    if (rosterRefusal !== undefined) {
        throw new FinalityVerifierRefusalError(rosterRefusal);
    }
    const rosterByteLength = input.canonicalRosterBytes.byteLength;
    const output = new Uint8Array(
        2 + 3 * hashByteLength + 4 + rosterByteLength,
    );
    const dataView = new DataView(output.buffer);
    let offset = 0;
    dataView.setUint16(offset, finalityVerifierConfigurationVersion, true);
    offset += 2;
    for (const hash of hashes) {
        output.set(hash, offset);
        offset += hashByteLength;
    }
    dataView.setUint32(offset, rosterByteLength, true);
    offset += 4;
    output.set(input.canonicalRosterBytes, offset);
    return output;
};

const allocate = (
    context: FinalityVerifierKernelContext,
    byteLength: number,
): number => {
    if (byteLength <= 0 || byteLength > maximumWasm32UnsignedInteger) {
        throw new FinalityVerifierInternalError(
            'The finality verifier requested an invalid allocation.',
        );
    }
    const pointer = context.allocate(byteLength);
    if (pointer === 0) {
        throw new FinalityVerifierInternalError(
            'The finality verifier allocation failed.',
        );
    }
    return pointer;
};

const zeroMemory = (
    context: FinalityVerifierKernelContext,
    pointer: number,
    byteLength: number,
): void => {
    if (pointer !== 0 && byteLength > 0) {
        new Uint8Array(context.memory.buffer, pointer, byteLength).fill(0);
    }
};

const allocateAndCopy = (
    context: FinalityVerifierKernelContext,
    bytes: Uint8Array,
): number => {
    const pointer = allocate(context, bytes.byteLength);
    try {
        new Uint8Array(context.memory.buffer).set(bytes, pointer);
        return pointer;
    } catch (error) {
        zeroMemory(context, pointer, bytes.byteLength);
        context.deallocate(pointer, bytes.byteLength);
        throw new FinalityVerifierInternalError(
            'Finality verifier input could not be copied into WASM memory.',
            error,
        );
    }
};

const allocateZeroed = (
    context: FinalityVerifierKernelContext,
    byteLength: number,
): number => {
    const pointer = allocate(context, byteLength);
    zeroMemory(context, pointer, byteLength);
    return pointer;
};

const deallocate = (
    context: FinalityVerifierKernelContext,
    pointer: number,
    byteLength: number,
): void => {
    if (pointer !== 0) {
        zeroMemory(context, pointer, byteLength);
        context.deallocate(pointer, byteLength);
    }
};

const encodeHandles = (handles: readonly number[]): Uint8Array<ArrayBuffer> => {
    if (handles.length === 0) {
        throw new FinalityVerifierRefusalError('wrongTypeOrLength');
    }
    const bytes = new Uint8Array(handles.length * wasm32WordByteLength);
    const dataView = new DataView(bytes.buffer);
    handles.forEach((handle, index) => {
        if (
            !Number.isSafeInteger(handle) ||
            handle < 0 ||
            handle > maximumWasm32UnsignedInteger
        ) {
            bytes.fill(0);
            throw new FinalityVerifierInternalError(
                'A verifier-owned handle is outside the WASM32 range.',
            );
        }
        dataView.setUint32(index * wasm32WordByteLength, handle, true);
    });
    return bytes;
};

class FinalityVerifierSessionImplementation implements FinalityVerifierSession {
    readonly #context: FinalityVerifierKernelContext;
    readonly #handle: number;
    readonly #kernel: TranscriptCoreKernel;
    readonly #records = new Set<VerifiedFinalityRecord>();
    #capabilityPointer: number;
    #state: 'active' | 'cancelled' = 'active';

    public constructor(
        kernel: TranscriptCoreKernel,
        context: FinalityVerifierKernelContext,
        handle: number,
        capabilityPointer: number,
    ) {
        this.#kernel = kernel;
        this.#context = context;
        this.#handle = handle;
        this.#capabilityPointer = capabilityPointer;
    }

    public state(): 'active' | 'cancelled' {
        return this.#state;
    }

    public kernelAuthorization(
        record: VerifiedFinalityRecord,
        kernel: TranscriptCoreKernel,
    ): VerifiedFinalityKernelAuthorization {
        if (
            this.#state !== 'active' ||
            !record.active ||
            record.session !== this
        ) {
            throw new TypeError('The verified finality is unavailable.');
        }
        if (kernel !== this.#kernel) {
            throw new TypeError(
                'The verified finality belongs to another WASM kernel.',
            );
        }
        return Object.freeze({
            capabilityMemory: this.#context.memory,
            capabilityPointer: this.#capabilityPointer,
            finalityHandle: record.handle,
            sessionHandle: this.#handle,
        });
    }

    public verify(
        input: FinalityVerification,
    ): VerificationResult<VerifiedFinality> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        if (
            typeof input !== 'object' ||
            input === null ||
            Array.isArray(input)
        ) {
            return refused('wrongTypeOrLength');
        }
        const statementRefusal = requireBytes(input.canonicalStatement);
        const certificateRefusal = requireBytes(input.canonicalCertificate);
        if (
            statementRefusal !== undefined ||
            certificateRefusal !== undefined
        ) {
            return refused(
                statementRefusal ?? certificateRefusal ?? 'wrongTypeOrLength',
            );
        }
        if (
            !Array.isArray(input.verifiedFinalityObjects) ||
            input.verifiedFinalityObjects.length === 0
        ) {
            return refused('wrongTypeOrLength');
        }

        let replayRecord: VerifiedEvaluatorReplayRecord;
        try {
            const resolved = verifiedEvaluatorReplayRecords.get(
                input.verifiedEvaluatorReplay,
            );
            if (
                resolved === undefined ||
                !resolved.active ||
                resolved.kernel !== this.#kernel
            ) {
                return refused('missingPrerequisite');
            }
            replayRecord = resolved;
        } catch {
            return refused('wrongTypeOrLength');
        }

        let boardSessionHandle = 0;
        let boardCapabilityPointer = 0;
        const finalityObjectHandles: number[] = [];
        try {
            for (const verifiedObject of input.verifiedFinalityObjects as readonly VerifiedTranscriptObject[]) {
                const authorization =
                    resolveVerifiedTranscriptObjectKernelAuthorization(
                        verifiedObject,
                        this.#kernel,
                    );
                if (
                    authorization.capabilityMemory !== this.#context.memory ||
                    (boardSessionHandle !== 0 &&
                        (authorization.sessionHandle !== boardSessionHandle ||
                            authorization.capabilityPointer !==
                                boardCapabilityPointer))
                ) {
                    return refused('wrongContext');
                }
                boardSessionHandle = authorization.sessionHandle;
                boardCapabilityPointer = authorization.capabilityPointer;
                finalityObjectHandles.push(authorization.objectHandle);
            }
        } catch {
            return refused('consumedState');
        }

        const statement = Uint8Array.from(input.canonicalStatement);
        const certificate = Uint8Array.from(input.canonicalCertificate);
        let finalityHandleBytes = new Uint8Array();
        let statementPointer = 0;
        let certificatePointer = 0;
        let finalityHandlesPointer = 0;
        let statusPointer = 0;
        try {
            finalityHandleBytes = encodeHandles(finalityObjectHandles);
            statementPointer = allocateAndCopy(this.#context, statement);
            certificatePointer = allocateAndCopy(this.#context, certificate);
            finalityHandlesPointer = allocateAndCopy(
                this.#context,
                finalityHandleBytes,
            );
            statusPointer = allocateZeroed(this.#context, wasm32WordByteLength);
            const verifiedFinalityHandle = this.#context.runExclusive(
                'finality verification',
                () =>
                    this.#context.verify(
                        this.#handle,
                        this.#capabilityPointer,
                        finalityVerifierCapabilityByteLength,
                        replayRecord.handle,
                        boardSessionHandle,
                        boardCapabilityPointer,
                        finalityVerifierCapabilityByteLength,
                        finalityHandlesPointer,
                        finalityHandleBytes.byteLength,
                        statementPointer,
                        statement.byteLength,
                        certificatePointer,
                        certificate.byteLength,
                        statusPointer,
                    ),
            );
            const status = new DataView(
                this.#context.memory.buffer,
                statusPointer,
                wasm32WordByteLength,
            ).getUint32(0, true);
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                if (verifiedFinalityHandle !== 0) {
                    throw new FinalityVerifierInternalError(
                        'A refused finality verification returned a capability handle.',
                    );
                }
                return refused(refusalReason);
            }
            requireWasm32Handle(
                verifiedFinalityHandle,
                'verified finality handle',
            );
            const capability = Object.freeze(Object.create(null) as object);
            const record: VerifiedFinalityRecord = {
                active: true,
                handle: verifiedFinalityHandle,
                session: this,
            };
            verifiedFinalityRecords.set(capability, record);
            this.#records.add(record);
            return valid(capability as VerifiedFinality);
        } finally {
            statement.fill(0);
            certificate.fill(0);
            finalityHandleBytes.fill(0);
            deallocate(this.#context, statementPointer, statement.byteLength);
            deallocate(
                this.#context,
                certificatePointer,
                certificate.byteLength,
            );
            deallocate(
                this.#context,
                finalityHandlesPointer,
                finalityHandleBytes.byteLength,
            );
            deallocate(this.#context, statusPointer, wasm32WordByteLength);
        }
    }

    public describe(
        verifiedFinality: VerifiedFinality,
    ): VerificationResult<VerifiedFinalityDescription> {
        const record = this.#resolve(verifiedFinality);
        if ('refusalReason' in record) {
            return refused(record.refusalReason);
        }
        let outputPointer = 0;
        try {
            outputPointer = allocateZeroed(
                this.#context,
                verifiedFinalityDescriptionByteLength,
            );
            const status = this.#context.runExclusive(
                'describe verified finality',
                () =>
                    this.#context.describe(
                        this.#handle,
                        this.#capabilityPointer,
                        finalityVerifierCapabilityByteLength,
                        record.handle,
                        outputPointer,
                        verifiedFinalityDescriptionByteLength,
                    ),
            );
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            const output = new Uint8Array(
                this.#context.memory.buffer,
                outputPointer,
                verifiedFinalityDescriptionByteLength,
            );
            const dataView = new DataView(
                output.buffer,
                output.byteOffset,
                output.byteLength,
            );
            if (dataView.getUint16(0, true) !== 1) {
                throw new FinalityVerifierInternalError(
                    'The verified-finality description version is unsupported.',
                );
            }
            return valid(
                Object.freeze({
                    finalityHash: output.slice(2, 2 + hashByteLength),
                    evaluatorReplayObjectHash: output.slice(
                        2 + hashByteLength,
                        2 + 2 * hashByteLength,
                    ),
                    acceptedSignerCount: dataView.getUint32(
                        2 + 2 * hashByteLength,
                        true,
                    ),
                }),
            );
        } finally {
            deallocate(
                this.#context,
                outputPointer,
                verifiedFinalityDescriptionByteLength,
            );
        }
    }

    public release(
        verifiedFinality: VerifiedFinality,
    ): VerificationResult<undefined> {
        const record = this.#resolve(verifiedFinality);
        if ('refusalReason' in record) {
            return refused(record.refusalReason);
        }
        const status = this.#context.runExclusive(
            'release verified finality',
            () =>
                this.#context.release(
                    this.#handle,
                    this.#capabilityPointer,
                    finalityVerifierCapabilityByteLength,
                    record.handle,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            return refused(refusalReason);
        }
        record.active = false;
        this.#records.delete(record);
        return valid(undefined);
    }

    public cancel(): void {
        if (this.#state === 'cancelled') {
            return;
        }
        const status = this.#context.runExclusive(
            'cancel finality verifier',
            () =>
                this.#context.cancel(
                    this.#handle,
                    this.#capabilityPointer,
                    finalityVerifierCapabilityByteLength,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            throw new FinalityVerifierRefusalError(refusalReason);
        }
        this.#state = 'cancelled';
        for (const record of this.#records) {
            record.active = false;
        }
        this.#records.clear();
        deallocate(
            this.#context,
            this.#capabilityPointer,
            finalityVerifierCapabilityByteLength,
        );
        this.#capabilityPointer = 0;
    }

    #resolve(
        verifiedFinality: VerifiedFinality,
    ): VerifiedFinalityRecord | Readonly<{ refusalReason: RefusalReason }> {
        if (this.#state !== 'active') {
            return { refusalReason: 'consumedState' };
        }
        const record = verifiedFinalityRecords.get(verifiedFinality);
        if (record === undefined || !record.active || record.session !== this) {
            return { refusalReason: 'consumedState' };
        }
        return record;
    }
}

export const openFinalityVerifierSession = (input: {
    configuration: FinalityVerifierConfiguration;
    kernel: TranscriptCoreKernel;
}): VerificationResult<FinalityVerifierSession> => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        return refused('wrongTypeOrLength');
    }
    const context = contexts.get(input.kernel);
    if (context === undefined) {
        throw new FinalityVerifierInternalError(
            'The transcript-core kernel has no registered finality verifier boundary.',
        );
    }
    let configuration: Uint8Array<ArrayBuffer>;
    try {
        configuration = encodeConfiguration(input.configuration);
    } catch (error) {
        if (error instanceof FinalityVerifierRefusalError) {
            return refused(error.refusalReason);
        }
        throw error;
    }

    let capabilityPointer = 0;
    let configurationPointer = 0;
    let statusPointer = 0;
    let handle = 0;
    let sessionActivated = false;
    const capability = new Uint8Array(finalityVerifierCapabilityByteLength);
    try {
        if (globalThis.crypto === undefined) {
            throw new FinalityVerifierInternalError(
                'Web Crypto is required for finality session capabilities.',
            );
        }
        globalThis.crypto.getRandomValues(capability);
        if (capability.every((byte) => byte === 0)) {
            globalThis.crypto.getRandomValues(capability);
        }
        if (capability.every((byte) => byte === 0)) {
            throw new FinalityVerifierInternalError(
                'Web Crypto produced an invalid finality session capability.',
            );
        }
        capabilityPointer = allocateAndCopy(context, capability);
        configurationPointer = allocateAndCopy(context, configuration);
        statusPointer = allocateZeroed(context, wasm32WordByteLength);
        handle = context.runExclusive('finality verifier begin', () =>
            context.begin(
                configurationPointer,
                configuration.byteLength,
                capabilityPointer,
                finalityVerifierCapabilityByteLength,
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
                throw new FinalityVerifierInternalError(
                    'A refused finality-verifier begin returned a session handle.',
                );
            }
            return refused(refusalReason);
        }
        requireWasm32Handle(handle, 'finality verifier session handle');
        sessionActivated = true;
        return valid(
            Object.freeze(
                new FinalityVerifierSessionImplementation(
                    input.kernel,
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
                    'finality verifier begin failure cleanup',
                    () =>
                        context.cancel(
                            handle,
                            capabilityPointer,
                            finalityVerifierCapabilityByteLength,
                        ),
                );
                const cleanupRefusal = decodeStatus(cleanupStatus);
                if (cleanupRefusal !== undefined) {
                    throw new FinalityVerifierRefusalError(cleanupRefusal);
                }
            } catch (cleanupFailure) {
                throw new FinalityVerifierInternalError(
                    'The finality-verifier begin and cleanup both failed.',
                    Object.freeze({ cleanupFailure, operationFailure }),
                );
            }
        }
        throw operationFailure;
    } finally {
        capability.fill(0);
        configuration.fill(0);
        deallocate(context, configurationPointer, configuration.byteLength);
        deallocate(context, statusPointer, wasm32WordByteLength);
        if (!sessionActivated) {
            deallocate(
                context,
                capabilityPointer,
                finalityVerifierCapabilityByteLength,
            );
        }
    }
};
