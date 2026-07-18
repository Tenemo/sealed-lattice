import type { RefusalReason, VerificationResult } from '@sealed-lattice/types';
import { foundationProfile } from '@sealed-lattice/types';

import { isUint8Array } from './byte-array.js';
import { decodeWasmRefusalStatus } from './transcript-core-bridge/kernel-errors.js';
import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';

const boardVerifierCapabilityByteLength = 32;
const hashByteLength = 64;
const wasm32WordByteLength = 4;
const verifiedObjectDescriptionByteLength = 2 + 2 + hashByteLength;
const maximumWasm32UnsignedInteger = 0xffff_ffff;
const maximumCanonicalBoardBatchCarrierCount = 4_096;

export const foundationObjectTypes = Object.freeze({
    publicRandomnessCommitment: 0x0001,
    publicRandomnessReveal: 0x0002,
    setupIntent: 0x0010,
    privateShareAcceptance: 0x0011,
    complaint: 0x0012,
    publicSetupRecord: 0x0013,
    ballotPackage: 0x0020,
    aggregate: 0x0030,
    evaluatorReplay: 0x0040,
    finalitySignature: 0x0050,
    stateReservation: 0x0051,
    stateOutputIntent: 0x0052,
    stateWitnessVote: 0x0053,
    targetDecryptionShare: 0x0060,
    storageRootCommitment: 0x0070,
} as const);

export type FoundationObjectType =
    (typeof foundationObjectTypes)[keyof typeof foundationObjectTypes];

export type CanonicalBoardKernelContext = Readonly<{
    allocate(length: number): number;
    begin(
        canonicalSuiteRecordPointer: number,
        canonicalSuiteRecordLength: number,
        canonicalManifestPointer: number,
        canonicalManifestLength: number,
        canonicalRosterPointer: number,
        canonicalRosterLength: number,
        canonicalActionDefinitionPointer: number,
        canonicalActionDefinitionLength: number,
        canonicalBoardPolicyPointer: number,
        canonicalBoardPolicyLength: number,
        ceremonyIdentifierPointer: number,
        ceremonyIdentifierLength: number,
        actionIdentifierPointer: number,
        actionIdentifierLength: number,
        expectedSuiteIdentifierPointer: number,
        expectedSuiteIdentifierLength: number,
        expectedCeremonyContextHashPointer: number,
        expectedCeremonyContextHashLength: number,
        expectedActionContextHashPointer: number,
        expectedActionContextHashLength: number,
        capabilityPointer: number,
        capabilityLength: number,
        statusPointer: number,
    ): number;
    cachedCarrierLength(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        statusPointer: number,
    ): number;
    cancel(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
    ): number;
    copyCachedCarrier(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ): number;
    deallocate(pointer: number, length: number): void;
    describe(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
        outputPointer: number,
        outputLength: number,
    ): number;
    memory: WebAssembly.Memory;
    release(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        verifiedObjectHandle: number,
    ): number;
    runExclusive<Result>(
        operationName: string,
        operation: () => Result,
    ): Result;
    verifyUnordered(
        sessionHandle: number,
        capabilityPointer: number,
        capabilityLength: number,
        framedCarrierPointer: number,
        framedCarrierLength: number,
        outputPointer: number,
        outputLength: number,
        statusPointer: number,
    ): number;
}>;

const contexts = new WeakMap<
    TranscriptCoreKernel,
    CanonicalBoardKernelContext
>();

export const registerCanonicalBoardKernelContext = (
    kernel: TranscriptCoreKernel,
    context: CanonicalBoardKernelContext,
): void => {
    contexts.set(kernel, context);
};

declare const verifiedTranscriptObjectBrand: unique symbol;

/** Foundation-validated object capability; owning relations verify separately. */
export type VerifiedTranscriptObject = Readonly<{
    readonly [verifiedTranscriptObjectBrand]: true;
}>;

export type VerifiedTranscriptObjectDescription = Readonly<{
    objectHash: Uint8Array;
    objectType: FoundationObjectType;
}>;

export type UntrustedCanonicalBoardCarrier = Readonly<{
    canonicalCarrier: Uint8Array;
}>;

export type CanonicalBoardContextInput = Readonly<{
    actionIdentifier: string;
    canonicalActionDefinitionBytes: Uint8Array;
    canonicalBoardPolicyBytes: Uint8Array;
    canonicalManifestBytes: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    canonicalSuiteRecordBytes: Uint8Array;
    ceremonyIdentifier: string;
    expectedActionContextHash: Uint8Array;
    expectedCeremonyContextHash: Uint8Array;
    expectedSuiteIdentifier: Uint8Array;
}>;

export type CanonicalBoardVerifierSessionState = 'active' | 'closed';

export type CanonicalBoardVerifierSession = Readonly<{
    close(): void;
    copyCachedCarrier(
        object: VerifiedTranscriptObject,
    ): VerificationResult<Uint8Array>;
    describe(
        object: VerifiedTranscriptObject,
    ): VerificationResult<VerifiedTranscriptObjectDescription>;
    release(object: VerifiedTranscriptObject): void;
    state(): CanonicalBoardVerifierSessionState;
    verifyUnorderedCarriers(
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): VerificationResult<readonly VerifiedTranscriptObject[]>;
}>;

type VerifiedObjectRecord = {
    readonly handle: number;
    readonly session: CanonicalBoardVerifierSessionImplementation;
    released: boolean;
};

const verifiedObjectRecords = new WeakMap<object, VerifiedObjectRecord>();

type VerifiedTranscriptObjectKernelAuthorization = Readonly<{
    capabilityMemory: WebAssembly.Memory;
    capabilityPointer: number;
    objectHandle: number;
    sessionHandle: number;
}>;

export const resolveVerifiedTranscriptObjectKernelAuthorization = (
    object: VerifiedTranscriptObject,
    kernel: TranscriptCoreKernel,
): VerifiedTranscriptObjectKernelAuthorization => {
    if (
        (typeof object !== 'object' && typeof object !== 'function') ||
        object === null
    ) {
        throw new TypeError(
            'The transcript object was not issued by the WASM canonical-board verifier.',
        );
    }
    const record = verifiedObjectRecords.get(object);
    if (record === undefined || record.released) {
        throw new TypeError(
            'The transcript object is unavailable or was not issued by the WASM canonical-board verifier.',
        );
    }
    return record.session.kernelAuthorization(record, kernel);
};

class CanonicalBoardInternalError extends Error {
    public override readonly name = 'CanonicalBoardInternalError';
    public readonly failureCause: unknown;

    public constructor(message: string, failureCause?: unknown) {
        super(message);
        this.failureCause = failureCause;
    }
}

class CanonicalBoardRefusalError extends Error {
    public override readonly name = 'CanonicalBoardRefusalError';

    public constructor(public readonly refusalReason: RefusalReason) {
        super(`Canonical-board verification refused: ${refusalReason}.`);
    }
}

const refused = <Value>(
    refusalReason: RefusalReason,
): VerificationResult<Value> =>
    Object.freeze({ isValid: false, refusalReason });

const valid = <Value>(value: Value): VerificationResult<Value> =>
    Object.freeze({ isValid: true, value });

const isFoundationObjectType = (value: number): value is FoundationObjectType =>
    Object.values(foundationObjectTypes).some(
        (assignedValue) => assignedValue === value,
    );

const decodeStatus = (status: number): RefusalReason | undefined => {
    return decodeWasmRefusalStatus(
        status,
        CanonicalBoardInternalError,
        'The WASM canonical-board verifier returned an unknown status code.',
    );
};

const requireCopiedBytes = (
    value: unknown,
    expectedByteLength?: number,
): RefusalReason | undefined => {
    try {
        if (
            !isUint8Array(value) ||
            value.byteLength === 0 ||
            (expectedByteLength !== undefined &&
                value.byteLength !== expectedByteLength)
        ) {
            return 'wrongTypeOrLength';
        }
        if (
            value.byteLength >
                foundationProfile.maximumCopiedBufferByteLength ||
            value.byteLength > maximumWasm32UnsignedInteger
        ) {
            return 'outsideSupportedProfile';
        }
    } catch {
        return 'wrongTypeOrLength';
    }
    return undefined;
};

type EncodedCanonicalBoardContextInput = Readonly<{
    actionIdentifierBytes: Uint8Array<ArrayBuffer>;
    canonicalActionDefinitionBytes: Uint8Array<ArrayBuffer>;
    canonicalBoardPolicyBytes: Uint8Array<ArrayBuffer>;
    canonicalManifestBytes: Uint8Array<ArrayBuffer>;
    canonicalRosterBytes: Uint8Array<ArrayBuffer>;
    canonicalSuiteRecordBytes: Uint8Array<ArrayBuffer>;
    ceremonyIdentifierBytes: Uint8Array<ArrayBuffer>;
    expectedActionContextHash: Uint8Array<ArrayBuffer>;
    expectedCeremonyContextHash: Uint8Array<ArrayBuffer>;
    expectedSuiteIdentifier: Uint8Array<ArrayBuffer>;
}>;

const copyRequiredBytes = (
    value: unknown,
    expectedByteLength?: number,
): Uint8Array<ArrayBuffer> => {
    const refusalReason = requireCopiedBytes(value, expectedByteLength);
    if (refusalReason !== undefined) {
        throw new CanonicalBoardRefusalError(refusalReason);
    }
    return (value as Uint8Array).slice();
};

const encodeIdentifier = (value: unknown): Uint8Array<ArrayBuffer> => {
    if (typeof value !== 'string') {
        throw new CanonicalBoardRefusalError('wrongTypeOrLength');
    }
    return copyRequiredBytes(new TextEncoder().encode(value));
};

const copyCanonicalBoardContextInput = (
    input: CanonicalBoardContextInput,
): EncodedCanonicalBoardContextInput => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new CanonicalBoardRefusalError('wrongTypeOrLength');
    }
    let copiedInput: EncodedCanonicalBoardContextInput;
    try {
        copiedInput = {
            actionIdentifierBytes: encodeIdentifier(input.actionIdentifier),
            canonicalActionDefinitionBytes: copyRequiredBytes(
                input.canonicalActionDefinitionBytes,
            ),
            canonicalBoardPolicyBytes: copyRequiredBytes(
                input.canonicalBoardPolicyBytes,
            ),
            canonicalManifestBytes: copyRequiredBytes(
                input.canonicalManifestBytes,
            ),
            canonicalRosterBytes: copyRequiredBytes(input.canonicalRosterBytes),
            canonicalSuiteRecordBytes: copyRequiredBytes(
                input.canonicalSuiteRecordBytes,
            ),
            ceremonyIdentifierBytes: encodeIdentifier(input.ceremonyIdentifier),
            expectedActionContextHash: copyRequiredBytes(
                input.expectedActionContextHash,
                hashByteLength,
            ),
            expectedCeremonyContextHash: copyRequiredBytes(
                input.expectedCeremonyContextHash,
                hashByteLength,
            ),
            expectedSuiteIdentifier: copyRequiredBytes(
                input.expectedSuiteIdentifier,
                hashByteLength,
            ),
        };
    } catch (error) {
        if (error instanceof CanonicalBoardRefusalError) {
            throw error;
        }
        throw new CanonicalBoardRefusalError('wrongTypeOrLength');
    }
    return copiedInput;
};

const frameCarriers = (
    carriers: readonly UntrustedCanonicalBoardCarrier[],
    maximumCarrierCount: number,
): Readonly<{
    bytes: Uint8Array<ArrayBuffer>;
    carrierCount: number;
}> => {
    if (!Array.isArray(carriers)) {
        throw new CanonicalBoardRefusalError('wrongTypeOrLength');
    }
    let carrierCount: number;
    try {
        carrierCount = carriers.length;
    } catch {
        throw new CanonicalBoardRefusalError('wrongTypeOrLength');
    }
    if (
        !Number.isSafeInteger(carrierCount) ||
        carrierCount <= 0 ||
        carrierCount > maximumCarrierCount
    ) {
        throw new CanonicalBoardRefusalError('outsideSupportedProfile');
    }
    const copiedCarriers: Uint8Array<ArrayBuffer>[] = [];
    let framedByteLength = wasm32WordByteLength;
    try {
        for (
            let carrierIndex = 0;
            carrierIndex < carrierCount;
            carrierIndex += 1
        ) {
            let carrier: unknown;
            try {
                carrier = (carriers as readonly unknown[])[carrierIndex];
            } catch {
                throw new CanonicalBoardRefusalError('wrongTypeOrLength');
            }
            if (
                typeof carrier !== 'object' ||
                carrier === null ||
                Array.isArray(carrier)
            ) {
                throw new CanonicalBoardRefusalError('wrongTypeOrLength');
            }
            // Transport metadata is deliberately unselected. Only canonical bytes enter WASM.
            let canonicalCarrier: unknown;
            try {
                canonicalCarrier = Reflect.get(carrier, 'canonicalCarrier');
            } catch {
                throw new CanonicalBoardRefusalError('wrongTypeOrLength');
            }
            const refusalReason = requireCopiedBytes(canonicalCarrier);
            if (refusalReason !== undefined) {
                throw new CanonicalBoardRefusalError(refusalReason);
            }
            const validatedCanonicalCarrier = canonicalCarrier as Uint8Array;
            const nextFramedByteLength =
                framedByteLength +
                wasm32WordByteLength +
                validatedCanonicalCarrier.byteLength;
            if (
                nextFramedByteLength >
                    foundationProfile.maximumCopiedBufferByteLength ||
                nextFramedByteLength > maximumWasm32UnsignedInteger
            ) {
                throw new CanonicalBoardRefusalError('outsideSupportedProfile');
            }
            framedByteLength = nextFramedByteLength;
            const copiedCarrier = new Uint8Array(
                validatedCanonicalCarrier.byteLength,
            );
            copiedCarrier.set(validatedCanonicalCarrier);
            copiedCarriers.push(copiedCarrier);
        }
        const framed = new Uint8Array(framedByteLength);
        const view = new DataView(framed.buffer);
        let offset = 0;
        view.setUint32(offset, copiedCarriers.length, true);
        offset += wasm32WordByteLength;
        for (const carrier of copiedCarriers) {
            view.setUint32(offset, carrier.byteLength, true);
            offset += wasm32WordByteLength;
            framed.set(carrier, offset);
            offset += carrier.byteLength;
        }
        return Object.freeze({ bytes: framed, carrierCount });
    } finally {
        for (const carrier of copiedCarriers) {
            carrier.fill(0);
        }
    }
};

const decodeHandles = (
    bytes: Uint8Array,
    maximumCount: number,
): readonly number[] => {
    if (bytes.byteLength < wasm32WordByteLength) {
        throw new CanonicalBoardInternalError(
            'The WASM canonical-board verifier returned a truncated handle list.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const count = view.getUint32(0, true);
    if (
        count === 0 ||
        count > maximumCount ||
        bytes.byteLength !== wasm32WordByteLength + count * wasm32WordByteLength
    ) {
        throw new CanonicalBoardInternalError(
            'The WASM canonical-board verifier returned an inconsistent handle list.',
        );
    }
    const handles: number[] = [];
    const seen = new Set<number>();
    for (
        let offset = wasm32WordByteLength;
        offset < bytes.byteLength;
        offset += wasm32WordByteLength
    ) {
        const handle = view.getUint32(offset, true);
        if (handle === 0 || seen.has(handle)) {
            throw new CanonicalBoardInternalError(
                'The WASM canonical-board verifier returned an invalid object handle.',
            );
        }
        seen.add(handle);
        handles.push(handle);
    }
    return Object.freeze(handles);
};

const decodeDescription = (
    bytes: Uint8Array,
): VerifiedTranscriptObjectDescription => {
    if (bytes.byteLength !== verifiedObjectDescriptionByteLength) {
        throw new CanonicalBoardInternalError(
            'The WASM canonical-board verifier returned a malformed object description.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const objectType = view.getUint16(2, true);
    if (view.getUint16(0, true) !== 1 || !isFoundationObjectType(objectType)) {
        throw new CanonicalBoardInternalError(
            'The WASM canonical-board verifier returned an unsupported object description.',
        );
    }
    return Object.freeze({
        objectHash: bytes.slice(4),
        objectType,
    });
};

const allocate = (
    context: CanonicalBoardKernelContext,
    byteLength: number,
): number => {
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength <= 0 ||
        byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new CanonicalBoardRefusalError('outsideSupportedProfile');
    }
    if (
        context.memory.buffer.byteLength >
        foundationProfile.maximumWasmMemoryByteLength - byteLength
    ) {
        throw new CanonicalBoardRefusalError('outsideSupportedProfile');
    }
    const pointer = context.allocate(byteLength) >>> 0;
    if (
        pointer === 0 ||
        pointer + byteLength > context.memory.buffer.byteLength
    ) {
        throw new CanonicalBoardInternalError(
            'The WASM canonical-board allocator returned an invalid range.',
        );
    }
    return pointer;
};

const zeroMemory = (
    context: CanonicalBoardKernelContext,
    pointer: number,
    byteLength: number,
): void => {
    if (
        pointer !== 0 &&
        pointer + byteLength <= context.memory.buffer.byteLength
    ) {
        new Uint8Array(context.memory.buffer, pointer, byteLength).fill(0);
    }
};

const allocateZeroed = (
    context: CanonicalBoardKernelContext,
    byteLength: number,
): number => {
    const pointer = allocate(context, byteLength);
    zeroMemory(context, pointer, byteLength);
    return pointer;
};

const allocateAndCopy = (
    context: CanonicalBoardKernelContext,
    bytes: Uint8Array,
): number => {
    const pointer = allocate(context, bytes.byteLength);
    try {
        new Uint8Array(context.memory.buffer).set(bytes, pointer);
        return pointer;
    } catch (error) {
        zeroMemory(context, pointer, bytes.byteLength);
        context.deallocate(pointer, bytes.byteLength);
        throw new CanonicalBoardInternalError(
            'Canonical-board input could not be copied into WASM memory.',
            error,
        );
    }
};

const createCapability = (context: CanonicalBoardKernelContext): number => {
    const capability = new Uint8Array(boardVerifierCapabilityByteLength);
    if (globalThis.crypto === undefined) {
        throw new CanonicalBoardInternalError(
            'Web Crypto getRandomValues is required for board capabilities.',
        );
    }
    try {
        globalThis.crypto.getRandomValues(capability);
        if (capability.every((byte) => byte === 0)) {
            globalThis.crypto.getRandomValues(capability);
        }
        if (capability.every((byte) => byte === 0)) {
            throw new CanonicalBoardInternalError(
                'Web Crypto produced an invalid all-zero board capability.',
            );
        }
        return allocateAndCopy(context, capability);
    } finally {
        capability.fill(0);
    }
};

class CanonicalBoardVerifierSessionImplementation implements CanonicalBoardVerifierSession {
    readonly #context: CanonicalBoardKernelContext;
    readonly #handle: number;
    readonly #kernel: TranscriptCoreKernel;
    readonly #maximumCarrierCount: number;
    readonly #objectsByHandle = new Map<number, VerifiedTranscriptObject>();
    #capabilityPointer: number;
    #state: CanonicalBoardVerifierSessionState = 'active';

    public constructor(
        kernel: TranscriptCoreKernel,
        context: CanonicalBoardKernelContext,
        handle: number,
        capabilityPointer: number,
        maximumCarrierCount: number,
    ) {
        this.#kernel = kernel;
        this.#context = context;
        this.#handle = handle;
        this.#capabilityPointer = capabilityPointer;
        this.#maximumCarrierCount = maximumCarrierCount;
    }

    public state(): CanonicalBoardVerifierSessionState {
        return this.#state;
    }

    public kernelAuthorization(
        record: VerifiedObjectRecord,
        kernel: TranscriptCoreKernel,
    ): VerifiedTranscriptObjectKernelAuthorization {
        if (
            this.#state !== 'active' ||
            record.released ||
            record.session !== this ||
            !this.#objectsByHandle.has(record.handle)
        ) {
            throw new TypeError(
                'The verified transcript object is unavailable.',
            );
        }
        if (kernel !== this.#kernel) {
            throw new TypeError(
                'The verified transcript object belongs to another WASM kernel.',
            );
        }
        return Object.freeze({
            capabilityMemory: this.#context.memory,
            capabilityPointer: this.#capabilityPointer,
            objectHandle: record.handle,
            sessionHandle: this.#handle,
        });
    }

    public verifyUnorderedCarriers(
        carriers: readonly UntrustedCanonicalBoardCarrier[],
    ): VerificationResult<readonly VerifiedTranscriptObject[]> {
        if (this.#state !== 'active') {
            return refused('consumedState');
        }
        let framed = new Uint8Array();
        let framedPointer = 0;
        let maximumOutputByteLength = 0;
        let outputPointer = 0;
        let statusPointer = 0;
        try {
            const framedCarriers = frameCarriers(
                carriers,
                this.#maximumCarrierCount,
            );
            framed = framedCarriers.bytes;
            const framedCarrierCount = framedCarriers.carrierCount;
            framedPointer = allocateAndCopy(this.#context, framed);
            maximumOutputByteLength =
                wasm32WordByteLength +
                framedCarrierCount * wasm32WordByteLength;
            outputPointer = allocateZeroed(
                this.#context,
                maximumOutputByteLength,
            );
            statusPointer = allocateZeroed(this.#context, wasm32WordByteLength);
            const outputByteLength = this.#context.runExclusive(
                'canonical-board unordered verification',
                () =>
                    this.#context.verifyUnordered(
                        this.#handle,
                        this.#capabilityPointer,
                        boardVerifierCapabilityByteLength,
                        framedPointer,
                        framed.byteLength,
                        outputPointer,
                        maximumOutputByteLength,
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
                if (outputByteLength !== 0) {
                    throw new CanonicalBoardInternalError(
                        'A refused board verification returned output bytes.',
                    );
                }
                return refused(refusalReason);
            }
            if (
                outputByteLength === 0 ||
                outputByteLength > maximumOutputByteLength
            ) {
                throw new CanonicalBoardInternalError(
                    'The WASM board verifier returned an invalid output length.',
                );
            }
            const handles = decodeHandles(
                new Uint8Array(
                    this.#context.memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).slice(),
                framedCarrierCount,
            );
            const objects = handles.map((handle) => this.#issueObject(handle));
            return valid(Object.freeze(objects));
        } catch (error) {
            if (error instanceof CanonicalBoardRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            framed.fill(0);
            for (const [pointer, byteLength] of [
                [framedPointer, framed.byteLength],
                [outputPointer, maximumOutputByteLength],
                [statusPointer, wasm32WordByteLength],
            ] as const) {
                if (pointer !== 0) {
                    zeroMemory(this.#context, pointer, byteLength);
                    this.#context.deallocate(pointer, byteLength);
                }
            }
        }
    }

    public describe(
        object: VerifiedTranscriptObject,
    ): VerificationResult<VerifiedTranscriptObjectDescription> {
        const resolved = this.#resolveObject(object);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        let outputPointer = 0;
        try {
            outputPointer = allocateZeroed(
                this.#context,
                verifiedObjectDescriptionByteLength,
            );
            const status = this.#context.runExclusive(
                'canonical-board object description',
                () =>
                    this.#context.describe(
                        this.#handle,
                        this.#capabilityPointer,
                        boardVerifierCapabilityByteLength,
                        resolved.record.handle,
                        outputPointer,
                        verifiedObjectDescriptionByteLength,
                    ),
            );
            const refusalReason = decodeStatus(status);
            if (refusalReason !== undefined) {
                return refused(refusalReason);
            }
            return valid(
                decodeDescription(
                    new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        verifiedObjectDescriptionByteLength,
                    ).slice(),
                ),
            );
        } catch (error) {
            if (error instanceof CanonicalBoardRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            if (outputPointer !== 0) {
                zeroMemory(
                    this.#context,
                    outputPointer,
                    verifiedObjectDescriptionByteLength,
                );
                this.#context.deallocate(
                    outputPointer,
                    verifiedObjectDescriptionByteLength,
                );
            }
        }
    }

    public copyCachedCarrier(
        object: VerifiedTranscriptObject,
    ): VerificationResult<Uint8Array> {
        const resolved = this.#resolveObject(object);
        if ('refusalReason' in resolved) {
            return refused(resolved.refusalReason);
        }
        let outputByteLength = 0;
        let outputPointer = 0;
        let statusPointer = 0;
        try {
            statusPointer = allocateZeroed(this.#context, wasm32WordByteLength);
            outputByteLength = this.#context.runExclusive(
                'canonical-board cached carrier length',
                () =>
                    this.#context.cachedCarrierLength(
                        this.#handle,
                        this.#capabilityPointer,
                        boardVerifierCapabilityByteLength,
                        resolved.record.handle,
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
                if (outputByteLength !== 0) {
                    throw new CanonicalBoardInternalError(
                        'A refused cached-carrier length returned a byte length.',
                    );
                }
                return refused(refusalReason);
            }
            if (
                outputByteLength === 0 ||
                outputByteLength >
                    foundationProfile.maximumCopiedBufferByteLength
            ) {
                throw new CanonicalBoardInternalError(
                    'The WASM board verifier returned an invalid cached-carrier length.',
                );
            }
            outputPointer = allocateZeroed(this.#context, outputByteLength);
            const copyStatus = this.#context.runExclusive(
                'canonical-board cached carrier copy',
                () =>
                    this.#context.copyCachedCarrier(
                        this.#handle,
                        this.#capabilityPointer,
                        boardVerifierCapabilityByteLength,
                        resolved.record.handle,
                        outputPointer,
                        outputByteLength,
                    ),
            );
            const copyRefusal = decodeStatus(copyStatus);
            if (copyRefusal !== undefined) {
                return refused(copyRefusal);
            }
            return valid(
                new Uint8Array(
                    this.#context.memory.buffer,
                    outputPointer,
                    outputByteLength,
                ).slice(),
            );
        } catch (error) {
            if (error instanceof CanonicalBoardRefusalError) {
                return refused(error.refusalReason);
            }
            throw error;
        } finally {
            if (outputPointer !== 0) {
                zeroMemory(this.#context, outputPointer, outputByteLength);
                this.#context.deallocate(outputPointer, outputByteLength);
            }
            if (statusPointer !== 0) {
                zeroMemory(this.#context, statusPointer, wasm32WordByteLength);
                this.#context.deallocate(statusPointer, wasm32WordByteLength);
            }
        }
    }

    public release(object: VerifiedTranscriptObject): void {
        const resolved = this.#resolveObject(object);
        if ('refusalReason' in resolved) {
            throw new CanonicalBoardRefusalError(resolved.refusalReason);
        }
        const status = this.#context.runExclusive(
            'canonical-board object release',
            () =>
                this.#context.release(
                    this.#handle,
                    this.#capabilityPointer,
                    boardVerifierCapabilityByteLength,
                    resolved.record.handle,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            throw new CanonicalBoardRefusalError(refusalReason);
        }
        resolved.record.released = true;
        this.#objectsByHandle.delete(resolved.record.handle);
    }

    public close(): void {
        if (this.#state === 'closed') {
            return;
        }
        const status = this.#context.runExclusive(
            'canonical-board verifier cancel',
            () =>
                this.#context.cancel(
                    this.#handle,
                    this.#capabilityPointer,
                    boardVerifierCapabilityByteLength,
                ),
        );
        const refusalReason = decodeStatus(status);
        if (refusalReason !== undefined) {
            throw new CanonicalBoardRefusalError(refusalReason);
        }
        for (const object of this.#objectsByHandle.values()) {
            const record = verifiedObjectRecords.get(object);
            if (record !== undefined) {
                record.released = true;
            }
        }
        this.#objectsByHandle.clear();
        const capabilityPointer = this.#capabilityPointer;
        this.#capabilityPointer = 0;
        this.#state = 'closed';
        zeroMemory(
            this.#context,
            capabilityPointer,
            boardVerifierCapabilityByteLength,
        );
        this.#context.deallocate(
            capabilityPointer,
            boardVerifierCapabilityByteLength,
        );
    }

    #issueObject(handle: number): VerifiedTranscriptObject {
        const previous = this.#objectsByHandle.get(handle);
        if (previous !== undefined) {
            return previous;
        }
        const object = Object.freeze(
            Object.create(null) as object,
        ) as VerifiedTranscriptObject;
        const record: VerifiedObjectRecord = {
            handle,
            released: false,
            session: this,
        };
        verifiedObjectRecords.set(object, record);
        this.#objectsByHandle.set(handle, object);
        return object;
    }

    #resolveObject(
        object: VerifiedTranscriptObject,
    ):
        | Readonly<{ record: VerifiedObjectRecord }>
        | Readonly<{ refusalReason: RefusalReason }> {
        if (this.#state !== 'active') {
            return { refusalReason: 'consumedState' };
        }
        if (
            (typeof object !== 'object' && typeof object !== 'function') ||
            object === null
        ) {
            return { refusalReason: 'wrongTypeOrLength' };
        }
        const record = verifiedObjectRecords.get(object);
        if (record === undefined || record.session !== this) {
            return { refusalReason: 'wrongContext' };
        }
        if (record.released) {
            return { refusalReason: 'consumedState' };
        }
        return { record };
    }
}

export const openCanonicalBoardVerifierSession = (input: {
    readonly contextInput: CanonicalBoardContextInput;
    readonly kernel: TranscriptCoreKernel;
}): VerificationResult<CanonicalBoardVerifierSession> => {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        return refused('wrongTypeOrLength');
    }
    let rawContextInput: CanonicalBoardContextInput;
    let inputKernel: TranscriptCoreKernel;
    try {
        rawContextInput = input.contextInput;
        inputKernel = input.kernel;
    } catch {
        return refused('wrongTypeOrLength');
    }
    const context = contexts.get(inputKernel);
    if (context === undefined) {
        throw new CanonicalBoardInternalError(
            'The transcript-core kernel has no registered canonical-board boundary.',
        );
    }
    const allocatedInputs: Array<
        Readonly<{
            bytes: Uint8Array<ArrayBuffer>;
            pointer: number;
        }>
    > = [];
    let capabilityPointer = 0;
    let statusPointer = 0;
    let handle = 0;
    let sessionActivated = false;
    try {
        const contextInput = copyCanonicalBoardContextInput(rawContextInput);
        const allocateInput = (bytes: Uint8Array<ArrayBuffer>): number => {
            const pointer = allocateAndCopy(context, bytes);
            allocatedInputs.push({ bytes, pointer });
            return pointer;
        };
        const canonicalSuiteRecordPointer = allocateInput(
            contextInput.canonicalSuiteRecordBytes,
        );
        const canonicalManifestPointer = allocateInput(
            contextInput.canonicalManifestBytes,
        );
        const canonicalRosterPointer = allocateInput(
            contextInput.canonicalRosterBytes,
        );
        const canonicalActionDefinitionPointer = allocateInput(
            contextInput.canonicalActionDefinitionBytes,
        );
        const canonicalBoardPolicyPointer = allocateInput(
            contextInput.canonicalBoardPolicyBytes,
        );
        const ceremonyIdentifierPointer = allocateInput(
            contextInput.ceremonyIdentifierBytes,
        );
        const actionIdentifierPointer = allocateInput(
            contextInput.actionIdentifierBytes,
        );
        const expectedSuiteIdentifierPointer = allocateInput(
            contextInput.expectedSuiteIdentifier,
        );
        const expectedCeremonyContextHashPointer = allocateInput(
            contextInput.expectedCeremonyContextHash,
        );
        const expectedActionContextHashPointer = allocateInput(
            contextInput.expectedActionContextHash,
        );
        capabilityPointer = createCapability(context);
        statusPointer = allocateZeroed(context, wasm32WordByteLength);
        handle = context.runExclusive('canonical-board verifier begin', () =>
            context.begin(
                canonicalSuiteRecordPointer,
                contextInput.canonicalSuiteRecordBytes.byteLength,
                canonicalManifestPointer,
                contextInput.canonicalManifestBytes.byteLength,
                canonicalRosterPointer,
                contextInput.canonicalRosterBytes.byteLength,
                canonicalActionDefinitionPointer,
                contextInput.canonicalActionDefinitionBytes.byteLength,
                canonicalBoardPolicyPointer,
                contextInput.canonicalBoardPolicyBytes.byteLength,
                ceremonyIdentifierPointer,
                contextInput.ceremonyIdentifierBytes.byteLength,
                actionIdentifierPointer,
                contextInput.actionIdentifierBytes.byteLength,
                expectedSuiteIdentifierPointer,
                contextInput.expectedSuiteIdentifier.byteLength,
                expectedCeremonyContextHashPointer,
                contextInput.expectedCeremonyContextHash.byteLength,
                expectedActionContextHashPointer,
                contextInput.expectedActionContextHash.byteLength,
                capabilityPointer,
                boardVerifierCapabilityByteLength,
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
                throw new CanonicalBoardInternalError(
                    'A refused canonical-board begin returned a session handle.',
                );
            }
            return refused(refusalReason);
        }
        if (handle === 0) {
            throw new CanonicalBoardInternalError(
                'The WASM canonical-board verifier returned an invalid session handle.',
            );
        }
        const session = Object.freeze(
            new CanonicalBoardVerifierSessionImplementation(
                inputKernel,
                context,
                handle,
                capabilityPointer,
                maximumCanonicalBoardBatchCarrierCount,
            ),
        );
        sessionActivated = true;
        return valid(session);
    } catch (operationFailure) {
        if (!sessionActivated && handle !== 0 && capabilityPointer !== 0) {
            try {
                const cleanupStatus = context.runExclusive(
                    'canonical-board begin cleanup',
                    () =>
                        context.cancel(
                            handle,
                            capabilityPointer,
                            boardVerifierCapabilityByteLength,
                        ),
                );
                const cleanupRefusal = decodeStatus(cleanupStatus);
                if (cleanupRefusal !== undefined) {
                    throw new CanonicalBoardRefusalError(cleanupRefusal);
                }
            } catch (cleanupFailure) {
                throw new CanonicalBoardInternalError(
                    'Canonical-board begin and cleanup both failed.',
                    Object.freeze({ cleanupFailure, operationFailure }),
                );
            }
        }
        if (operationFailure instanceof CanonicalBoardRefusalError) {
            return refused(operationFailure.refusalReason);
        }
        throw operationFailure;
    } finally {
        for (const allocatedInput of allocatedInputs) {
            allocatedInput.bytes.fill(0);
            zeroMemory(
                context,
                allocatedInput.pointer,
                allocatedInput.bytes.byteLength,
            );
            context.deallocate(
                allocatedInput.pointer,
                allocatedInput.bytes.byteLength,
            );
        }
        if (statusPointer !== 0) {
            zeroMemory(context, statusPointer, wasm32WordByteLength);
            context.deallocate(statusPointer, wasm32WordByteLength);
        }
        if (!sessionActivated && capabilityPointer !== 0) {
            zeroMemory(
                context,
                capabilityPointer,
                boardVerifierCapabilityByteLength,
            );
            context.deallocate(
                capabilityPointer,
                boardVerifierCapabilityByteLength,
            );
        }
    }
};
