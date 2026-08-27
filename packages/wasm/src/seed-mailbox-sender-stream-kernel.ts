import { foundationProfile } from '@sealed-lattice/types';

import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';

const requestMagic = Uint8Array.of(0x53, 0x4c, 0x4d, 0x51);
const responseMagic = Uint8Array.of(0x53, 0x4c, 0x4d, 0x52);
const codecVersion = 1;
const openContextOperation = 1;
const prepareCarrierOperation = 2;
const completeCarrierOperation = 3;
const validateCarrierOperation = 4;
const closeContextOperation = 5;
const failureStatus = 0;
const openContextStatus = 1;
const preparedCarrierStatus = 2;
const completeCarrierStatus = 3;
const validationStatus = 4;
const closedContextStatus = 5;
const hashByteLength = 64;
const encapsulationRandomnessByteLength = 32;
const signatureRandomnessByteLength = 32;
const signingVerificationKeyByteLength = 1_952;
const signatureByteLength = 3_309;
const signatureBodyByteLength = 309;
const responseHeaderByteLength = responseMagic.byteLength + 2 + 1;
const failureResponseByteLength = responseHeaderByteLength + 2;
const openResponseByteLength =
    responseHeaderByteLength + 4 + signingVerificationKeyByteLength;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const seedMailboxSenderStreamKernelBrand: unique symbol = Symbol(
    'seed-mailbox-sender-stream-kernel',
);

declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

export type SeedMailboxSenderStreamContext = Readonly<{
    parameterIdentity: Uint8Array;
    participantCount: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    recipientPosition: number;
    rootTerminalIdentity: Uint8Array;
    senderPosition: number;
}>;

export type SeedMailboxSenderStreamGeometry = Readonly<{
    encryptedChunkByteLengths: readonly number[];
    headerByteLength: number;
    manifestByteLength: number;
    signatureEnvelopeByteLength: number;
    sourcePayloadByteLength: number;
    totalCarrierByteLength: number;
}>;

export type SeedMailboxSenderStreamCarrier = Readonly<{
    encryptedChunks: readonly Uint8Array[];
    headerBytes: Uint8Array;
    manifestBytes: Uint8Array;
    signatureEnvelopeBytes: Uint8Array;
}>;

export type SeedMailboxSenderStreamProductionInput = Readonly<{
    canonicalDeliveryDescriptorBytes: Uint8Array;
    context: SeedMailboxSenderStreamContext;
    encapsulationRandomness: Uint8Array;
    signatureRandomness: Uint8Array;
    sourcePayloadBytes: Uint8Array;
}>;

export type SeedMailboxSenderStreamValidationInput = Readonly<{
    canonicalDeliveryDescriptorBytes: Uint8Array;
    carrier: SeedMailboxSenderStreamCarrier;
    context: SeedMailboxSenderStreamContext;
    geometry: SeedMailboxSenderStreamGeometry;
}>;

export type SeedMailboxSenderRootAuthorizationPackageBytes = Readonly<{
    contributorSignatureEnvelopeBytes: Uint8Array;
    exactOutputCertificateBytes: Uint8Array;
    reservationCertificateBytes: Uint8Array;
    rootBodyBytes: Uint8Array;
}>;

/**
 * Fixed-purpose signing operations supplied by the browser-local key owner.
 * Their output is not trusted: Rust reconstructs and positively verifies the
 * exact sender envelope before returning any carrier.
 */
export type SeedMailboxSenderSigningOperations = Readonly<{
    assertMatchesSenderVerificationKey(input: {
        readonly senderSigningVerificationKey: Uint8Array;
    }): void;
    signManifestBody(input: {
        readonly senderSigningVerificationKey: Uint8Array;
        readonly signatureBodyBytes: Uint8Array;
        readonly signatureRandomness: Uint8Array;
    }): Uint8Array;
}>;

type SnapshottedSeedMailboxSenderSigningOperations = Readonly<{
    assertMatchesSenderVerificationKey(input: {
        readonly senderSigningVerificationKey: Uint8Array;
    }): void;
    signManifestBody(input: {
        readonly senderSigningVerificationKey: Uint8Array;
        readonly signatureBodyBytes: Uint8Array;
        readonly signatureRandomness: Uint8Array;
    }): Uint8Array;
}>;

export type OpenProductionSeedMailboxSenderStreamKernelInput = Readonly<{
    parameterIdentity: Uint8Array;
    preparationContextBytes: Uint8Array;
    rootAuthorizationPackages: readonly SeedMailboxSenderRootAuthorizationPackageBytes[];
    rootTerminalCertificateBytes: Uint8Array;
    rosterBytes: Uint8Array;
    senderPosition: number;
    signingOperations: SeedMailboxSenderSigningOperations;
}>;

export type SeedMailboxSenderKernelErrorCode =
    | 'CarrierMismatch'
    | 'ContextMismatch'
    | 'ContextUnavailable'
    | 'MalformedKernelResponse'
    | 'MalformedRequest'
    | 'PublicVerification'
    | 'ResourceLimit'
    | 'SignatureMismatch'
    | 'StreamProduction';

export class SeedMailboxSenderKernelError extends Error {
    public readonly code: SeedMailboxSenderKernelErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: SeedMailboxSenderKernelErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'SeedMailboxSenderKernelError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

/**
 * Integrity-pinned scalar Rust/WebAssembly sender boundary. Its opaque context
 * exists only after positive root-terminal verification and its output remains
 * inert publication custody rather than a recipient or continuation result.
 */
export type ProductionSeedMailboxSenderStreamKernel = Readonly<{
    readonly [seedMailboxSenderStreamKernelBrand]: true;
    close(): void;
    produce(
        input: SeedMailboxSenderStreamProductionInput,
    ): SeedMailboxSenderStreamCarrier;
    validate(input: SeedMailboxSenderStreamValidationInput): void;
}>;

const productionKernels = new WeakSet<object>();

const responseCodeByNumber = new Map<
    number,
    Exclude<SeedMailboxSenderKernelErrorCode, 'MalformedKernelResponse'>
>([
    [1, 'MalformedRequest'],
    [2, 'ResourceLimit'],
    [3, 'ContextMismatch'],
    [4, 'PublicVerification'],
    [5, 'StreamProduction'],
    [6, 'CarrierMismatch'],
    [7, 'ContextUnavailable'],
    [8, 'SignatureMismatch'],
]);

const malformedResponse = (detail: string): SeedMailboxSenderKernelError =>
    new SeedMailboxSenderKernelError(
        'MalformedKernelResponse',
        `The seed-mailbox sender kernel returned ${detail}.`,
    );

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const isReadonlyArray = (value: unknown): value is readonly unknown[] =>
    Array.isArray(value);

const snapshotDataProperty = (
    value: unknown,
    propertyName: string,
    label: string,
): unknown => {
    if (typeof value !== 'object' || value === null) {
        throw new TypeError(`${label} must be an ordinary object.`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, propertyName);
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new TypeError(
            `${label}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const snapshotSigningOperations = (
    value: unknown,
): SnapshottedSeedMailboxSenderSigningOperations => {
    const assertMatchesSenderVerificationKey = snapshotDataProperty(
        value,
        'assertMatchesSenderVerificationKey',
        'Sender-mailbox signing operations',
    );
    const signManifestBody = snapshotDataProperty(
        value,
        'signManifestBody',
        'Sender-mailbox signing operations',
    );
    if (
        typeof assertMatchesSenderVerificationKey !== 'function' ||
        typeof signManifestBody !== 'function'
    ) {
        throw new TypeError(
            'Sender-mailbox signing operations must provide fixed-purpose functions.',
        );
    }
    const typedAssertMatchesSenderVerificationKey =
        assertMatchesSenderVerificationKey as SnapshottedSeedMailboxSenderSigningOperations['assertMatchesSenderVerificationKey'];
    const typedSignManifestBody =
        signManifestBody as SnapshottedSeedMailboxSenderSigningOperations['signManifestBody'];
    return Object.freeze({
        assertMatchesSenderVerificationKey:
            typedAssertMatchesSenderVerificationKey,
        signManifestBody: (input) =>
            requireExactBytes(
                typedSignManifestBody(input),
                signatureByteLength,
                'Sender-mailbox signing-operation response',
            ),
    });
};

const requireExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new TypeError(`${label} has the wrong exact byte length.`);
    }
    return value;
};

const requireBoundedBytes = (value: unknown, label: string): Uint8Array => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new TypeError(`${label} is not a bounded nonempty byte array.`);
    }
    return value;
};

const requireInteger = (
    value: unknown,
    maximum: number,
    label: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > maximum
    ) {
        throw new TypeError(`${label} is outside its unsigned integer range.`);
    }
    return value;
};

const unsigned16LittleEndian = (value: number, label: string): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(
        0,
        requireInteger(value, unsigned16Maximum, label),
        true,
    );
    return bytes;
};

const unsigned32LittleEndian = (value: number, label: string): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(
        0,
        requireInteger(value, unsigned32Maximum, label),
        true,
    );
    return bytes;
};

const boundedBytesParts = (
    value: Uint8Array,
    label: string,
): readonly Uint8Array[] => {
    const bytes = requireBoundedBytes(value, label);
    return [
        unsigned32LittleEndian(bytes.byteLength, `${label} byte length`),
        bytes,
    ];
};

const concatenateRequestParts = (parts: readonly Uint8Array[]): Uint8Array => {
    let byteLength = 0;
    for (const part of parts) {
        byteLength += part.byteLength;
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw new SeedMailboxSenderKernelError(
                'ResourceLimit',
                'The seed-mailbox sender request exceeds the absolute copied-buffer bound.',
            );
        }
    }
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const part of parts) {
        bytes.set(part, offset);
        offset += part.byteLength;
    }
    return bytes;
};

const requestHeaderParts = (operation: number): readonly Uint8Array[] => [
    requestMagic,
    unsigned16LittleEndian(codecVersion, 'Sender-mailbox codec version'),
    Uint8Array.of(operation),
];

const streamContextParts = (
    context: SeedMailboxSenderStreamContext,
): readonly Uint8Array[] => [
    requireExactBytes(
        context.parameterIdentity,
        hashByteLength,
        'Sender-mailbox parameter identity',
    ),
    unsigned16LittleEndian(
        context.participantCount,
        'Sender-mailbox participant count',
    ),
    unsigned16LittleEndian(
        context.preparationAttemptOrdinal,
        'Sender-mailbox preparation-attempt ordinal',
    ),
    requireExactBytes(
        context.preparationContextIdentity,
        hashByteLength,
        'Sender-mailbox preparation-context identity',
    ),
    requireExactBytes(
        context.rootTerminalIdentity,
        hashByteLength,
        'Sender-mailbox root-terminal identity',
    ),
    unsigned16LittleEndian(
        context.senderPosition,
        'Sender-mailbox sender position',
    ),
    unsigned16LittleEndian(
        context.recipientPosition,
        'Sender-mailbox recipient position',
    ),
];

const encodeOpenContextRequest = (
    input: OpenProductionSeedMailboxSenderStreamKernelInput,
): Uint8Array => {
    const rootAuthorizationPackages: unknown = input.rootAuthorizationPackages;
    if (!isReadonlyArray(rootAuthorizationPackages)) {
        throw new TypeError(
            'Sender-mailbox root authorization packages must be an array.',
        );
    }
    const packageCount = requireInteger(
        rootAuthorizationPackages.length,
        unsigned16Maximum,
        'Sender-mailbox root-package count',
    );
    if (packageCount === 0) {
        throw new TypeError(
            'Sender-mailbox root authorization packages cannot be empty.',
        );
    }
    const parts: Uint8Array[] = [
        ...requestHeaderParts(openContextOperation),
        requireExactBytes(
            input.parameterIdentity,
            hashByteLength,
            'Sender-mailbox parameter identity',
        ),
        unsigned16LittleEndian(
            input.senderPosition,
            'Sender-mailbox sender position',
        ),
        ...boundedBytesParts(
            input.preparationContextBytes,
            'Sender-mailbox preparation context',
        ),
        ...boundedBytesParts(input.rosterBytes, 'Sender-mailbox roster'),
        unsigned16LittleEndian(
            packageCount,
            'Sender-mailbox root-package count',
        ),
    ];
    for (const [
        packageIndex,
        rootPackage,
    ] of rootAuthorizationPackages.entries()) {
        parts.push(
            ...boundedBytesParts(
                requireBoundedBytes(
                    snapshotDataProperty(
                        rootPackage,
                        'rootBodyBytes',
                        `Sender-mailbox root package ${packageIndex}`,
                    ),
                    `Sender-mailbox root package ${packageIndex} body`,
                ),
                `Sender-mailbox root package ${packageIndex} body`,
            ),
            ...boundedBytesParts(
                requireBoundedBytes(
                    snapshotDataProperty(
                        rootPackage,
                        'reservationCertificateBytes',
                        `Sender-mailbox root package ${packageIndex}`,
                    ),
                    `Sender-mailbox root package ${packageIndex} reservation certificate`,
                ),
                `Sender-mailbox root package ${packageIndex} reservation certificate`,
            ),
            ...boundedBytesParts(
                requireBoundedBytes(
                    snapshotDataProperty(
                        rootPackage,
                        'exactOutputCertificateBytes',
                        `Sender-mailbox root package ${packageIndex}`,
                    ),
                    `Sender-mailbox root package ${packageIndex} exact-output certificate`,
                ),
                `Sender-mailbox root package ${packageIndex} exact-output certificate`,
            ),
            ...boundedBytesParts(
                requireBoundedBytes(
                    snapshotDataProperty(
                        rootPackage,
                        'contributorSignatureEnvelopeBytes',
                        `Sender-mailbox root package ${packageIndex}`,
                    ),
                    `Sender-mailbox root package ${packageIndex} signature envelope`,
                ),
                `Sender-mailbox root package ${packageIndex} signature envelope`,
            ),
        );
    }
    parts.push(
        ...boundedBytesParts(
            input.rootTerminalCertificateBytes,
            'Sender-mailbox root-terminal certificate',
        ),
    );
    return concatenateRequestParts(parts);
};

const encodePrepareRequest = (
    contextHandle: number,
    input: SeedMailboxSenderStreamProductionInput,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(prepareCarrierOperation),
        unsigned32LittleEndian(contextHandle, 'Sender-mailbox context handle'),
        ...streamContextParts(input.context),
        ...boundedBytesParts(
            input.canonicalDeliveryDescriptorBytes,
            'Sender-mailbox delivery descriptor',
        ),
        requireExactBytes(
            input.encapsulationRandomness,
            encapsulationRandomnessByteLength,
            'Sender-mailbox encapsulation randomness',
        ),
        ...boundedBytesParts(
            input.sourcePayloadBytes,
            'Sender-mailbox source payload',
        ),
    ]);

type PreparedCarrier = Readonly<{
    encryptedChunks: readonly Uint8Array[];
    headerBytes: Uint8Array;
    manifestBytes: Uint8Array;
    signatureBodyBytes: Uint8Array;
}>;

const encryptedChunkParts = (
    encryptedChunks: readonly Uint8Array[],
): readonly Uint8Array[] => {
    const chunks: unknown = encryptedChunks;
    if (!isReadonlyArray(chunks) || chunks.length === 0) {
        throw new TypeError(
            'Sender-mailbox encrypted chunks must be a nonempty array.',
        );
    }
    const parts: Uint8Array[] = [
        unsigned16LittleEndian(
            chunks.length,
            'Sender-mailbox encrypted chunk count',
        ),
    ];
    for (const [chunkIndex, encryptedChunk] of chunks.entries()) {
        parts.push(
            ...boundedBytesParts(
                requireBoundedBytes(
                    encryptedChunk,
                    `Sender-mailbox encrypted chunk ${chunkIndex}`,
                ),
                `Sender-mailbox encrypted chunk ${chunkIndex}`,
            ),
        );
    }
    return parts;
};

const encodeCompleteRequest = (
    contextHandle: number,
    input: SeedMailboxSenderStreamProductionInput,
    prepared: PreparedCarrier,
    signature: Uint8Array,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(completeCarrierOperation),
        unsigned32LittleEndian(contextHandle, 'Sender-mailbox context handle'),
        ...streamContextParts(input.context),
        ...boundedBytesParts(
            input.canonicalDeliveryDescriptorBytes,
            'Sender-mailbox delivery descriptor',
        ),
        ...boundedBytesParts(
            prepared.headerBytes,
            'Sender-mailbox prepared header',
        ),
        ...boundedBytesParts(
            prepared.manifestBytes,
            'Sender-mailbox prepared manifest',
        ),
        ...encryptedChunkParts(prepared.encryptedChunks),
        requireExactBytes(
            signature,
            signatureByteLength,
            'Sender-mailbox signature',
        ),
    ]);

const geometryParts = (
    geometry: SeedMailboxSenderStreamGeometry,
): readonly Uint8Array[] => {
    const encryptedChunkByteLengths: unknown =
        geometry.encryptedChunkByteLengths;
    if (
        !isReadonlyArray(encryptedChunkByteLengths) ||
        encryptedChunkByteLengths.length === 0
    ) {
        throw new TypeError(
            'Sender-mailbox chunk geometry must be a nonempty array.',
        );
    }
    return [
        unsigned32LittleEndian(
            geometry.sourcePayloadByteLength,
            'Sender-mailbox source-payload byte length',
        ),
        unsigned32LittleEndian(
            geometry.totalCarrierByteLength,
            'Sender-mailbox total-carrier byte length',
        ),
        unsigned32LittleEndian(
            geometry.headerByteLength,
            'Sender-mailbox header byte length',
        ),
        unsigned32LittleEndian(
            geometry.manifestByteLength,
            'Sender-mailbox manifest byte length',
        ),
        unsigned32LittleEndian(
            geometry.signatureEnvelopeByteLength,
            'Sender-mailbox signature-envelope byte length',
        ),
        unsigned16LittleEndian(
            encryptedChunkByteLengths.length,
            'Sender-mailbox geometry chunk count',
        ),
        ...encryptedChunkByteLengths.map((byteLength, chunkIndex) =>
            unsigned32LittleEndian(
                requireInteger(
                    byteLength,
                    unsigned32Maximum,
                    `Sender-mailbox encrypted chunk ${chunkIndex} byte length`,
                ),
                `Sender-mailbox encrypted chunk ${chunkIndex} byte length`,
            ),
        ),
    ];
};

const carrierParts = (
    carrier: SeedMailboxSenderStreamCarrier,
): readonly Uint8Array[] => [
    ...boundedBytesParts(carrier.headerBytes, 'Sender-mailbox header'),
    ...boundedBytesParts(carrier.manifestBytes, 'Sender-mailbox manifest'),
    ...boundedBytesParts(
        carrier.signatureEnvelopeBytes,
        'Sender-mailbox signature envelope',
    ),
    ...encryptedChunkParts(carrier.encryptedChunks),
];

const encodeValidationRequest = (
    contextHandle: number,
    input: SeedMailboxSenderStreamValidationInput,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(validateCarrierOperation),
        unsigned32LittleEndian(contextHandle, 'Sender-mailbox context handle'),
        ...streamContextParts(input.context),
        ...boundedBytesParts(
            input.canonicalDeliveryDescriptorBytes,
            'Sender-mailbox delivery descriptor',
        ),
        ...geometryParts(input.geometry),
        ...carrierParts(input.carrier),
    ]);

const encodeCloseRequest = (contextHandle: number): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(closeContextOperation),
        unsigned32LittleEndian(contextHandle, 'Sender-mailbox context handle'),
    ]);

class ResponseCursor {
    readonly #bytes: Uint8Array;
    #offset: number;

    public constructor(bytes: Uint8Array, expectedStatus: number) {
        if (bytes.byteLength < responseHeaderByteLength) {
            throw malformedResponse('a truncated response header');
        }
        for (
            let magicByteIndex = 0;
            magicByteIndex < responseMagic.byteLength;
            magicByteIndex += 1
        ) {
            if (bytes[magicByteIndex] !== responseMagic[magicByteIndex]) {
                throw malformedResponse('the wrong response magic');
            }
        }
        const view = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        );
        if (view.getUint16(responseMagic.byteLength, true) !== codecVersion) {
            throw malformedResponse('an unsupported response version');
        }
        const status = bytes[responseHeaderByteLength - 1];
        if (status === failureStatus) {
            if (bytes.byteLength !== failureResponseByteLength) {
                throw malformedResponse('a malformed failure response');
            }
            const responseCode = view.getUint16(responseHeaderByteLength, true);
            const code = responseCodeByNumber.get(responseCode);
            if (code === undefined) {
                throw malformedResponse('an unknown failure code');
            }
            throw new SeedMailboxSenderKernelError(
                code,
                `The seed-mailbox sender kernel refused the request with ${code}.`,
            );
        }
        if (status !== expectedStatus) {
            throw malformedResponse('an unexpected response status');
        }
        this.#bytes = bytes;
        this.#offset = responseHeaderByteLength;
    }

    public readUnsigned16(label: string): number {
        const bytes = this.readExact(2, label);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    public readUnsigned32(label: string): number {
        const bytes = this.readExact(4, label);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(0, true);
    }

    public readExact(byteLength: number, label: string): Uint8Array {
        const end = this.#offset + byteLength;
        if (
            !Number.isSafeInteger(end) ||
            byteLength < 0 ||
            end > this.#bytes.byteLength
        ) {
            throw malformedResponse(`a truncated ${label}`);
        }
        const value = this.#bytes.slice(this.#offset, end);
        this.#offset = end;
        return value;
    }

    public readBounded(label: string): Uint8Array {
        const byteLength = this.readUnsigned32(`${label} byte length`);
        if (
            byteLength === 0 ||
            byteLength > foundationProfile.maximumCopiedBufferByteLength
        ) {
            throw malformedResponse(`an invalid ${label} byte length`);
        }
        return this.readExact(byteLength, label);
    }

    public readEncryptedChunks(): readonly Uint8Array[] {
        const chunkCount = this.readUnsigned16('encrypted chunk count');
        if (chunkCount === 0) {
            throw malformedResponse('an empty encrypted-chunk inventory');
        }
        return Object.freeze(
            Array.from({ length: chunkCount }, (_unused, chunkIndex) =>
                this.readBounded(`encrypted chunk ${chunkIndex}`),
            ),
        );
    }

    public requireComplete(): void {
        if (this.#offset !== this.#bytes.byteLength) {
            throw malformedResponse('trailing response bytes');
        }
    }
}

const parseOpenResponse = (
    responseBytes: Uint8Array,
): Readonly<{
    contextHandle: number;
    senderSigningVerificationKey: Uint8Array;
}> => {
    if (responseBytes.byteLength !== openResponseByteLength) {
        const failureCursor = new ResponseCursor(
            responseBytes,
            openContextStatus,
        );
        failureCursor.requireComplete();
        throw malformedResponse('a malformed open-context response length');
    }
    const cursor = new ResponseCursor(responseBytes, openContextStatus);
    const contextHandle = cursor.readUnsigned32('context handle');
    if (contextHandle === 0) {
        throw malformedResponse('a zero context handle');
    }
    const senderSigningVerificationKey = cursor.readExact(
        signingVerificationKeyByteLength,
        'sender signing verification key',
    );
    cursor.requireComplete();
    return Object.freeze({
        contextHandle,
        senderSigningVerificationKey,
    });
};

const parsePreparedResponse = (responseBytes: Uint8Array): PreparedCarrier => {
    const cursor = new ResponseCursor(responseBytes, preparedCarrierStatus);
    const headerBytes = cursor.readBounded('prepared header');
    const manifestBytes = cursor.readBounded('prepared manifest');
    const signatureBodyBytes = cursor.readBounded('signature body');
    if (signatureBodyBytes.byteLength !== signatureBodyByteLength) {
        headerBytes.fill(0);
        manifestBytes.fill(0);
        signatureBodyBytes.fill(0);
        throw malformedResponse('the wrong signature-body byte length');
    }
    const encryptedChunks = cursor.readEncryptedChunks();
    try {
        cursor.requireComplete();
        return Object.freeze({
            encryptedChunks,
            headerBytes,
            manifestBytes,
            signatureBodyBytes,
        });
    } catch (error) {
        headerBytes.fill(0);
        manifestBytes.fill(0);
        signatureBodyBytes.fill(0);
        encryptedChunks.forEach((chunk) => chunk.fill(0));
        throw error;
    }
};

const parseCarrierResponse = (
    responseBytes: Uint8Array,
): SeedMailboxSenderStreamCarrier => {
    const cursor = new ResponseCursor(responseBytes, completeCarrierStatus);
    const headerBytes = cursor.readBounded('header');
    const manifestBytes = cursor.readBounded('manifest');
    const signatureEnvelopeBytes = cursor.readBounded('signature envelope');
    const encryptedChunks = cursor.readEncryptedChunks();
    try {
        cursor.requireComplete();
        return Object.freeze({
            encryptedChunks,
            headerBytes,
            manifestBytes,
            signatureEnvelopeBytes,
        });
    } catch (error) {
        headerBytes.fill(0);
        manifestBytes.fill(0);
        signatureEnvelopeBytes.fill(0);
        encryptedChunks.forEach((chunk) => chunk.fill(0));
        throw error;
    }
};

const parseEmptyResponse = (
    responseBytes: Uint8Array,
    expectedStatus: number,
): void => {
    const cursor = new ResponseCursor(responseBytes, expectedStatus);
    cursor.requireComplete();
};

const executeRequest = <Result>(input: {
    parse(responseBytes: Uint8Array): Result;
    requestBytes: Uint8Array;
    runtime: TranscriptCoreKernelCommandRuntime;
}): Result => {
    let responseBytes: Uint8Array | undefined;
    try {
        responseBytes = input.runtime.executeSeedMailboxSender(
            input.requestBytes,
        );
        return input.parse(responseBytes);
    } finally {
        input.requestBytes.fill(0);
        responseBytes?.fill(0);
    }
};

const destroyPreparedCarrier = (prepared: PreparedCarrier): void => {
    prepared.headerBytes.fill(0);
    prepared.manifestBytes.fill(0);
    prepared.signatureBodyBytes.fill(0);
    prepared.encryptedChunks.forEach((chunk) => chunk.fill(0));
};

const closeContext = (
    runtime: TranscriptCoreKernelCommandRuntime,
    contextHandle: number,
): void =>
    executeRequest({
        parse: (responseBytes) =>
            parseEmptyResponse(responseBytes, closedContextStatus),
        requestBytes: encodeCloseRequest(contextHandle),
        runtime,
    });

export const isProductionSeedMailboxSenderStreamKernel = (
    value: unknown,
): value is ProductionSeedMailboxSenderStreamKernel =>
    typeof value === 'object' && value !== null && productionKernels.has(value);

/**
 * Positively verifies one exact public root context before retaining an opaque
 * handle inside the integrity-pinned scalar WebAssembly instance.
 */
export const openProductionSeedMailboxSenderStreamKernel = async (
    transcriptCoreKernelUrl: URL,
    input: OpenProductionSeedMailboxSenderStreamKernelInput,
): Promise<ProductionSeedMailboxSenderStreamKernel> => {
    if (packagedKernelSha256Hex === undefined) {
        throw new Error(
            'The seed-mailbox sender kernel requires the package build integrity identity.',
        );
    }
    const signingOperations = snapshotSigningOperations(
        input.signingOperations,
    );
    const openContextRequestBytes = encodeOpenContextRequest(input);
    let runtime: TranscriptCoreKernelCommandRuntime;
    try {
        runtime = await instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            { expectedKernelSha256Hex: packagedKernelSha256Hex },
        );
    } catch (error) {
        openContextRequestBytes.fill(0);
        throw error;
    }
    const opened = executeRequest({
        parse: parseOpenResponse,
        requestBytes: openContextRequestBytes,
        runtime,
    });
    let contextIsOpen = true;
    try {
        signingOperations.assertMatchesSenderVerificationKey({
            senderSigningVerificationKey: opened.senderSigningVerificationKey,
        });
    } catch (error) {
        try {
            closeContext(runtime, opened.contextHandle);
            contextIsOpen = false;
        } catch (closeError) {
            throw new SeedMailboxSenderKernelError(
                'ContextUnavailable',
                'The seed-mailbox sender key mismatch also failed context cleanup.',
                [error, closeError],
            );
        } finally {
            opened.senderSigningVerificationKey.fill(0);
        }
        throw error;
    }

    const requireOpen = (): void => {
        if (!contextIsOpen) {
            throw new SeedMailboxSenderKernelError(
                'ContextUnavailable',
                'The seed-mailbox sender kernel context is closed.',
            );
        }
    };
    const kernel = Object.freeze({
        [seedMailboxSenderStreamKernelBrand]: true as const,
        close: (): void => {
            if (!contextIsOpen) {
                return;
            }
            try {
                closeContext(runtime, opened.contextHandle);
            } finally {
                contextIsOpen = false;
                opened.senderSigningVerificationKey.fill(0);
            }
        },
        produce: (
            productionInput: SeedMailboxSenderStreamProductionInput,
        ): SeedMailboxSenderStreamCarrier => {
            requireOpen();
            const prepared = executeRequest({
                parse: parsePreparedResponse,
                requestBytes: encodePrepareRequest(
                    opened.contextHandle,
                    productionInput,
                ),
                runtime,
            });
            let signature: Uint8Array | undefined;
            try {
                signature = signingOperations.signManifestBody({
                    signatureBodyBytes: prepared.signatureBodyBytes,
                    signatureRandomness: requireExactBytes(
                        productionInput.signatureRandomness,
                        signatureRandomnessByteLength,
                        'Sender-mailbox signature randomness',
                    ),
                    senderSigningVerificationKey:
                        opened.senderSigningVerificationKey,
                });
                return executeRequest({
                    parse: parseCarrierResponse,
                    requestBytes: encodeCompleteRequest(
                        opened.contextHandle,
                        productionInput,
                        prepared,
                        signature,
                    ),
                    runtime,
                });
            } finally {
                signature?.fill(0);
                destroyPreparedCarrier(prepared);
            }
        },
        validate: (
            validationInput: SeedMailboxSenderStreamValidationInput,
        ): void => {
            requireOpen();
            executeRequest({
                parse: (responseBytes) =>
                    parseEmptyResponse(responseBytes, validationStatus),
                requestBytes: encodeValidationRequest(
                    opened.contextHandle,
                    validationInput,
                ),
                runtime,
            });
        },
    });
    productionKernels.add(kernel);
    return kernel;
};
