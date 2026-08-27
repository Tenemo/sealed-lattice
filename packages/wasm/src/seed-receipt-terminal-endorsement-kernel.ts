import { foundationProfile } from '@sealed-lattice/types';

import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';

const requestMagic = Uint8Array.of(0x53, 0x4c, 0x54, 0x51);
const responseMagic = Uint8Array.of(0x53, 0x4c, 0x54, 0x50);
const codecVersion = 1;
const openContextOperation = 1;
const prepareEndorsementOperation = 2;
const completeEndorsementOperation = 3;
const validateEndorsementOperation = 4;
const closeContextOperation = 5;
const failureStatus = 0;
const openContextStatus = 1;
const preparedEndorsementStatus = 2;
const completeEndorsementStatus = 3;
const validationStatus = 4;
const closedContextStatus = 5;
const hashByteLength = 64;
const signingVerificationKeyByteLength = 1_952;
const signatureByteLength = 3_309;
const endorsementAuthorizationBodyByteLength = 174;
const endorsementEnvelopeByteLength = 3_599;
const responseHeaderByteLength = responseMagic.byteLength + 2 + 1;
const failureResponseByteLength = responseHeaderByteLength + 2;
const openResponseByteLength =
    responseHeaderByteLength + 4 + signingVerificationKeyByteLength;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const seedReceiptTerminalEndorsementKernelBrand: unique symbol = Symbol(
    'seed-receipt-terminal-endorsement-kernel',
);

declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

export type SeedReceiptTerminalEndorsementContext = Readonly<{
    parameterIdentity: Uint8Array;
    participantCount: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    endorserPosition: number;
    rootTerminalIdentity: Uint8Array;
}>;

export type PreparedSeedReceiptTerminalEndorsementInventory = Readonly<{
    endorsementAuthorizationBodyBytes: Uint8Array;
    verifiedReceiptInventoryBodyBytes: Uint8Array;
    verifiedReceiptInventoryIdentity: Uint8Array;
    orderedReceiptEnvelopeBytes: readonly Uint8Array[];
    retainedLocalReceiptBodyIdentity: Uint8Array;
    retainedLocalReceiptEnvelopeIdentity: Uint8Array;
    terminalBodyBytes: Uint8Array;
    terminalBodyIdentity: Uint8Array;
}>;

export type SeedReceiptTerminalEndorsementProductionInput = Readonly<{
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory;
    signatureRandomness: Uint8Array;
}>;

export type SeedReceiptTerminalEndorsementValidationInput = Readonly<{
    context: SeedReceiptTerminalEndorsementContext;
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory;
    endorsementEnvelopeBytes?: Uint8Array;
}>;

export type SeedReceiptTerminalEndorsementRootAuthorizationPackageBytes =
    Readonly<{
        contributorSignatureEnvelopeBytes: Uint8Array;
        exactOutputCertificateBytes: Uint8Array;
        reservationCertificateBytes: Uint8Array;
        rootBodyBytes: Uint8Array;
    }>;

export type SeedRecipientReceiptCustodyContext = Readonly<{
    parameterIdentity: Uint8Array;
    preparationContextIdentity: Uint8Array;
    rootTerminalIdentity: Uint8Array;
    preparationAttemptOrdinal: number;
    participantCount: number;
    recipientPosition: number;
}>;

export type SeedReceiptTerminalEndorsementSigningOperations = Readonly<{
    assertMatchesEndorserVerificationKey(input: {
        readonly endorserSigningVerificationKey: Uint8Array;
    }): void;
    signEndorsementBody(input: {
        readonly endorsementAuthorizationBodyBytes: Uint8Array;
        readonly endorserSigningVerificationKey: Uint8Array;
        readonly signatureRandomness: Uint8Array;
    }): Uint8Array;
}>;

type SnapshottedSeedReceiptTerminalEndorsementSigningOperations = Readonly<{
    assertMatchesEndorserVerificationKey(input: {
        readonly endorserSigningVerificationKey: Uint8Array;
    }): void;
    signEndorsementBody(input: {
        readonly endorsementAuthorizationBodyBytes: Uint8Array;
        readonly endorserSigningVerificationKey: Uint8Array;
        readonly signatureRandomness: Uint8Array;
    }): Uint8Array;
}>;

export type OpenProductionSeedReceiptTerminalEndorsementKernelInput = Readonly<{
    endorserPosition: number;
    parameterIdentity: Uint8Array;
    preparationContextBytes: Uint8Array;
    receiptCustodyContext: SeedRecipientReceiptCustodyContext;
    receiptCustodyRecordBytes: Uint8Array;
    receiptEnvelopeBytes: readonly Uint8Array[];
    rootAuthorizationPackages: readonly SeedReceiptTerminalEndorsementRootAuthorizationPackageBytes[];
    rootTerminalCertificateBytes: Uint8Array;
    rosterBytes: Uint8Array;
    signingOperations: SeedReceiptTerminalEndorsementSigningOperations;
}>;

export type SeedReceiptTerminalEndorsementKernelErrorCode =
    | 'ContextMismatch'
    | 'ContextUnavailable'
    | 'MalformedKernelResponse'
    | 'MalformedRequest'
    | 'PreparedMismatch'
    | 'PublicVerification'
    | 'ReceiptCustody'
    | 'ResourceLimit'
    | 'SignatureMismatch';

export class SeedReceiptTerminalEndorsementKernelError extends Error {
    public readonly code: SeedReceiptTerminalEndorsementKernelErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: SeedReceiptTerminalEndorsementKernelErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'SeedReceiptTerminalEndorsementKernelError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

/**
 * Integrity-pinned scalar Rust/WebAssembly receipt-terminal endorsement
 * boundary. Its opaque context exists only after the completed authenticated
 * local receipt and exact public receipt inventory pass positive verification.
 */
export type ProductionSeedReceiptTerminalEndorsementKernel = Readonly<{
    readonly [seedReceiptTerminalEndorsementKernelBrand]: true;
    close(): void;
    prepare(): PreparedSeedReceiptTerminalEndorsementInventory;
    produce(input: SeedReceiptTerminalEndorsementProductionInput): Uint8Array;
    validate(input: SeedReceiptTerminalEndorsementValidationInput): void;
}>;

const productionKernels = new WeakSet<object>();

const responseCodeByNumber = new Map<
    number,
    Exclude<
        SeedReceiptTerminalEndorsementKernelErrorCode,
        'MalformedKernelResponse'
    >
>([
    [1, 'MalformedRequest'],
    [2, 'ResourceLimit'],
    [3, 'ContextMismatch'],
    [4, 'PublicVerification'],
    [5, 'ReceiptCustody'],
    [6, 'PreparedMismatch'],
    [7, 'ContextUnavailable'],
    [8, 'SignatureMismatch'],
]);

const malformedResponse = (
    detail: string,
): SeedReceiptTerminalEndorsementKernelError =>
    new SeedReceiptTerminalEndorsementKernelError(
        'MalformedKernelResponse',
        `The seed-receipt terminal endorsement kernel returned ${detail}.`,
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
        throw new TypeError(`${label} must be an admitted unsigned integer.`);
    }
    return value;
};

const requireExactBytes = (
    value: unknown,
    byteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== byteLength) {
        throw new TypeError(
            `${label} must contain exactly ${byteLength} bytes.`,
        );
    }
    return value;
};

const requireBoundedBytes = (value: unknown, label: string): Uint8Array => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new TypeError(
            `${label} must be a nonempty byte array within the absolute copied-buffer bound.`,
        );
    }
    return value;
};

const unsigned16LittleEndian = (value: unknown, label: string): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(
        0,
        requireInteger(value, unsigned16Maximum, label),
        true,
    );
    return bytes;
};

const unsigned32LittleEndian = (value: unknown, label: string): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(
        0,
        requireInteger(value, unsigned32Maximum, label),
        true,
    );
    return bytes;
};

const boundedBytesParts = (
    value: unknown,
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
        if (
            part.byteLength >
            foundationProfile.maximumCopiedBufferByteLength - byteLength
        ) {
            throw new SeedReceiptTerminalEndorsementKernelError(
                'ResourceLimit',
                'The seed-receipt terminal endorsement request exceeds the absolute copied-buffer bound.',
            );
        }
        byteLength += part.byteLength;
    }
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    return output;
};

const requestHeaderParts = (operation: number): readonly Uint8Array[] => [
    requestMagic,
    unsigned16LittleEndian(codecVersion, 'Endorsement kernel codec version'),
    Uint8Array.of(operation),
];

const snapshotSigningOperations = (
    value: unknown,
): SnapshottedSeedReceiptTerminalEndorsementSigningOperations => {
    const assertMatchesEndorserVerificationKey = snapshotDataProperty(
        value,
        'assertMatchesEndorserVerificationKey',
        'Receipt-terminal endorsement signing operations',
    );
    const signEndorsementBody = snapshotDataProperty(
        value,
        'signEndorsementBody',
        'Receipt-terminal endorsement signing operations',
    );
    if (
        typeof assertMatchesEndorserVerificationKey !== 'function' ||
        typeof signEndorsementBody !== 'function'
    ) {
        throw new TypeError(
            'Receipt-terminal endorsement signing operations must provide fixed-purpose functions.',
        );
    }
    const typedAssertMatchesEndorserVerificationKey =
        assertMatchesEndorserVerificationKey as SnapshottedSeedReceiptTerminalEndorsementSigningOperations['assertMatchesEndorserVerificationKey'];
    const typedSignEndorsementBody =
        signEndorsementBody as SnapshottedSeedReceiptTerminalEndorsementSigningOperations['signEndorsementBody'];
    return Object.freeze({
        assertMatchesEndorserVerificationKey:
            typedAssertMatchesEndorserVerificationKey,
        signEndorsementBody: (input) =>
            requireExactBytes(
                typedSignEndorsementBody(input),
                signatureByteLength,
                'Receipt-terminal endorsement signature',
            ).slice(),
    });
};

const receiptCustodyContextParts = (
    context: SeedRecipientReceiptCustodyContext,
): readonly Uint8Array[] => [
    requireExactBytes(
        context.parameterIdentity,
        hashByteLength,
        'Receipt-custody parameter identity',
    ),
    requireExactBytes(
        context.preparationContextIdentity,
        hashByteLength,
        'Receipt-custody preparation-context identity',
    ),
    requireExactBytes(
        context.rootTerminalIdentity,
        hashByteLength,
        'Receipt-custody root-terminal identity',
    ),
    unsigned16LittleEndian(
        context.preparationAttemptOrdinal,
        'Receipt-custody preparation-attempt ordinal',
    ),
    unsigned16LittleEndian(
        context.participantCount,
        'Receipt-custody participant count',
    ),
    unsigned16LittleEndian(
        context.recipientPosition,
        'Receipt-custody recipient position',
    ),
];

const encodeOpenContextRequest = (
    input: OpenProductionSeedReceiptTerminalEndorsementKernelInput,
): Uint8Array => {
    const rootAuthorizationPackages: unknown = input.rootAuthorizationPackages;
    const receiptEnvelopeBytes: unknown = input.receiptEnvelopeBytes;
    if (!isReadonlyArray(rootAuthorizationPackages)) {
        throw new TypeError(
            'Receipt-terminal endorsement root authorization packages must be an array.',
        );
    }
    if (!isReadonlyArray(receiptEnvelopeBytes)) {
        throw new TypeError(
            'Receipt-terminal endorsement receipt envelopes must be an array.',
        );
    }
    const rootPackageCount = requireInteger(
        rootAuthorizationPackages.length,
        unsigned16Maximum,
        'Receipt-terminal endorsement root-package count',
    );
    const receiptCount = requireInteger(
        receiptEnvelopeBytes.length,
        unsigned16Maximum,
        'Receipt-terminal endorsement receipt count',
    );
    if (rootPackageCount === 0 || receiptCount === 0) {
        throw new TypeError(
            'Receipt-terminal endorsement public inventories cannot be empty.',
        );
    }
    const parts: Uint8Array[] = [
        ...requestHeaderParts(openContextOperation),
        requireExactBytes(
            input.parameterIdentity,
            hashByteLength,
            'Receipt-terminal endorsement parameter identity',
        ),
        unsigned16LittleEndian(
            input.endorserPosition,
            'Receipt-terminal endorsement endorser position',
        ),
        ...boundedBytesParts(
            input.preparationContextBytes,
            'Receipt-terminal endorsement preparation context',
        ),
        ...boundedBytesParts(
            input.rosterBytes,
            'Receipt-terminal endorsement roster',
        ),
        unsigned16LittleEndian(
            rootPackageCount,
            'Receipt-terminal endorsement root-package count',
        ),
    ];
    for (const [
        packageIndex,
        rootPackage,
    ] of rootAuthorizationPackages.entries()) {
        for (const [propertyName, label] of [
            ['rootBodyBytes', 'body'],
            ['reservationCertificateBytes', 'reservation certificate'],
            ['exactOutputCertificateBytes', 'exact-output certificate'],
            ['contributorSignatureEnvelopeBytes', 'signature envelope'],
        ] as const) {
            parts.push(
                ...boundedBytesParts(
                    snapshotDataProperty(
                        rootPackage,
                        propertyName,
                        `Receipt-terminal endorsement root package ${packageIndex}`,
                    ),
                    `Receipt-terminal endorsement root package ${packageIndex} ${label}`,
                ),
            );
        }
    }
    parts.push(
        ...boundedBytesParts(
            input.rootTerminalCertificateBytes,
            'Receipt-terminal endorsement root-terminal certificate',
        ),
        unsigned16LittleEndian(
            receiptCount,
            'Receipt-terminal endorsement receipt count',
        ),
    );
    for (const [
        receiptIndex,
        envelopeBytes,
    ] of receiptEnvelopeBytes.entries()) {
        parts.push(
            ...boundedBytesParts(
                envelopeBytes,
                `Receipt-terminal endorsement receipt envelope ${receiptIndex}`,
            ),
        );
    }
    parts.push(
        ...receiptCustodyContextParts(input.receiptCustodyContext),
        ...boundedBytesParts(
            input.receiptCustodyRecordBytes,
            'Receipt-terminal endorsement completed receipt-custody record',
        ),
    );
    return concatenateRequestParts(parts);
};

const contextParts = (
    context: SeedReceiptTerminalEndorsementContext,
): readonly Uint8Array[] => [
    requireExactBytes(
        context.parameterIdentity,
        hashByteLength,
        'Receipt-terminal endorsement parameter identity',
    ),
    unsigned16LittleEndian(
        context.participantCount,
        'Receipt-terminal endorsement participant count',
    ),
    unsigned16LittleEndian(
        context.preparationAttemptOrdinal,
        'Receipt-terminal endorsement preparation-attempt ordinal',
    ),
    requireExactBytes(
        context.preparationContextIdentity,
        hashByteLength,
        'Receipt-terminal endorsement preparation-context identity',
    ),
    unsigned16LittleEndian(
        context.endorserPosition,
        'Receipt-terminal endorsement endorser position',
    ),
    requireExactBytes(
        context.rootTerminalIdentity,
        hashByteLength,
        'Receipt-terminal endorsement root-terminal identity',
    ),
];

const preparedInventoryParts = (
    prepared: PreparedSeedReceiptTerminalEndorsementInventory,
): readonly Uint8Array[] => {
    const orderedReceiptEnvelopeBytes: unknown =
        prepared.orderedReceiptEnvelopeBytes;
    if (
        !isReadonlyArray(orderedReceiptEnvelopeBytes) ||
        orderedReceiptEnvelopeBytes.length === 0
    ) {
        throw new TypeError(
            'Receipt-terminal endorsement ordered receipt envelopes must be a nonempty array.',
        );
    }
    const parts: Uint8Array[] = [
        ...boundedBytesParts(
            requireExactBytes(
                prepared.endorsementAuthorizationBodyBytes,
                endorsementAuthorizationBodyByteLength,
                'Receipt-terminal endorsement authorization body',
            ),
            'Receipt-terminal endorsement authorization body',
        ),
        ...boundedBytesParts(
            prepared.verifiedReceiptInventoryBodyBytes,
            'Receipt-terminal endorsement verified receipt-inventory body',
        ),
        requireExactBytes(
            prepared.verifiedReceiptInventoryIdentity,
            hashByteLength,
            'Receipt-terminal endorsement verified receipt-inventory identity',
        ),
        unsigned16LittleEndian(
            orderedReceiptEnvelopeBytes.length,
            'Receipt-terminal endorsement ordered receipt count',
        ),
    ];
    for (const [
        receiptIndex,
        envelopeBytes,
    ] of orderedReceiptEnvelopeBytes.entries()) {
        parts.push(
            ...boundedBytesParts(
                envelopeBytes,
                `Receipt-terminal endorsement ordered receipt envelope ${receiptIndex}`,
            ),
        );
    }
    parts.push(
        requireExactBytes(
            prepared.retainedLocalReceiptBodyIdentity,
            hashByteLength,
            'Receipt-terminal endorsement retained local receipt-body identity',
        ),
        requireExactBytes(
            prepared.retainedLocalReceiptEnvelopeIdentity,
            hashByteLength,
            'Receipt-terminal endorsement retained local receipt-envelope identity',
        ),
        ...boundedBytesParts(
            prepared.terminalBodyBytes,
            'Receipt-terminal endorsement terminal body',
        ),
        requireExactBytes(
            prepared.terminalBodyIdentity,
            hashByteLength,
            'Receipt-terminal endorsement terminal identity',
        ),
    );
    return parts;
};

const encodeHandleRequest = (
    operation: number,
    contextHandle: number,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(operation),
        unsigned32LittleEndian(
            contextHandle,
            'Receipt-terminal endorsement context handle',
        ),
    ]);

const encodeCompleteRequest = (
    contextHandle: number,
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory,
    signature: Uint8Array,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(completeEndorsementOperation),
        unsigned32LittleEndian(
            contextHandle,
            'Receipt-terminal endorsement context handle',
        ),
        ...preparedInventoryParts(preparedInventory),
        requireExactBytes(
            signature,
            signatureByteLength,
            'Receipt-terminal endorsement signature',
        ),
    ]);

const encodeValidationRequest = (
    contextHandle: number,
    input: SeedReceiptTerminalEndorsementValidationInput,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(validateEndorsementOperation),
        unsigned32LittleEndian(
            contextHandle,
            'Receipt-terminal endorsement context handle',
        ),
        ...contextParts(input.context),
        ...preparedInventoryParts(input.preparedInventory),
        Uint8Array.of(input.endorsementEnvelopeBytes === undefined ? 0 : 1),
        ...(input.endorsementEnvelopeBytes === undefined
            ? []
            : boundedBytesParts(
                  requireExactBytes(
                      input.endorsementEnvelopeBytes,
                      endorsementEnvelopeByteLength,
                      'Receipt-terminal endorsement envelope',
                  ),
                  'Receipt-terminal endorsement envelope',
              )),
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
            const code = responseCodeByNumber.get(
                view.getUint16(responseHeaderByteLength, true),
            );
            if (code === undefined) {
                throw malformedResponse('an unknown failure code');
            }
            throw new SeedReceiptTerminalEndorsementKernelError(
                code,
                `The seed-receipt terminal endorsement kernel refused the request with ${code}.`,
            );
        }
        if (status !== expectedStatus) {
            throw malformedResponse('an unexpected success status');
        }
        this.#bytes = bytes;
        this.#offset = responseHeaderByteLength;
    }

    public readExact(byteLength: number, label: string): Uint8Array {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > this.#bytes.byteLength - this.#offset
        ) {
            throw malformedResponse(`a truncated ${label}`);
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;
        return value;
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
    endorserSigningVerificationKey: Uint8Array;
}> => {
    if (responseBytes.byteLength !== openResponseByteLength) {
        if (responseBytes[responseHeaderByteLength - 1] !== failureStatus) {
            throw malformedResponse('an invalid open-response byte length');
        }
    }
    const cursor = new ResponseCursor(responseBytes, openContextStatus);
    const contextHandle = cursor.readUnsigned32('context handle');
    if (contextHandle === 0) {
        throw malformedResponse('a zero context handle');
    }
    const endorserSigningVerificationKey = cursor.readExact(
        signingVerificationKeyByteLength,
        'endorser signing verification key',
    );
    cursor.requireComplete();
    return Object.freeze({
        contextHandle,
        endorserSigningVerificationKey,
    });
};

const parsePreparedResponse = (
    responseBytes: Uint8Array,
    expectedReceiptCount: number,
): PreparedSeedReceiptTerminalEndorsementInventory => {
    const cursor = new ResponseCursor(responseBytes, preparedEndorsementStatus);
    const endorsementAuthorizationBodyBytes = cursor.readBounded(
        'endorsement authorization body',
    );
    if (
        endorsementAuthorizationBodyBytes.byteLength !==
        endorsementAuthorizationBodyByteLength
    ) {
        throw malformedResponse(
            'an invalid endorsement authorization-body byte length',
        );
    }
    const verifiedReceiptInventoryBodyBytes = cursor.readBounded(
        'verified receipt-inventory body',
    );
    const verifiedReceiptInventoryIdentity = cursor.readExact(
        hashByteLength,
        'verified receipt-inventory identity',
    );
    const receiptCount = cursor.readUnsigned16('ordered receipt count');
    if (receiptCount !== expectedReceiptCount) {
        throw malformedResponse('an unexpected ordered receipt count');
    }
    const orderedReceiptEnvelopeBytes = Array.from(
        { length: receiptCount },
        (_unused, receiptIndex) =>
            cursor.readBounded(`ordered receipt envelope ${receiptIndex}`),
    );
    const retainedLocalReceiptBodyIdentity = cursor.readExact(
        hashByteLength,
        'retained local receipt-body identity',
    );
    const retainedLocalReceiptEnvelopeIdentity = cursor.readExact(
        hashByteLength,
        'retained local receipt-envelope identity',
    );
    const terminalBodyBytes = cursor.readBounded('terminal body');
    const terminalBodyIdentity = cursor.readExact(
        hashByteLength,
        'terminal identity',
    );
    cursor.requireComplete();
    return Object.freeze({
        endorsementAuthorizationBodyBytes,
        verifiedReceiptInventoryBodyBytes,
        verifiedReceiptInventoryIdentity,
        orderedReceiptEnvelopeBytes: Object.freeze(orderedReceiptEnvelopeBytes),
        retainedLocalReceiptBodyIdentity,
        retainedLocalReceiptEnvelopeIdentity,
        terminalBodyBytes,
        terminalBodyIdentity,
    });
};

const parseCompleteResponse = (responseBytes: Uint8Array): Uint8Array => {
    const cursor = new ResponseCursor(responseBytes, completeEndorsementStatus);
    const endorsementEnvelopeBytes = cursor.readBounded('endorsement envelope');
    if (endorsementEnvelopeBytes.byteLength !== endorsementEnvelopeByteLength) {
        throw malformedResponse('an invalid endorsement-envelope byte length');
    }
    cursor.requireComplete();
    return endorsementEnvelopeBytes;
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
        responseBytes = input.runtime.executeSeedReceiptTerminalEndorsement(
            input.requestBytes,
        );
        return input.parse(responseBytes);
    } finally {
        input.requestBytes.fill(0);
        responseBytes?.fill(0);
    }
};

const closeContext = (
    runtime: TranscriptCoreKernelCommandRuntime,
    contextHandle: number,
): void =>
    executeRequest({
        parse: (responseBytes) =>
            parseEmptyResponse(responseBytes, closedContextStatus),
        requestBytes: encodeHandleRequest(closeContextOperation, contextHandle),
        runtime,
    });

export const isProductionSeedReceiptTerminalEndorsementKernel = (
    value: unknown,
): value is ProductionSeedReceiptTerminalEndorsementKernel =>
    typeof value === 'object' && value !== null && productionKernels.has(value);

/**
 * Positively verifies the exact public root and receipt inventories plus the
 * completed authenticated local receipt before retaining an opaque scalar
 * WebAssembly context.
 */
export const openProductionSeedReceiptTerminalEndorsementKernel = async (
    transcriptCoreKernelUrl: URL,
    input: OpenProductionSeedReceiptTerminalEndorsementKernelInput,
): Promise<ProductionSeedReceiptTerminalEndorsementKernel> => {
    if (packagedKernelSha256Hex === undefined) {
        throw new Error(
            'The seed-receipt terminal endorsement kernel requires the package build integrity identity.',
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
        signingOperations.assertMatchesEndorserVerificationKey({
            endorserSigningVerificationKey:
                opened.endorserSigningVerificationKey,
        });
    } catch (error) {
        try {
            closeContext(runtime, opened.contextHandle);
            contextIsOpen = false;
        } catch (closeError) {
            throw new SeedReceiptTerminalEndorsementKernelError(
                'ContextUnavailable',
                'The receipt-terminal endorsement key mismatch also failed context cleanup.',
                [error, closeError],
            );
        } finally {
            opened.endorserSigningVerificationKey.fill(0);
        }
        throw error;
    }

    const requireOpen = (): void => {
        if (!contextIsOpen) {
            throw new SeedReceiptTerminalEndorsementKernelError(
                'ContextUnavailable',
                'The seed-receipt terminal endorsement kernel context is closed.',
            );
        }
    };
    const kernel = Object.freeze({
        [seedReceiptTerminalEndorsementKernelBrand]: true as const,
        close: (): void => {
            if (!contextIsOpen) {
                return;
            }
            try {
                closeContext(runtime, opened.contextHandle);
            } finally {
                contextIsOpen = false;
                opened.endorserSigningVerificationKey.fill(0);
            }
        },
        prepare: (): PreparedSeedReceiptTerminalEndorsementInventory => {
            requireOpen();
            return executeRequest({
                parse: (responseBytes) =>
                    parsePreparedResponse(
                        responseBytes,
                        input.receiptEnvelopeBytes.length,
                    ),
                requestBytes: encodeHandleRequest(
                    prepareEndorsementOperation,
                    opened.contextHandle,
                ),
                runtime,
            });
        },
        produce: (
            productionInput: SeedReceiptTerminalEndorsementProductionInput,
        ): Uint8Array => {
            requireOpen();
            let signature: Uint8Array | undefined;
            try {
                signature = signingOperations.signEndorsementBody({
                    endorsementAuthorizationBodyBytes: requireExactBytes(
                        productionInput.preparedInventory
                            .endorsementAuthorizationBodyBytes,
                        endorsementAuthorizationBodyByteLength,
                        'Receipt-terminal endorsement authorization body',
                    ),
                    endorserSigningVerificationKey:
                        opened.endorserSigningVerificationKey,
                    signatureRandomness: requireExactBytes(
                        productionInput.signatureRandomness,
                        32,
                        'Receipt-terminal endorsement signature randomness',
                    ),
                });
                return executeRequest({
                    parse: parseCompleteResponse,
                    requestBytes: encodeCompleteRequest(
                        opened.contextHandle,
                        productionInput.preparedInventory,
                        signature,
                    ),
                    runtime,
                });
            } finally {
                signature?.fill(0);
            }
        },
        validate: (
            validationInput: SeedReceiptTerminalEndorsementValidationInput,
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
