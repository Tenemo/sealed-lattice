import { foundationProfile } from '@sealed-lattice/types';

import type { SeedMailboxSenderStreamCarrier } from './seed-mailbox-sender-stream-kernel.js';
import type { TranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';
import { instantiateTranscriptCoreKernelCommandRuntime } from './transcript-core-bridge/kernel-runtime.js';

const requestMagic = Uint8Array.of(0x53, 0x4c, 0x52, 0x51);
const responseMagic = Uint8Array.of(0x53, 0x4c, 0x52, 0x52);
const codecVersion = 1;
const openContextOperation = 1;
const completeAuthenticationOperation = 2;
const completeReceiptOperation = 3;
const validateReceiptOperation = 4;
const closeContextOperation = 5;
const failureStatus = 0;
const openContextStatus = 1;
const authenticatedInventoryStatus = 2;
const completeReceiptStatus = 3;
const validationStatus = 4;
const closedContextStatus = 5;
const authenticatedInconsistencyStatus = 6;
const hashByteLength = 64;
const sharedSecretByteLength = 32;
const signatureRandomnessByteLength = 32;
const signingVerificationKeyByteLength = 1_952;
const mailboxEncapsulationKeyByteLength = 1_184;
const encapsulationCiphertextByteLength = 1_088;
const signatureByteLength = 3_309;
const receiptBodyByteLength = 374;
const receiptEnvelopeByteLength = 3_778;
const responseHeaderByteLength = responseMagic.byteLength + 2 + 1;
const failureResponseByteLength = responseHeaderByteLength + 2;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const seedRecipientReceiptKernelBrand: unique symbol = Symbol(
    'seed-recipient-receipt-kernel',
);
const authenticatedInventoryAuthorizationBrand: unique symbol = Symbol(
    'authenticated-seed-recipient-inventory-authorization',
);

declare const __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__:
    | string
    | undefined;
const packagedKernelSha256Hex =
    typeof __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__ === 'undefined'
        ? undefined
        : __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;

export type SeedRecipientReceiptContext = Readonly<{
    parameterIdentity: Uint8Array;
    participantCount: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    recipientPosition: number;
    rootTerminalIdentity: Uint8Array;
}>;

export type PreparedSeedRecipientReceiptInventory = Readonly<{
    authenticatedInventoryBodyBytes: Uint8Array;
    authenticatedInventoryIdentity: Uint8Array;
    localSeedCustodySegments: readonly Uint8Array[];
    receiptIntentBytes: Uint8Array;
    receiptIntentIdentity: Uint8Array;
}>;

export type SeedRecipientReceiptProductionInput = Readonly<{
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    signatureRandomness: Uint8Array;
}>;

export type SeedRecipientReceiptValidationInput = Readonly<{
    context: SeedRecipientReceiptContext;
    preparedInventory: PreparedSeedRecipientReceiptInventory;
    receiptEnvelopeBytes?: Uint8Array;
}>;

export type SeedRecipientReceiptRootAuthorizationPackageBytes = Readonly<{
    contributorSignatureEnvelopeBytes: Uint8Array;
    exactOutputCertificateBytes: Uint8Array;
    reservationCertificateBytes: Uint8Array;
    rootBodyBytes: Uint8Array;
}>;

export type SeedRecipientReceiptMailboxCarrier = Readonly<
    SeedMailboxSenderStreamCarrier & {
        senderPosition: number;
    }
>;

/**
 * Fixed-purpose operations supplied by the browser-local key owner. Rust
 * verifies every public carrier before any ciphertext reaches decapsulation,
 * and it verifies the final receipt signature before returning its envelope.
 */
export type SeedRecipientReceiptKeyOperations = Readonly<{
    assertMatchesRecipientKeys(input: {
        readonly mailboxEncapsulationKey: Uint8Array;
        readonly recipientSigningVerificationKey: Uint8Array;
    }): void;
    decapsulateMailboxCiphertext(input: {
        readonly ciphertext: Uint8Array;
        readonly mailboxEncapsulationKey: Uint8Array;
    }): Uint8Array;
    signReceiptBody(input: {
        readonly receiptBodyBytes: Uint8Array;
        readonly recipientSigningVerificationKey: Uint8Array;
        readonly signatureRandomness: Uint8Array;
    }): Uint8Array;
}>;

type SnapshottedSeedRecipientReceiptKeyOperations =
    SeedRecipientReceiptKeyOperations;

export type SeedRecipientReceiptAuthenticationStateOperations = Readonly<{
    retainAuthenticatedInconsistency(input: {
        readonly disclosedAuthenticatedEncryptionKey: Uint8Array;
        readonly evidenceIdentity: Uint8Array;
        readonly canonicalOpenRequestBytes: Uint8Array;
        readonly recipientPosition: number;
        readonly senderPosition: number;
        readonly verifiedContext: SeedRecipientReceiptContext;
    }): Promise<void>;
    retainVerifiedPublicSelection(input: {
        readonly canonicalOpenRequestBytes: Uint8Array;
        readonly verifiedContext: SeedRecipientReceiptContext;
    }): Promise<void>;
}>;

type SnapshottedSeedRecipientReceiptAuthenticationStateOperations =
    SeedRecipientReceiptAuthenticationStateOperations;

export type OpenProductionSeedRecipientReceiptKernelInput = Readonly<{
    carriers: readonly SeedRecipientReceiptMailboxCarrier[];
    keyOperations: SeedRecipientReceiptKeyOperations;
    parameterIdentity: Uint8Array;
    preparationContextBytes: Uint8Array;
    recipientPosition: number;
    rootAuthorizationPackages: readonly SeedRecipientReceiptRootAuthorizationPackageBytes[];
    rootTerminalCertificateBytes: Uint8Array;
    rosterBytes: Uint8Array;
    stateOperations: SeedRecipientReceiptAuthenticationStateOperations;
}>;

export type SeedRecipientReceiptKernelErrorCode =
    | 'AuthenticatedInconsistency'
    | 'ContextMismatch'
    | 'ContextUnavailable'
    | 'MalformedKernelResponse'
    | 'MalformedRequest'
    | 'PreparedMismatch'
    | 'PublicVerification'
    | 'ResourceLimit'
    | 'SignatureMismatch';

export class SeedRecipientReceiptKernelError extends Error {
    public readonly code: SeedRecipientReceiptKernelErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: SeedRecipientReceiptKernelErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'SeedRecipientReceiptKernelError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

/**
 * Opaque authorization minted only after the integrity-pinned Rust kernel has
 * authenticated and root-matched every canonical remote mailbox stream.
 */
export type AuthenticatedSeedRecipientInventoryAuthorization = Readonly<{
    readonly [authenticatedInventoryAuthorizationBrand]: true;
}>;

/**
 * One integrity-pinned scalar Rust/WebAssembly recipient boundary. Its
 * authorization and prepared output prove only local mailbox authentication;
 * they grant no all-roster terminal, burn, seed-combination, coin-opening, or
 * preparation-continuation authority.
 */
export type ProductionSeedRecipientReceiptKernel = Readonly<{
    readonly [seedRecipientReceiptKernelBrand]: true;
    authenticatedInventoryAuthorization(): AuthenticatedSeedRecipientInventoryAuthorization;
    close(): void;
    prepare(
        authorization: AuthenticatedSeedRecipientInventoryAuthorization,
    ): PreparedSeedRecipientReceiptInventory;
    produce(input: SeedRecipientReceiptProductionInput): Uint8Array;
    validate(input: SeedRecipientReceiptValidationInput): void;
}>;

const productionKernels = new WeakSet<object>();
const authorizationKernels = new WeakMap<object, object>();
const authenticatedKernelResponseErrors = new WeakSet<object>();
type AuthenticatedInconsistencyDisclosure = Readonly<{
    disclosedAuthenticatedEncryptionKey: Uint8Array;
    evidenceIdentity: Uint8Array;
    recipientPosition: number;
    senderPosition: number;
}>;
const authenticatedInconsistencyDisclosureByError = new WeakMap<
    object,
    AuthenticatedInconsistencyDisclosure
>();

const responseCodeByNumber = new Map<
    number,
    Exclude<SeedRecipientReceiptKernelErrorCode, 'MalformedKernelResponse'>
>([
    [1, 'MalformedRequest'],
    [2, 'ResourceLimit'],
    [3, 'ContextMismatch'],
    [4, 'PublicVerification'],
    [5, 'AuthenticatedInconsistency'],
    [6, 'PreparedMismatch'],
    [7, 'ContextUnavailable'],
    [8, 'SignatureMismatch'],
]);

const malformedResponse = (detail: string): SeedRecipientReceiptKernelError =>
    new SeedRecipientReceiptKernelError(
        'MalformedKernelResponse',
        `The seed-recipient receipt kernel returned ${detail}.`,
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

const snapshotKeyOperations = (
    value: unknown,
): SnapshottedSeedRecipientReceiptKeyOperations => {
    const assertMatchesRecipientKeys = snapshotDataProperty(
        value,
        'assertMatchesRecipientKeys',
        'Seed-recipient receipt key operations',
    );
    const decapsulateMailboxCiphertext = snapshotDataProperty(
        value,
        'decapsulateMailboxCiphertext',
        'Seed-recipient receipt key operations',
    );
    const signReceiptBody = snapshotDataProperty(
        value,
        'signReceiptBody',
        'Seed-recipient receipt key operations',
    );
    if (
        typeof assertMatchesRecipientKeys !== 'function' ||
        typeof decapsulateMailboxCiphertext !== 'function' ||
        typeof signReceiptBody !== 'function'
    ) {
        throw new TypeError(
            'Seed-recipient receipt key operations must provide all fixed-purpose methods.',
        );
    }
    return Object.freeze({
        assertMatchesRecipientKeys: assertMatchesRecipientKeys.bind(
            value,
        ) as SeedRecipientReceiptKeyOperations['assertMatchesRecipientKeys'],
        decapsulateMailboxCiphertext: decapsulateMailboxCiphertext.bind(
            value,
        ) as SeedRecipientReceiptKeyOperations['decapsulateMailboxCiphertext'],
        signReceiptBody: signReceiptBody.bind(
            value,
        ) as SeedRecipientReceiptKeyOperations['signReceiptBody'],
    });
};

const snapshotAuthenticationStateOperations = (
    value: unknown,
): SnapshottedSeedRecipientReceiptAuthenticationStateOperations => {
    const retainAuthenticatedInconsistency = snapshotDataProperty(
        value,
        'retainAuthenticatedInconsistency',
        'Seed-recipient receipt authentication state operations',
    );
    const retainVerifiedPublicSelection = snapshotDataProperty(
        value,
        'retainVerifiedPublicSelection',
        'Seed-recipient receipt authentication state operations',
    );
    if (
        typeof retainAuthenticatedInconsistency !== 'function' ||
        typeof retainVerifiedPublicSelection !== 'function'
    ) {
        throw new TypeError(
            'Seed-recipient receipt authentication state operations must provide both durable transition methods.',
        );
    }
    return Object.freeze({
        retainAuthenticatedInconsistency: retainAuthenticatedInconsistency.bind(
            value,
        ) as SeedRecipientReceiptAuthenticationStateOperations['retainAuthenticatedInconsistency'],
        retainVerifiedPublicSelection: retainVerifiedPublicSelection.bind(
            value,
        ) as SeedRecipientReceiptAuthenticationStateOperations['retainVerifiedPublicSelection'],
    });
};

const requireExactBytes = (
    value: unknown,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new TypeError(
            `${label} must be exactly ${expectedByteLength} bytes.`,
        );
    }
    return value.slice();
};

const requireBoundedBytes = (value: unknown, label: string): Uint8Array => {
    if (
        !isUint8Array(value) ||
        value.byteLength === 0 ||
        value.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new TypeError(`${label} must be a nonempty bounded byte array.`);
    }
    return value.slice();
};

const requireUnsigned16 = (value: unknown, label: string): number => {
    if (
        !Number.isSafeInteger(value) ||
        (value as number) < 0 ||
        (value as number) > unsigned16Maximum
    ) {
        throw new TypeError(`${label} must be an unsigned 16-bit integer.`);
    }
    return value as number;
};

const unsigned16LittleEndian = (value: number, label: string): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(
        0,
        requireUnsigned16(value, label),
        true,
    );
    return bytes;
};

const unsigned32LittleEndian = (value: number, label: string): Uint8Array => {
    if (
        !Number.isSafeInteger(value) ||
        value < 0 ||
        value > unsigned32Maximum
    ) {
        throw new TypeError(`${label} exceeds the unsigned 32-bit range.`);
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
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
    let totalByteLength = 0;
    for (const part of parts) {
        if (part.byteLength > unsigned32Maximum - totalByteLength) {
            throw new TypeError(
                'Seed-recipient receipt request exceeds the unsigned 32-bit range.',
            );
        }
        totalByteLength += part.byteLength;
    }
    if (totalByteLength > foundationProfile.maximumCopiedBufferByteLength) {
        throw new TypeError(
            'Seed-recipient receipt request exceeds the absolute copied-buffer bound.',
        );
    }
    const output = new Uint8Array(totalByteLength);
    let offset = 0;
    try {
        for (const part of parts) {
            output.set(part, offset);
            offset += part.byteLength;
        }
        return output;
    } finally {
        parts.forEach((part) => part.fill(0));
    }
};

const requestHeaderParts = (operation: number): readonly Uint8Array[] => [
    requestMagic.slice(),
    unsigned16LittleEndian(codecVersion, 'Receipt-kernel codec version'),
    Uint8Array.of(operation),
];

const encodeOpenContextRequest = (
    input: OpenProductionSeedRecipientReceiptKernelInput,
): Uint8Array => {
    const packages: unknown = input.rootAuthorizationPackages;
    const carriers: unknown = input.carriers;
    if (
        !isReadonlyArray(packages) ||
        packages.length === 0 ||
        packages.length > unsigned16Maximum
    ) {
        throw new TypeError(
            'Seed-recipient receipt root authorization packages must be a bounded nonempty array.',
        );
    }
    if (
        !isReadonlyArray(carriers) ||
        carriers.length === 0 ||
        carriers.length > unsigned16Maximum
    ) {
        throw new TypeError(
            'Seed-recipient receipt carriers must be a bounded nonempty array.',
        );
    }
    const parts: Uint8Array[] = [
        ...requestHeaderParts(openContextOperation),
        requireExactBytes(
            input.parameterIdentity,
            hashByteLength,
            'Seed-recipient receipt parameter identity',
        ),
        unsigned16LittleEndian(
            input.recipientPosition,
            'Seed-recipient receipt recipient position',
        ),
        ...boundedBytesParts(
            input.preparationContextBytes,
            'Seed-recipient receipt preparation context',
        ),
        ...boundedBytesParts(
            input.rosterBytes,
            'Seed-recipient receipt roster',
        ),
        unsigned16LittleEndian(
            packages.length,
            'Seed-recipient receipt root-package count',
        ),
    ];
    for (const [packageIndex, rootPackage] of packages.entries()) {
        parts.push(
            ...boundedBytesParts(
                snapshotDataProperty(
                    rootPackage,
                    'rootBodyBytes',
                    `Seed-recipient receipt root package ${packageIndex}`,
                ),
                `Seed-recipient receipt root body ${packageIndex}`,
            ),
            ...boundedBytesParts(
                snapshotDataProperty(
                    rootPackage,
                    'reservationCertificateBytes',
                    `Seed-recipient receipt root package ${packageIndex}`,
                ),
                `Seed-recipient receipt root reservation ${packageIndex}`,
            ),
            ...boundedBytesParts(
                snapshotDataProperty(
                    rootPackage,
                    'exactOutputCertificateBytes',
                    `Seed-recipient receipt root package ${packageIndex}`,
                ),
                `Seed-recipient receipt root exact output ${packageIndex}`,
            ),
            ...boundedBytesParts(
                snapshotDataProperty(
                    rootPackage,
                    'contributorSignatureEnvelopeBytes',
                    `Seed-recipient receipt root package ${packageIndex}`,
                ),
                `Seed-recipient receipt root signature ${packageIndex}`,
            ),
        );
    }
    parts.push(
        ...boundedBytesParts(
            input.rootTerminalCertificateBytes,
            'Seed-recipient receipt root-terminal certificate',
        ),
        unsigned16LittleEndian(
            carriers.length,
            'Seed-recipient receipt carrier count',
        ),
    );
    for (const [carrierIndex, carrier] of carriers.entries()) {
        const encryptedChunks = snapshotDataProperty(
            carrier,
            'encryptedChunks',
            `Seed-recipient receipt carrier ${carrierIndex}`,
        );
        if (
            !isReadonlyArray(encryptedChunks) ||
            encryptedChunks.length === 0 ||
            encryptedChunks.length > unsigned16Maximum
        ) {
            throw new TypeError(
                `Seed-recipient receipt carrier ${carrierIndex} must contain a bounded nonempty chunk array.`,
            );
        }
        parts.push(
            unsigned16LittleEndian(
                requireUnsigned16(
                    snapshotDataProperty(
                        carrier,
                        'senderPosition',
                        `Seed-recipient receipt carrier ${carrierIndex}`,
                    ),
                    `Seed-recipient receipt sender position ${carrierIndex}`,
                ),
                `Seed-recipient receipt sender position ${carrierIndex}`,
            ),
            ...boundedBytesParts(
                snapshotDataProperty(
                    carrier,
                    'headerBytes',
                    `Seed-recipient receipt carrier ${carrierIndex}`,
                ),
                `Seed-recipient receipt header ${carrierIndex}`,
            ),
            ...boundedBytesParts(
                snapshotDataProperty(
                    carrier,
                    'manifestBytes',
                    `Seed-recipient receipt carrier ${carrierIndex}`,
                ),
                `Seed-recipient receipt manifest ${carrierIndex}`,
            ),
            ...boundedBytesParts(
                snapshotDataProperty(
                    carrier,
                    'signatureEnvelopeBytes',
                    `Seed-recipient receipt carrier ${carrierIndex}`,
                ),
                `Seed-recipient receipt signature envelope ${carrierIndex}`,
            ),
            unsigned16LittleEndian(
                encryptedChunks.length,
                `Seed-recipient receipt chunk count ${carrierIndex}`,
            ),
        );
        for (const [chunkIndex, chunk] of encryptedChunks.entries()) {
            parts.push(
                ...boundedBytesParts(
                    chunk,
                    `Seed-recipient receipt encrypted chunk ${carrierIndex}:${chunkIndex}`,
                ),
            );
        }
    }
    return concatenateRequestParts(parts);
};

const preparedInventoryParts = (
    prepared: PreparedSeedRecipientReceiptInventory,
): readonly Uint8Array[] => {
    const segments: unknown = prepared.localSeedCustodySegments;
    if (
        !isReadonlyArray(segments) ||
        segments.length === 0 ||
        segments.length > unsigned16Maximum
    ) {
        throw new TypeError(
            'Seed-recipient receipt local custody segments must be a bounded nonempty array.',
        );
    }
    const parts: Uint8Array[] = [
        ...boundedBytesParts(
            prepared.authenticatedInventoryBodyBytes,
            'Seed-recipient authenticated-inventory body',
        ),
        requireExactBytes(
            prepared.authenticatedInventoryIdentity,
            hashByteLength,
            'Seed-recipient authenticated-inventory identity',
        ),
        unsigned16LittleEndian(
            segments.length,
            'Seed-recipient local custody segment count',
        ),
    ];
    for (const [segmentIndex, segment] of segments.entries()) {
        parts.push(
            ...boundedBytesParts(
                segment,
                `Seed-recipient local custody segment ${segmentIndex}`,
            ),
        );
    }
    parts.push(
        ...boundedBytesParts(
            requireExactBytes(
                prepared.receiptIntentBytes,
                receiptBodyByteLength,
                'Seed-recipient receipt intent',
            ),
            'Seed-recipient receipt intent',
        ),
        requireExactBytes(
            prepared.receiptIntentIdentity,
            hashByteLength,
            'Seed-recipient receipt-intent identity',
        ),
    );
    return parts;
};

const contextParts = (
    context: SeedRecipientReceiptContext,
): readonly Uint8Array[] => [
    requireExactBytes(
        context.parameterIdentity,
        hashByteLength,
        'Seed-recipient validation parameter identity',
    ),
    unsigned16LittleEndian(
        context.participantCount,
        'Seed-recipient validation participant count',
    ),
    unsigned16LittleEndian(
        context.preparationAttemptOrdinal,
        'Seed-recipient validation preparation attempt',
    ),
    requireExactBytes(
        context.preparationContextIdentity,
        hashByteLength,
        'Seed-recipient validation preparation-context identity',
    ),
    unsigned16LittleEndian(
        context.recipientPosition,
        'Seed-recipient validation recipient position',
    ),
    requireExactBytes(
        context.rootTerminalIdentity,
        hashByteLength,
        'Seed-recipient validation root-terminal identity',
    ),
];

const encodeCompleteAuthenticationRequest = (
    contextHandle: number,
    sharedSecrets: readonly Uint8Array[],
): Uint8Array => {
    if (
        sharedSecrets.length === 0 ||
        sharedSecrets.length > unsigned16Maximum
    ) {
        throw new TypeError(
            'Seed-recipient receipt shared-secret inventory must be bounded and nonempty.',
        );
    }
    return concatenateRequestParts([
        ...requestHeaderParts(completeAuthenticationOperation),
        unsigned32LittleEndian(contextHandle, 'Receipt context handle'),
        unsigned16LittleEndian(
            sharedSecrets.length,
            'Seed-recipient shared-secret count',
        ),
        ...sharedSecrets.map((sharedSecret, sharedSecretIndex) =>
            requireExactBytes(
                sharedSecret,
                sharedSecretByteLength,
                `Seed-recipient shared secret ${sharedSecretIndex}`,
            ),
        ),
    ]);
};

const encodeCompleteReceiptRequest = (
    contextHandle: number,
    preparedInventory: PreparedSeedRecipientReceiptInventory,
    signature: Uint8Array,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(completeReceiptOperation),
        unsigned32LittleEndian(contextHandle, 'Receipt context handle'),
        ...preparedInventoryParts(preparedInventory),
        requireExactBytes(
            signature,
            signatureByteLength,
            'Seed-recipient receipt signature',
        ),
    ]);

const encodeValidationRequest = (
    contextHandle: number,
    input: SeedRecipientReceiptValidationInput,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(validateReceiptOperation),
        unsigned32LittleEndian(contextHandle, 'Receipt context handle'),
        ...contextParts(input.context),
        ...preparedInventoryParts(input.preparedInventory),
        Uint8Array.of(input.receiptEnvelopeBytes === undefined ? 0 : 1),
        ...(input.receiptEnvelopeBytes === undefined
            ? []
            : boundedBytesParts(
                  requireExactBytes(
                      input.receiptEnvelopeBytes,
                      receiptEnvelopeByteLength,
                      'Seed-recipient receipt envelope',
                  ),
                  'Seed-recipient receipt envelope',
              )),
    ]);

const encodeHandleRequest = (
    operation: number,
    contextHandle: number,
): Uint8Array =>
    concatenateRequestParts([
        ...requestHeaderParts(operation),
        unsigned32LittleEndian(contextHandle, 'Receipt context handle'),
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
            const failure = new SeedRecipientReceiptKernelError(
                code,
                `The seed-recipient receipt kernel refused the request with ${code}.`,
            );
            authenticatedKernelResponseErrors.add(failure);
            throw failure;
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
    expectedCarrierCount: number,
): Readonly<{
    contextHandle: number;
    ciphertexts: readonly Uint8Array[];
    mailboxEncapsulationKey: Uint8Array;
    recipientSigningVerificationKey: Uint8Array;
    verifiedContext: SeedRecipientReceiptContext;
}> => {
    const expectedByteLength =
        responseHeaderByteLength +
        4 +
        hashByteLength * 3 +
        2 * 3 +
        signingVerificationKeyByteLength +
        mailboxEncapsulationKeyByteLength +
        2 +
        expectedCarrierCount * encapsulationCiphertextByteLength;
    if (
        responseBytes.byteLength !== expectedByteLength &&
        responseBytes[responseHeaderByteLength - 1] !== failureStatus
    ) {
        throw malformedResponse('an invalid open-response byte length');
    }
    const cursor = new ResponseCursor(responseBytes, openContextStatus);
    const contextHandle = cursor.readUnsigned32('context handle');
    if (contextHandle === 0) {
        throw malformedResponse('a zero context handle');
    }
    const verifiedContext = Object.freeze({
        parameterIdentity: cursor.readExact(
            hashByteLength,
            'verified parameter identity',
        ),
        preparationContextIdentity: cursor.readExact(
            hashByteLength,
            'verified preparation-context identity',
        ),
        rootTerminalIdentity: cursor.readExact(
            hashByteLength,
            'verified root-terminal identity',
        ),
        preparationAttemptOrdinal: cursor.readUnsigned16(
            'verified preparation-attempt ordinal',
        ),
        participantCount: cursor.readUnsigned16('verified participant count'),
        recipientPosition: cursor.readUnsigned16('verified recipient position'),
    });
    const recipientSigningVerificationKey = cursor.readExact(
        signingVerificationKeyByteLength,
        'recipient signing verification key',
    );
    const mailboxEncapsulationKey = cursor.readExact(
        mailboxEncapsulationKeyByteLength,
        'recipient mailbox encapsulation key',
    );
    const ciphertextCount = cursor.readUnsigned16('ciphertext count');
    if (ciphertextCount !== expectedCarrierCount) {
        throw malformedResponse('an unexpected ciphertext count');
    }
    const ciphertexts = Object.freeze(
        Array.from({ length: ciphertextCount }, (_unused, ciphertextIndex) =>
            cursor.readExact(
                encapsulationCiphertextByteLength,
                `encapsulation ciphertext ${ciphertextIndex}`,
            ),
        ),
    );
    cursor.requireComplete();
    return Object.freeze({
        contextHandle,
        ciphertexts,
        mailboxEncapsulationKey,
        recipientSigningVerificationKey,
        verifiedContext,
    });
};

const parsePreparedResponse = (
    responseBytes: Uint8Array,
    expectedSegmentCount: number,
): PreparedSeedRecipientReceiptInventory => {
    if (
        responseBytes.byteLength >= responseHeaderByteLength &&
        responseBytes[responseHeaderByteLength - 1] ===
            authenticatedInconsistencyStatus
    ) {
        const cursor = new ResponseCursor(
            responseBytes,
            authenticatedInconsistencyStatus,
        );
        const senderPosition = cursor.readUnsigned16('inconsistent sender');
        const recipientPosition = cursor.readUnsigned16(
            'inconsistency recipient',
        );
        const disclosedAuthenticatedEncryptionKey = cursor.readExact(
            sharedSecretByteLength,
            'disclosed authenticated-encryption key',
        );
        const evidenceIdentity = cursor.readExact(
            hashByteLength,
            'authenticated-inconsistency identity',
        );
        cursor.requireComplete();
        const failure = new SeedRecipientReceiptKernelError(
            'AuthenticatedInconsistency',
            'The seed-recipient receipt kernel verified a sender-authenticated delivery inconsistency.',
        );
        authenticatedKernelResponseErrors.add(failure);
        authenticatedInconsistencyDisclosureByError.set(
            failure,
            Object.freeze({
                disclosedAuthenticatedEncryptionKey,
                evidenceIdentity,
                recipientPosition,
                senderPosition,
            }),
        );
        throw failure;
    }
    const cursor = new ResponseCursor(
        responseBytes,
        authenticatedInventoryStatus,
    );
    const authenticatedInventoryBodyBytes = cursor.readBounded(
        'authenticated-inventory body',
    );
    const authenticatedInventoryIdentity = cursor.readExact(
        hashByteLength,
        'authenticated-inventory identity',
    );
    const segmentCount = cursor.readUnsigned16('local custody segment count');
    if (segmentCount !== expectedSegmentCount) {
        throw malformedResponse('an unexpected local custody segment count');
    }
    const localSeedCustodySegments = Object.freeze(
        Array.from({ length: segmentCount }, (_unused, segmentIndex) =>
            cursor.readBounded(`local seed custody segment ${segmentIndex}`),
        ),
    );
    const receiptIntentBytes = cursor.readBounded('receipt intent');
    if (receiptIntentBytes.byteLength !== receiptBodyByteLength) {
        throw malformedResponse('an invalid receipt-intent byte length');
    }
    const receiptIntentIdentity = cursor.readExact(
        hashByteLength,
        'receipt-intent identity',
    );
    cursor.requireComplete();
    return Object.freeze({
        authenticatedInventoryBodyBytes,
        authenticatedInventoryIdentity,
        localSeedCustodySegments,
        receiptIntentBytes,
        receiptIntentIdentity,
    });
};

const parseCompleteResponse = (responseBytes: Uint8Array): Uint8Array => {
    const cursor = new ResponseCursor(responseBytes, completeReceiptStatus);
    const receiptEnvelopeBytes = cursor.readBounded('receipt envelope');
    if (receiptEnvelopeBytes.byteLength !== receiptEnvelopeByteLength) {
        throw malformedResponse('an invalid receipt-envelope byte length');
    }
    cursor.requireComplete();
    return receiptEnvelopeBytes;
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
        responseBytes = input.runtime.executeSeedRecipientReceipt(
            input.requestBytes,
        );
        return input.parse(responseBytes);
    } finally {
        input.requestBytes.fill(0);
        responseBytes?.fill(0);
    }
};

const destroyPreparedInventory = (
    prepared: PreparedSeedRecipientReceiptInventory,
): void => {
    prepared.authenticatedInventoryBodyBytes.fill(0);
    prepared.authenticatedInventoryIdentity.fill(0);
    prepared.localSeedCustodySegments.forEach((segment) => segment.fill(0));
    prepared.receiptIntentBytes.fill(0);
    prepared.receiptIntentIdentity.fill(0);
};

const destroyContext = (context: SeedRecipientReceiptContext): void => {
    context.parameterIdentity.fill(0);
    context.preparationContextIdentity.fill(0);
    context.rootTerminalIdentity.fill(0);
};

const copyContext = (
    context: SeedRecipientReceiptContext,
): SeedRecipientReceiptContext =>
    Object.freeze({
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        recipientPosition: context.recipientPosition,
        rootTerminalIdentity: context.rootTerminalIdentity.slice(),
    });

const copyPreparedInventory = (
    prepared: PreparedSeedRecipientReceiptInventory,
): PreparedSeedRecipientReceiptInventory =>
    Object.freeze({
        authenticatedInventoryBodyBytes:
            prepared.authenticatedInventoryBodyBytes.slice(),
        authenticatedInventoryIdentity:
            prepared.authenticatedInventoryIdentity.slice(),
        localSeedCustodySegments: Object.freeze(
            prepared.localSeedCustodySegments.map((segment) => segment.slice()),
        ),
        receiptIntentBytes: prepared.receiptIntentBytes.slice(),
        receiptIntentIdentity: prepared.receiptIntentIdentity.slice(),
    });

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

export const isProductionSeedRecipientReceiptKernel = (
    value: unknown,
): value is ProductionSeedRecipientReceiptKernel =>
    typeof value === 'object' && value !== null && productionKernels.has(value);

export const isAuthenticatedSeedRecipientReceiptInconsistency = (
    value: unknown,
): value is SeedRecipientReceiptKernelError =>
    typeof value === 'object' &&
    value !== null &&
    authenticatedKernelResponseErrors.has(value) &&
    (value as SeedRecipientReceiptKernelError).code ===
        'AuthenticatedInconsistency';

/**
 * Verifies the full public root context and every canonical sender carrier in
 * Rust before invoking the browser-local ML-KEM operations. Rust then decrypts
 * and root-matches all plaintexts before minting the opaque local inventory.
 */
export const openProductionSeedRecipientReceiptKernel = async (
    transcriptCoreKernelUrl: URL,
    input: OpenProductionSeedRecipientReceiptKernelInput,
): Promise<ProductionSeedRecipientReceiptKernel> => {
    if (packagedKernelSha256Hex === undefined) {
        throw new Error(
            'The seed-recipient receipt kernel requires the package build integrity identity.',
        );
    }
    const keyOperations = snapshotKeyOperations(input.keyOperations);
    const stateOperations = snapshotAuthenticationStateOperations(
        input.stateOperations,
    );
    const canonicalOpenRequestBytes = encodeOpenContextRequest(input);
    const expectedCarrierCount = input.carriers.length;
    let runtime: TranscriptCoreKernelCommandRuntime;
    try {
        runtime = await instantiateTranscriptCoreKernelCommandRuntime(
            transcriptCoreKernelUrl,
            { expectedKernelSha256Hex: packagedKernelSha256Hex },
        );
    } catch (error) {
        canonicalOpenRequestBytes.fill(0);
        throw error;
    }
    let opened: ReturnType<typeof parseOpenResponse>;
    try {
        opened = executeRequest({
            parse: (responseBytes) =>
                parseOpenResponse(responseBytes, expectedCarrierCount),
            requestBytes: canonicalOpenRequestBytes.slice(),
            runtime,
        });
    } catch (error) {
        canonicalOpenRequestBytes.fill(0);
        throw error;
    }
    let contextIsOpen = true;
    let preparedInventory: PreparedSeedRecipientReceiptInventory | undefined;
    const sharedSecrets: Uint8Array[] = [];
    try {
        const retainedSelectionInput = Object.freeze({
            canonicalOpenRequestBytes: canonicalOpenRequestBytes.slice(),
            verifiedContext: copyContext(opened.verifiedContext),
        });
        try {
            await stateOperations.retainVerifiedPublicSelection(
                retainedSelectionInput,
            );
        } finally {
            retainedSelectionInput.canonicalOpenRequestBytes.fill(0);
            destroyContext(retainedSelectionInput.verifiedContext);
        }
        keyOperations.assertMatchesRecipientKeys({
            mailboxEncapsulationKey: opened.mailboxEncapsulationKey,
            recipientSigningVerificationKey:
                opened.recipientSigningVerificationKey,
        });
        for (const ciphertext of opened.ciphertexts) {
            sharedSecrets.push(
                requireExactBytes(
                    keyOperations.decapsulateMailboxCiphertext({
                        ciphertext,
                        mailboxEncapsulationKey: opened.mailboxEncapsulationKey,
                    }),
                    sharedSecretByteLength,
                    'Seed-recipient decapsulated shared secret',
                ),
            );
        }
        try {
            preparedInventory = executeRequest({
                parse: (responseBytes) =>
                    parsePreparedResponse(responseBytes, expectedCarrierCount),
                requestBytes: encodeCompleteAuthenticationRequest(
                    opened.contextHandle,
                    sharedSecrets,
                ),
                runtime,
            });
        } catch (error) {
            if (isAuthenticatedSeedRecipientReceiptInconsistency(error)) {
                const disclosure =
                    authenticatedInconsistencyDisclosureByError.get(error);
                authenticatedInconsistencyDisclosureByError.delete(error);
                if (disclosure === undefined) {
                    throw new SeedRecipientReceiptKernelError(
                        'ContextUnavailable',
                        'The authenticated seed-delivery inconsistency omitted its verified disclosure.',
                        error,
                    );
                }
                const retainedBurnInput = Object.freeze({
                    canonicalOpenRequestBytes:
                        canonicalOpenRequestBytes.slice(),
                    disclosedAuthenticatedEncryptionKey:
                        disclosure.disclosedAuthenticatedEncryptionKey.slice(),
                    evidenceIdentity: disclosure.evidenceIdentity.slice(),
                    recipientPosition: disclosure.recipientPosition,
                    senderPosition: disclosure.senderPosition,
                    verifiedContext: copyContext(opened.verifiedContext),
                });
                try {
                    await stateOperations.retainAuthenticatedInconsistency(
                        retainedBurnInput,
                    );
                } catch (burnFailure) {
                    throw new SeedRecipientReceiptKernelError(
                        'ContextUnavailable',
                        'The authenticated seed-delivery inconsistency could not be retained durably.',
                        [error, burnFailure],
                    );
                } finally {
                    retainedBurnInput.canonicalOpenRequestBytes.fill(0);
                    retainedBurnInput.disclosedAuthenticatedEncryptionKey.fill(
                        0,
                    );
                    retainedBurnInput.evidenceIdentity.fill(0);
                    disclosure.disclosedAuthenticatedEncryptionKey.fill(0);
                    disclosure.evidenceIdentity.fill(0);
                    destroyContext(retainedBurnInput.verifiedContext);
                }
            }
            throw error;
        }
    } catch (error) {
        try {
            closeContext(runtime, opened.contextHandle);
            contextIsOpen = false;
        } catch (closeError) {
            throw new SeedRecipientReceiptKernelError(
                'ContextUnavailable',
                'The seed-recipient receipt opening failure also failed context cleanup.',
                [error, closeError],
            );
        }
        throw error;
    } finally {
        canonicalOpenRequestBytes.fill(0);
        sharedSecrets.forEach((sharedSecret) => sharedSecret.fill(0));
        opened.ciphertexts.forEach((ciphertext) => ciphertext.fill(0));
        destroyContext(opened.verifiedContext);
    }
    const authorizedPreparedInventory = preparedInventory;
    const requireOpen = (): void => {
        if (!contextIsOpen) {
            throw new SeedRecipientReceiptKernelError(
                'ContextUnavailable',
                'The seed-recipient receipt kernel context is closed.',
            );
        }
    };
    const kernel: ProductionSeedRecipientReceiptKernel = Object.freeze({
        [seedRecipientReceiptKernelBrand]: true as const,
        authenticatedInventoryAuthorization:
            (): AuthenticatedSeedRecipientInventoryAuthorization => {
                requireOpen();
                const authorization = Object.freeze({
                    [authenticatedInventoryAuthorizationBrand]: true as const,
                });
                authorizationKernels.set(authorization, kernel);
                return authorization;
            },
        close: (): void => {
            if (!contextIsOpen) {
                return;
            }
            try {
                closeContext(runtime, opened.contextHandle);
            } finally {
                contextIsOpen = false;
                opened.mailboxEncapsulationKey.fill(0);
                opened.recipientSigningVerificationKey.fill(0);
                destroyPreparedInventory(authorizedPreparedInventory);
            }
        },
        prepare: (
            authorization: AuthenticatedSeedRecipientInventoryAuthorization,
        ): PreparedSeedRecipientReceiptInventory => {
            requireOpen();
            if (
                typeof authorization !== 'object' ||
                authorization === null ||
                authorizationKernels.get(authorization) !== kernel
            ) {
                throw new SeedRecipientReceiptKernelError(
                    'ContextMismatch',
                    'The authenticated recipient-inventory authorization does not belong to this kernel.',
                );
            }
            return copyPreparedInventory(authorizedPreparedInventory);
        },
        produce: (
            productionInput: SeedRecipientReceiptProductionInput,
        ): Uint8Array => {
            requireOpen();
            let receiptBodyBytes: Uint8Array | undefined;
            let signature: Uint8Array | undefined;
            let signatureRandomness: Uint8Array | undefined;
            try {
                receiptBodyBytes = requireExactBytes(
                    productionInput.preparedInventory.receiptIntentBytes,
                    receiptBodyByteLength,
                    'Seed-recipient receipt intent',
                );
                signatureRandomness = requireExactBytes(
                    productionInput.signatureRandomness,
                    signatureRandomnessByteLength,
                    'Seed-recipient receipt signature randomness',
                );
                signature = requireExactBytes(
                    keyOperations.signReceiptBody({
                        receiptBodyBytes,
                        recipientSigningVerificationKey:
                            opened.recipientSigningVerificationKey,
                        signatureRandomness,
                    }),
                    signatureByteLength,
                    'Seed-recipient receipt signature',
                );
                return executeRequest({
                    parse: parseCompleteResponse,
                    requestBytes: encodeCompleteReceiptRequest(
                        opened.contextHandle,
                        productionInput.preparedInventory,
                        signature,
                    ),
                    runtime,
                });
            } finally {
                receiptBodyBytes?.fill(0);
                signature?.fill(0);
                signatureRandomness?.fill(0);
            }
        },
        validate: (
            validationInput: SeedRecipientReceiptValidationInput,
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
