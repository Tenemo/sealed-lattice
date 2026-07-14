import { hkdf } from '@noble/hashes/hkdf.js';
import { sha384 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
    foundationProfile,
    type ProtocolHash,
    type RefusalReason,
    type VerificationResult,
} from '@sealed-lattice/types';

import {
    decapsulateClosedMailboxCiphertext,
    encapsulateFreshMailbox,
    encapsulateResetSafeSetupMailbox,
    signFreshMailboxEnvelope,
    signResetSafeSetupMailboxEnvelope,
    type BrowserLocalActionRandomnessCapability,
    type BrowserLocalMailboxCapability,
    type BrowserLocalSigningCapability,
} from './browser-local-key-provider.js';

const textEncoder = new TextEncoder();
const mailboxSignatureContext = textEncoder.encode(
    'sealed-lattice/mailbox-signature/v1',
);
const aesGcmKeyByteLength = 32;
const aesGcmNonceByteLength = 12;
const aesGcmTagByteLength = 16;
const mlKem768EncapsulationKeyByteLength = ml_kem768.lengths.publicKey!;
const mlKem768CiphertextByteLength = ml_kem768.lengths.cipherText!;
const mlDsa65VerificationKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;
const maximumMailboxCiphertextByteLength = 2_147_483_648;
const canonicalUnsignedDecimalPattern = /^(?:0|[1-9][0-9]*)$/u;
const refusalReasons = new Set<RefusalReason>([
    'malformedEncoding',
    'unsupportedVersionOrSuite',
    'outsideSupportedProfile',
    'wrongContext',
    'wrongTypeOrLength',
    'wrongHashOrRoot',
    'invalidSignature',
    'duplicateIdentity',
    'equivocation',
    'missingPrerequisite',
    'invalidProof',
    'invalidArithmeticRelation',
    'consumedState',
]);

export type MailboxPayloadType = 1 | 2;

export type MailboxKeyScheduleInput = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly recipientParticipantId: string;
    readonly producerSequence: string;
    readonly envelopeAttemptIdentifierHex: string;
    readonly payloadType: MailboxPayloadType;
    readonly statementHash: ProtocolHash;
    readonly orderedMaterialRoots: readonly ProtocolHash[];
    readonly kemCiphertextHash: ProtocolHash;
}>;

export type MailboxAssociatedData = Readonly<
    MailboxKeyScheduleInput & {
        readonly plaintextByteLength: string;
    }
>;

export type MailboxAssociatedDataExpectation = Omit<
    MailboxAssociatedData,
    'envelopeAttemptIdentifierHex' | 'kemCiphertextHash'
>;

export type MailboxCiphertextDescriptor = Readonly<{
    readonly totalByteLength: string;
    readonly orderedChunkDigests: readonly ProtocolHash[];
    readonly fullObjectDigest: ProtocolHash;
}>;

export type UnsignedMailboxEnvelope = Readonly<{
    readonly associatedData: MailboxAssociatedData;
    readonly kemCiphertextHex: string;
    readonly ciphertextDescriptor: MailboxCiphertextDescriptor;
    readonly gcmTagHex: string;
}>;

export type SignedMailboxEnvelope = Readonly<
    UnsignedMailboxEnvelope & {
        readonly sourceSignatureHex: string;
    }
>;

export type AuthenticatedMailboxKernel = Readonly<{
    encodeMailboxKeyScheduleInput(value: MailboxKeyScheduleInput): Readonly<{
        readonly canonicalBytesHex: string;
        readonly hkdfExtractSaltHex: string;
    }>;
    encodeMailboxAssociatedData(value: MailboxAssociatedData): Readonly<{
        readonly canonicalBytesHex: string;
        readonly hkdfExtractSaltHex: string;
    }>;
    encodeSignedMailboxEnvelope(value: SignedMailboxEnvelope): Readonly<{
        readonly canonicalBytesHex: string;
        readonly envelopeHash: ProtocolHash;
    }>;
    decodeSignedMailboxEnvelope(input: {
        readonly canonicalBytesHex: string;
    }): Readonly<{
        readonly value: SignedMailboxEnvelope;
        readonly envelopeHash: ProtocolHash;
    }>;
    deriveMailboxKemCiphertextHash(input: {
        readonly kemCiphertextHex: string;
    }): ProtocolHash;
    deriveMailboxEnvelopeHash(value: UnsignedMailboxEnvelope): ProtocolHash;
}>;

type MailboxLeaseState =
    | 'active'
    | 'authenticating'
    | 'cancelled'
    | 'completed'
    | 'decrypting'
    | 'failed';

type MailboxGcmEncryptorLease = Readonly<{
    cancel(): void;
    encryptChunk(bytes: ArrayBuffer): void;
    finish(): Uint8Array;
    state(): MailboxLeaseState;
}>;

type MailboxGcmVerifierLease = Readonly<{
    authenticateChunk(bytes: ArrayBuffer): void;
    cancel(): void;
    decryptChunk(bytes: ArrayBuffer): void;
    finishAuthentication(tag: Uint8Array): void;
    finishDecryption(): void;
    state(): MailboxLeaseState;
}>;

export type AuthenticatedMailboxGcmRuntime = Readonly<{
    openEncryptor(input: {
        readonly associatedData: Uint8Array;
        readonly key: Uint8Array;
        readonly nonce: Uint8Array;
        readonly totalByteLength: number;
    }): MailboxGcmEncryptorLease;
    openVerifier(input: {
        readonly associatedData: Uint8Array;
        readonly key: Uint8Array;
        readonly nonce: Uint8Array;
        readonly totalByteLength: number;
    }): MailboxGcmVerifierLease;
}>;

type MailboxStreamWriterLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(chunkIndex: number, bytes: ArrayBuffer): void;
    cancel(): void;
    finish(): MailboxCiphertextDescriptor;
    state(): MailboxLeaseState;
}>;

type MailboxStreamVerifierLease = Readonly<{
    readonly chunkCount: number;
    readonly totalByteLength: number;
    absorbChunk(chunkIndex: number, bytes: ArrayBuffer): void;
    cancel(): void;
    finish(): void;
    state(): MailboxLeaseState;
}>;

export type AuthenticatedMailboxStreamBoundary = Readonly<{
    openWriter(input: {
        readonly totalByteLength: number;
    }): MailboxStreamWriterLease;
    openVerifier(input: {
        readonly descriptor: MailboxCiphertextDescriptor;
    }): MailboxStreamVerifierLease;
}>;

export type AuthenticatedMailboxCarrier = Readonly<{
    readonly canonicalEnvelopeBytes: Uint8Array;
    readonly envelopeHash: ProtocolHash;
}>;

type MailboxChunkPull = (input: {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
}) => Promise<ArrayBuffer | undefined>;

/**
 * A pull transfers one exact chunk to the mailbox operation. A sink must copy
 * or durably transfer the chunk before resolving; the operation zeroes the
 * supplied buffer before requesting the next chunk.
 */
type MailboxChunkSink = (input: {
    readonly abortSignal?: AbortSignal;
    readonly bytes: ArrayBuffer;
    readonly chunkIndex: number;
}) => Promise<void>;

export type AuthenticatedMailboxProducerSlot = Readonly<{
    readonly suiteId: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly recipientParticipantId: string;
    readonly producerSequence: string;
    readonly payloadType: MailboxPayloadType;
}>;

type AuthenticatedMailboxOutboundCacheLease = Readonly<{
    readonly disposition: 'cached' | 'fresh';
    cachedCarrier(): Promise<AuthenticatedMailboxCarrier>;
    stageChunk(input: {
        readonly bytes: ArrayBuffer;
        readonly chunkIndex: number;
    }): Promise<void>;
    commit(carrier: AuthenticatedMailboxCarrier): Promise<void>;
    pullChunk: MailboxChunkPull;
    cancel(): Promise<void>;
}>;

export type AuthenticatedMailboxOutboundCache = Readonly<{
    /**
     * Reserves one semantic producer slot before any randomness or plaintext
     * is consumed. A fresh lease atomically publishes the signed carrier and
     * all staged chunks before pullChunk becomes readable. A cached lease is
     * an already authenticated, byte-identical retransmission source.
     */
    reserve(input: {
        readonly chunkCount: number;
        readonly plaintextByteLength: number;
        readonly producerSlot: AuthenticatedMailboxProducerSlot;
    }): Promise<AuthenticatedMailboxOutboundCacheLease>;
}>;

type AuthenticatedMailboxInboundSlotLease = Readonly<{
    readonly disposition: 'byteIdenticalRetransmission' | 'fresh';
    cancel(): Promise<void>;
    commit(): Promise<void>;
}>;

export type AuthenticatedMailboxInboundSlotAuthority = Readonly<{
    /**
     * Reserves a signed semantic slot. Only a previously committed exact
     * carrier may return byteIdenticalRetransmission; conflicting bytes return
     * equivocation, and a fresh lease is committed only after plaintext
     * consumption succeeds.
     */
    reserve(input: {
        readonly canonicalEnvelopeBytes: Uint8Array;
        readonly envelopeHash: ProtocolHash;
        readonly producerSlot: AuthenticatedMailboxProducerSlot;
    }): Promise<VerificationResult<AuthenticatedMailboxInboundSlotLease>>;
}>;

type AuthenticatedMailboxStagingLease = Readonly<{
    stageChunk(input: {
        readonly bytes: ArrayBuffer;
        readonly chunkIndex: number;
    }): Promise<void>;
    seal(): Promise<void>;
    pullChunk: MailboxChunkPull;
    dispose(): Promise<void>;
}>;

export type AuthenticatedMailboxStagingBoundary = Readonly<{
    /**
     * Opens a transaction-owned ciphertext staging lease. seal makes every
     * exact staged chunk rereadable without trusting storage bytes, and dispose
     * atomically removes or abandons all lease-owned state.
     */
    open(input: {
        readonly chunkCount: number;
        readonly envelopeHash: ProtocolHash;
        readonly totalByteLength: number;
    }): Promise<AuthenticatedMailboxStagingLease>;
}>;

type AuthenticatedMailboxSealCommonInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly associatedData: Omit<
        MailboxAssociatedData,
        | 'kemCiphertextHash'
        | 'plaintextByteLength'
        | 'envelopeAttemptIdentifierHex'
    >;
    readonly emitCiphertextChunk: MailboxChunkSink;
    readonly gcmRuntime: AuthenticatedMailboxGcmRuntime;
    readonly kernel: AuthenticatedMailboxKernel;
    readonly outboundCache: AuthenticatedMailboxOutboundCache;
    readonly plaintextByteLength: number;
    readonly pullPlaintextChunk: MailboxChunkPull;
    readonly recipientEncapsulationKey: Uint8Array;
    readonly sourceSigningCapability: BrowserLocalSigningCapability;
    readonly sourceVerificationKey: Uint8Array;
    readonly streamBoundary: AuthenticatedMailboxStreamBoundary;
}>;

export type AuthenticatedMailboxSealInput = AuthenticatedMailboxSealCommonInput;

export type ResetSafeSetupMailboxSealInput = Readonly<
    AuthenticatedMailboxSealCommonInput & {
        readonly actionRandomnessCapability: BrowserLocalActionRandomnessCapability;
    }
>;

export type AuthenticatedMailboxOpenInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly carrier: AuthenticatedMailboxCarrier;
    readonly consumePlaintextChunk: MailboxChunkSink;
    readonly expectedAssociatedData: MailboxAssociatedDataExpectation;
    readonly gcmRuntime: AuthenticatedMailboxGcmRuntime;
    readonly inboundSlotAuthority: AuthenticatedMailboxInboundSlotAuthority;
    readonly kernel: AuthenticatedMailboxKernel;
    readonly pullCiphertextChunk: MailboxChunkPull;
    readonly recipientMailboxCapability: BrowserLocalMailboxCapability;
    readonly sourceVerificationKey: Uint8Array;
    readonly stagingBoundary: AuthenticatedMailboxStagingBoundary;
    readonly streamBoundary: AuthenticatedMailboxStreamBoundary;
}>;

export type OpenedAuthenticatedMailbox = Readonly<{
    readonly disposition: 'accepted' | 'byteIdenticalRetransmission';
    readonly envelopeHash: ProtocolHash;
    readonly plaintextByteLength: number;
}>;

export class AuthenticatedMailboxCleanupError extends Error {
    public readonly cleanupFailures: readonly unknown[];
    public readonly operationFailure: unknown;

    public constructor(
        operationFailure: unknown,
        cleanupFailures: readonly unknown[],
    ) {
        super('The authenticated mailbox operation and its cleanup failed.');
        this.name = 'AuthenticatedMailboxCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailures = cleanupFailures;
    }
}

class AuthenticatedMailboxRefusalError extends Error {
    public readonly refusalReason: RefusalReason;

    public constructor(refusalReason: RefusalReason, message: string) {
        super(message);
        this.name = 'AuthenticatedMailboxRefusalError';
        this.refusalReason = refusalReason;
    }
}

class AuthenticatedMailboxOperationError extends Error {
    public readonly failureCause: unknown;

    public constructor(failureCause: unknown) {
        super('The authenticated mailbox operation failed.');
        this.name = 'AuthenticatedMailboxOperationError';
        this.failureCause = failureCause;
    }
}

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
    Object.prototype.toString.call(value) === '[object ArrayBuffer]';

const requireExactBytes = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength !== expectedByteLength) {
        throw new TypeError(
            `${label} must be a Uint8Array containing exactly ${String(expectedByteLength)} bytes.`,
        );
    }

    return value.slice();
};

const requireNonemptyBytes = (value: Uint8Array, label: string): Uint8Array => {
    if (!isUint8Array(value) || value.byteLength === 0) {
        throw new TypeError(`${label} must be a nonempty Uint8Array.`);
    }

    return value.slice();
};

const requireMailboxByteLength = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${label} must be a positive safe integer.`);
    }
    if (value > maximumMailboxCiphertextByteLength) {
        throw new RangeError(
            `${label} exceeds the supported mailbox stream profile.`,
        );
    }

    return value;
};

const parseMailboxByteLength = (
    value: string,
    refusalReason: RefusalReason,
    label: string,
): number => {
    if (
        typeof value !== 'string' ||
        !canonicalUnsignedDecimalPattern.test(value)
    ) {
        throw new AuthenticatedMailboxRefusalError(
            refusalReason,
            `${label} is not a canonical unsigned decimal integer.`,
        );
    }
    const parsed = Number(value);
    if (
        !Number.isSafeInteger(parsed) ||
        parsed <= 0 ||
        parsed > maximumMailboxCiphertextByteLength
    ) {
        throw new AuthenticatedMailboxRefusalError(
            parsed > maximumMailboxCiphertextByteLength
                ? 'outsideSupportedProfile'
                : refusalReason,
            `${label} is outside the supported mailbox stream profile.`,
        );
    }

    return parsed;
};

const deriveAesKeyAndNonce = (
    sharedSecret: Uint8Array,
    hkdfExtractSaltHex: string,
    canonicalKeyScheduleInputHex: string,
): Uint8Array =>
    hkdf(
        sha384,
        sharedSecret,
        hexToBytes(hkdfExtractSaltHex),
        hexToBytes(canonicalKeyScheduleInputHex),
        aesGcmKeyByteLength + aesGcmNonceByteLength,
    );

const canonicalAssociatedDataMatches = (
    kernel: AuthenticatedMailboxKernel,
    actual: MailboxAssociatedData,
    expectation: MailboxAssociatedDataExpectation,
): boolean => {
    const expected: MailboxAssociatedData = {
        ...expectation,
        envelopeAttemptIdentifierHex: actual.envelopeAttemptIdentifierHex,
        kemCiphertextHash: actual.kemCiphertextHash,
    };

    return (
        kernel.encodeMailboxAssociatedData(actual).canonicalBytesHex ===
        kernel.encodeMailboxAssociatedData(expected).canonicalBytesHex
    );
};

const producerSlot = (
    associatedData:
        | AuthenticatedMailboxSealCommonInput['associatedData']
        | MailboxAssociatedData,
): AuthenticatedMailboxProducerSlot => ({
    suiteId: associatedData.suiteId,
    ceremonyContextHash: associatedData.ceremonyContextHash,
    actionContextHash: associatedData.actionContextHash,
    rosterHash: associatedData.rosterHash,
    sourceParticipantId: associatedData.sourceParticipantId,
    recipientParticipantId: associatedData.recipientParticipantId,
    producerSequence: associatedData.producerSequence,
    payloadType: associatedData.payloadType,
});

const expectedChunkCount = (totalByteLength: number): number =>
    Math.ceil(totalByteLength / foundationProfile.streamChunkByteLength);

const expectedChunkByteLength = (
    totalByteLength: number,
    chunkCount: number,
    chunkIndex: number,
): number =>
    chunkIndex + 1 < chunkCount
        ? foundationProfile.streamChunkByteLength
        : totalByteLength -
          (chunkCount - 1) * foundationProfile.streamChunkByteLength;

const throwIfAborted = (abortSignal: AbortSignal | undefined): void => {
    if (abortSignal?.aborted === true) {
        throw new Error('The authenticated mailbox operation was cancelled.');
    }
};

const callbackInput = (
    abortSignal: AbortSignal | undefined,
    bytes: ArrayBuffer,
    chunkIndex: number,
): {
    readonly abortSignal?: AbortSignal;
    readonly bytes: ArrayBuffer;
    readonly chunkIndex: number;
} => ({
    ...(abortSignal === undefined ? {} : { abortSignal }),
    bytes,
    chunkIndex,
});

const pullInput = (
    abortSignal: AbortSignal | undefined,
    chunkIndex: number,
    expectedByteLength: number,
): {
    readonly abortSignal?: AbortSignal;
    readonly chunkIndex: number;
    readonly expectedByteLength: number;
} => ({
    ...(abortSignal === undefined ? {} : { abortSignal }),
    chunkIndex,
    expectedByteLength,
});

const requirePulledChunk = (
    value: ArrayBuffer | undefined,
    expectedByteLength: number,
): ArrayBuffer => {
    if (!isArrayBuffer(value) || value.byteLength !== expectedByteLength) {
        if (isArrayBuffer(value)) {
            new Uint8Array(value).fill(0);
        }
        throw new AuthenticatedMailboxRefusalError(
            'wrongTypeOrLength',
            'A mailbox stream chunk has the wrong type or byte length.',
        );
    }

    return value;
};

const requireNoTrailingChunk = async (
    pullChunk: MailboxChunkPull,
    abortSignal: AbortSignal | undefined,
    chunkCount: number,
): Promise<void> => {
    const trailing = await pullChunk(pullInput(abortSignal, chunkCount, 0));
    if (trailing !== undefined) {
        if (isArrayBuffer(trailing)) {
            new Uint8Array(trailing).fill(0);
        }
        throw new AuthenticatedMailboxRefusalError(
            'wrongTypeOrLength',
            'A mailbox stream contains bytes after its authenticated length.',
        );
    }
    throwIfAborted(abortSignal);
};

const signatureValid = (
    envelopeHash: ProtocolHash,
    sourceSignatureHex: string,
    sourceVerificationKey: Uint8Array,
): boolean => {
    let sourceSignature: Uint8Array | undefined;
    try {
        sourceSignature = requireExactBytes(
            hexToBytes(sourceSignatureHex),
            mlDsa65SignatureByteLength,
            'sourceSignatureHex',
        );
        return ml_dsa65.verify(
            sourceSignature,
            hexToBytes(envelopeHash),
            sourceVerificationKey,
            { context: mailboxSignatureContext },
        );
    } catch {
        return false;
    } finally {
        sourceSignature?.fill(0);
    }
};

const validatedCarrierEnvelope = (
    kernel: AuthenticatedMailboxKernel,
    carrier: AuthenticatedMailboxCarrier,
    sourceVerificationKey: Uint8Array,
): SignedMailboxEnvelope => {
    let decodedEnvelope: ReturnType<
        AuthenticatedMailboxKernel['decodeSignedMailboxEnvelope']
    >;
    try {
        decodedEnvelope = kernel.decodeSignedMailboxEnvelope({
            canonicalBytesHex: bytesToHex(carrier.canonicalEnvelopeBytes),
        });
    } catch {
        throw new AuthenticatedMailboxRefusalError(
            'malformedEncoding',
            'The signed mailbox envelope is not canonical.',
        );
    }
    if (decodedEnvelope.envelopeHash !== carrier.envelopeHash) {
        throw new AuthenticatedMailboxRefusalError(
            'wrongHashOrRoot',
            'The signed mailbox envelope does not match its expected envelope hash.',
        );
    }
    if (
        !signatureValid(
            decodedEnvelope.envelopeHash,
            decodedEnvelope.value.sourceSignatureHex,
            sourceVerificationKey,
        )
    ) {
        throw new AuthenticatedMailboxRefusalError(
            'invalidSignature',
            'The mailbox source signature is invalid.',
        );
    }

    return decodedEnvelope.value;
};

const validateDescriptorLength = (envelope: SignedMailboxEnvelope): number => {
    const plaintextByteLength = parseMailboxByteLength(
        envelope.associatedData.plaintextByteLength,
        'wrongTypeOrLength',
        'The authenticated mailbox plaintext byte length',
    );
    const descriptorByteLength = parseMailboxByteLength(
        envelope.ciphertextDescriptor.totalByteLength,
        'wrongTypeOrLength',
        'The mailbox ciphertext descriptor byte length',
    );
    if (descriptorByteLength !== plaintextByteLength) {
        throw new AuthenticatedMailboxRefusalError(
            'wrongTypeOrLength',
            'The mailbox ciphertext descriptor length does not match its authenticated plaintext length.',
        );
    }
    if (
        !Array.isArray(envelope.ciphertextDescriptor.orderedChunkDigests) ||
        envelope.ciphertextDescriptor.orderedChunkDigests.length !==
            expectedChunkCount(plaintextByteLength)
    ) {
        throw new AuthenticatedMailboxRefusalError(
            'wrongTypeOrLength',
            'The mailbox ciphertext descriptor has the wrong chunk count.',
        );
    }

    return plaintextByteLength;
};

const refusalReasonFromBoundaryError = (
    error: unknown,
): RefusalReason | undefined => {
    if (
        typeof error !== 'object' ||
        error === null ||
        !('refusalReason' in error)
    ) {
        return undefined;
    }
    const refusalReason = error.refusalReason;

    return typeof refusalReason === 'string' &&
        refusalReasons.has(refusalReason as RefusalReason)
        ? (refusalReason as RefusalReason)
        : undefined;
};

const asVerificationRefusal = (error: unknown): unknown => {
    if (error instanceof AuthenticatedMailboxRefusalError) {
        return error;
    }
    const refusalReason = refusalReasonFromBoundaryError(error);

    return refusalReason === undefined
        ? error
        : new AuthenticatedMailboxRefusalError(
              refusalReason,
              'The authenticated mailbox was refused by its canonical runtime boundary.',
          );
};

const cancelSynchronousLease = (
    lease:
        | MailboxGcmEncryptorLease
        | MailboxGcmVerifierLease
        | MailboxStreamWriterLease
        | MailboxStreamVerifierLease
        | undefined,
    cleanupFailures: unknown[],
): void => {
    if (lease === undefined) {
        return;
    }
    const state = lease.state();
    if (state === 'cancelled' || state === 'completed' || state === 'failed') {
        return;
    }
    try {
        lease.cancel();
    } catch (error) {
        cleanupFailures.push(error);
    }
};

const throwAfterCleanup = (
    operationFailure: unknown,
    cleanupFailures: readonly unknown[],
): never => {
    if (cleanupFailures.length > 0) {
        throw new AuthenticatedMailboxCleanupError(
            operationFailure,
            cleanupFailures,
        );
    }
    throw operationFailure instanceof Error
        ? operationFailure
        : new AuthenticatedMailboxOperationError(operationFailure);
};

const retransmitCachedCiphertext = async (input: {
    readonly abortSignal?: AbortSignal;
    readonly descriptor: MailboxCiphertextDescriptor;
    readonly emitCiphertextChunk: MailboxChunkSink;
    readonly pullCiphertextChunk: MailboxChunkPull;
    readonly streamBoundary: AuthenticatedMailboxStreamBoundary;
}): Promise<void> => {
    let verifier: MailboxStreamVerifierLease | undefined;
    let operationFailure: unknown;
    try {
        verifier = input.streamBoundary.openVerifier({
            descriptor: input.descriptor,
        });
        for (
            let chunkIndex = 0;
            chunkIndex < verifier.chunkCount;
            chunkIndex += 1
        ) {
            throwIfAborted(input.abortSignal);
            const byteLength = expectedChunkByteLength(
                verifier.totalByteLength,
                verifier.chunkCount,
                chunkIndex,
            );
            const chunk = requirePulledChunk(
                await input.pullCiphertextChunk(
                    pullInput(input.abortSignal, chunkIndex, byteLength),
                ),
                byteLength,
            );
            try {
                verifier.absorbChunk(chunkIndex, chunk);
                await input.emitCiphertextChunk(
                    callbackInput(input.abortSignal, chunk, chunkIndex),
                );
            } finally {
                new Uint8Array(chunk).fill(0);
            }
        }
        await requireNoTrailingChunk(
            input.pullCiphertextChunk,
            input.abortSignal,
            verifier.chunkCount,
        );
        verifier.finish();
    } catch (error) {
        operationFailure = asVerificationRefusal(error);
    }
    const cleanupFailures: unknown[] = [];
    cancelSynchronousLease(verifier, cleanupFailures);
    if (operationFailure !== undefined) {
        throwAfterCleanup(operationFailure, cleanupFailures);
    }
    if (cleanupFailures.length > 0) {
        throw new AuthenticatedMailboxCleanupError(
            new Error('Cached mailbox ciphertext retransmission completed.'),
            cleanupFailures,
        );
    }
};

const cachedSeal = async (
    input: AuthenticatedMailboxSealCommonInput,
    cacheLease: AuthenticatedMailboxOutboundCacheLease,
    sourceVerificationKey: Uint8Array,
): Promise<AuthenticatedMailboxCarrier> => {
    const carrier = await cacheLease.cachedCarrier();
    const canonicalEnvelopeBytes = requireNonemptyBytes(
        carrier.canonicalEnvelopeBytes,
        'cached carrier canonicalEnvelopeBytes',
    );
    try {
        const cachedCarrier = Object.freeze({
            canonicalEnvelopeBytes,
            envelopeHash: carrier.envelopeHash,
        });
        const envelope = validatedCarrierEnvelope(
            input.kernel,
            cachedCarrier,
            sourceVerificationKey,
        );
        const expectedAssociatedData: MailboxAssociatedDataExpectation = {
            ...input.associatedData,
            plaintextByteLength: String(input.plaintextByteLength),
        };
        if (
            !canonicalAssociatedDataMatches(
                input.kernel,
                envelope.associatedData,
                expectedAssociatedData,
            )
        ) {
            throw new Error(
                'The cached mailbox carrier conflicts with its producer slot.',
            );
        }
        if (validateDescriptorLength(envelope) !== input.plaintextByteLength) {
            throw new Error(
                'The cached mailbox carrier conflicts with its plaintext length.',
            );
        }
        await retransmitCachedCiphertext({
            ...(input.abortSignal === undefined
                ? {}
                : { abortSignal: input.abortSignal }),
            descriptor: envelope.ciphertextDescriptor,
            emitCiphertextChunk: input.emitCiphertextChunk,
            pullCiphertextChunk: cacheLease.pullChunk,
            streamBoundary: input.streamBoundary,
        });

        return Object.freeze({
            canonicalEnvelopeBytes: canonicalEnvelopeBytes.slice(),
            envelopeHash: carrier.envelopeHash,
        });
    } finally {
        canonicalEnvelopeBytes.fill(0);
    }
};

const sealMailbox = async (
    input: AuthenticatedMailboxSealCommonInput,
    actionRandomnessCapability?: BrowserLocalActionRandomnessCapability,
): Promise<AuthenticatedMailboxCarrier> => {
    const plaintextByteLength = requireMailboxByteLength(
        input.plaintextByteLength,
        'plaintextByteLength',
    );
    const recipientEncapsulationKey = requireExactBytes(
        input.recipientEncapsulationKey,
        mlKem768EncapsulationKeyByteLength,
        'recipientEncapsulationKey',
    );
    const sourceVerificationKey = requireExactBytes(
        input.sourceVerificationKey,
        mlDsa65VerificationKeyByteLength,
        'sourceVerificationKey',
    );
    const chunkCount = expectedChunkCount(plaintextByteLength);
    const cacheLease = await input.outboundCache.reserve({
        chunkCount,
        plaintextByteLength,
        producerSlot: producerSlot(input.associatedData),
    });
    if (cacheLease.disposition === 'cached') {
        try {
            return await cachedSeal(input, cacheLease, sourceVerificationKey);
        } finally {
            recipientEncapsulationKey.fill(0);
            sourceVerificationKey.fill(0);
        }
    }

    let cacheCommitted = false;
    let envelopeAttemptIdentifier: Uint8Array | undefined;
    let gcmEncryptor: MailboxGcmEncryptorLease | undefined;
    let keyAndNonce: Uint8Array | undefined;
    let sharedSecret: Uint8Array | undefined;
    let streamWriter: MailboxStreamWriterLease | undefined;
    let operationFailure: unknown;
    let result: AuthenticatedMailboxCarrier | undefined;
    try {
        throwIfAborted(input.abortSignal);
        const resetSafeEncapsulation =
            actionRandomnessCapability === undefined
                ? undefined
                : encapsulateResetSafeSetupMailbox({
                      actionRandomnessCapability,
                      signingCapability: input.sourceSigningCapability,
                      slot: input.associatedData,
                      recipientEncapsulationKey,
                  });
        const freshEncapsulation =
            resetSafeEncapsulation === undefined
                ? encapsulateFreshMailbox({
                      signingCapability: input.sourceSigningCapability,
                      recipientEncapsulationKey,
                  })
                : undefined;
        const encapsulation = resetSafeEncapsulation ?? freshEncapsulation!;
        envelopeAttemptIdentifier = encapsulation.envelopeAttemptIdentifier;
        sharedSecret = encapsulation.sharedSecret;
        const kemCiphertextHex = bytesToHex(encapsulation.ciphertext);
        const keyScheduleInput: MailboxKeyScheduleInput = {
            ...input.associatedData,
            envelopeAttemptIdentifierHex: bytesToHex(envelopeAttemptIdentifier),
            kemCiphertextHash: input.kernel.deriveMailboxKemCiphertextHash({
                kemCiphertextHex,
            }),
        };
        const associatedData: MailboxAssociatedData = {
            ...keyScheduleInput,
            plaintextByteLength: String(plaintextByteLength),
        };
        const encodedKeySchedule =
            input.kernel.encodeMailboxKeyScheduleInput(keyScheduleInput);
        const encodedAssociatedData =
            input.kernel.encodeMailboxAssociatedData(associatedData);
        keyAndNonce = deriveAesKeyAndNonce(
            sharedSecret,
            encodedKeySchedule.hkdfExtractSaltHex,
            encodedKeySchedule.canonicalBytesHex,
        );
        const canonicalAssociatedData = hexToBytes(
            encodedAssociatedData.canonicalBytesHex,
        );
        try {
            gcmEncryptor = input.gcmRuntime.openEncryptor({
                associatedData: canonicalAssociatedData,
                key: keyAndNonce.subarray(0, aesGcmKeyByteLength),
                nonce: keyAndNonce.subarray(aesGcmKeyByteLength),
                totalByteLength: plaintextByteLength,
            });
        } finally {
            canonicalAssociatedData.fill(0);
        }
        streamWriter = input.streamBoundary.openWriter({
            totalByteLength: plaintextByteLength,
        });
        if (streamWriter.chunkCount !== chunkCount) {
            throw new Error(
                'The canonical mailbox stream returned the wrong chunk count.',
            );
        }
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            throwIfAborted(input.abortSignal);
            const byteLength = expectedChunkByteLength(
                plaintextByteLength,
                chunkCount,
                chunkIndex,
            );
            const chunk = requirePulledChunk(
                await input.pullPlaintextChunk(
                    pullInput(input.abortSignal, chunkIndex, byteLength),
                ),
                byteLength,
            );
            try {
                gcmEncryptor.encryptChunk(chunk);
                streamWriter.absorbChunk(chunkIndex, chunk);
                await cacheLease.stageChunk({ bytes: chunk, chunkIndex });
            } finally {
                new Uint8Array(chunk).fill(0);
            }
        }
        await requireNoTrailingChunk(
            input.pullPlaintextChunk,
            input.abortSignal,
            chunkCount,
        );
        const gcmTag = gcmEncryptor.finish();
        const ciphertextDescriptor = streamWriter.finish();
        try {
            const unsignedEnvelope: UnsignedMailboxEnvelope = {
                associatedData,
                kemCiphertextHex,
                ciphertextDescriptor,
                gcmTagHex: bytesToHex(gcmTag),
            };
            const envelopeHash =
                input.kernel.deriveMailboxEnvelopeHash(unsignedEnvelope);
            const sourceSignature =
                resetSafeEncapsulation === undefined
                    ? signFreshMailboxEnvelope({
                          signingCapability: input.sourceSigningCapability,
                          signingPermit: freshEncapsulation!.signingPermit,
                          envelopeHash,
                      })
                    : signResetSafeSetupMailboxEnvelope({
                          signingCapability: input.sourceSigningCapability,
                          signingPermit: resetSafeEncapsulation.signingPermit,
                          envelopeHash,
                      });
            try {
                const encodedEnvelope =
                    input.kernel.encodeSignedMailboxEnvelope({
                        ...unsignedEnvelope,
                        sourceSignatureHex: bytesToHex(sourceSignature),
                    });
                if (encodedEnvelope.envelopeHash !== envelopeHash) {
                    throw new Error(
                        'The canonical mailbox envelope hash changed while attaching its signature.',
                    );
                }
                if (
                    !signatureValid(
                        envelopeHash,
                        bytesToHex(sourceSignature),
                        sourceVerificationKey,
                    )
                ) {
                    throw new Error(
                        'The browser-local provider produced an invalid mailbox signature.',
                    );
                }
                result = Object.freeze({
                    canonicalEnvelopeBytes: hexToBytes(
                        encodedEnvelope.canonicalBytesHex,
                    ),
                    envelopeHash,
                });
                await cacheLease.commit(result);
                cacheCommitted = true;
                await retransmitCachedCiphertext({
                    ...(input.abortSignal === undefined
                        ? {}
                        : { abortSignal: input.abortSignal }),
                    descriptor: ciphertextDescriptor,
                    emitCiphertextChunk: input.emitCiphertextChunk,
                    pullCiphertextChunk: cacheLease.pullChunk,
                    streamBoundary: input.streamBoundary,
                });
            } finally {
                sourceSignature.fill(0);
            }
        } finally {
            gcmTag.fill(0);
        }
    } catch (error) {
        operationFailure = asVerificationRefusal(error);
    }

    const cleanupFailures: unknown[] = [];
    cancelSynchronousLease(gcmEncryptor, cleanupFailures);
    cancelSynchronousLease(streamWriter, cleanupFailures);
    if (!cacheCommitted) {
        try {
            await cacheLease.cancel();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    envelopeAttemptIdentifier?.fill(0);
    keyAndNonce?.fill(0);
    recipientEncapsulationKey.fill(0);
    sharedSecret?.fill(0);
    sourceVerificationKey.fill(0);
    if (operationFailure !== undefined) {
        throwAfterCleanup(operationFailure, cleanupFailures);
    }
    if (cleanupFailures.length > 0) {
        throw new AuthenticatedMailboxCleanupError(
            new Error('Authenticated mailbox sealing completed.'),
            cleanupFailures,
        );
    }
    if (result === undefined) {
        throw new Error('Authenticated mailbox sealing produced no carrier.');
    }

    return result;
};

export const sealAuthenticatedMailbox = async (
    input: AuthenticatedMailboxSealInput,
): Promise<AuthenticatedMailboxCarrier> => sealMailbox(input);

export const sealResetSafeSetupMailbox = async (
    input: ResetSafeSetupMailboxSealInput,
): Promise<AuthenticatedMailboxCarrier> =>
    sealMailbox(input, input.actionRandomnessCapability);

export const openAuthenticatedMailbox = async (
    input: AuthenticatedMailboxOpenInput,
): Promise<VerificationResult<OpenedAuthenticatedMailbox>> => {
    const canonicalEnvelopeBytes = requireNonemptyBytes(
        input.carrier.canonicalEnvelopeBytes,
        'carrier.canonicalEnvelopeBytes',
    );
    const sourceVerificationKey = requireExactBytes(
        input.sourceVerificationKey,
        mlDsa65VerificationKeyByteLength,
        'sourceVerificationKey',
    );
    let gcmVerifier: MailboxGcmVerifierLease | undefined;
    let inboundSlotLease: AuthenticatedMailboxInboundSlotLease | undefined;
    let inboundSlotCommitted = false;
    let keyAndNonce: Uint8Array | undefined;
    let kemCiphertext: Uint8Array | undefined;
    let sharedSecret: Uint8Array | undefined;
    let stagingLease: AuthenticatedMailboxStagingLease | undefined;
    let stagingDisposed = false;
    let stagedStreamVerifier: MailboxStreamVerifierLease | undefined;
    let streamVerifier: MailboxStreamVerifierLease | undefined;
    let operationFailure: unknown;
    let result: VerificationResult<OpenedAuthenticatedMailbox> | undefined;
    try {
        throwIfAborted(input.abortSignal);
        const carrier = Object.freeze({
            canonicalEnvelopeBytes,
            envelopeHash: input.carrier.envelopeHash,
        });
        const envelope = validatedCarrierEnvelope(
            input.kernel,
            carrier,
            sourceVerificationKey,
        );
        if (
            !canonicalAssociatedDataMatches(
                input.kernel,
                envelope.associatedData,
                input.expectedAssociatedData,
            )
        ) {
            throw new AuthenticatedMailboxRefusalError(
                'wrongContext',
                'The mailbox associated data does not match the expected protocol slot.',
            );
        }
        const plaintextByteLength = validateDescriptorLength(envelope);
        const slotReservation = await input.inboundSlotAuthority.reserve({
            canonicalEnvelopeBytes: canonicalEnvelopeBytes.slice(),
            envelopeHash: input.carrier.envelopeHash,
            producerSlot: producerSlot(envelope.associatedData),
        });
        if (!slotReservation.isValid) {
            result = slotReservation;
        } else {
            inboundSlotLease = slotReservation.value;
            if (
                inboundSlotLease.disposition === 'byteIdenticalRetransmission'
            ) {
                result = {
                    isValid: true,
                    value: {
                        disposition: 'byteIdenticalRetransmission',
                        envelopeHash: input.carrier.envelopeHash,
                        plaintextByteLength,
                    },
                };
            } else {
                streamVerifier = input.streamBoundary.openVerifier({
                    descriptor: envelope.ciphertextDescriptor,
                });
                if (
                    streamVerifier.totalByteLength !== plaintextByteLength ||
                    streamVerifier.chunkCount !==
                        expectedChunkCount(plaintextByteLength)
                ) {
                    throw new AuthenticatedMailboxRefusalError(
                        'wrongTypeOrLength',
                        'The canonical mailbox descriptor metadata does not match its authenticated length.',
                    );
                }
                let gcmTag: Uint8Array | undefined;
                try {
                    gcmTag = requireExactBytes(
                        hexToBytes(envelope.gcmTagHex),
                        aesGcmTagByteLength,
                        'gcmTagHex',
                    );
                    kemCiphertext = requireExactBytes(
                        hexToBytes(envelope.kemCiphertextHex),
                        mlKem768CiphertextByteLength,
                        'kemCiphertextHex',
                    );
                } catch (error) {
                    throw new AuthenticatedMailboxRefusalError(
                        'wrongTypeOrLength',
                        error instanceof Error
                            ? error.message
                            : 'The mailbox cryptographic fields have the wrong length.',
                    );
                }
                sharedSecret = decapsulateClosedMailboxCiphertext({
                    capability: input.recipientMailboxCapability,
                    ciphertext: kemCiphertext,
                });
                const encodedKeySchedule =
                    input.kernel.encodeMailboxKeyScheduleInput(
                        envelope.associatedData,
                    );
                const encodedAssociatedData =
                    input.kernel.encodeMailboxAssociatedData(
                        envelope.associatedData,
                    );
                keyAndNonce = deriveAesKeyAndNonce(
                    sharedSecret,
                    encodedKeySchedule.hkdfExtractSaltHex,
                    encodedKeySchedule.canonicalBytesHex,
                );
                const canonicalAssociatedData = hexToBytes(
                    encodedAssociatedData.canonicalBytesHex,
                );
                try {
                    gcmVerifier = input.gcmRuntime.openVerifier({
                        associatedData: canonicalAssociatedData,
                        key: keyAndNonce.subarray(0, aesGcmKeyByteLength),
                        nonce: keyAndNonce.subarray(aesGcmKeyByteLength),
                        totalByteLength: plaintextByteLength,
                    });
                } finally {
                    canonicalAssociatedData.fill(0);
                }
                stagingLease = await input.stagingBoundary.open({
                    chunkCount: streamVerifier.chunkCount,
                    envelopeHash: input.carrier.envelopeHash,
                    totalByteLength: plaintextByteLength,
                });
                for (
                    let chunkIndex = 0;
                    chunkIndex < streamVerifier.chunkCount;
                    chunkIndex += 1
                ) {
                    throwIfAborted(input.abortSignal);
                    const byteLength = expectedChunkByteLength(
                        plaintextByteLength,
                        streamVerifier.chunkCount,
                        chunkIndex,
                    );
                    const chunk = requirePulledChunk(
                        await input.pullCiphertextChunk(
                            pullInput(
                                input.abortSignal,
                                chunkIndex,
                                byteLength,
                            ),
                        ),
                        byteLength,
                    );
                    try {
                        streamVerifier.absorbChunk(chunkIndex, chunk);
                        gcmVerifier.authenticateChunk(chunk);
                        await stagingLease.stageChunk({
                            bytes: chunk,
                            chunkIndex,
                        });
                    } finally {
                        new Uint8Array(chunk).fill(0);
                    }
                }
                await requireNoTrailingChunk(
                    input.pullCiphertextChunk,
                    input.abortSignal,
                    streamVerifier.chunkCount,
                );
                streamVerifier.finish();
                await stagingLease.seal();
                try {
                    gcmVerifier.finishAuthentication(gcmTag);
                } finally {
                    gcmTag.fill(0);
                }
                stagedStreamVerifier = input.streamBoundary.openVerifier({
                    descriptor: envelope.ciphertextDescriptor,
                });
                for (
                    let chunkIndex = 0;
                    chunkIndex < stagedStreamVerifier.chunkCount;
                    chunkIndex += 1
                ) {
                    throwIfAborted(input.abortSignal);
                    const byteLength = expectedChunkByteLength(
                        plaintextByteLength,
                        stagedStreamVerifier.chunkCount,
                        chunkIndex,
                    );
                    const chunk = requirePulledChunk(
                        await stagingLease.pullChunk(
                            pullInput(
                                input.abortSignal,
                                chunkIndex,
                                byteLength,
                            ),
                        ),
                        byteLength,
                    );
                    try {
                        stagedStreamVerifier.absorbChunk(chunkIndex, chunk);
                        gcmVerifier.decryptChunk(chunk);
                        await input.consumePlaintextChunk(
                            callbackInput(input.abortSignal, chunk, chunkIndex),
                        );
                    } finally {
                        new Uint8Array(chunk).fill(0);
                    }
                }
                await requireNoTrailingChunk(
                    stagingLease.pullChunk,
                    input.abortSignal,
                    stagedStreamVerifier.chunkCount,
                );
                stagedStreamVerifier.finish();
                gcmVerifier.finishDecryption();
                await inboundSlotLease.commit();
                inboundSlotCommitted = true;
                await stagingLease.dispose();
                stagingDisposed = true;
                result = {
                    isValid: true,
                    value: {
                        disposition: 'accepted',
                        envelopeHash: input.carrier.envelopeHash,
                        plaintextByteLength,
                    },
                };
            }
        }
    } catch (error) {
        operationFailure = asVerificationRefusal(error);
    }

    const cleanupFailures: unknown[] = [];
    cancelSynchronousLease(gcmVerifier, cleanupFailures);
    cancelSynchronousLease(stagedStreamVerifier, cleanupFailures);
    cancelSynchronousLease(streamVerifier, cleanupFailures);
    if (stagingLease !== undefined && !stagingDisposed) {
        try {
            await stagingLease.dispose();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (inboundSlotLease !== undefined && !inboundSlotCommitted) {
        try {
            await inboundSlotLease.cancel();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    canonicalEnvelopeBytes.fill(0);
    kemCiphertext?.fill(0);
    keyAndNonce?.fill(0);
    sharedSecret?.fill(0);
    sourceVerificationKey.fill(0);
    if (cleanupFailures.length > 0) {
        throw new AuthenticatedMailboxCleanupError(
            operationFailure ??
                new Error('Authenticated mailbox opening completed.'),
            cleanupFailures,
        );
    }
    if (operationFailure !== undefined) {
        if (operationFailure instanceof AuthenticatedMailboxRefusalError) {
            return {
                isValid: false,
                refusalReason: operationFailure.refusalReason,
            };
        }
        throw operationFailure instanceof Error
            ? operationFailure
            : new AuthenticatedMailboxOperationError(operationFailure);
    }
    if (result === undefined) {
        throw new Error('Authenticated mailbox opening produced no result.');
    }

    return result;
};
