import { shake256 } from '@noble/hashes/sha3.js';
import {
    assertSeedMailboxSenderSigningCapabilityMatchesRosterKey,
    signSeedMailboxManifestBody,
    type BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';
import {
    isProductionSeedMailboxSenderStreamKernel,
    openProductionSeedMailboxSenderStreamKernel,
    type OpenProductionSeedMailboxSenderStreamKernelInput,
    type ProductionSeedMailboxSenderStreamKernel,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    bytesEqual,
    copyBoundedBytes,
    copyExactBytes,
    mapStorageError,
    readRuntimeRecord,
    runtimeRecordEnvelopeOverheadByteLength,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
} from './authenticated-runtime-record.js';
import { AuthenticatedStorageRecencyCoordinator } from './authenticated-storage-recency.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const senderStreamCustodyRecordMagic = Uint8Array.of(0x53, 0x4c, 0x53, 0x43);
const senderStreamCustodyRecordVersion = 1;
const reservedRecordKind = 1;
const completedRecordKind = 2;
const hashByteLength = 64;
const randomnessByteLength = 32;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const senderStreamSourceDigestDomain =
    'sealed-lattice/runtime/seed-mailbox-sender-source-digest/v1';
const seedMailboxSenderStreamCustodyOperationDomain =
    'sealed-lattice/runtime/seed-mailbox-sender-stream-record/v1';
const textEncoder = new TextEncoder();

export type SeedMailboxSenderStreamCustodyContext = Readonly<{
    parameterIdentity: Uint8Array;
    participantCount: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
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

export type SeedMailboxSenderStreamCustodyLimits = Readonly<{
    maximumCanonicalDeliveryDescriptorByteLength: number;
    maximumEncryptedChunkByteLength: number;
    maximumEncryptedChunkCount: number;
    maximumHeaderByteLength: number;
    maximumManifestByteLength: number;
    maximumSignatureEnvelopeByteLength: number;
    maximumSourcePayloadByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

/**
 * Exact transport bytes retained for byte-identical publication replay.
 *
 * This is inert custody output. It is not a verified delivery, receipt,
 * preparation capability, key-combination capability, or coin-opening
 * capability.
 */
export type RetainedSeedMailboxSenderStreamCarrier = Readonly<{
    encryptedChunks: readonly Uint8Array[];
    headerBytes: Uint8Array;
    manifestBytes: Uint8Array;
    signatureEnvelopeBytes: Uint8Array;
}>;

export type SeedMailboxSenderStreamProductionInput = Readonly<{
    canonicalDeliveryDescriptorBytes: Uint8Array;
    context: SeedMailboxSenderStreamCustodyContext &
        Readonly<{ recipientPosition: number }>;
    encapsulationRandomness: Uint8Array;
    signatureRandomness: Uint8Array;
    sourcePayloadBytes: Uint8Array;
}>;

export type SeedMailboxSenderStreamValidationInput = Readonly<{
    canonicalDeliveryDescriptorBytes: Uint8Array;
    carrier: RetainedSeedMailboxSenderStreamCarrier;
    context: SeedMailboxSenderStreamCustodyContext &
        Readonly<{ recipientPosition: number }>;
    geometry: SeedMailboxSenderStreamGeometry;
}>;

export type SeedMailboxSenderStreamKernel = Readonly<{
    produce(
        input: SeedMailboxSenderStreamProductionInput,
    ):
        | Promise<RetainedSeedMailboxSenderStreamCarrier>
        | RetainedSeedMailboxSenderStreamCarrier;
    validate(
        input: SeedMailboxSenderStreamValidationInput,
    ): Promise<void> | void;
}>;

type OpenBrowserLocalSeedMailboxSenderStreamKernelInput = Omit<
    OpenProductionSeedMailboxSenderStreamKernelInput,
    'signingOperations'
> &
    Readonly<{ signingCapability: BrowserLocalSigningCapability }>;

/**
 * Binds the fixed-purpose sender-manifest operations to an opaque browser-local
 * signing capability. Rust still verifies the exact output under the
 * terminal-selected roster key before any carrier can leave the adapter.
 */
export const openBrowserLocalSeedMailboxSenderStreamKernel = (
    transcriptCoreKernelUrl: URL,
    input: OpenBrowserLocalSeedMailboxSenderStreamKernelInput,
): Promise<ProductionSeedMailboxSenderStreamKernel> => {
    const signingCapability = input.signingCapability;
    return openProductionSeedMailboxSenderStreamKernel(
        transcriptCoreKernelUrl,
        {
            parameterIdentity: input.parameterIdentity,
            preparationContextBytes: input.preparationContextBytes,
            rootAuthorizationPackages: input.rootAuthorizationPackages,
            rootTerminalCertificateBytes: input.rootTerminalCertificateBytes,
            rosterBytes: input.rosterBytes,
            senderPosition: input.senderPosition,
            signingOperations: Object.freeze({
                assertMatchesSenderVerificationKey: ({
                    senderSigningVerificationKey,
                }): void =>
                    assertSeedMailboxSenderSigningCapabilityMatchesRosterKey({
                        senderSigningVerificationKey,
                        signingCapability,
                    }),
                signManifestBody: ({
                    senderSigningVerificationKey,
                    signatureBodyBytes,
                    signatureRandomness,
                }): Uint8Array =>
                    signSeedMailboxManifestBody({
                        senderSigningVerificationKey,
                        signatureBodyBytes,
                        signatureRandomness,
                        signingCapability,
                    }),
            }),
        },
    );
};

type SeedMailboxSenderStreamCustodyRecordByteLengths = Readonly<{
    completedCiphertextByteLength: number;
    completedPlaintextByteLength: number;
    copyOnWriteCiphertextOverlapByteLength: number;
    reservationCiphertextByteLength: number;
    reservationPlaintextByteLength: number;
}>;

type SeedMailboxSenderRootAuthorizationPackageByteLengths = Readonly<{
    contributorSignatureEnvelopeByteLength: number;
    exactOutputCertificateByteLength: number;
    reservationCertificateByteLength: number;
    rootBodyByteLength: number;
}>;

type SeedMailboxSenderStreamKernelByteLengths = Readonly<{
    closeContextRequestByteLength: number;
    closeContextResponseByteLength: number;
    coldValidationCumulativeRequestByteLength: number;
    coldValidationCumulativeResponseByteLength: number;
    coldValidationInvocationCount: number;
    completeCarrierRequestByteLengthPerStream: number;
    completeCarrierResponseByteLengthPerStream: number;
    maximumRequestByteLength: number;
    maximumResponseByteLength: number;
    openContextRequestByteLength: number;
    openContextResponseByteLength: number;
    prepareCarrierRequestByteLengthPerStream: number;
    prepareCarrierResponseByteLengthPerStream: number;
    signatureBodyByteLengthPerStream: number;
    signatureContextByteLengthPerStream: number;
    signatureRandomnessByteLengthPerStream: number;
    signatureResponseByteLengthPerStream: number;
    signingVerificationKeyByteLengthPerStream: number;
    successfulCumulativeRequestByteLength: number;
    successfulCumulativeResponseByteLength: number;
    successfulInvocationCount: number;
    validateCarrierRequestByteLengthPerStream: number;
    validateCarrierResponseByteLengthPerStream: number;
}>;

export type RetainSeedMailboxSenderStreamInput = Readonly<{
    canonicalDeliveryDescriptorBytes: Uint8Array;
    geometry: SeedMailboxSenderStreamGeometry;
    recipientPosition: number;
    sourcePayloadBytes: Uint8Array;
}>;

type SeedMailboxSenderStreamCoordinate = SeedMailboxSenderStreamCustodyContext &
    Readonly<{
        canonicalDeliveryDescriptorBytes: Uint8Array;
        geometry: SeedMailboxSenderStreamGeometry;
        recipientPosition: number;
        sourcePayloadDigest: Uint8Array;
    }>;

type ReservedSeedMailboxSenderStreamRecord = Readonly<{
    coordinate: SeedMailboxSenderStreamCoordinate;
    encapsulationRandomness: Uint8Array;
    kind: 'reserved';
    signatureRandomness: Uint8Array;
    sourcePayloadBytes: Uint8Array;
}>;

type CompletedSeedMailboxSenderStreamRecord = Readonly<{
    carrier: RetainedSeedMailboxSenderStreamCarrier;
    coordinate: SeedMailboxSenderStreamCoordinate;
    kind: 'completed';
}>;

type SeedMailboxSenderStreamRecord =
    | ReservedSeedMailboxSenderStreamRecord
    | CompletedSeedMailboxSenderStreamRecord;

type OpenedSeedMailboxSenderStreamRecord = Readonly<{
    record: SeedMailboxSenderStreamRecord;
    sealedBytes: Uint8Array;
}>;

const snapshotDataProperty = (
    container: unknown,
    propertyName: string,
    containerName: string,
): unknown => {
    if (
        container === null ||
        (typeof container !== 'object' && typeof container !== 'function')
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName} must be an object.`,
        );
    }
    let descriptor: PropertyDescriptor | undefined;
    try {
        descriptor = Object.getOwnPropertyDescriptor(container, propertyName);
    } catch (error) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must be an ordinary data property.`,
            error,
        );
    }
    if (descriptor === undefined || !('value' in descriptor)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must be an ordinary data property.`,
        );
    }
    return descriptor.value;
};

const requireSafeInteger = (
    value: unknown,
    minimum: number,
    maximum: number,
    label: string,
    code: 'InvalidConfiguration' | 'InvalidInput' = 'InvalidInput',
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < minimum ||
        value > maximum
    ) {
        throw new AuthenticatedRuntimeRecordError(
            code,
            `${label} is outside the supported integer range.`,
        );
    }
    return value;
};

const checkedAdd = (left: number, right: number, label: string): number => {
    const result = left + right;
    if (!Number.isSafeInteger(result) || result > unsigned32Maximum) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the local record length range.`,
        );
    }
    return result;
};

const checkedMultiply = (
    left: number,
    right: number,
    label: string,
): number => {
    const result = left * right;
    if (!Number.isSafeInteger(result) || result > unsigned32Maximum) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the local record length range.`,
        );
    }
    return result;
};

const sumByteLengths = (
    byteLengths: readonly number[],
    label: string,
): number =>
    byteLengths.reduce(
        (total, byteLength) => checkedAdd(total, byteLength, label),
        0,
    );

const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
};

const concatenateBytes = (
    parts: readonly Uint8Array[],
    expectedByteLength: number,
): Uint8Array => {
    const output = new Uint8Array(expectedByteLength);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.byteLength;
    }
    if (offset !== expectedByteLength) {
        output.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Seed-mailbox sender custody encoded an unexpected byte length.',
        );
    }
    return output;
};

const copyGeometry = (
    value: unknown,
    limits?: SeedMailboxSenderStreamCustodyLimits,
): SeedMailboxSenderStreamGeometry => {
    const encryptedChunkByteLengthsValue = snapshotDataProperty(
        value,
        'encryptedChunkByteLengths',
        'geometry',
    );
    if (!Array.isArray(encryptedChunkByteLengthsValue)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'geometry.encryptedChunkByteLengths must be an array.',
        );
    }
    const maximumChunkCount = limits?.maximumEncryptedChunkCount ?? 0xffff;
    const encryptedChunkCount = requireSafeInteger(
        snapshotDataProperty(
            encryptedChunkByteLengthsValue,
            'length',
            'geometry.encryptedChunkByteLengths',
        ),
        1,
        maximumChunkCount,
        'geometry.encryptedChunkByteLengths.length',
    );
    const maximumChunkByteLength =
        limits?.maximumEncryptedChunkByteLength ?? unsigned32Maximum;
    const encryptedChunkByteLengths = Array.from(
        { length: encryptedChunkCount },
        (_unused, chunkIndex) =>
            requireSafeInteger(
                snapshotDataProperty(
                    encryptedChunkByteLengthsValue,
                    String(chunkIndex),
                    'geometry.encryptedChunkByteLengths',
                ),
                1,
                maximumChunkByteLength,
                `geometry.encryptedChunkByteLengths[${chunkIndex}]`,
            ),
    );
    const geometry = Object.freeze({
        encryptedChunkByteLengths: Object.freeze(encryptedChunkByteLengths),
        headerByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'headerByteLength', 'geometry'),
            1,
            limits?.maximumHeaderByteLength ?? unsigned32Maximum,
            'geometry.headerByteLength',
        ),
        manifestByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'manifestByteLength', 'geometry'),
            1,
            limits?.maximumManifestByteLength ?? unsigned32Maximum,
            'geometry.manifestByteLength',
        ),
        signatureEnvelopeByteLength: requireSafeInteger(
            snapshotDataProperty(
                value,
                'signatureEnvelopeByteLength',
                'geometry',
            ),
            1,
            limits?.maximumSignatureEnvelopeByteLength ?? unsigned32Maximum,
            'geometry.signatureEnvelopeByteLength',
        ),
        sourcePayloadByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'sourcePayloadByteLength', 'geometry'),
            1,
            limits?.maximumSourcePayloadByteLength ?? unsigned32Maximum,
            'geometry.sourcePayloadByteLength',
        ),
        totalCarrierByteLength: requireSafeInteger(
            snapshotDataProperty(value, 'totalCarrierByteLength', 'geometry'),
            1,
            unsigned32Maximum,
            'geometry.totalCarrierByteLength',
        ),
    });
    const derivedTotalCarrierByteLength = sumByteLengths(
        [
            geometry.headerByteLength,
            geometry.manifestByteLength,
            geometry.signatureEnvelopeByteLength,
            ...geometry.encryptedChunkByteLengths,
        ],
        'Seed-mailbox sender carrier length',
    );
    if (geometry.totalCarrierByteLength !== derivedTotalCarrierByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Seed-mailbox sender geometry has an inconsistent total carrier byte length.',
        );
    }
    return geometry;
};

const copyContext = (value: unknown): SeedMailboxSenderStreamCustodyContext => {
    const participantCount = requireSafeInteger(
        snapshotDataProperty(value, 'participantCount', 'context'),
        configurableParticipantCountRange.minimum,
        configurableParticipantCountRange.maximum,
        'context.participantCount',
        'InvalidConfiguration',
    );
    const senderPosition = requireSafeInteger(
        snapshotDataProperty(value, 'senderPosition', 'context'),
        0,
        participantCount - 1,
        'context.senderPosition',
        'InvalidConfiguration',
    );
    return Object.freeze({
        parameterIdentity: copyExactBytes(
            snapshotDataProperty(value, 'parameterIdentity', 'context'),
            hashByteLength,
            'context.parameterIdentity',
        ),
        participantCount,
        preparationAttemptOrdinal: requireSafeInteger(
            snapshotDataProperty(value, 'preparationAttemptOrdinal', 'context'),
            0,
            unsigned16Maximum,
            'context.preparationAttemptOrdinal',
            'InvalidConfiguration',
        ),
        preparationContextIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'preparationContextIdentity',
                'context',
            ),
            hashByteLength,
            'context.preparationContextIdentity',
        ),
        rootTerminalIdentity: copyExactBytes(
            snapshotDataProperty(value, 'rootTerminalIdentity', 'context'),
            hashByteLength,
            'context.rootTerminalIdentity',
        ),
        senderPosition,
    });
};

const maximumRecordPlaintextByteLengths = (
    limits: SeedMailboxSenderStreamCustodyLimits,
): Readonly<{ completed: number; reservation: number }> => {
    const maximumChunkCorpusByteLength = checkedMultiply(
        limits.maximumEncryptedChunkCount,
        limits.maximumEncryptedChunkByteLength,
        'Maximum seed-mailbox chunk corpus',
    );
    const maximumChunkLengthTableByteLength = checkedMultiply(
        limits.maximumEncryptedChunkCount,
        4,
        'Maximum seed-mailbox chunk-length table',
    );
    return Object.freeze({
        completed: sumByteLengths(
            [
                299,
                limits.maximumCanonicalDeliveryDescriptorByteLength,
                maximumChunkLengthTableByteLength,
                limits.maximumHeaderByteLength,
                limits.maximumManifestByteLength,
                limits.maximumSignatureEnvelopeByteLength,
                maximumChunkCorpusByteLength,
            ],
            'Maximum seed-mailbox completed record',
        ),
        reservation: sumByteLengths(
            [
                363,
                limits.maximumCanonicalDeliveryDescriptorByteLength,
                maximumChunkLengthTableByteLength,
                limits.maximumSourcePayloadByteLength,
            ],
            'Maximum seed-mailbox reservation record',
        ),
    });
};

const copyLimits = (value: unknown): SeedMailboxSenderStreamCustodyLimits => {
    const readLimit = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(value, propertyName, 'limits'),
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            `limits.${propertyName}`,
            'InvalidConfiguration',
        );
    const limits = Object.freeze({
        maximumCanonicalDeliveryDescriptorByteLength: readLimit(
            'maximumCanonicalDeliveryDescriptorByteLength',
        ),
        maximumEncryptedChunkByteLength: readLimit(
            'maximumEncryptedChunkByteLength',
        ),
        maximumEncryptedChunkCount: readLimit('maximumEncryptedChunkCount'),
        maximumHeaderByteLength: readLimit('maximumHeaderByteLength'),
        maximumManifestByteLength: readLimit('maximumManifestByteLength'),
        maximumSignatureEnvelopeByteLength: readLimit(
            'maximumSignatureEnvelopeByteLength',
        ),
        maximumSourcePayloadByteLength: readLimit(
            'maximumSourcePayloadByteLength',
        ),
        transactionLifetimeMilliseconds: requireSafeInteger(
            snapshotDataProperty(
                value,
                'transactionLifetimeMilliseconds',
                'limits',
            ),
            1,
            Number.MAX_SAFE_INTEGER,
            'limits.transactionLifetimeMilliseconds',
            'InvalidConfiguration',
        ),
    });
    const maximumPlaintextByteLengths =
        maximumRecordPlaintextByteLengths(limits);
    if (
        maximumPlaintextByteLengths.reservation >
            foundationProfile.maximumCopiedBufferByteLength ||
        maximumPlaintextByteLengths.completed >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-mailbox sender custody limits exceed the absolute copied-buffer bound.',
        );
    }
    return limits;
};

export const deriveSeedMailboxSenderStreamCustodyRecordByteLengths = (input: {
    canonicalDeliveryDescriptorByteLength: number;
    geometry: SeedMailboxSenderStreamGeometry;
}): SeedMailboxSenderStreamCustodyRecordByteLengths => {
    const canonicalDeliveryDescriptorByteLength = requireSafeInteger(
        snapshotDataProperty(
            input,
            'canonicalDeliveryDescriptorByteLength',
            'input',
        ),
        1,
        unsigned32Maximum,
        'canonicalDeliveryDescriptorByteLength',
    );
    const geometry = copyGeometry(
        snapshotDataProperty(input, 'geometry', 'input'),
    );
    const chunkLengthTableByteLength = checkedMultiply(
        geometry.encryptedChunkByteLengths.length,
        4,
        'Seed-mailbox chunk-length table',
    );
    const reservationPlaintextByteLength = sumByteLengths(
        [
            363,
            canonicalDeliveryDescriptorByteLength,
            chunkLengthTableByteLength,
            geometry.sourcePayloadByteLength,
        ],
        'Seed-mailbox reservation record',
    );
    const completedPlaintextByteLength = sumByteLengths(
        [
            299,
            canonicalDeliveryDescriptorByteLength,
            chunkLengthTableByteLength,
            geometry.totalCarrierByteLength,
        ],
        'Seed-mailbox completed record',
    );
    const reservationCiphertextByteLength = checkedAdd(
        reservationPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-mailbox reservation ciphertext',
    );
    const completedCiphertextByteLength = checkedAdd(
        completedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-mailbox completed ciphertext',
    );
    return Object.freeze({
        completedCiphertextByteLength,
        completedPlaintextByteLength,
        copyOnWriteCiphertextOverlapByteLength: checkedAdd(
            reservationCiphertextByteLength,
            completedCiphertextByteLength,
            'Seed-mailbox copy-on-write ciphertext overlap',
        ),
        reservationCiphertextByteLength,
        reservationPlaintextByteLength,
    });
};

export const deriveSeedMailboxSenderStreamKernelByteLengths = (input: {
    canonicalDeliveryDescriptorByteLength: number;
    geometry: SeedMailboxSenderStreamGeometry;
    preparationContextByteLength: number;
    rootAuthorizationPackages: readonly SeedMailboxSenderRootAuthorizationPackageByteLengths[];
    rootTerminalCertificateByteLength: number;
    rosterByteLength: number;
    streamCount: number;
}): SeedMailboxSenderStreamKernelByteLengths => {
    const canonicalDeliveryDescriptorByteLength = requireSafeInteger(
        snapshotDataProperty(
            input,
            'canonicalDeliveryDescriptorByteLength',
            'input',
        ),
        1,
        unsigned32Maximum,
        'canonicalDeliveryDescriptorByteLength',
    );
    const preparationContextByteLength = requireSafeInteger(
        snapshotDataProperty(input, 'preparationContextByteLength', 'input'),
        1,
        unsigned32Maximum,
        'preparationContextByteLength',
    );
    const rosterByteLength = requireSafeInteger(
        snapshotDataProperty(input, 'rosterByteLength', 'input'),
        1,
        unsigned32Maximum,
        'rosterByteLength',
    );
    const rootTerminalCertificateByteLength = requireSafeInteger(
        snapshotDataProperty(
            input,
            'rootTerminalCertificateByteLength',
            'input',
        ),
        1,
        unsigned32Maximum,
        'rootTerminalCertificateByteLength',
    );
    const streamCount = requireSafeInteger(
        snapshotDataProperty(input, 'streamCount', 'input'),
        1,
        unsigned16Maximum,
        'streamCount',
    );
    const geometry = copyGeometry(
        snapshotDataProperty(input, 'geometry', 'input'),
    );
    const rootAuthorizationPackagesValue = snapshotDataProperty(
        input,
        'rootAuthorizationPackages',
        'input',
    );
    if (
        !Array.isArray(rootAuthorizationPackagesValue) ||
        rootAuthorizationPackagesValue.length === 0 ||
        rootAuthorizationPackagesValue.length > unsigned16Maximum
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'rootAuthorizationPackages must be a bounded nonempty array.',
        );
    }
    const readPackageByteLength = (
        packageValue: unknown,
        propertyName: keyof SeedMailboxSenderRootAuthorizationPackageByteLengths,
        packageIndex: number,
    ): number =>
        requireSafeInteger(
            snapshotDataProperty(
                packageValue,
                propertyName,
                `rootAuthorizationPackages[${packageIndex}]`,
            ),
            1,
            unsigned32Maximum,
            `rootAuthorizationPackages[${packageIndex}].${propertyName}`,
        );
    const rootPackageCorpusByteLength = sumByteLengths(
        rootAuthorizationPackagesValue.map((packageValue, packageIndex) =>
            sumByteLengths(
                [
                    4,
                    readPackageByteLength(
                        packageValue,
                        'rootBodyByteLength',
                        packageIndex,
                    ),
                    4,
                    readPackageByteLength(
                        packageValue,
                        'reservationCertificateByteLength',
                        packageIndex,
                    ),
                    4,
                    readPackageByteLength(
                        packageValue,
                        'exactOutputCertificateByteLength',
                        packageIndex,
                    ),
                    4,
                    readPackageByteLength(
                        packageValue,
                        'contributorSignatureEnvelopeByteLength',
                        packageIndex,
                    ),
                ],
                `Sender-mailbox root package ${packageIndex}`,
            ),
        ),
        'Sender-mailbox root-package corpus',
    );
    const chunkCount = geometry.encryptedChunkByteLengths.length;
    const chunkLengthTableByteLength = checkedMultiply(
        chunkCount,
        4,
        'Sender-mailbox kernel chunk-length table',
    );
    const encryptedChunkCorpusByteLength = sumByteLengths(
        geometry.encryptedChunkByteLengths,
        'Sender-mailbox encrypted chunk corpus',
    );
    const openContextRequestByteLength = sumByteLengths(
        [
            7,
            hashByteLength,
            2,
            4,
            preparationContextByteLength,
            4,
            rosterByteLength,
            2,
            rootPackageCorpusByteLength,
            4,
            rootTerminalCertificateByteLength,
        ],
        'Sender-mailbox open-context request',
    );
    const openContextResponseByteLength = 7 + 4 + 1_952;
    const prepareCarrierRequestByteLengthPerStream = sumByteLengths(
        [
            251,
            canonicalDeliveryDescriptorByteLength,
            geometry.sourcePayloadByteLength,
        ],
        'Sender-mailbox prepare-carrier request',
    );
    const prepareCarrierResponseByteLengthPerStream = sumByteLengths(
        [
            7 + 4 * 3 + 2,
            geometry.headerByteLength,
            geometry.manifestByteLength,
            309,
            chunkLengthTableByteLength,
            encryptedChunkCorpusByteLength,
        ],
        'Sender-mailbox prepare-carrier response',
    );
    const completeCarrierRequestByteLengthPerStream = sumByteLengths(
        [
            211,
            4,
            canonicalDeliveryDescriptorByteLength,
            4,
            geometry.headerByteLength,
            4,
            geometry.manifestByteLength,
            2,
            chunkLengthTableByteLength,
            encryptedChunkCorpusByteLength,
            3_309,
        ],
        'Sender-mailbox complete-carrier request',
    );
    const completeCarrierResponseByteLengthPerStream = sumByteLengths(
        [
            7 + 4 * 3 + 2,
            chunkLengthTableByteLength,
            geometry.totalCarrierByteLength,
        ],
        'Sender-mailbox complete-carrier response',
    );
    const validateCarrierRequestByteLengthPerStream = sumByteLengths(
        [
            211,
            4,
            canonicalDeliveryDescriptorByteLength,
            5 * 4 + 2,
            chunkLengthTableByteLength,
            4 * 3 + 2,
            chunkLengthTableByteLength,
            geometry.totalCarrierByteLength,
        ],
        'Sender-mailbox validate-carrier request',
    );
    const validateCarrierResponseByteLengthPerStream = 7;
    const closeContextRequestByteLength = 11;
    const closeContextResponseByteLength = 7;
    const maximumRequestByteLength = Math.max(
        openContextRequestByteLength,
        prepareCarrierRequestByteLengthPerStream,
        completeCarrierRequestByteLengthPerStream,
        validateCarrierRequestByteLengthPerStream,
        closeContextRequestByteLength,
    );
    const maximumResponseByteLength = Math.max(
        openContextResponseByteLength,
        prepareCarrierResponseByteLengthPerStream,
        completeCarrierResponseByteLengthPerStream,
        validateCarrierResponseByteLengthPerStream,
        closeContextResponseByteLength,
    );
    if (
        maximumRequestByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        maximumResponseByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Sender-mailbox kernel geometry exceeds the absolute copied-buffer bound.',
        );
    }
    const successfulRequestByteLengthPerStream = sumByteLengths(
        [
            prepareCarrierRequestByteLengthPerStream,
            completeCarrierRequestByteLengthPerStream,
            validateCarrierRequestByteLengthPerStream,
        ],
        'Sender-mailbox successful requests per stream',
    );
    const successfulResponseByteLengthPerStream = sumByteLengths(
        [
            prepareCarrierResponseByteLengthPerStream,
            completeCarrierResponseByteLengthPerStream,
            validateCarrierResponseByteLengthPerStream,
        ],
        'Sender-mailbox successful responses per stream',
    );
    return Object.freeze({
        closeContextRequestByteLength,
        closeContextResponseByteLength,
        coldValidationCumulativeRequestByteLength: sumByteLengths(
            [
                openContextRequestByteLength,
                checkedMultiply(
                    streamCount,
                    validateCarrierRequestByteLengthPerStream,
                    'Sender-mailbox cold-validation requests',
                ),
                closeContextRequestByteLength,
            ],
            'Sender-mailbox cold-validation cumulative request',
        ),
        coldValidationCumulativeResponseByteLength: sumByteLengths(
            [
                openContextResponseByteLength,
                checkedMultiply(
                    streamCount,
                    validateCarrierResponseByteLengthPerStream,
                    'Sender-mailbox cold-validation responses',
                ),
                closeContextResponseByteLength,
            ],
            'Sender-mailbox cold-validation cumulative response',
        ),
        coldValidationInvocationCount: checkedAdd(
            streamCount,
            2,
            'Sender-mailbox cold-validation invocation count',
        ),
        completeCarrierRequestByteLengthPerStream,
        completeCarrierResponseByteLengthPerStream,
        maximumRequestByteLength,
        maximumResponseByteLength,
        openContextRequestByteLength,
        openContextResponseByteLength,
        prepareCarrierRequestByteLengthPerStream,
        prepareCarrierResponseByteLengthPerStream,
        signatureBodyByteLengthPerStream: 309,
        signatureContextByteLengthPerStream: 51,
        signatureRandomnessByteLengthPerStream: 32,
        signatureResponseByteLengthPerStream: 3_309,
        signingVerificationKeyByteLengthPerStream: 1_952,
        successfulCumulativeRequestByteLength: sumByteLengths(
            [
                openContextRequestByteLength,
                checkedMultiply(
                    streamCount,
                    successfulRequestByteLengthPerStream,
                    'Sender-mailbox successful request corpus',
                ),
                closeContextRequestByteLength,
            ],
            'Sender-mailbox successful cumulative request',
        ),
        successfulCumulativeResponseByteLength: sumByteLengths(
            [
                openContextResponseByteLength,
                checkedMultiply(
                    streamCount,
                    successfulResponseByteLengthPerStream,
                    'Sender-mailbox successful response corpus',
                ),
                closeContextResponseByteLength,
            ],
            'Sender-mailbox successful cumulative response',
        ),
        successfulInvocationCount: checkedAdd(
            checkedMultiply(
                streamCount,
                3,
                'Sender-mailbox successful stream invocation count',
            ),
            2,
            'Sender-mailbox successful invocation count',
        ),
        validateCarrierRequestByteLengthPerStream,
        validateCarrierResponseByteLengthPerStream,
    });
};

const geometryEquals = (
    left: SeedMailboxSenderStreamGeometry,
    right: SeedMailboxSenderStreamGeometry,
): boolean =>
    left.headerByteLength === right.headerByteLength &&
    left.manifestByteLength === right.manifestByteLength &&
    left.signatureEnvelopeByteLength === right.signatureEnvelopeByteLength &&
    left.sourcePayloadByteLength === right.sourcePayloadByteLength &&
    left.totalCarrierByteLength === right.totalCarrierByteLength &&
    left.encryptedChunkByteLengths.length ===
        right.encryptedChunkByteLengths.length &&
    left.encryptedChunkByteLengths.every(
        (byteLength, chunkIndex) =>
            byteLength === right.encryptedChunkByteLengths[chunkIndex],
    );

const copyCoordinate = (
    coordinate: SeedMailboxSenderStreamCoordinate,
): SeedMailboxSenderStreamCoordinate =>
    Object.freeze({
        canonicalDeliveryDescriptorBytes:
            coordinate.canonicalDeliveryDescriptorBytes.slice(),
        geometry: Object.freeze({
            ...coordinate.geometry,
            encryptedChunkByteLengths: Object.freeze([
                ...coordinate.geometry.encryptedChunkByteLengths,
            ]),
        }),
        parameterIdentity: coordinate.parameterIdentity.slice(),
        participantCount: coordinate.participantCount,
        preparationAttemptOrdinal: coordinate.preparationAttemptOrdinal,
        preparationContextIdentity:
            coordinate.preparationContextIdentity.slice(),
        recipientPosition: coordinate.recipientPosition,
        rootTerminalIdentity: coordinate.rootTerminalIdentity.slice(),
        senderPosition: coordinate.senderPosition,
        sourcePayloadDigest: coordinate.sourcePayloadDigest.slice(),
    });

const destroyCoordinate = (
    coordinate: SeedMailboxSenderStreamCoordinate | undefined,
): void => {
    coordinate?.canonicalDeliveryDescriptorBytes.fill(0);
    coordinate?.parameterIdentity.fill(0);
    coordinate?.preparationContextIdentity.fill(0);
    coordinate?.rootTerminalIdentity.fill(0);
    coordinate?.sourcePayloadDigest.fill(0);
};

const coordinateEquals = (
    left: SeedMailboxSenderStreamCoordinate,
    right: SeedMailboxSenderStreamCoordinate,
): boolean =>
    left.participantCount === right.participantCount &&
    left.preparationAttemptOrdinal === right.preparationAttemptOrdinal &&
    left.recipientPosition === right.recipientPosition &&
    left.senderPosition === right.senderPosition &&
    bytesEqual(left.parameterIdentity, right.parameterIdentity) &&
    bytesEqual(
        left.preparationContextIdentity,
        right.preparationContextIdentity,
    ) &&
    bytesEqual(left.rootTerminalIdentity, right.rootTerminalIdentity) &&
    bytesEqual(left.sourcePayloadDigest, right.sourcePayloadDigest) &&
    bytesEqual(
        left.canonicalDeliveryDescriptorBytes,
        right.canonicalDeliveryDescriptorBytes,
    ) &&
    geometryEquals(left.geometry, right.geometry);

const copyCarrier = (
    carrier: RetainedSeedMailboxSenderStreamCarrier,
): RetainedSeedMailboxSenderStreamCarrier =>
    Object.freeze({
        encryptedChunks: Object.freeze(
            carrier.encryptedChunks.map((chunk) => chunk.slice()),
        ),
        headerBytes: carrier.headerBytes.slice(),
        manifestBytes: carrier.manifestBytes.slice(),
        signatureEnvelopeBytes: carrier.signatureEnvelopeBytes.slice(),
    });

const destroyCarrier = (
    carrier: RetainedSeedMailboxSenderStreamCarrier | undefined,
): void => {
    carrier?.headerBytes.fill(0);
    carrier?.manifestBytes.fill(0);
    carrier?.signatureEnvelopeBytes.fill(0);
    carrier?.encryptedChunks.forEach((chunk) => chunk.fill(0));
};

const carriersEqual = (
    left: RetainedSeedMailboxSenderStreamCarrier,
    right: RetainedSeedMailboxSenderStreamCarrier,
): boolean =>
    bytesEqual(left.headerBytes, right.headerBytes) &&
    bytesEqual(left.manifestBytes, right.manifestBytes) &&
    bytesEqual(left.signatureEnvelopeBytes, right.signatureEnvelopeBytes) &&
    left.encryptedChunks.length === right.encryptedChunks.length &&
    left.encryptedChunks.every((chunk, chunkIndex) =>
        bytesEqual(chunk, right.encryptedChunks[chunkIndex]),
    );

const snapshotCarrier = (
    value: unknown,
    geometry: SeedMailboxSenderStreamGeometry,
): RetainedSeedMailboxSenderStreamCarrier => {
    const encryptedChunksValue = snapshotDataProperty(
        value,
        'encryptedChunks',
        'carrier',
    );
    if (!Array.isArray(encryptedChunksValue)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'carrier.encryptedChunks must be an array.',
        );
    }
    const encryptedChunkCount = requireSafeInteger(
        snapshotDataProperty(
            encryptedChunksValue,
            'length',
            'carrier.encryptedChunks',
        ),
        geometry.encryptedChunkByteLengths.length,
        geometry.encryptedChunkByteLengths.length,
        'carrier.encryptedChunks.length',
    );
    const copyCarrierPart = (
        container: unknown,
        propertyName: string,
        expectedByteLength: number,
        containerName: string,
    ): Uint8Array =>
        copyExactBytes(
            snapshotDataProperty(container, propertyName, containerName),
            expectedByteLength,
            `${containerName}.${propertyName}`,
        );
    return Object.freeze({
        encryptedChunks: Object.freeze(
            Array.from({ length: encryptedChunkCount }, (_unused, chunkIndex) =>
                copyCarrierPart(
                    encryptedChunksValue,
                    String(chunkIndex),
                    geometry.encryptedChunkByteLengths[chunkIndex] ?? 0,
                    'carrier.encryptedChunks',
                ),
            ),
        ),
        headerBytes: copyCarrierPart(
            value,
            'headerBytes',
            geometry.headerByteLength,
            'carrier',
        ),
        manifestBytes: copyCarrierPart(
            value,
            'manifestBytes',
            geometry.manifestByteLength,
            'carrier',
        ),
        signatureEnvelopeBytes: copyCarrierPart(
            value,
            'signatureEnvelopeBytes',
            geometry.signatureEnvelopeByteLength,
            'carrier',
        ),
    });
};

const deriveSourcePayloadDigest = (
    sourcePayloadBytes: Uint8Array,
): Uint8Array => {
    const domainBytes = textEncoder.encode(senderStreamSourceDigestDomain);
    const hasher = shake256.create({ dkLen: hashByteLength });
    hasher.update(unsigned32LittleEndian(domainBytes.byteLength));
    hasher.update(domainBytes);
    hasher.update(unsigned32LittleEndian(sourcePayloadBytes.byteLength));
    hasher.update(sourcePayloadBytes);
    return Uint8Array.from(hasher.digest());
};

const logicalRecordKey = (
    context: SeedMailboxSenderStreamCustodyContext,
    recipientPosition: number,
): string =>
    `seed-mailbox/sender-stream/${context.preparationAttemptOrdinal
        .toString(10)
        .padStart(5, '0')}/${context.senderPosition
        .toString(10)
        .padStart(5, '0')}/${recipientPosition.toString(10).padStart(5, '0')}`;

const encodeCoordinateParts = (
    coordinate: SeedMailboxSenderStreamCoordinate,
): readonly Uint8Array[] => [
    coordinate.parameterIdentity,
    coordinate.preparationContextIdentity,
    coordinate.rootTerminalIdentity,
    unsigned16LittleEndian(coordinate.preparationAttemptOrdinal),
    unsigned16LittleEndian(coordinate.participantCount),
    unsigned16LittleEndian(coordinate.senderPosition),
    unsigned16LittleEndian(coordinate.recipientPosition),
    coordinate.sourcePayloadDigest,
    unsigned32LittleEndian(
        coordinate.canonicalDeliveryDescriptorBytes.byteLength,
    ),
    coordinate.canonicalDeliveryDescriptorBytes,
    unsigned32LittleEndian(coordinate.geometry.sourcePayloadByteLength),
    unsigned32LittleEndian(coordinate.geometry.headerByteLength),
    unsigned32LittleEndian(coordinate.geometry.manifestByteLength),
    unsigned32LittleEndian(coordinate.geometry.signatureEnvelopeByteLength),
    unsigned32LittleEndian(coordinate.geometry.totalCarrierByteLength),
    unsigned32LittleEndian(
        coordinate.geometry.encryptedChunkByteLengths.length,
    ),
    ...coordinate.geometry.encryptedChunkByteLengths.map(
        unsigned32LittleEndian,
    ),
];

const encodeRecord = (record: SeedMailboxSenderStreamRecord): Uint8Array => {
    const byteLengths = deriveSeedMailboxSenderStreamCustodyRecordByteLengths({
        canonicalDeliveryDescriptorByteLength:
            record.coordinate.canonicalDeliveryDescriptorBytes.byteLength,
        geometry: record.coordinate.geometry,
    });
    const prefix = [
        senderStreamCustodyRecordMagic,
        unsigned16LittleEndian(senderStreamCustodyRecordVersion),
        Uint8Array.of(
            record.kind === 'reserved'
                ? reservedRecordKind
                : completedRecordKind,
        ),
        ...encodeCoordinateParts(record.coordinate),
    ];
    if (record.kind === 'reserved') {
        return concatenateBytes(
            [
                ...prefix,
                record.sourcePayloadBytes,
                record.encapsulationRandomness,
                record.signatureRandomness,
            ],
            byteLengths.reservationPlaintextByteLength,
        );
    }
    return concatenateBytes(
        [
            ...prefix,
            record.carrier.headerBytes,
            record.carrier.manifestBytes,
            record.carrier.signatureEnvelopeBytes,
            ...record.carrier.encryptedChunks,
        ],
        byteLengths.completedPlaintextByteLength,
    );
};

class BoundedRecordCursor {
    readonly #bytes: Uint8Array;
    #offset = 0;

    public constructor(bytes: Uint8Array) {
        this.#bytes = bytes;
    }

    public readExact(byteLength: number, label: string): Uint8Array {
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > this.#bytes.byteLength - this.#offset
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                `Seed-mailbox sender custody record ends within ${label}.`,
            );
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;
        return value;
    }

    public readUnsigned8(label: string): number {
        const bytes = this.readExact(1, label);
        try {
            return bytes[0] ?? 0;
        } finally {
            bytes.fill(0);
        }
    }

    public readUnsigned16(label: string): number {
        const bytes = this.readExact(2, label);
        try {
            return new DataView(
                bytes.buffer,
                bytes.byteOffset,
                bytes.byteLength,
            ).getUint16(0, true);
        } finally {
            bytes.fill(0);
        }
    }

    public readUnsigned32(label: string): number {
        const bytes = this.readExact(4, label);
        try {
            return new DataView(
                bytes.buffer,
                bytes.byteOffset,
                bytes.byteLength,
            ).getUint32(0, true);
        } finally {
            bytes.fill(0);
        }
    }

    public requireComplete(): void {
        if (this.#offset !== this.#bytes.byteLength) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-mailbox sender custody record has trailing bytes.',
            );
        }
    }
}

const decodeRecord = (
    plaintext: Uint8Array,
    limits: SeedMailboxSenderStreamCustodyLimits,
): SeedMailboxSenderStreamRecord => {
    const maximumPlaintextByteLengths =
        maximumRecordPlaintextByteLengths(limits);
    if (
        plaintext.byteLength >
        Math.max(
            maximumPlaintextByteLengths.reservation,
            maximumPlaintextByteLengths.completed,
        )
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-mailbox sender custody record exceeds its configured byte bound.',
        );
    }
    const cursor = new BoundedRecordCursor(plaintext);
    const magic = cursor.readExact(
        senderStreamCustodyRecordMagic.byteLength,
        'record magic',
    );
    try {
        if (!bytesEqual(magic, senderStreamCustodyRecordMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-mailbox sender custody record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (
        cursor.readUnsigned16('record version') !==
        senderStreamCustodyRecordVersion
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-mailbox sender custody record has an unsupported version.',
        );
    }
    const recordKind = cursor.readUnsigned8('record kind');
    if (
        recordKind !== reservedRecordKind &&
        recordKind !== completedRecordKind
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-mailbox sender custody record has an invalid kind.',
        );
    }
    const parameterIdentity = cursor.readExact(
        hashByteLength,
        'parameter identity',
    );
    const preparationContextIdentity = cursor.readExact(
        hashByteLength,
        'preparation-context identity',
    );
    const rootTerminalIdentity = cursor.readExact(
        hashByteLength,
        'root-terminal identity',
    );
    const preparationAttemptOrdinal = cursor.readUnsigned16(
        'preparation-attempt ordinal',
    );
    const participantCount = cursor.readUnsigned16('participant count');
    const senderPosition = cursor.readUnsigned16('sender position');
    const recipientPosition = cursor.readUnsigned16('recipient position');
    const sourcePayloadDigest = cursor.readExact(
        hashByteLength,
        'source-payload digest',
    );
    const canonicalDeliveryDescriptorByteLength = requireSafeInteger(
        cursor.readUnsigned32('delivery-descriptor byte length'),
        1,
        limits.maximumCanonicalDeliveryDescriptorByteLength,
        'Stored canonical delivery descriptor byte length',
    );
    const canonicalDeliveryDescriptorBytes = cursor.readExact(
        canonicalDeliveryDescriptorByteLength,
        'canonical delivery descriptor',
    );
    const sourcePayloadByteLength = cursor.readUnsigned32(
        'source-payload byte length',
    );
    const headerByteLength = cursor.readUnsigned32('header byte length');
    const manifestByteLength = cursor.readUnsigned32('manifest byte length');
    const signatureEnvelopeByteLength = cursor.readUnsigned32(
        'signature-envelope byte length',
    );
    const totalCarrierByteLength = cursor.readUnsigned32(
        'total-carrier byte length',
    );
    const encryptedChunkCount = requireSafeInteger(
        cursor.readUnsigned32('encrypted-chunk count'),
        1,
        limits.maximumEncryptedChunkCount,
        'Stored encrypted-chunk count',
    );
    const encryptedChunkByteLengths = Array.from(
        { length: encryptedChunkCount },
        (_unused, chunkIndex) =>
            cursor.readUnsigned32(`encrypted-chunk ${chunkIndex} byte length`),
    );
    let geometry: SeedMailboxSenderStreamGeometry;
    try {
        geometry = copyGeometry(
            {
                encryptedChunkByteLengths,
                headerByteLength,
                manifestByteLength,
                signatureEnvelopeByteLength,
                sourcePayloadByteLength,
                totalCarrierByteLength,
            },
            limits,
        );
    } catch (error) {
        parameterIdentity.fill(0);
        preparationContextIdentity.fill(0);
        rootTerminalIdentity.fill(0);
        sourcePayloadDigest.fill(0);
        canonicalDeliveryDescriptorBytes.fill(0);
        if (error instanceof AuthenticatedRuntimeRecordError) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-mailbox sender custody record has invalid geometry.',
                error,
            );
        }
        throw error;
    }
    const coordinate: SeedMailboxSenderStreamCoordinate = Object.freeze({
        canonicalDeliveryDescriptorBytes,
        geometry,
        parameterIdentity,
        participantCount,
        preparationAttemptOrdinal,
        preparationContextIdentity,
        recipientPosition,
        rootTerminalIdentity,
        senderPosition,
        sourcePayloadDigest,
    });
    try {
        if (
            participantCount < configurableParticipantCountRange.minimum ||
            participantCount > configurableParticipantCountRange.maximum ||
            senderPosition >= participantCount ||
            recipientPosition >= participantCount ||
            senderPosition === recipientPosition
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-mailbox sender custody record has invalid roster coordinates.',
            );
        }
        if (recordKind === reservedRecordKind) {
            let sourcePayloadBytes: Uint8Array | undefined;
            let encapsulationRandomness: Uint8Array | undefined;
            let signatureRandomness: Uint8Array | undefined;
            let recomputedSourcePayloadDigest: Uint8Array | undefined;
            try {
                sourcePayloadBytes = cursor.readExact(
                    geometry.sourcePayloadByteLength,
                    'source payload',
                );
                encapsulationRandomness = cursor.readExact(
                    randomnessByteLength,
                    'encapsulation randomness',
                );
                signatureRandomness = cursor.readExact(
                    randomnessByteLength,
                    'signature randomness',
                );
                cursor.requireComplete();
                if (
                    encapsulationRandomness.every((byte) => byte === 0) ||
                    signatureRandomness.every((byte) => byte === 0) ||
                    bytesEqual(encapsulationRandomness, signatureRandomness)
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Seed-mailbox sender custody record has invalid or reused randomness.',
                    );
                }
                recomputedSourcePayloadDigest =
                    deriveSourcePayloadDigest(sourcePayloadBytes);
                if (
                    !bytesEqual(
                        sourcePayloadDigest,
                        recomputedSourcePayloadDigest,
                    )
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Seed-mailbox sender custody source payload has the wrong digest.',
                    );
                }
                const record = Object.freeze({
                    coordinate,
                    encapsulationRandomness,
                    kind: 'reserved' as const,
                    signatureRandomness,
                    sourcePayloadBytes,
                });
                sourcePayloadBytes = undefined;
                encapsulationRandomness = undefined;
                signatureRandomness = undefined;
                return record;
            } finally {
                sourcePayloadBytes?.fill(0);
                encapsulationRandomness?.fill(0);
                signatureRandomness?.fill(0);
                recomputedSourcePayloadDigest?.fill(0);
            }
        }
        let headerBytes: Uint8Array | undefined;
        let manifestBytes: Uint8Array | undefined;
        let signatureEnvelopeBytes: Uint8Array | undefined;
        let encryptedChunks: Uint8Array[] | undefined;
        try {
            headerBytes = cursor.readExact(
                geometry.headerByteLength,
                'header bytes',
            );
            manifestBytes = cursor.readExact(
                geometry.manifestByteLength,
                'manifest bytes',
            );
            signatureEnvelopeBytes = cursor.readExact(
                geometry.signatureEnvelopeByteLength,
                'signature-envelope bytes',
            );
            encryptedChunks = geometry.encryptedChunkByteLengths.map(
                (byteLength, chunkIndex) =>
                    cursor.readExact(
                        byteLength,
                        `encrypted chunk ${chunkIndex}`,
                    ),
            );
            cursor.requireComplete();
            const carrier = Object.freeze({
                encryptedChunks: Object.freeze(encryptedChunks),
                headerBytes,
                manifestBytes,
                signatureEnvelopeBytes,
            });
            headerBytes = undefined;
            manifestBytes = undefined;
            signatureEnvelopeBytes = undefined;
            encryptedChunks = undefined;
            return Object.freeze({
                carrier,
                coordinate,
                kind: 'completed' as const,
            });
        } finally {
            headerBytes?.fill(0);
            manifestBytes?.fill(0);
            signatureEnvelopeBytes?.fill(0);
            encryptedChunks?.forEach((chunk) => chunk.fill(0));
        }
    } catch (error) {
        destroyCoordinate(coordinate);
        throw error;
    }
};

const destroyRecord = (
    record: SeedMailboxSenderStreamRecord | undefined,
): void => {
    if (record === undefined) {
        return;
    }
    destroyCoordinate(record.coordinate);
    if (record.kind === 'reserved') {
        record.encapsulationRandomness.fill(0);
        record.signatureRandomness.fill(0);
        record.sourcePayloadBytes.fill(0);
    } else {
        destroyCarrier(record.carrier);
    }
};

const readRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: SeedMailboxSenderStreamCustodyLimits,
): Promise<OpenedSeedMailboxSenderStreamRecord | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: seedMailboxSenderStreamCustodyOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        const record = decodeRecord(opened.plaintext, limits);
        return Object.freeze({
            record,
            sealedBytes: opened.sealedBytes.slice(),
        });
    } finally {
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

const closeTransactionAfterFailure = async (
    transaction: UntrustedStorageTransaction,
    operationFailure: unknown,
): Promise<AuthenticatedRuntimeRecordError> => {
    const mappedOperationFailure = mapStorageError(operationFailure);
    try {
        await transaction.closeAfterFailure();
    } catch (closeFailure) {
        throw new AuthenticatedRuntimeRecordError(
            'CleanupFailed',
            'Seed-mailbox sender custody failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const commitRecord = async (input: {
    expectedCurrentSealedBytes: Uint8Array | null;
    limits: SeedMailboxSenderStreamCustodyLimits;
    protection: RuntimeRecordProtection;
    record: SeedMailboxSenderStreamRecord;
    recordKey: string;
    store: UntrustedStorageTransactionStore;
}): Promise<Uint8Array> => {
    const plaintext = encodeRecord(input.record);
    const transaction = await input.store.beginTransaction({
        lifetimeMilliseconds: input.limits.transactionLifetimeMilliseconds,
    });
    let stagedSealedBytes: Uint8Array | undefined;
    try {
        stagedSealedBytes = await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: input.expectedCurrentSealedBytes,
            logicalRecordKey: input.recordKey,
            operationDomain: seedMailboxSenderStreamCustodyOperationDomain,
            plaintext,
            protection: input.protection,
            transaction,
        });
        await transaction.commit();
        return stagedSealedBytes.slice();
    } catch (error) {
        throw await closeTransactionAfterFailure(transaction, error);
    } finally {
        plaintext.fill(0);
        stagedSealedBytes?.fill(0);
    }
};

const errorHasCode = (error: unknown, code: string): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code;

const copyValidationContext = (
    coordinate: SeedMailboxSenderStreamCoordinate,
): SeedMailboxSenderStreamCustodyContext &
    Readonly<{ recipientPosition: number }> =>
    Object.freeze({
        parameterIdentity: coordinate.parameterIdentity.slice(),
        participantCount: coordinate.participantCount,
        preparationAttemptOrdinal: coordinate.preparationAttemptOrdinal,
        preparationContextIdentity:
            coordinate.preparationContextIdentity.slice(),
        recipientPosition: coordinate.recipientPosition,
        rootTerminalIdentity: coordinate.rootTerminalIdentity.slice(),
        senderPosition: coordinate.senderPosition,
    });

/**
 * Owns persist-before-publish replay state for one sender's ordered seed
 * mailbox streams. The stable record key excludes the selected root terminal
 * and all carrier bytes, so a competing semantic body cannot obtain another
 * local slot for the same action, sender, recipient, and attempt.
 *
 * The supplied kernel is an internal generation and structural-validation
 * boundary. This class never accepts caller-supplied randomness, never returns
 * a carrier before its completed encrypted record is recency-anchored, and
 * never creates a protocol acceptance capability.
 */
export class SeedMailboxSenderStreamCustody {
    readonly #context: SeedMailboxSenderStreamCustodyContext;
    readonly #issuedRandomness = new Set<string>();
    readonly #kernel: SeedMailboxSenderStreamKernel;
    readonly #limits: SeedMailboxSenderStreamCustodyLimits;
    readonly #protection: RuntimeRecordProtection;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        context: SeedMailboxSenderStreamCustodyContext;
        kernel: ProductionSeedMailboxSenderStreamKernel;
        limits: SeedMailboxSenderStreamCustodyLimits;
        protection: RuntimeRecordProtection;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    }) {
        if (!isProductionSeedMailboxSenderStreamKernel(input.kernel)) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-mailbox sender custody requires the integrity-pinned production kernel.',
            );
        }
        if (
            !(
                input.recencyCoordinator instanceof
                AuthenticatedStorageRecencyCoordinator
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-mailbox sender custody requires an authenticated storage recency coordinator.',
            );
        }
        this.#context = copyContext(input.context);
        this.#kernel = input.kernel;
        this.#limits = copyLimits(input.limits);
        this.#protection = input.protection;
        this.#recencyCoordinator = input.recencyCoordinator;
    }

    public retainForPublication(
        input: RetainSeedMailboxSenderStreamInput,
    ): Promise<RetainedSeedMailboxSenderStreamCarrier> {
        const request = this.#snapshotRequest(input);
        const scheduled = this.#operationTail.then(() =>
            this.#retainForPublication(request),
        );
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled.finally(() => {
            destroyCoordinate(request.coordinate);
            request.sourcePayloadBytes.fill(0);
        });
    }

    #snapshotRequest(input: RetainSeedMailboxSenderStreamInput): {
        coordinate: SeedMailboxSenderStreamCoordinate;
        sourcePayloadBytes: Uint8Array;
    } {
        const recipientPosition = requireSafeInteger(
            snapshotDataProperty(input, 'recipientPosition', 'input'),
            0,
            this.#context.participantCount - 1,
            'input.recipientPosition',
        );
        if (recipientPosition === this.#context.senderPosition) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'A seed-mailbox sender stream must target another roster participant.',
            );
        }
        const geometry = copyGeometry(
            snapshotDataProperty(input, 'geometry', 'input'),
            this.#limits,
        );
        const canonicalDeliveryDescriptorBytes = copyBoundedBytes(
            snapshotDataProperty(
                input,
                'canonicalDeliveryDescriptorBytes',
                'input',
            ),
            this.#limits.maximumCanonicalDeliveryDescriptorByteLength,
            'input.canonicalDeliveryDescriptorBytes',
        );
        const sourcePayloadBytes = copyBoundedBytes(
            snapshotDataProperty(input, 'sourcePayloadBytes', 'input'),
            this.#limits.maximumSourcePayloadByteLength,
            'input.sourcePayloadBytes',
        );
        if (
            sourcePayloadBytes.byteLength !== geometry.sourcePayloadByteLength
        ) {
            canonicalDeliveryDescriptorBytes.fill(0);
            sourcePayloadBytes.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'Seed-mailbox source payload does not match the exact stream geometry.',
            );
        }
        const recordByteLengths =
            deriveSeedMailboxSenderStreamCustodyRecordByteLengths({
                canonicalDeliveryDescriptorByteLength:
                    canonicalDeliveryDescriptorBytes.byteLength,
                geometry,
            });
        if (
            recordByteLengths.reservationPlaintextByteLength >
                foundationProfile.maximumCopiedBufferByteLength ||
            recordByteLengths.completedPlaintextByteLength >
                foundationProfile.maximumCopiedBufferByteLength
        ) {
            canonicalDeliveryDescriptorBytes.fill(0);
            sourcePayloadBytes.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                'Seed-mailbox sender custody record exceeds the absolute copied-buffer bound.',
            );
        }
        const sourcePayloadDigest =
            deriveSourcePayloadDigest(sourcePayloadBytes);
        return {
            coordinate: Object.freeze({
                canonicalDeliveryDescriptorBytes,
                geometry,
                parameterIdentity: this.#context.parameterIdentity.slice(),
                participantCount: this.#context.participantCount,
                preparationAttemptOrdinal:
                    this.#context.preparationAttemptOrdinal,
                preparationContextIdentity:
                    this.#context.preparationContextIdentity.slice(),
                recipientPosition,
                rootTerminalIdentity:
                    this.#context.rootTerminalIdentity.slice(),
                senderPosition: this.#context.senderPosition,
                sourcePayloadDigest,
            }),
            sourcePayloadBytes,
        };
    }

    async #retainForPublication(request: {
        coordinate: SeedMailboxSenderStreamCoordinate;
        sourcePayloadBytes: Uint8Array;
    }): Promise<RetainedSeedMailboxSenderStreamCarrier> {
        const recordKey = logicalRecordKey(
            this.#context,
            request.coordinate.recipientPosition,
        );
        let opened = await this.#readOpenedRecord(recordKey);
        if (opened === undefined) {
            opened = await this.#reserve(recordKey, request);
        }
        try {
            this.#requireMatchingRequest(opened.record, request);
            if (opened.record.kind === 'completed') {
                await this.#validateCarrier(
                    opened.record.coordinate,
                    opened.record.carrier,
                );
                return copyCarrier(opened.record.carrier);
            }
            const producedCarrier = await this.#produceCarrier(opened.record);
            try {
                await this.#validateCarrier(
                    opened.record.coordinate,
                    producedCarrier,
                );
                return await this.#completeReservation({
                    producedCarrier,
                    recordKey,
                    request,
                    reservation: opened.record,
                    sealedReservationBytes: opened.sealedBytes,
                });
            } finally {
                destroyCarrier(producedCarrier);
            }
        } finally {
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
        }
    }

    async #readOpenedRecord(
        recordKey: string,
    ): Promise<OpenedSeedMailboxSenderStreamRecord | undefined> {
        return this.#recencyCoordinator.runRead((store) =>
            readRecord(store, this.#protection, recordKey, this.#limits),
        );
    }

    async #reserve(
        recordKey: string,
        request: {
            coordinate: SeedMailboxSenderStreamCoordinate;
            sourcePayloadBytes: Uint8Array;
        },
    ): Promise<OpenedSeedMailboxSenderStreamRecord> {
        let encapsulationRandomness: Uint8Array | undefined;
        let signatureRandomness: Uint8Array | undefined;
        try {
            encapsulationRandomness = sampleRuntimeIdentifier(
                this.#protection,
                this.#issuedRandomness,
                'Seed-mailbox ML-KEM encapsulation randomness',
            );
            signatureRandomness = sampleRuntimeIdentifier(
                this.#protection,
                this.#issuedRandomness,
                'Seed-mailbox ML-DSA signature randomness',
            );
            const reservation: ReservedSeedMailboxSenderStreamRecord =
                Object.freeze({
                    coordinate: copyCoordinate(request.coordinate),
                    encapsulationRandomness: encapsulationRandomness.slice(),
                    kind: 'reserved' as const,
                    signatureRandomness: signatureRandomness.slice(),
                    sourcePayloadBytes: request.sourcePayloadBytes.slice(),
                });
            try {
                let sealedBytes: Uint8Array;
                try {
                    sealedBytes = await this.#recencyCoordinator.runMutation(
                        (store) =>
                            commitRecord({
                                expectedCurrentSealedBytes: null,
                                limits: this.#limits,
                                protection: this.#protection,
                                record: reservation,
                                recordKey,
                                store,
                            }),
                    );
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readOpenedRecord(recordKey);
                    if (existing === undefined) {
                        throw error;
                    }
                    this.#requireMatchingRequest(existing.record, request);
                    return existing;
                }
                return Object.freeze({
                    record: Object.freeze({
                        coordinate: copyCoordinate(reservation.coordinate),
                        encapsulationRandomness:
                            reservation.encapsulationRandomness.slice(),
                        kind: 'reserved' as const,
                        signatureRandomness:
                            reservation.signatureRandomness.slice(),
                        sourcePayloadBytes:
                            reservation.sourcePayloadBytes.slice(),
                    }),
                    sealedBytes,
                });
            } finally {
                destroyRecord(reservation);
            }
        } finally {
            encapsulationRandomness?.fill(0);
            signatureRandomness?.fill(0);
        }
    }

    #requireMatchingRequest(
        record: SeedMailboxSenderStreamRecord,
        request: {
            coordinate: SeedMailboxSenderStreamCoordinate;
            sourcePayloadBytes: Uint8Array;
        },
    ): void {
        if (
            !coordinateEquals(record.coordinate, request.coordinate) ||
            (record.kind === 'reserved' &&
                !bytesEqual(
                    record.sourcePayloadBytes,
                    request.sourcePayloadBytes,
                ))
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The seed-mailbox sender stream slot is durably bound to different bytes.',
            );
        }
    }

    async #produceCarrier(
        reservation: ReservedSeedMailboxSenderStreamRecord,
    ): Promise<RetainedSeedMailboxSenderStreamCarrier> {
        const productionInput: SeedMailboxSenderStreamProductionInput =
            Object.freeze({
                canonicalDeliveryDescriptorBytes:
                    reservation.coordinate.canonicalDeliveryDescriptorBytes.slice(),
                context: copyValidationContext(reservation.coordinate),
                encapsulationRandomness:
                    reservation.encapsulationRandomness.slice(),
                signatureRandomness: reservation.signatureRandomness.slice(),
                sourcePayloadBytes: reservation.sourcePayloadBytes.slice(),
            });
        let productionFailed = false;
        let productionFailure: unknown;
        let produced: unknown;
        try {
            try {
                produced = await this.#kernel.produce(productionInput);
            } catch (error) {
                productionFailed = true;
                productionFailure = error;
            }
            if (productionFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Seed-mailbox sender stream production failed before publication.',
                    productionFailure,
                );
            }
            return snapshotCarrier(produced, reservation.coordinate.geometry);
        } finally {
            productionInput.canonicalDeliveryDescriptorBytes.fill(0);
            productionInput.context.parameterIdentity.fill(0);
            productionInput.context.preparationContextIdentity.fill(0);
            productionInput.context.rootTerminalIdentity.fill(0);
            productionInput.encapsulationRandomness.fill(0);
            productionInput.signatureRandomness.fill(0);
            productionInput.sourcePayloadBytes.fill(0);
        }
    }

    async #validateCarrier(
        coordinate: SeedMailboxSenderStreamCoordinate,
        carrier: RetainedSeedMailboxSenderStreamCarrier,
    ): Promise<void> {
        const validationCarrier = copyCarrier(carrier);
        const validationContext = copyValidationContext(coordinate);
        const validationInput: SeedMailboxSenderStreamValidationInput =
            Object.freeze({
                canonicalDeliveryDescriptorBytes:
                    coordinate.canonicalDeliveryDescriptorBytes.slice(),
                carrier: validationCarrier,
                context: validationContext,
                geometry: Object.freeze({
                    ...coordinate.geometry,
                    encryptedChunkByteLengths: Object.freeze([
                        ...coordinate.geometry.encryptedChunkByteLengths,
                    ]),
                }),
            });
        let validationFailed = false;
        let validationFailure: unknown;
        try {
            try {
                await this.#kernel.validate(validationInput);
            } catch (error) {
                validationFailed = true;
                validationFailure = error;
            }
            if (validationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-mailbox sender stream failed kernel validation.',
                    validationFailure,
                );
            }
        } finally {
            validationInput.canonicalDeliveryDescriptorBytes.fill(0);
            destroyCarrier(validationCarrier);
            validationContext.parameterIdentity.fill(0);
            validationContext.preparationContextIdentity.fill(0);
            validationContext.rootTerminalIdentity.fill(0);
        }
    }

    async #completeReservation(input: {
        producedCarrier: RetainedSeedMailboxSenderStreamCarrier;
        recordKey: string;
        request: {
            coordinate: SeedMailboxSenderStreamCoordinate;
            sourcePayloadBytes: Uint8Array;
        };
        reservation: ReservedSeedMailboxSenderStreamRecord;
        sealedReservationBytes: Uint8Array;
    }): Promise<RetainedSeedMailboxSenderStreamCarrier> {
        const completedRecord: CompletedSeedMailboxSenderStreamRecord =
            Object.freeze({
                carrier: copyCarrier(input.producedCarrier),
                coordinate: copyCoordinate(input.reservation.coordinate),
                kind: 'completed' as const,
            });
        try {
            try {
                const committedSealedBytes =
                    await this.#recencyCoordinator.runMutation((store) =>
                        commitRecord({
                            expectedCurrentSealedBytes:
                                input.sealedReservationBytes,
                            limits: this.#limits,
                            protection: this.#protection,
                            record: completedRecord,
                            recordKey: input.recordKey,
                            store,
                        }),
                    );
                committedSealedBytes.fill(0);
                return copyCarrier(completedRecord.carrier);
            } catch (error) {
                if (!errorHasCode(error, 'Conflict')) {
                    throw error;
                }
                const existing = await this.#readOpenedRecord(input.recordKey);
                if (existing === undefined) {
                    throw error;
                }
                try {
                    this.#requireMatchingRequest(
                        existing.record,
                        input.request,
                    );
                    if (
                        existing.record.kind !== 'completed' ||
                        !carriersEqual(
                            existing.record.carrier,
                            input.producedCarrier,
                        )
                    ) {
                        throw new AuthenticatedRuntimeRecordError(
                            'Conflict',
                            'Concurrent seed-mailbox completion selected different carrier bytes.',
                        );
                    }
                    await this.#validateCarrier(
                        existing.record.coordinate,
                        existing.record.carrier,
                    );
                    return copyCarrier(existing.record.carrier);
                } finally {
                    existing.sealedBytes.fill(0);
                    destroyRecord(existing.record);
                }
            }
        } finally {
            destroyRecord(completedRecord);
        }
    }
}
