import {
    assertSeedReceiptTerminalEndorsementSigningCapabilityMatchesRosterKey,
    signSeedReceiptTerminalEndorsementBody,
    type BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';
import {
    isProductionSeedReceiptTerminalEndorsementKernel,
    openProductionSeedReceiptTerminalEndorsementKernel,
    type OpenProductionSeedReceiptTerminalEndorsementKernelInput,
    type ProductionSeedReceiptTerminalEndorsementKernel,
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
import {
    consumeSeedRecipientReceiptTerminalEndorsementAuthorization,
    type ConsumedSeedRecipientReceiptTerminalEndorsementAuthorization,
    type SeedRecipientReceiptTerminalEndorsementAuthorization,
} from './seed-recipient-receipt-custody.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const endorsementCustodyRecordMagic = Uint8Array.of(0x53, 0x4c, 0x54, 0x45);
const endorsementCustodyRecordVersion = 1;
const reservedRecordKind = 1;
const completedRecordKind = 2;
const hashByteLength = 64;
const signatureRandomnessByteLength = 32;
const kernelRequestHeaderByteLength = 7;
const kernelResponseHeaderByteLength = 7;
const kernelContextHandleByteLength = 4;
const signingVerificationKeyByteLength = 1_952;
const signatureByteLength = 3_309;
const receiptCustodyKernelContextByteLength = hashByteLength * 3 + 2 * 3;
const endorsementValidationContextByteLength = hashByteLength * 3 + 2 * 3;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const endorsementCustodyOperationDomain =
    'sealed-lattice/runtime/seed-receipt-terminal-endorsement-record/v1';

export type SeedReceiptTerminalEndorsementCustodyContext = Readonly<{
    parameterIdentity: Uint8Array;
    participantCount: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    endorserPosition: number;
    rootTerminalIdentity: Uint8Array;
}>;

export type SeedReceiptTerminalEndorsementCustodyLimits = Readonly<{
    maximumEndorsementAuthorizationBodyByteLength: number;
    maximumVerifiedReceiptInventoryBodyByteLength: number;
    maximumReceiptEnvelopeByteLength: number;
    maximumEndorsementEnvelopeByteLength: number;
    maximumTerminalBodyByteLength: number;
    transactionLifetimeMilliseconds: number;
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
    context: SeedReceiptTerminalEndorsementCustodyContext;
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory;
    endorsementEnvelopeBytes?: Uint8Array;
}>;

export type SeedReceiptTerminalEndorsementCustodyKernel = Readonly<{
    prepare():
        | Promise<PreparedSeedReceiptTerminalEndorsementInventory>
        | PreparedSeedReceiptTerminalEndorsementInventory;
    produce(
        input: SeedReceiptTerminalEndorsementProductionInput,
    ): Promise<Uint8Array> | Uint8Array;
    validate(
        input: SeedReceiptTerminalEndorsementValidationInput,
    ): Promise<void> | void;
}>;

type OpenBrowserLocalSeedReceiptTerminalEndorsementKernelInput = Omit<
    OpenProductionSeedReceiptTerminalEndorsementKernelInput,
    'receiptCustodyContext' | 'receiptCustodyRecordBytes' | 'signingOperations'
> &
    Readonly<{
        receiptCustodyAuthorization: SeedRecipientReceiptTerminalEndorsementAuthorization;
        signingCapability: BrowserLocalSigningCapability;
    }>;

/**
 * Binds the fixed-purpose terminal-endorsement operation to an opaque
 * browser-local signing capability and a one-shot completed receipt-custody
 * authorization. Rust positively verifies every predecessor and the final
 * signature carrier.
 */
export const openBrowserLocalSeedReceiptTerminalEndorsementKernel = async (
    transcriptCoreKernelUrl: URL,
    input: OpenBrowserLocalSeedReceiptTerminalEndorsementKernelInput,
): Promise<ProductionSeedReceiptTerminalEndorsementKernel> => {
    const endorserPosition = input.endorserPosition;
    const parameterIdentity = input.parameterIdentity.slice();
    const preparationContextBytes = input.preparationContextBytes.slice();
    const receiptEnvelopeBytes = input.receiptEnvelopeBytes.map((bytes) =>
        bytes.slice(),
    );
    const rootAuthorizationPackages = input.rootAuthorizationPackages.map(
        (rootPackage) =>
            Object.freeze({
                contributorSignatureEnvelopeBytes:
                    rootPackage.contributorSignatureEnvelopeBytes.slice(),
                exactOutputCertificateBytes:
                    rootPackage.exactOutputCertificateBytes.slice(),
                reservationCertificateBytes:
                    rootPackage.reservationCertificateBytes.slice(),
                rootBodyBytes: rootPackage.rootBodyBytes.slice(),
            }),
    );
    const rootTerminalCertificateBytes =
        input.rootTerminalCertificateBytes.slice();
    const rosterBytes = input.rosterBytes.slice();
    const signingCapability = input.signingCapability;
    let consumedReceipt:
        | ConsumedSeedRecipientReceiptTerminalEndorsementAuthorization
        | undefined;
    try {
        consumedReceipt =
            await consumeSeedRecipientReceiptTerminalEndorsementAuthorization(
                input.receiptCustodyAuthorization,
            );
        return await openProductionSeedReceiptTerminalEndorsementKernel(
            transcriptCoreKernelUrl,
            {
                endorserPosition,
                parameterIdentity,
                preparationContextBytes,
                receiptCustodyContext: consumedReceipt.context,
                receiptCustodyRecordBytes: consumedReceipt.recordBytes,
                receiptEnvelopeBytes,
                rootAuthorizationPackages,
                rootTerminalCertificateBytes,
                rosterBytes,
                signingOperations: Object.freeze({
                    assertMatchesEndorserVerificationKey: ({
                        endorserSigningVerificationKey,
                    }): void =>
                        assertSeedReceiptTerminalEndorsementSigningCapabilityMatchesRosterKey(
                            {
                                endorserSigningVerificationKey,
                                signingCapability,
                            },
                        ),
                    signEndorsementBody: ({
                        endorsementAuthorizationBodyBytes,
                        endorserSigningVerificationKey,
                        signatureRandomness,
                    }): Uint8Array =>
                        signSeedReceiptTerminalEndorsementBody({
                            endorsementAuthorizationBodyBytes,
                            endorserSigningVerificationKey,
                            signatureRandomness,
                            signingCapability,
                        }),
                }),
            },
        );
    } finally {
        parameterIdentity.fill(0);
        preparationContextBytes.fill(0);
        receiptEnvelopeBytes.forEach((bytes) => bytes.fill(0));
        rootAuthorizationPackages.forEach((rootPackage) => {
            rootPackage.contributorSignatureEnvelopeBytes.fill(0);
            rootPackage.exactOutputCertificateBytes.fill(0);
            rootPackage.reservationCertificateBytes.fill(0);
            rootPackage.rootBodyBytes.fill(0);
        });
        rootTerminalCertificateBytes.fill(0);
        rosterBytes.fill(0);
        if (consumedReceipt !== undefined) {
            consumedReceipt.context.parameterIdentity.fill(0);
            consumedReceipt.context.preparationContextIdentity.fill(0);
            consumedReceipt.context.rootTerminalIdentity.fill(0);
            consumedReceipt.recordBytes.fill(0);
        }
    }
};

/**
 * Exact public terminal-endorsement carrier retained for byte-identical
 * publication replay.
 *
 * This output is inert. It is not a complete receipt inventory, roster-endorsed
 * receipt terminal, seed-combination capability, coin-opening capability, burn
 * result, or preparation-continuation capability.
 */
type RetainedSeedReceiptTerminalEndorsementPublication = Readonly<{
    endorsementEnvelopeBytes: Uint8Array;
}>;

type SeedReceiptTerminalEndorsementCustodyRecordByteLengths = Readonly<{
    completedCiphertextByteLength: number;
    completedPlaintextByteLength: number;
    copyOnWriteCiphertextOverlapByteLength: number;
    reservationCiphertextByteLength: number;
    reservationPlaintextByteLength: number;
}>;

type SeedReceiptTerminalEndorsementRootAuthorizationPackageByteLengths =
    Readonly<{
        contributorSignatureEnvelopeByteLength: number;
        exactOutputCertificateByteLength: number;
        reservationCertificateByteLength: number;
        rootBodyByteLength: number;
    }>;

type SeedReceiptTerminalEndorsementKernelByteLengths = Readonly<{
    closeContextRequestByteLength: number;
    closeContextResponseByteLength: number;
    coldValidationCumulativeRequestByteLength: number;
    coldValidationCumulativeResponseByteLength: number;
    coldValidationInvocationCount: number;
    completeEndorsementRequestByteLength: number;
    completeEndorsementResponseByteLength: number;
    completedValidationRequestByteLength: number;
    maximumRequestByteLength: number;
    maximumResponseByteLength: number;
    openContextRequestByteLength: number;
    openContextResponseByteLength: number;
    prepareEndorsementRequestByteLength: number;
    prepareEndorsementResponseByteLength: number;
    preparedInventoryKernelByteLength: number;
    preparedValidationRequestByteLength: number;
    successfulCumulativeRequestByteLength: number;
    successfulCumulativeResponseByteLength: number;
    successfulInvocationCount: number;
    validationResponseByteLength: number;
}>;

type ReservedSeedReceiptTerminalEndorsementRecord = Readonly<{
    context: SeedReceiptTerminalEndorsementCustodyContext;
    kind: 'reserved';
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory;
    signatureRandomness: Uint8Array;
}>;

type CompletedSeedReceiptTerminalEndorsementRecord = Readonly<{
    context: SeedReceiptTerminalEndorsementCustodyContext;
    kind: 'completed';
    preparedInventory: PreparedSeedReceiptTerminalEndorsementInventory;
    endorsementEnvelopeBytes: Uint8Array;
}>;

type SeedReceiptTerminalEndorsementRecord =
    | ReservedSeedReceiptTerminalEndorsementRecord
    | CompletedSeedReceiptTerminalEndorsementRecord;

type OpenedSeedReceiptTerminalEndorsementRecord = Readonly<{
    record: SeedReceiptTerminalEndorsementRecord;
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
    code:
        | 'AuthenticationFailed'
        | 'InvalidConfiguration'
        | 'InvalidInput' = 'InvalidInput',
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
            'Seed-receipt terminal endorsement custody encoded an unexpected byte length.',
        );
    }
    return output;
};

const copyNonemptyBoundedBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    const bytes = copyBoundedBytes(value, maximumByteLength, label);
    if (bytes.byteLength === 0) {
        bytes.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${label} must not be empty.`,
        );
    }
    return bytes;
};

const copyContext = (
    value: unknown,
): SeedReceiptTerminalEndorsementCustodyContext => {
    const participantCount = requireSafeInteger(
        snapshotDataProperty(value, 'participantCount', 'context'),
        configurableParticipantCountRange.minimum,
        configurableParticipantCountRange.maximum,
        'context.participantCount',
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
        endorserPosition: requireSafeInteger(
            snapshotDataProperty(value, 'endorserPosition', 'context'),
            0,
            participantCount - 1,
            'context.endorserPosition',
            'InvalidConfiguration',
        ),
        rootTerminalIdentity: copyExactBytes(
            snapshotDataProperty(value, 'rootTerminalIdentity', 'context'),
            hashByteLength,
            'context.rootTerminalIdentity',
        ),
    });
};

const copyLimits = (
    value: unknown,
): SeedReceiptTerminalEndorsementCustodyLimits => {
    const readByteLimit = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(value, propertyName, 'limits'),
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            `limits.${propertyName}`,
            'InvalidConfiguration',
        );
    const limits = Object.freeze({
        maximumEndorsementAuthorizationBodyByteLength: readByteLimit(
            'maximumEndorsementAuthorizationBodyByteLength',
        ),
        maximumVerifiedReceiptInventoryBodyByteLength: readByteLimit(
            'maximumVerifiedReceiptInventoryBodyByteLength',
        ),
        maximumReceiptEnvelopeByteLength: readByteLimit(
            'maximumReceiptEnvelopeByteLength',
        ),
        maximumEndorsementEnvelopeByteLength: readByteLimit(
            'maximumEndorsementEnvelopeByteLength',
        ),
        maximumTerminalBodyByteLength: readByteLimit(
            'maximumTerminalBodyByteLength',
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
    const maximumReceiptEnvelopeCount =
        configurableParticipantCountRange.maximum;
    const maximumSharedPlaintextByteLength = sumByteLengths(
        [
            commonRecordPrefixByteLength(maximumReceiptEnvelopeCount),
            limits.maximumEndorsementAuthorizationBodyByteLength,
            limits.maximumVerifiedReceiptInventoryBodyByteLength,
            limits.maximumTerminalBodyByteLength,
            checkedMultiply(
                maximumReceiptEnvelopeCount,
                limits.maximumReceiptEnvelopeByteLength,
                'Maximum ordered receipt-envelope corpus',
            ),
        ],
        'Maximum seed-receipt terminal endorsement custody record',
    );
    const maximumReservationPlaintextByteLength = checkedAdd(
        maximumSharedPlaintextByteLength,
        signatureRandomnessByteLength,
        'Maximum seed-receipt terminal endorsement reservation',
    );
    const maximumCompletedPlaintextByteLength = sumByteLengths(
        [
            maximumSharedPlaintextByteLength,
            4,
            limits.maximumEndorsementEnvelopeByteLength,
        ],
        'Maximum seed-receipt terminal endorsement completed record',
    );
    if (
        maximumReservationPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        maximumCompletedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-receipt terminal endorsement custody limits exceed the absolute copied-buffer bound.',
        );
    }
    return limits;
};

const commonRecordPrefixByteLength = (receiptEnvelopeCount: number): number =>
    sumByteLengths(
        [
            endorsementCustodyRecordMagic.byteLength,
            2,
            1,
            hashByteLength * 7,
            2 * 3,
            4 * 3,
            2,
            checkedMultiply(
                receiptEnvelopeCount,
                4,
                'Ordered receipt envelope-length table',
            ),
        ],
        'Seed-receipt terminal endorsement record prefix',
    );

export const deriveSeedReceiptTerminalEndorsementCustodyRecordByteLengths =
    (input: {
        endorsementAuthorizationBodyByteLength: number;
        verifiedReceiptInventoryBodyByteLength: number;
        receiptEnvelopeByteLengths: readonly number[];
        endorsementEnvelopeByteLength: number;
        terminalBodyByteLength: number;
    }): SeedReceiptTerminalEndorsementCustodyRecordByteLengths => {
        const endorsementAuthorizationBodyByteLength = requireSafeInteger(
            snapshotDataProperty(
                input,
                'endorsementAuthorizationBodyByteLength',
                'input',
            ),
            1,
            unsigned32Maximum,
            'input.endorsementAuthorizationBodyByteLength',
        );
        const verifiedReceiptInventoryBodyByteLength = requireSafeInteger(
            snapshotDataProperty(
                input,
                'verifiedReceiptInventoryBodyByteLength',
                'input',
            ),
            1,
            unsigned32Maximum,
            'input.verifiedReceiptInventoryBodyByteLength',
        );
        const terminalBodyByteLength = requireSafeInteger(
            snapshotDataProperty(input, 'terminalBodyByteLength', 'input'),
            1,
            unsigned32Maximum,
            'input.terminalBodyByteLength',
        );
        const endorsementEnvelopeByteLength = requireSafeInteger(
            snapshotDataProperty(
                input,
                'endorsementEnvelopeByteLength',
                'input',
            ),
            1,
            unsigned32Maximum,
            'input.endorsementEnvelopeByteLength',
        );
        const receiptEnvelopeByteLengthsValue = snapshotDataProperty(
            input,
            'receiptEnvelopeByteLengths',
            'input',
        );
        if (!Array.isArray(receiptEnvelopeByteLengthsValue)) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidInput',
                'input.receiptEnvelopeByteLengths must be an array.',
            );
        }
        const receiptEnvelopeCount = requireSafeInteger(
            snapshotDataProperty(
                receiptEnvelopeByteLengthsValue,
                'length',
                'input.receiptEnvelopeByteLengths',
            ),
            1,
            unsigned16Maximum,
            'input.receiptEnvelopeByteLengths.length',
        );
        const receiptEnvelopeByteLengths = Array.from(
            { length: receiptEnvelopeCount },
            (_unused, receiptEnvelopeIndex) =>
                requireSafeInteger(
                    snapshotDataProperty(
                        receiptEnvelopeByteLengthsValue,
                        String(receiptEnvelopeIndex),
                        'input.receiptEnvelopeByteLengths',
                    ),
                    1,
                    unsigned32Maximum,
                    `input.receiptEnvelopeByteLengths[${receiptEnvelopeIndex}]`,
                ),
        );
        const sharedPlaintextByteLength = sumByteLengths(
            [
                commonRecordPrefixByteLength(receiptEnvelopeCount),
                endorsementAuthorizationBodyByteLength,
                verifiedReceiptInventoryBodyByteLength,
                terminalBodyByteLength,
                sumByteLengths(
                    receiptEnvelopeByteLengths,
                    'Ordered receipt-envelope corpus byte length',
                ),
            ],
            'Seed-receipt terminal endorsement shared record bytes',
        );
        const reservationPlaintextByteLength = checkedAdd(
            sharedPlaintextByteLength,
            signatureRandomnessByteLength,
            'Seed-receipt terminal endorsement reservation record',
        );
        const completedPlaintextByteLength = sumByteLengths(
            [sharedPlaintextByteLength, 4, endorsementEnvelopeByteLength],
            'Seed-receipt terminal endorsement completed record',
        );
        const reservationCiphertextByteLength = checkedAdd(
            reservationPlaintextByteLength,
            runtimeRecordEnvelopeOverheadByteLength,
            'Seed-receipt terminal endorsement reservation ciphertext',
        );
        const completedCiphertextByteLength = checkedAdd(
            completedPlaintextByteLength,
            runtimeRecordEnvelopeOverheadByteLength,
            'Seed-receipt terminal endorsement completed ciphertext',
        );
        return Object.freeze({
            completedCiphertextByteLength,
            completedPlaintextByteLength,
            copyOnWriteCiphertextOverlapByteLength: checkedAdd(
                reservationCiphertextByteLength,
                completedCiphertextByteLength,
                'Seed-receipt terminal endorsement copy-on-write ciphertext overlap',
            ),
            reservationCiphertextByteLength,
            reservationPlaintextByteLength,
        });
    };

export const deriveSeedReceiptTerminalEndorsementKernelByteLengths = (input: {
    endorsementAuthorizationBodyByteLength: number;
    endorsementEnvelopeByteLength: number;
    preparationContextByteLength: number;
    receiptCustodyRecordByteLength: number;
    receiptEnvelopeByteLengths: readonly number[];
    rootAuthorizationPackages: readonly SeedReceiptTerminalEndorsementRootAuthorizationPackageByteLengths[];
    rootTerminalCertificateByteLength: number;
    rosterByteLength: number;
    terminalBodyByteLength: number;
    verifiedReceiptInventoryBodyByteLength: number;
}): SeedReceiptTerminalEndorsementKernelByteLengths => {
    const readInputByteLength = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(input, propertyName, 'input'),
            1,
            unsigned32Maximum,
            `input.${propertyName}`,
        );
    const endorsementAuthorizationBodyByteLength = readInputByteLength(
        'endorsementAuthorizationBodyByteLength',
    );
    const endorsementEnvelopeByteLength = readInputByteLength(
        'endorsementEnvelopeByteLength',
    );
    const preparationContextByteLength = readInputByteLength(
        'preparationContextByteLength',
    );
    const receiptCustodyRecordByteLength = readInputByteLength(
        'receiptCustodyRecordByteLength',
    );
    const rootTerminalCertificateByteLength = readInputByteLength(
        'rootTerminalCertificateByteLength',
    );
    const rosterByteLength = readInputByteLength('rosterByteLength');
    const terminalBodyByteLength = readInputByteLength(
        'terminalBodyByteLength',
    );
    const verifiedReceiptInventoryBodyByteLength = readInputByteLength(
        'verifiedReceiptInventoryBodyByteLength',
    );
    const receiptEnvelopeByteLengthsValue = snapshotDataProperty(
        input,
        'receiptEnvelopeByteLengths',
        'input',
    );
    const rootAuthorizationPackagesValue = snapshotDataProperty(
        input,
        'rootAuthorizationPackages',
        'input',
    );
    if (!Array.isArray(receiptEnvelopeByteLengthsValue)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'input.receiptEnvelopeByteLengths must be an array.',
        );
    }
    if (!Array.isArray(rootAuthorizationPackagesValue)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'input.rootAuthorizationPackages must be an array.',
        );
    }
    const receiptEnvelopeCount = requireSafeInteger(
        snapshotDataProperty(
            receiptEnvelopeByteLengthsValue,
            'length',
            'input.receiptEnvelopeByteLengths',
        ),
        1,
        unsigned16Maximum,
        'input.receiptEnvelopeByteLengths.length',
    );
    const rootPackageCount = requireSafeInteger(
        snapshotDataProperty(
            rootAuthorizationPackagesValue,
            'length',
            'input.rootAuthorizationPackages',
        ),
        1,
        unsigned16Maximum,
        'input.rootAuthorizationPackages.length',
    );
    if (rootPackageCount !== receiptEnvelopeCount) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Receipt-terminal endorsement kernel inventories must have the same nonzero participant count.',
        );
    }
    const receiptEnvelopeByteLengths = Array.from(
        { length: receiptEnvelopeCount },
        (_unused, receiptIndex) =>
            requireSafeInteger(
                snapshotDataProperty(
                    receiptEnvelopeByteLengthsValue,
                    String(receiptIndex),
                    'input.receiptEnvelopeByteLengths',
                ),
                1,
                unsigned32Maximum,
                `input.receiptEnvelopeByteLengths[${receiptIndex}]`,
            ),
    );
    const rootAuthorizationPackageByteLengths = Array.from(
        { length: rootPackageCount },
        (_unused, packageIndex) => {
            const packageValue = snapshotDataProperty(
                rootAuthorizationPackagesValue,
                String(packageIndex),
                'input.rootAuthorizationPackages',
            );
            return sumByteLengths(
                [
                    'rootBodyByteLength',
                    'reservationCertificateByteLength',
                    'exactOutputCertificateByteLength',
                    'contributorSignatureEnvelopeByteLength',
                ].map((propertyName) =>
                    checkedAdd(
                        4,
                        requireSafeInteger(
                            snapshotDataProperty(
                                packageValue,
                                propertyName,
                                `input.rootAuthorizationPackages[${packageIndex}]`,
                            ),
                            1,
                            unsigned32Maximum,
                            `input.rootAuthorizationPackages[${packageIndex}].${propertyName}`,
                        ),
                        `Receipt-terminal endorsement root package ${packageIndex}`,
                    ),
                ),
                `Receipt-terminal endorsement root package ${packageIndex}`,
            );
        },
    );
    const boundedReceiptEnvelopeCorpusByteLength = sumByteLengths(
        receiptEnvelopeByteLengths.map((byteLength) =>
            checkedAdd(
                4,
                byteLength,
                'Receipt-terminal endorsement bounded receipt envelope',
            ),
        ),
        'Receipt-terminal endorsement bounded receipt-envelope corpus',
    );
    const preparedInventoryKernelByteLength = sumByteLengths(
        [
            4,
            endorsementAuthorizationBodyByteLength,
            4,
            verifiedReceiptInventoryBodyByteLength,
            hashByteLength,
            2,
            boundedReceiptEnvelopeCorpusByteLength,
            hashByteLength * 2,
            4,
            terminalBodyByteLength,
            hashByteLength,
        ],
        'Receipt-terminal endorsement prepared kernel inventory',
    );
    const openContextRequestByteLength = sumByteLengths(
        [
            kernelRequestHeaderByteLength,
            hashByteLength,
            2,
            4,
            preparationContextByteLength,
            4,
            rosterByteLength,
            2,
            sumByteLengths(
                rootAuthorizationPackageByteLengths,
                'Receipt-terminal endorsement root-package corpus',
            ),
            4,
            rootTerminalCertificateByteLength,
            2,
            boundedReceiptEnvelopeCorpusByteLength,
            receiptCustodyKernelContextByteLength,
            4,
            receiptCustodyRecordByteLength,
        ],
        'Receipt-terminal endorsement open request',
    );
    const openContextResponseByteLength = sumByteLengths(
        [
            kernelResponseHeaderByteLength,
            kernelContextHandleByteLength,
            signingVerificationKeyByteLength,
        ],
        'Receipt-terminal endorsement open response',
    );
    const prepareEndorsementRequestByteLength =
        kernelRequestHeaderByteLength + kernelContextHandleByteLength;
    const prepareEndorsementResponseByteLength = checkedAdd(
        kernelResponseHeaderByteLength,
        preparedInventoryKernelByteLength,
        'Receipt-terminal endorsement prepare response',
    );
    const completeEndorsementRequestByteLength = sumByteLengths(
        [
            kernelRequestHeaderByteLength,
            kernelContextHandleByteLength,
            preparedInventoryKernelByteLength,
            signatureByteLength,
        ],
        'Receipt-terminal endorsement completion request',
    );
    const completeEndorsementResponseByteLength = sumByteLengths(
        [kernelResponseHeaderByteLength, 4, endorsementEnvelopeByteLength],
        'Receipt-terminal endorsement completion response',
    );
    const preparedValidationRequestByteLength = sumByteLengths(
        [
            kernelRequestHeaderByteLength,
            kernelContextHandleByteLength,
            endorsementValidationContextByteLength,
            preparedInventoryKernelByteLength,
            1,
        ],
        'Receipt-terminal endorsement prepared validation request',
    );
    const completedValidationRequestByteLength = sumByteLengths(
        [preparedValidationRequestByteLength, 4, endorsementEnvelopeByteLength],
        'Receipt-terminal endorsement completed validation request',
    );
    const validationResponseByteLength = kernelResponseHeaderByteLength;
    const closeContextRequestByteLength =
        kernelRequestHeaderByteLength + kernelContextHandleByteLength;
    const closeContextResponseByteLength = kernelResponseHeaderByteLength;
    const successfulRequestByteLengths = [
        openContextRequestByteLength,
        prepareEndorsementRequestByteLength,
        preparedValidationRequestByteLength,
        completeEndorsementRequestByteLength,
        completedValidationRequestByteLength,
        closeContextRequestByteLength,
    ];
    const successfulResponseByteLengths = [
        openContextResponseByteLength,
        prepareEndorsementResponseByteLength,
        validationResponseByteLength,
        completeEndorsementResponseByteLength,
        validationResponseByteLength,
        closeContextResponseByteLength,
    ];
    const coldValidationRequestByteLengths = [
        openContextRequestByteLength,
        completedValidationRequestByteLength,
        closeContextRequestByteLength,
    ];
    const coldValidationResponseByteLengths = [
        openContextResponseByteLength,
        validationResponseByteLength,
        closeContextResponseByteLength,
    ];
    const maximumRequestByteLength = Math.max(...successfulRequestByteLengths);
    const maximumResponseByteLength = Math.max(
        ...successfulResponseByteLengths,
    );
    if (
        maximumRequestByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        maximumResponseByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Receipt-terminal endorsement kernel traffic exceeds the absolute copied-buffer bound.',
        );
    }
    return Object.freeze({
        closeContextRequestByteLength,
        closeContextResponseByteLength,
        coldValidationCumulativeRequestByteLength: sumByteLengths(
            coldValidationRequestByteLengths,
            'Receipt-terminal endorsement cold-validation requests',
        ),
        coldValidationCumulativeResponseByteLength: sumByteLengths(
            coldValidationResponseByteLengths,
            'Receipt-terminal endorsement cold-validation responses',
        ),
        coldValidationInvocationCount: coldValidationRequestByteLengths.length,
        completeEndorsementRequestByteLength,
        completeEndorsementResponseByteLength,
        completedValidationRequestByteLength,
        maximumRequestByteLength,
        maximumResponseByteLength,
        openContextRequestByteLength,
        openContextResponseByteLength,
        prepareEndorsementRequestByteLength,
        prepareEndorsementResponseByteLength,
        preparedInventoryKernelByteLength,
        preparedValidationRequestByteLength,
        successfulCumulativeRequestByteLength: sumByteLengths(
            successfulRequestByteLengths,
            'Receipt-terminal endorsement successful requests',
        ),
        successfulCumulativeResponseByteLength: sumByteLengths(
            successfulResponseByteLengths,
            'Receipt-terminal endorsement successful responses',
        ),
        successfulInvocationCount: successfulRequestByteLengths.length,
        validationResponseByteLength,
    });
};

const copyPreparedInventory = (
    value: unknown,
    context: SeedReceiptTerminalEndorsementCustodyContext,
    limits: SeedReceiptTerminalEndorsementCustodyLimits,
): PreparedSeedReceiptTerminalEndorsementInventory => {
    const receiptEnvelopeValues = snapshotDataProperty(
        value,
        'orderedReceiptEnvelopeBytes',
        'preparedInventory',
    );
    if (!Array.isArray(receiptEnvelopeValues)) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'preparedInventory.orderedReceiptEnvelopeBytes must be an array.',
        );
    }
    const expectedReceiptEnvelopeCount = context.participantCount;
    const receiptEnvelopeCount = requireSafeInteger(
        snapshotDataProperty(
            receiptEnvelopeValues,
            'length',
            'preparedInventory.orderedReceiptEnvelopeBytes',
        ),
        expectedReceiptEnvelopeCount,
        expectedReceiptEnvelopeCount,
        'preparedInventory.orderedReceiptEnvelopeBytes.length',
    );
    const prepared = Object.freeze({
        endorsementAuthorizationBodyBytes: copyNonemptyBoundedBytes(
            snapshotDataProperty(
                value,
                'endorsementAuthorizationBodyBytes',
                'preparedInventory',
            ),
            limits.maximumEndorsementAuthorizationBodyByteLength,
            'preparedInventory.endorsementAuthorizationBodyBytes',
        ),
        verifiedReceiptInventoryBodyBytes: copyNonemptyBoundedBytes(
            snapshotDataProperty(
                value,
                'verifiedReceiptInventoryBodyBytes',
                'preparedInventory',
            ),
            limits.maximumVerifiedReceiptInventoryBodyByteLength,
            'preparedInventory.verifiedReceiptInventoryBodyBytes',
        ),
        verifiedReceiptInventoryIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'verifiedReceiptInventoryIdentity',
                'preparedInventory',
            ),
            hashByteLength,
            'preparedInventory.verifiedReceiptInventoryIdentity',
        ),
        orderedReceiptEnvelopeBytes: Object.freeze(
            Array.from(
                { length: receiptEnvelopeCount },
                (_unused, receiptEnvelopeIndex) =>
                    copyNonemptyBoundedBytes(
                        snapshotDataProperty(
                            receiptEnvelopeValues,
                            String(receiptEnvelopeIndex),
                            'preparedInventory.orderedReceiptEnvelopeBytes',
                        ),
                        limits.maximumReceiptEnvelopeByteLength,
                        `preparedInventory.orderedReceiptEnvelopeBytes[${receiptEnvelopeIndex}]`,
                    ),
            ),
        ),
        retainedLocalReceiptBodyIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'retainedLocalReceiptBodyIdentity',
                'preparedInventory',
            ),
            hashByteLength,
            'preparedInventory.retainedLocalReceiptBodyIdentity',
        ),
        retainedLocalReceiptEnvelopeIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'retainedLocalReceiptEnvelopeIdentity',
                'preparedInventory',
            ),
            hashByteLength,
            'preparedInventory.retainedLocalReceiptEnvelopeIdentity',
        ),
        terminalBodyBytes: copyNonemptyBoundedBytes(
            snapshotDataProperty(
                value,
                'terminalBodyBytes',
                'preparedInventory',
            ),
            limits.maximumTerminalBodyByteLength,
            'preparedInventory.terminalBodyBytes',
        ),
        terminalBodyIdentity: copyExactBytes(
            snapshotDataProperty(
                value,
                'terminalBodyIdentity',
                'preparedInventory',
            ),
            hashByteLength,
            'preparedInventory.terminalBodyIdentity',
        ),
    });
    const byteLengths =
        deriveSeedReceiptTerminalEndorsementCustodyRecordByteLengths({
            endorsementAuthorizationBodyByteLength:
                prepared.endorsementAuthorizationBodyBytes.byteLength,
            verifiedReceiptInventoryBodyByteLength:
                prepared.verifiedReceiptInventoryBodyBytes.byteLength,
            receiptEnvelopeByteLengths:
                prepared.orderedReceiptEnvelopeBytes.map(
                    (receiptEnvelope) => receiptEnvelope.byteLength,
                ),
            endorsementEnvelopeByteLength:
                limits.maximumEndorsementEnvelopeByteLength,
            terminalBodyByteLength: prepared.terminalBodyBytes.byteLength,
        });
    if (
        byteLengths.reservationPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        byteLengths.completedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        destroyPreparedInventory(prepared);
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Seed-receipt terminal endorsement custody record exceeds the absolute copied-buffer bound.',
        );
    }
    return prepared;
};

const destroyContext = (
    context: SeedReceiptTerminalEndorsementCustodyContext | undefined,
): void => {
    context?.parameterIdentity.fill(0);
    context?.preparationContextIdentity.fill(0);
    context?.rootTerminalIdentity.fill(0);
};

const destroyPreparedInventory = (
    prepared: PreparedSeedReceiptTerminalEndorsementInventory | undefined,
): void => {
    prepared?.endorsementAuthorizationBodyBytes.fill(0);
    prepared?.verifiedReceiptInventoryBodyBytes.fill(0);
    prepared?.verifiedReceiptInventoryIdentity.fill(0);
    prepared?.orderedReceiptEnvelopeBytes.forEach((receiptEnvelope) =>
        receiptEnvelope.fill(0),
    );
    prepared?.retainedLocalReceiptBodyIdentity.fill(0);
    prepared?.retainedLocalReceiptEnvelopeIdentity.fill(0);
    prepared?.terminalBodyBytes.fill(0);
    prepared?.terminalBodyIdentity.fill(0);
};

const contextsEqual = (
    left: SeedReceiptTerminalEndorsementCustodyContext,
    right: SeedReceiptTerminalEndorsementCustodyContext,
): boolean =>
    left.participantCount === right.participantCount &&
    left.preparationAttemptOrdinal === right.preparationAttemptOrdinal &&
    left.endorserPosition === right.endorserPosition &&
    bytesEqual(left.parameterIdentity, right.parameterIdentity) &&
    bytesEqual(
        left.preparationContextIdentity,
        right.preparationContextIdentity,
    ) &&
    bytesEqual(left.rootTerminalIdentity, right.rootTerminalIdentity);

const preparedInventoriesEqual = (
    left: PreparedSeedReceiptTerminalEndorsementInventory,
    right: PreparedSeedReceiptTerminalEndorsementInventory,
): boolean =>
    bytesEqual(
        left.endorsementAuthorizationBodyBytes,
        right.endorsementAuthorizationBodyBytes,
    ) &&
    bytesEqual(
        left.verifiedReceiptInventoryBodyBytes,
        right.verifiedReceiptInventoryBodyBytes,
    ) &&
    bytesEqual(
        left.verifiedReceiptInventoryIdentity,
        right.verifiedReceiptInventoryIdentity,
    ) &&
    bytesEqual(left.terminalBodyBytes, right.terminalBodyBytes) &&
    bytesEqual(left.terminalBodyIdentity, right.terminalBodyIdentity) &&
    bytesEqual(
        left.retainedLocalReceiptBodyIdentity,
        right.retainedLocalReceiptBodyIdentity,
    ) &&
    bytesEqual(
        left.retainedLocalReceiptEnvelopeIdentity,
        right.retainedLocalReceiptEnvelopeIdentity,
    ) &&
    left.orderedReceiptEnvelopeBytes.length ===
        right.orderedReceiptEnvelopeBytes.length &&
    left.orderedReceiptEnvelopeBytes.every(
        (receiptEnvelope, receiptEnvelopeIndex) =>
            bytesEqual(
                receiptEnvelope,
                right.orderedReceiptEnvelopeBytes[receiptEnvelopeIndex],
            ),
    );

const logicalRecordKey = (
    context: SeedReceiptTerminalEndorsementCustodyContext,
): string =>
    `seed-mailbox/receipt-terminal-endorsement/${context.preparationAttemptOrdinal
        .toString(10)
        .padStart(5, '0')}/${context.endorserPosition
        .toString(10)
        .padStart(5, '0')}`;

const encodeRecord = (
    record: SeedReceiptTerminalEndorsementRecord,
): Uint8Array => {
    const prepared = record.preparedInventory;
    const byteLengths =
        deriveSeedReceiptTerminalEndorsementCustodyRecordByteLengths({
            endorsementAuthorizationBodyByteLength:
                prepared.endorsementAuthorizationBodyBytes.byteLength,
            verifiedReceiptInventoryBodyByteLength:
                prepared.verifiedReceiptInventoryBodyBytes.byteLength,
            receiptEnvelopeByteLengths:
                prepared.orderedReceiptEnvelopeBytes.map(
                    (receiptEnvelope) => receiptEnvelope.byteLength,
                ),
            endorsementEnvelopeByteLength:
                record.kind === 'completed'
                    ? record.endorsementEnvelopeBytes.byteLength
                    : 1,
            terminalBodyByteLength: prepared.terminalBodyBytes.byteLength,
        });
    const sharedParts = [
        endorsementCustodyRecordMagic,
        unsigned16LittleEndian(endorsementCustodyRecordVersion),
        Uint8Array.of(
            record.kind === 'reserved'
                ? reservedRecordKind
                : completedRecordKind,
        ),
        record.context.parameterIdentity,
        record.context.preparationContextIdentity,
        record.context.rootTerminalIdentity,
        unsigned16LittleEndian(record.context.preparationAttemptOrdinal),
        unsigned16LittleEndian(record.context.participantCount),
        unsigned16LittleEndian(record.context.endorserPosition),
        prepared.verifiedReceiptInventoryIdentity,
        prepared.terminalBodyIdentity,
        prepared.retainedLocalReceiptBodyIdentity,
        prepared.retainedLocalReceiptEnvelopeIdentity,
        unsigned32LittleEndian(
            prepared.verifiedReceiptInventoryBodyBytes.byteLength,
        ),
        unsigned32LittleEndian(prepared.terminalBodyBytes.byteLength),
        unsigned32LittleEndian(
            prepared.endorsementAuthorizationBodyBytes.byteLength,
        ),
        unsigned16LittleEndian(prepared.orderedReceiptEnvelopeBytes.length),
        ...prepared.orderedReceiptEnvelopeBytes.map((receiptEnvelope) =>
            unsigned32LittleEndian(receiptEnvelope.byteLength),
        ),
        prepared.verifiedReceiptInventoryBodyBytes,
        prepared.terminalBodyBytes,
        prepared.endorsementAuthorizationBodyBytes,
        ...prepared.orderedReceiptEnvelopeBytes,
    ];
    if (record.kind === 'reserved') {
        return concatenateBytes(
            [...sharedParts, record.signatureRandomness],
            byteLengths.reservationPlaintextByteLength,
        );
    }
    return concatenateBytes(
        [
            ...sharedParts,
            unsigned32LittleEndian(record.endorsementEnvelopeBytes.byteLength),
            record.endorsementEnvelopeBytes,
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
                `Seed-receipt terminal endorsement custody record ends within ${label}.`,
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
                'Seed-receipt terminal endorsement custody record has trailing bytes.',
            );
        }
    }
}

const decodeRecord = (
    plaintext: Uint8Array,
    limits: SeedReceiptTerminalEndorsementCustodyLimits,
): SeedReceiptTerminalEndorsementRecord => {
    if (
        plaintext.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-receipt terminal endorsement custody record exceeds the absolute copied-buffer bound.',
        );
    }
    const cursor = new BoundedRecordCursor(plaintext);
    const magic = cursor.readExact(
        endorsementCustodyRecordMagic.byteLength,
        'record magic',
    );
    try {
        if (!bytesEqual(magic, endorsementCustodyRecordMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-receipt terminal endorsement custody record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (
        cursor.readUnsigned16('record version') !==
        endorsementCustodyRecordVersion
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-receipt terminal endorsement custody record has an unsupported version.',
        );
    }
    const recordKind = cursor.readUnsigned8('record kind');
    if (
        recordKind !== reservedRecordKind &&
        recordKind !== completedRecordKind
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-receipt terminal endorsement custody record has an invalid kind.',
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
    const endorserPosition = cursor.readUnsigned16('endorser position');
    if (
        participantCount < configurableParticipantCountRange.minimum ||
        participantCount > configurableParticipantCountRange.maximum ||
        endorserPosition >= participantCount
    ) {
        parameterIdentity.fill(0);
        preparationContextIdentity.fill(0);
        rootTerminalIdentity.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-receipt terminal endorsement custody record has invalid roster coordinates.',
        );
    }
    const verifiedReceiptInventoryIdentity = cursor.readExact(
        hashByteLength,
        'verified receipt-inventory identity',
    );
    const terminalBodyIdentity = cursor.readExact(
        hashByteLength,
        'terminal-body identity',
    );
    const retainedLocalReceiptBodyIdentity = cursor.readExact(
        hashByteLength,
        'retained local receipt-body identity',
    );
    const retainedLocalReceiptEnvelopeIdentity = cursor.readExact(
        hashByteLength,
        'retained local receipt-envelope identity',
    );
    const verifiedReceiptInventoryBodyByteLength = requireSafeInteger(
        cursor.readUnsigned32('verified receipt-inventory body byte length'),
        1,
        limits.maximumVerifiedReceiptInventoryBodyByteLength,
        'Stored verified receipt-inventory body byte length',
        'AuthenticationFailed',
    );
    const terminalBodyByteLength = requireSafeInteger(
        cursor.readUnsigned32('terminal-body byte length'),
        1,
        limits.maximumTerminalBodyByteLength,
        'Stored terminal-body byte length',
        'AuthenticationFailed',
    );
    const endorsementAuthorizationBodyByteLength = requireSafeInteger(
        cursor.readUnsigned32('endorsement authorization-body byte length'),
        1,
        limits.maximumEndorsementAuthorizationBodyByteLength,
        'Stored endorsement authorization-body byte length',
        'AuthenticationFailed',
    );
    const receiptEnvelopeCount = requireSafeInteger(
        cursor.readUnsigned16('ordered receipt envelope count'),
        participantCount,
        participantCount,
        'Stored ordered receipt envelope count',
        'AuthenticationFailed',
    );
    const receiptEnvelopeByteLengths = Array.from(
        { length: receiptEnvelopeCount },
        (_unused, receiptEnvelopeIndex) =>
            requireSafeInteger(
                cursor.readUnsigned32(
                    `ordered receipt envelope ${receiptEnvelopeIndex} byte length`,
                ),
                1,
                limits.maximumReceiptEnvelopeByteLength,
                `Stored ordered receipt envelope ${receiptEnvelopeIndex} byte length`,
                'AuthenticationFailed',
            ),
    );
    const context = Object.freeze({
        parameterIdentity,
        participantCount,
        preparationAttemptOrdinal,
        preparationContextIdentity,
        endorserPosition,
        rootTerminalIdentity,
    });
    let verifiedReceiptInventoryBodyBytes: Uint8Array | undefined;
    let terminalBodyBytes: Uint8Array | undefined;
    let endorsementAuthorizationBodyBytes: Uint8Array | undefined;
    let orderedReceiptEnvelopeBytes: Uint8Array[] | undefined;
    try {
        verifiedReceiptInventoryBodyBytes = cursor.readExact(
            verifiedReceiptInventoryBodyByteLength,
            'verified receipt-inventory body',
        );
        terminalBodyBytes = cursor.readExact(
            terminalBodyByteLength,
            'terminal body',
        );
        endorsementAuthorizationBodyBytes = cursor.readExact(
            endorsementAuthorizationBodyByteLength,
            'endorsement authorization body',
        );
        orderedReceiptEnvelopeBytes = receiptEnvelopeByteLengths.map(
            (byteLength, receiptEnvelopeIndex) =>
                cursor.readExact(
                    byteLength,
                    `ordered receipt envelope ${receiptEnvelopeIndex}`,
                ),
        );
        const preparedInventory = Object.freeze({
            endorsementAuthorizationBodyBytes,
            verifiedReceiptInventoryBodyBytes,
            verifiedReceiptInventoryIdentity,
            orderedReceiptEnvelopeBytes: Object.freeze(
                orderedReceiptEnvelopeBytes,
            ),
            retainedLocalReceiptBodyIdentity,
            retainedLocalReceiptEnvelopeIdentity,
            terminalBodyBytes,
            terminalBodyIdentity,
        });
        verifiedReceiptInventoryBodyBytes = undefined;
        terminalBodyBytes = undefined;
        endorsementAuthorizationBodyBytes = undefined;
        orderedReceiptEnvelopeBytes = undefined;
        if (recordKind === reservedRecordKind) {
            let signatureRandomness: Uint8Array | undefined;
            try {
                signatureRandomness = cursor.readExact(
                    signatureRandomnessByteLength,
                    'signature randomness',
                );
                cursor.requireComplete();
                if (signatureRandomness.every((byte) => byte === 0)) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Seed-receipt terminal endorsement custody record has invalid signature randomness.',
                    );
                }
                const record = Object.freeze({
                    context,
                    kind: 'reserved' as const,
                    preparedInventory,
                    signatureRandomness,
                });
                signatureRandomness = undefined;
                return record;
            } catch (error) {
                destroyPreparedInventory(preparedInventory);
                throw error;
            } finally {
                signatureRandomness?.fill(0);
            }
        }
        let endorsementEnvelopeBytes: Uint8Array | undefined;
        try {
            const endorsementEnvelopeByteLength = requireSafeInteger(
                cursor.readUnsigned32('endorsement-envelope byte length'),
                1,
                limits.maximumEndorsementEnvelopeByteLength,
                'Stored endorsement-envelope byte length',
                'AuthenticationFailed',
            );
            endorsementEnvelopeBytes = cursor.readExact(
                endorsementEnvelopeByteLength,
                'endorsement envelope',
            );
            cursor.requireComplete();
            const record = Object.freeze({
                context,
                kind: 'completed' as const,
                preparedInventory,
                endorsementEnvelopeBytes,
            });
            endorsementEnvelopeBytes = undefined;
            return record;
        } catch (error) {
            destroyPreparedInventory(preparedInventory);
            throw error;
        } finally {
            endorsementEnvelopeBytes?.fill(0);
        }
    } catch (error) {
        destroyContext(context);
        throw error;
    } finally {
        verifiedReceiptInventoryBodyBytes?.fill(0);
        terminalBodyBytes?.fill(0);
        endorsementAuthorizationBodyBytes?.fill(0);
        orderedReceiptEnvelopeBytes?.forEach((receiptEnvelope) =>
            receiptEnvelope.fill(0),
        );
    }
};

const destroyRecord = (
    record: SeedReceiptTerminalEndorsementRecord | undefined,
): void => {
    if (record === undefined) {
        return;
    }
    destroyContext(record.context);
    destroyPreparedInventory(record.preparedInventory);
    if (record.kind === 'reserved') {
        record.signatureRandomness.fill(0);
    } else {
        record.endorsementEnvelopeBytes.fill(0);
    }
};

const readRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: SeedReceiptTerminalEndorsementCustodyLimits,
): Promise<OpenedSeedReceiptTerminalEndorsementRecord | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: endorsementCustodyOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        return Object.freeze({
            record: decodeRecord(opened.plaintext, limits),
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
            'Seed-receipt terminal endorsement custody failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const commitRecord = async (input: {
    expectedCurrentSealedBytes: Uint8Array | null;
    limits: SeedReceiptTerminalEndorsementCustodyLimits;
    protection: RuntimeRecordProtection;
    record: SeedReceiptTerminalEndorsementRecord;
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
            operationDomain: endorsementCustodyOperationDomain,
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
    context: SeedReceiptTerminalEndorsementCustodyContext,
): SeedReceiptTerminalEndorsementCustodyContext =>
    Object.freeze({
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        endorserPosition: context.endorserPosition,
        rootTerminalIdentity: context.rootTerminalIdentity.slice(),
    });

const copyPublication = (
    endorsementEnvelopeBytes: Uint8Array,
): RetainedSeedReceiptTerminalEndorsementPublication =>
    Object.freeze({
        endorsementEnvelopeBytes: endorsementEnvelopeBytes.slice(),
    });

/**
 * Owns one alternative-independent receipt-terminal endorsement slot for an
 * action. The complete verified receipt inventory, exact public receipt
 * carriers, retained-local receipt identities, terminal and authorization
 * bodies, and one internally sampled signing seed are encrypted and
 * recency-anchored before signing. The complete endorsement envelope is then
 * atomically retained before publication.
 *
 * The integrity-pinned kernel must have opened its opaque context from the
 * completed authenticated local receipt and exact public receipt inventory.
 * This class accepts no caller-supplied inventory capability, terminal body,
 * signature seed, or endorsement carrier and constructs no protocol acceptance
 * capability.
 */
export class SeedReceiptTerminalEndorsementCustody {
    readonly #context: SeedReceiptTerminalEndorsementCustodyContext;
    readonly #issuedRandomness = new Set<string>();
    readonly #kernel: SeedReceiptTerminalEndorsementCustodyKernel;
    readonly #limits: SeedReceiptTerminalEndorsementCustodyLimits;
    readonly #protection: RuntimeRecordProtection;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        context: SeedReceiptTerminalEndorsementCustodyContext;
        kernel: ProductionSeedReceiptTerminalEndorsementKernel;
        limits: SeedReceiptTerminalEndorsementCustodyLimits;
        protection: RuntimeRecordProtection;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    }) {
        if (!isProductionSeedReceiptTerminalEndorsementKernel(input.kernel)) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-receipt terminal endorsement custody requires an integrity-pinned production kernel.',
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
                'Seed-receipt terminal endorsement custody requires an authenticated storage recency coordinator.',
            );
        }
        this.#context = copyContext(input.context);
        this.#kernel = Object.freeze({
            prepare: input.kernel.prepare.bind(input.kernel),
            produce: input.kernel.produce.bind(input.kernel),
            validate: input.kernel.validate.bind(input.kernel),
        });
        this.#limits = copyLimits(input.limits);
        this.#protection = input.protection;
        this.#recencyCoordinator = input.recencyCoordinator;
    }

    public retainForPublication(): Promise<RetainedSeedReceiptTerminalEndorsementPublication> {
        return this.#schedule(() => this.#prepareAndRetain());
    }

    public resumeForPublication(): Promise<
        RetainedSeedReceiptTerminalEndorsementPublication | undefined
    > {
        return this.#schedule(() => this.#resume());
    }

    #schedule<Result>(operation: () => Promise<Result>): Promise<Result> {
        const scheduled = this.#operationTail.then(operation);
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    async #prepareAndRetain(): Promise<RetainedSeedReceiptTerminalEndorsementPublication> {
        let prepared:
            | PreparedSeedReceiptTerminalEndorsementInventory
            | undefined;
        try {
            let preparationFailed = false;
            let preparationFailure: unknown;
            let preparedValue: unknown;
            try {
                preparedValue = await this.#kernel.prepare();
            } catch (error) {
                preparationFailed = true;
                preparationFailure = error;
            }
            if (preparationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-receipt terminal endorsement preparation rejected the opaque verified context.',
                    preparationFailure,
                );
            }
            prepared = copyPreparedInventory(
                preparedValue,
                this.#context,
                this.#limits,
            );
            await this.#validate(prepared);
            const recordKey = logicalRecordKey(this.#context);
            let opened = await this.#readOpenedRecord(recordKey);
            if (opened === undefined) {
                opened = await this.#reserve(recordKey, prepared);
            }
            return await this.#continueOpened(recordKey, opened, prepared);
        } finally {
            destroyPreparedInventory(prepared);
        }
    }

    async #resume(): Promise<
        RetainedSeedReceiptTerminalEndorsementPublication | undefined
    > {
        const recordKey = logicalRecordKey(this.#context);
        const opened = await this.#readOpenedRecord(recordKey);
        if (opened === undefined) {
            return undefined;
        }
        return this.#continueOpened(recordKey, opened);
    }

    async #continueOpened(
        recordKey: string,
        opened: OpenedSeedReceiptTerminalEndorsementRecord,
        expectedPrepared?: PreparedSeedReceiptTerminalEndorsementInventory,
    ): Promise<RetainedSeedReceiptTerminalEndorsementPublication> {
        try {
            this.#requireMatchingRecord(opened.record, expectedPrepared);
            if (expectedPrepared === undefined) {
                await this.#validate(opened.record.preparedInventory);
            }
            if (opened.record.kind === 'completed') {
                await this.#validate(
                    opened.record.preparedInventory,
                    opened.record.endorsementEnvelopeBytes,
                );
                return copyPublication(opened.record.endorsementEnvelopeBytes);
            }
            const endorsementEnvelopeBytes = await this.#produce(opened.record);
            try {
                await this.#validate(
                    opened.record.preparedInventory,
                    endorsementEnvelopeBytes,
                );
                return await this.#completeReservation({
                    expectedPrepared,
                    endorsementEnvelopeBytes,
                    recordKey,
                    reservation: opened.record,
                    sealedReservationBytes: opened.sealedBytes,
                });
            } finally {
                endorsementEnvelopeBytes.fill(0);
            }
        } finally {
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
        }
    }

    #requireMatchingRecord(
        record: SeedReceiptTerminalEndorsementRecord,
        expectedPrepared?: PreparedSeedReceiptTerminalEndorsementInventory,
    ): void {
        if (
            !contextsEqual(record.context, this.#context) ||
            (expectedPrepared !== undefined &&
                !preparedInventoriesEqual(
                    record.preparedInventory,
                    expectedPrepared,
                ))
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The seed-receipt terminal endorsement slot is durably bound to a different receipt inventory, retained local receipt, or terminal body.',
            );
        }
    }

    async #readOpenedRecord(
        recordKey: string,
    ): Promise<OpenedSeedReceiptTerminalEndorsementRecord | undefined> {
        return this.#recencyCoordinator.runRead((store) =>
            readRecord(store, this.#protection, recordKey, this.#limits),
        );
    }

    async #reserve(
        recordKey: string,
        prepared: PreparedSeedReceiptTerminalEndorsementInventory,
    ): Promise<OpenedSeedReceiptTerminalEndorsementRecord> {
        let signatureRandomness: Uint8Array | undefined;
        try {
            signatureRandomness = sampleRuntimeIdentifier(
                this.#protection,
                this.#issuedRandomness,
                'Receipt-terminal endorsement ML-DSA signature randomness',
            );
            const reservation: ReservedSeedReceiptTerminalEndorsementRecord =
                Object.freeze({
                    context: copyValidationContext(this.#context),
                    kind: 'reserved' as const,
                    preparedInventory: copyPreparedInventory(
                        prepared,
                        this.#context,
                        this.#limits,
                    ),
                    signatureRandomness: signatureRandomness.slice(),
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
                    this.#requireMatchingRecord(existing.record, prepared);
                    return existing;
                }
                return Object.freeze({
                    record: Object.freeze({
                        context: copyValidationContext(reservation.context),
                        kind: 'reserved' as const,
                        preparedInventory: copyPreparedInventory(
                            reservation.preparedInventory,
                            reservation.context,
                            this.#limits,
                        ),
                        signatureRandomness:
                            reservation.signatureRandomness.slice(),
                    }),
                    sealedBytes,
                });
            } finally {
                destroyRecord(reservation);
            }
        } finally {
            signatureRandomness?.fill(0);
        }
    }

    async #produce(
        reservation: ReservedSeedReceiptTerminalEndorsementRecord,
    ): Promise<Uint8Array> {
        const productionInput: SeedReceiptTerminalEndorsementProductionInput =
            Object.freeze({
                preparedInventory: copyPreparedInventory(
                    reservation.preparedInventory,
                    reservation.context,
                    this.#limits,
                ),
                signatureRandomness: reservation.signatureRandomness.slice(),
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
                    'Seed-receipt terminal endorsement production failed before publication.',
                    productionFailure,
                );
            }
            return copyNonemptyBoundedBytes(
                produced,
                this.#limits.maximumEndorsementEnvelopeByteLength,
                'endorsementEnvelopeBytes',
            );
        } finally {
            destroyPreparedInventory(productionInput.preparedInventory);
            productionInput.signatureRandomness.fill(0);
        }
    }

    async #validate(
        prepared: PreparedSeedReceiptTerminalEndorsementInventory,
        endorsementEnvelopeBytes?: Uint8Array,
    ): Promise<void> {
        const validationContext = copyValidationContext(this.#context);
        const validationInput: SeedReceiptTerminalEndorsementValidationInput =
            Object.freeze({
                context: validationContext,
                preparedInventory: copyPreparedInventory(
                    prepared,
                    validationContext,
                    this.#limits,
                ),
                ...(endorsementEnvelopeBytes === undefined
                    ? {}
                    : {
                          endorsementEnvelopeBytes:
                              endorsementEnvelopeBytes.slice(),
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
                    'Seed-receipt terminal endorsement custody failed kernel validation.',
                    validationFailure,
                );
            }
        } finally {
            destroyContext(validationContext);
            destroyPreparedInventory(validationInput.preparedInventory);
            validationInput.endorsementEnvelopeBytes?.fill(0);
        }
    }

    async #completeReservation(input: {
        expectedPrepared?: PreparedSeedReceiptTerminalEndorsementInventory;
        endorsementEnvelopeBytes: Uint8Array;
        recordKey: string;
        reservation: ReservedSeedReceiptTerminalEndorsementRecord;
        sealedReservationBytes: Uint8Array;
    }): Promise<RetainedSeedReceiptTerminalEndorsementPublication> {
        const completedRecord: CompletedSeedReceiptTerminalEndorsementRecord =
            Object.freeze({
                context: copyValidationContext(input.reservation.context),
                kind: 'completed' as const,
                preparedInventory: copyPreparedInventory(
                    input.reservation.preparedInventory,
                    input.reservation.context,
                    this.#limits,
                ),
                endorsementEnvelopeBytes:
                    input.endorsementEnvelopeBytes.slice(),
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
                return copyPublication(
                    completedRecord.endorsementEnvelopeBytes,
                );
            } catch (error) {
                if (!errorHasCode(error, 'Conflict')) {
                    throw error;
                }
                const existing = await this.#readOpenedRecord(input.recordKey);
                if (existing === undefined) {
                    throw error;
                }
                try {
                    this.#requireMatchingRecord(
                        existing.record,
                        input.reservation.preparedInventory,
                    );
                    if (
                        existing.record.kind !== 'completed' ||
                        !bytesEqual(
                            existing.record.endorsementEnvelopeBytes,
                            input.endorsementEnvelopeBytes,
                        )
                    ) {
                        throw new AuthenticatedRuntimeRecordError(
                            'Conflict',
                            'Concurrent seed-receipt terminal endorsement completion selected different carrier bytes.',
                        );
                    }
                    await this.#validate(
                        existing.record.preparedInventory,
                        existing.record.endorsementEnvelopeBytes,
                    );
                    return copyPublication(
                        existing.record.endorsementEnvelopeBytes,
                    );
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
