import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';
import {
    isProductionJoinedSeedMasterCustodyKernel,
    type ProductionJoinedSeedMasterCustodyKernel,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    bytesEqual,
    copyBoundedBytes,
    copyExactBytes,
    mapStorageError,
    readRuntimeRecord,
    runtimeRecordEnvelopeOverheadByteLength,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
} from './authenticated-runtime-record.js';
import { AuthenticatedStorageRecencyCoordinator } from './authenticated-storage-recency.js';
import {
    readCompletedSeedCatalogSourceCustodyForMasterJoin,
    snapshotSeedCatalogSourceCustodyLimitsForMasterJoin,
    type CompletedSeedCatalogSourceCustodyForMasterJoin,
    type SeedCatalogSourceCustodyContext,
    type SeedCatalogSourceCustodyLimits,
} from './seed-catalog-source-custody.js';
import {
    readSelectedSeedRecipientAuthenticationCustodyForMasterJoin,
    snapshotSeedRecipientAuthenticationCustodyLimitsForMasterJoin,
    stageSeedRecipientAuthenticationCustodyMasterJoinCompletion,
    type JoinedSeedRecipientAuthenticationCustodyForMasterJoin,
    type SeedRecipientAuthenticationCustodyLimits,
    type SelectedSeedRecipientAuthenticationCustodyForMasterJoin,
} from './seed-recipient-authentication-custody.js';
import {
    readCompletedSeedRecipientReceiptCustodyForMasterJoin,
    snapshotSeedRecipientReceiptCustodyLimitsForMasterJoin,
    type CompletedSeedRecipientReceiptCustodyForMasterJoin,
    type SeedRecipientReceiptCustodyContext,
    type SeedRecipientReceiptCustodyLimits,
} from './seed-recipient-receipt-custody.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const joinedCustodyRecordMagic = Uint8Array.of(0x53, 0x4c, 0x4a, 0x4d);
const joinedCustodyJoinRequestMagic = Uint8Array.of(0x53, 0x4c, 0x4a, 0x51);
const joinedCustodyRecordVersion = 1;
const hashByteLength = 64;
const preparationAttemptOrdinal = 0;
const unsigned32Maximum = 0xffff_ffff;
const joinedCustodyOperationDomain =
    'sealed-lattice/runtime/joined-seed-master-custody-record/v1';
const joinedCustodyHashFieldCount = 13;
const joinedCustodyVariableFieldCount = 4;
const joinedCustodyJoinRequestVariableFieldCount = 5;
const joinedCustodyContextByteLength =
    joinedCustodyHashFieldCount * hashByteLength + 3 * 2;
const joinedCustodyFixedPlaintextByteLength =
    joinedCustodyRecordMagic.byteLength +
    2 +
    joinedCustodyContextByteLength +
    joinedCustodyVariableFieldCount * 4;
const joinedCustodyJoinRequestFixedByteLength =
    joinedCustodyJoinRequestMagic.byteLength +
    2 +
    joinedCustodyContextByteLength +
    joinedCustodyJoinRequestVariableFieldCount * 4;
const joinedCustodyJoinResponseFixedByteLength = 4 + 2 + 1 + 4;
const joinedCustodyValidationResponseByteLength = 4 + 2 + 1;

export type JoinedSeedMasterCustodyContext = Readonly<{
    actionContextIdentity: Uint8Array;
    authenticatedRecipientInventoryIdentity: Uint8Array;
    catalogCompilerIdentity: Uint8Array;
    parameterIdentity: Uint8Array;
    participantCount: number;
    participantPosition: number;
    preparationAttemptOrdinal: number;
    preparationContextIdentity: Uint8Array;
    receiptBodyIdentity: Uint8Array;
    receiptEnvelopeIdentity: Uint8Array;
    receiptTerminalCertificateIdentity: Uint8Array;
    receiptTerminalIdentity: Uint8Array;
    rootTerminalCertificateIdentity: Uint8Array;
    rootTerminalIdentity: Uint8Array;
    rosterIdentity: Uint8Array;
    statePredecessorIdentity: Uint8Array;
}>;

export type JoinedSeedMasterCustodyLimits = Readonly<{
    maximumJoinedMasterPayloadByteLength: number;
    maximumReceiptTerminalCertificateByteLength: number;
    maximumRootTerminalCertificateByteLength: number;
    maximumVerificationContextByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

type JoinedSeedMasterCustodyRecordByteLengths = Readonly<{
    atomicTransitionCiphertextOverlapByteLength: number;
    joinRequestByteLength: number;
    joinResponseByteLength: number;
    joinedCiphertextByteLength: number;
    joinedPlaintextByteLength: number;
    joinedValidationRequestByteLength: number;
    joinedValidationResponseByteLength: number;
    logicallyReclaimedPredecessorCiphertextByteLength: number;
    maximumKernelInputByteLength: number;
    maximumColdRestartReadByteLength: number;
    netCiphertextReclamationByteLength: number;
    retainedSuccessorCiphertextByteLength: number;
}>;

/**
 * Inert confirmation that one encrypted joined record is retained locally.
 *
 * This object is deliberately not a master handle, coin-opening capability,
 * burn result, or preparation-continuation capability.
 */
type RetainedJoinedSeedMasterCustody = Readonly<{
    joinedCiphertextByteLength: number;
    participantPosition: number;
    receiptTerminalIdentity: Uint8Array;
    rootTerminalIdentity: Uint8Array;
}>;

type JoinedSeedMasterTransitionInput = Readonly<{
    receiptTerminalCertificateBytes: Uint8Array;
    rootTerminalCertificateBytes: Uint8Array;
    verificationContextBytes: Uint8Array;
}>;

type JoinedSeedMasterRecord = JoinedSeedMasterTransitionInput &
    Readonly<{
        context: JoinedSeedMasterCustodyContext;
        joinedMasterPayloadBytes: Uint8Array;
    }>;

type OpenedJoinedSeedMasterRecord = Readonly<{
    record: JoinedSeedMasterRecord;
    sealedBytes: Uint8Array;
}>;

const joinedSeedMasterRestorationAuthorizationBrand: unique symbol = Symbol(
    'joined-seed-master-restoration-authorization',
);

/**
 * One-shot authority to read one recency-anchored joined record into a later
 * Rust operation. It exposes no retained bytes and is not a preparation,
 * coin-opening, burn, or continuation capability.
 */
export type JoinedSeedMasterRestorationAuthorization = Readonly<{
    readonly [joinedSeedMasterRestorationAuthorizationBrand]: true;
}>;

/**
 * Exact authenticated predecessor bytes for a Rust consumer. That consumer
 * must positively reverify the complete record and erase these bytes after
 * use; this object alone authorizes no cryptographic transition.
 */
export type ConsumedJoinedSeedMasterRestorationAuthorization = Readonly<{
    context: JoinedSeedMasterCustodyContext;
    recordBytes: Uint8Array;
}>;

const joinedSeedMasterRestorationAuthorizationReaders = new WeakMap<
    object,
    () => Promise<ConsumedJoinedSeedMasterRestorationAuthorization>
>();

export const consumeJoinedSeedMasterRestorationAuthorization = async (
    authorization: JoinedSeedMasterRestorationAuthorization,
): Promise<ConsumedJoinedSeedMasterRestorationAuthorization> => {
    if (typeof authorization !== 'object' || authorization === null) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Joined seed-master restoration authorization must be an opaque state-owner capability.',
        );
    }
    const read =
        joinedSeedMasterRestorationAuthorizationReaders.get(authorization);
    if (read === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Joined seed-master restoration authorization is invalid or has already been consumed.',
        );
    }
    joinedSeedMasterRestorationAuthorizationReaders.delete(authorization);
    return read();
};

type SourcePredecessorState =
    | CompletedSeedCatalogSourceCustodyForMasterJoin
    | 'incomplete'
    | undefined;
type ReceiptPredecessorState =
    | CompletedSeedRecipientReceiptCustodyForMasterJoin
    | 'incomplete'
    | undefined;
type AuthenticationPredecessorState =
    | JoinedSeedRecipientAuthenticationCustodyForMasterJoin
    | SelectedSeedRecipientAuthenticationCustodyForMasterJoin
    | 'burned'
    | undefined;

type JoinedSeedMasterStorageSnapshot = Readonly<{
    authentication: AuthenticationPredecessorState;
    joined: OpenedJoinedSeedMasterRecord | undefined;
    receipt: ReceiptPredecessorState;
    source: SourcePredecessorState;
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
    const value = left + right;
    if (!Number.isSafeInteger(value)) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            `${label} exceeds the safe integer range.`,
        );
    }
    return value;
};

const sumByteLengths = (values: readonly number[], label: string): number =>
    values.reduce((total, value) => checkedAdd(total, value, label), 0);

const copyNonzeroHash = (
    container: unknown,
    propertyName: string,
    containerName: string,
): Uint8Array => {
    const bytes = copyExactBytes(
        snapshotDataProperty(container, propertyName, containerName),
        hashByteLength,
        `${containerName}.${propertyName}`,
    );
    if (bytes.every((byte) => byte === 0)) {
        bytes.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `${containerName}.${propertyName} must not be all zero.`,
        );
    }
    return bytes;
};

const copyContext = (value: unknown): JoinedSeedMasterCustodyContext => {
    const participantCount = requireSafeInteger(
        snapshotDataProperty(value, 'participantCount', 'context'),
        configurableParticipantCountRange.minimum,
        configurableParticipantCountRange.maximum,
        'context.participantCount',
        'InvalidConfiguration',
    );
    const participantPosition = requireSafeInteger(
        snapshotDataProperty(value, 'participantPosition', 'context'),
        0,
        participantCount - 1,
        'context.participantPosition',
        'InvalidConfiguration',
    );
    const attempt = requireSafeInteger(
        snapshotDataProperty(value, 'preparationAttemptOrdinal', 'context'),
        preparationAttemptOrdinal,
        preparationAttemptOrdinal,
        'context.preparationAttemptOrdinal',
        'InvalidConfiguration',
    );
    return Object.freeze({
        actionContextIdentity: copyNonzeroHash(
            value,
            'actionContextIdentity',
            'context',
        ),
        authenticatedRecipientInventoryIdentity: copyNonzeroHash(
            value,
            'authenticatedRecipientInventoryIdentity',
            'context',
        ),
        catalogCompilerIdentity: copyNonzeroHash(
            value,
            'catalogCompilerIdentity',
            'context',
        ),
        parameterIdentity: copyNonzeroHash(
            value,
            'parameterIdentity',
            'context',
        ),
        participantCount,
        participantPosition,
        preparationAttemptOrdinal: attempt,
        preparationContextIdentity: copyNonzeroHash(
            value,
            'preparationContextIdentity',
            'context',
        ),
        receiptBodyIdentity: copyNonzeroHash(
            value,
            'receiptBodyIdentity',
            'context',
        ),
        receiptEnvelopeIdentity: copyNonzeroHash(
            value,
            'receiptEnvelopeIdentity',
            'context',
        ),
        receiptTerminalCertificateIdentity: copyNonzeroHash(
            value,
            'receiptTerminalCertificateIdentity',
            'context',
        ),
        receiptTerminalIdentity: copyNonzeroHash(
            value,
            'receiptTerminalIdentity',
            'context',
        ),
        rootTerminalCertificateIdentity: copyNonzeroHash(
            value,
            'rootTerminalCertificateIdentity',
            'context',
        ),
        rootTerminalIdentity: copyNonzeroHash(
            value,
            'rootTerminalIdentity',
            'context',
        ),
        rosterIdentity: copyNonzeroHash(value, 'rosterIdentity', 'context'),
        statePredecessorIdentity: copyNonzeroHash(
            value,
            'statePredecessorIdentity',
            'context',
        ),
    });
};

const copyContextValue = (
    context: JoinedSeedMasterCustodyContext,
): JoinedSeedMasterCustodyContext =>
    Object.freeze({
        actionContextIdentity: context.actionContextIdentity.slice(),
        authenticatedRecipientInventoryIdentity:
            context.authenticatedRecipientInventoryIdentity.slice(),
        catalogCompilerIdentity: context.catalogCompilerIdentity.slice(),
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        participantPosition: context.participantPosition,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        receiptBodyIdentity: context.receiptBodyIdentity.slice(),
        receiptEnvelopeIdentity: context.receiptEnvelopeIdentity.slice(),
        receiptTerminalCertificateIdentity:
            context.receiptTerminalCertificateIdentity.slice(),
        receiptTerminalIdentity: context.receiptTerminalIdentity.slice(),
        rootTerminalCertificateIdentity:
            context.rootTerminalCertificateIdentity.slice(),
        rootTerminalIdentity: context.rootTerminalIdentity.slice(),
        rosterIdentity: context.rosterIdentity.slice(),
        statePredecessorIdentity: context.statePredecessorIdentity.slice(),
    });

const destroyContext = (
    context: JoinedSeedMasterCustodyContext | undefined,
): void => {
    context?.actionContextIdentity.fill(0);
    context?.authenticatedRecipientInventoryIdentity.fill(0);
    context?.catalogCompilerIdentity.fill(0);
    context?.parameterIdentity.fill(0);
    context?.preparationContextIdentity.fill(0);
    context?.receiptBodyIdentity.fill(0);
    context?.receiptEnvelopeIdentity.fill(0);
    context?.receiptTerminalCertificateIdentity.fill(0);
    context?.receiptTerminalIdentity.fill(0);
    context?.rootTerminalCertificateIdentity.fill(0);
    context?.rootTerminalIdentity.fill(0);
    context?.rosterIdentity.fill(0);
    context?.statePredecessorIdentity.fill(0);
};

const contextsEqual = (
    left: JoinedSeedMasterCustodyContext,
    right: JoinedSeedMasterCustodyContext,
): boolean =>
    left.participantCount === right.participantCount &&
    left.participantPosition === right.participantPosition &&
    left.preparationAttemptOrdinal === right.preparationAttemptOrdinal &&
    bytesEqual(left.actionContextIdentity, right.actionContextIdentity) &&
    bytesEqual(
        left.authenticatedRecipientInventoryIdentity,
        right.authenticatedRecipientInventoryIdentity,
    ) &&
    bytesEqual(left.catalogCompilerIdentity, right.catalogCompilerIdentity) &&
    bytesEqual(left.parameterIdentity, right.parameterIdentity) &&
    bytesEqual(
        left.preparationContextIdentity,
        right.preparationContextIdentity,
    ) &&
    bytesEqual(left.receiptBodyIdentity, right.receiptBodyIdentity) &&
    bytesEqual(left.receiptEnvelopeIdentity, right.receiptEnvelopeIdentity) &&
    bytesEqual(
        left.receiptTerminalCertificateIdentity,
        right.receiptTerminalCertificateIdentity,
    ) &&
    bytesEqual(left.receiptTerminalIdentity, right.receiptTerminalIdentity) &&
    bytesEqual(
        left.rootTerminalCertificateIdentity,
        right.rootTerminalCertificateIdentity,
    ) &&
    bytesEqual(left.rootTerminalIdentity, right.rootTerminalIdentity) &&
    bytesEqual(left.rosterIdentity, right.rosterIdentity) &&
    bytesEqual(left.statePredecessorIdentity, right.statePredecessorIdentity);

const copyLimits = (value: unknown): JoinedSeedMasterCustodyLimits => {
    const readByteLimit = (propertyName: string): number =>
        requireSafeInteger(
            snapshotDataProperty(value, propertyName, 'limits'),
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            `limits.${propertyName}`,
            'InvalidConfiguration',
        );
    const limits = Object.freeze({
        maximumJoinedMasterPayloadByteLength: readByteLimit(
            'maximumJoinedMasterPayloadByteLength',
        ),
        maximumReceiptTerminalCertificateByteLength: readByteLimit(
            'maximumReceiptTerminalCertificateByteLength',
        ),
        maximumRootTerminalCertificateByteLength: readByteLimit(
            'maximumRootTerminalCertificateByteLength',
        ),
        maximumVerificationContextByteLength: readByteLimit(
            'maximumVerificationContextByteLength',
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
    const maximumPlaintextByteLength = sumByteLengths(
        [
            joinedCustodyFixedPlaintextByteLength,
            limits.maximumJoinedMasterPayloadByteLength,
            limits.maximumReceiptTerminalCertificateByteLength,
            limits.maximumRootTerminalCertificateByteLength,
            limits.maximumVerificationContextByteLength,
        ],
        'Maximum joined seed-master custody record',
    );
    if (
        maximumPlaintextByteLength >
        foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Joined seed-master custody limits exceed the absolute copied-buffer bound.',
        );
    }
    return limits;
};

const requireByteLength = (value: unknown, label: string): number =>
    requireSafeInteger(value, 1, unsigned32Maximum, label);

const deriveJoinedPlaintextByteLength = (input: {
    joinedMasterPayloadByteLength: number;
    receiptTerminalCertificateByteLength: number;
    rootTerminalCertificateByteLength: number;
    verificationContextByteLength: number;
}): number =>
    sumByteLengths(
        [
            joinedCustodyFixedPlaintextByteLength,
            requireByteLength(
                input.joinedMasterPayloadByteLength,
                'Joined master payload byte length',
            ),
            requireByteLength(
                input.receiptTerminalCertificateByteLength,
                'Receipt-terminal certificate byte length',
            ),
            requireByteLength(
                input.rootTerminalCertificateByteLength,
                'Root-terminal certificate byte length',
            ),
            requireByteLength(
                input.verificationContextByteLength,
                'Verification-context byte length',
            ),
        ],
        'Joined seed-master custody plaintext',
    );

export const deriveJoinedSeedMasterCustodyRecordByteLengths = (input: {
    authenticationPredecessorCiphertextByteLength: number;
    authenticationSuccessorCiphertextByteLength: number;
    joinedMasterPayloadByteLength: number;
    receiptPredecessorCiphertextByteLength: number;
    receiptTerminalCertificateByteLength: number;
    rootTerminalCertificateByteLength: number;
    sourcePredecessorCiphertextByteLength: number;
    verificationContextByteLength: number;
}): JoinedSeedMasterCustodyRecordByteLengths => {
    const joinedPlaintextByteLength = deriveJoinedPlaintextByteLength(input);
    const joinedCiphertextByteLength = checkedAdd(
        joinedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Joined seed-master custody ciphertext',
    );
    const sourcePredecessorCiphertextByteLength = requireByteLength(
        input.sourcePredecessorCiphertextByteLength,
        'Source predecessor ciphertext byte length',
    );
    const receiptPredecessorCiphertextByteLength = requireByteLength(
        input.receiptPredecessorCiphertextByteLength,
        'Receipt predecessor ciphertext byte length',
    );
    const authenticationPredecessorCiphertextByteLength = requireByteLength(
        input.authenticationPredecessorCiphertextByteLength,
        'Authentication predecessor ciphertext byte length',
    );
    const authenticationSuccessorCiphertextByteLength = requireByteLength(
        input.authenticationSuccessorCiphertextByteLength,
        'Authentication successor ciphertext byte length',
    );
    if (
        authenticationPredecessorCiphertextByteLength <=
            runtimeRecordEnvelopeOverheadByteLength ||
        sourcePredecessorCiphertextByteLength <=
            runtimeRecordEnvelopeOverheadByteLength ||
        receiptPredecessorCiphertextByteLength <=
            runtimeRecordEnvelopeOverheadByteLength ||
        authenticationSuccessorCiphertextByteLength <=
            runtimeRecordEnvelopeOverheadByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Joined seed-master predecessors cannot contain an empty authenticated plaintext.',
        );
    }
    const sourcePredecessorPlaintextByteLength =
        sourcePredecessorCiphertextByteLength -
        runtimeRecordEnvelopeOverheadByteLength;
    const receiptPredecessorPlaintextByteLength =
        receiptPredecessorCiphertextByteLength -
        runtimeRecordEnvelopeOverheadByteLength;
    const joinRequestByteLength = sumByteLengths(
        [
            joinedCustodyJoinRequestFixedByteLength,
            sourcePredecessorPlaintextByteLength,
            receiptPredecessorPlaintextByteLength,
            requireByteLength(
                input.verificationContextByteLength,
                'Verification-context byte length',
            ),
            requireByteLength(
                input.rootTerminalCertificateByteLength,
                'Root-terminal certificate byte length',
            ),
            requireByteLength(
                input.receiptTerminalCertificateByteLength,
                'Receipt-terminal certificate byte length',
            ),
        ],
        'Joined seed-master kernel request',
    );
    if (
        joinRequestByteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Joined seed-master kernel request exceeds the absolute copied-buffer bound.',
        );
    }
    const joinResponseByteLength = checkedAdd(
        joinedCustodyJoinResponseFixedByteLength,
        requireByteLength(
            input.joinedMasterPayloadByteLength,
            'Joined master payload byte length',
        ),
        'Joined seed-master kernel response',
    );
    const logicallyReclaimedPredecessorCiphertextByteLength = sumByteLengths(
        [
            authenticationPredecessorCiphertextByteLength,
            sourcePredecessorCiphertextByteLength,
            receiptPredecessorCiphertextByteLength,
        ],
        'Logically reclaimed joined-master predecessors',
    );
    const retainedSuccessorCiphertextByteLength = checkedAdd(
        authenticationSuccessorCiphertextByteLength,
        joinedCiphertextByteLength,
        'Joined seed-master retained successor ciphertexts',
    );
    if (
        retainedSuccessorCiphertextByteLength >
        logicallyReclaimedPredecessorCiphertextByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Joined seed-master retained successors exceed their replaced predecessors.',
        );
    }
    return Object.freeze({
        atomicTransitionCiphertextOverlapByteLength: checkedAdd(
            logicallyReclaimedPredecessorCiphertextByteLength,
            retainedSuccessorCiphertextByteLength,
            'Joined seed-master atomic transition overlap',
        ),
        joinRequestByteLength,
        joinResponseByteLength,
        joinedCiphertextByteLength,
        joinedPlaintextByteLength,
        joinedValidationRequestByteLength: joinedPlaintextByteLength,
        joinedValidationResponseByteLength:
            joinedCustodyValidationResponseByteLength,
        logicallyReclaimedPredecessorCiphertextByteLength,
        maximumKernelInputByteLength: Math.max(
            joinRequestByteLength,
            joinedPlaintextByteLength,
        ),
        maximumColdRestartReadByteLength: checkedAdd(
            authenticationSuccessorCiphertextByteLength,
            joinedCiphertextByteLength,
            'Joined seed-master cold-restart authenticated record reads',
        ),
        netCiphertextReclamationByteLength:
            logicallyReclaimedPredecessorCiphertextByteLength -
            retainedSuccessorCiphertextByteLength,
        retainedSuccessorCiphertextByteLength,
    });
};

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
        if (part.byteLength > output.byteLength - offset) {
            output.fill(0);
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Joined seed-master custody record exceeds its derived byte length.',
            );
        }
        output.set(part, offset);
        offset += part.byteLength;
    }
    if (offset !== expectedByteLength) {
        output.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Joined seed-master custody encoded an unexpected byte length.',
        );
    }
    return output;
};

const encodeContext = (context: JoinedSeedMasterCustodyContext): Uint8Array =>
    concatenateBytes(
        [
            context.parameterIdentity,
            context.rosterIdentity,
            context.actionContextIdentity,
            context.preparationContextIdentity,
            context.catalogCompilerIdentity,
            context.statePredecessorIdentity,
            context.rootTerminalIdentity,
            context.rootTerminalCertificateIdentity,
            context.receiptTerminalIdentity,
            context.receiptTerminalCertificateIdentity,
            context.authenticatedRecipientInventoryIdentity,
            context.receiptBodyIdentity,
            context.receiptEnvelopeIdentity,
            unsigned16LittleEndian(context.preparationAttemptOrdinal),
            unsigned16LittleEndian(context.participantCount),
            unsigned16LittleEndian(context.participantPosition),
        ],
        joinedCustodyContextByteLength,
    );

const copyTransitionInput = (
    value: unknown,
    limits: JoinedSeedMasterCustodyLimits,
): JoinedSeedMasterTransitionInput =>
    Object.freeze({
        receiptTerminalCertificateBytes: copyBoundedBytes(
            snapshotDataProperty(
                value,
                'receiptTerminalCertificateBytes',
                'input',
            ),
            limits.maximumReceiptTerminalCertificateByteLength,
            'input.receiptTerminalCertificateBytes',
        ),
        rootTerminalCertificateBytes: copyBoundedBytes(
            snapshotDataProperty(
                value,
                'rootTerminalCertificateBytes',
                'input',
            ),
            limits.maximumRootTerminalCertificateByteLength,
            'input.rootTerminalCertificateBytes',
        ),
        verificationContextBytes: copyBoundedBytes(
            snapshotDataProperty(value, 'verificationContextBytes', 'input'),
            limits.maximumVerificationContextByteLength,
            'input.verificationContextBytes',
        ),
    });

const copyTransitionInputValue = (
    input: JoinedSeedMasterTransitionInput,
): JoinedSeedMasterTransitionInput =>
    Object.freeze({
        receiptTerminalCertificateBytes:
            input.receiptTerminalCertificateBytes.slice(),
        rootTerminalCertificateBytes:
            input.rootTerminalCertificateBytes.slice(),
        verificationContextBytes: input.verificationContextBytes.slice(),
    });

const transitionInputsEqual = (
    left: JoinedSeedMasterTransitionInput,
    right: JoinedSeedMasterTransitionInput,
): boolean =>
    bytesEqual(
        left.receiptTerminalCertificateBytes,
        right.receiptTerminalCertificateBytes,
    ) &&
    bytesEqual(
        left.rootTerminalCertificateBytes,
        right.rootTerminalCertificateBytes,
    ) &&
    bytesEqual(left.verificationContextBytes, right.verificationContextBytes);

const destroyTransitionInput = (
    input: JoinedSeedMasterTransitionInput | undefined,
): void => {
    input?.receiptTerminalCertificateBytes.fill(0);
    input?.rootTerminalCertificateBytes.fill(0);
    input?.verificationContextBytes.fill(0);
};

const createRecord = (input: {
    context: JoinedSeedMasterCustodyContext;
    joinedMasterPayloadBytes: Uint8Array;
    transitionInput: JoinedSeedMasterTransitionInput;
}): JoinedSeedMasterRecord =>
    Object.freeze({
        context: copyContextValue(input.context),
        joinedMasterPayloadBytes: input.joinedMasterPayloadBytes.slice(),
        ...copyTransitionInputValue(input.transitionInput),
    });

const destroyRecord = (record: JoinedSeedMasterRecord | undefined): void => {
    if (record === undefined) {
        return;
    }
    destroyContext(record.context);
    record.joinedMasterPayloadBytes.fill(0);
    destroyTransitionInput(record);
};

const recordKey = (context: JoinedSeedMasterCustodyContext): string =>
    `seed-master/joined-custody/${context.preparationAttemptOrdinal
        .toString(10)
        .padStart(5, '0')}/${context.participantPosition
        .toString(10)
        .padStart(5, '0')}`;

const encodeRecord = (record: JoinedSeedMasterRecord): Uint8Array => {
    const joinedPlaintextByteLength = deriveJoinedPlaintextByteLength({
        joinedMasterPayloadByteLength:
            record.joinedMasterPayloadBytes.byteLength,
        receiptTerminalCertificateByteLength:
            record.receiptTerminalCertificateBytes.byteLength,
        rootTerminalCertificateByteLength:
            record.rootTerminalCertificateBytes.byteLength,
        verificationContextByteLength:
            record.verificationContextBytes.byteLength,
    });
    const contextBytes = encodeContext(record.context);
    try {
        return concatenateBytes(
            [
                joinedCustodyRecordMagic,
                unsigned16LittleEndian(joinedCustodyRecordVersion),
                contextBytes,
                unsigned32LittleEndian(
                    record.verificationContextBytes.byteLength,
                ),
                unsigned32LittleEndian(
                    record.rootTerminalCertificateBytes.byteLength,
                ),
                unsigned32LittleEndian(
                    record.receiptTerminalCertificateBytes.byteLength,
                ),
                unsigned32LittleEndian(
                    record.joinedMasterPayloadBytes.byteLength,
                ),
                record.verificationContextBytes,
                record.rootTerminalCertificateBytes,
                record.receiptTerminalCertificateBytes,
                record.joinedMasterPayloadBytes,
            ],
            joinedPlaintextByteLength,
        );
    } finally {
        contextBytes.fill(0);
    }
};

const encodeJoinRequest = (input: {
    context: JoinedSeedMasterCustodyContext;
    receiptCustodyRecordBytes: Uint8Array;
    sourceCustodyRecordBytes: Uint8Array;
    transitionInput: JoinedSeedMasterTransitionInput;
}): Uint8Array => {
    const variableFields = [
        input.sourceCustodyRecordBytes,
        input.receiptCustodyRecordBytes,
        input.transitionInput.verificationContextBytes,
        input.transitionInput.rootTerminalCertificateBytes,
        input.transitionInput.receiptTerminalCertificateBytes,
    ] as const;
    const variableFieldByteLength = variableFields.reduce(
        (total, fieldBytes, fieldPosition) =>
            checkedAdd(
                total,
                requireByteLength(
                    fieldBytes.byteLength,
                    `Joined seed-master request field ${fieldPosition} byte length`,
                ),
                'Joined seed-master request',
            ),
        0,
    );
    const requestByteLength = sumByteLengths(
        [joinedCustodyJoinRequestFixedByteLength, variableFieldByteLength],
        'Joined seed-master request',
    );
    if (requestByteLength > foundationProfile.maximumCopiedBufferByteLength) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Joined seed-master request exceeds the absolute copied-buffer bound.',
        );
    }
    const contextBytes = encodeContext(input.context);
    try {
        return concatenateBytes(
            [
                joinedCustodyJoinRequestMagic,
                unsigned16LittleEndian(joinedCustodyRecordVersion),
                contextBytes,
                ...variableFields.flatMap((fieldBytes) => [
                    unsigned32LittleEndian(fieldBytes.byteLength),
                    fieldBytes,
                ]),
            ],
            requestByteLength,
        );
    } finally {
        contextBytes.fill(0);
    }
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
                `Joined seed-master custody record ends within ${label}.`,
            );
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
                'Joined seed-master custody record has trailing bytes.',
            );
        }
    }
}

const decodeRecord = (
    plaintext: Uint8Array,
    limits: JoinedSeedMasterCustodyLimits,
): JoinedSeedMasterRecord => {
    if (
        plaintext.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Joined seed-master custody record exceeds the absolute copied-buffer bound.',
        );
    }
    const cursor = new BoundedRecordCursor(plaintext);
    const magic = cursor.readExact(
        joinedCustodyRecordMagic.byteLength,
        'record magic',
    );
    try {
        if (!bytesEqual(magic, joinedCustodyRecordMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Joined seed-master custody record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (
        cursor.readUnsigned16('record version') !== joinedCustodyRecordVersion
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Joined seed-master custody record has an unsupported version.',
        );
    }
    const rawContext = Object.freeze({
        parameterIdentity: cursor.readExact(
            hashByteLength,
            'parameter identity',
        ),
        rosterIdentity: cursor.readExact(hashByteLength, 'roster identity'),
        actionContextIdentity: cursor.readExact(
            hashByteLength,
            'action-context identity',
        ),
        preparationContextIdentity: cursor.readExact(
            hashByteLength,
            'preparation-context identity',
        ),
        catalogCompilerIdentity: cursor.readExact(
            hashByteLength,
            'catalog-compiler identity',
        ),
        statePredecessorIdentity: cursor.readExact(
            hashByteLength,
            'state-predecessor identity',
        ),
        rootTerminalIdentity: cursor.readExact(
            hashByteLength,
            'root-terminal identity',
        ),
        rootTerminalCertificateIdentity: cursor.readExact(
            hashByteLength,
            'root-terminal certificate identity',
        ),
        receiptTerminalIdentity: cursor.readExact(
            hashByteLength,
            'receipt-terminal identity',
        ),
        receiptTerminalCertificateIdentity: cursor.readExact(
            hashByteLength,
            'receipt-terminal certificate identity',
        ),
        authenticatedRecipientInventoryIdentity: cursor.readExact(
            hashByteLength,
            'authenticated recipient-inventory identity',
        ),
        receiptBodyIdentity: cursor.readExact(
            hashByteLength,
            'receipt-body identity',
        ),
        receiptEnvelopeIdentity: cursor.readExact(
            hashByteLength,
            'receipt-envelope identity',
        ),
        preparationAttemptOrdinal: cursor.readUnsigned16(
            'preparation-attempt ordinal',
        ),
        participantCount: cursor.readUnsigned16('participant count'),
        participantPosition: cursor.readUnsigned16('participant position'),
    });
    let context: JoinedSeedMasterCustodyContext | undefined;
    let transitionInput: JoinedSeedMasterTransitionInput | undefined;
    let joinedMasterPayloadBytes: Uint8Array | undefined;
    try {
        try {
            context = copyContext(rawContext);
        } catch (error) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Joined seed-master custody record has an invalid context.',
                error,
            );
        } finally {
            destroyContext(rawContext);
        }
        const verificationContextByteLength = requireSafeInteger(
            cursor.readUnsigned32('verification-context byte length'),
            1,
            limits.maximumVerificationContextByteLength,
            'Stored verification-context byte length',
            'AuthenticationFailed',
        );
        const rootTerminalCertificateByteLength = requireSafeInteger(
            cursor.readUnsigned32('root-terminal certificate byte length'),
            1,
            limits.maximumRootTerminalCertificateByteLength,
            'Stored root-terminal certificate byte length',
            'AuthenticationFailed',
        );
        const receiptTerminalCertificateByteLength = requireSafeInteger(
            cursor.readUnsigned32('receipt-terminal certificate byte length'),
            1,
            limits.maximumReceiptTerminalCertificateByteLength,
            'Stored receipt-terminal certificate byte length',
            'AuthenticationFailed',
        );
        const joinedMasterPayloadByteLength = requireSafeInteger(
            cursor.readUnsigned32('joined master payload byte length'),
            1,
            limits.maximumJoinedMasterPayloadByteLength,
            'Stored joined master payload byte length',
            'AuthenticationFailed',
        );
        transitionInput = Object.freeze({
            verificationContextBytes: cursor.readExact(
                verificationContextByteLength,
                'verification-context bytes',
            ),
            rootTerminalCertificateBytes: cursor.readExact(
                rootTerminalCertificateByteLength,
                'root-terminal certificate bytes',
            ),
            receiptTerminalCertificateBytes: cursor.readExact(
                receiptTerminalCertificateByteLength,
                'receipt-terminal certificate bytes',
            ),
        });
        joinedMasterPayloadBytes = cursor.readExact(
            joinedMasterPayloadByteLength,
            'joined master payload bytes',
        );
        cursor.requireComplete();
        const record = Object.freeze({
            context,
            joinedMasterPayloadBytes,
            ...transitionInput,
        });
        context = undefined;
        joinedMasterPayloadBytes = undefined;
        transitionInput = undefined;
        return record;
    } finally {
        destroyContext(context);
        joinedMasterPayloadBytes?.fill(0);
        destroyTransitionInput(transitionInput);
    }
};

const readJoinedRecord = async (input: {
    context: JoinedSeedMasterCustodyContext;
    limits: JoinedSeedMasterCustodyLimits;
    protection: RuntimeRecordProtection;
    store: UntrustedStorageTransactionStore;
}): Promise<OpenedJoinedSeedMasterRecord | undefined> => {
    const joinedRecordKey = recordKey(input.context);
    const opened = await readRuntimeRecord({
        logicalRecordKey: joinedRecordKey,
        operationDomain: joinedCustodyOperationDomain,
        protection: input.protection,
        store: input.store,
    });
    if (opened === undefined) {
        return undefined;
    }
    let record: JoinedSeedMasterRecord | undefined;
    let canonicalRecordBytes: Uint8Array | undefined;
    try {
        record = decodeRecord(opened.plaintext, input.limits);
        if (!contextsEqual(record.context, input.context)) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The joined seed-master slot is bound to a different context.',
            );
        }
        canonicalRecordBytes = encodeRecord(record);
        if (!bytesEqual(canonicalRecordBytes, opened.plaintext)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'The joined seed-master custody record is not canonical.',
            );
        }
        const output = Object.freeze({
            record,
            sealedBytes: opened.sealedBytes.slice(),
        });
        record = undefined;
        return output;
    } finally {
        canonicalRecordBytes?.fill(0);
        destroyRecord(record);
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

const createSourceContext = (
    context: JoinedSeedMasterCustodyContext,
): SeedCatalogSourceCustodyContext =>
    Object.freeze({
        actionContextIdentity: context.actionContextIdentity.slice(),
        catalogCompilerIdentity: context.catalogCompilerIdentity.slice(),
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        participantPosition: context.participantPosition,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        rosterIdentity: context.rosterIdentity.slice(),
        statePredecessorIdentity: context.statePredecessorIdentity.slice(),
    });

const createReceiptContext = (
    context: JoinedSeedMasterCustodyContext,
): SeedRecipientReceiptCustodyContext =>
    Object.freeze({
        parameterIdentity: context.parameterIdentity.slice(),
        participantCount: context.participantCount,
        preparationAttemptOrdinal: context.preparationAttemptOrdinal,
        preparationContextIdentity: context.preparationContextIdentity.slice(),
        recipientPosition: context.participantPosition,
        rootTerminalIdentity: context.rootTerminalIdentity.slice(),
    });

const destroySourcePredecessor = (
    predecessor: SourcePredecessorState,
): void => {
    if (predecessor === undefined || predecessor === 'incomplete') {
        return;
    }
    predecessor.recordBytes.fill(0);
    predecessor.sealedBytes.fill(0);
};

const destroyReceiptPredecessor = (
    predecessor: ReceiptPredecessorState,
): void => {
    if (predecessor === undefined || predecessor === 'incomplete') {
        return;
    }
    predecessor.recordBytes.fill(0);
    predecessor.sealedBytes.fill(0);
};

const destroyAuthenticationPredecessor = (
    predecessor: AuthenticationPredecessorState,
): void => {
    if (predecessor === undefined || predecessor === 'burned') {
        return;
    }
    if (predecessor.kind === 'joined') {
        predecessor.receiptTerminalIdentity.fill(0);
        return;
    }
    predecessor.context.parameterIdentity.fill(0);
    predecessor.context.preparationContextIdentity.fill(0);
    predecessor.context.rootTerminalIdentity.fill(0);
    predecessor.sealedBytes.fill(0);
};

const destroyStorageSnapshot = (
    snapshot: JoinedSeedMasterStorageSnapshot | undefined,
): void => {
    if (snapshot === undefined) {
        return;
    }
    if (snapshot.joined !== undefined) {
        destroyRecord(snapshot.joined.record);
        snapshot.joined.sealedBytes.fill(0);
    }
    destroyAuthenticationPredecessor(snapshot.authentication);
    destroyReceiptPredecessor(snapshot.receipt);
    destroySourcePredecessor(snapshot.source);
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
            'Joined seed-master custody failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const errorHasCode = (error: unknown, code: string): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code;

const commitTransition = async (input: {
    authentication: SelectedSeedRecipientAuthenticationCustodyForMasterJoin;
    joinedRecordKey: string;
    limits: JoinedSeedMasterCustodyLimits;
    protection: RuntimeRecordProtection;
    receipt: CompletedSeedRecipientReceiptCustodyForMasterJoin;
    record: JoinedSeedMasterRecord;
    source: CompletedSeedCatalogSourceCustodyForMasterJoin;
    store: UntrustedStorageTransactionStore;
}): Promise<Uint8Array> => {
    const plaintext = encodeRecord(input.record);
    let transaction: UntrustedStorageTransaction | undefined;
    let stagedAuthenticationBytes: Uint8Array | undefined;
    let stagedSealedBytes: Uint8Array | undefined;
    try {
        transaction = await input.store.beginTransaction({
            lifetimeMilliseconds: input.limits.transactionLifetimeMilliseconds,
        });
        stagedSealedBytes = await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: null,
            logicalRecordKey: input.joinedRecordKey,
            operationDomain: joinedCustodyOperationDomain,
            plaintext,
            protection: input.protection,
            transaction,
        });
        stagedAuthenticationBytes =
            await stageSeedRecipientAuthenticationCustodyMasterJoinCompletion({
                protection: input.protection,
                receiptTerminalIdentity:
                    input.record.context.receiptTerminalIdentity,
                selection: input.authentication,
                transaction,
            });
        await transaction.stageDeletion(
            input.source.recordKey,
            input.source.sealedBytes,
        );
        await transaction.stageDeletion(
            input.receipt.recordKey,
            input.receipt.sealedBytes,
        );
        await transaction.commit();
        return stagedSealedBytes.slice();
    } catch (error) {
        if (transaction === undefined) {
            throw mapStorageError(error);
        }
        throw await closeTransactionAfterFailure(transaction, error);
    } finally {
        plaintext.fill(0);
        stagedAuthenticationBytes?.fill(0);
        stagedSealedBytes?.fill(0);
    }
};

const copyRetention = (
    record: JoinedSeedMasterRecord,
    joinedCiphertextByteLength: number,
): RetainedJoinedSeedMasterCustody =>
    Object.freeze({
        joinedCiphertextByteLength,
        participantPosition: record.context.participantPosition,
        receiptTerminalIdentity: record.context.receiptTerminalIdentity.slice(),
        rootTerminalIdentity: record.context.rootTerminalIdentity.slice(),
    });

/**
 * Atomically replaces complete raw source and recipient custody with one
 * encrypted joined-master record and replaces the authenticated action
 * selection with its compact terminal marker after the kernel validates every
 * exact predecessor and terminal byte.
 *
 * The integrity-pinned scalar Rust/WebAssembly kernel owns both predecessor
 * decoders, public-terminal verification, source correspondence, and the
 * positive join. This owner returns only inert retention metadata and exposes
 * no secret bytes or preparation-continuation method.
 */
export class JoinedSeedMasterCustody {
    readonly #authenticationLimits: SeedRecipientAuthenticationCustodyLimits;
    readonly #context: JoinedSeedMasterCustodyContext;
    readonly #joinedRecordKey: string;
    readonly #kernel: ProductionJoinedSeedMasterCustodyKernel;
    readonly #limits: JoinedSeedMasterCustodyLimits;
    readonly #protection: RuntimeRecordProtection;
    readonly #receiptContext: SeedRecipientReceiptCustodyContext;
    readonly #receiptLimits: SeedRecipientReceiptCustodyLimits;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    readonly #sourceContext: SeedCatalogSourceCustodyContext;
    readonly #sourceLimits: SeedCatalogSourceCustodyLimits;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        authenticationCustodyLimits: SeedRecipientAuthenticationCustodyLimits;
        context: JoinedSeedMasterCustodyContext;
        kernel: ProductionJoinedSeedMasterCustodyKernel;
        limits: JoinedSeedMasterCustodyLimits;
        protection: RuntimeRecordProtection;
        receiptCustodyLimits: SeedRecipientReceiptCustodyLimits;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
        sourceCustodyLimits: SeedCatalogSourceCustodyLimits;
    }) {
        if (!isProductionJoinedSeedMasterCustodyKernel(input.kernel)) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Joined seed-master custody requires an integrity-pinned production kernel.',
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
                'Joined seed-master custody requires an authenticated storage recency coordinator.',
            );
        }
        this.#context = copyContext(input.context);
        this.#authenticationLimits =
            snapshotSeedRecipientAuthenticationCustodyLimitsForMasterJoin(
                input.authenticationCustodyLimits,
            );
        this.#kernel = input.kernel;
        this.#limits = copyLimits(input.limits);
        this.#protection = input.protection;
        this.#receiptContext = createReceiptContext(this.#context);
        this.#receiptLimits =
            snapshotSeedRecipientReceiptCustodyLimitsForMasterJoin(
                input.receiptCustodyLimits,
            );
        this.#recencyCoordinator = input.recencyCoordinator;
        this.#sourceContext = createSourceContext(this.#context);
        this.#sourceLimits =
            snapshotSeedCatalogSourceCustodyLimitsForMasterJoin(
                input.sourceCustodyLimits,
            );
        this.#joinedRecordKey = recordKey(this.#context);
    }

    public retainJoinedMasters(input: {
        receiptTerminalCertificateBytes: Uint8Array;
        rootTerminalCertificateBytes: Uint8Array;
        verificationContextBytes: Uint8Array;
    }): Promise<RetainedJoinedSeedMasterCustody> {
        const transitionInput = copyTransitionInput(input, this.#limits);
        return this.#schedule(async () => {
            try {
                return await this.#retain(transitionInput);
            } finally {
                destroyTransitionInput(transitionInput);
            }
        });
    }

    public resumeRetained(): Promise<
        RetainedJoinedSeedMasterCustody | undefined
    > {
        return this.#schedule(async () => {
            const snapshot = await this.#readStorageSnapshot();
            try {
                if (snapshot.joined === undefined) {
                    if (snapshot.authentication === 'burned') {
                        throw new AuthenticatedRuntimeRecordError(
                            'InvalidState',
                            'Joined seed-master custody cannot resume a durably burned recipient action.',
                        );
                    }
                    if (snapshot.authentication?.kind === 'joined') {
                        throw new AuthenticatedRuntimeRecordError(
                            'Conflict',
                            'Seed-recipient action state records a joined transition without joined custody.',
                        );
                    }
                    return undefined;
                }
                this.#requireRawPredecessorsErased(snapshot);
                this.#validate(snapshot.joined.record);
                return copyRetention(
                    snapshot.joined.record,
                    snapshot.joined.sealedBytes.byteLength,
                );
            } finally {
                destroyStorageSnapshot(snapshot);
            }
        });
    }

    public authorizeRustRestoration(): JoinedSeedMasterRestorationAuthorization {
        const authorization = Object.freeze({
            [joinedSeedMasterRestorationAuthorizationBrand]: true as const,
        });
        joinedSeedMasterRestorationAuthorizationReaders.set(authorization, () =>
            this.#schedule(() => this.#readForRustRestoration()),
        );
        return authorization;
    }

    #schedule<Result>(operation: () => Promise<Result>): Promise<Result> {
        const scheduled = this.#operationTail.then(operation);
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    async #retain(
        transitionInput: JoinedSeedMasterTransitionInput,
    ): Promise<RetainedJoinedSeedMasterCustody> {
        let snapshot = await this.#readStorageSnapshot();
        try {
            if (snapshot.joined !== undefined) {
                this.#requireRawPredecessorsErased(snapshot);
                this.#requireMatchingTransition(
                    snapshot.joined.record,
                    transitionInput,
                );
                this.#validate(snapshot.joined.record);
                return copyRetention(
                    snapshot.joined.record,
                    snapshot.joined.sealedBytes.byteLength,
                );
            }
            const source = snapshot.source;
            const receipt = snapshot.receipt;
            const authentication = snapshot.authentication;
            if (authentication === 'burned') {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Joined seed-master custody cannot continue a durably burned recipient action.',
                );
            }
            if (authentication?.kind === 'joined') {
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'Seed-recipient action state records a joined transition without joined custody.',
                );
            }
            if (
                authentication === undefined ||
                source === undefined ||
                source === 'incomplete' ||
                receipt === undefined ||
                receipt === 'incomplete'
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'MissingRecord',
                    'Joined seed-master custody is pending complete source and recipient predecessors.',
                );
            }
            const joinedMasterPayloadBytes = this.#produce({
                receipt,
                source,
                transitionInput,
            });
            let record: JoinedSeedMasterRecord | undefined;
            try {
                record = createRecord({
                    context: this.#context,
                    joinedMasterPayloadBytes,
                    transitionInput,
                });
                this.#validate(record);
                try {
                    const committedSealedBytes =
                        await this.#recencyCoordinator.runMutation((store) =>
                            commitTransition({
                                authentication,
                                joinedRecordKey: this.#joinedRecordKey,
                                limits: this.#limits,
                                protection: this.#protection,
                                receipt,
                                record: record as JoinedSeedMasterRecord,
                                source,
                                store,
                            }),
                        );
                    committedSealedBytes.fill(0);
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                }
            } finally {
                destroyRecord(record);
                joinedMasterPayloadBytes.fill(0);
            }
        } finally {
            destroyStorageSnapshot(snapshot);
        }

        snapshot = await this.#readStorageSnapshot();
        try {
            if (snapshot.joined === undefined) {
                if (snapshot.authentication === 'burned') {
                    throw new AuthenticatedRuntimeRecordError(
                        'InvalidState',
                        'Joined seed-master transition lost its selection to the durable action burn.',
                    );
                }
                if (snapshot.authentication?.kind === 'joined') {
                    throw new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'Seed-recipient action state records a joined transition without joined custody.',
                    );
                }
                throw new AuthenticatedRuntimeRecordError(
                    'Conflict',
                    'Joined seed-master transition did not retain its completed record.',
                );
            }
            this.#requireRawPredecessorsErased(snapshot);
            this.#requireMatchingTransition(
                snapshot.joined.record,
                transitionInput,
            );
            this.#validate(snapshot.joined.record);
            return copyRetention(
                snapshot.joined.record,
                snapshot.joined.sealedBytes.byteLength,
            );
        } finally {
            destroyStorageSnapshot(snapshot);
        }
    }

    async #readStorageSnapshot(): Promise<JoinedSeedMasterStorageSnapshot> {
        return this.#recencyCoordinator.runRead(async (store) => {
            let authentication: AuthenticationPredecessorState = undefined;
            let joined: OpenedJoinedSeedMasterRecord | undefined;
            let source: SourcePredecessorState = undefined;
            let receipt: ReceiptPredecessorState = undefined;
            let completed = false;
            try {
                authentication =
                    await readSelectedSeedRecipientAuthenticationCustodyForMasterJoin(
                        {
                            context: this.#receiptContext,
                            limits: this.#authenticationLimits,
                            protection: this.#protection,
                            store,
                        },
                    );
                joined = await readJoinedRecord({
                    context: this.#context,
                    limits: this.#limits,
                    protection: this.#protection,
                    store,
                });
                source =
                    await readCompletedSeedCatalogSourceCustodyForMasterJoin({
                        context: this.#sourceContext,
                        limits: this.#sourceLimits,
                        protection: this.#protection,
                        store,
                    });
                receipt =
                    await readCompletedSeedRecipientReceiptCustodyForMasterJoin(
                        {
                            context: this.#receiptContext,
                            limits: this.#receiptLimits,
                            protection: this.#protection,
                            store,
                        },
                    );
                const snapshot = Object.freeze({
                    authentication,
                    joined,
                    receipt,
                    source,
                });
                authentication = undefined;
                joined = undefined;
                receipt = undefined;
                source = undefined;
                completed = true;
                return snapshot;
            } finally {
                if (!completed) {
                    destroyAuthenticationPredecessor(authentication);
                    if (joined !== undefined) {
                        destroyRecord(joined.record);
                        joined.sealedBytes.fill(0);
                    }
                    destroyReceiptPredecessor(receipt);
                    destroySourcePredecessor(source);
                }
            }
        });
    }

    async #readForRustRestoration(): Promise<ConsumedJoinedSeedMasterRestorationAuthorization> {
        const snapshot = await this.#readStorageSnapshot();
        let context: JoinedSeedMasterCustodyContext | undefined;
        let recordBytes: Uint8Array | undefined;
        try {
            if (snapshot.joined === undefined) {
                if (snapshot.authentication === 'burned') {
                    throw new AuthenticatedRuntimeRecordError(
                        'InvalidState',
                        'Joined seed-master restoration cannot read a durably burned recipient action.',
                    );
                }
                if (snapshot.authentication?.kind === 'joined') {
                    throw new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'Seed-recipient action state records a joined transition without joined custody.',
                    );
                }
                throw new AuthenticatedRuntimeRecordError(
                    'MissingRecord',
                    'Joined seed-master restoration is pending retained joined custody.',
                );
            }
            this.#requireRawPredecessorsErased(snapshot);
            context = copyContext(snapshot.joined.record.context);
            recordBytes = this.#encodeAndValidateRestoration(
                snapshot.joined.record,
            );
            const consumed = Object.freeze({ context, recordBytes });
            context = undefined;
            recordBytes = undefined;
            return consumed;
        } finally {
            destroyContext(context);
            recordBytes?.fill(0);
            destroyStorageSnapshot(snapshot);
        }
    }

    #produce(input: {
        receipt: CompletedSeedRecipientReceiptCustodyForMasterJoin;
        source: CompletedSeedCatalogSourceCustodyForMasterJoin;
        transitionInput: JoinedSeedMasterTransitionInput;
    }): Uint8Array {
        const requestBytes = encodeJoinRequest({
            context: this.#context,
            receiptCustodyRecordBytes: input.receipt.recordBytes,
            sourceCustodyRecordBytes: input.source.recordBytes,
            transitionInput: input.transitionInput,
        });
        let produced: Uint8Array | undefined;
        let productionFailed = false;
        let productionFailure: unknown;
        try {
            try {
                produced = this.#kernel.joinAndEncode(requestBytes);
            } catch (error) {
                productionFailed = true;
                productionFailure = error;
            }
            if (productionFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Joined seed-master kernel rejected the exact predecessor records.',
                    productionFailure,
                );
            }
            return copyBoundedBytes(
                produced,
                this.#limits.maximumJoinedMasterPayloadByteLength,
                'joinedMasterPayloadBytes',
            );
        } finally {
            produced?.fill(0);
            requestBytes.fill(0);
        }
    }

    #validate(record: JoinedSeedMasterRecord): void {
        const recordBytes = this.#encodeAndValidate(record);
        recordBytes.fill(0);
    }

    #encodeAndValidate(record: JoinedSeedMasterRecord): Uint8Array {
        const recordBytes = encodeRecord(record);
        let validationFailed = false;
        let validationFailure: unknown;
        try {
            try {
                this.#kernel.validateRetained(recordBytes);
            } catch (error) {
                validationFailed = true;
                validationFailure = error;
            }
            if (validationFailed) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Joined seed-master custody failed retained-state validation.',
                    validationFailure,
                );
            }
            return recordBytes;
        } catch (error) {
            recordBytes.fill(0);
            throw error;
        }
    }

    #encodeAndValidateRestoration(record: JoinedSeedMasterRecord): Uint8Array {
        const recordBytes = encodeRecord(record);
        try {
            try {
                this.#kernel.validateRestoration(recordBytes);
            } catch (error) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Joined seed-master custody failed typed restoration validation.',
                    error,
                );
            }
            return recordBytes;
        } catch (error) {
            recordBytes.fill(0);
            throw error;
        }
    }

    #requireMatchingTransition(
        record: JoinedSeedMasterRecord,
        transitionInput: JoinedSeedMasterTransitionInput,
    ): void {
        if (!transitionInputsEqual(record, transitionInput)) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The joined seed-master slot is durably bound to different terminal or verification bytes.',
            );
        }
    }

    #requireRawPredecessorsErased(
        snapshot: JoinedSeedMasterStorageSnapshot,
    ): void {
        if (
            snapshot.authentication === undefined ||
            snapshot.authentication === 'burned' ||
            snapshot.authentication.kind !== 'joined' ||
            !bytesEqual(
                snapshot.authentication.receiptTerminalIdentity,
                this.#context.receiptTerminalIdentity,
            ) ||
            snapshot.source !== undefined ||
            snapshot.receipt !== undefined
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'Joined seed-master custody has mismatched action completion or retained raw predecessor state.',
            );
        }
    }
}
