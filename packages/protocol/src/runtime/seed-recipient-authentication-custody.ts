import {
    assertSeedRecipientReceiptCapabilitiesMatchRosterKeys,
    decapsulateSeedRecipientMailboxCiphertext,
    signSeedRecipientReceiptBody,
    type BrowserLocalMailboxCapability,
    type BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import {
    configurableParticipantCountRange,
    foundationProfile,
} from '@sealed-lattice/types';
import {
    openProductionSeedRecipientReceiptKernel,
    type OpenProductionSeedRecipientReceiptKernelInput,
    type ProductionSeedRecipientReceiptKernel,
    type SeedRecipientReceiptAuthenticationStateOperations,
    type SeedRecipientReceiptContext,
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
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const authenticationRecordMagic = Uint8Array.of(0x53, 0x4c, 0x52, 0x41);
const authenticationRecordVersion = 2;
const selectedRecordKind = 1;
const burnedRecordKind = 2;
const joinedRecordKind = 3;
const authenticatedDeliveryInconsistencyReason = 1;
const conflictingRecipientReceiptReason = 2;
const conflictingReceiptTerminalEndorsementReason = 3;
const hashByteLength = 64;
const unsigned16Maximum = 0xffff;
const unsigned32Maximum = 0xffff_ffff;
const authenticationRecordOperationDomain =
    'sealed-lattice/runtime/seed-recipient-authentication-record/v2';

export type SeedRecipientReceiptCustodyContext = SeedRecipientReceiptContext;

export type SeedRecipientAuthenticationCustodyLimits = Readonly<{
    maximumCanonicalOpenRequestByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

type SeedRecipientAuthenticationCustodyByteLengths = Readonly<{
    authenticatedInconsistencyBurnedCiphertextByteLength: number;
    authenticatedInconsistencyBurnedPlaintextByteLength: number;
    authenticatedInconsistencyBurnTransitionCiphertextOverlapByteLength: number;
    conflictingIntentBurnedCiphertextByteLength: number;
    conflictingIntentBurnedPlaintextByteLength: number;
    conflictingIntentBurnTransitionCiphertextOverlapByteLength: number;
    joinedCiphertextByteLength: number;
    joinedPlaintextByteLength: number;
    selectedCiphertextByteLength: number;
    selectedPlaintextByteLength: number;
}>;

type SelectedSeedRecipientAuthenticationRecord = Readonly<{
    canonicalOpenRequestBytes: Uint8Array;
    context: SeedRecipientReceiptCustodyContext;
    kind: 'selected';
}>;

type BurnedSeedRecipientAuthenticationRecord = Readonly<{
    authenticatedInconsistencyEvidence?: AuthenticatedInconsistencyEvidence;
    burnReason: SeedRecipientActionBurnReason;
    canonicalOpenRequestBytes: Uint8Array;
    context: SeedRecipientReceiptCustodyContext;
    kind: 'burned';
}>;

type AuthenticatedInconsistencyEvidence = Readonly<{
    disclosedAuthenticatedEncryptionKey: Uint8Array;
    evidenceIdentity: Uint8Array;
    recipientPosition: number;
    senderPosition: number;
}>;

type JoinedSeedRecipientAuthenticationRecord = Readonly<{
    context: SeedRecipientReceiptCustodyContext;
    kind: 'joined';
    receiptTerminalIdentity: Uint8Array;
}>;

type SeedRecipientAuthenticationRecord =
    | BurnedSeedRecipientAuthenticationRecord
    | JoinedSeedRecipientAuthenticationRecord
    | SelectedSeedRecipientAuthenticationRecord;

type SeedRecipientAuthenticationSelectionRecord =
    | BurnedSeedRecipientAuthenticationRecord
    | SelectedSeedRecipientAuthenticationRecord;

type OpenedSeedRecipientAuthenticationRecord = Readonly<{
    record: SeedRecipientAuthenticationRecord;
    sealedBytes: Uint8Array;
}>;

export type SelectedSeedRecipientAuthenticationCustodyForMasterJoin = Readonly<{
    context: SeedRecipientReceiptCustodyContext;
    kind: 'selected';
    recordKey: string;
    sealedBytes: Uint8Array;
}>;

export type JoinedSeedRecipientAuthenticationCustodyForMasterJoin = Readonly<{
    kind: 'joined';
    receiptTerminalIdentity: Uint8Array;
}>;

type OpenBrowserLocalSeedRecipientReceiptKernelInput = Omit<
    OpenProductionSeedRecipientReceiptKernelInput,
    'keyOperations' | 'stateOperations'
> &
    Readonly<{
        authenticationCustody: SeedRecipientAuthenticationCustody;
        mailboxCapability: BrowserLocalMailboxCapability;
        signingCapability: BrowserLocalSigningCapability;
    }>;

const custodyOperations = new WeakMap<
    object,
    SeedRecipientReceiptAuthenticationStateOperations
>();
const authenticationCustodyByKernel = new WeakMap<object, object>();

type SeedRecipientActionBurnReason =
    | typeof authenticatedDeliveryInconsistencyReason
    | typeof conflictingRecipientReceiptReason
    | typeof conflictingReceiptTerminalEndorsementReason;

const seedRecipientActionStateGuardBrand: unique symbol = Symbol(
    'seed-recipient-action-state-guard',
);

export type SeedRecipientActionStateGuard = Readonly<{
    readonly [seedRecipientActionStateGuardBrand]: true;
}>;

type SeedRecipientActionStateOperations = Readonly<{
    assertSelected(): Promise<void>;
    retainConflictingReceiptBurn(): Promise<void>;
    retainConflictingTerminalEndorsementBurn(): Promise<void>;
}>;

type SeedRecipientActionStateRegistration = Readonly<{
    context: SeedRecipientReceiptCustodyContext;
    operations: SeedRecipientActionStateOperations;
    recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
}>;

const actionStateRegistrationByCustody = new WeakMap<
    object,
    SeedRecipientActionStateRegistration
>();
const actionStateRegistrationByGuard = new WeakMap<
    object,
    SeedRecipientActionStateRegistration
>();

const requireActionStateOperations = (
    guard: SeedRecipientActionStateGuard,
): SeedRecipientActionStateOperations => {
    if (typeof guard !== 'object' || guard === null) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-recipient action state requires an opaque durable-custody guard.',
        );
    }
    const registration = actionStateRegistrationByGuard.get(guard);
    if (registration === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-recipient action state requires an opaque durable-custody guard.',
        );
    }
    return registration.operations;
};

export const createSeedRecipientActionStateGuard = (input: {
    authenticationCustody: SeedRecipientAuthenticationCustody;
    context: SeedRecipientReceiptCustodyContext;
    recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
}): SeedRecipientActionStateGuard => {
    const context = copyContext(input.context, 'InvalidConfiguration');
    const registration = actionStateRegistrationByCustody.get(
        input.authenticationCustody,
    );
    try {
        if (
            registration === undefined ||
            registration.recencyCoordinator !== input.recencyCoordinator ||
            !contextsEqual(registration.context, context)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-recipient action state requires its exact authentication custody, context, and recency coordinator.',
            );
        }
        const guard = Object.freeze({
            [seedRecipientActionStateGuardBrand]: true as const,
        });
        actionStateRegistrationByGuard.set(guard, registration);
        return guard;
    } finally {
        destroyContext(context);
    }
};

export const assertSeedRecipientActionStateGuardUsesRecencyCoordinator = (
    guard: SeedRecipientActionStateGuard,
    recencyCoordinator: AuthenticatedStorageRecencyCoordinator,
): void => {
    if (
        actionStateRegistrationByGuard.get(guard)?.recencyCoordinator !==
        recencyCoordinator
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-recipient action state requires its exact authenticated storage recency coordinator.',
        );
    }
};

export const assertSeedRecipientActionStateGuardMatchesContext = (
    guard: SeedRecipientActionStateGuard,
    contextValue: SeedRecipientReceiptCustodyContext,
): void => {
    const context = copyContext(contextValue, 'InvalidConfiguration');
    try {
        const registration = actionStateRegistrationByGuard.get(guard);
        if (
            registration === undefined ||
            !contextsEqual(registration.context, context)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-recipient action state requires its exact authenticated context.',
            );
        }
    } finally {
        destroyContext(context);
    }
};

export const assertSeedRecipientActionSelected = (
    guard: SeedRecipientActionStateGuard,
): Promise<void> => requireActionStateOperations(guard).assertSelected();

export const retainConflictingSeedRecipientReceiptBurn = (
    guard: SeedRecipientActionStateGuard,
): Promise<void> =>
    requireActionStateOperations(guard).retainConflictingReceiptBurn();

export const retainConflictingSeedReceiptTerminalEndorsementBurn = (
    guard: SeedRecipientActionStateGuard,
): Promise<void> =>
    requireActionStateOperations(
        guard,
    ).retainConflictingTerminalEndorsementBurn();

const preprocessingSourceStateAuthorizationBrand: unique symbol = Symbol(
    'preprocessing-source-state-authorization',
);

type PreprocessingSourceStateAuthorization = Readonly<{
    readonly [preprocessingSourceStateAuthorizationBrand]: true;
}>;

type ConsumedPreprocessingSourceStateAuthorization = Readonly<{
    actionStateGuard: SeedRecipientActionStateGuard;
    context: SeedRecipientReceiptCustodyContext;
    recordBytes: Uint8Array;
}>;

const preprocessingSourceStateAuthorizationReaders = new WeakMap<
    object,
    () => Promise<ConsumedPreprocessingSourceStateAuthorization>
>();

export const consumePreprocessingSourceStateAuthorization = async (
    authorization: PreprocessingSourceStateAuthorization,
): Promise<ConsumedPreprocessingSourceStateAuthorization> => {
    if (typeof authorization !== 'object' || authorization === null) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Preprocessing-source state authorization must be an opaque state-owner capability.',
        );
    }
    const read =
        preprocessingSourceStateAuthorizationReaders.get(authorization);
    if (read === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Preprocessing-source state authorization is invalid or has already been consumed.',
        );
    }
    preprocessingSourceStateAuthorizationReaders.delete(authorization);
    return read();
};

export const isSeedRecipientReceiptKernelAuthorizedByAuthenticationCustody = (
    kernel: unknown,
    custody: unknown,
): boolean =>
    typeof kernel === 'object' &&
    kernel !== null &&
    typeof custody === 'object' &&
    custody !== null &&
    authenticationCustodyByKernel.get(kernel) === custody;

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
    code: 'AuthenticationFailed' | 'InvalidConfiguration' | 'InvalidInput',
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

const copyContext = (
    value: unknown,
    errorCode:
        | 'AuthenticationFailed'
        | 'InvalidConfiguration'
        | 'InvalidInput' = 'InvalidInput',
): SeedRecipientReceiptCustodyContext => {
    const participantCount = requireSafeInteger(
        snapshotDataProperty(value, 'participantCount', 'context'),
        configurableParticipantCountRange.minimum,
        configurableParticipantCountRange.maximum,
        'context.participantCount',
        errorCode,
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
            errorCode,
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
        recipientPosition: requireSafeInteger(
            snapshotDataProperty(value, 'recipientPosition', 'context'),
            0,
            participantCount - 1,
            'context.recipientPosition',
            errorCode,
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
): SeedRecipientAuthenticationCustodyLimits => {
    const limits = Object.freeze({
        maximumCanonicalOpenRequestByteLength: requireSafeInteger(
            snapshotDataProperty(
                value,
                'maximumCanonicalOpenRequestByteLength',
                'limits',
            ),
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            'limits.maximumCanonicalOpenRequestByteLength',
            'InvalidConfiguration',
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
    deriveSeedRecipientAuthenticationCustodyByteLengths({
        canonicalOpenRequestByteLength:
            limits.maximumCanonicalOpenRequestByteLength,
    });
    return limits;
};

const destroyContext = (
    context: SeedRecipientReceiptCustodyContext | undefined,
): void => {
    context?.parameterIdentity.fill(0);
    context?.preparationContextIdentity.fill(0);
    context?.rootTerminalIdentity.fill(0);
};

const contextsEqual = (
    left: SeedRecipientReceiptCustodyContext,
    right: SeedRecipientReceiptCustodyContext,
): boolean =>
    left.participantCount === right.participantCount &&
    left.preparationAttemptOrdinal === right.preparationAttemptOrdinal &&
    left.recipientPosition === right.recipientPosition &&
    bytesEqual(left.parameterIdentity, right.parameterIdentity) &&
    bytesEqual(
        left.preparationContextIdentity,
        right.preparationContextIdentity,
    ) &&
    bytesEqual(left.rootTerminalIdentity, right.rootTerminalIdentity);

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
            'Seed-recipient authentication custody encoded an unexpected byte length.',
        );
    }
    return output;
};

const authenticationContextPlaintextByteLength =
    4 + 2 + 1 + hashByteLength * 3 + 2 * 3;

const selectionPlaintextByteLength = (
    canonicalOpenRequestByteLength: number,
): number =>
    checkedAdd(
        authenticationContextPlaintextByteLength + 4,
        canonicalOpenRequestByteLength,
        'Seed-recipient authentication custody record',
    );

export const deriveSeedRecipientAuthenticationCustodyByteLengths = (input: {
    canonicalOpenRequestByteLength: number;
}): SeedRecipientAuthenticationCustodyByteLengths => {
    const canonicalOpenRequestByteLength = requireSafeInteger(
        snapshotDataProperty(input, 'canonicalOpenRequestByteLength', 'input'),
        1,
        foundationProfile.maximumCopiedBufferByteLength,
        'input.canonicalOpenRequestByteLength',
        'InvalidInput',
    );
    const selectedPlaintextByteLength = selectionPlaintextByteLength(
        canonicalOpenRequestByteLength,
    );
    const joinedPlaintextByteLength = checkedAdd(
        authenticationContextPlaintextByteLength,
        hashByteLength,
        'Seed-recipient authentication joined record',
    );
    const conflictingIntentBurnedPlaintextByteLength = checkedAdd(
        selectedPlaintextByteLength,
        1,
        'Seed-recipient authentication conflicting-intent burn record',
    );
    const authenticatedInconsistencyBurnedPlaintextByteLength = checkedAdd(
        conflictingIntentBurnedPlaintextByteLength,
        2 + 2 + 32 + hashByteLength,
        'Seed-recipient authentication inconsistency burn record',
    );
    if (
        selectedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        joinedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength ||
        authenticatedInconsistencyBurnedPlaintextByteLength >
            foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'ResourceLimit',
            'Seed-recipient authentication custody exceeds the absolute copied-buffer bound.',
        );
    }
    const selectedCiphertextByteLength = checkedAdd(
        selectedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-recipient authentication selection ciphertext',
    );
    const conflictingIntentBurnedCiphertextByteLength = checkedAdd(
        conflictingIntentBurnedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-recipient authentication conflicting-intent burn ciphertext',
    );
    const authenticatedInconsistencyBurnedCiphertextByteLength = checkedAdd(
        authenticatedInconsistencyBurnedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-recipient authentication inconsistency burn ciphertext',
    );
    const joinedCiphertextByteLength = checkedAdd(
        joinedPlaintextByteLength,
        runtimeRecordEnvelopeOverheadByteLength,
        'Seed-recipient authentication joined ciphertext',
    );
    return Object.freeze({
        authenticatedInconsistencyBurnedCiphertextByteLength,
        authenticatedInconsistencyBurnedPlaintextByteLength,
        authenticatedInconsistencyBurnTransitionCiphertextOverlapByteLength:
            checkedAdd(
                selectedCiphertextByteLength,
                authenticatedInconsistencyBurnedCiphertextByteLength,
                'Seed-recipient authentication inconsistency burn transition overlap',
            ),
        conflictingIntentBurnedCiphertextByteLength,
        conflictingIntentBurnedPlaintextByteLength,
        conflictingIntentBurnTransitionCiphertextOverlapByteLength: checkedAdd(
            selectedCiphertextByteLength,
            conflictingIntentBurnedCiphertextByteLength,
            'Seed-recipient authentication conflicting-intent burn transition overlap',
        ),
        joinedCiphertextByteLength,
        joinedPlaintextByteLength,
        selectedCiphertextByteLength,
        selectedPlaintextByteLength,
    });
};

const logicalRecordKey = (
    context: SeedRecipientReceiptCustodyContext,
): string =>
    `seed-mailbox/recipient-authentication/${context.preparationAttemptOrdinal
        .toString(10)
        .padStart(5, '0')}/${context.recipientPosition
        .toString(10)
        .padStart(5, '0')}`;

const encodeRecord = (
    record: SeedRecipientAuthenticationRecord,
): Uint8Array => {
    const byteLengths = deriveSeedRecipientAuthenticationCustodyByteLengths({
        canonicalOpenRequestByteLength:
            record.kind === 'joined'
                ? 1
                : record.canonicalOpenRequestBytes.byteLength,
    });
    const contextParts = [
        authenticationRecordMagic,
        unsigned16LittleEndian(authenticationRecordVersion),
        Uint8Array.of(
            record.kind === 'selected'
                ? selectedRecordKind
                : record.kind === 'burned'
                  ? burnedRecordKind
                  : joinedRecordKind,
        ),
        record.context.parameterIdentity,
        record.context.preparationContextIdentity,
        record.context.rootTerminalIdentity,
        unsigned16LittleEndian(record.context.preparationAttemptOrdinal),
        unsigned16LittleEndian(record.context.participantCount),
        unsigned16LittleEndian(record.context.recipientPosition),
    ];
    if (record.kind === 'joined') {
        return concatenateBytes(
            [...contextParts, record.receiptTerminalIdentity],
            byteLengths.joinedPlaintextByteLength,
        );
    }
    const selectionParts = [
        ...contextParts,
        unsigned32LittleEndian(record.canonicalOpenRequestBytes.byteLength),
        record.canonicalOpenRequestBytes,
    ];
    if (record.kind === 'selected') {
        return concatenateBytes(
            selectionParts,
            byteLengths.selectedPlaintextByteLength,
        );
    }
    const evidence = record.authenticatedInconsistencyEvidence;
    if (
        (record.burnReason === authenticatedDeliveryInconsistencyReason) !==
            (evidence !== undefined) ||
        (evidence !== undefined &&
            (evidence.recipientPosition !== record.context.recipientPosition ||
                evidence.senderPosition >= record.context.participantCount ||
                evidence.senderPosition === evidence.recipientPosition))
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidState',
            'Seed-recipient authentication burn evidence does not match its durable reason and recipient context.',
        );
    }
    const burnParts = [
        ...selectionParts,
        Uint8Array.of(record.burnReason),
        ...(evidence === undefined
            ? []
            : [
                  unsigned16LittleEndian(evidence.senderPosition),
                  unsigned16LittleEndian(evidence.recipientPosition),
                  evidence.disclosedAuthenticatedEncryptionKey,
                  evidence.evidenceIdentity,
              ]),
    ];
    return concatenateBytes(
        burnParts,
        evidence === undefined
            ? byteLengths.conflictingIntentBurnedPlaintextByteLength
            : byteLengths.authenticatedInconsistencyBurnedPlaintextByteLength,
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
                `Seed-recipient authentication record ends within ${label}.`,
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
                'Seed-recipient authentication record has trailing bytes.',
            );
        }
    }
}

const decodeRecord = (
    plaintext: Uint8Array,
    limits: SeedRecipientAuthenticationCustodyLimits,
): SeedRecipientAuthenticationRecord => {
    if (
        plaintext.byteLength > foundationProfile.maximumCopiedBufferByteLength
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient authentication record exceeds the absolute copied-buffer bound.',
        );
    }
    const cursor = new BoundedRecordCursor(plaintext);
    const magic = cursor.readExact(
        authenticationRecordMagic.byteLength,
        'record magic',
    );
    try {
        if (!bytesEqual(magic, authenticationRecordMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-recipient authentication record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (
        cursor.readUnsigned16('record version') !== authenticationRecordVersion
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient authentication record has an unsupported version.',
        );
    }
    const recordKind = cursor.readUnsigned8('record kind');
    if (
        recordKind !== selectedRecordKind &&
        recordKind !== burnedRecordKind &&
        recordKind !== joinedRecordKind
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient authentication record has an invalid kind.',
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
    const recipientPosition = cursor.readUnsigned16('recipient position');
    if (
        participantCount < configurableParticipantCountRange.minimum ||
        participantCount > configurableParticipantCountRange.maximum ||
        recipientPosition >= participantCount
    ) {
        parameterIdentity.fill(0);
        preparationContextIdentity.fill(0);
        rootTerminalIdentity.fill(0);
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Seed-recipient authentication record has invalid roster coordinates.',
        );
    }
    const context = Object.freeze({
        parameterIdentity,
        participantCount,
        preparationAttemptOrdinal,
        preparationContextIdentity,
        recipientPosition,
        rootTerminalIdentity,
    });
    let authenticatedInconsistencyEvidence:
        | AuthenticatedInconsistencyEvidence
        | undefined;
    let canonicalOpenRequestBytes: Uint8Array | undefined;
    let receiptTerminalIdentity: Uint8Array | undefined;
    try {
        if (recordKind === joinedRecordKind) {
            receiptTerminalIdentity = cursor.readExact(
                hashByteLength,
                'receipt-terminal identity',
            );
            cursor.requireComplete();
            const record = Object.freeze({
                context,
                kind: 'joined' as const,
                receiptTerminalIdentity,
            });
            receiptTerminalIdentity = undefined;
            return record;
        }
        const canonicalOpenRequestByteLength = requireSafeInteger(
            cursor.readUnsigned32('canonical open-request byte length'),
            1,
            limits.maximumCanonicalOpenRequestByteLength,
            'Stored canonical open-request byte length',
            'AuthenticationFailed',
        );
        canonicalOpenRequestBytes = cursor.readExact(
            canonicalOpenRequestByteLength,
            'canonical open request',
        );
        let burnReason: SeedRecipientActionBurnReason | undefined;
        if (recordKind === burnedRecordKind) {
            const decodedBurnReason = cursor.readUnsigned8('burn reason');
            if (
                decodedBurnReason !==
                    authenticatedDeliveryInconsistencyReason &&
                decodedBurnReason !== conflictingRecipientReceiptReason &&
                decodedBurnReason !==
                    conflictingReceiptTerminalEndorsementReason
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Seed-recipient authentication record has an invalid burn reason.',
                );
            }
            burnReason = decodedBurnReason;
            if (burnReason === authenticatedDeliveryInconsistencyReason) {
                const evidenceSenderPosition = cursor.readUnsigned16(
                    'inconsistency sender position',
                );
                const evidenceRecipientPosition = cursor.readUnsigned16(
                    'inconsistency recipient position',
                );
                if (
                    evidenceRecipientPosition !== recipientPosition ||
                    evidenceSenderPosition >= participantCount ||
                    evidenceSenderPosition === evidenceRecipientPosition
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Seed-recipient authentication inconsistency evidence has invalid roster coordinates.',
                    );
                }
                authenticatedInconsistencyEvidence = Object.freeze({
                    disclosedAuthenticatedEncryptionKey: cursor.readExact(
                        32,
                        'disclosed authenticated-encryption key',
                    ),
                    evidenceIdentity: cursor.readExact(
                        hashByteLength,
                        'authenticated-inconsistency identity',
                    ),
                    recipientPosition: evidenceRecipientPosition,
                    senderPosition: evidenceSenderPosition,
                });
            }
        }
        cursor.requireComplete();
        const record: SeedRecipientAuthenticationRecord =
            recordKind === selectedRecordKind
                ? Object.freeze({
                      canonicalOpenRequestBytes,
                      context,
                      kind: 'selected' as const,
                  })
                : Object.freeze({
                      ...(authenticatedInconsistencyEvidence === undefined
                          ? {}
                          : { authenticatedInconsistencyEvidence }),
                      burnReason: burnReason as SeedRecipientActionBurnReason,
                      canonicalOpenRequestBytes,
                      context,
                      kind: 'burned' as const,
                  });
        canonicalOpenRequestBytes = undefined;
        authenticatedInconsistencyEvidence = undefined;
        return record;
    } catch (error) {
        destroyContext(context);
        throw error;
    } finally {
        destroyAuthenticatedInconsistencyEvidence(
            authenticatedInconsistencyEvidence,
        );
        canonicalOpenRequestBytes?.fill(0);
        receiptTerminalIdentity?.fill(0);
    }
};

const destroyAuthenticatedInconsistencyEvidence = (
    evidence: AuthenticatedInconsistencyEvidence | undefined,
): void => {
    evidence?.disclosedAuthenticatedEncryptionKey.fill(0);
    evidence?.evidenceIdentity.fill(0);
};

const copyAuthenticatedInconsistencyEvidence = (
    evidence: AuthenticatedInconsistencyEvidence,
): AuthenticatedInconsistencyEvidence =>
    Object.freeze({
        disclosedAuthenticatedEncryptionKey: copyExactBytes(
            evidence.disclosedAuthenticatedEncryptionKey,
            32,
            'disclosedAuthenticatedEncryptionKey',
        ),
        evidenceIdentity: copyExactBytes(
            evidence.evidenceIdentity,
            hashByteLength,
            'evidenceIdentity',
        ),
        recipientPosition: requireSafeInteger(
            evidence.recipientPosition,
            0,
            unsigned16Maximum,
            'recipientPosition',
            'InvalidInput',
        ),
        senderPosition: requireSafeInteger(
            evidence.senderPosition,
            0,
            unsigned16Maximum,
            'senderPosition',
            'InvalidInput',
        ),
    });

const destroyRecord = (
    record: SeedRecipientAuthenticationRecord | undefined,
): void => {
    if (record === undefined) {
        return;
    }
    destroyContext(record.context);
    if (record.kind === 'joined') {
        record.receiptTerminalIdentity.fill(0);
    } else {
        record.canonicalOpenRequestBytes.fill(0);
        if (record.kind === 'burned') {
            destroyAuthenticatedInconsistencyEvidence(
                record.authenticatedInconsistencyEvidence,
            );
        }
    }
};

const recordsHaveSameSelection = (
    left: SeedRecipientAuthenticationSelectionRecord,
    right: SeedRecipientAuthenticationSelectionRecord,
): boolean =>
    contextsEqual(left.context, right.context) &&
    bytesEqual(left.canonicalOpenRequestBytes, right.canonicalOpenRequestBytes);

const authenticatedInconsistencyEvidenceEqual = (
    left: AuthenticatedInconsistencyEvidence | undefined,
    right: AuthenticatedInconsistencyEvidence | undefined,
): boolean =>
    left === undefined
        ? right === undefined
        : right !== undefined &&
          left.senderPosition === right.senderPosition &&
          left.recipientPosition === right.recipientPosition &&
          bytesEqual(
              left.disclosedAuthenticatedEncryptionKey,
              right.disclosedAuthenticatedEncryptionKey,
          ) &&
          bytesEqual(left.evidenceIdentity, right.evidenceIdentity);

const readRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: SeedRecipientAuthenticationCustodyLimits,
): Promise<OpenedSeedRecipientAuthenticationRecord | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: authenticationRecordOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    let record: SeedRecipientAuthenticationRecord | undefined;
    let canonicalBytes: Uint8Array | undefined;
    try {
        record = decodeRecord(opened.plaintext, limits);
        canonicalBytes = encodeRecord(record);
        if (!bytesEqual(canonicalBytes, opened.plaintext)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Seed-recipient authentication record is not canonical.',
            );
        }
        const result = Object.freeze({
            record,
            sealedBytes: opened.sealedBytes.slice(),
        });
        record = undefined;
        return result;
    } finally {
        canonicalBytes?.fill(0);
        destroyRecord(record);
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

export const snapshotSeedRecipientAuthenticationCustodyLimitsForMasterJoin = (
    value: unknown,
): SeedRecipientAuthenticationCustodyLimits => copyLimits(value);

export const readSelectedSeedRecipientAuthenticationCustodyForMasterJoin =
    async (input: {
        context: SeedRecipientReceiptCustodyContext;
        limits: SeedRecipientAuthenticationCustodyLimits;
        protection: RuntimeRecordProtection;
        store: UntrustedStorageTransactionStore;
    }): Promise<
        | JoinedSeedRecipientAuthenticationCustodyForMasterJoin
        | SelectedSeedRecipientAuthenticationCustodyForMasterJoin
        | 'burned'
        | undefined
    > => {
        const context = copyContext(input.context);
        try {
            const limits = copyLimits(input.limits);
            const recordKey = logicalRecordKey(context);
            const opened = await readRecord(
                input.store,
                input.protection,
                recordKey,
                limits,
            );
            if (opened === undefined) {
                return undefined;
            }
            try {
                if (!contextsEqual(opened.record.context, context)) {
                    throw new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'The seed-recipient authentication predecessor is bound to a different context.',
                    );
                }
                if (opened.record.kind === 'burned') {
                    return 'burned';
                }
                if (opened.record.kind === 'joined') {
                    return Object.freeze({
                        kind: 'joined' as const,
                        receiptTerminalIdentity:
                            opened.record.receiptTerminalIdentity.slice(),
                    });
                }
                return Object.freeze({
                    context: copyContext(opened.record.context),
                    kind: 'selected' as const,
                    recordKey,
                    sealedBytes: opened.sealedBytes.slice(),
                });
            } finally {
                opened.sealedBytes.fill(0);
                destroyRecord(opened.record);
            }
        } finally {
            destroyContext(context);
        }
    };

export const stageSeedRecipientAuthenticationCustodyMasterJoinCompletion =
    async (input: {
        protection: RuntimeRecordProtection;
        receiptTerminalIdentity: Uint8Array;
        selection: SelectedSeedRecipientAuthenticationCustodyForMasterJoin;
        transaction: UntrustedStorageTransaction;
    }): Promise<Uint8Array> => {
        let completedRecord:
            | JoinedSeedRecipientAuthenticationRecord
            | undefined;
        let context: SeedRecipientReceiptCustodyContext | undefined;
        let expectedCurrentSealedBytes: Uint8Array | undefined;
        let plaintext: Uint8Array | undefined;
        let receiptTerminalIdentity: Uint8Array | undefined;
        let stagedSealedBytes: Uint8Array | undefined;
        try {
            context = copyContext(input.selection.context);
            receiptTerminalIdentity = copyExactBytes(
                input.receiptTerminalIdentity,
                hashByteLength,
                'receiptTerminalIdentity',
            );
            expectedCurrentSealedBytes = copyBoundedBytes(
                input.selection.sealedBytes,
                foundationProfile.maximumCopiedBufferByteLength +
                    runtimeRecordEnvelopeOverheadByteLength,
                'selection.sealedBytes',
            );
            const recordKey = logicalRecordKey(context);
            if (input.selection.recordKey !== recordKey) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidInput',
                    'Seed-recipient authentication completion has a mismatched record key.',
                );
            }
            completedRecord = Object.freeze({
                context,
                kind: 'joined' as const,
                receiptTerminalIdentity,
            });
            context = undefined;
            receiptTerminalIdentity = undefined;
            plaintext = encodeRecord(completedRecord);
            stagedSealedBytes = await stageRuntimeRecordWrite({
                expectedCurrentSealedBytes,
                logicalRecordKey: recordKey,
                operationDomain: authenticationRecordOperationDomain,
                plaintext,
                protection: input.protection,
                transaction: input.transaction,
            });
            return stagedSealedBytes.slice();
        } finally {
            plaintext?.fill(0);
            stagedSealedBytes?.fill(0);
            expectedCurrentSealedBytes?.fill(0);
            destroyRecord(completedRecord);
            destroyContext(context);
            receiptTerminalIdentity?.fill(0);
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
            'Seed-recipient authentication custody failed and could not release its transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const commitRecord = async (input: {
    expectedCurrentSealedBytes: Uint8Array | null;
    limits: SeedRecipientAuthenticationCustodyLimits;
    protection: RuntimeRecordProtection;
    record: SeedRecipientAuthenticationRecord;
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
            operationDomain: authenticationRecordOperationDomain,
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

/**
 * Owns the one action-scoped selection made after Rust has verified every
 * public carrier but before the recipient performs any private decapsulation.
 * An authenticated plaintext inconsistency or a conflicting durable receipt
 * or terminal-endorsement intent irreversibly replaces that selection with a
 * retained burn record. A successful joined-master transition instead
 * atomically replaces it with a compact terminal marker. These records are
 * local state evidence, not public misconduct certificates or continuation
 * capabilities.
 */
export class SeedRecipientAuthenticationCustody {
    readonly #context: SeedRecipientReceiptCustodyContext;
    readonly #limits: SeedRecipientAuthenticationCustodyLimits;
    readonly #protection: RuntimeRecordProtection;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        context: SeedRecipientReceiptCustodyContext;
        limits: SeedRecipientAuthenticationCustodyLimits;
        protection: RuntimeRecordProtection;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    }) {
        if (
            !(
                input.recencyCoordinator instanceof
                AuthenticatedStorageRecencyCoordinator
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Seed-recipient authentication custody requires an authenticated storage recency coordinator.',
            );
        }
        this.#context = copyContext(input.context, 'InvalidConfiguration');
        this.#limits = copyLimits(input.limits);
        this.#protection = input.protection;
        this.#recencyCoordinator = input.recencyCoordinator;
        custodyOperations.set(
            this,
            Object.freeze({
                retainAuthenticatedInconsistency: (operationInput) =>
                    this.#schedule(() => this.#burn(operationInput)),
                retainVerifiedPublicSelection: (operationInput) =>
                    this.#schedule(() => this.#select(operationInput)),
            }),
        );
        actionStateRegistrationByCustody.set(
            this,
            Object.freeze({
                context: this.#context,
                operations: Object.freeze({
                    assertSelected: () =>
                        this.#schedule(() => this.#assertSelected()),
                    retainConflictingReceiptBurn: () =>
                        this.#schedule(() =>
                            this.#burnSelectedAction(
                                conflictingRecipientReceiptReason,
                            ),
                        ),
                    retainConflictingTerminalEndorsementBurn: () =>
                        this.#schedule(() =>
                            this.#burnSelectedAction(
                                conflictingReceiptTerminalEndorsementReason,
                            ),
                        ),
                }),
                recencyCoordinator: this.#recencyCoordinator,
            }),
        );
    }

    public readStatus(): Promise<'burned' | 'joined' | 'pending' | 'selected'> {
        return this.#schedule(async () => {
            const opened = await this.#readOpenedRecord();
            if (opened === undefined) {
                return 'pending';
            }
            try {
                this.#requireOwnerContext(opened.record.context);
                return opened.record.kind;
            } finally {
                opened.sealedBytes.fill(0);
                destroyRecord(opened.record);
            }
        });
    }

    public authorizePreprocessingSourceState(): PreprocessingSourceStateAuthorization {
        const authorization = Object.freeze({
            [preprocessingSourceStateAuthorizationBrand]: true as const,
        });
        preprocessingSourceStateAuthorizationReaders.set(authorization, () =>
            this.#schedule(() => this.#readForPreprocessingSourceState()),
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

    #snapshotOperationInput(input: {
        readonly canonicalOpenRequestBytes: Uint8Array;
        readonly verifiedContext: SeedRecipientReceiptContext;
    }): SelectedSeedRecipientAuthenticationRecord {
        const context = copyContext(
            snapshotDataProperty(input, 'verifiedContext', 'input'),
        );
        let canonicalOpenRequestBytes: Uint8Array | undefined;
        try {
            this.#requireOwnerContext(context);
            canonicalOpenRequestBytes = copyBoundedBytes(
                snapshotDataProperty(
                    input,
                    'canonicalOpenRequestBytes',
                    'input',
                ),
                this.#limits.maximumCanonicalOpenRequestByteLength,
                'input.canonicalOpenRequestBytes',
            );
            deriveSeedRecipientAuthenticationCustodyByteLengths({
                canonicalOpenRequestByteLength:
                    canonicalOpenRequestBytes.byteLength,
            });
            const record = Object.freeze({
                canonicalOpenRequestBytes,
                context,
                kind: 'selected' as const,
            });
            canonicalOpenRequestBytes = undefined;
            return record;
        } catch (error) {
            destroyContext(context);
            throw error;
        } finally {
            canonicalOpenRequestBytes?.fill(0);
        }
    }

    #requireOwnerContext(context: SeedRecipientReceiptCustodyContext): void {
        if (!contextsEqual(this.#context, context)) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The Rust-verified seed-recipient authentication scope does not match this action owner.',
            );
        }
    }

    async #readOpenedRecord(): Promise<
        OpenedSeedRecipientAuthenticationRecord | undefined
    > {
        const recordKey = logicalRecordKey(this.#context);
        return this.#recencyCoordinator.runRead((store) =>
            readRecord(store, this.#protection, recordKey, this.#limits),
        );
    }

    async #readForPreprocessingSourceState(): Promise<ConsumedPreprocessingSourceStateAuthorization> {
        const opened = await this.#readOpenedRecord();
        if (opened === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'MissingRecord',
                'Preprocessing-source state is pending one retained recipient authentication record.',
            );
        }
        let context: SeedRecipientReceiptCustodyContext | undefined;
        let recordBytes: Uint8Array | undefined;
        try {
            this.#requireOwnerContext(opened.record.context);
            if (
                opened.record.kind === 'burned' &&
                opened.record.burnReason !==
                    authenticatedDeliveryInconsistencyReason
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'A conflicting local receipt intent cannot authorize preprocessing-source state.',
                );
            }
            context = copyContext(opened.record.context);
            recordBytes = encodeRecord(opened.record);
            const consumed = Object.freeze({
                actionStateGuard: createSeedRecipientActionStateGuard({
                    authenticationCustody: this,
                    context,
                    recencyCoordinator: this.#recencyCoordinator,
                }),
                context,
                recordBytes,
            });
            context = undefined;
            recordBytes = undefined;
            return consumed;
        } finally {
            destroyContext(context);
            recordBytes?.fill(0);
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
        }
    }

    async #assertSelected(): Promise<void> {
        const opened = await this.#readOpenedRecord();
        if (opened === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'This seed-recipient action has no durable authenticated selection.',
            );
        }
        try {
            this.#requireOwnerContext(opened.record.context);
            if (opened.record.kind === 'burned') {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'This seed-recipient action is durably burned and cannot continue.',
                );
            }
            if (opened.record.kind === 'joined') {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'This seed-recipient action has already completed its joined-master transition.',
                );
            }
        } finally {
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
        }
    }

    async #select(input: {
        readonly canonicalOpenRequestBytes: Uint8Array;
        readonly verifiedContext: SeedRecipientReceiptContext;
    }): Promise<void> {
        const selection = this.#snapshotOperationInput(input);
        const recordKey = logicalRecordKey(this.#context);
        try {
            const opened = await this.#readOpenedRecord();
            if (opened !== undefined) {
                try {
                    if (opened.record.kind === 'joined') {
                        throw new AuthenticatedRuntimeRecordError(
                            'InvalidState',
                            'This seed-recipient action has already completed its joined-master transition.',
                        );
                    }
                    this.#requireMatchingSelection(opened.record, selection);
                    if (opened.record.kind === 'burned') {
                        throw new AuthenticatedRuntimeRecordError(
                            'InvalidState',
                            'This seed-recipient action is durably burned and cannot authenticate another receipt inventory.',
                        );
                    }
                    return;
                } finally {
                    opened.sealedBytes.fill(0);
                    destroyRecord(opened.record);
                }
            }
            try {
                const sealedBytes = await this.#recencyCoordinator.runMutation(
                    (store) =>
                        commitRecord({
                            expectedCurrentSealedBytes: null,
                            limits: this.#limits,
                            protection: this.#protection,
                            record: selection,
                            recordKey,
                            store,
                        }),
                );
                sealedBytes.fill(0);
            } catch (error) {
                if (!errorHasCode(error, 'Conflict')) {
                    throw error;
                }
                const existing = await this.#readOpenedRecord();
                if (existing === undefined) {
                    throw error;
                }
                try {
                    if (existing.record.kind === 'joined') {
                        throw new AuthenticatedRuntimeRecordError(
                            'InvalidState',
                            'This seed-recipient action has already completed its joined-master transition.',
                        );
                    }
                    this.#requireMatchingSelection(existing.record, selection);
                    if (existing.record.kind === 'burned') {
                        throw new AuthenticatedRuntimeRecordError(
                            'InvalidState',
                            'This seed-recipient action is durably burned and cannot authenticate another receipt inventory.',
                        );
                    }
                } finally {
                    existing.sealedBytes.fill(0);
                    destroyRecord(existing.record);
                }
            }
        } finally {
            destroyRecord(selection);
        }
    }

    async #burn(input: {
        readonly canonicalOpenRequestBytes: Uint8Array;
        readonly disclosedAuthenticatedEncryptionKey: Uint8Array;
        readonly evidenceIdentity: Uint8Array;
        readonly recipientPosition: number;
        readonly senderPosition: number;
        readonly verifiedContext: SeedRecipientReceiptContext;
    }): Promise<void> {
        const selection = this.#snapshotOperationInput(input);
        let authenticatedInconsistencyEvidence:
            | AuthenticatedInconsistencyEvidence
            | undefined;
        try {
            authenticatedInconsistencyEvidence =
                copyAuthenticatedInconsistencyEvidence(input);
            if (
                authenticatedInconsistencyEvidence.recipientPosition !==
                    selection.context.recipientPosition ||
                authenticatedInconsistencyEvidence.senderPosition >=
                    selection.context.participantCount ||
                authenticatedInconsistencyEvidence.senderPosition ===
                    authenticatedInconsistencyEvidence.recipientPosition
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'The Rust-verified authenticated inconsistency disclosure does not match the selected recipient context.',
                );
            }
            await this.#burnSelectedAction(
                authenticatedDeliveryInconsistencyReason,
                selection,
                authenticatedInconsistencyEvidence,
            );
        } finally {
            destroyAuthenticatedInconsistencyEvidence(
                authenticatedInconsistencyEvidence,
            );
            destroyRecord(selection);
        }
    }

    async #burnSelectedAction(
        burnReason: SeedRecipientActionBurnReason,
        expectedSelection?: SelectedSeedRecipientAuthenticationRecord,
        authenticatedInconsistencyEvidence?: AuthenticatedInconsistencyEvidence,
    ): Promise<void> {
        if (
            (burnReason === authenticatedDeliveryInconsistencyReason) !==
            (authenticatedInconsistencyEvidence !== undefined)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Seed-recipient authentication burn evidence does not match the requested terminal reason.',
            );
        }
        const recordKey = logicalRecordKey(this.#context);
        const opened = await this.#readOpenedRecord();
        if (opened === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'A seed-recipient terminal condition cannot burn an unselected action.',
            );
        }
        try {
            this.#requireOwnerContext(opened.record.context);
            if (opened.record.kind === 'joined') {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'A completed joined-master action cannot select a later terminal burn.',
                );
            }
            if (expectedSelection !== undefined) {
                this.#requireMatchingSelection(
                    opened.record,
                    expectedSelection,
                );
            }
            if (opened.record.kind === 'burned') {
                if (
                    opened.record.burnReason !== burnReason ||
                    !authenticatedInconsistencyEvidenceEqual(
                        opened.record.authenticatedInconsistencyEvidence,
                        authenticatedInconsistencyEvidence,
                    )
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'Conflict',
                        'The seed-recipient action is durably bound to different terminal burn evidence.',
                    );
                }
                return;
            }
            const burnedRecord: BurnedSeedRecipientAuthenticationRecord =
                Object.freeze({
                    ...(authenticatedInconsistencyEvidence === undefined
                        ? {}
                        : {
                              authenticatedInconsistencyEvidence:
                                  copyAuthenticatedInconsistencyEvidence(
                                      authenticatedInconsistencyEvidence,
                                  ),
                          }),
                    burnReason,
                    canonicalOpenRequestBytes:
                        opened.record.canonicalOpenRequestBytes.slice(),
                    context: copyContext(opened.record.context),
                    kind: 'burned' as const,
                });
            try {
                try {
                    const sealedBytes =
                        await this.#recencyCoordinator.runMutation((store) =>
                            commitRecord({
                                expectedCurrentSealedBytes: opened.sealedBytes,
                                limits: this.#limits,
                                protection: this.#protection,
                                record: burnedRecord,
                                recordKey,
                                store,
                            }),
                        );
                    sealedBytes.fill(0);
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readOpenedRecord();
                    if (existing === undefined) {
                        throw error;
                    }
                    try {
                        if (existing.record.kind === 'joined') {
                            throw new AuthenticatedRuntimeRecordError(
                                'InvalidState',
                                'A completed joined-master action cannot select a later terminal burn.',
                            );
                        }
                        this.#requireMatchingSelection(
                            existing.record,
                            opened.record,
                        );
                        if (existing.record.kind !== 'burned') {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'Concurrent seed-recipient authentication state did not select the same terminal burn.',
                            );
                        }
                        if (
                            existing.record.burnReason !== burnReason ||
                            !authenticatedInconsistencyEvidenceEqual(
                                existing.record
                                    .authenticatedInconsistencyEvidence,
                                authenticatedInconsistencyEvidence,
                            )
                        ) {
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'Concurrent seed-recipient authentication state retained different terminal burn evidence.',
                            );
                        }
                    } finally {
                        existing.sealedBytes.fill(0);
                        destroyRecord(existing.record);
                    }
                }
            } finally {
                destroyRecord(burnedRecord);
            }
        } finally {
            opened.sealedBytes.fill(0);
            destroyRecord(opened.record);
        }
    }

    #requireMatchingSelection(
        record: SeedRecipientAuthenticationSelectionRecord,
        selection: SeedRecipientAuthenticationSelectionRecord,
    ): void {
        if (!recordsHaveSameSelection(record, selection)) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The seed-recipient authentication slot is durably bound to different verified public bytes.',
            );
        }
    }
}

/**
 * Opens the fixed Rust/WebAssembly receipt boundary only after the verified
 * public carrier selection is recency-anchored. The adapter retains a genuine
 * Rust-reported authenticated plaintext inconsistency before it returns the
 * refusal. Unsigned, malformed, truncated, or publicly inconsistent transport
 * never reaches the burn transition.
 */
export const openBrowserLocalSeedRecipientReceiptKernel = async (
    transcriptCoreKernelUrl: URL,
    input: OpenBrowserLocalSeedRecipientReceiptKernelInput,
): Promise<ProductionSeedRecipientReceiptKernel> => {
    const authenticationCustody = snapshotDataProperty(
        input,
        'authenticationCustody',
        'input',
    );
    const stateOperations = custodyOperations.get(
        authenticationCustody as object,
    );
    if (stateOperations === undefined) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidConfiguration',
            'Seed-recipient receipt authentication requires a genuine durable custody owner.',
        );
    }
    const kernel = await openProductionSeedRecipientReceiptKernel(
        transcriptCoreKernelUrl,
        {
            carriers: input.carriers,
            keyOperations: Object.freeze({
                assertMatchesRecipientKeys: ({
                    mailboxEncapsulationKey,
                    recipientSigningVerificationKey,
                }): void =>
                    assertSeedRecipientReceiptCapabilitiesMatchRosterKeys({
                        mailboxCapability: input.mailboxCapability,
                        mailboxEncapsulationKey,
                        recipientSigningVerificationKey,
                        signingCapability: input.signingCapability,
                    }),
                decapsulateMailboxCiphertext: ({
                    ciphertext,
                    mailboxEncapsulationKey,
                }): Uint8Array =>
                    decapsulateSeedRecipientMailboxCiphertext({
                        ciphertext,
                        mailboxCapability: input.mailboxCapability,
                        mailboxEncapsulationKey,
                    }),
                signReceiptBody: ({
                    receiptBodyBytes,
                    recipientSigningVerificationKey,
                    signatureRandomness,
                }): Uint8Array =>
                    signSeedRecipientReceiptBody({
                        receiptBodyBytes,
                        recipientSigningVerificationKey,
                        signatureRandomness,
                        signingCapability: input.signingCapability,
                    }),
            }),
            parameterIdentity: input.parameterIdentity,
            preparationContextBytes: input.preparationContextBytes,
            recipientPosition: input.recipientPosition,
            rootAuthorizationPackages: input.rootAuthorizationPackages,
            rootTerminalCertificateBytes: input.rootTerminalCertificateBytes,
            rosterBytes: input.rosterBytes,
            stateOperations,
        },
    );
    authenticationCustodyByKernel.set(kernel, authenticationCustody as object);
    return kernel;
};
