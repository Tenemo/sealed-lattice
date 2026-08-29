import {
    assertDirectMpcPreprocessingSourceStateSigningCapabilityMatchesRosterKey,
    signDirectMpcPreprocessingSourceStateSubjectBody,
    signDirectMpcPreprocessingSourceStateWitnessBody,
    type BrowserLocalSigningCapability,
} from '@sealed-lattice/crypto';
import { foundationProfile } from '@sealed-lattice/types';
import {
    isProductionDirectMpcPreprocessingSourceStateKernel,
    openProductionDirectMpcPreprocessingSourceStateKernel,
    type DirectMpcPreprocessingSourceStateKernelOpening,
    type DirectMpcPreprocessingSourceStateOutcome,
    type OpenDirectMpcPreprocessingSourceStateKernelInput,
    type PreparedDirectMpcPreprocessingSourceStateAuthorization,
    type ProductionDirectMpcPreprocessingSourceStateKernel,
    type VerifiedDirectMpcPreprocessingSourceStateTerminal,
} from '@sealed-lattice/wasm';

import {
    AuthenticatedRuntimeRecordError,
    bytesEqual,
    bytesToHex,
    copyBoundedBytes,
    copyExactBytes,
    mapStorageError,
    readRuntimeRecord,
    sampleRuntimeIdentifier,
    stageRuntimeRecordWrite,
    type RuntimeRecordProtection,
} from './authenticated-runtime-record.js';
import { AuthenticatedStorageRecencyCoordinator } from './authenticated-storage-recency.js';
import {
    consumeJoinedSeedMasterRestorationAuthorization,
    type JoinedSeedMasterRestorationAuthorization,
} from './joined-seed-master-custody.js';
import {
    assertSeedRecipientActionStateGuardUsesRecencyCoordinator,
    consumePreprocessingSourceStateAuthorization,
    type SeedRecipientActionStateGuard,
} from './seed-recipient-authentication-custody.js';
import type {
    UntrustedStorageTransaction,
    UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const stateAuthorizationRecordMagic = Uint8Array.of(0x53, 0x4c, 0x53, 0x41);
const stateTerminalRecordMagic = Uint8Array.of(0x53, 0x4c, 0x53, 0x54);
const recordVersion = 1;
const reservedRecordKind = 1;
const completedRecordKind = 2;
const witnessRole = 1;
const subjectRole = 2;
const successOutcome = 1;
const burnOutcome = 2;
const hashByteLength = 64;
const witnessAuthorizationBodyByteLength = 170;
const subjectAuthorizationBodyByteLength = 240;
const signingVerificationKeyByteLength = 1_952;
const signatureRandomnessByteLength = 32;
const signatureByteLength = 3_309;
const unsigned32Maximum = 0xffff_ffff;
const authorizationRecordOperationDomain =
    'sealed-lattice/runtime/direct-mpc-preprocessing-source-state-authorization/v1';
const terminalRecordOperationDomain =
    'sealed-lattice/runtime/direct-mpc-preprocessing-source-terminal/v1';

type PreprocessingSourceStateAuthorization = Parameters<
    typeof consumePreprocessingSourceStateAuthorization
>[0];
type DirectMpcPreprocessingSourceStateKernelLoaderOptions = NonNullable<
    Parameters<typeof openProductionDirectMpcPreprocessingSourceStateKernel>[1]
>;

type OpenBrowserLocalDirectMpcPreprocessingSourceStateKernelInput = Omit<
    OpenDirectMpcPreprocessingSourceStateKernelInput,
    'authenticationRecordBytes' | 'joinedCustodyRecordBytes'
> &
    Readonly<{
        joinedSeedMasterRestorationAuthorization?: JoinedSeedMasterRestorationAuthorization;
        preprocessingSourceStateAuthorization: PreprocessingSourceStateAuthorization;
        signingCapability: BrowserLocalSigningCapability;
    }>;

type BrowserLocalStateKernelRegistration = Readonly<{
    actionStateGuard: SeedRecipientActionStateGuard;
    localParticipantPosition: number;
    signingCapability: BrowserLocalSigningCapability;
    stateNamespaceIdentity: Uint8Array;
}>;

const browserLocalRegistrationByKernel = new WeakMap<
    object,
    BrowserLocalStateKernelRegistration
>();

const destroyByteArraysInObject = (value: object | undefined): void => {
    if (value === undefined) {
        return;
    }
    for (const member of Object.values(value)) {
        if (member instanceof Uint8Array) {
            member.fill(0);
        }
    }
};

/**
 * Opens the scalar state verifier only from one authenticated local source
 * predecessor. Joined source custody is consumed when and only when that
 * predecessor reached its joined state. Rust positively verifies all supplied
 * bytes before a browser-local signing capability is associated with the
 * resulting opaque context.
 */
export const openBrowserLocalDirectMpcPreprocessingSourceStateKernel = async (
    input: OpenBrowserLocalDirectMpcPreprocessingSourceStateKernelInput,
    options: DirectMpcPreprocessingSourceStateKernelLoaderOptions = {},
): Promise<DirectMpcPreprocessingSourceStateKernelOpening> => {
    let consumedAuthentication:
        | Awaited<
              ReturnType<typeof consumePreprocessingSourceStateAuthorization>
          >
        | undefined;
    let consumedJoined:
        | Awaited<
              ReturnType<typeof consumeJoinedSeedMasterRestorationAuthorization>
          >
        | undefined;
    try {
        consumedAuthentication =
            await consumePreprocessingSourceStateAuthorization(
                input.preprocessingSourceStateAuthorization,
            );
        if (input.joinedSeedMasterRestorationAuthorization !== undefined) {
            consumedJoined =
                await consumeJoinedSeedMasterRestorationAuthorization(
                    input.joinedSeedMasterRestorationAuthorization,
                );
        }
        const opening =
            await openProductionDirectMpcPreprocessingSourceStateKernel(
                {
                    authenticationRecordBytes:
                        consumedAuthentication.recordBytes,
                    foundationEvidence: input.foundationEvidence,
                    ...(consumedJoined === undefined
                        ? {}
                        : {
                              joinedCustodyRecordBytes:
                                  consumedJoined.recordBytes,
                          }),
                    ...(input.publicInconsistencyCarrierBytes === undefined
                        ? {}
                        : {
                              publicInconsistencyCarrierBytes:
                                  input.publicInconsistencyCarrierBytes,
                          }),
                },
                options,
            );
        if (opening.status === 'verified') {
            const kernel = opening.kernel;
            if (browserLocalRegistrationByKernel.has(kernel)) {
                kernel.close();
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Preprocessing-source state kernel identity was already bound to a browser-local owner.',
                );
            }
            const registration = Object.freeze({
                actionStateGuard: consumedAuthentication.actionStateGuard,
                localParticipantPosition: kernel.localParticipantPosition,
                signingCapability: input.signingCapability,
                stateNamespaceIdentity: copyExactBytes(
                    kernel.stateNamespaceIdentity,
                    hashByteLength,
                    'stateNamespaceIdentity',
                ),
            });
            browserLocalRegistrationByKernel.set(kernel, registration);
        }
        return opening;
    } finally {
        if (consumedAuthentication !== undefined) {
            destroyByteArraysInObject(consumedAuthentication.context);
            consumedAuthentication.recordBytes.fill(0);
        }
        if (consumedJoined !== undefined) {
            destroyByteArraysInObject(consumedJoined.context);
            consumedJoined.recordBytes.fill(0);
        }
    }
};

export type DirectMpcPreprocessingSourceStateCustodyLimits = Readonly<{
    maximumEndorsementCarrierByteLength: number;
    maximumIntentByteLength: number;
    maximumTerminalByteLength: number;
    maximumWitnessEnvelopeByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

type RetainedDirectMpcPreprocessingSourceStateWitness = Readonly<{
    stateKeyIdentity: Uint8Array;
    witnessEnvelopeBytes: Uint8Array;
}>;

type RetainedDirectMpcPreprocessingSourceStateSubject = Readonly<{
    endorsementCarrierBytes: Uint8Array;
    stateKeyIdentity: Uint8Array;
}>;

type RetainedDirectMpcPreprocessingSourceStateTerminal = Readonly<{
    outcome: DirectMpcPreprocessingSourceStateOutcome;
    stateNamespaceIdentity: Uint8Array;
    terminalBytes: Uint8Array;
    terminalIdentity: Uint8Array;
}>;

export type DirectMpcPreprocessingSourceStateCustodyKernel = Readonly<{
    close(): void;
    completeSubject(input: {
        authorizationBodyBytes: Uint8Array;
        signature: Uint8Array;
        witnessEnvelopeBytes: readonly Uint8Array[];
    }): Readonly<{
        endorsementCarrierBytes: Uint8Array;
        stateKeyIdentity: Uint8Array;
    }>;
    completeWitness(input: {
        authorizationBodyBytes: Uint8Array;
        signature: Uint8Array;
        subjectPosition: number;
    }): Readonly<{
        stateKeyIdentity: Uint8Array;
        witnessEnvelopeBytes: Uint8Array;
    }>;
    createTerminal(input: {
        endorsementCarrierBytes: readonly Uint8Array[];
    }): VerifiedDirectMpcPreprocessingSourceStateTerminal;
    prepareSubject(input: {
        witnessEnvelopeBytes: readonly Uint8Array[];
    }): PreparedDirectMpcPreprocessingSourceStateAuthorization;
    prepareWitness(input: {
        subjectPosition: number;
    }): PreparedDirectMpcPreprocessingSourceStateAuthorization;
    validateTerminal(input: {
        terminalBytes: Uint8Array;
    }): VerifiedDirectMpcPreprocessingSourceStateTerminal;
}>;

type StateAuthorizationRole = 'subject' | 'witness';

type StateAuthorizationOperation = Readonly<{
    authorizationBodyBytes: Uint8Array;
    intentBytes: Uint8Array;
    role: StateAuthorizationRole;
    signingVerificationKey: Uint8Array;
    stateKeyIdentity: Uint8Array;
    subjectPosition: number;
    witnessEnvelopeBytes: readonly Uint8Array[];
}>;

type ReservedStateAuthorizationRecord = StateAuthorizationOperation &
    Readonly<{
        kind: 'reserved';
        signatureRandomness: Uint8Array;
        stateNamespaceIdentity: Uint8Array;
    }>;

type CompletedStateAuthorizationRecord = StateAuthorizationOperation &
    Readonly<{
        kind: 'completed';
        outputCarrierBytes: Uint8Array;
        signature: Uint8Array;
        stateNamespaceIdentity: Uint8Array;
    }>;

type StateAuthorizationRecord =
    | CompletedStateAuthorizationRecord
    | ReservedStateAuthorizationRecord;

type StateTerminalRecord = RetainedDirectMpcPreprocessingSourceStateTerminal;

type OpenedRecord<RecordValue> = Readonly<{
    record: RecordValue;
    sealedBytes: Uint8Array;
}>;

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

const copyLimits = (
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): DirectMpcPreprocessingSourceStateCustodyLimits =>
    Object.freeze({
        maximumEndorsementCarrierByteLength: requireSafeInteger(
            limits.maximumEndorsementCarrierByteLength,
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            'Maximum endorsement-carrier byte length',
            'InvalidConfiguration',
        ),
        maximumIntentByteLength: requireSafeInteger(
            limits.maximumIntentByteLength,
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            'Maximum state-intent byte length',
            'InvalidConfiguration',
        ),
        maximumTerminalByteLength: requireSafeInteger(
            limits.maximumTerminalByteLength,
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            'Maximum source-terminal byte length',
            'InvalidConfiguration',
        ),
        maximumWitnessEnvelopeByteLength: requireSafeInteger(
            limits.maximumWitnessEnvelopeByteLength,
            1,
            foundationProfile.maximumCopiedBufferByteLength,
            'Maximum state-witness envelope byte length',
            'InvalidConfiguration',
        ),
        transactionLifetimeMilliseconds: requireSafeInteger(
            limits.transactionLifetimeMilliseconds,
            1,
            unsigned32Maximum,
            'State-custody transaction lifetime',
            'InvalidConfiguration',
        ),
    });

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

const concatenateBytes = (parts: readonly Uint8Array[]): Uint8Array => {
    let byteLength = 0;
    for (const part of parts) {
        if (
            part.byteLength >
            foundationProfile.maximumCopiedBufferByteLength - byteLength
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'ResourceLimit',
                'Preprocessing-source state custody record exceeds the absolute copied-buffer bound.',
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

const copyWitnessEnvelopes = (
    value: readonly Uint8Array[],
    expectedCount: number,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): readonly Uint8Array[] => {
    if (!Array.isArray(value) || value.length !== expectedCount) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            `State-witness envelope inventory must contain exactly ${expectedCount} entries.`,
        );
    }
    return Object.freeze(
        value.map((bytes, index) =>
            copyBoundedBytes(
                bytes,
                limits.maximumWitnessEnvelopeByteLength,
                `witnessEnvelopeBytes[${index}]`,
            ),
        ),
    );
};

const copyEndorsementCarriers = (
    value: readonly Uint8Array[],
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): readonly Uint8Array[] => {
    if (
        !Array.isArray(value) ||
        value.length !== foundationProfile.finalityQuorum
    ) {
        throw new AuthenticatedRuntimeRecordError(
            'InvalidInput',
            'Preprocessing-source terminal endorsement inventory must contain the exact finality quorum.',
        );
    }
    return Object.freeze(
        value.map((bytes, index) =>
            copyBoundedBytes(
                bytes,
                limits.maximumEndorsementCarrierByteLength,
                `endorsementCarrierBytes[${index}]`,
            ),
        ),
    );
};

const copyPreparedOperation = (input: {
    limits: DirectMpcPreprocessingSourceStateCustodyLimits;
    prepared: PreparedDirectMpcPreprocessingSourceStateAuthorization;
    role: StateAuthorizationRole;
    subjectPosition: number;
    witnessEnvelopeBytes: readonly Uint8Array[];
}): StateAuthorizationOperation =>
    Object.freeze({
        authorizationBodyBytes: copyExactBytes(
            input.prepared.authorizationBodyBytes,
            input.role === 'witness'
                ? witnessAuthorizationBodyByteLength
                : subjectAuthorizationBodyByteLength,
            'authorizationBodyBytes',
        ),
        intentBytes: copyBoundedBytes(
            input.prepared.intentBytes,
            input.limits.maximumIntentByteLength,
            'intentBytes',
        ),
        role: input.role,
        signingVerificationKey: copyExactBytes(
            input.prepared.signingVerificationKey,
            signingVerificationKeyByteLength,
            'signingVerificationKey',
        ),
        stateKeyIdentity: copyExactBytes(
            input.prepared.stateKeyIdentity,
            hashByteLength,
            'stateKeyIdentity',
        ),
        subjectPosition: requireSafeInteger(
            input.subjectPosition,
            0,
            foundationProfile.participantCount - 1,
            'State subject position',
        ),
        witnessEnvelopeBytes: copyWitnessEnvelopes(
            input.witnessEnvelopeBytes,
            input.role === 'witness' ? 0 : foundationProfile.stateWitnessQuorum,
            input.limits,
        ),
    });

const copyOperation = (
    operation: StateAuthorizationOperation,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): StateAuthorizationOperation =>
    copyPreparedOperation({
        limits,
        prepared: operation,
        role: operation.role,
        subjectPosition: operation.subjectPosition,
        witnessEnvelopeBytes: operation.witnessEnvelopeBytes,
    });

const destroyOperation = (
    operation: StateAuthorizationOperation | undefined,
): void => {
    operation?.authorizationBodyBytes.fill(0);
    operation?.intentBytes.fill(0);
    operation?.signingVerificationKey.fill(0);
    operation?.stateKeyIdentity.fill(0);
    operation?.witnessEnvelopeBytes.forEach((bytes) => bytes.fill(0));
};

const operationsEqual = (
    left: StateAuthorizationOperation,
    right: StateAuthorizationOperation,
): boolean =>
    left.role === right.role &&
    left.subjectPosition === right.subjectPosition &&
    bytesEqual(left.authorizationBodyBytes, right.authorizationBodyBytes) &&
    bytesEqual(left.intentBytes, right.intentBytes) &&
    bytesEqual(left.signingVerificationKey, right.signingVerificationKey) &&
    bytesEqual(left.stateKeyIdentity, right.stateKeyIdentity) &&
    left.witnessEnvelopeBytes.length === right.witnessEnvelopeBytes.length &&
    left.witnessEnvelopeBytes.every((bytes, index) =>
        bytesEqual(bytes, right.witnessEnvelopeBytes[index]),
    );

const encodeAuthorizationRecord = (
    record: StateAuthorizationRecord,
): Uint8Array => {
    const operation = record;
    const parts: Uint8Array[] = [
        stateAuthorizationRecordMagic,
        unsigned16LittleEndian(recordVersion),
        Uint8Array.of(
            record.kind === 'reserved'
                ? reservedRecordKind
                : completedRecordKind,
        ),
        Uint8Array.of(operation.role === 'witness' ? witnessRole : subjectRole),
        record.stateNamespaceIdentity,
        operation.stateKeyIdentity,
        unsigned16LittleEndian(operation.subjectPosition),
        unsigned32LittleEndian(operation.authorizationBodyBytes.byteLength),
        unsigned32LittleEndian(operation.intentBytes.byteLength),
        operation.signingVerificationKey,
        unsigned16LittleEndian(operation.witnessEnvelopeBytes.length),
        ...operation.witnessEnvelopeBytes.map((bytes) =>
            unsigned32LittleEndian(bytes.byteLength),
        ),
        operation.authorizationBodyBytes,
        operation.intentBytes,
        ...operation.witnessEnvelopeBytes,
    ];
    if (record.kind === 'reserved') {
        parts.push(record.signatureRandomness);
    } else {
        parts.push(
            record.signature,
            unsigned32LittleEndian(record.outputCarrierBytes.byteLength),
            record.outputCarrierBytes,
        );
    }
    return concatenateBytes(parts);
};

const encodeTerminalRecord = (record: StateTerminalRecord): Uint8Array =>
    concatenateBytes([
        stateTerminalRecordMagic,
        unsigned16LittleEndian(recordVersion),
        Uint8Array.of(
            record.outcome === 'success' ? successOutcome : burnOutcome,
        ),
        record.stateNamespaceIdentity,
        record.terminalIdentity,
        unsigned32LittleEndian(record.terminalBytes.byteLength),
        record.terminalBytes,
    ]);

class RecordCursor {
    readonly #bytes: Uint8Array;
    readonly #ownedReadBytes: Uint8Array[] = [];
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
                `Preprocessing-source state custody record ends within ${label}.`,
            );
        }
        const value = this.#bytes.slice(
            this.#offset,
            this.#offset + byteLength,
        );
        this.#offset += byteLength;
        this.#ownedReadBytes.push(value);
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
                'Preprocessing-source state custody record has trailing bytes.',
            );
        }
    }

    public releaseReadBytes(): void {
        this.#ownedReadBytes.length = 0;
    }

    public destroyReadBytes(): void {
        this.#ownedReadBytes.forEach((bytes) => bytes.fill(0));
        this.#ownedReadBytes.length = 0;
    }
}

const requireMagicAndVersion = (
    cursor: RecordCursor,
    expectedMagic: Uint8Array,
): void => {
    const magic = cursor.readExact(expectedMagic.byteLength, 'record magic');
    try {
        if (!bytesEqual(magic, expectedMagic)) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source state custody record has the wrong magic.',
            );
        }
    } finally {
        magic.fill(0);
    }
    if (cursor.readUnsigned16('record version') !== recordVersion) {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Preprocessing-source state custody record has an unsupported version.',
        );
    }
};

const decodeAuthorizationRecord = (
    plaintext: Uint8Array,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): StateAuthorizationRecord => {
    const cursor = new RecordCursor(plaintext);
    try {
        requireMagicAndVersion(cursor, stateAuthorizationRecordMagic);
        const recordKind = cursor.readUnsigned8('record kind');
        if (
            recordKind !== reservedRecordKind &&
            recordKind !== completedRecordKind
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source state authorization record has an invalid kind.',
            );
        }
        const encodedRole = cursor.readUnsigned8('authorization role');
        if (encodedRole !== witnessRole && encodedRole !== subjectRole) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source state authorization record has an invalid role.',
            );
        }
        const role: StateAuthorizationRole =
            encodedRole === witnessRole ? 'witness' : 'subject';
        const stateNamespaceIdentity = cursor.readExact(
            hashByteLength,
            'state-namespace identity',
        );
        const stateKeyIdentity = cursor.readExact(
            hashByteLength,
            'state-key identity',
        );
        const subjectPosition = requireSafeInteger(
            cursor.readUnsigned16('subject position'),
            0,
            foundationProfile.participantCount - 1,
            'Stored state subject position',
            'AuthenticationFailed',
        );
        const authorizationBodyByteLength = requireSafeInteger(
            cursor.readUnsigned32('authorization-body byte length'),
            role === 'witness'
                ? witnessAuthorizationBodyByteLength
                : subjectAuthorizationBodyByteLength,
            role === 'witness'
                ? witnessAuthorizationBodyByteLength
                : subjectAuthorizationBodyByteLength,
            'Stored authorization-body byte length',
            'AuthenticationFailed',
        );
        const intentByteLength = requireSafeInteger(
            cursor.readUnsigned32('intent byte length'),
            1,
            limits.maximumIntentByteLength,
            'Stored intent byte length',
            'AuthenticationFailed',
        );
        const signingVerificationKey = cursor.readExact(
            signingVerificationKeyByteLength,
            'signing verification key',
        );
        const witnessEnvelopeCount = requireSafeInteger(
            cursor.readUnsigned16('witness-envelope count'),
            role === 'witness' ? 0 : foundationProfile.stateWitnessQuorum,
            role === 'witness' ? 0 : foundationProfile.stateWitnessQuorum,
            'Stored witness-envelope count',
            'AuthenticationFailed',
        );
        const witnessEnvelopeByteLengths = Array.from(
            { length: witnessEnvelopeCount },
            (_unused, index) =>
                requireSafeInteger(
                    cursor.readUnsigned32(
                        `witness envelope ${index} byte length`,
                    ),
                    1,
                    limits.maximumWitnessEnvelopeByteLength,
                    `Stored witness envelope ${index} byte length`,
                    'AuthenticationFailed',
                ),
        );
        const authorizationBodyBytes = cursor.readExact(
            authorizationBodyByteLength,
            'authorization body',
        );
        const intentBytes = cursor.readExact(intentByteLength, 'state intent');
        const witnessEnvelopeBytes = Object.freeze(
            witnessEnvelopeByteLengths.map((byteLength, index) =>
                cursor.readExact(byteLength, `witness envelope ${index}`),
            ),
        );
        const shared = {
            authorizationBodyBytes,
            intentBytes,
            role,
            signingVerificationKey,
            stateKeyIdentity,
            stateNamespaceIdentity,
            subjectPosition,
            witnessEnvelopeBytes,
        };
        if (recordKind === reservedRecordKind) {
            const signatureRandomness = cursor.readExact(
                signatureRandomnessByteLength,
                'signature randomness',
            );
            cursor.requireComplete();
            if (signatureRandomness.every((byte) => byte === 0)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Preprocessing-source state reservation has invalid signature randomness.',
                );
            }
            const record = Object.freeze({
                ...shared,
                kind: 'reserved' as const,
                signatureRandomness,
            });
            cursor.releaseReadBytes();
            return record;
        }
        const signature = cursor.readExact(signatureByteLength, 'signature');
        const outputCarrierByteLength = requireSafeInteger(
            cursor.readUnsigned32('output-carrier byte length'),
            1,
            role === 'witness'
                ? limits.maximumWitnessEnvelopeByteLength
                : limits.maximumEndorsementCarrierByteLength,
            'Stored output-carrier byte length',
            'AuthenticationFailed',
        );
        const outputCarrierBytes = cursor.readExact(
            outputCarrierByteLength,
            'output carrier',
        );
        cursor.requireComplete();
        const record = Object.freeze({
            ...shared,
            kind: 'completed' as const,
            outputCarrierBytes,
            signature,
        });
        cursor.releaseReadBytes();
        return record;
    } catch (error) {
        cursor.destroyReadBytes();
        throw error;
    }
};

const decodeTerminalRecord = (
    plaintext: Uint8Array,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): StateTerminalRecord => {
    const cursor = new RecordCursor(plaintext);
    try {
        requireMagicAndVersion(cursor, stateTerminalRecordMagic);
        const encodedOutcome = cursor.readUnsigned8('terminal outcome');
        if (
            encodedOutcome !== successOutcome &&
            encodedOutcome !== burnOutcome
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source terminal record has an invalid outcome.',
            );
        }
        const stateNamespaceIdentity = cursor.readExact(
            hashByteLength,
            'state-namespace identity',
        );
        const terminalIdentity = cursor.readExact(
            hashByteLength,
            'terminal identity',
        );
        const terminalByteLength = requireSafeInteger(
            cursor.readUnsigned32('terminal byte length'),
            1,
            limits.maximumTerminalByteLength,
            'Stored source-terminal byte length',
            'AuthenticationFailed',
        );
        const terminalBytes = cursor.readExact(
            terminalByteLength,
            'source terminal',
        );
        cursor.requireComplete();
        const record = Object.freeze({
            outcome: encodedOutcome === successOutcome ? 'success' : 'burn',
            stateNamespaceIdentity,
            terminalBytes,
            terminalIdentity,
        });
        cursor.releaseReadBytes();
        return record;
    } catch (error) {
        cursor.destroyReadBytes();
        throw error;
    }
};

const destroyAuthorizationRecord = (
    record: StateAuthorizationRecord | undefined,
): void => {
    if (record === undefined) {
        return;
    }
    destroyOperation(record);
    record.stateNamespaceIdentity.fill(0);
    if (record.kind === 'reserved') {
        record.signatureRandomness.fill(0);
    } else {
        record.signature.fill(0);
        record.outputCarrierBytes.fill(0);
    }
};

const destroyTerminalRecord = (
    record: StateTerminalRecord | undefined,
): void => {
    record?.stateNamespaceIdentity.fill(0);
    record?.terminalIdentity.fill(0);
    record?.terminalBytes.fill(0);
};

const authorizationRecordKey = (
    stateNamespaceIdentity: Uint8Array,
    stateKeyIdentity: Uint8Array,
): string =>
    `direct-mpc/preprocessing-source/state/${bytesToHex(
        stateNamespaceIdentity,
    )}/authorization/${bytesToHex(stateKeyIdentity)}`;

const terminalRecordKey = (stateNamespaceIdentity: Uint8Array): string =>
    `direct-mpc/preprocessing-source/state/${bytesToHex(
        stateNamespaceIdentity,
    )}/terminal`;

const readAuthorizationRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): Promise<OpenedRecord<StateAuthorizationRecord> | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: authorizationRecordOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        return Object.freeze({
            record: decodeAuthorizationRecord(opened.plaintext, limits),
            sealedBytes: opened.sealedBytes.slice(),
        });
    } finally {
        opened.plaintext.fill(0);
        opened.sealedBytes.fill(0);
    }
};

const readTerminalRecord = async (
    store: UntrustedStorageTransactionStore,
    protection: RuntimeRecordProtection,
    recordKey: string,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): Promise<OpenedRecord<StateTerminalRecord> | undefined> => {
    const opened = await readRuntimeRecord({
        logicalRecordKey: recordKey,
        operationDomain: terminalRecordOperationDomain,
        protection,
        store,
    });
    if (opened === undefined) {
        return undefined;
    }
    try {
        return Object.freeze({
            record: decodeTerminalRecord(opened.plaintext, limits),
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
            'Preprocessing-source state custody failed and could not release transaction ownership.',
            [mappedOperationFailure, mapStorageError(closeFailure)],
        );
    }
    return mappedOperationFailure;
};

const commitPlaintext = async (input: {
    expectedCurrentSealedBytes: Uint8Array | null;
    logicalRecordKey: string;
    operationDomain: string;
    plaintext: Uint8Array;
    protection: RuntimeRecordProtection;
    store: UntrustedStorageTransactionStore;
    transactionLifetimeMilliseconds: number;
}): Promise<Uint8Array> => {
    const transaction = await input.store.beginTransaction({
        lifetimeMilliseconds: input.transactionLifetimeMilliseconds,
    });
    let stagedSealedBytes: Uint8Array | undefined;
    try {
        stagedSealedBytes = await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: input.expectedCurrentSealedBytes,
            logicalRecordKey: input.logicalRecordKey,
            operationDomain: input.operationDomain,
            plaintext: input.plaintext,
            protection: input.protection,
            transaction,
        });
        await transaction.commit();
        return stagedSealedBytes.slice();
    } catch (error) {
        throw await closeTransactionAfterFailure(transaction, error);
    } finally {
        stagedSealedBytes?.fill(0);
    }
};

const errorHasCode = (error: unknown, code: string): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code;

const copyTerminal = (
    terminal: VerifiedDirectMpcPreprocessingSourceStateTerminal,
    limits: DirectMpcPreprocessingSourceStateCustodyLimits,
): RetainedDirectMpcPreprocessingSourceStateTerminal => {
    if (terminal.outcome !== 'success' && terminal.outcome !== 'burn') {
        throw new AuthenticatedRuntimeRecordError(
            'AuthenticationFailed',
            'Verified preprocessing-source terminal returned an invalid outcome.',
        );
    }
    return Object.freeze({
        outcome: terminal.outcome,
        stateNamespaceIdentity: copyExactBytes(
            terminal.stateNamespaceIdentity,
            hashByteLength,
            'stateNamespaceIdentity',
        ),
        terminalBytes: copyBoundedBytes(
            terminal.terminalBytes,
            limits.maximumTerminalByteLength,
            'terminalBytes',
        ),
        terminalIdentity: copyExactBytes(
            terminal.terminalIdentity,
            hashByteLength,
            'terminalIdentity',
        ),
    });
};

const terminalsEqual = (
    left: StateTerminalRecord,
    right: StateTerminalRecord,
): boolean =>
    left.outcome === right.outcome &&
    bytesEqual(left.stateNamespaceIdentity, right.stateNamespaceIdentity) &&
    bytesEqual(left.terminalIdentity, right.terminalIdentity) &&
    bytesEqual(left.terminalBytes, right.terminalBytes);

/**
 * Owns the persistent one-shot witness, subject and terminal slots for one
 * positively verified preprocessing-source outcome. Every signing hedge is
 * retained before use and every resulting carrier is retained before return.
 * The logical keys contain only Rust-derived alternative-independent state
 * identities, so success and burn alternatives collide at the same slots.
 */
export class DirectMpcPreprocessingSourceStateCustody {
    readonly #issuedSignatureRandomness = new Set<string>();
    readonly #kernel: DirectMpcPreprocessingSourceStateCustodyKernel;
    readonly #limits: DirectMpcPreprocessingSourceStateCustodyLimits;
    readonly #localParticipantPosition: number;
    readonly #protection: RuntimeRecordProtection;
    readonly #recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    readonly #signingCapability: BrowserLocalSigningCapability;
    readonly #stateNamespaceIdentity: Uint8Array;
    #closed = false;
    #operationTail: Promise<void> = Promise.resolve();

    public constructor(input: {
        kernel: ProductionDirectMpcPreprocessingSourceStateKernel;
        limits: DirectMpcPreprocessingSourceStateCustodyLimits;
        protection: RuntimeRecordProtection;
        recencyCoordinator: AuthenticatedStorageRecencyCoordinator;
    }) {
        if (
            !isProductionDirectMpcPreprocessingSourceStateKernel(input.kernel)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Preprocessing-source state custody requires an integrity-pinned production kernel.',
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
                'Preprocessing-source state custody requires an authenticated storage recency coordinator.',
            );
        }
        const registration = browserLocalRegistrationByKernel.get(input.kernel);
        if (registration === undefined) {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidConfiguration',
                'Preprocessing-source state custody requires a kernel opened from authenticated local predecessor custody.',
            );
        }
        assertSeedRecipientActionStateGuardUsesRecencyCoordinator(
            registration.actionStateGuard,
            input.recencyCoordinator,
        );
        this.#kernel = Object.freeze({
            close: input.kernel.close.bind(input.kernel),
            completeSubject: input.kernel.completeSubject.bind(input.kernel),
            completeWitness: input.kernel.completeWitness.bind(input.kernel),
            createTerminal: input.kernel.createTerminal.bind(input.kernel),
            prepareSubject: input.kernel.prepareSubject.bind(input.kernel),
            prepareWitness: input.kernel.prepareWitness.bind(input.kernel),
            validateTerminal: input.kernel.validateTerminal.bind(input.kernel),
        });
        this.#limits = copyLimits(input.limits);
        this.#localParticipantPosition = registration.localParticipantPosition;
        this.#protection = input.protection;
        this.#recencyCoordinator = input.recencyCoordinator;
        this.#signingCapability = registration.signingCapability;
        this.#stateNamespaceIdentity =
            registration.stateNamespaceIdentity.slice();
    }

    public close(): Promise<void> {
        const scheduled = this.#operationTail.then(() => {
            if (this.#closed) {
                return;
            }
            try {
                this.#kernel.close();
            } catch (error) {
                throw new AuthenticatedRuntimeRecordError(
                    'CleanupFailed',
                    'Preprocessing-source state custody could not close its scalar kernel context.',
                    error,
                );
            } finally {
                this.#closed = true;
                this.#stateNamespaceIdentity.fill(0);
            }
        });
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    public retainWitness(
        subjectPosition: number,
    ): Promise<RetainedDirectMpcPreprocessingSourceStateWitness> {
        return this.#schedule(async () => {
            const operation = this.#prepareWitness(subjectPosition);
            try {
                const completed = await this.#retainAuthorization(operation);
                try {
                    return Object.freeze({
                        stateKeyIdentity: completed.stateKeyIdentity.slice(),
                        witnessEnvelopeBytes:
                            completed.outputCarrierBytes.slice(),
                    });
                } finally {
                    destroyAuthorizationRecord(completed);
                }
            } finally {
                destroyOperation(operation);
            }
        });
    }

    public retainSubject(
        witnessEnvelopeBytes: readonly Uint8Array[],
    ): Promise<RetainedDirectMpcPreprocessingSourceStateSubject> {
        const witnesses = copyWitnessEnvelopes(
            witnessEnvelopeBytes,
            foundationProfile.stateWitnessQuorum,
            this.#limits,
        );
        return this.#schedule(async () => {
            try {
                const operation = this.#prepareSubject(witnesses);
                try {
                    const completed =
                        await this.#retainAuthorization(operation);
                    try {
                        return Object.freeze({
                            endorsementCarrierBytes:
                                completed.outputCarrierBytes.slice(),
                            stateKeyIdentity:
                                completed.stateKeyIdentity.slice(),
                        });
                    } finally {
                        destroyAuthorizationRecord(completed);
                    }
                } finally {
                    destroyOperation(operation);
                }
            } finally {
                witnesses.forEach((bytes) => bytes.fill(0));
            }
        });
    }

    public createAndRetainTerminal(
        endorsementCarrierBytes: readonly Uint8Array[],
    ): Promise<RetainedDirectMpcPreprocessingSourceStateTerminal> {
        const carriers = copyEndorsementCarriers(
            endorsementCarrierBytes,
            this.#limits,
        );
        return this.#schedule(async () => {
            try {
                let verified: VerifiedDirectMpcPreprocessingSourceStateTerminal;
                try {
                    verified = this.#kernel.createTerminal({
                        endorsementCarrierBytes: carriers,
                    });
                } catch (error) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Preprocessing-source terminal creation rejected the endorsement inventory.',
                        error,
                    );
                }
                return await this.#retainTerminal(verified);
            } finally {
                carriers.forEach((bytes) => bytes.fill(0));
            }
        });
    }

    public validateAndRetainTerminal(
        terminalBytes: Uint8Array,
    ): Promise<RetainedDirectMpcPreprocessingSourceStateTerminal> {
        const terminal = copyBoundedBytes(
            terminalBytes,
            this.#limits.maximumTerminalByteLength,
            'terminalBytes',
        );
        return this.#schedule(async () => {
            try {
                let verified: VerifiedDirectMpcPreprocessingSourceStateTerminal;
                try {
                    verified = this.#kernel.validateTerminal({
                        terminalBytes: terminal,
                    });
                } catch (error) {
                    throw new AuthenticatedRuntimeRecordError(
                        errorHasCode(error, 'ConsumedState')
                            ? 'InvalidState'
                            : 'AuthenticationFailed',
                        'Preprocessing-source terminal validation refused the supplied transcript.',
                        error,
                    );
                }
                return await this.#retainTerminal(verified);
            } finally {
                terminal.fill(0);
            }
        });
    }

    public resumeTerminal(): Promise<
        RetainedDirectMpcPreprocessingSourceStateTerminal | undefined
    > {
        return this.#schedule(async () => {
            const opened = await this.#readTerminal();
            if (opened === undefined) {
                return undefined;
            }
            try {
                return this.#validateStoredTerminal(opened.record);
            } finally {
                destroyTerminalRecord(opened.record);
                opened.sealedBytes.fill(0);
            }
        });
    }

    #schedule<Result>(operation: () => Promise<Result>): Promise<Result> {
        const scheduled = this.#operationTail.then(() => {
            if (this.#closed) {
                throw new AuthenticatedRuntimeRecordError(
                    'InvalidState',
                    'Preprocessing-source state custody is closed.',
                );
            }
            return operation();
        });
        this.#operationTail = scheduled.then(
            () => undefined,
            () => undefined,
        );
        return scheduled;
    }

    #prepareWitness(subjectPositionValue: number): StateAuthorizationOperation {
        const subjectPosition = requireSafeInteger(
            subjectPositionValue,
            0,
            foundationProfile.participantCount - 1,
            'State subject position',
        );
        let prepared: PreparedDirectMpcPreprocessingSourceStateAuthorization;
        try {
            prepared = this.#kernel.prepareWitness({ subjectPosition });
        } catch (error) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source state witness preparation rejected the verified predecessor.',
                error,
            );
        }
        return copyPreparedOperation({
            limits: this.#limits,
            prepared,
            role: 'witness',
            subjectPosition,
            witnessEnvelopeBytes: [],
        });
    }

    #prepareSubject(
        witnessEnvelopeBytes: readonly Uint8Array[],
    ): StateAuthorizationOperation {
        let prepared: PreparedDirectMpcPreprocessingSourceStateAuthorization;
        try {
            prepared = this.#kernel.prepareSubject({ witnessEnvelopeBytes });
        } catch (error) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source state subject preparation rejected the witness inventory.',
                error,
            );
        }
        return copyPreparedOperation({
            limits: this.#limits,
            prepared,
            role: 'subject',
            subjectPosition: this.#localParticipantPosition,
            witnessEnvelopeBytes,
        });
    }

    async #retainAuthorization(
        operation: StateAuthorizationOperation,
    ): Promise<CompletedStateAuthorizationRecord> {
        const recordKey = authorizationRecordKey(
            this.#stateNamespaceIdentity,
            operation.stateKeyIdentity,
        );
        let opened = await this.#readAuthorization(recordKey);
        if (opened === undefined) {
            opened = await this.#reserveAuthorization(recordKey, operation);
        }
        return this.#continueAuthorization(recordKey, opened, operation);
    }

    async #reserveAuthorization(
        recordKey: string,
        operation: StateAuthorizationOperation,
    ): Promise<OpenedRecord<StateAuthorizationRecord>> {
        let signatureRandomness: Uint8Array | undefined;
        let reservation: ReservedStateAuthorizationRecord | undefined;
        try {
            signatureRandomness = sampleRuntimeIdentifier(
                this.#protection,
                this.#issuedSignatureRandomness,
                'Preprocessing-source state ML-DSA signature randomness',
            );
            reservation = Object.freeze({
                ...copyOperation(operation, this.#limits),
                kind: 'reserved' as const,
                signatureRandomness: signatureRandomness.slice(),
                stateNamespaceIdentity: this.#stateNamespaceIdentity.slice(),
            });
            const plaintext = encodeAuthorizationRecord(reservation);
            try {
                let sealedBytes: Uint8Array;
                try {
                    sealedBytes = await this.#recencyCoordinator.runMutation(
                        async (store) => {
                            const terminal = await readTerminalRecord(
                                store,
                                this.#protection,
                                terminalRecordKey(this.#stateNamespaceIdentity),
                                this.#limits,
                            );
                            if (terminal !== undefined) {
                                destroyTerminalRecord(terminal.record);
                                terminal.sealedBytes.fill(0);
                                throw new AuthenticatedRuntimeRecordError(
                                    'InvalidState',
                                    'A retained preprocessing-source terminal consumes new state authorizations.',
                                );
                            }
                            return commitPlaintext({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey: recordKey,
                                operationDomain:
                                    authorizationRecordOperationDomain,
                                plaintext,
                                protection: this.#protection,
                                store,
                                transactionLifetimeMilliseconds:
                                    this.#limits
                                        .transactionLifetimeMilliseconds,
                            });
                        },
                    );
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const existing = await this.#readAuthorization(recordKey);
                    if (existing === undefined) {
                        throw error;
                    }
                    this.#requireMatchingAuthorization(
                        existing.record,
                        operation,
                    );
                    return existing;
                }
                return Object.freeze({
                    record: Object.freeze({
                        ...copyOperation(reservation, this.#limits),
                        kind: 'reserved' as const,
                        signatureRandomness:
                            reservation.signatureRandomness.slice(),
                        stateNamespaceIdentity:
                            reservation.stateNamespaceIdentity.slice(),
                    }),
                    sealedBytes,
                });
            } finally {
                plaintext.fill(0);
            }
        } finally {
            signatureRandomness?.fill(0);
            destroyAuthorizationRecord(reservation);
        }
    }

    async #continueAuthorization(
        recordKey: string,
        opened: OpenedRecord<StateAuthorizationRecord>,
        expectedOperation: StateAuthorizationOperation,
    ): Promise<CompletedStateAuthorizationRecord> {
        try {
            this.#requireMatchingAuthorization(
                opened.record,
                expectedOperation,
            );
            if (opened.record.kind === 'completed') {
                this.#validateCompletedAuthorization(opened.record);
                return this.#copyCompletedRecord(opened.record);
            }
            return await this.#completeReservedAuthorization(
                recordKey,
                opened,
                expectedOperation,
            );
        } finally {
            destroyAuthorizationRecord(opened.record);
            opened.sealedBytes.fill(0);
        }
    }

    async #completeReservedAuthorization(
        recordKey: string,
        opened: OpenedRecord<StateAuthorizationRecord>,
        expectedOperation: StateAuthorizationOperation,
    ): Promise<CompletedStateAuthorizationRecord> {
        if (opened.record.kind !== 'reserved') {
            throw new AuthenticatedRuntimeRecordError(
                'InvalidState',
                'Completed preprocessing-source state authorization cannot re-enter reservation completion.',
            );
        }
        const reservation = opened.record;
        try {
            return await this.#recencyCoordinator.runMutation(async (store) => {
                const terminal = await readTerminalRecord(
                    store,
                    this.#protection,
                    terminalRecordKey(this.#stateNamespaceIdentity),
                    this.#limits,
                );
                if (terminal !== undefined) {
                    destroyTerminalRecord(terminal.record);
                    terminal.sealedBytes.fill(0);
                    throw new AuthenticatedRuntimeRecordError(
                        'InvalidState',
                        'A retained preprocessing-source terminal consumes an incomplete state authorization.',
                    );
                }
                const signature = this.#signAuthorization(reservation);
                try {
                    const outputCarrierBytes = this.#completeAuthorization(
                        reservation,
                        signature,
                    );
                    try {
                        const completed: CompletedStateAuthorizationRecord =
                            Object.freeze({
                                ...copyOperation(reservation, this.#limits),
                                kind: 'completed' as const,
                                outputCarrierBytes: outputCarrierBytes.slice(),
                                signature: signature.slice(),
                                stateNamespaceIdentity:
                                    reservation.stateNamespaceIdentity.slice(),
                            });
                        try {
                            const plaintext =
                                encodeAuthorizationRecord(completed);
                            try {
                                const sealedBytes = await commitPlaintext({
                                    expectedCurrentSealedBytes:
                                        opened.sealedBytes,
                                    logicalRecordKey: recordKey,
                                    operationDomain:
                                        authorizationRecordOperationDomain,
                                    plaintext,
                                    protection: this.#protection,
                                    store,
                                    transactionLifetimeMilliseconds:
                                        this.#limits
                                            .transactionLifetimeMilliseconds,
                                });
                                sealedBytes.fill(0);
                                return this.#copyCompletedRecord(completed);
                            } finally {
                                plaintext.fill(0);
                            }
                        } finally {
                            destroyAuthorizationRecord(completed);
                        }
                    } finally {
                        outputCarrierBytes.fill(0);
                    }
                } finally {
                    signature.fill(0);
                }
            });
        } catch (error) {
            if (!errorHasCode(error, 'Conflict')) {
                throw error;
            }
            const existing = await this.#readAuthorization(recordKey);
            if (existing === undefined) {
                throw error;
            }
            try {
                this.#requireMatchingAuthorization(
                    existing.record,
                    expectedOperation,
                );
                if (existing.record.kind !== 'completed') {
                    throw error;
                }
                this.#validateCompletedAuthorization(existing.record);
                return this.#copyCompletedRecord(existing.record);
            } finally {
                destroyAuthorizationRecord(existing.record);
                existing.sealedBytes.fill(0);
            }
        }
    }

    #requireMatchingAuthorization(
        record: StateAuthorizationRecord,
        expectedOperation: StateAuthorizationOperation,
    ): void {
        if (
            !bytesEqual(
                record.stateNamespaceIdentity,
                this.#stateNamespaceIdentity,
            ) ||
            !operationsEqual(record, expectedOperation)
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'Conflict',
                'The alternative-independent preprocessing-source state slot is already bound to a different semantic output.',
            );
        }
    }

    #signAuthorization(record: ReservedStateAuthorizationRecord): Uint8Array {
        assertDirectMpcPreprocessingSourceStateSigningCapabilityMatchesRosterKey(
            {
                signingCapability: this.#signingCapability,
                signingVerificationKey: record.signingVerificationKey,
            },
        );
        if (record.role === 'witness') {
            return signDirectMpcPreprocessingSourceStateWitnessBody({
                signatureRandomness: record.signatureRandomness,
                signingCapability: this.#signingCapability,
                signingVerificationKey: record.signingVerificationKey,
                witnessAuthorizationBodyBytes: record.authorizationBodyBytes,
            });
        }
        return signDirectMpcPreprocessingSourceStateSubjectBody({
            signatureRandomness: record.signatureRandomness,
            signingCapability: this.#signingCapability,
            signingVerificationKey: record.signingVerificationKey,
            subjectAuthorizationBodyBytes: record.authorizationBodyBytes,
        });
    }

    #completeAuthorization(
        operation: StateAuthorizationOperation,
        signature: Uint8Array,
    ): Uint8Array {
        try {
            if (operation.role === 'witness') {
                const completed = this.#kernel.completeWitness({
                    authorizationBodyBytes: operation.authorizationBodyBytes,
                    signature,
                    subjectPosition: operation.subjectPosition,
                });
                if (
                    !bytesEqual(
                        completed.stateKeyIdentity,
                        operation.stateKeyIdentity,
                    )
                ) {
                    throw new AuthenticatedRuntimeRecordError(
                        'AuthenticationFailed',
                        'Completed state witness returned the wrong stable key.',
                    );
                }
                return copyBoundedBytes(
                    completed.witnessEnvelopeBytes,
                    this.#limits.maximumWitnessEnvelopeByteLength,
                    'witnessEnvelopeBytes',
                );
            }
            const completed = this.#kernel.completeSubject({
                authorizationBodyBytes: operation.authorizationBodyBytes,
                signature,
                witnessEnvelopeBytes: operation.witnessEnvelopeBytes,
            });
            if (
                !bytesEqual(
                    completed.stateKeyIdentity,
                    operation.stateKeyIdentity,
                )
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Completed state subject returned the wrong stable key.',
                );
            }
            return copyBoundedBytes(
                completed.endorsementCarrierBytes,
                this.#limits.maximumEndorsementCarrierByteLength,
                'endorsementCarrierBytes',
            );
        } catch (error) {
            if (error instanceof AuthenticatedRuntimeRecordError) {
                throw error;
            }
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Preprocessing-source state signature completion failed positive verification.',
                error,
            );
        }
    }

    #validateCompletedAuthorization(
        record: CompletedStateAuthorizationRecord,
    ): void {
        const outputCarrierBytes = this.#completeAuthorization(
            record,
            record.signature,
        );
        try {
            if (!bytesEqual(outputCarrierBytes, record.outputCarrierBytes)) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Retained preprocessing-source state carrier does not match its verified authorization.',
                );
            }
        } finally {
            outputCarrierBytes.fill(0);
        }
    }

    #copyCompletedRecord(
        record: CompletedStateAuthorizationRecord,
    ): CompletedStateAuthorizationRecord {
        return Object.freeze({
            ...copyOperation(record, this.#limits),
            kind: 'completed' as const,
            outputCarrierBytes: record.outputCarrierBytes.slice(),
            signature: record.signature.slice(),
            stateNamespaceIdentity: record.stateNamespaceIdentity.slice(),
        });
    }

    async #readAuthorization(
        recordKey: string,
    ): Promise<OpenedRecord<StateAuthorizationRecord> | undefined> {
        return this.#recencyCoordinator.runRead((store) =>
            readAuthorizationRecord(
                store,
                this.#protection,
                recordKey,
                this.#limits,
            ),
        );
    }

    async #retainTerminal(
        terminalValue: VerifiedDirectMpcPreprocessingSourceStateTerminal,
    ): Promise<RetainedDirectMpcPreprocessingSourceStateTerminal> {
        const terminal = copyTerminal(terminalValue, this.#limits);
        try {
            if (
                !bytesEqual(
                    terminal.stateNamespaceIdentity,
                    this.#stateNamespaceIdentity,
                )
            ) {
                throw new AuthenticatedRuntimeRecordError(
                    'AuthenticationFailed',
                    'Verified preprocessing-source terminal returned the wrong state namespace.',
                );
            }
            const existing = await this.#readTerminal();
            if (existing !== undefined) {
                try {
                    const retained = this.#validateStoredTerminal(
                        existing.record,
                    );
                    if (!terminalsEqual(existing.record, terminal)) {
                        destroyTerminalRecord(retained);
                        throw new AuthenticatedRuntimeRecordError(
                            'Conflict',
                            'The preprocessing-source namespace already retained a different terminal transcript.',
                        );
                    }
                    return retained;
                } finally {
                    destroyTerminalRecord(existing.record);
                    existing.sealedBytes.fill(0);
                }
            }
            const recordKey = terminalRecordKey(this.#stateNamespaceIdentity);
            const plaintext = encodeTerminalRecord(terminal);
            try {
                try {
                    const sealedBytes =
                        await this.#recencyCoordinator.runMutation((store) =>
                            commitPlaintext({
                                expectedCurrentSealedBytes: null,
                                logicalRecordKey: recordKey,
                                operationDomain: terminalRecordOperationDomain,
                                plaintext,
                                protection: this.#protection,
                                store,
                                transactionLifetimeMilliseconds:
                                    this.#limits
                                        .transactionLifetimeMilliseconds,
                            }),
                        );
                    sealedBytes.fill(0);
                    return copyTerminal(terminal, this.#limits);
                } catch (error) {
                    if (!errorHasCode(error, 'Conflict')) {
                        throw error;
                    }
                    const raced = await this.#readTerminal();
                    if (raced === undefined) {
                        throw error;
                    }
                    try {
                        const retained = this.#validateStoredTerminal(
                            raced.record,
                        );
                        if (!terminalsEqual(raced.record, terminal)) {
                            destroyTerminalRecord(retained);
                            throw new AuthenticatedRuntimeRecordError(
                                'Conflict',
                                'The preprocessing-source namespace concurrently retained a different terminal transcript.',
                            );
                        }
                        return retained;
                    } finally {
                        destroyTerminalRecord(raced.record);
                        raced.sealedBytes.fill(0);
                    }
                }
            } finally {
                plaintext.fill(0);
            }
        } finally {
            destroyTerminalRecord(terminal);
        }
    }

    async #readTerminal(): Promise<
        OpenedRecord<StateTerminalRecord> | undefined
    > {
        const recordKey = terminalRecordKey(this.#stateNamespaceIdentity);
        return this.#recencyCoordinator.runRead((store) =>
            readTerminalRecord(
                store,
                this.#protection,
                recordKey,
                this.#limits,
            ),
        );
    }

    #validateStoredTerminal(
        record: StateTerminalRecord,
    ): RetainedDirectMpcPreprocessingSourceStateTerminal {
        if (
            !bytesEqual(
                record.stateNamespaceIdentity,
                this.#stateNamespaceIdentity,
            )
        ) {
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Retained preprocessing-source terminal has the wrong state namespace.',
            );
        }
        let verified: VerifiedDirectMpcPreprocessingSourceStateTerminal;
        try {
            verified = this.#kernel.validateTerminal({
                terminalBytes: record.terminalBytes,
            });
        } catch (error) {
            throw new AuthenticatedRuntimeRecordError(
                errorHasCode(error, 'ConsumedState')
                    ? 'InvalidState'
                    : 'AuthenticationFailed',
                'Retained preprocessing-source terminal failed positive verification.',
                error,
            );
        }
        const retained = copyTerminal(verified, this.#limits);
        if (!terminalsEqual(record, retained)) {
            destroyTerminalRecord(retained);
            throw new AuthenticatedRuntimeRecordError(
                'AuthenticationFailed',
                'Retained preprocessing-source terminal does not match its verified bytes.',
            );
        }
        return retained;
    }
}
