import {
    UntrustedStorageTransactionError,
    type UntrustedStorageTransaction,
    type UntrustedStorageTransactionStore,
} from './untrusted-storage-transaction-store.js';

const hashByteLength = 64;
const participantIdentityByteLength = 64;
const maximumUnsigned64 = (1n << 64n) - 1n;
const maximumSupportedCanonicalCarrierByteLength = 4_194_304;
const maximumSupportedStateCertificateByteLength = 33_554_432;
const maximumSupportedExactOutputByteLength = 33_554_432;
const maximumSupportedSealedExactOutputByteLength = 50_331_648;
const maximumSupportedConflictRetryCount = 32;
const generationReservationIdentifierByteLength = 32;

type DurableNonForkingStateErrorCode =
    | 'AuthenticationFailed'
    | 'BoundsExceeded'
    | 'CertificateResolutionFailed'
    | 'ConflictExhausted'
    | 'CorruptRecord'
    | 'Equivocation'
    | 'ExactOutputUnavailable'
    | 'InvalidConfiguration'
    | 'InvalidInput'
    | 'MissingPrerequisite'
    | 'OutsideSupportedProfile'
    | 'RandomnessUnavailable'
    | 'SigningFailed'
    | 'StorageFailure'
    | 'VerificationFailed';

export class DurableNonForkingStateError extends Error {
    public readonly code: DurableNonForkingStateErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: DurableNonForkingStateErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'DurableNonForkingStateError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

class DurableStateTransactionCleanupError extends Error {
    public readonly cleanupFailure: unknown;
    public readonly originalFailure: unknown;

    public constructor(originalFailure: unknown, cleanupFailure: unknown) {
        super('State mutation and transaction cleanup both failed.');
        this.name = 'DurableStateTransactionCleanupError';
        this.originalFailure = originalFailure;
        this.cleanupFailure = cleanupFailure;
    }
}

export type DurableStateWitnessVoteKind = 'reservation' | 'output' | 'recovery';

type ResolvedStateIntentBase = Readonly<{
    actionContextHash: Uint8Array;
    intentObjectHash: Uint8Array;
    stateKey: Uint8Array;
    subjectEpoch: bigint;
    subjectParticipantIdentity: Uint8Array;
}>;

export type ResolvedDurableStateIntent =
    | (ResolvedStateIntentBase &
          Readonly<{
              voteKind: 'reservation';
          }>)
    | (ResolvedStateIntentBase &
          Readonly<{
              exactOutputHash: Uint8Array;
              reservationIntentObjectHash: Uint8Array;
              voteKind: 'output';
          }>)
    | (ResolvedStateIntentBase &
          Readonly<{
              preservedOutputIntentObjectHash?: Uint8Array;
              preservedReservationIntentObjectHash?: Uint8Array;
              voteKind: 'recovery';
          }>);

export type ResolvedDurableStateWitnessVote = Readonly<{
    actionContextHash: Uint8Array;
    intentObjectHash: Uint8Array;
    producerSequence: bigint;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}>;

export type DurableStateWitnessVoteSigningInput = Readonly<{
    actionContextHash: Uint8Array;
    canonicalIntentCarrier: Uint8Array;
    intentObjectHash: Uint8Array;
    producerSequence: bigint;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    voteKind: DurableStateWitnessVoteKind;
    witnessParticipantIdentity: Uint8Array;
}>;

export type DurableStateCryptography = Readonly<{
    resolveSignedStateWitnessVote(input: {
        canonicalSignedStateWitnessVoteCarrier: Uint8Array;
    }):
        | Promise<ResolvedDurableStateWitnessVote>
        | ResolvedDurableStateWitnessVote;
    resolveStateIntent(input: {
        canonicalIntentCarrier: Uint8Array;
    }): Promise<ResolvedDurableStateIntent> | ResolvedDurableStateIntent;
    signStateWitnessVote(
        input: DurableStateWitnessVoteSigningInput,
    ): Promise<Uint8Array> | Uint8Array;
}>;

export type DurableExactOutputScope = Readonly<{
    reservationIntentObjectHash: Uint8Array;
    stateKey: Uint8Array;
}>;

export type DurableExactOutputRecordContext = Readonly<{
    logicalRecordKey: string;
    reservationIntentObjectHash: Uint8Array;
    stateKey: Uint8Array;
}>;

export type DurableExactOutputInspector = (input: {
    exactOutputBytes: Uint8Array;
    reservationIntentObjectHash: Uint8Array;
    stateKey: Uint8Array;
}) =>
    | Promise<Readonly<{ exactOutputHash: Uint8Array }>>
    | Readonly<{
          exactOutputHash: Uint8Array;
      }>;

type DurableExactOutputSeal = (input: {
    context: DurableExactOutputRecordContext;
    plaintext: Uint8Array;
}) => Promise<Uint8Array> | Uint8Array;

type DurableExactOutputOpen = (input: {
    context: DurableExactOutputRecordContext;
    sealedBytes: Uint8Array;
}) => Promise<Uint8Array> | Uint8Array;

type DurableStateLimits = Readonly<{
    maximumCanonicalCarrierByteLength: number;
    maximumConflictRetryCount: number;
    maximumExactOutputByteLength: number;
    maximumSealedExactOutputByteLength: number;
    maximumStateCertificateByteLength: number;
    transactionLifetimeMilliseconds: number;
}>;

type DurableNonForkingStateServiceConfiguration = Readonly<{
    cryptography: DurableStateCryptography;
    generationReservationCryptoProvider: Pick<Crypto, 'getRandomValues'>;
    limits: DurableStateLimits;
    openExactOutput: DurableExactOutputOpen;
    sealExactOutput: DurableExactOutputSeal;
    store: UntrustedStorageTransactionStore;
    witnessParticipantIdentity: Uint8Array;
}>;

type DurableExactOutput = Readonly<{
    exactOutputBytes: Uint8Array;
    exactOutputHash: Uint8Array;
    reservationIntentObjectHash: Uint8Array;
    stateKey: Uint8Array;
}>;

type DurableStateCertificateResolution<Result> = Readonly<{
    exactOutputBytes?: Uint8Array;
    verifiedCapability: Result;
}>;

type DurableStateCertificateVerifier<Result> = (input: {
    canonicalIntentCarrier: Uint8Array;
    canonicalStateCertificate: Uint8Array;
    exactOutputBytes?: Uint8Array;
}) => Promise<Result> | Result;

type InternalResolvedStateIntent =
    | Readonly<{
          actionContextHash: Uint8Array;
          intentObjectHash: Uint8Array;
          stateKey: Uint8Array;
          subjectEpoch: bigint;
          subjectParticipantIdentity: Uint8Array;
          voteKind: 'reservation';
      }>
    | Readonly<{
          actionContextHash: Uint8Array;
          exactOutputHash: Uint8Array;
          intentObjectHash: Uint8Array;
          reservationIntentObjectHash: Uint8Array;
          stateKey: Uint8Array;
          subjectEpoch: bigint;
          subjectParticipantIdentity: Uint8Array;
          voteKind: 'output';
      }>
    | Readonly<{
          actionContextHash: Uint8Array;
          intentObjectHash: Uint8Array;
          preservedOutputIntentObjectHash: Uint8Array | undefined;
          preservedReservationIntentObjectHash: Uint8Array | undefined;
          stateKey: Uint8Array;
          subjectEpoch: bigint;
          subjectParticipantIdentity: Uint8Array;
          voteKind: 'recovery';
      }>;

type InternalResolvedStateWitnessVote = Readonly<{
    actionContextHash: Uint8Array;
    intentObjectHash: Uint8Array;
    producerSequence: bigint;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}>;

type AuthenticatedIntentRecord = Readonly<{
    bytes: Uint8Array;
    intent: InternalResolvedStateIntent;
}>;

type StateLockSnapshot = Readonly<{
    output: AuthenticatedIntentRecord | undefined;
    reservation: AuthenticatedIntentRecord | undefined;
}>;

type WitnessLockSnapshot = StateLockSnapshot &
    Readonly<{
        voteIntent: AuthenticatedIntentRecord;
        voteIntentLogicalRecordKey: string;
    }>;

type ExactOutputInspection = Readonly<{
    exactOutputBytes: Uint8Array;
    exactOutputHash: Uint8Array;
}>;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }

    return true;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const assertSafePositiveInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            `${label} must be a positive safe integer.`,
        );
    }
};

const assertLimits = (limits: DurableStateLimits): void => {
    assertSafePositiveInteger(
        limits.maximumCanonicalCarrierByteLength,
        'maximumCanonicalCarrierByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumConflictRetryCount,
        'maximumConflictRetryCount',
    );
    assertSafePositiveInteger(
        limits.maximumExactOutputByteLength,
        'maximumExactOutputByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumSealedExactOutputByteLength,
        'maximumSealedExactOutputByteLength',
    );
    assertSafePositiveInteger(
        limits.maximumStateCertificateByteLength,
        'maximumStateCertificateByteLength',
    );
    assertSafePositiveInteger(
        limits.transactionLifetimeMilliseconds,
        'transactionLifetimeMilliseconds',
    );
    if (
        limits.maximumCanonicalCarrierByteLength >
        maximumSupportedCanonicalCarrierByteLength
    ) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            `maximumCanonicalCarrierByteLength must not exceed ${maximumSupportedCanonicalCarrierByteLength}.`,
        );
    }
    if (
        limits.maximumStateCertificateByteLength >
        maximumSupportedStateCertificateByteLength
    ) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            `maximumStateCertificateByteLength must not exceed ${maximumSupportedStateCertificateByteLength}.`,
        );
    }
    if (
        limits.maximumExactOutputByteLength >
        maximumSupportedExactOutputByteLength
    ) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            `maximumExactOutputByteLength must not exceed ${maximumSupportedExactOutputByteLength}.`,
        );
    }
    if (
        limits.maximumSealedExactOutputByteLength >
        maximumSupportedSealedExactOutputByteLength
    ) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            `maximumSealedExactOutputByteLength must not exceed ${maximumSupportedSealedExactOutputByteLength}.`,
        );
    }
    if (
        limits.maximumSealedExactOutputByteLength <
        limits.maximumExactOutputByteLength
    ) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            'maximumSealedExactOutputByteLength must contain the largest exact output.',
        );
    }
    if (limits.maximumConflictRetryCount > maximumSupportedConflictRetryCount) {
        throw new DurableNonForkingStateError(
            'InvalidConfiguration',
            `maximumConflictRetryCount must not exceed ${maximumSupportedConflictRetryCount}.`,
        );
    }
};

const copyFixedBytes = (
    bytes: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array => {
    if (
        !(bytes instanceof Uint8Array) ||
        bytes.byteLength !== expectedByteLength
    ) {
        throw new DurableNonForkingStateError(
            'InvalidInput',
            `${label} must contain exactly ${expectedByteLength} bytes.`,
        );
    }

    return bytes.slice();
};

const copyBoundedBytes = (
    bytes: Uint8Array,
    maximumByteLength: number,
    label: string,
    allowEmpty = false,
): Uint8Array => {
    if (
        !(bytes instanceof Uint8Array) ||
        (!allowEmpty && bytes.byteLength === 0) ||
        bytes.byteLength > maximumByteLength
    ) {
        throw new DurableNonForkingStateError(
            'BoundsExceeded',
            `${label} is empty or exceeds its configured byte bound.`,
        );
    }

    return bytes.slice();
};

const copyUnsigned64 = (value: bigint, label: string): bigint => {
    if (typeof value !== 'bigint' || value < 0n || value > maximumUnsigned64) {
        throw new DurableNonForkingStateError(
            'OutsideSupportedProfile',
            `${label} must fit canonical u64.`,
        );
    }

    return value;
};

export const deriveStateWitnessVoteProducerSequence = (
    voteKind: DurableStateWitnessVoteKind,
    subjectEpoch: bigint,
): bigint => {
    const epoch = copyUnsigned64(subjectEpoch, 'subjectEpoch');
    if (voteKind === 'recovery' && epoch === 0n) {
        throw new DurableNonForkingStateError(
            'InvalidInput',
            'a recovery vote must propose a positive subject epoch.',
        );
    }
    if (
        voteKind !== 'reservation' &&
        voteKind !== 'output' &&
        voteKind !== 'recovery'
    ) {
        throw new DurableNonForkingStateError(
            'InvalidInput',
            'state witness vote kind is unsupported.',
        );
    }
    const multipliedEpoch = epoch * 3n;
    const sequence =
        voteKind === 'reservation'
            ? multipliedEpoch + 1n
            : voteKind === 'output'
              ? multipliedEpoch + 2n
              : multipliedEpoch;
    if (sequence > maximumUnsigned64) {
        throw new DurableNonForkingStateError(
            'OutsideSupportedProfile',
            'state witness vote producer sequence overflows canonical u64.',
        );
    }

    return sequence;
};

export const deriveStateRecoveryProducerSequence = (
    oldRecoveryEpoch: bigint,
): bigint => {
    const epoch = copyUnsigned64(oldRecoveryEpoch, 'oldRecoveryEpoch');
    if (epoch === maximumUnsigned64) {
        throw new DurableNonForkingStateError(
            'OutsideSupportedProfile',
            'state recovery producer sequence overflows canonical u64.',
        );
    }

    return epoch + 1n;
};

const copyIntent = (
    value: ResolvedDurableStateIntent,
): InternalResolvedStateIntent => {
    if (value === null || typeof value !== 'object') {
        throw new DurableNonForkingStateError(
            'VerificationFailed',
            'state intent resolver returned no binding.',
        );
    }
    const base = {
        actionContextHash: copyFixedBytes(
            value.actionContextHash,
            hashByteLength,
            'resolved actionContextHash',
        ),
        intentObjectHash: copyFixedBytes(
            value.intentObjectHash,
            hashByteLength,
            'resolved intentObjectHash',
        ),
        stateKey: copyFixedBytes(
            value.stateKey,
            hashByteLength,
            'resolved stateKey',
        ),
        subjectEpoch: copyUnsigned64(
            value.subjectEpoch,
            'resolved subjectEpoch',
        ),
        subjectParticipantIdentity: copyFixedBytes(
            value.subjectParticipantIdentity,
            participantIdentityByteLength,
            'resolved subjectParticipantIdentity',
        ),
    };
    if (value.voteKind === 'reservation') {
        return { ...base, voteKind: 'reservation' };
    }
    if (value.voteKind === 'output') {
        return {
            ...base,
            exactOutputHash: copyFixedBytes(
                value.exactOutputHash,
                hashByteLength,
                'resolved exactOutputHash',
            ),
            reservationIntentObjectHash: copyFixedBytes(
                value.reservationIntentObjectHash,
                hashByteLength,
                'resolved reservationIntentObjectHash',
            ),
            voteKind: 'output',
        };
    }
    if (value.voteKind === 'recovery') {
        const preservedReservationIntentObjectHash =
            value.preservedReservationIntentObjectHash === undefined
                ? undefined
                : copyFixedBytes(
                      value.preservedReservationIntentObjectHash,
                      hashByteLength,
                      'resolved preservedReservationIntentObjectHash',
                  );
        const preservedOutputIntentObjectHash =
            value.preservedOutputIntentObjectHash === undefined
                ? undefined
                : copyFixedBytes(
                      value.preservedOutputIntentObjectHash,
                      hashByteLength,
                      'resolved preservedOutputIntentObjectHash',
                  );
        if (
            preservedOutputIntentObjectHash !== undefined &&
            preservedReservationIntentObjectHash === undefined
        ) {
            throw new DurableNonForkingStateError(
                'MissingPrerequisite',
                'a preserved output intent requires its reservation intent.',
            );
        }

        return {
            ...base,
            preservedOutputIntentObjectHash,
            preservedReservationIntentObjectHash,
            voteKind: 'recovery',
        };
    }
    throw new DurableNonForkingStateError(
        'VerificationFailed',
        'state intent resolver returned an unsupported vote kind.',
    );
};

const copyResolvedVote = (
    value: ResolvedDurableStateWitnessVote,
): InternalResolvedStateWitnessVote => {
    if (value === null || typeof value !== 'object') {
        throw new DurableNonForkingStateError(
            'VerificationFailed',
            'state witness vote resolver returned no binding.',
        );
    }

    return {
        actionContextHash: copyFixedBytes(
            value.actionContextHash,
            hashByteLength,
            'resolved vote actionContextHash',
        ),
        intentObjectHash: copyFixedBytes(
            value.intentObjectHash,
            hashByteLength,
            'resolved vote intentObjectHash',
        ),
        producerSequence: copyUnsigned64(
            value.producerSequence,
            'resolved vote producerSequence',
        ),
        stateKey: copyFixedBytes(
            value.stateKey,
            hashByteLength,
            'resolved vote stateKey',
        ),
        subjectParticipantIdentity: copyFixedBytes(
            value.subjectParticipantIdentity,
            participantIdentityByteLength,
            'resolved vote subjectParticipantIdentity',
        ),
        witnessParticipantIdentity: copyFixedBytes(
            value.witnessParticipantIdentity,
            participantIdentityByteLength,
            'resolved vote witnessParticipantIdentity',
        ),
    };
};

const copyExactOutputScope = (
    scope: DurableExactOutputScope,
): DurableExactOutputScope => ({
    reservationIntentObjectHash: copyFixedBytes(
        scope.reservationIntentObjectHash,
        hashByteLength,
        'reservationIntentObjectHash',
    ),
    stateKey: copyFixedBytes(scope.stateKey, hashByteLength, 'stateKey'),
});

const reservationLockLogicalRecordKey = (stateKey: Uint8Array): string =>
    `non-forking-state/locks/${bytesToHex(stateKey)}/reservation`;

const outputLockLogicalRecordKey = (stateKey: Uint8Array): string =>
    `non-forking-state/locks/${bytesToHex(stateKey)}/output`;

const witnessVoteLogicalRecordKey = (input: {
    actionContextHash: Uint8Array;
    producerSequence: bigint;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}): string =>
    `non-forking-state/votes/${bytesToHex(
        input.actionContextHash,
    )}/${bytesToHex(input.witnessParticipantIdentity)}/${bytesToHex(
        input.subjectParticipantIdentity,
    )}/${bytesToHex(input.stateKey)}/${input.producerSequence
        .toString(16)
        .padStart(16, '0')}`;

const witnessVoteIntentLogicalRecordKey = (input: {
    actionContextHash: Uint8Array;
    producerSequence: bigint;
    stateKey: Uint8Array;
    subjectParticipantIdentity: Uint8Array;
    witnessParticipantIdentity: Uint8Array;
}): string =>
    witnessVoteLogicalRecordKey(input).replace(
        'non-forking-state/votes/',
        'non-forking-state/vote-intents/',
    );

const exactOutputLogicalRecordKey = (scope: DurableExactOutputScope): string =>
    `non-forking-state/exact-outputs/${bytesToHex(
        scope.stateKey,
    )}/${bytesToHex(scope.reservationIntentObjectHash)}`;

const exactOutputGenerationReservationLogicalRecordKey = (
    scope: DurableExactOutputScope,
): string => `${exactOutputLogicalRecordKey(scope)}/generation-reservation`;

const createOpaqueGenerationReservationIdentifier = (
    cryptoProvider: Pick<Crypto, 'getRandomValues'>,
): Uint8Array => {
    const identifier = new Uint8Array(
        generationReservationIdentifierByteLength,
    );
    try {
        const returnedIdentifier = cryptoProvider.getRandomValues(identifier);
        if (
            returnedIdentifier !== identifier ||
            !identifier.some((byte) => byte !== 0)
        ) {
            throw new Error(
                'generation reservation entropy was not fresh nonzero bytes',
            );
        }
    } catch (error) {
        identifier.fill(0);
        throw new DurableNonForkingStateError(
            'RandomnessUnavailable',
            'fresh Web Crypto randomness is required for an exact-output generation reservation.',
            error,
        );
    }

    return identifier;
};

const isRetryableStorageContention = (error: unknown): boolean =>
    error instanceof UntrustedStorageTransactionError &&
    (error.code === 'Conflict' || error.code === 'Expired');

const normalizeStorageFailure = (error: unknown): never => {
    if (
        error instanceof UntrustedStorageTransactionError &&
        error.code === 'AuthenticationFailed' &&
        error.failureCause instanceof DurableNonForkingStateError
    ) {
        throw error.failureCause;
    }
    if (error instanceof DurableNonForkingStateError) {
        throw error;
    }
    throw new DurableNonForkingStateError(
        'StorageFailure',
        'durable non-forking state storage failed.',
        error,
    );
};

const abortBeforeCommit = async (
    transaction: UntrustedStorageTransaction,
    commitMayHaveSucceeded: boolean,
    originalFailure: unknown,
): Promise<never> => {
    if (commitMayHaveSucceeded) {
        throw originalFailure;
    }
    try {
        await transaction.abort();
    } catch (cleanupFailure) {
        throw new DurableNonForkingStateError(
            'StorageFailure',
            'Durable state mutation failed and its uncommitted storage transaction could not be aborted.',
            new DurableStateTransactionCleanupError(
                originalFailure,
                cleanupFailure,
            ),
        );
    }
    throw originalFailure;
};

export class DurableNonForkingStateService {
    readonly #cryptography: DurableStateCryptography;
    readonly #generationReservationCryptoProvider: Pick<
        Crypto,
        'getRandomValues'
    >;
    readonly #limits: DurableStateLimits;
    readonly #openExactOutput: DurableExactOutputOpen;
    readonly #sealExactOutput: DurableExactOutputSeal;
    readonly #store: UntrustedStorageTransactionStore;
    readonly #witnessParticipantIdentity: Uint8Array;

    public constructor(
        configuration: DurableNonForkingStateServiceConfiguration,
    ) {
        assertLimits(configuration.limits);
        if (
            configuration.generationReservationCryptoProvider === null ||
            typeof configuration.generationReservationCryptoProvider !==
                'object' ||
            typeof configuration.generationReservationCryptoProvider
                .getRandomValues !== 'function'
        ) {
            throw new DurableNonForkingStateError(
                'InvalidConfiguration',
                'generationReservationCryptoProvider must provide Web Crypto getRandomValues.',
            );
        }
        this.#cryptography = configuration.cryptography;
        this.#generationReservationCryptoProvider =
            configuration.generationReservationCryptoProvider;
        this.#limits = { ...configuration.limits };
        this.#openExactOutput = configuration.openExactOutput;
        this.#sealExactOutput = configuration.sealExactOutput;
        this.#store = configuration.store;
        this.#witnessParticipantIdentity = copyFixedBytes(
            configuration.witnessParticipantIdentity,
            participantIdentityByteLength,
            'witnessParticipantIdentity',
        );
    }

    public async obtainSignedWitnessVote(input: {
        canonicalIntentCarrier: Uint8Array;
        canonicalPreservedOutputIntentCarrier?: Uint8Array;
        canonicalPreservedReservationIntentCarrier?: Uint8Array;
    }): Promise<Uint8Array> {
        const canonicalIntentCarrier = copyBoundedBytes(
            input.canonicalIntentCarrier,
            this.#limits.maximumCanonicalCarrierByteLength,
            'canonicalIntentCarrier',
        );
        const intent = await this.#resolveIntent(canonicalIntentCarrier);
        if (
            bytesEqual(
                intent.subjectParticipantIdentity,
                this.#witnessParticipantIdentity,
            )
        ) {
            throw new DurableNonForkingStateError(
                'InvalidInput',
                'a state subject cannot witness its own intent.',
            );
        }
        const producerSequence = deriveStateWitnessVoteProducerSequence(
            intent.voteKind,
            intent.subjectEpoch,
        );
        const preservedRecords = await this.#resolvePreservedRecords({
            canonicalPreservedOutputIntentCarrier:
                input.canonicalPreservedOutputIntentCarrier,
            canonicalPreservedReservationIntentCarrier:
                input.canonicalPreservedReservationIntentCarrier,
            intent,
        });
        const expectedVote: InternalResolvedStateWitnessVote = {
            actionContextHash: intent.actionContextHash.slice(),
            intentObjectHash: intent.intentObjectHash.slice(),
            producerSequence,
            stateKey: intent.stateKey.slice(),
            subjectParticipantIdentity:
                intent.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                this.#witnessParticipantIdentity.slice(),
        };
        const voteLogicalRecordKey = witnessVoteLogicalRecordKey(expectedVote);
        const voteIntentLogicalRecordKey =
            witnessVoteIntentLogicalRecordKey(expectedVote);

        return this.#withConflictRetries(async () => {
            const existingVote = await this.#readWitnessVoteRecord(
                voteLogicalRecordKey,
                expectedVote,
            );
            if (existingVote !== undefined) {
                await this.#readCommittedWitnessLock({
                    intent,
                    voteIntentLogicalRecordKey,
                });
                return existingVote;
            }

            const lockSnapshot = await this.#compareAndLockIntent({
                canonicalIntentCarrier,
                intent,
                preservedOutput: preservedRecords.output,
                preservedReservation: preservedRecords.reservation,
                voteIntentLogicalRecordKey,
            });

            const cachedAfterLock = await this.#readWitnessVoteRecord(
                voteLogicalRecordKey,
                expectedVote,
            );
            if (cachedAfterLock !== undefined) {
                await this.#readCommittedWitnessLock({
                    intent,
                    voteIntentLogicalRecordKey,
                });
                return cachedAfterLock;
            }

            let candidateCarrier: Uint8Array;
            try {
                candidateCarrier = copyBoundedBytes(
                    await this.#cryptography.signStateWitnessVote({
                        actionContextHash: intent.actionContextHash.slice(),
                        canonicalIntentCarrier: canonicalIntentCarrier.slice(),
                        intentObjectHash: intent.intentObjectHash.slice(),
                        producerSequence,
                        stateKey: intent.stateKey.slice(),
                        subjectParticipantIdentity:
                            intent.subjectParticipantIdentity.slice(),
                        voteKind: intent.voteKind,
                        witnessParticipantIdentity:
                            this.#witnessParticipantIdentity.slice(),
                    }),
                    this.#limits.maximumCanonicalCarrierByteLength,
                    'signed state witness vote carrier',
                );
            } catch (error) {
                if (error instanceof DurableNonForkingStateError) {
                    throw error;
                }
                throw new DurableNonForkingStateError(
                    'SigningFailed',
                    'state witness vote signing failed after the durable lock.',
                    error,
                );
            }
            await this.#authenticateWitnessVoteBytes(
                candidateCarrier,
                expectedVote,
            );
            await this.#commitWitnessVoteCache({
                candidateCarrier,
                expectedVote,
                lockSnapshot,
                voteLogicalRecordKey,
            });
            const committedCarrier = await this.#readWitnessVoteRecord(
                voteLogicalRecordKey,
                expectedVote,
            );
            if (committedCarrier === undefined) {
                throw new DurableNonForkingStateError(
                    'CorruptRecord',
                    'committed state witness vote cache is missing.',
                );
            }

            return committedCarrier;
        });
    }

    public async obtainExactOutput(input: {
        createExactOutput(): Promise<Uint8Array> | Uint8Array;
        inspectExactOutput: DurableExactOutputInspector;
        scope: DurableExactOutputScope;
    }): Promise<DurableExactOutput> {
        const scope = copyExactOutputScope(input.scope);
        const logicalRecordKey = exactOutputLogicalRecordKey(scope);
        let generationReservationIdentifier: Uint8Array | undefined;
        let createdExactOutput: Uint8Array | undefined;

        try {
            return await this.#withConflictRetries(async () => {
                const existing = await this.#readExactOutputRecord({
                    inspectExactOutput: input.inspectExactOutput,
                    logicalRecordKey,
                    scope,
                });
                if (existing !== undefined) {
                    return {
                        exactOutputBytes: existing.exactOutputBytes.slice(),
                        exactOutputHash: existing.exactOutputHash.slice(),
                        reservationIntentObjectHash:
                            scope.reservationIntentObjectHash.slice(),
                        stateKey: scope.stateKey.slice(),
                    };
                }
                generationReservationIdentifier ??=
                    createOpaqueGenerationReservationIdentifier(
                        this.#generationReservationCryptoProvider,
                    );
                await this.#claimExactOutputGenerationReservation({
                    generationReservationIdentifier,
                    scope,
                });
                createdExactOutput ??= copyBoundedBytes(
                    await input.createExactOutput(),
                    this.#limits.maximumExactOutputByteLength,
                    'exact output',
                );
                const inspected = await this.#inspectExactOutput({
                    exactOutputBytes: createdExactOutput,
                    inspectExactOutput: input.inspectExactOutput,
                    scope,
                });
                const sealedBytes = await this.#sealAndReopenExactOutput({
                    exactOutputBytes: inspected.exactOutputBytes,
                    inspectExactOutput: input.inspectExactOutput,
                    logicalRecordKey,
                    scope,
                });
                await this.#writeExactOutputRecord({
                    inspectExactOutput: input.inspectExactOutput,
                    logicalRecordKey,
                    scope,
                    sealedBytes,
                });
                const committed = await this.#readExactOutputRecord({
                    inspectExactOutput: input.inspectExactOutput,
                    logicalRecordKey,
                    scope,
                });
                if (committed === undefined) {
                    throw new DurableNonForkingStateError(
                        'CorruptRecord',
                        'committed exact output cache is missing.',
                    );
                }

                return {
                    exactOutputBytes: committed.exactOutputBytes.slice(),
                    exactOutputHash: committed.exactOutputHash.slice(),
                    reservationIntentObjectHash:
                        scope.reservationIntentObjectHash.slice(),
                    stateKey: scope.stateKey.slice(),
                };
            });
        } finally {
            generationReservationIdentifier?.fill(0);
        }
    }

    public async resolveStateCertificate<Result>(input: {
        canonicalIntentCarrier: Uint8Array;
        canonicalStateCertificate: Uint8Array;
        exactOutput?: Readonly<{
            inspectExactOutput: DurableExactOutputInspector;
            scope: DurableExactOutputScope;
        }>;
        verifyCertificate: DurableStateCertificateVerifier<Result>;
    }): Promise<DurableStateCertificateResolution<Result>> {
        const canonicalIntentCarrier = copyBoundedBytes(
            input.canonicalIntentCarrier,
            this.#limits.maximumCanonicalCarrierByteLength,
            'canonicalIntentCarrier',
        );
        const canonicalStateCertificate = copyBoundedBytes(
            input.canonicalStateCertificate,
            this.#limits.maximumStateCertificateByteLength,
            'canonicalStateCertificate',
        );
        const intent = await this.#resolveIntent(canonicalIntentCarrier);
        let exactOutputBytes: Uint8Array | undefined;
        if (intent.voteKind === 'output') {
            if (input.exactOutput === undefined) {
                throw new DurableNonForkingStateError(
                    'ExactOutputUnavailable',
                    'output certificate resolution requires the durable exact output cache.',
                );
            }
            const scope = copyExactOutputScope(input.exactOutput.scope);
            if (
                !bytesEqual(scope.stateKey, intent.stateKey) ||
                !bytesEqual(
                    scope.reservationIntentObjectHash,
                    intent.reservationIntentObjectHash,
                )
            ) {
                throw new DurableNonForkingStateError(
                    'InvalidInput',
                    'exact output scope does not match the resolved output intent.',
                );
            }
            const cachedOutput = await this.#withConflictRetries(() =>
                this.#readExactOutputRecord({
                    inspectExactOutput: input.exactOutput!.inspectExactOutput,
                    logicalRecordKey: exactOutputLogicalRecordKey(scope),
                    scope,
                }),
            );
            if (cachedOutput === undefined) {
                throw new DurableNonForkingStateError(
                    'ExactOutputUnavailable',
                    'the output intent names exact bytes that are not durably cached.',
                );
            }
            if (
                !bytesEqual(
                    cachedOutput.exactOutputHash,
                    intent.exactOutputHash,
                )
            ) {
                throw new DurableNonForkingStateError(
                    'Equivocation',
                    'the durable exact output does not match the output intent.',
                );
            }
            exactOutputBytes = cachedOutput.exactOutputBytes.slice();
        } else if (input.exactOutput !== undefined) {
            throw new DurableNonForkingStateError(
                'InvalidInput',
                'only output certificate resolution accepts an exact output cache.',
            );
        }

        let verifiedCapability: Result;
        try {
            verifiedCapability = await input.verifyCertificate({
                canonicalIntentCarrier: canonicalIntentCarrier.slice(),
                canonicalStateCertificate: canonicalStateCertificate.slice(),
                ...(exactOutputBytes === undefined
                    ? {}
                    : { exactOutputBytes: exactOutputBytes.slice() }),
            });
        } catch (error) {
            throw new DurableNonForkingStateError(
                'CertificateResolutionFailed',
                'state certificate did not resolve to a verified capability.',
                error,
            );
        }

        return {
            ...(exactOutputBytes === undefined
                ? {}
                : { exactOutputBytes: exactOutputBytes.slice() }),
            verifiedCapability,
        };
    }

    async #withConflictRetries<Result>(
        operation: () => Promise<Result>,
    ): Promise<Result> {
        let latestContention: unknown;
        for (
            let attemptNumber = 0;
            attemptNumber <= this.#limits.maximumConflictRetryCount;
            attemptNumber += 1
        ) {
            try {
                return await operation();
            } catch (error) {
                if (!isRetryableStorageContention(error)) {
                    normalizeStorageFailure(error);
                }
                latestContention = error;
            }
        }
        throw new DurableNonForkingStateError(
            'ConflictExhausted',
            'durable state remained contended throughout every bounded compare-and-lock retry.',
            latestContention,
        );
    }

    async #resolveIntent(
        canonicalIntentCarrier: Uint8Array,
    ): Promise<InternalResolvedStateIntent> {
        try {
            return copyIntent(
                await this.#cryptography.resolveStateIntent({
                    canonicalIntentCarrier: canonicalIntentCarrier.slice(),
                }),
            );
        } catch (error) {
            if (error instanceof DurableNonForkingStateError) {
                throw error;
            }
            throw new DurableNonForkingStateError(
                'VerificationFailed',
                'canonical state intent verification failed.',
                error,
            );
        }
    }

    async #resolvePreservedRecords(input: {
        canonicalPreservedOutputIntentCarrier: Uint8Array | undefined;
        canonicalPreservedReservationIntentCarrier: Uint8Array | undefined;
        intent: InternalResolvedStateIntent;
    }): Promise<{
        output: AuthenticatedIntentRecord | undefined;
        reservation: AuthenticatedIntentRecord | undefined;
    }> {
        if (input.intent.voteKind !== 'recovery') {
            if (
                input.canonicalPreservedOutputIntentCarrier !== undefined ||
                input.canonicalPreservedReservationIntentCarrier !== undefined
            ) {
                throw new DurableNonForkingStateError(
                    'InvalidInput',
                    'only recovery intents accept preserved intent carriers.',
                );
            }

            return { output: undefined, reservation: undefined };
        }
        const reservation =
            input.canonicalPreservedReservationIntentCarrier === undefined
                ? undefined
                : await this.#resolvedInputRecord(
                      input.canonicalPreservedReservationIntentCarrier,
                      'reservation',
                      input.intent.stateKey,
                  );
        const output =
            input.canonicalPreservedOutputIntentCarrier === undefined
                ? undefined
                : await this.#resolvedInputRecord(
                      input.canonicalPreservedOutputIntentCarrier,
                      'output',
                      input.intent.stateKey,
                  );
        if (
            (input.intent.preservedReservationIntentObjectHash ===
                undefined) !==
                (reservation === undefined) ||
            (input.intent.preservedOutputIntentObjectHash === undefined) !==
                (output === undefined)
        ) {
            throw new DurableNonForkingStateError(
                'MissingPrerequisite',
                'recovery preserved intent carriers do not match its resolved preservation.',
            );
        }
        if (
            reservation !== undefined &&
            !bytesEqual(
                reservation.intent.intentObjectHash,
                input.intent.preservedReservationIntentObjectHash!,
            )
        ) {
            throw new DurableNonForkingStateError(
                'Equivocation',
                'recovery reservation preservation resolves to another intent.',
            );
        }
        if (
            output !== undefined &&
            (!bytesEqual(
                output.intent.intentObjectHash,
                input.intent.preservedOutputIntentObjectHash!,
            ) ||
                output.intent.voteKind !== 'output' ||
                reservation === undefined ||
                !bytesEqual(
                    output.intent.reservationIntentObjectHash,
                    reservation.intent.intentObjectHash,
                ))
        ) {
            throw new DurableNonForkingStateError(
                'Equivocation',
                'recovery output preservation does not transitively preserve its reservation.',
            );
        }

        return { output, reservation };
    }

    async #resolvedInputRecord(
        carrier: Uint8Array,
        expectedKind: 'reservation' | 'output',
        expectedStateKey: Uint8Array,
    ): Promise<AuthenticatedIntentRecord> {
        const bytes = copyBoundedBytes(
            carrier,
            this.#limits.maximumCanonicalCarrierByteLength,
            'preserved canonical intent carrier',
        );
        const intent = await this.#resolveIntent(bytes);
        if (
            intent.voteKind !== expectedKind ||
            !bytesEqual(intent.stateKey, expectedStateKey)
        ) {
            throw new DurableNonForkingStateError(
                'VerificationFailed',
                'preserved intent carrier has the wrong kind or state key.',
            );
        }

        return { bytes, intent };
    }

    async #compareAndLockIntent(input: {
        canonicalIntentCarrier: Uint8Array;
        intent: InternalResolvedStateIntent;
        preservedOutput: AuthenticatedIntentRecord | undefined;
        preservedReservation: AuthenticatedIntentRecord | undefined;
        voteIntentLogicalRecordKey: string;
    }): Promise<WitnessLockSnapshot> {
        const stateSnapshot = await this.#readWitnessLock(
            input.intent.stateKey,
        );
        const existingVoteIntent = await this.#readIntentRecord(
            input.voteIntentLogicalRecordKey,
            input.intent.voteKind,
            input.intent.stateKey,
        );
        if (
            existingVoteIntent !== undefined &&
            !bytesEqual(
                existingVoteIntent.intent.intentObjectHash,
                input.intent.intentObjectHash,
            )
        ) {
            throw new DurableNonForkingStateError(
                'Equivocation',
                'state witness producer slot is already locked to another intent.',
            );
        }
        const voteIntent: AuthenticatedIntentRecord = existingVoteIntent ?? {
            bytes: input.canonicalIntentCarrier.slice(),
            intent: input.intent,
        };
        const writes = new Map<string, AuthenticatedIntentRecord>();
        if (existingVoteIntent === undefined) {
            writes.set(input.voteIntentLogicalRecordKey, voteIntent);
        }
        if (input.intent.voteKind === 'reservation') {
            if (stateSnapshot.reservation !== undefined) {
                if (
                    !bytesEqual(
                        stateSnapshot.reservation.intent.intentObjectHash,
                        input.intent.intentObjectHash,
                    )
                ) {
                    throw new DurableNonForkingStateError(
                        'Equivocation',
                        'state reservation slot is already locked to another intent.',
                    );
                }
            } else if (stateSnapshot.output !== undefined) {
                throw new DurableNonForkingStateError(
                    'CorruptRecord',
                    'state output lock exists without a reservation lock.',
                );
            } else {
                writes.set(
                    reservationLockLogicalRecordKey(input.intent.stateKey),
                    {
                        bytes: input.canonicalIntentCarrier.slice(),
                        intent: input.intent,
                    },
                );
            }
        } else if (input.intent.voteKind === 'output') {
            if (stateSnapshot.reservation === undefined) {
                throw new DurableNonForkingStateError(
                    'MissingPrerequisite',
                    'state output locking requires its durable reservation lock.',
                );
            }
            if (
                !bytesEqual(
                    stateSnapshot.reservation.intent.intentObjectHash,
                    input.intent.reservationIntentObjectHash,
                )
            ) {
                throw new DurableNonForkingStateError(
                    'Equivocation',
                    'state output references another reservation lock.',
                );
            }
            if (stateSnapshot.output !== undefined) {
                if (
                    !bytesEqual(
                        stateSnapshot.output.intent.intentObjectHash,
                        input.intent.intentObjectHash,
                    )
                ) {
                    throw new DurableNonForkingStateError(
                        'Equivocation',
                        'state output slot is already locked to another intent.',
                    );
                }
            } else {
                writes.set(
                    reservationLockLogicalRecordKey(input.intent.stateKey),
                    stateSnapshot.reservation,
                );
                writes.set(outputLockLogicalRecordKey(input.intent.stateKey), {
                    bytes: input.canonicalIntentCarrier.slice(),
                    intent: input.intent,
                });
            }
        } else {
            const expectedReservationHash =
                input.intent.preservedReservationIntentObjectHash;
            const expectedOutputHash =
                input.intent.preservedOutputIntentObjectHash;
            if (
                stateSnapshot.reservation !== undefined &&
                (expectedReservationHash === undefined ||
                    !bytesEqual(
                        stateSnapshot.reservation.intent.intentObjectHash,
                        expectedReservationHash,
                    ))
            ) {
                throw new DurableNonForkingStateError(
                    'Equivocation',
                    'state recovery does not preserve the durable reservation lock.',
                );
            }
            if (
                stateSnapshot.output !== undefined &&
                (expectedOutputHash === undefined ||
                    !bytesEqual(
                        stateSnapshot.output.intent.intentObjectHash,
                        expectedOutputHash,
                    ))
            ) {
                throw new DurableNonForkingStateError(
                    'Equivocation',
                    'state recovery does not preserve the durable output lock.',
                );
            }
            const reservation =
                stateSnapshot.reservation ?? input.preservedReservation;
            const output = stateSnapshot.output ?? input.preservedOutput;
            if (
                (expectedReservationHash === undefined) !==
                    (reservation === undefined) ||
                (expectedOutputHash === undefined) !== (output === undefined)
            ) {
                throw new DurableNonForkingStateError(
                    'MissingPrerequisite',
                    'state recovery cannot durably materialize its preserved locks.',
                );
            }
            if (reservation !== undefined) {
                writes.set(
                    reservationLockLogicalRecordKey(input.intent.stateKey),
                    reservation,
                );
            }
            if (output !== undefined) {
                writes.set(
                    outputLockLogicalRecordKey(input.intent.stateKey),
                    output,
                );
            }
        }

        if (writes.size !== 0) {
            await this.#writeIntentRecords(writes);
        }

        const committedStateSnapshot = await this.#readWitnessLock(
            input.intent.stateKey,
        );
        const committedVoteIntent = await this.#readIntentRecord(
            input.voteIntentLogicalRecordKey,
            input.intent.voteKind,
            input.intent.stateKey,
        );
        if (
            committedVoteIntent === undefined ||
            !bytesEqual(
                committedVoteIntent.intent.intentObjectHash,
                input.intent.intentObjectHash,
            )
        ) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'durable state witness producer lock is missing or changed.',
            );
        }

        return {
            ...committedStateSnapshot,
            voteIntent: committedVoteIntent,
            voteIntentLogicalRecordKey: input.voteIntentLogicalRecordKey,
        };
    }

    async #readCommittedWitnessLock(input: {
        intent: InternalResolvedStateIntent;
        voteIntentLogicalRecordKey: string;
    }): Promise<WitnessLockSnapshot> {
        const stateSnapshot = await this.#readWitnessLock(
            input.intent.stateKey,
        );
        const voteIntent = await this.#readIntentRecord(
            input.voteIntentLogicalRecordKey,
            input.intent.voteKind,
            input.intent.stateKey,
        );
        if (
            voteIntent === undefined ||
            !bytesEqual(
                voteIntent.intent.intentObjectHash,
                input.intent.intentObjectHash,
            )
        ) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'cached state witness vote has no matching durable producer lock.',
            );
        }
        if (
            input.intent.voteKind === 'reservation' &&
            (stateSnapshot.reservation === undefined ||
                !bytesEqual(
                    stateSnapshot.reservation.intent.intentObjectHash,
                    input.intent.intentObjectHash,
                ))
        ) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'cached reservation vote has no matching durable reservation lock.',
            );
        }
        if (
            input.intent.voteKind === 'output' &&
            (stateSnapshot.output === undefined ||
                !bytesEqual(
                    stateSnapshot.output.intent.intentObjectHash,
                    input.intent.intentObjectHash,
                ))
        ) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'cached output vote has no matching durable output lock.',
            );
        }
        if (
            input.intent.voteKind === 'recovery' &&
            ((input.intent.preservedReservationIntentObjectHash ===
                undefined) !==
                (stateSnapshot.reservation === undefined) ||
                (input.intent.preservedOutputIntentObjectHash === undefined) !==
                    (stateSnapshot.output === undefined) ||
                (stateSnapshot.reservation !== undefined &&
                    !bytesEqual(
                        stateSnapshot.reservation.intent.intentObjectHash,
                        input.intent.preservedReservationIntentObjectHash!,
                    )) ||
                (stateSnapshot.output !== undefined &&
                    !bytesEqual(
                        stateSnapshot.output.intent.intentObjectHash,
                        input.intent.preservedOutputIntentObjectHash!,
                    )))
        ) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'cached recovery vote has no matching durable preserved locks.',
            );
        }

        return {
            ...stateSnapshot,
            voteIntent,
            voteIntentLogicalRecordKey: input.voteIntentLogicalRecordKey,
        };
    }

    async #readWitnessLock(stateKey: Uint8Array): Promise<StateLockSnapshot> {
        const reservation = await this.#readIntentRecord(
            reservationLockLogicalRecordKey(stateKey),
            'reservation',
            stateKey,
        );
        const output = await this.#readIntentRecord(
            outputLockLogicalRecordKey(stateKey),
            'output',
            stateKey,
        );
        if (output !== undefined) {
            if (
                reservation === undefined ||
                output.intent.voteKind !== 'output' ||
                !bytesEqual(
                    output.intent.reservationIntentObjectHash,
                    reservation.intent.intentObjectHash,
                )
            ) {
                throw new DurableNonForkingStateError(
                    'CorruptRecord',
                    'durable state output lock is detached from its reservation.',
                );
            }
        }

        return { output, reservation };
    }

    async #readIntentRecord(
        logicalRecordKey: string,
        expectedKind: DurableStateWitnessVoteKind,
        expectedStateKey: Uint8Array,
    ): Promise<AuthenticatedIntentRecord | undefined> {
        let resolvedIntent: InternalResolvedStateIntent | undefined;
        const bytes = await this.#store.readAuthenticated({
            logicalRecordKey,
            authenticate: async ({ bytes: storedBytes }) => {
                if (
                    storedBytes.byteLength === 0 ||
                    storedBytes.byteLength >
                        this.#limits.maximumCanonicalCarrierByteLength
                ) {
                    throw new DurableNonForkingStateError(
                        'BoundsExceeded',
                        'durable state intent carrier exceeds its configured bound.',
                    );
                }
                const resolved = await this.#resolveIntent(storedBytes);
                if (
                    resolved.voteKind !== expectedKind ||
                    !bytesEqual(resolved.stateKey, expectedStateKey)
                ) {
                    throw new DurableNonForkingStateError(
                        'CorruptRecord',
                        'durable state lock has the wrong kind or state key.',
                    );
                }
                resolvedIntent = resolved;
            },
        });
        if (bytes === undefined) {
            return undefined;
        }
        if (resolvedIntent === undefined) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'durable state lock authentication produced no binding.',
            );
        }

        return { bytes, intent: resolvedIntent };
    }

    async #writeIntentRecords(
        records: ReadonlyMap<string, AuthenticatedIntentRecord>,
    ): Promise<void> {
        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#limits.transactionLifetimeMilliseconds,
        });
        let commitStarted = false;
        try {
            for (const [logicalRecordKey, record] of records) {
                const lease = await transaction.issueWriteLease({
                    declaredByteLength: record.bytes.byteLength,
                    logicalRecordKey,
                });
                await lease.write(record.bytes.slice());
                await lease.seal(async ({ bytes }) => {
                    const resolved = await this.#resolveIntent(bytes);
                    if (
                        resolved.voteKind !== record.intent.voteKind ||
                        !bytesEqual(
                            resolved.stateKey,
                            record.intent.stateKey,
                        ) ||
                        !bytesEqual(
                            resolved.intentObjectHash,
                            record.intent.intentObjectHash,
                        )
                    ) {
                        throw new DurableNonForkingStateError(
                            'CorruptRecord',
                            'state lock changed before durable commit.',
                        );
                    }
                });
            }
            commitStarted = true;
            await transaction.commit();
        } catch (error) {
            await abortBeforeCommit(
                transaction,
                commitStarted && !isRetryableStorageContention(error),
                error,
            );
        }
    }

    async #readWitnessVoteRecord(
        logicalRecordKey: string,
        expectedVote: InternalResolvedStateWitnessVote,
    ): Promise<Uint8Array | undefined> {
        return this.#store.readAuthenticated({
            logicalRecordKey,
            authenticate: ({ bytes }) =>
                this.#authenticateWitnessVoteBytes(bytes, expectedVote),
        });
    }

    async #authenticateWitnessVoteBytes(
        bytes: Uint8Array,
        expectedVote: InternalResolvedStateWitnessVote,
    ): Promise<void> {
        if (
            bytes.byteLength === 0 ||
            bytes.byteLength > this.#limits.maximumCanonicalCarrierByteLength
        ) {
            throw new DurableNonForkingStateError(
                'BoundsExceeded',
                'cached state witness vote exceeds its carrier bound.',
            );
        }
        let resolved: InternalResolvedStateWitnessVote;
        try {
            resolved = copyResolvedVote(
                await this.#cryptography.resolveSignedStateWitnessVote({
                    canonicalSignedStateWitnessVoteCarrier: bytes.slice(),
                }),
            );
        } catch (error) {
            if (error instanceof DurableNonForkingStateError) {
                throw error;
            }
            throw new DurableNonForkingStateError(
                'AuthenticationFailed',
                'cached state witness vote signature or canonical encoding is invalid.',
                error,
            );
        }
        const sameSlot =
            bytesEqual(
                resolved.actionContextHash,
                expectedVote.actionContextHash,
            ) &&
            bytesEqual(
                resolved.witnessParticipantIdentity,
                expectedVote.witnessParticipantIdentity,
            ) &&
            bytesEqual(
                resolved.subjectParticipantIdentity,
                expectedVote.subjectParticipantIdentity,
            ) &&
            bytesEqual(resolved.stateKey, expectedVote.stateKey) &&
            resolved.producerSequence === expectedVote.producerSequence;
        if (!sameSlot) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'cached state witness vote belongs to another producer slot.',
            );
        }
        if (
            !bytesEqual(
                resolved.intentObjectHash,
                expectedVote.intentObjectHash,
            )
        ) {
            throw new DurableNonForkingStateError(
                'Equivocation',
                'cached state witness vote names another intent in the same producer slot.',
            );
        }
    }

    async #commitWitnessVoteCache(input: {
        candidateCarrier: Uint8Array;
        expectedVote: InternalResolvedStateWitnessVote;
        lockSnapshot: WitnessLockSnapshot;
        voteLogicalRecordKey: string;
    }): Promise<void> {
        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#limits.transactionLifetimeMilliseconds,
        });
        let commitStarted = false;
        try {
            if (input.lockSnapshot.reservation === undefined) {
                await transaction.stageDeletion(
                    reservationLockLogicalRecordKey(
                        input.expectedVote.stateKey,
                    ),
                );
            } else {
                await this.#stageIntentRecord(
                    transaction,
                    reservationLockLogicalRecordKey(
                        input.expectedVote.stateKey,
                    ),
                    input.lockSnapshot.reservation,
                );
            }
            if (input.lockSnapshot.output === undefined) {
                await transaction.stageDeletion(
                    outputLockLogicalRecordKey(input.expectedVote.stateKey),
                );
            } else {
                await this.#stageIntentRecord(
                    transaction,
                    outputLockLogicalRecordKey(input.expectedVote.stateKey),
                    input.lockSnapshot.output,
                );
            }
            await this.#stageIntentRecord(
                transaction,
                input.lockSnapshot.voteIntentLogicalRecordKey,
                input.lockSnapshot.voteIntent,
            );
            const voteLease = await transaction.issueWriteLease({
                declaredByteLength: input.candidateCarrier.byteLength,
                logicalRecordKey: input.voteLogicalRecordKey,
            });
            await voteLease.write(input.candidateCarrier.slice());
            await voteLease.seal(({ bytes }) =>
                this.#authenticateWitnessVoteBytes(bytes, input.expectedVote),
            );
            commitStarted = true;
            await transaction.commit();
        } catch (error) {
            await abortBeforeCommit(
                transaction,
                commitStarted && !isRetryableStorageContention(error),
                error,
            );
        }
    }

    async #stageIntentRecord(
        transaction: UntrustedStorageTransaction,
        logicalRecordKey: string,
        record: AuthenticatedIntentRecord,
    ): Promise<void> {
        const lease = await transaction.issueWriteLease({
            declaredByteLength: record.bytes.byteLength,
            logicalRecordKey,
        });
        await lease.write(record.bytes.slice());
        await lease.seal(async ({ bytes }) => {
            const resolved = await this.#resolveIntent(bytes);
            if (
                resolved.voteKind !== record.intent.voteKind ||
                !bytesEqual(resolved.stateKey, record.intent.stateKey) ||
                !bytesEqual(
                    resolved.intentObjectHash,
                    record.intent.intentObjectHash,
                )
            ) {
                throw new DurableNonForkingStateError(
                    'CorruptRecord',
                    'state lock changed before signed-carrier cache commit.',
                );
            }
        });
    }

    #exactOutputRecordContext(
        logicalRecordKey: string,
        scope: DurableExactOutputScope,
    ): DurableExactOutputRecordContext {
        return {
            logicalRecordKey,
            reservationIntentObjectHash:
                scope.reservationIntentObjectHash.slice(),
            stateKey: scope.stateKey.slice(),
        };
    }

    async #claimExactOutputGenerationReservation(input: {
        generationReservationIdentifier: Uint8Array;
        scope: DurableExactOutputScope;
    }): Promise<void> {
        const logicalRecordKey =
            exactOutputGenerationReservationLogicalRecordKey(input.scope);
        const existingIdentifier =
            await this.#readExactOutputGenerationReservation({
                logicalRecordKey,
                scope: input.scope,
            });
        if (existingIdentifier !== undefined) {
            const callerOwnsReservation = bytesEqual(
                existingIdentifier,
                input.generationReservationIdentifier,
            );
            existingIdentifier.fill(0);
            if (callerOwnsReservation) {
                return;
            }
            throw new DurableNonForkingStateError(
                'ExactOutputUnavailable',
                'exact-output generation was already consumed without a recoverable cached output.',
            );
        }

        const sealedBytes =
            await this.#sealAndReopenExactOutputGenerationReservation({
                generationReservationIdentifier:
                    input.generationReservationIdentifier,
                logicalRecordKey,
                scope: input.scope,
            });
        await this.#writeExactOutputGenerationReservation({
            generationReservationIdentifier:
                input.generationReservationIdentifier,
            logicalRecordKey,
            scope: input.scope,
            sealedBytes,
        });
        const committedIdentifier =
            await this.#readExactOutputGenerationReservation({
                logicalRecordKey,
                scope: input.scope,
            });
        if (committedIdentifier === undefined) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'committed exact-output generation reservation is missing or changed.',
            );
        }
        const committedIdentifierMatches = bytesEqual(
            committedIdentifier,
            input.generationReservationIdentifier,
        );
        committedIdentifier.fill(0);
        if (!committedIdentifierMatches) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'committed exact-output generation reservation is missing or changed.',
            );
        }
    }

    async #openExactOutputGenerationReservation(input: {
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
        sealedBytes: Uint8Array;
    }): Promise<Uint8Array> {
        if (
            input.sealedBytes.byteLength === 0 ||
            input.sealedBytes.byteLength >
                this.#limits.maximumSealedExactOutputByteLength
        ) {
            throw new DurableNonForkingStateError(
                'BoundsExceeded',
                'sealed exact-output generation reservation exceeds its configured bound.',
            );
        }
        let openedIdentifier: Uint8Array | undefined;
        try {
            openedIdentifier = await this.#openExactOutput({
                context: this.#exactOutputRecordContext(
                    input.logicalRecordKey,
                    input.scope,
                ),
                sealedBytes: input.sealedBytes.slice(),
            });

            return copyFixedBytes(
                openedIdentifier,
                generationReservationIdentifierByteLength,
                'opened exact-output generation reservation',
            );
        } catch (error) {
            if (error instanceof DurableNonForkingStateError) {
                throw error;
            }
            throw new DurableNonForkingStateError(
                'AuthenticationFailed',
                'sealed exact-output generation reservation authentication failed.',
                error,
            );
        } finally {
            openedIdentifier?.fill(0);
        }
    }

    async #readExactOutputGenerationReservation(input: {
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
    }): Promise<Uint8Array | undefined> {
        let generationReservationIdentifier: Uint8Array | undefined;
        let sealedBytes: Uint8Array | undefined;
        try {
            sealedBytes = await this.#store.readAuthenticated({
                logicalRecordKey: input.logicalRecordKey,
                authenticate: async ({ bytes }) => {
                    const openedIdentifier =
                        await this.#openExactOutputGenerationReservation({
                            logicalRecordKey: input.logicalRecordKey,
                            scope: input.scope,
                            sealedBytes: bytes,
                        });
                    generationReservationIdentifier?.fill(0);
                    generationReservationIdentifier = openedIdentifier;
                },
            });
        } catch (error) {
            generationReservationIdentifier?.fill(0);
            throw error;
        }
        if (sealedBytes === undefined) {
            return undefined;
        }
        if (generationReservationIdentifier === undefined) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'authenticated exact-output generation reservation produced no identifier.',
            );
        }

        const copiedIdentifier = generationReservationIdentifier.slice();
        generationReservationIdentifier.fill(0);

        return copiedIdentifier;
    }

    async #sealAndReopenExactOutputGenerationReservation(input: {
        generationReservationIdentifier: Uint8Array;
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
    }): Promise<Uint8Array> {
        const identifier = copyFixedBytes(
            input.generationReservationIdentifier,
            generationReservationIdentifierByteLength,
            'exact-output generation reservation identifier',
        );
        try {
            let sealedBytes: Uint8Array;
            try {
                sealedBytes = copyBoundedBytes(
                    await this.#sealExactOutput({
                        context: this.#exactOutputRecordContext(
                            input.logicalRecordKey,
                            input.scope,
                        ),
                        plaintext: identifier,
                    }),
                    this.#limits.maximumSealedExactOutputByteLength,
                    'sealed exact-output generation reservation',
                );
            } catch (error) {
                if (error instanceof DurableNonForkingStateError) {
                    throw error;
                }
                throw new DurableNonForkingStateError(
                    'AuthenticationFailed',
                    'exact-output generation reservation sealing failed.',
                    error,
                );
            }
            const reopenedIdentifier =
                await this.#openExactOutputGenerationReservation({
                    logicalRecordKey: input.logicalRecordKey,
                    scope: input.scope,
                    sealedBytes,
                });
            const reopenedIdentifierMatches = bytesEqual(
                identifier,
                reopenedIdentifier,
            );
            reopenedIdentifier.fill(0);
            if (!reopenedIdentifierMatches) {
                throw new DurableNonForkingStateError(
                    'AuthenticationFailed',
                    'sealed exact-output generation reservation did not reopen to its source identifier.',
                );
            }

            return sealedBytes;
        } finally {
            identifier.fill(0);
        }
    }

    async #writeExactOutputGenerationReservation(input: {
        generationReservationIdentifier: Uint8Array;
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
        sealedBytes: Uint8Array;
    }): Promise<void> {
        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#limits.transactionLifetimeMilliseconds,
        });
        let commitStarted = false;
        try {
            const lease = await transaction.issueWriteLease({
                declaredByteLength: input.sealedBytes.byteLength,
                logicalRecordKey: input.logicalRecordKey,
            });
            await lease.write(input.sealedBytes.slice());
            await lease.seal(async ({ bytes }) => {
                const identifier =
                    await this.#openExactOutputGenerationReservation({
                        logicalRecordKey: input.logicalRecordKey,
                        scope: input.scope,
                        sealedBytes: bytes,
                    });
                const identifierMatches = bytesEqual(
                    identifier,
                    input.generationReservationIdentifier,
                );
                identifier.fill(0);
                if (!identifierMatches) {
                    throw new DurableNonForkingStateError(
                        'CorruptRecord',
                        'exact-output generation reservation changed before durable commit.',
                    );
                }
            });
            commitStarted = true;
            await transaction.commit();
        } catch (error) {
            await abortBeforeCommit(
                transaction,
                commitStarted && !isRetryableStorageContention(error),
                error,
            );
        }
    }

    async #inspectExactOutput(input: {
        exactOutputBytes: Uint8Array;
        inspectExactOutput: DurableExactOutputInspector;
        scope: DurableExactOutputScope;
    }): Promise<ExactOutputInspection> {
        const exactOutputBytes = copyBoundedBytes(
            input.exactOutputBytes,
            this.#limits.maximumExactOutputByteLength,
            'exact output plaintext',
        );
        let inspection: Readonly<{ exactOutputHash: Uint8Array }>;
        try {
            inspection = await input.inspectExactOutput({
                exactOutputBytes: exactOutputBytes.slice(),
                reservationIntentObjectHash:
                    input.scope.reservationIntentObjectHash.slice(),
                stateKey: input.scope.stateKey.slice(),
            });
        } catch (error) {
            throw new DurableNonForkingStateError(
                'VerificationFailed',
                'operation-owned exact output inspection failed.',
                error,
            );
        }

        return {
            exactOutputBytes,
            exactOutputHash: copyFixedBytes(
                inspection.exactOutputHash,
                hashByteLength,
                'inspected exactOutputHash',
            ),
        };
    }

    async #sealAndReopenExactOutput(input: {
        exactOutputBytes: Uint8Array;
        inspectExactOutput: DurableExactOutputInspector;
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
    }): Promise<Uint8Array> {
        const context = this.#exactOutputRecordContext(
            input.logicalRecordKey,
            input.scope,
        );
        let sealedBytes: Uint8Array;
        try {
            sealedBytes = copyBoundedBytes(
                await this.#sealExactOutput({
                    context,
                    plaintext: input.exactOutputBytes.slice(),
                }),
                this.#limits.maximumSealedExactOutputByteLength,
                'sealed exact output record',
            );
        } catch (error) {
            if (error instanceof DurableNonForkingStateError) {
                throw error;
            }
            throw new DurableNonForkingStateError(
                'AuthenticationFailed',
                'exact output sealing failed.',
                error,
            );
        }
        const reopened = await this.#openAndInspectExactOutput({
            inspectExactOutput: input.inspectExactOutput,
            logicalRecordKey: input.logicalRecordKey,
            scope: input.scope,
            sealedBytes,
        });
        if (!bytesEqual(reopened.exactOutputBytes, input.exactOutputBytes)) {
            throw new DurableNonForkingStateError(
                'AuthenticationFailed',
                'sealed exact output did not reopen to the exact source bytes.',
            );
        }

        return sealedBytes;
    }

    async #openAndInspectExactOutput(input: {
        inspectExactOutput: DurableExactOutputInspector;
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
        sealedBytes: Uint8Array;
    }): Promise<ExactOutputInspection> {
        if (
            input.sealedBytes.byteLength === 0 ||
            input.sealedBytes.byteLength >
                this.#limits.maximumSealedExactOutputByteLength
        ) {
            throw new DurableNonForkingStateError(
                'BoundsExceeded',
                'sealed exact output record exceeds its configured bound.',
            );
        }
        let plaintext: Uint8Array;
        try {
            plaintext = copyBoundedBytes(
                await this.#openExactOutput({
                    context: this.#exactOutputRecordContext(
                        input.logicalRecordKey,
                        input.scope,
                    ),
                    sealedBytes: input.sealedBytes.slice(),
                }),
                this.#limits.maximumExactOutputByteLength,
                'opened exact output plaintext',
            );
        } catch (error) {
            if (error instanceof DurableNonForkingStateError) {
                throw error;
            }
            throw new DurableNonForkingStateError(
                'AuthenticationFailed',
                'sealed exact output authentication failed.',
                error,
            );
        }

        return this.#inspectExactOutput({
            exactOutputBytes: plaintext,
            inspectExactOutput: input.inspectExactOutput,
            scope: input.scope,
        });
    }

    async #readExactOutputRecord(input: {
        inspectExactOutput: DurableExactOutputInspector;
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
    }): Promise<ExactOutputInspection | undefined> {
        let inspection: ExactOutputInspection | undefined;
        const sealedBytes = await this.#store.readAuthenticated({
            logicalRecordKey: input.logicalRecordKey,
            authenticate: async ({ bytes }) => {
                inspection = await this.#openAndInspectExactOutput({
                    inspectExactOutput: input.inspectExactOutput,
                    logicalRecordKey: input.logicalRecordKey,
                    scope: input.scope,
                    sealedBytes: bytes,
                });
            },
        });
        if (sealedBytes === undefined) {
            return undefined;
        }
        if (inspection === undefined) {
            throw new DurableNonForkingStateError(
                'CorruptRecord',
                'authenticated exact output record produced no plaintext.',
            );
        }

        return {
            exactOutputBytes: inspection.exactOutputBytes.slice(),
            exactOutputHash: inspection.exactOutputHash.slice(),
        };
    }

    async #writeExactOutputRecord(input: {
        inspectExactOutput: DurableExactOutputInspector;
        logicalRecordKey: string;
        scope: DurableExactOutputScope;
        sealedBytes: Uint8Array;
    }): Promise<void> {
        const transaction = await this.#store.beginTransaction({
            lifetimeMilliseconds: this.#limits.transactionLifetimeMilliseconds,
        });
        let commitStarted = false;
        try {
            const lease = await transaction.issueWriteLease({
                declaredByteLength: input.sealedBytes.byteLength,
                logicalRecordKey: input.logicalRecordKey,
            });
            await lease.write(input.sealedBytes.slice());
            await lease.seal(({ bytes }) =>
                this.#openAndInspectExactOutput({
                    inspectExactOutput: input.inspectExactOutput,
                    logicalRecordKey: input.logicalRecordKey,
                    scope: input.scope,
                    sealedBytes: bytes,
                }).then(() => undefined),
            );
            commitStarted = true;
            await transaction.commit();
        } catch (error) {
            await abortBeforeCommit(
                transaction,
                commitStarted && !isRetryableStorageContention(error),
                error,
            );
        }
    }
}
