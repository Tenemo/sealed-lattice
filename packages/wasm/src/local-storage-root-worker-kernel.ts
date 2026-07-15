import {
    BrowserActionStorageCustodyError,
    stateCapabilityKinds,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessRecordContext,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionStateRecoveryVerificationInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserPersistentProofAttemptInput,
    type BrowserSealedActionRandomnessSession,
    type BrowserTargetReleaseAttemptInput,
    type ProtocolHash,
    type VerificationResult,
    type BrowserLocalRecordExpectedContext,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type BrowserActionStorageRootBinding,
    type BrowserActionStorageWorkerKernel,
    type UntrustedExpectedStorageRootCommitment,
    type LocalStorageRecoveryExportMaterial,
    type WorkerPreparedDeviceWrappingState,
    type WorkerPreparedRecoveryState,
} from '@sealed-lattice/types';

import {
    openStateVerifierSession,
    resolveVerifiedStateReservationKernelAuthorization,
    type StateVerifierSession,
    type VerifiedStateRecovery,
    type VerifiedStateReservation,
} from './state-verifier-runtime.js';
import type {
    SetupMailboxSlot,
    TranscriptCoreKernel,
} from './transcript-core-bridge/kernel-types.js';
import {
    resolveActionRandomnessKernelContext,
    type ActionRandomnessKernelContext,
} from './transcript-core-bridge/action-randomness-kernel-context.js';
import {
    resolveLocalStorageRootKernelContext,
    type LocalStorageRootKernelContext,
} from './transcript-core-bridge/local-storage-root-kernel-context.js';

const actionStorageRootByteLength = 48;
const actionRandomnessRootByteLength = 64;
const attemptIdentifierByteLength = 32;
const capabilityByteLength = 32;
const deviceWrappingNonceByteLength = 12;
const deviceWrappingTagByteLength = 16;
const foundationHashByteLength = 64;
const handleByteLength = 4;
const localRecordNonceByteLength = 12;
const maximumLocalRecordPlaintextByteLength = 1_048_576;
const maximumCommandByteLength = 1_572_864;
const maximumWrappedStorageRootByteLength = 492;
const mlDsa65VerificationKeyByteLength = 1_952;
const mlKem768CiphertextByteLength = 1_088;
const mlKem768EncapsulationKeyByteLength = 1_184;
const mlKem768SharedSecretByteLength = 32;
const mutationIdentifierByteLength = 32;
const recoveryChecksumByteLength = 16;
const recoveryTextByteLength = 708;
const wasm32WordByteLength = 4;
const opaqueWorkerIdentifierPattern = /^[0-9a-f]{64}$/u;

const localStorageRootCommands = Object.freeze({
    associatedData: 4,
    commit: 8,
    confirmRecovery: 12,
    copyForDeviceWrap: 5,
    decodeDeviceEnvelope: 7,
    destroy: 10,
    discard: 9,
    encodeDeviceEnvelope: 6,
    prepareRecovery: 11,
    reset: 13,
    deriveRecordIdentifier: 14,
    sealRecord: 15,
    openRecord: 16,
    hashRecordEnvelope: 17,
    stageNew: 1,
    stageOpened: 2,
    stageRecovery: 3,
} as const);

const actionRandomnessCommands = Object.freeze({
    close: 2,
    createAndSeal: 9,
    persistentProofAttempt: 5,
    openSealed: 10,
    setupMailboxEncapsulate: 3,
    setupMailboxSignatureHedge: 4,
    setupActionRandomnessAuthorization: 11,
    targetReleaseAttempt: 7,
    validateSetupMailboxSourceKeys: 12,
} as const);

const localStorageRootStatuses = Object.freeze({
    capabilityMismatch: 0x0001_0002,
    consumedState: 0x000d,
    malformedEncoding: 0x0001,
    outsideSupportedProfile: 0x0003,
    resourceLimit: 0x0001_0000,
    staleHandle: 0x0001_0001,
    unsupportedVersionOrSuite: 0x0002,
    wrongContext: 0x0004,
    wrongHashOrRoot: 0x0006,
    wrongTypeOrLength: 0x0005,
} as const);

type RootLease = {
    binding: BrowserActionStorageRootBinding;
    capability: Uint8Array<ArrayBuffer>;
    handle: number;
    storageRootCommitment: Uint8Array<ArrayBuffer>;
};

export type WorkerActionRandomnessRecordContext =
    BrowserActionRandomnessRecordContext;

export type WorkerSealedActionRandomnessSession =
    BrowserSealedActionRandomnessSession;

export type ClosedWorkerSetupMailboxRandomnessOperations = Readonly<{
    readonly actionContextHash: ProtocolHash;
    readonly ceremonyContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly sourceParticipantId: string;
    readonly suiteId: ProtocolHash;
    encapsulate(input: {
        readonly recipientEncapsulationKey: Uint8Array;
        readonly setupMailboxSlot: SetupMailboxSlot;
        readonly setupMailboxSlotHash: ProtocolHash;
    }): Readonly<{
        readonly ciphertext: Uint8Array<ArrayBuffer>;
        readonly envelopeAttemptIdentifier: Uint8Array<ArrayBuffer>;
        readonly sharedSecret: Uint8Array<ArrayBuffer>;
    }>;
    withSignatureHedge<Result>(
        input: {
            readonly envelopeHash: ProtocolHash;
            readonly setupMailboxSlot: SetupMailboxSlot;
            readonly setupMailboxSlotHash: ProtocolHash;
        },
        consume: (hedge: Uint8Array<ArrayBuffer>) => Result,
    ): Result;
    revoke(): void;
}>;

export type WorkerSetupMailboxRandomnessInput = Readonly<{
    readonly actionRandomnessSessionIdentifier: string;
    readonly sourceMailboxEncapsulationKey: Uint8Array;
    readonly sourceSigningVerificationKey: Uint8Array;
    readonly stateReservationIdentifier: string;
}>;

type WorkerActionRandomnessKernelRunner = Readonly<{
    close(sessionIdentifier: string): Promise<void>;
    createAndSeal(
        input: WorkerActionRandomnessRecordContext,
    ): Promise<WorkerSealedActionRandomnessSession>;
    openSealed(
        input: WorkerActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession>;
    openSetupMailboxRandomness(
        input: WorkerSetupMailboxRandomnessInput,
    ): Promise<ClosedWorkerSetupMailboxRandomnessOperations>;
}>;

type WorkerStateObject =
    | Readonly<{
          kind: 'recovery';
          sessionIdentifier: string;
          value: VerifiedStateRecovery;
      }>
    | Readonly<{
          capabilityKind: number;
          kind: 'reservation';
          sessionIdentifier: string;
          subjectParticipantIdentity: Uint8Array<ArrayBuffer>;
          value: VerifiedStateReservation;
      }>;

type WorkerStateVerifierSession = Readonly<{
    canonicalRosterBytes: Uint8Array<ArrayBuffer>;
    session: StateVerifierSession;
}>;

const workerActionRandomnessKernelRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    WorkerActionRandomnessKernelRunner
>();

type DecodedDeviceEnvelope = Readonly<{
    canonicalAssociatedData: Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<ArrayBuffer>;
    nonce: Uint8Array<ArrayBuffer>;
    tag: Uint8Array<ArrayBuffer>;
}>;

type CommandFailureContext =
    | 'open'
    | 'recoveryConfirmation'
    | 'recoveryImport'
    | 'recordHash'
    | 'recordOpen'
    | 'recordSeal'
    | 'runtime';

type TerminalSetupCheckpointKernelCommandRunner = Readonly<{
    run(command: number, input: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
    sampleEntropy(
        byteLength: number,
        label: string,
    ): Promise<Uint8Array<ArrayBuffer>>;
}>;

const terminalSetupCheckpointKernelCommandRunners = new WeakMap<
    BrowserActionStorageWorkerKernel,
    TerminalSetupCheckpointKernelCommandRunner
>();

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }

    return difference === 0;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const protocolHashBytes = (
    value: unknown,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be a lowercase 64-byte hexadecimal hash.`,
        );
    }
    const bytes = new Uint8Array(foundationHashByteLength);
    for (let byteIndex = 0; byteIndex < bytes.byteLength; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            value.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }
    return bytes;
};

const requireOpaqueWorkerIdentifier = (
    value: unknown,
    label: string,
): string => {
    if (
        typeof value !== 'string' ||
        !opaqueWorkerIdentifierPattern.test(value)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} is malformed.`,
        );
    }

    return value;
};

const copyBoundedBytes = (
    value: unknown,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength === 0 ||
        value.byteLength > maximumCommandByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} has an unsupported length.`,
        );
    }

    return value.slice();
};

const copyExactBytes = (
    value: Uint8Array,
    expectedByteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength !== expectedByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${expectedByteLength} bytes.`,
        );
    }
    const copy = new Uint8Array(expectedByteLength);
    copy.set(value);

    return copy;
};

const concatenateBytes = (
    ...values: readonly Uint8Array[]
): Uint8Array<ArrayBuffer> => {
    const byteLength = values.reduce(
        (accumulatedByteLength, value) =>
            accumulatedByteLength + value.byteLength,
        0,
    );
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength > maximumCommandByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The local storage-root command exceeds its supported byte limit.',
        );
    }
    const output = new Uint8Array(byteLength);
    let offset = 0;
    for (const value of values) {
        output.set(value, offset);
        offset += value.byteLength;
    }

    return output;
};

const encodeUnsigned32 = (value: number): Uint8Array<ArrayBuffer> => {
    if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffff_ffff) {
        throw new BrowserActionStorageCustodyError(
            'InvalidState',
            'The WASM local storage-root handle is invalid.',
        );
    }
    const bytes = new Uint8Array(handleByteLength);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

const encodeCanonicalUnsigned16 = (
    value: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 16-bit integer.`,
        );
    }
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);

    return bytes;
};

const encodeCanonicalUnsigned32 = (
    value: number,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 32-bit integer.`,
        );
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

const encodeCanonicalUnsigned64 = (
    value: bigint,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        typeof value !== 'bigint' ||
        value < 0n ||
        value > 0xffff_ffff_ffff_ffffn
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be an unsigned 64-bit integer.`,
        );
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);

    return bytes;
};

const encodeByteLength = (
    byteLength: number,
    label: string,
): Uint8Array<ArrayBuffer> => encodeCanonicalUnsigned32(byteLength, label);

type EncodedLocalRecordIdentifierInput = Readonly<{
    context: Uint8Array<ArrayBuffer>;
    recordTypeCode: number;
}>;

const encodeLocalRecordIdentifierInput = (
    input: BrowserLocalRecordIdentifierInput,
): EncodedLocalRecordIdentifierInput => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The local-record identifier input must be an object.',
        );
    }
    switch (input.recordType) {
        case 'actionRandomness':
            return { context: new Uint8Array(0), recordTypeCode: 1 };
        case 'publicCoinPrivateMaterial':
            return { context: new Uint8Array(0), recordTypeCode: 2 };
        case 'sourceVssMaterial':
            return {
                context: copyExactBytes(
                    input.materialContextHash,
                    foundationHashByteLength,
                    'Material-context hash',
                ),
                recordTypeCode: 3,
            };
        case 'aggregateThresholdShare':
            return {
                context: copyExactBytes(
                    input.recipientInputRoot,
                    foundationHashByteLength,
                    'Recipient-input root',
                ),
                recordTypeCode: 4,
            };
        case 'proofAttempt':
            return {
                context: copyExactBytes(
                    input.applicationSlotHash,
                    foundationHashByteLength,
                    'Application-slot hash',
                ),
                recordTypeCode: 5,
            };
        case 'ballotAttempt': {
            if (
                !(input.canonicalBallotStatementBytes instanceof Uint8Array) ||
                input.canonicalBallotStatementBytes.byteLength === 0 ||
                input.canonicalBallotStatementBytes.byteLength >
                    maximumCommandByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The canonical ballot statement has an unsupported length.',
                );
            }
            const statement = input.canonicalBallotStatementBytes.slice();
            const attemptIdentifier = copyExactBytes(
                input.ballotEncryptionAttemptIdentifier,
                32,
                'Ballot-encryption attempt identifier',
            );

            return {
                context: concatenateBytes(
                    encodeByteLength(
                        statement.byteLength,
                        'Ballot-statement byte length',
                    ),
                    statement,
                    attemptIdentifier,
                ),
                recordTypeCode: 6,
            };
        }
        case 'exactOutputChunk':
            return {
                context: concatenateBytes(
                    encodeCanonicalUnsigned16(
                        input.capabilityKind,
                        'Capability kind',
                    ),
                    copyExactBytes(
                        input.exactOutputHash,
                        foundationHashByteLength,
                        'Exact-output hash',
                    ),
                    encodeCanonicalUnsigned64(
                        input.outputChunkIndex,
                        'Output-chunk index',
                    ),
                ),
                recordTypeCode: 7,
            };
        case 'subjectState':
            return {
                context: copyExactBytes(
                    input.stateKey,
                    foundationHashByteLength,
                    'Subject-state key',
                ),
                recordTypeCode: 8,
            };
        case 'witnessState':
            return {
                context: copyExactBytes(
                    input.stateKey,
                    foundationHashByteLength,
                    'Witness-state key',
                ),
                recordTypeCode: 9,
            };
        case 'checkpointManifest': {
            const orderedSourceDigests: unknown = input.orderedSourceDigests;
            if (!Array.isArray(orderedSourceDigests)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Ordered checkpoint source digests must be an array.',
                );
            }
            if (orderedSourceDigests.length > 4_096) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Ordered checkpoint source digests exceed the supported count.',
                );
            }
            const sourceDigests = orderedSourceDigests.map((digest) => {
                if (!(digest instanceof Uint8Array)) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'Each ordered checkpoint source digest must be bytes.',
                    );
                }

                return copyExactBytes(
                    digest,
                    foundationHashByteLength,
                    'Checkpoint source digest',
                );
            });

            return {
                context: concatenateBytes(
                    copyExactBytes(
                        input.runtimeBuildManifestHash,
                        foundationHashByteLength,
                        'Runtime build-manifest hash',
                    ),
                    copyExactBytes(
                        input.checkpointLineageIdentifier,
                        32,
                        'Checkpoint-lineage identifier',
                    ),
                    encodeCanonicalUnsigned16(
                        input.operationKind,
                        'Checkpoint operation kind',
                    ),
                    encodeCanonicalUnsigned32(
                        input.safeBoundaryOrdinal,
                        'Checkpoint safe-boundary ordinal',
                    ),
                    encodeCanonicalUnsigned32(
                        sourceDigests.length,
                        'Checkpoint source-digest count',
                    ),
                    ...sourceDigests,
                ),
                recordTypeCode: 10,
            };
        }
        case 'checkpointChunk':
            return {
                context: concatenateBytes(
                    copyExactBytes(
                        input.checkpointIdentifier,
                        foundationHashByteLength,
                        'Checkpoint identifier',
                    ),
                    encodeCanonicalUnsigned32(
                        input.chunkIndex,
                        'Checkpoint chunk index',
                    ),
                    copyExactBytes(
                        input.chunkDigest,
                        foundationHashByteLength,
                        'Checkpoint chunk digest',
                    ),
                ),
                recordTypeCode: 11,
            };
    }
};

const encodeLocalRecordExpectedContext = (
    input: BrowserLocalRecordExpectedContext,
): Uint8Array<ArrayBuffer> => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The local-record expected context must be an object.',
        );
    }
    const encodedIdentifier = encodeLocalRecordIdentifierInput(
        input.identifierInput,
    );
    const predecessorRecordHash =
        input.predecessorRecordHash === undefined
            ? undefined
            : copyExactBytes(
                  input.predecessorRecordHash,
                  foundationHashByteLength,
                  'Predecessor record hash',
              );
    if (
        (input.recordVersion === 0n) !==
        (predecessorRecordHash === undefined)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Predecessor record-hash presence must match the local-record version.',
        );
    }

    return concatenateBytes(
        copyExactBytes(
            input.actionRandomnessCommitment,
            foundationHashByteLength,
            'Action-randomness commitment',
        ),
        encodeCanonicalUnsigned16(
            encodedIdentifier.recordTypeCode,
            'Local-record type',
        ),
        encodeByteLength(
            encodedIdentifier.context.byteLength,
            'Record-identifier context length',
        ),
        encodedIdentifier.context,
        encodeCanonicalUnsigned64(input.recordVersion, 'Local-record version'),
        encodeCanonicalUnsigned64(
            input.creationRecoveryEpoch,
            'Local-record creation recovery epoch',
        ),
        predecessorRecordHash === undefined
            ? new Uint8Array([0])
            : concatenateBytes(new Uint8Array([1]), predecessorRecordHash),
    );
};

const decodeUnsigned32 = (bytes: Uint8Array, offset: number): number => {
    if (offset < 0 || offset + wasm32WordByteLength > bytes.byteLength) {
        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            'The WASM local storage-root output is truncated.',
        );
    }

    return new DataView(
        bytes.buffer,
        bytes.byteOffset + offset,
        wasm32WordByteLength,
    ).getUint32(0, true);
};

const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

const encodeBinding = (
    binding: BrowserActionStorageRootBinding,
): Uint8Array<ArrayBuffer> =>
    concatenateBytes(
        copyExactBytes(binding.suiteId, foundationHashByteLength, 'Suite ID'),
        copyExactBytes(
            binding.ceremonyContextHash,
            foundationHashByteLength,
            'Ceremony-context hash',
        ),
        copyExactBytes(
            binding.actionContextHash,
            foundationHashByteLength,
            'Action-context hash',
        ),
        copyExactBytes(
            binding.participantId,
            foundationHashByteLength,
            'Participant identity',
        ),
    );

const copyBinding = (
    binding: BrowserActionStorageRootBinding,
): BrowserActionStorageRootBinding =>
    Object.freeze({
        actionContextHash: copyExactBytes(
            binding.actionContextHash,
            foundationHashByteLength,
            'Action-context hash',
        ),
        ceremonyContextHash: copyExactBytes(
            binding.ceremonyContextHash,
            foundationHashByteLength,
            'Ceremony-context hash',
        ),
        participantId: copyExactBytes(
            binding.participantId,
            foundationHashByteLength,
            'Participant identity',
        ),
        suiteId: copyExactBytes(
            binding.suiteId,
            foundationHashByteLength,
            'Suite ID',
        ),
    });

const encodeActionRandomnessRecordContext = (
    binding: BrowserActionStorageRootBinding,
    input: WorkerActionRandomnessRecordContext,
): Uint8Array<ArrayBuffer> => {
    if (typeof input !== 'object' || input === null) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action-randomness record context must be an object.',
        );
    }
    const predecessorRecordHash =
        input.predecessorRecordHash === undefined
            ? undefined
            : copyExactBytes(
                  input.predecessorRecordHash,
                  foundationHashByteLength,
                  'Action-randomness predecessor record hash',
              );
    if (
        (input.recordVersion === 0n) !==
        (predecessorRecordHash === undefined)
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'Action-randomness predecessor presence must match the record version.',
        );
    }
    return concatenateBytes(
        encodeBinding(binding),
        encodeCanonicalUnsigned64(
            input.recordVersion,
            'Action-randomness record version',
        ),
        encodeCanonicalUnsigned64(
            input.creationRecoveryEpoch,
            'Action-randomness creation recovery epoch',
        ),
        predecessorRecordHash === undefined
            ? new Uint8Array([0])
            : concatenateBytes(new Uint8Array([1]), predecessorRecordHash),
    );
};

const untrustedExpectedCommitmentBytes = (
    value: UntrustedExpectedStorageRootCommitment,
): Uint8Array<ArrayBuffer> =>
    copyExactBytes(
        value.storageRootCommitment,
        foundationHashByteLength,
        'Untrusted expected storage-root commitment',
    );

class WasmBrowserActionStorageWorkerKernel implements BrowserActionStorageWorkerKernel {
    readonly #actionRandomnessContext: ActionRandomnessKernelContext;
    readonly #context: LocalStorageRootKernelContext;
    readonly #cryptoProvider: Crypto;
    readonly #kernel: TranscriptCoreKernel;
    #activeLease: RootLease | undefined;
    readonly #actionRandomnessSessions = new Map<string, number>();
    #operationTail: Promise<void> = Promise.resolve();
    readonly #stateObjects = new Map<string, WorkerStateObject>();
    readonly #stateVerifierSessions = new Map<
        string,
        WorkerStateVerifierSession
    >();
    #stagedLease: RootLease | undefined;

    public constructor(input: {
        actionRandomnessContext: ActionRandomnessKernelContext;
        context: LocalStorageRootKernelContext;
        cryptoProvider: Crypto;
        kernel: TranscriptCoreKernel;
    }) {
        this.#actionRandomnessContext = input.actionRandomnessContext;
        this.#context = input.context;
        this.#cryptoProvider = input.cryptoProvider;
        this.#kernel = input.kernel;
    }

    public createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState> {
        return this.#enqueue(() => this.#createAndStage(input.binding));
    }

    public stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        return this.#enqueue(() => this.#stageDeviceWrappingOpen(input));
    }

    public stageRecoveryValueImportAndDeviceWrapping(input: {
        binding: BrowserActionStorageRootBinding;
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<WorkerPreparedRecoveryState> {
        return this.#enqueue(() => this.#stageRecoveryAndWrap(input));
    }

    public commitStagedActionStorageRoot(input: {
        mutationIdentifier: Uint8Array;
    }): Promise<void> {
        return this.#enqueue(() => this.#commitStaged(input));
    }

    public discardStagedActionStorageRoot(): Promise<void> {
        return this.#enqueue(() => this.#discardStaged());
    }

    public destroyActiveActionStorageRoot(): Promise<void> {
        return this.#enqueue(() => this.#destroyActive());
    }

    public prepareRecoveryExport(input: {
        activeMutationIdentifier: Uint8Array;
    }): Promise<LocalStorageRecoveryExportMaterial> {
        return this.#enqueue(() => this.#prepareRecovery(input));
    }

    public confirmRecoveryChecksum(input: {
        canonicalRecoveryText: string;
        confirmedChecksum: Uint8Array;
    }): Promise<void> {
        return this.#enqueue(() => this.#confirmRecovery(input));
    }

    public deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#deriveLocalRecordIdentifier(input));
    }

    public sealActiveLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#sealLocalRecord(input));
    }

    public openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#openLocalRecord(input));
    }

    public hashActiveLocalRecordEnvelope(
        envelope: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#hashLocalRecordEnvelope(envelope));
    }

    public openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() => this.#openActionStateVerifierSession(input));
    }

    public verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() => this.#verifyActionStateReservation(input));
    }

    public verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() =>
            this.#verifyActionRandomnessReservation(input),
        );
    }

    public verifyActionStateRecovery(
        input: BrowserActionStateRecoveryVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() => this.#verifyActionStateRecovery(input));
    }

    public releaseActionStateObject(identifier: string): Promise<void> {
        return this.#enqueue(() => this.#releaseActionStateObject(identifier));
    }

    public closeActionStateVerifierSession(identifier: string): Promise<void> {
        return this.#enqueue(() =>
            this.#closeActionStateVerifierSession(identifier),
        );
    }

    public runTerminalSetupCheckpointCommand(
        command: number,
        input: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => {
            if (!(input instanceof Uint8Array)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint command input must be bytes.',
                );
            }
            const activeLease = this.#requireActiveLease();

            return this.#runCommand(
                command,
                this.#leaseCommandInput(activeLease, input),
                'run an authenticated checkpoint command',
                'runtime',
            );
        });
    }

    public sampleTerminalSetupCheckpointEntropy(
        byteLength: number,
        label: string,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => {
            if (!Number.isSafeInteger(byteLength) || byteLength <= 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint entropy byte length must be a positive safe integer.',
                );
            }

            return this.#randomBytes(byteLength, label);
        });
    }

    public createAndSealActionRandomness(
        input: WorkerActionRandomnessRecordContext,
    ): Promise<WorkerSealedActionRandomnessSession> {
        return this.#enqueue(() => this.#createAndSealActionRandomness(input));
    }

    public openSealedActionRandomness(
        input: WorkerActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession> {
        return this.#enqueue(() => this.#openSealedActionRandomness(input));
    }

    public closeActionRandomness(sessionIdentifier: string): Promise<void> {
        return this.#enqueue(() =>
            this.#closeActionRandomness(sessionIdentifier),
        );
    }

    public openClosedSetupMailboxRandomness(
        input: WorkerSetupMailboxRandomnessInput,
    ): ClosedWorkerSetupMailboxRandomnessOperations {
        return this.#openClosedSetupMailboxRandomness(input);
    }

    public derivePersistentProofAttempt(
        input: BrowserPersistentProofAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#enqueue(() => this.#derivePersistentProofAttempt(input));
    }

    public deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#enqueue(() => this.#deriveTargetReleaseAttempt(input));
    }

    #openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action state-verifier session input must be an object.',
            );
        }
        const activeLease = this.#requireActiveLease();
        const canonicalRosterBytes = copyBoundedBytes(
            input.canonicalRosterBytes,
            'Canonical roster bytes',
        );
        const maximumRecoveryTransitionsPerStateKey =
            encodeCanonicalUnsigned16(
                input.maximumRecoveryTransitionsPerStateKey,
                'Maximum recovery transitions per state key',
            );
        const opened = openStateVerifierSession({
            configuration: {
                actionContextHash: activeLease.binding.actionContextHash,
                canonicalRosterBytes,
                ceremonyContextHash: activeLease.binding.ceremonyContextHash,
                maximumRecoveryTransitionsPerStateKey: new DataView(
                    maximumRecoveryTransitionsPerStateKey.buffer,
                ).getUint16(0, true),
                suiteIdentifier: activeLease.binding.suiteId,
            },
            kernel: this.#kernel,
        });
        if (!opened.isValid) {
            return opened;
        }
        const identifier = this.#issueOpaqueWorkerIdentifier();
        this.#stateVerifierSessions.set(identifier, {
            canonicalRosterBytes,
            session: opened.value,
        });
        return Object.freeze({ isValid: true, value: identifier });
    }

    #verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action state-reservation input must be an object.',
            );
        }
        if (
            input.capabilityKind ===
            stateCapabilityKinds.setupActionRandomnessRoot
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'Action-randomness reservations must be verified against the retained commitment.',
            );
        }
        const sessionIdentifier = requireOpaqueWorkerIdentifier(
            input.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        );
        const session = this.#requireStateVerifierSession(sessionIdentifier);
        const verified = session.verifyReservation({
            canonicalReservationIntentCarrier: copyBoundedBytes(
                input.canonicalReservationIntentCarrier,
                'Canonical state-reservation intent carrier',
            ),
            canonicalStateCertificate: copyBoundedBytes(
                input.canonicalStateCertificate,
                'Canonical state certificate',
            ),
            capabilityKind: input.capabilityKind,
            expectedAuthorizationHash: copyExactBytes(
                input.expectedAuthorizationHash,
                foundationHashByteLength,
                'Expected state authorization hash',
            ),
            subjectParticipantIdentity: copyExactBytes(
                input.subjectParticipantIdentity,
                foundationHashByteLength,
                'State subject participant identity',
            ),
            verifiedPredecessorRecovery: this.#resolvePredecessorRecovery(
                input.verifiedPredecessorRecoveryIdentifier,
                sessionIdentifier,
            ),
        });
        if (!verified.isValid) {
            return verified;
        }
        const identifier = this.#issueOpaqueWorkerIdentifier();
        this.#stateObjects.set(identifier, {
            capabilityKind: input.capabilityKind,
            kind: 'reservation',
            sessionIdentifier,
            subjectParticipantIdentity: input.subjectParticipantIdentity.slice(),
            value: verified.value,
        });
        return Object.freeze({ isValid: true, value: identifier });
    }

    #verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action-randomness reservation input must be an object.',
            );
        }
        const stateVerifierSessionIdentifier =
            requireOpaqueWorkerIdentifier(
                input.stateVerifierSessionIdentifier,
                'State-verifier session identifier',
            );
        const stateVerifierSession = this.#requireStateVerifierSessionRecord(
            stateVerifierSessionIdentifier,
        );
        const actionRandomnessSessionHandle =
            this.#requireActionRandomnessSession(
                input.actionRandomnessSessionIdentifier,
            );
        const activeBinding = this.#requireActiveLease().binding;
        let expectedAuthorizationHash: Uint8Array<ArrayBuffer> | undefined;
        try {
            expectedAuthorizationHash = this.#runActionRandomnessCommand(
                actionRandomnessCommands.setupActionRandomnessAuthorization,
                concatenateBytes(
                    encodeUnsigned32(actionRandomnessSessionHandle),
                    stateVerifierSession.canonicalRosterBytes,
                ),
                'derive the action-randomness reservation authorization',
                'runtime',
            );
            if (
                expectedAuthorizationHash.byteLength !==
                foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned a malformed reservation authorization.',
                );
            }
            const verified = stateVerifierSession.session.verifyReservation({
                canonicalReservationIntentCarrier: copyBoundedBytes(
                    input.canonicalReservationIntentCarrier,
                    'Canonical action-randomness reservation intent carrier',
                ),
                canonicalStateCertificate: copyBoundedBytes(
                    input.canonicalStateCertificate,
                    'Canonical state certificate',
                ),
                capabilityKind:
                    stateCapabilityKinds.setupActionRandomnessRoot,
                expectedAuthorizationHash,
                subjectParticipantIdentity: activeBinding.participantId.slice(),
                verifiedPredecessorRecovery: this.#resolvePredecessorRecovery(
                    input.verifiedPredecessorRecoveryIdentifier,
                    stateVerifierSessionIdentifier,
                ),
            });
            if (!verified.isValid) {
                return verified;
            }
            const identifier = this.#issueOpaqueWorkerIdentifier();
            this.#stateObjects.set(identifier, {
                capabilityKind:
                    stateCapabilityKinds.setupActionRandomnessRoot,
                kind: 'reservation',
                sessionIdentifier: stateVerifierSessionIdentifier,
                subjectParticipantIdentity: activeBinding.participantId.slice(),
                value: verified.value,
            });
            return Object.freeze({ isValid: true, value: identifier });
        } finally {
            expectedAuthorizationHash?.fill(0);
        }
    }

    #verifyActionStateRecovery(
        input: BrowserActionStateRecoveryVerificationInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action state-recovery input must be an object.',
            );
        }
        const sessionIdentifier = requireOpaqueWorkerIdentifier(
            input.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        );
        const session = this.#requireStateVerifierSession(sessionIdentifier);
        const verified = session.verifyRecovery({
            canonicalRecoveryTransitionCarrier: copyBoundedBytes(
                input.canonicalRecoveryTransitionCarrier,
                'Canonical state-recovery transition carrier',
            ),
            canonicalStateCertificate: copyBoundedBytes(
                input.canonicalStateCertificate,
                'Canonical state certificate',
            ),
            capabilityKind: input.capabilityKind,
            subjectParticipantIdentity: copyExactBytes(
                input.subjectParticipantIdentity,
                foundationHashByteLength,
                'State subject participant identity',
            ),
            verifiedPredecessorRecovery: this.#resolvePredecessorRecovery(
                input.verifiedPredecessorRecoveryIdentifier,
                sessionIdentifier,
            ),
        });
        if (!verified.isValid) {
            return verified;
        }
        const identifier = this.#issueOpaqueWorkerIdentifier();
        this.#stateObjects.set(identifier, {
            kind: 'recovery',
            sessionIdentifier,
            value: verified.value,
        });
        return Object.freeze({ isValid: true, value: identifier });
    }

    #releaseActionStateObject(identifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State object identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (stateObject === undefined) {
            return;
        }
        const session = this.#requireStateVerifierSession(
            stateObject.sessionIdentifier,
        );
        const released = session.releaseVerifiedObject(stateObject.value);
        if (!released.isValid) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                `The state verifier refused object release: ${released.refusalReason}.`,
            );
        }
        this.#stateObjects.delete(copiedIdentifier);
    }

    #closeActionStateVerifierSession(identifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State-verifier session identifier',
        );
        const sessionRecord = this.#stateVerifierSessions.get(copiedIdentifier);
        if (sessionRecord === undefined) {
            return;
        }
        sessionRecord.session.cancel();
        sessionRecord.canonicalRosterBytes.fill(0);
        this.#stateVerifierSessions.delete(copiedIdentifier);
        for (const [stateObjectIdentifier, stateObject] of this.#stateObjects) {
            if (stateObject.sessionIdentifier === copiedIdentifier) {
                this.#stateObjects.delete(stateObjectIdentifier);
            }
        }
    }

    #createAndSealActionRandomness(
        input: WorkerActionRandomnessRecordContext,
    ): WorkerSealedActionRandomnessSession {
        const activeLease = this.#requireActiveLease();
        const actionRoot = this.#randomBytes(
            actionRandomnessRootByteLength,
            'action-randomness root',
        );
        const nonce = this.#randomBytes(
            localRecordNonceByteLength,
            'action-randomness record nonce',
        );
        let output: Uint8Array<ArrayBuffer> | undefined;
        let sessionHandle = 0;
        let sessionRetained = false;
        try {
            output = this.#runActionRandomnessCommand(
                actionRandomnessCommands.createAndSeal,
                concatenateBytes(
                    this.#leaseCommandInput(activeLease),
                    actionRoot,
                    encodeActionRandomnessRecordContext(
                        activeLease.binding,
                        input,
                    ),
                    nonce,
                ),
                'create and seal action randomness',
                'recordSeal',
            );
            if (
                output.byteLength <=
                handleByteLength + foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned malformed sealed-session metadata.',
                );
            }
            sessionHandle = decodeUnsigned32(output, 0);
            if (sessionHandle === 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned a zero session handle.',
                );
            }
            const sessionIdentifier = this.#issueOpaqueWorkerIdentifier();
            this.#actionRandomnessSessions.set(
                sessionIdentifier,
                sessionHandle,
            );
            sessionRetained = true;
            return Object.freeze({
                actionRandomnessCommitment: output.slice(
                    handleByteLength,
                    handleByteLength + foundationHashByteLength,
                ),
                actionRandomnessSessionIdentifier: sessionIdentifier,
                canonicalEnvelope: output.slice(
                    handleByteLength + foundationHashByteLength,
                ),
            });
        } catch (error) {
            if (sessionHandle !== 0 && !sessionRetained) {
                this.#closeRawActionRandomness(sessionHandle);
            }
            throw error;
        } finally {
            actionRoot.fill(0);
            nonce.fill(0);
            output?.fill(0);
        }
    }

    #openSealedActionRandomness(
        input: WorkerActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): BrowserOpenedActionRandomnessSession {
        if (
            !(input.canonicalEnvelope instanceof Uint8Array) ||
            input.canonicalEnvelope.byteLength === 0 ||
            input.canonicalEnvelope.byteLength > maximumCommandByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The sealed action-randomness envelope has an unsupported length.',
            );
        }
        const activeLease = this.#requireActiveLease();
        const expectedCommitment = copyExactBytes(
            input.actionRandomnessCommitment,
            foundationHashByteLength,
            'Action-randomness commitment',
        );
        let output: Uint8Array<ArrayBuffer> | undefined;
        let sessionHandle = 0;
        let sessionRetained = false;
        try {
            output = this.#runActionRandomnessCommand(
                actionRandomnessCommands.openSealed,
                concatenateBytes(
                    this.#leaseCommandInput(activeLease),
                    expectedCommitment,
                    encodeActionRandomnessRecordContext(
                        activeLease.binding,
                        input,
                    ),
                    input.canonicalEnvelope,
                ),
                'open sealed action randomness',
                'recordOpen',
            );
            if (
                output.byteLength !==
                handleByteLength + foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned malformed reopened-session metadata.',
                );
            }
            sessionHandle = decodeUnsigned32(output, 0);
            const commitment = output.slice(handleByteLength);
            if (
                sessionHandle === 0 ||
                !bytesEqual(commitment, expectedCommitment)
            ) {
                commitment.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned inconsistent reopened-session metadata.',
                );
            }
            const sessionIdentifier = this.#issueOpaqueWorkerIdentifier();
            this.#actionRandomnessSessions.set(
                sessionIdentifier,
                sessionHandle,
            );
            sessionRetained = true;
            return Object.freeze({
                actionRandomnessCommitment: commitment,
                actionRandomnessSessionIdentifier: sessionIdentifier,
            });
        } catch (error) {
            if (sessionHandle !== 0 && !sessionRetained) {
                this.#closeRawActionRandomness(sessionHandle);
            }
            throw error;
        } finally {
            expectedCommitment.fill(0);
            output?.fill(0);
        }
    }

    #closeActionRandomness(sessionIdentifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            sessionIdentifier,
            'Action-randomness session identifier',
        );
        const sessionHandle = this.#actionRandomnessSessions.get(
            copiedIdentifier,
        );
        if (sessionHandle === undefined) {
            return;
        }
        this.#closeRawActionRandomness(sessionHandle);
        this.#actionRandomnessSessions.delete(copiedIdentifier);
    }

    #openClosedSetupMailboxRandomness(
        input: WorkerSetupMailboxRandomnessInput,
    ): ClosedWorkerSetupMailboxRandomnessOperations {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The setup-mailbox randomness input must be an object.',
            );
        }
        const actionRandomnessSessionIdentifier =
            requireOpaqueWorkerIdentifier(
                input.actionRandomnessSessionIdentifier,
                'Action-randomness session identifier',
            );
        const stateReservationIdentifier = requireOpaqueWorkerIdentifier(
            input.stateReservationIdentifier,
            'State-reservation identifier',
        );
        const initialBinding = this.#requireActiveLease().binding;
        const actionRandomnessSessionHandle =
            this.#requireActionRandomnessSession(
            actionRandomnessSessionIdentifier,
        );
        const initialReservation = this.#requireStateReservation(
            stateReservationIdentifier,
            stateCapabilityKinds.setupActionRandomnessRoot,
            initialBinding,
        );
        const stateVerifierSession = this.#requireStateVerifierSessionRecord(
            initialReservation.sessionIdentifier,
        );
        const sourceMailboxEncapsulationKey = copyExactBytes(
            input.sourceMailboxEncapsulationKey,
            mlKem768EncapsulationKeyByteLength,
            'Source mailbox encapsulation key',
        );
        const sourceSigningVerificationKey = copyExactBytes(
            input.sourceSigningVerificationKey,
            mlDsa65VerificationKeyByteLength,
            'Source signing verification key',
        );
        const reservationAuthorization = this.#reservationAuthorizationBytes(
            initialReservation.value,
        );
        let rosterHashBytes: Uint8Array<ArrayBuffer>;
        try {
            const validationOutput = this.#runActionRandomnessCommand(
                actionRandomnessCommands.validateSetupMailboxSourceKeys,
                concatenateBytes(
                    encodeUnsigned32(actionRandomnessSessionHandle),
                    reservationAuthorization,
                    sourceSigningVerificationKey,
                    sourceMailboxEncapsulationKey,
                    stateVerifierSession.canonicalRosterBytes,
                ),
                'validate setup-mailbox source keys against the frozen roster',
                'runtime',
            );
            if (validationOutput.byteLength !== foundationHashByteLength) {
                validationOutput.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned a malformed frozen-roster hash.',
                );
            }
            rosterHashBytes = validationOutput;
        } finally {
            reservationAuthorization.fill(0);
            sourceMailboxEncapsulationKey.fill(0);
            sourceSigningVerificationKey.fill(0);
        }
        const actionContextHash = bytesToHex(initialBinding.actionContextHash);
        const ceremonyContextHash = bytesToHex(
            initialBinding.ceremonyContextHash,
        );
        const rosterHash = bytesToHex(rosterHashBytes);
        const sourceParticipantId = bytesToHex(initialBinding.participantId);
        const suiteId = bytesToHex(initialBinding.suiteId);
        let revoked = false;

        const requireSlot = (
            setupMailboxSlot: SetupMailboxSlot,
            suppliedSlotHash: ProtocolHash,
        ): Readonly<{
            reservation: Extract<
                WorkerStateObject,
                Readonly<{ kind: 'reservation' }>
            >;
            sessionHandle: number;
            slotHashBytes: Uint8Array<ArrayBuffer>;
        }> => {
            if (revoked) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The setup-mailbox randomness capability was revoked.',
                );
            }
            const binding = this.#requireActiveLease().binding;
            const sessionHandle = this.#requireActionRandomnessSession(
                actionRandomnessSessionIdentifier,
            );
            const reservation = this.#requireStateReservation(
                stateReservationIdentifier,
                stateCapabilityKinds.setupActionRandomnessRoot,
                binding,
            );
            if (
                typeof setupMailboxSlot !== 'object' ||
                setupMailboxSlot === null ||
                setupMailboxSlot.suiteId !== suiteId ||
                setupMailboxSlot.ceremonyContextHash !==
                    ceremonyContextHash ||
                setupMailboxSlot.actionContextHash !== actionContextHash ||
                setupMailboxSlot.rosterHash !== rosterHash ||
                setupMailboxSlot.sourceParticipantId !== sourceParticipantId ||
                this.#kernel.deriveSetupMailboxSlotHash(setupMailboxSlot) !==
                    suppliedSlotHash
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The setup-mailbox slot does not match the worker-owned action randomness and frozen roster.',
                );
            }
            return Object.freeze({
                reservation,
                sessionHandle,
                slotHashBytes: protocolHashBytes(
                    suppliedSlotHash,
                    'Setup-mailbox slot hash',
                ),
            });
        };

        return Object.freeze({
            actionContextHash,
            ceremonyContextHash,
            rosterHash,
            sourceParticipantId,
            suiteId,
            encapsulate: ({
                recipientEncapsulationKey,
                setupMailboxSlot,
                setupMailboxSlotHash,
            }) => {
                const { reservation, sessionHandle, slotHashBytes } =
                    requireSlot(setupMailboxSlot, setupMailboxSlotHash);
                const reservationAuthorization =
                    this.#reservationAuthorizationBytes(reservation.value);
                const copiedRecipientEncapsulationKey = copyExactBytes(
                    recipientEncapsulationKey,
                    mlKem768EncapsulationKeyByteLength,
                    'Setup-mailbox recipient encapsulation key',
                );
                const recipientParticipantIdentityBytes = protocolHashBytes(
                    setupMailboxSlot.recipientParticipantId,
                    'Setup-mailbox recipient participant identity',
                );
                let output: Uint8Array<ArrayBuffer> | undefined;
                try {
                    output = this.#runActionRandomnessCommand(
                        actionRandomnessCommands.setupMailboxEncapsulate,
                        concatenateBytes(
                            encodeUnsigned32(sessionHandle),
                            reservationAuthorization,
                            rosterHashBytes,
                            slotHashBytes,
                            recipientParticipantIdentityBytes,
                            copiedRecipientEncapsulationKey,
                        ),
                        'encapsulate a reset-safe setup-mailbox shared secret',
                        'runtime',
                    );
                    if (
                        output.byteLength !==
                        attemptIdentifierByteLength +
                            mlKem768CiphertextByteLength +
                            mlKem768SharedSecretByteLength
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness kernel returned a malformed setup-mailbox encapsulation.',
                        );
                    }
                    return Object.freeze({
                        ciphertext: output.slice(
                            attemptIdentifierByteLength,
                            attemptIdentifierByteLength +
                                mlKem768CiphertextByteLength,
                        ),
                        envelopeAttemptIdentifier: output.slice(
                            0,
                            attemptIdentifierByteLength,
                        ),
                        sharedSecret: output.slice(
                            attemptIdentifierByteLength +
                                mlKem768CiphertextByteLength,
                        ),
                    });
                } finally {
                    copiedRecipientEncapsulationKey.fill(0);
                    recipientParticipantIdentityBytes.fill(0);
                    reservationAuthorization.fill(0);
                    slotHashBytes.fill(0);
                    output?.fill(0);
                }
            },
            withSignatureHedge: (
                {
                    envelopeHash,
                    setupMailboxSlot,
                    setupMailboxSlotHash,
                },
                consume,
            ) => {
                if (typeof consume !== 'function') {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        'The setup-mailbox signature consumer must be a function.',
                    );
                }
                const { reservation, sessionHandle, slotHashBytes } =
                    requireSlot(setupMailboxSlot, setupMailboxSlotHash);
                const reservationAuthorization =
                    this.#reservationAuthorizationBytes(reservation.value);
                const envelopeHashBytes = protocolHashBytes(
                    envelopeHash,
                    'Setup-mailbox envelope hash',
                );
                let output: Uint8Array<ArrayBuffer> | undefined;
                try {
                    output = this.#runActionRandomnessCommand(
                        actionRandomnessCommands.setupMailboxSignatureHedge,
                        concatenateBytes(
                            encodeUnsigned32(sessionHandle),
                            reservationAuthorization,
                            rosterHashBytes,
                            envelopeHashBytes,
                        ),
                        'derive and consume a setup-mailbox signature hedge',
                        'runtime',
                    );
                    if (output.byteLength !== attemptIdentifierByteLength) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness kernel returned a malformed setup-mailbox signature hedge.',
                        );
                    }
                    return consume(output);
                } finally {
                    reservationAuthorization.fill(0);
                    slotHashBytes.fill(0);
                    envelopeHashBytes.fill(0);
                    output?.fill(0);
                }
            },
            revoke: () => {
                if (revoked) {
                    return;
                }
                revoked = true;
                rosterHashBytes.fill(0);
            },
        });
    }

    #closeRawActionRandomness(sessionHandle: number): void {
        const output = this.#runActionRandomnessCommand(
            actionRandomnessCommands.close,
            encodeUnsigned32(sessionHandle),
            'close action randomness',
            'runtime',
        );
        try {
            if (output.byteLength !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness close command returned unexpected output.',
                );
            }
        } finally {
            output.fill(0);
        }
    }

    #closeAllActionRandomness(): void {
        for (const sessionIdentifier of [
            ...this.#actionRandomnessSessions.keys(),
        ]) {
            this.#closeActionRandomness(sessionIdentifier);
        }
    }

    #closeAllStateVerifierSessions(): void {
        for (const sessionIdentifier of [
            ...this.#stateVerifierSessions.keys(),
        ]) {
            this.#closeActionStateVerifierSession(sessionIdentifier);
        }
    }

    #derivePersistentProofAttempt(
        input: BrowserPersistentProofAttemptInput,
    ): BrowserActionProofAttemptBinding {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The persistent proof-attempt input must be an object.',
            );
        }
        const sessionHandle = this.#requireActionRandomnessSession(
            input.actionRandomnessSessionIdentifier,
        );
        const expectedCapabilityKind = this.#persistentProofCapabilityKind(
            input.statementSchemaIdentifier,
            input.schedulePosition,
        );
        const reservation = this.#requireStateReservation(
            input.stateReservationIdentifier,
            expectedCapabilityKind,
            this.#requireActiveLease().binding,
        );
        const reservationAuthorization =
            this.#reservationAuthorizationBytes(reservation.value);
        try {
            return this.#parseProofAttemptOutput(
                this.#runActionRandomnessCommand(
                    actionRandomnessCommands.persistentProofAttempt,
                    concatenateBytes(
                        encodeUnsigned32(sessionHandle),
                        reservationAuthorization,
                        encodeCanonicalUnsigned16(
                            input.statementSchemaIdentifier,
                            'Proof statement schema identifier',
                        ),
                        encodeCanonicalUnsigned16(
                            input.rosterPosition,
                            'Proof roster position',
                        ),
                        input.schedulePosition === undefined
                            ? new Uint8Array([0])
                            : concatenateBytes(
                                  new Uint8Array([1]),
                                  encodeCanonicalUnsigned32(
                                      input.schedulePosition,
                                      'Proof schedule position',
                                  ),
                              ),
                        copyExactBytes(
                            input.applicationStatementHash,
                            foundationHashByteLength,
                            'Application statement hash',
                        ),
                    ),
                    'derive a persistent proof attempt',
                    'runtime',
                ),
            );
        } finally {
            reservationAuthorization.fill(0);
        }
    }

    #deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): BrowserActionProofAttemptBinding {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The target-release attempt input must be an object.',
            );
        }
        const sessionHandle = this.#requireActionRandomnessSession(
            input.actionRandomnessSessionIdentifier,
        );
        const reservation = this.#requireStateReservation(
            input.stateReservationIdentifier,
            stateCapabilityKinds.targetRelease,
            this.#requireActiveLease().binding,
        );
        const reservationAuthorization =
            this.#reservationAuthorizationBytes(reservation.value);
        try {
            return this.#parseProofAttemptOutput(
                this.#runActionRandomnessCommand(
                    actionRandomnessCommands.targetReleaseAttempt,
                    concatenateBytes(
                        encodeUnsigned32(sessionHandle),
                        reservationAuthorization,
                        encodeCanonicalUnsigned16(
                            input.rosterPosition,
                            'Target-release roster position',
                        ),
                    ),
                    'derive a target-release attempt',
                    'runtime',
                ),
            );
        } finally {
            reservationAuthorization.fill(0);
        }
    }

    #requireStateVerifierSession(identifier: string): StateVerifierSession {
        return this.#requireStateVerifierSessionRecord(identifier).session;
    }

    #requireStateVerifierSessionRecord(
        identifier: string,
    ): WorkerStateVerifierSession {
        const sessionRecord = this.#stateVerifierSessions.get(identifier);
        if (
            sessionRecord === undefined ||
            sessionRecord.session.state() !== 'active'
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The state-verifier session is closed or unavailable in this worker.',
            );
        }

        return sessionRecord;
    }

    #resolvePredecessorRecovery(
        identifier: string | undefined,
        expectedSessionIdentifier: string,
    ): VerifiedStateRecovery | undefined {
        if (identifier === undefined) {
            return undefined;
        }
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'Predecessor state-recovery identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (
            stateObject === undefined ||
            stateObject.kind !== 'recovery' ||
            stateObject.sessionIdentifier !== expectedSessionIdentifier
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The predecessor recovery is unavailable in the selected state-verifier session.',
            );
        }

        return stateObject.value;
    }

    #requireStateReservation(
        identifier: string,
        expectedCapabilityKind: number,
        binding: BrowserActionStorageRootBinding,
    ): Extract<WorkerStateObject, Readonly<{ kind: 'reservation' }>> {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State-reservation identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (
            stateObject === undefined ||
            stateObject.kind !== 'reservation' ||
            stateObject.capabilityKind !== expectedCapabilityKind ||
            !bytesEqual(
                stateObject.subjectParticipantIdentity,
                binding.participantId,
            ) ||
            !this.#stateVerifierSessions.has(stateObject.sessionIdentifier)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The required matching state reservation is unavailable in this worker.',
            );
        }

        return stateObject;
    }

    #reservationAuthorizationBytes(
        reservation: VerifiedStateReservation,
    ): Uint8Array<ArrayBuffer> {
        let authorization;
        try {
            authorization =
                resolveVerifiedStateReservationKernelAuthorization(
                    reservation,
                    this.#kernel,
                );
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The state reservation is no longer active in this worker.',
                error,
            );
        }
        if (
            authorization.capabilityMemory !==
                this.#actionRandomnessContext.memory ||
            authorization.capabilityPointer <= 0 ||
            authorization.capabilityPointer + capabilityByteLength >
                authorization.capabilityMemory.buffer.byteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The state verifier returned malformed reservation authorization.',
            );
        }
        const bytes = new Uint8Array(
            handleByteLength + capabilityByteLength + handleByteLength,
        );
        const view = new DataView(bytes.buffer);
        view.setUint32(0, authorization.sessionHandle, true);
        bytes.set(
            new Uint8Array(
                authorization.capabilityMemory.buffer,
                authorization.capabilityPointer,
                capabilityByteLength,
            ),
            handleByteLength,
        );
        view.setUint32(
            handleByteLength + capabilityByteLength,
            authorization.reservationHandle,
            true,
        );

        return bytes;
    }

    #requireActionRandomnessSession(identifier: string): number {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'Action-randomness session identifier',
        );
        const handle = this.#actionRandomnessSessions.get(copiedIdentifier);
        if (handle === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The action-randomness session is closed or unavailable in this worker.',
            );
        }

        return handle;
    }

    #persistentProofCapabilityKind(
        statementSchemaIdentifier: number,
        schedulePosition: number | undefined,
    ): number {
        let capabilityKind: number;
        let requiresSchedulePosition = false;
        switch (statementSchemaIdentifier) {
            case 0x2110:
                capabilityKind = stateCapabilityKinds.setupPublicSeedBranch;
                break;
            case 0x2111:
            case 0x1211:
            case 0x1212:
                capabilityKind = stateCapabilityKinds.setupDealerSetBranch;
                break;
            case 0x1214:
            case 0x1217:
                capabilityKind = stateCapabilityKinds.setupDealerSetBranch;
                requiresSchedulePosition = true;
                break;
            case 0x1216:
                capabilityKind = stateCapabilityKinds.setupRkgRoundOneBranch;
                requiresSchedulePosition = true;
                break;
            case 0x1621:
                capabilityKind = stateCapabilityKinds.targetRelease;
                break;
            default:
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The statement schema is not a reset-safe proof family.',
                );
        }
        if (requiresSchedulePosition !== (schedulePosition !== undefined)) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                requiresSchedulePosition
                    ? 'The selected proof family requires a schedule position.'
                    : 'The selected proof family does not accept a schedule position.',
            );
        }

        return capabilityKind;
    }

    #parseProofAttemptOutput(
        output: Uint8Array<ArrayBuffer>,
    ): BrowserActionProofAttemptBinding {
        try {
            if (
                output.byteLength !==
                foundationHashByteLength + attemptIdentifierByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned malformed proof-attempt metadata.',
                );
            }

            return Object.freeze({
                applicationSlotHash: output.slice(
                    0,
                    foundationHashByteLength,
                ),
                attemptIdentifier: output.slice(foundationHashByteLength),
            });
        } finally {
            output.fill(0);
        }
    }

    #issueOpaqueWorkerIdentifier(): string {
        for (let attempt = 0; attempt < 16; attempt += 1) {
            const bytes = this.#randomBytes(
                attemptIdentifierByteLength,
                'opaque worker identifier',
            );
            const identifier = bytesToHex(bytes);
            bytes.fill(0);
            if (
                !this.#stateVerifierSessions.has(identifier) &&
                !this.#stateObjects.has(identifier) &&
                !this.#actionRandomnessSessions.has(identifier)
            ) {
                return identifier;
            }
        }
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Secure randomness repeatedly produced an existing worker identifier.',
        );
    }

    #deriveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Uint8Array<ArrayBuffer> {
        const activeLease = this.#requireActiveLease();
        const encodedIdentifier = encodeLocalRecordIdentifierInput(input);
        const identifier = this.#runCommand(
            localStorageRootCommands.deriveRecordIdentifier,
            this.#leaseCommandInput(
                activeLease,
                encodeCanonicalUnsigned16(
                    encodedIdentifier.recordTypeCode,
                    'Local-record type',
                ),
                encodedIdentifier.context,
            ),
            'derive a local-record identifier',
            'recordSeal',
        );
        if (identifier.byteLength !== foundationHashByteLength) {
            identifier.fill(0);
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM kernel returned a malformed local-record identifier.',
            );
        }

        return identifier;
    }

    #sealLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Uint8Array<ArrayBuffer> {
        if (
            typeof input !== 'object' ||
            input === null ||
            !(input.plaintext instanceof Uint8Array) ||
            input.plaintext.byteLength > maximumLocalRecordPlaintextByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                `The local-record plaintext must contain at most ${maximumLocalRecordPlaintextByteLength} bytes.`,
            );
        }
        const activeLease = this.#requireActiveLease();
        const nonce = this.#randomBytes(
            localRecordNonceByteLength,
            'local-record nonce',
        );
        try {
            const envelope = this.#runCommand(
                localStorageRootCommands.sealRecord,
                this.#leaseCommandInput(
                    activeLease,
                    encodeLocalRecordExpectedContext(input),
                    nonce,
                    input.plaintext,
                ),
                'seal a local record',
                'recordSeal',
            );
            if (envelope.byteLength === 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM kernel returned an empty local-record envelope.',
                );
            }

            return envelope;
        } finally {
            nonce.fill(0);
        }
    }

    #openLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Uint8Array<ArrayBuffer> {
        if (
            typeof input !== 'object' ||
            input === null ||
            !(input.envelope instanceof Uint8Array) ||
            input.envelope.byteLength === 0 ||
            input.envelope.byteLength > maximumCommandByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The local-record envelope has an unsupported length.',
            );
        }
        const activeLease = this.#requireActiveLease();

        return this.#runCommand(
            localStorageRootCommands.openRecord,
            this.#leaseCommandInput(
                activeLease,
                encodeLocalRecordExpectedContext(input),
                input.envelope,
            ),
            'open a local record',
            'recordOpen',
        );
    }

    #hashLocalRecordEnvelope(envelope: Uint8Array): Uint8Array<ArrayBuffer> {
        if (
            !(envelope instanceof Uint8Array) ||
            envelope.byteLength === 0 ||
            envelope.byteLength > maximumCommandByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The local-record envelope has an unsupported length.',
            );
        }
        const activeLease = this.#requireActiveLease();
        const envelopeHash = this.#runCommand(
            localStorageRootCommands.hashRecordEnvelope,
            this.#leaseCommandInput(activeLease, envelope),
            'hash a canonical local-record envelope',
            'recordHash',
        );
        if (envelopeHash.byteLength !== foundationHashByteLength) {
            envelopeHash.fill(0);
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM kernel returned a malformed local-record envelope hash.',
            );
        }

        return envelopeHash;
    }

    async #createAndStage(
        binding: BrowserActionStorageRootBinding,
    ): Promise<WorkerPreparedDeviceWrappingState> {
        this.#assertNoStagedLease();
        const capability = this.#randomBytes(
            capabilityByteLength,
            'storage-root capability',
        );
        if (capability.every((byte) => byte === 0)) {
            capability.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Secure randomness returned an invalid storage-root capability.',
            );
        }
        const root = this.#randomBytes(
            actionStorageRootByteLength,
            'action storage root',
        );
        let stageOutput: Uint8Array<ArrayBuffer> | undefined;
        try {
            stageOutput = this.#runCommand(
                localStorageRootCommands.stageNew,
                concatenateBytes(capability, encodeBinding(binding), root),
                'stage a new local storage root',
                'runtime',
            );
            const staged = this.#readStageOutput(
                stageOutput,
                capability,
                binding,
            );
            this.#stagedLease = staged.lease;
            try {
                const wrapped = await this.#wrapStagedRoot();

                return Object.freeze({
                    ...wrapped,
                    storageRootCommitment: staged.commitment,
                });
            } catch (error) {
                return this.#discardAfterFailure(error);
            }
        } finally {
            root.fill(0);
            stageOutput?.fill(0);
            if (this.#stagedLease?.capability !== capability) {
                capability.fill(0);
            }
        }
    }

    async #stageDeviceWrappingOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        const expectedCommitment = untrustedExpectedCommitmentBytes(
            input.untrustedExpectedCommitment,
        );
        const storedCommitment = copyExactBytes(
            input.state.storageRootCommitment,
            foundationHashByteLength,
            'Stored storage-root commitment',
        );
        if (!bytesEqual(storedCommitment, expectedCommitment)) {
            throw new BrowserActionStorageCustodyError(
                'CommitmentMismatch',
                'The stored storage-root commitment does not match the untrusted expected commitment.',
            );
        }
        this.#assertCompatibleStagedCommitment(expectedCommitment);
        const wrappedStorageRoot = input.state.wrappedStorageRoot;
        if (
            !(wrappedStorageRoot instanceof Uint8Array) ||
            wrappedStorageRoot.byteLength === 0 ||
            wrappedStorageRoot.byteLength > maximumWrappedStorageRootByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidCanonicalMaterial',
                'The device-wrapped storage-root envelope has an invalid length.',
            );
        }
        const decoded = this.#decodeDeviceEnvelope(
            input.binding,
            expectedCommitment,
            wrappedStorageRoot,
        );
        const combinedCiphertext = concatenateBytes(
            decoded.ciphertext,
            decoded.tag,
        );
        let openedRoot: Uint8Array<ArrayBuffer> | undefined;
        let capability: Uint8Array<ArrayBuffer> | undefined;
        let stageOutput: Uint8Array<ArrayBuffer> | undefined;
        try {
            try {
                openedRoot = new Uint8Array(
                    await this.#cryptoProvider.subtle.decrypt(
                        {
                            additionalData: arrayBufferFromBytes(
                                decoded.canonicalAssociatedData,
                            ),
                            iv: arrayBufferFromBytes(decoded.nonce),
                            name: 'AES-GCM',
                            tagLength: deviceWrappingTagByteLength * 8,
                        },
                        input.state.deviceKey,
                        arrayBufferFromBytes(combinedCiphertext),
                    ),
                );
            } catch (error) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidCanonicalMaterial',
                    'The device-wrapped storage root could not be authenticated and opened.',
                    error,
                );
            }
            if (openedRoot.byteLength !== actionStorageRootByteLength) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidCanonicalMaterial',
                    `The opened action storage root must contain exactly ${actionStorageRootByteLength} bytes.`,
                );
            }
            this.#discardStaged();
            capability = this.#randomCapability();
            stageOutput = this.#runCommand(
                localStorageRootCommands.stageOpened,
                concatenateBytes(
                    capability,
                    encodeBinding(input.binding),
                    expectedCommitment,
                    openedRoot,
                ),
                'stage an opened local storage root',
                'open',
            );
            const staged = this.#readStageOutput(
                stageOutput,
                capability,
                input.binding,
            );
            if (!bytesEqual(staged.commitment, expectedCommitment)) {
                throw new BrowserActionStorageCustodyError(
                    'CommitmentMismatch',
                    'The opened storage root does not match the expected commitment.',
                );
            }
            this.#stagedLease = staged.lease;
        } finally {
            combinedCiphertext.fill(0);
            decoded.canonicalAssociatedData.fill(0);
            decoded.ciphertext.fill(0);
            decoded.nonce.fill(0);
            decoded.tag.fill(0);
            openedRoot?.fill(0);
            stageOutput?.fill(0);
            if (
                capability !== undefined &&
                this.#stagedLease?.capability !== capability
            ) {
                capability.fill(0);
            }
        }
    }

    async #stageRecoveryAndWrap(input: {
        binding: BrowserActionStorageRootBinding;
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<WorkerPreparedRecoveryState> {
        if (typeof input.caseInsensitiveRecoveryText !== 'string') {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'Recovery material must be text.',
            );
        }
        const canonicalRecoveryText =
            input.caseInsensitiveRecoveryText.toUpperCase();
        const recoveryTextBytes = new TextEncoder().encode(
            canonicalRecoveryText,
        );
        if (recoveryTextBytes.byteLength !== recoveryTextByteLength) {
            recoveryTextBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'InvalidCanonicalMaterial',
                `Recovery material must encode to exactly ${recoveryTextByteLength} bytes.`,
            );
        }
        const expectedCommitment = untrustedExpectedCommitmentBytes(
            input.untrustedExpectedCommitment,
        );
        this.#assertCompatibleStagedCommitment(expectedCommitment);
        const capability = this.#randomCapability();
        let stageOutput: Uint8Array<ArrayBuffer> | undefined;
        try {
            this.#discardStaged();
            stageOutput = this.#runCommand(
                localStorageRootCommands.stageRecovery,
                concatenateBytes(
                    capability,
                    encodeBinding(input.binding),
                    expectedCommitment,
                    recoveryTextBytes,
                ),
                'import a local storage recovery value',
                'recoveryImport',
            );
            if (
                stageOutput.byteLength !==
                handleByteLength +
                    foundationHashByteLength +
                    recoveryTextByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM recovery import returned malformed output.',
                );
            }
            const staged = this.#readStageOutput(
                stageOutput.subarray(
                    0,
                    handleByteLength + foundationHashByteLength,
                ),
                capability,
                input.binding,
            );
            if (!bytesEqual(staged.commitment, expectedCommitment)) {
                throw new BrowserActionStorageCustodyError(
                    'CommitmentMismatch',
                    'The recovered storage root does not match the externally verified commitment.',
                );
            }
            this.#stagedLease = staged.lease;
            const returnedRecoveryText = new TextDecoder('utf-8', {
                fatal: true,
            }).decode(
                stageOutput.subarray(
                    handleByteLength + foundationHashByteLength,
                ),
            );
            try {
                const wrapped = await this.#wrapStagedRoot();

                return Object.freeze({
                    canonicalRecoveryText: returnedRecoveryText,
                    ...wrapped,
                    storageRootCommitment: staged.commitment,
                });
            } catch (error) {
                return this.#discardAfterFailure(error);
            }
        } finally {
            recoveryTextBytes.fill(0);
            stageOutput?.fill(0);
            if (this.#stagedLease?.capability !== capability) {
                capability.fill(0);
            }
        }
    }

    #commitStaged(input: { mutationIdentifier: Uint8Array }): void {
        const stagedLease = this.#requireStagedLease();
        const mutationIdentifier = copyExactBytes(
            input.mutationIdentifier,
            mutationIdentifierByteLength,
            'Storage mutation identifier',
        );
        this.#runCommand(
            localStorageRootCommands.commit,
            this.#leaseCommandInput(stagedLease, mutationIdentifier),
            'commit a staged local storage root',
            'runtime',
        );
        this.#closeAllActionRandomness();
        this.#closeAllStateVerifierSessions();
        this.#activeLease?.capability.fill(0);
        this.#activeLease = stagedLease;
        this.#stagedLease = undefined;
    }

    #discardStaged(): void {
        const stagedLease = this.#stagedLease;
        if (stagedLease === undefined) {
            return;
        }
        this.#runCommand(
            localStorageRootCommands.discard,
            this.#leaseCommandInput(stagedLease),
            'discard a staged local storage root',
            'runtime',
        );
        stagedLease.capability.fill(0);
        this.#stagedLease = undefined;
    }

    #destroyActive(): void {
        const activeLease = this.#activeLease;
        if (activeLease === undefined) {
            return;
        }
        this.#closeAllActionRandomness();
        this.#closeAllStateVerifierSessions();
        this.#runCommand(
            localStorageRootCommands.destroy,
            this.#leaseCommandInput(activeLease),
            'destroy an active local storage root',
            'runtime',
        );
        activeLease.capability.fill(0);
        this.#activeLease = undefined;
    }

    #prepareRecovery(input: {
        activeMutationIdentifier: Uint8Array;
    }): LocalStorageRecoveryExportMaterial {
        const activeLease = this.#requireActiveLease();
        const mutationIdentifier = copyExactBytes(
            input.activeMutationIdentifier,
            mutationIdentifierByteLength,
            'Active storage mutation identifier',
        );
        const output = this.#runCommand(
            localStorageRootCommands.prepareRecovery,
            this.#leaseCommandInput(activeLease, mutationIdentifier),
            'prepare local storage recovery material',
            'runtime',
        );
        try {
            if (
                output.byteLength !==
                recoveryChecksumByteLength + recoveryTextByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM recovery export returned malformed output.',
                );
            }

            return Object.freeze({
                canonicalRecoveryText: new TextDecoder('utf-8', {
                    fatal: true,
                }).decode(output.subarray(recoveryChecksumByteLength)),
                recoveryChecksum: output.slice(0, recoveryChecksumByteLength),
            });
        } finally {
            output.fill(0);
        }
    }

    #confirmRecovery(input: {
        canonicalRecoveryText: string;
        confirmedChecksum: Uint8Array;
    }): void {
        const activeLease = this.#requireActiveLease();
        if (typeof input.canonicalRecoveryText !== 'string') {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'Canonical recovery material must be text.',
            );
        }
        const recoveryTextBytes = new TextEncoder().encode(
            input.canonicalRecoveryText,
        );
        if (recoveryTextBytes.byteLength !== recoveryTextByteLength) {
            recoveryTextBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'RecoveryConfirmationFailed',
                'Canonical recovery material has the wrong length.',
            );
        }
        const checksum = copyExactBytes(
            input.confirmedChecksum,
            recoveryChecksumByteLength,
            'Confirmed recovery checksum',
        );
        try {
            this.#runCommand(
                localStorageRootCommands.confirmRecovery,
                this.#leaseCommandInput(
                    activeLease,
                    recoveryTextBytes,
                    checksum,
                ),
                'confirm local storage recovery material',
                'recoveryConfirmation',
            );
        } finally {
            recoveryTextBytes.fill(0);
            checksum.fill(0);
        }
    }

    async #wrapStagedRoot(): Promise<WorkerPreparedDeviceWrappingState> {
        const stagedLease = this.#requireStagedLease();
        const canonicalAssociatedData = this.#runCommand(
            localStorageRootCommands.associatedData,
            this.#leaseCommandInput(stagedLease),
            'derive device-wrapping associated data',
            'runtime',
        );
        const root = this.#runCommand(
            localStorageRootCommands.copyForDeviceWrap,
            this.#leaseCommandInput(stagedLease),
            'copy a staged root for device wrapping',
            'runtime',
        );
        let combinedCiphertext: Uint8Array<ArrayBuffer> | undefined;
        try {
            if (root.byteLength !== actionStorageRootByteLength) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM registry returned a malformed action storage root.',
                );
            }
            const generatedKey = await this.#cryptoProvider.subtle.generateKey(
                { length: 256, name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt'],
            );
            if ('privateKey' in generatedKey) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'WebCrypto returned a key pair for AES-GCM.',
                );
            }
            const nonce = this.#randomBytes(
                deviceWrappingNonceByteLength,
                'device-wrapping nonce',
            );
            combinedCiphertext = new Uint8Array(
                await this.#cryptoProvider.subtle.encrypt(
                    {
                        additionalData: arrayBufferFromBytes(
                            canonicalAssociatedData,
                        ),
                        iv: arrayBufferFromBytes(nonce),
                        name: 'AES-GCM',
                        tagLength: deviceWrappingTagByteLength * 8,
                    },
                    generatedKey,
                    arrayBufferFromBytes(root),
                ),
            );
            if (
                combinedCiphertext.byteLength !==
                actionStorageRootByteLength + deviceWrappingTagByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'WebCrypto returned a malformed device-wrapping ciphertext.',
                );
            }
            const wrappedStorageRoot = this.#runCommand(
                localStorageRootCommands.encodeDeviceEnvelope,
                this.#leaseCommandInput(
                    stagedLease,
                    nonce,
                    combinedCiphertext.subarray(0, actionStorageRootByteLength),
                    combinedCiphertext.subarray(actionStorageRootByteLength),
                ),
                'encode a device-wrapped storage-root envelope',
                'runtime',
            );
            if (
                wrappedStorageRoot.byteLength === 0 ||
                wrappedStorageRoot.byteLength >
                    maximumWrappedStorageRootByteLength
            ) {
                wrappedStorageRoot.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM registry returned a malformed device-wrapped envelope.',
                );
            }

            return Object.freeze({
                deviceKey: generatedKey,
                storageRootCommitment: new Uint8Array(0),
                wrappedStorageRoot,
            });
        } finally {
            canonicalAssociatedData.fill(0);
            root.fill(0);
            combinedCiphertext?.fill(0);
        }
    }

    #decodeDeviceEnvelope(
        binding: BrowserActionStorageRootBinding,
        expectedCommitment: Uint8Array,
        wrappedStorageRoot: Uint8Array,
    ): DecodedDeviceEnvelope {
        const output = this.#runCommand(
            localStorageRootCommands.decodeDeviceEnvelope,
            concatenateBytes(
                encodeBinding(binding),
                expectedCommitment,
                wrappedStorageRoot,
            ),
            'decode a device-wrapped storage-root envelope',
            'open',
        );
        try {
            const associatedDataByteLength = decodeUnsigned32(output, 0);
            const fixedTrailingByteLength =
                deviceWrappingNonceByteLength +
                actionStorageRootByteLength +
                deviceWrappingTagByteLength;
            if (
                associatedDataByteLength === 0 ||
                output.byteLength !==
                    wasm32WordByteLength +
                        associatedDataByteLength +
                        fixedTrailingByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM envelope decoder returned malformed output.',
                );
            }
            let offset = wasm32WordByteLength;
            const canonicalAssociatedData = output.slice(
                offset,
                (offset += associatedDataByteLength),
            );
            const nonce = output.slice(
                offset,
                (offset += deviceWrappingNonceByteLength),
            );
            const ciphertext = output.slice(
                offset,
                (offset += actionStorageRootByteLength),
            );
            const tag = output.slice(
                offset,
                (offset += deviceWrappingTagByteLength),
            );
            if (offset !== output.byteLength) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM envelope decoder returned trailing bytes.',
                );
            }

            return Object.freeze({
                canonicalAssociatedData,
                ciphertext,
                nonce,
                tag,
            });
        } finally {
            output.fill(0);
        }
    }

    #readStageOutput(
        output: Uint8Array,
        capability: Uint8Array<ArrayBuffer>,
        binding: BrowserActionStorageRootBinding,
    ): Readonly<{
        commitment: Uint8Array<ArrayBuffer>;
        lease: RootLease;
    }> {
        if (output.byteLength !== handleByteLength + foundationHashByteLength) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM storage-root stage command returned malformed output.',
            );
        }
        const handle = decodeUnsigned32(output, 0);
        if (handle === 0) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM storage-root stage command returned a zero handle.',
            );
        }

        const commitment = output.slice(handleByteLength);

        return Object.freeze({
            commitment,
            lease: {
                binding: copyBinding(binding),
                capability,
                handle,
                storageRootCommitment: commitment.slice(),
            },
        });
    }

    #runActionRandomnessCommand(
        command: number,
        input: Uint8Array<ArrayBuffer>,
        operationName: string,
        failureContext: CommandFailureContext,
    ): Uint8Array<ArrayBuffer> {
        if (input.byteLength > maximumCommandByteLength) {
            input.fill(0);
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action-randomness command input exceeds its supported byte limit.',
            );
        }
        const context = this.#actionRandomnessContext;
        return context.runExclusive(`action randomness: ${operationName}`, () => {
            let inputPointer = 0;
            let metadataPointer = 0;
            let outputPointer = 0;
            let outputByteLength = 0;
            try {
                if (input.byteLength > 0) {
                    inputPointer = context.allocate(input.byteLength);
                    if (inputPointer === 0) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'WASM could not allocate action-randomness input.',
                        );
                    }
                    new Uint8Array(
                        context.memory.buffer,
                        inputPointer,
                        input.byteLength,
                    ).set(input);
                }
                metadataPointer = context.allocate(wasm32WordByteLength * 2);
                if (metadataPointer === 0) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'WASM could not allocate action-randomness metadata.',
                    );
                }
                outputPointer = context.command(
                    command,
                    inputPointer,
                    input.byteLength,
                    metadataPointer,
                    metadataPointer + wasm32WordByteLength,
                );
                const metadata = new DataView(
                    context.memory.buffer,
                    metadataPointer,
                    wasm32WordByteLength * 2,
                );
                const status = metadata.getUint32(0, true);
                outputByteLength = metadata.getUint32(
                    wasm32WordByteLength,
                    true,
                );
                if (status !== 0) {
                    if (outputPointer !== 0 || outputByteLength !== 0) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness command returned output with an error status.',
                        );
                    }
                    this.#throwCommandStatus(status, failureContext);
                }
                if (
                    outputByteLength > maximumCommandByteLength ||
                    (outputByteLength === 0) !== (outputPointer === 0) ||
                    outputPointer + outputByteLength >
                        context.memory.buffer.byteLength
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'The WASM action-randomness command returned invalid output metadata.',
                    );
                }
                return outputByteLength === 0
                    ? new Uint8Array(0)
                    : new Uint8Array(
                          context.memory.buffer,
                          outputPointer,
                          outputByteLength,
                      ).slice();
            } catch (error) {
                throw error instanceof BrowserActionStorageCustodyError
                    ? error
                    : new BrowserActionStorageCustodyError(
                          'OwnedWorkerFailure',
                          `The WASM kernel failed to ${operationName}.`,
                          error,
                      );
            } finally {
                input.fill(0);
                if (outputPointer !== 0 && outputByteLength > 0) {
                    new Uint8Array(
                        context.memory.buffer,
                        outputPointer,
                        outputByteLength,
                    ).fill(0);
                    context.deallocate(outputPointer, outputByteLength);
                }
                if (metadataPointer !== 0) {
                    new Uint8Array(
                        context.memory.buffer,
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    ).fill(0);
                    context.deallocate(
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    );
                }
                if (inputPointer !== 0) {
                    new Uint8Array(
                        context.memory.buffer,
                        inputPointer,
                        input.byteLength,
                    ).fill(0);
                    context.deallocate(inputPointer, input.byteLength);
                }
            }
        });
    }

    #runCommand(
        command: number,
        input: Uint8Array<ArrayBuffer>,
        operationName: string,
        failureContext: CommandFailureContext,
    ): Uint8Array<ArrayBuffer> {
        if (input.byteLength > maximumCommandByteLength) {
            input.fill(0);
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The local storage-root command input exceeds its supported byte limit.',
            );
        }

        return this.#context.runExclusive(
            `local storage root: ${operationName}`,
            () => {
                let inputPointer = 0;
                let metadataPointer = 0;
                let outputPointer = 0;
                let outputByteLength = 0;
                try {
                    if (input.byteLength > 0) {
                        inputPointer = this.#context.allocate(input.byteLength);
                        if (inputPointer === 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'WASM could not allocate local storage-root input.',
                            );
                        }
                        new Uint8Array(
                            this.#context.memory.buffer,
                            inputPointer,
                            input.byteLength,
                        ).set(input);
                    }
                    metadataPointer = this.#context.allocate(
                        wasm32WordByteLength * 2,
                    );
                    if (metadataPointer === 0) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'WASM could not allocate local storage-root metadata.',
                        );
                    }
                    outputPointer = this.#context.command(
                        command,
                        inputPointer,
                        input.byteLength,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const metadata = new Uint32Array(
                        this.#context.memory.buffer,
                        metadataPointer,
                        2,
                    );
                    const status = metadata[0];
                    outputByteLength = metadata[1];
                    if (status !== 0) {
                        if (outputPointer !== 0 || outputByteLength !== 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'The WASM local storage-root command returned output with an error status.',
                            );
                        }
                        this.#throwCommandStatus(status, failureContext);
                    }
                    if (
                        outputByteLength > maximumCommandByteLength ||
                        (outputByteLength === 0) !== (outputPointer === 0)
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM local storage-root command returned invalid output metadata.',
                        );
                    }
                    if (outputByteLength === 0) {
                        return new Uint8Array(0);
                    }

                    return new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        outputByteLength,
                    ).slice();
                } catch (error) {
                    throw error instanceof BrowserActionStorageCustodyError
                        ? error
                        : new BrowserActionStorageCustodyError(
                              'OwnedWorkerFailure',
                              `The WASM kernel failed to ${operationName}.`,
                              error,
                          );
                } finally {
                    input.fill(0);
                    if (outputPointer !== 0 && outputByteLength > 0) {
                        this.#context.deallocate(
                            outputPointer,
                            outputByteLength,
                        );
                    }
                    if (metadataPointer !== 0) {
                        this.#context.deallocate(
                            metadataPointer,
                            wasm32WordByteLength * 2,
                        );
                    }
                    if (inputPointer !== 0) {
                        this.#context.deallocate(
                            inputPointer,
                            input.byteLength,
                        );
                    }
                }
            },
        );
    }

    #throwCommandStatus(
        status: number,
        failureContext: CommandFailureContext,
    ): never {
        if (
            failureContext === 'recordOpen' &&
            (status === localStorageRootStatuses.wrongContext ||
                status === localStorageRootStatuses.wrongHashOrRoot ||
                status === localStorageRootStatuses.malformedEncoding ||
                status === localStorageRootStatuses.unsupportedVersionOrSuite ||
                status === localStorageRootStatuses.wrongTypeOrLength)
        ) {
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'The local record could not be authenticated for its expected context.',
            );
        }
        if (
            status === localStorageRootStatuses.wrongContext ||
            status === localStorageRootStatuses.wrongHashOrRoot
        ) {
            throw new BrowserActionStorageCustodyError(
                failureContext === 'recoveryConfirmation'
                    ? 'RecoveryConfirmationFailed'
                    : 'CommitmentMismatch',
                'The local storage-root material does not match its required binding or commitment.',
            );
        }
        if (status === localStorageRootStatuses.consumedState) {
            throw new BrowserActionStorageCustodyError(
                failureContext === 'recoveryConfirmation'
                    ? 'RecoveryConfirmationFailed'
                    : 'InvalidState',
                'The local storage-root operation refers to consumed or replaced state.',
            );
        }
        if (
            status === localStorageRootStatuses.malformedEncoding ||
            status === localStorageRootStatuses.unsupportedVersionOrSuite ||
            status === localStorageRootStatuses.wrongTypeOrLength
        ) {
            throw new BrowserActionStorageCustodyError(
                failureContext === 'recoveryConfirmation'
                    ? 'RecoveryConfirmationFailed'
                    : failureContext === 'runtime'
                      ? 'OwnedWorkerFailure'
                      : 'InvalidCanonicalMaterial',
                'The local storage-root command refused malformed canonical material.',
            );
        }
        if (status === localStorageRootStatuses.outsideSupportedProfile) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'The local storage-root material exceeds the supported runtime profile.',
            );
        }
        if (
            status === localStorageRootStatuses.resourceLimit ||
            status === localStorageRootStatuses.staleHandle
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The local storage-root registry refused an unavailable lease.',
            );
        }
        if (status === localStorageRootStatuses.capabilityMismatch) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The local storage-root registry refused its opaque capability.',
            );
        }

        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            `The local storage-root command returned unknown status ${status}.`,
        );
    }

    #leaseCommandInput(
        lease: RootLease,
        ...trailingValues: readonly Uint8Array[]
    ): Uint8Array<ArrayBuffer> {
        return concatenateBytes(
            encodeUnsigned32(lease.handle),
            lease.capability,
            ...trailingValues,
        );
    }

    #randomCapability(): Uint8Array<ArrayBuffer> {
        const capability = this.#randomBytes(
            capabilityByteLength,
            'storage-root capability',
        );
        if (capability.every((byte) => byte === 0)) {
            capability.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Secure randomness returned an invalid storage-root capability.',
            );
        }

        return capability;
    }

    #randomBytes(byteLength: number, label: string): Uint8Array<ArrayBuffer> {
        const bytes = new Uint8Array(byteLength);
        try {
            this.#cryptoProvider.getRandomValues(bytes);
        } catch (error) {
            bytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                `Secure randomness is unavailable for the ${label}.`,
                error,
            );
        }

        return bytes;
    }

    #assertNoStagedLease(): void {
        if (this.#stagedLease !== undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A local storage root is already staged in this worker.',
            );
        }
    }

    #assertCompatibleStagedCommitment(expectedCommitment: Uint8Array): void {
        if (
            this.#stagedLease !== undefined &&
            !bytesEqual(
                this.#stagedLease.storageRootCommitment,
                expectedCommitment,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A different local storage root is already staged in this worker.',
            );
        }
    }

    #requireStagedLease(): RootLease {
        if (this.#stagedLease === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'No local storage root is staged in this worker.',
            );
        }

        return this.#stagedLease;
    }

    #requireActiveLease(): RootLease {
        if (this.#activeLease === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'No local storage root is active in this worker.',
            );
        }

        return this.#activeLease;
    }

    #discardAfterFailure(originalFailure: unknown): never {
        try {
            this.#discardStaged();
        } catch (cleanupFailure) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The local storage-root operation failed and staged-root cleanup also failed.',
                [originalFailure, cleanupFailure],
            );
        }

        throw originalFailure;
    }

    #enqueue<Result>(
        operation: () => Promise<Result> | Result,
    ): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );

        return result;
    }
}

class DeferredWasmBrowserActionStorageWorkerKernel implements BrowserActionStorageWorkerKernel {
    readonly #workerKernel: Promise<BrowserActionStorageWorkerKernel>;

    public constructor(
        workerKernel: Promise<BrowserActionStorageWorkerKernel>,
    ) {
        this.#workerKernel = workerKernel;
    }

    public async createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState> {
        return (await this.#workerKernel).createAndStageDeviceWrappingState(
            input,
        );
    }

    public async stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        return (await this.#workerKernel).stageDeviceWrappingStateOpen(input);
    }

    public async stageRecoveryValueImportAndDeviceWrapping(input: {
        binding: BrowserActionStorageRootBinding;
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<WorkerPreparedRecoveryState> {
        return (
            await this.#workerKernel
        ).stageRecoveryValueImportAndDeviceWrapping(input);
    }

    public async commitStagedActionStorageRoot(input: {
        mutationIdentifier: Uint8Array;
    }): Promise<void> {
        return (await this.#workerKernel).commitStagedActionStorageRoot(input);
    }

    public async discardStagedActionStorageRoot(): Promise<void> {
        return (await this.#workerKernel).discardStagedActionStorageRoot();
    }

    public async destroyActiveActionStorageRoot(): Promise<void> {
        return (await this.#workerKernel).destroyActiveActionStorageRoot();
    }

    public async prepareRecoveryExport(input: {
        activeMutationIdentifier: Uint8Array;
    }): Promise<LocalStorageRecoveryExportMaterial> {
        return (await this.#workerKernel).prepareRecoveryExport(input);
    }

    public async confirmRecoveryChecksum(input: {
        canonicalRecoveryText: string;
        confirmedChecksum: Uint8Array;
    }): Promise<void> {
        return (await this.#workerKernel).confirmRecoveryChecksum(input);
    }

    public async deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).deriveActiveLocalRecordIdentifier(
            input,
        );
    }

    public async sealActiveLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).sealActiveLocalRecord(input);
    }

    public async openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).openActiveLocalRecord(input);
    }

    public async hashActiveLocalRecordEnvelope(
        envelope: Uint8Array,
    ): Promise<Uint8Array> {
        return (await this.#workerKernel).hashActiveLocalRecordEnvelope(
            envelope,
        );
    }

    public async openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).openActionStateVerifierSession(input);
    }

    public async verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).verifyActionStateReservation(input);
    }

    public async verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).verifyActionRandomnessReservation(
            input,
        );
    }

    public async verifyActionStateRecovery(
        input: BrowserActionStateRecoveryVerificationInput,
    ): Promise<VerificationResult<string>> {
        return (await this.#workerKernel).verifyActionStateRecovery(input);
    }

    public async releaseActionStateObject(identifier: string): Promise<void> {
        return (await this.#workerKernel).releaseActionStateObject(identifier);
    }

    public async closeActionStateVerifierSession(
        identifier: string,
    ): Promise<void> {
        return (await this.#workerKernel).closeActionStateVerifierSession(
            identifier,
        );
    }

    public async createAndSealActionRandomness(
        input: BrowserActionRandomnessRecordContext,
    ): Promise<BrowserSealedActionRandomnessSession> {
        return (await this.#workerKernel).createAndSealActionRandomness(input);
    }

    public async openSealedActionRandomness(
        input: BrowserActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession> {
        return (await this.#workerKernel).openSealedActionRandomness(input);
    }

    public async closeActionRandomness(identifier: string): Promise<void> {
        return (await this.#workerKernel).closeActionRandomness(identifier);
    }

    public async derivePersistentProofAttempt(
        input: BrowserPersistentProofAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return (await this.#workerKernel).derivePersistentProofAttempt(input);
    }

    public async deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return (await this.#workerKernel).deriveTargetReleaseAttempt(input);
    }
}

const resolveWorkerCryptoProvider = (): Crypto => {
    const resolvedCryptoProvider = globalThis.crypto;
    if (
        resolvedCryptoProvider === undefined ||
        typeof resolvedCryptoProvider.getRandomValues !== 'function' ||
        resolvedCryptoProvider.subtle === undefined
    ) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'WebCrypto is required for local storage-root custody.',
        );
    }

    return resolvedCryptoProvider;
};

const createWorkerKernelFromLoadedKernel = (input: {
    cryptoProvider: Crypto;
    kernel: TranscriptCoreKernel;
}): BrowserActionStorageWorkerKernel => {
    const context = resolveLocalStorageRootKernelContext(input.kernel);
    if (context === undefined) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'The loaded WASM kernel does not expose the local storage-root runtime.',
        );
    }
    const actionRandomnessContext = resolveActionRandomnessKernelContext(
        input.kernel,
    );
    if (actionRandomnessContext === undefined) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'The loaded WASM kernel does not expose action-randomness custody.',
        );
    }

    const workerKernel = new WasmBrowserActionStorageWorkerKernel({
        actionRandomnessContext,
        context,
        cryptoProvider: input.cryptoProvider,
        kernel: input.kernel,
    });
    terminalSetupCheckpointKernelCommandRunners.set(workerKernel, {
        run: (command, commandInput) =>
            workerKernel.runTerminalSetupCheckpointCommand(
                command,
                commandInput,
            ),
        sampleEntropy: (byteLength, label) =>
            workerKernel.sampleTerminalSetupCheckpointEntropy(
                byteLength,
                label,
            ),
    });
    workerActionRandomnessKernelRunners.set(workerKernel, {
        close: (sessionIdentifier) =>
            workerKernel.closeActionRandomness(sessionIdentifier),
        createAndSeal: (operationInput) =>
            workerKernel.createAndSealActionRandomness(operationInput),
        openSetupMailboxRandomness: async (operationInput) =>
            workerKernel.openClosedSetupMailboxRandomness(operationInput),
        openSealed: (operationInput) =>
            workerKernel.openSealedActionRandomness(operationInput),
    });

    return workerKernel;
};

const isKernelPromise = (
    kernel: TranscriptCoreKernel | PromiseLike<TranscriptCoreKernel>,
): kernel is PromiseLike<TranscriptCoreKernel> =>
    typeof kernel === 'object' &&
    kernel !== null &&
    'then' in kernel &&
    typeof kernel.then === 'function';

/**
 * Creates the worker-owned storage-root kernel. Passing the loader promise lets
 * a module worker install its message host before WASM loading yields, so the
 * first channel request cannot be delivered before the worker listener exists.
 */
export const createWasmBrowserActionStorageWorkerKernel = (input: {
    kernel: TranscriptCoreKernel | PromiseLike<TranscriptCoreKernel>;
}): BrowserActionStorageWorkerKernel => {
    const cryptoProvider = resolveWorkerCryptoProvider();
    if (!isKernelPromise(input.kernel)) {
        return createWorkerKernelFromLoadedKernel({
            cryptoProvider,
            kernel: input.kernel,
        });
    }

    const resolvedWorkerKernel = Promise.resolve(input.kernel).then((kernel) =>
        createWorkerKernelFromLoadedKernel({ cryptoProvider, kernel }),
    );
    const deferredWorkerKernel =
        new DeferredWasmBrowserActionStorageWorkerKernel(resolvedWorkerKernel);
    terminalSetupCheckpointKernelCommandRunners.set(deferredWorkerKernel, {
        run: async (command, commandInput) =>
            runTerminalSetupCheckpointKernelCommand(
                await resolvedWorkerKernel,
                command,
                commandInput,
            ),
        sampleEntropy: async (byteLength, label) =>
            sampleTerminalSetupCheckpointEntropy(
                await resolvedWorkerKernel,
                byteLength,
                label,
            ),
    });
    workerActionRandomnessKernelRunners.set(deferredWorkerKernel, {
        close: async (sessionIdentifier) =>
            closeWorkerActionRandomness(
                await resolvedWorkerKernel,
                sessionIdentifier,
            ),
        createAndSeal: async (operationInput) =>
            createAndSealWorkerActionRandomness(
                await resolvedWorkerKernel,
                operationInput,
            ),
        openSetupMailboxRandomness: async (operationInput) =>
            openClosedWorkerSetupMailboxRandomness(
                await resolvedWorkerKernel,
                operationInput,
            ),
        openSealed: async (operationInput) =>
            openSealedWorkerActionRandomness(
                await resolvedWorkerKernel,
                operationInput,
            ),
    });

    return deferredWorkerKernel;
};

const requireWorkerActionRandomnessRunner = (
    workerKernel: BrowserActionStorageWorkerKernel,
): WorkerActionRandomnessKernelRunner => {
    const runner = workerActionRandomnessKernelRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }
    return runner;
};

export const createAndSealWorkerActionRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerActionRandomnessRecordContext,
): Promise<WorkerSealedActionRandomnessSession> =>
    requireWorkerActionRandomnessRunner(workerKernel).createAndSeal(input);

export const openSealedWorkerActionRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerActionRandomnessRecordContext &
        Readonly<{
            actionRandomnessCommitment: Uint8Array;
            canonicalEnvelope: Uint8Array;
        }>,
): Promise<BrowserOpenedActionRandomnessSession> =>
    requireWorkerActionRandomnessRunner(workerKernel).openSealed(input);

export const closeWorkerActionRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    sessionIdentifier: string,
): Promise<void> =>
    requireWorkerActionRandomnessRunner(workerKernel).close(sessionIdentifier);

export const openClosedWorkerSetupMailboxRandomness = (
    workerKernel: BrowserActionStorageWorkerKernel,
    input: WorkerSetupMailboxRandomnessInput,
): Promise<ClosedWorkerSetupMailboxRandomnessOperations> => {
    if (typeof globalThis.document !== 'undefined') {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Setup-mailbox randomness may only be consumed inside the dedicated custody worker.',
        );
    }
    return requireWorkerActionRandomnessRunner(
        workerKernel,
    ).openSetupMailboxRandomness(input);
};

const runTerminalSetupCheckpointKernelCommand = async (
    workerKernel: BrowserActionStorageWorkerKernel,
    command: number,
    input: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> => {
    const runner =
        terminalSetupCheckpointKernelCommandRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }

    return runner.run(command, input);
};

const sampleTerminalSetupCheckpointEntropy = async (
    workerKernel: BrowserActionStorageWorkerKernel,
    byteLength: number,
    label: string,
): Promise<Uint8Array<ArrayBuffer>> => {
    const runner =
        terminalSetupCheckpointKernelCommandRunners.get(workerKernel);
    if (runner === undefined) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            'The action storage worker does not belong to this WASM runtime.',
        );
    }

    return runner.sampleEntropy(byteLength, label);
};
