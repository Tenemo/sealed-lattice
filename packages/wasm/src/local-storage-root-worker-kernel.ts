import {
    BrowserActionStorageCustodyError,
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

import type { TranscriptCoreKernel } from './transcript-core-bridge/kernel-types.js';
import {
    resolveLocalStorageRootKernelContext,
    type LocalStorageRootKernelContext,
} from './transcript-core-bridge/local-storage-root-kernel-context.js';

const actionStorageRootByteLength = 48;
const capabilityByteLength = 32;
const deviceWrappingNonceByteLength = 12;
const deviceWrappingTagByteLength = 16;
const foundationHashByteLength = 64;
const handleByteLength = 4;
const localRecordNonceByteLength = 12;
const maximumLocalRecordPlaintextByteLength = 1_048_576;
const maximumCommandByteLength = 1_572_864;
const maximumWrappedStorageRootByteLength = 492;
const mutationIdentifierByteLength = 32;
const recoveryChecksumByteLength = 16;
const recoveryTextByteLength = 708;
const wasm32WordByteLength = 4;

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
    capability: Uint8Array<ArrayBuffer>;
    handle: number;
    storageRootCommitment: Uint8Array<ArrayBuffer>;
};

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

const untrustedExpectedCommitmentBytes = (
    value: UntrustedExpectedStorageRootCommitment,
): Uint8Array<ArrayBuffer> =>
    copyExactBytes(
        value.storageRootCommitment,
        foundationHashByteLength,
        'Untrusted expected storage-root commitment',
    );

class WasmBrowserActionStorageWorkerKernel implements BrowserActionStorageWorkerKernel {
    readonly #context: LocalStorageRootKernelContext;
    readonly #cryptoProvider: Crypto;
    #activeLease: RootLease | undefined;
    #operationTail: Promise<void> = Promise.resolve();
    #stagedLease: RootLease | undefined;

    public constructor(input: {
        context: LocalStorageRootKernelContext;
        cryptoProvider: Crypto;
    }) {
        this.#context = input.context;
        this.#cryptoProvider = input.cryptoProvider;
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
            const staged = this.#readStageOutput(stageOutput, capability);
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
            const staged = this.#readStageOutput(stageOutput, capability);
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
                capability,
                handle,
                storageRootCommitment: commitment.slice(),
            },
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
}

const resolveWorkerCryptoProvider = (
    cryptoProvider: Crypto | undefined,
): Crypto => {
    const resolvedCryptoProvider = cryptoProvider ?? globalThis.crypto;
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
    cryptoProvider?: Crypto;
    kernel: TranscriptCoreKernel;
}): BrowserActionStorageWorkerKernel => {
    const context = resolveLocalStorageRootKernelContext(input.kernel);
    if (context === undefined) {
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'The loaded WASM kernel does not expose the local storage-root runtime.',
        );
    }

    const workerKernel = new WasmBrowserActionStorageWorkerKernel({
        context,
        cryptoProvider: resolveWorkerCryptoProvider(input.cryptoProvider),
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
    cryptoProvider?: Crypto;
    kernel: TranscriptCoreKernel | PromiseLike<TranscriptCoreKernel>;
}): BrowserActionStorageWorkerKernel => {
    const cryptoProvider = resolveWorkerCryptoProvider(input.cryptoProvider);
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

    return deferredWorkerKernel;
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
