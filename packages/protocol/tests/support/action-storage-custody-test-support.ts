import type {
    BrowserActionStorageRootBinding,
    UntrustedExpectedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    BrowserActionStorageWorkerKernel,
    WorkerPreparedDeviceWrappingState,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-internal';
import type {
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
    WorkerBrowserFoundationInitializationPreparationInput,
    WorkerDerivedBrowserFoundationInitializationRecords,
    WorkerPreparedBrowserFoundationInitialization,
} from '#packages/types/src/browser-action-storage';

export const testActionStorageRootByteLength = 48;
export const testDeviceWrappingTagByteLength = 16;

const associatedDataByteLength = 64 * 5;
const nonceByteLength = 12;
const textEncoder = new TextEncoder();

export const testBytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((byte, byteIndex) => byte === right[byteIndex]);

export const createTestBytes = (byteLength: number, offset = 0): Uint8Array =>
    Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) => (byteIndex + offset) & 0xff,
    );

const arrayBufferFromBytes = (bytes: Uint8Array): ArrayBuffer => {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);

    return copy.buffer;
};

const serializeTestRecordContext = (value: unknown): Uint8Array => {
    const normalize = (currentValue: unknown): unknown => {
        if (currentValue instanceof Uint8Array) {
            return [...currentValue];
        }
        if (typeof currentValue === 'bigint') {
            return currentValue.toString(10);
        }
        if (Array.isArray(currentValue)) {
            return currentValue.map(normalize);
        }
        if (typeof currentValue === 'object' && currentValue !== null) {
            return Object.fromEntries(
                Object.entries(currentValue)
                    .sort(([leftKey], [rightKey]) =>
                        leftKey.localeCompare(rightKey),
                    )
                    .map(([key, entryValue]) => [key, normalize(entryValue)]),
            );
        }
        return currentValue;
    };

    return textEncoder.encode(JSON.stringify(normalize(value)));
};

const concatenateTestBytes = (...values: readonly Uint8Array[]): Uint8Array => {
    const combined = new Uint8Array(
        values.reduce(
            (totalByteLength, value) => totalByteLength + value.byteLength,
            0,
        ),
    );
    let offset = 0;
    for (const value of values) {
        combined.set(value, offset);
        offset += value.byteLength;
    }
    return combined;
};

export class TestActionStorageWorkerKernel implements BrowserActionStorageWorkerKernel {
    readonly #actionStorageRoot: Uint8Array;
    readonly #cryptoProvider: Crypto;
    #activeRoot: Uint8Array | undefined;
    #lastDeviceKey: CryptoKey | undefined;
    #lastEnvelopeNonce: Uint8Array | undefined;
    #lastOpenedLocalRecordEnvelope: Uint8Array | undefined;
    #lastOpenedLocalRecordPlaintext: Uint8Array | undefined;
    #lastSealedLocalRecordEnvelope: Uint8Array | undefined;
    #lastSealedLocalRecordPlaintext: Uint8Array | undefined;
    #nextRepairSessionIdentifier = 1;
    readonly #repairSessions = new Map<
        string,
        Readonly<{
            namespaceBytes: Uint8Array;
            runtimeBuildManifestHash: Uint8Array;
        }>
    >();
    #stagedRoot: Uint8Array | undefined;

    public constructor(input: {
        actionStorageRoot: Uint8Array;
        cryptoProvider: Crypto;
    }) {
        this.#actionStorageRoot = input.actionStorageRoot.slice();
        this.#cryptoProvider = input.cryptoProvider;
    }

    public async createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState> {
        const storageRootCommitment = await this.#deriveStorageRootCommitment(
            input.binding,
            this.#actionStorageRoot,
        );
        const associatedData = this.#associatedData(
            input.binding,
            storageRootCommitment,
        );
        const generatedKey = await this.#cryptoProvider.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
        if ('privateKey' in generatedKey) {
            throw new Error('Test WebCrypto returned a key pair for AES-GCM.');
        }
        const nonce = new Uint8Array(nonceByteLength);
        this.#cryptoProvider.getRandomValues(nonce);
        const combinedCiphertext = new Uint8Array(
            await this.#cryptoProvider.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: arrayBufferFromBytes(nonce),
                    additionalData: arrayBufferFromBytes(associatedData),
                    tagLength: testDeviceWrappingTagByteLength * 8,
                },
                generatedKey,
                arrayBufferFromBytes(this.#actionStorageRoot),
            ),
        );
        const wrappedStorageRoot = this.#encodeEnvelope({
            canonicalAssociatedData: associatedData,
            ciphertext: combinedCiphertext.slice(
                0,
                testActionStorageRootByteLength,
            ),
            nonce,
            tag: combinedCiphertext.slice(testActionStorageRootByteLength),
        });
        combinedCiphertext.fill(0);
        this.#replaceStagedRoot(this.#actionStorageRoot);
        this.#lastDeviceKey = generatedKey;
        this.#lastEnvelopeNonce = nonce.slice();

        return {
            deviceKey: generatedKey,
            storageRootCommitment,
            wrappedStorageRoot,
        };
    }

    public async stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        const envelope = this.decodeEnvelope(input.state.wrappedStorageRoot);
        const expectedAssociatedData = this.#associatedData(
            input.binding,
            input.untrustedExpectedCommitment.storageRootCommitment,
        );
        if (
            !testBytesEqual(
                envelope.canonicalAssociatedData,
                expectedAssociatedData,
            ) ||
            !testBytesEqual(
                input.state.storageRootCommitment,
                input.untrustedExpectedCommitment.storageRootCommitment,
            )
        ) {
            throw new Error('Wrong test device-wrapping associated data.');
        }
        const combinedCiphertext = new Uint8Array(
            envelope.ciphertext.byteLength + envelope.tag.byteLength,
        );
        combinedCiphertext.set(envelope.ciphertext);
        combinedCiphertext.set(envelope.tag, envelope.ciphertext.byteLength);
        let openedRoot: Uint8Array;
        try {
            openedRoot = new Uint8Array(
                await this.#cryptoProvider.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: arrayBufferFromBytes(envelope.nonce),
                        additionalData: arrayBufferFromBytes(
                            envelope.canonicalAssociatedData,
                        ),
                        tagLength: testDeviceWrappingTagByteLength * 8,
                    },
                    input.state.deviceKey,
                    arrayBufferFromBytes(combinedCiphertext),
                ),
            );
        } finally {
            combinedCiphertext.fill(0);
        }
        const recomputedCommitment = await this.#deriveStorageRootCommitment(
            input.binding,
            openedRoot,
        );
        if (
            !testBytesEqual(openedRoot, this.#actionStorageRoot) ||
            !testBytesEqual(
                recomputedCommitment,
                input.untrustedExpectedCommitment.storageRootCommitment,
            )
        ) {
            openedRoot.fill(0);
            throw new Error('Wrong test action storage root.');
        }
        this.#replaceStagedRoot(openedRoot);
        openedRoot.fill(0);
        this.#lastDeviceKey = input.state.deviceKey;
        this.#lastEnvelopeNonce = envelope.nonce.slice();
    }

    public commitStagedActionStorageRoot(): Promise<void> {
        if (this.#stagedRoot === undefined) {
            return Promise.reject(new Error('No staged test storage root.'));
        }
        this.#activeRoot?.fill(0);
        this.#closeAllRepairSessions();
        this.#activeRoot = this.#stagedRoot;
        this.#stagedRoot = undefined;

        return Promise.resolve();
    }

    public discardStagedActionStorageRoot(): Promise<void> {
        this.#stagedRoot?.fill(0);
        this.#stagedRoot = undefined;

        return Promise.resolve();
    }

    public destroyActiveActionStorageRoot(): Promise<void> {
        this.#closeAllRepairSessions();
        this.#activeRoot?.fill(0);
        this.#activeRoot = undefined;

        return Promise.resolve();
    }

    public async deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        const activeRoot = this.#requireActiveRoot();
        const identifierInput = concatenateTestBytes(
            activeRoot,
            serializeTestRecordContext(input),
        );
        try {
            return new Uint8Array(
                await this.#cryptoProvider.subtle.digest(
                    'SHA-512',
                    arrayBufferFromBytes(identifierInput),
                ),
            );
        } finally {
            identifierInput.fill(0);
        }
    }

    public async sealActiveLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array> {
        const { plaintext, ...expectedContext } = input;
        this.#lastSealedLocalRecordPlaintext = plaintext;
        const contextBytes = serializeTestRecordContext(expectedContext);
        const recordKey = await this.#deriveTestLocalRecordKey(contextBytes);
        const nonce = new Uint8Array(nonceByteLength);
        this.#cryptoProvider.getRandomValues(nonce);
        try {
            const ciphertext = new Uint8Array(
                await this.#cryptoProvider.subtle.encrypt(
                    {
                        additionalData: arrayBufferFromBytes(contextBytes),
                        iv: arrayBufferFromBytes(nonce),
                        name: 'AES-GCM',
                        tagLength: 128,
                    },
                    recordKey,
                    arrayBufferFromBytes(plaintext),
                ),
            );
            const envelope = concatenateTestBytes(nonce, ciphertext);
            this.#lastSealedLocalRecordEnvelope = envelope;
            return envelope;
        } finally {
            contextBytes.fill(0);
        }
    }

    public async openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        const { envelope, ...expectedContext } = input;
        this.#lastOpenedLocalRecordEnvelope = envelope;
        if (envelope.byteLength <= nonceByteLength + 16) {
            throw new Error('Malformed test local-record envelope.');
        }
        const contextBytes = serializeTestRecordContext(expectedContext);
        const recordKey = await this.#deriveTestLocalRecordKey(contextBytes);
        try {
            const plaintext = new Uint8Array(
                await this.#cryptoProvider.subtle.decrypt(
                    {
                        additionalData: arrayBufferFromBytes(contextBytes),
                        iv: arrayBufferFromBytes(
                            envelope.subarray(0, nonceByteLength),
                        ),
                        name: 'AES-GCM',
                        tagLength: 128,
                    },
                    recordKey,
                    arrayBufferFromBytes(envelope.subarray(nonceByteLength)),
                ),
            );
            this.#lastOpenedLocalRecordPlaintext = plaintext;
            return plaintext;
        } finally {
            contextBytes.fill(0);
        }
    }

    public async hashActiveLocalRecordEnvelope(
        envelope: Uint8Array,
    ): Promise<Uint8Array> {
        this.#requireActiveRoot();
        return new Uint8Array(
            await this.#cryptoProvider.subtle.digest(
                'SHA-512',
                arrayBufferFromBytes(envelope),
            ),
        );
    }

    public async openActiveAuthenticatedRepairProtection(
        input: Parameters<
            BrowserActionStorageWorkerKernel['openActiveAuthenticatedRepairProtection']
        >[0],
    ): Promise<
        Awaited<
            ReturnType<
                BrowserActionStorageWorkerKernel['openActiveAuthenticatedRepairProtection']
            >
        >
    > {
        this.#requireActiveRoot();
        const namespaceBytes = textEncoder.encode(input.namespace);
        const runtimeBuildManifestHash = input.runtimeBuildManifestHash.slice();
        const repairContext = this.#repairContext({
            namespaceBytes,
            runtimeBuildManifestHash,
        });
        const repairIdentity = new Uint8Array(
            await this.#cryptoProvider.subtle.digest(
                'SHA-512',
                arrayBufferFromBytes(repairContext),
            ),
        );
        repairContext.fill(0);
        const repairProtectionSessionIdentifier =
            this.#nextRepairSessionIdentifier.toString(16).padStart(64, '0');
        this.#nextRepairSessionIdentifier += 1;
        this.#repairSessions.set(repairProtectionSessionIdentifier, {
            namespaceBytes,
            runtimeBuildManifestHash,
        });
        return Object.freeze({
            repairIdentity,
            repairProtectionSessionIdentifier,
        });
    }

    public async sealAuthenticatedRepairHead(
        input: Parameters<
            BrowserActionStorageWorkerKernel['sealAuthenticatedRepairHead']
        >[0],
    ): Promise<Uint8Array> {
        const repairContext = this.#repairSessionContext(
            input.repairProtectionSessionIdentifier,
        );
        const key = await this.#deriveRepairKey(repairContext);
        const nonce = new Uint8Array(nonceByteLength);
        this.#cryptoProvider.getRandomValues(nonce);
        try {
            const ciphertext = new Uint8Array(
                await this.#cryptoProvider.subtle.encrypt(
                    {
                        additionalData: arrayBufferFromBytes(repairContext),
                        iv: arrayBufferFromBytes(nonce),
                        name: 'AES-GCM',
                        tagLength: 128,
                    },
                    key,
                    arrayBufferFromBytes(input.plaintext),
                ),
            );
            return concatenateTestBytes(nonce, ciphertext);
        } finally {
            nonce.fill(0);
            repairContext.fill(0);
        }
    }

    public async openAuthenticatedRepairHead(
        input: Parameters<
            BrowserActionStorageWorkerKernel['openAuthenticatedRepairHead']
        >[0],
    ): Promise<Uint8Array> {
        if (input.canonicalEnvelope.byteLength <= nonceByteLength + 16) {
            throw new Error('Malformed test authenticated repair envelope.');
        }
        const repairContext = this.#repairSessionContext(
            input.repairProtectionSessionIdentifier,
        );
        const key = await this.#deriveRepairKey(repairContext);
        try {
            return new Uint8Array(
                await this.#cryptoProvider.subtle.decrypt(
                    {
                        additionalData: arrayBufferFromBytes(repairContext),
                        iv: arrayBufferFromBytes(
                            input.canonicalEnvelope.subarray(
                                0,
                                nonceByteLength,
                            ),
                        ),
                        name: 'AES-GCM',
                        tagLength: 128,
                    },
                    key,
                    arrayBufferFromBytes(
                        input.canonicalEnvelope.subarray(nonceByteLength),
                    ),
                ),
            );
        } finally {
            repairContext.fill(0);
        }
    }

    public async deriveAuthenticatedRepairHeadDigest(
        input: Parameters<
            BrowserActionStorageWorkerKernel['deriveAuthenticatedRepairHeadDigest']
        >[0],
    ): Promise<Uint8Array> {
        const repairContext = this.#repairSessionContext(
            input.repairProtectionSessionIdentifier,
        );
        const digestInput = concatenateTestBytes(
            repairContext,
            input.sealedHeadBytes,
        );
        try {
            return new Uint8Array(
                await this.#cryptoProvider.subtle.digest(
                    'SHA-512',
                    arrayBufferFromBytes(digestInput),
                ),
            );
        } finally {
            repairContext.fill(0);
            digestInput.fill(0);
        }
    }

    public closeAuthenticatedRepairProtection(
        identifier: string,
    ): ReturnType<
        BrowserActionStorageWorkerKernel['closeAuthenticatedRepairProtection']
    > {
        const session = this.#repairSessions.get(identifier);
        session?.namespaceBytes.fill(0);
        session?.runtimeBuildManifestHash.fill(0);
        this.#repairSessions.delete(identifier);
        return Promise.resolve();
    }

    public async prepareBrowserFoundationInitialization(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerPreparedBrowserFoundationInitialization> {
        const actionRandomnessPlaintext = serializeTestRecordContext({
            actionRandomnessRecordContext: input.actionRandomnessRecordContext,
            kind: 'action-randomness',
        });
        const actionRandomnessCommitment = new Uint8Array(
            await this.#cryptoProvider.subtle.digest(
                'SHA-512',
                arrayBufferFromBytes(actionRandomnessPlaintext),
            ),
        );
        const canonicalActionRandomnessEnvelope =
            actionRandomnessPlaintext.slice();
        try {
            const actionRandomnessLocalRecordIdentifier =
                await this.deriveActiveLocalRecordIdentifier({
                    recordType: 'actionRandomness',
                });
            const witnessStateRecords = await Promise.all(
                input.orderedWitnessBindings.map(
                    async (witnessBinding, roleIndex) => {
                        const authorizedEmptyPlaintext =
                            serializeTestRecordContext({
                                roleIndex,
                                runtimeBuildManifestHash:
                                    input.runtimeBuildManifestHash,
                                version: 1,
                                witnessBinding,
                            });
                        const stateKey = new Uint8Array(
                            await this.#cryptoProvider.subtle.digest(
                                'SHA-512',
                                arrayBufferFromBytes(authorizedEmptyPlaintext),
                            ),
                        );
                        const identifierInput = {
                            recordType: 'witnessState' as const,
                            stateKey,
                        };
                        try {
                            const localRecordIdentifier =
                                await this.deriveActiveLocalRecordIdentifier(
                                    identifierInput,
                                );
                            const canonicalEnvelope =
                                await this.sealActiveLocalRecord({
                                    actionRandomnessCommitment,
                                    identifierInput,
                                    plaintext: authorizedEmptyPlaintext,
                                    recordVersion: 0n,
                                });
                            return Object.freeze({
                                authorizedEmptyPlaintext:
                                    authorizedEmptyPlaintext.slice(),
                                canonicalEnvelope,
                                envelopeHash:
                                    await this.hashActiveLocalRecordEnvelope(
                                        canonicalEnvelope,
                                    ),
                                localRecordIdentifier,
                                roleIndex,
                                stateKey: stateKey.slice(),
                            });
                        } finally {
                            authorizedEmptyPlaintext.fill(0);
                            stateKey.fill(0);
                        }
                    },
                ),
            );

            return Object.freeze({
                actionRandomness: Object.freeze({
                    actionRandomnessCommitment:
                        actionRandomnessCommitment.slice(),
                    actionRandomnessSessionIdentifier: '11'.repeat(32),
                    canonicalEnvelope: canonicalActionRandomnessEnvelope,
                    envelopeHash: await this.hashActiveLocalRecordEnvelope(
                        canonicalActionRandomnessEnvelope,
                    ),
                    localRecordIdentifier:
                        actionRandomnessLocalRecordIdentifier,
                }),
                witnessStateRecords: Object.freeze(witnessStateRecords),
            });
        } catch (error) {
            canonicalActionRandomnessEnvelope.fill(0);
            throw error;
        } finally {
            actionRandomnessPlaintext.fill(0);
            actionRandomnessCommitment.fill(0);
        }
    }

    public async deriveBrowserFoundationInitializationRecords(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerDerivedBrowserFoundationInitializationRecords> {
        const actionRandomnessLocalRecordIdentifier =
            await this.deriveActiveLocalRecordIdentifier({
                recordType: 'actionRandomness',
            });
        const witnessStateRecords = await Promise.all(
            input.orderedWitnessBindings.map(
                async (witnessBinding, roleIndex) => {
                    const authorizedEmptyPlaintext = serializeTestRecordContext(
                        {
                            roleIndex,
                            runtimeBuildManifestHash:
                                input.runtimeBuildManifestHash,
                            version: 1,
                            witnessBinding,
                        },
                    );
                    const stateKey = new Uint8Array(
                        await this.#cryptoProvider.subtle.digest(
                            'SHA-512',
                            arrayBufferFromBytes(authorizedEmptyPlaintext),
                        ),
                    );
                    const localRecordIdentifier =
                        await this.deriveActiveLocalRecordIdentifier({
                            recordType: 'witnessState',
                            stateKey,
                        });
                    return Object.freeze({
                        authorizedEmptyPlaintext,
                        localRecordIdentifier,
                        roleIndex,
                        stateKey,
                    });
                },
            ),
        );
        return Object.freeze({
            actionRandomnessLocalRecordIdentifier,
            witnessStateRecords: Object.freeze(witnessStateRecords),
        });
    }

    public openActionStateVerifierSession(
        input: Parameters<
            BrowserActionStorageWorkerKernel['openActionStateVerifierSession']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['openActionStateVerifierSession']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement state verification.'),
        );
    }

    public verifyActionStateReservation(
        input: Parameters<
            BrowserActionStorageWorkerKernel['verifyActionStateReservation']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['verifyActionStateReservation']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement state verification.'),
        );
    }

    public verifyActionRandomnessReservation(
        input: Parameters<
            BrowserActionStorageWorkerKernel['verifyActionRandomnessReservation']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['verifyActionRandomnessReservation']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement state verification.'),
        );
    }

    public releaseActionStateObject(
        identifier: string,
    ): ReturnType<
        BrowserActionStorageWorkerKernel['releaseActionStateObject']
    > {
        void identifier;
        return Promise.reject(
            new Error('The test worker does not implement state verification.'),
        );
    }

    public closeActionStateVerifierSession(
        identifier: string,
    ): ReturnType<
        BrowserActionStorageWorkerKernel['closeActionStateVerifierSession']
    > {
        void identifier;
        return Promise.reject(
            new Error('The test worker does not implement state verification.'),
        );
    }

    public createAndSealActionRandomness(
        input: Parameters<
            BrowserActionStorageWorkerKernel['createAndSealActionRandomness']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['createAndSealActionRandomness']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement action randomness.'),
        );
    }

    public async openSealedActionRandomness(
        input: Parameters<
            BrowserActionStorageWorkerKernel['openSealedActionRandomness']
        >[0],
    ): Promise<
        Awaited<
            ReturnType<
                BrowserActionStorageWorkerKernel['openSealedActionRandomness']
            >
        >
    > {
        const expectedPlaintext = serializeTestRecordContext({
            actionRandomnessRecordContext: {
                ...(input.predecessorRecordHash === undefined
                    ? {}
                    : {
                          predecessorRecordHash: input.predecessorRecordHash,
                      }),
                recordVersion: input.recordVersion,
            },
            kind: 'action-randomness',
        });
        const expectedCommitment = new Uint8Array(
            await this.#cryptoProvider.subtle.digest(
                'SHA-512',
                arrayBufferFromBytes(expectedPlaintext),
            ),
        );
        try {
            if (
                !testBytesEqual(input.canonicalEnvelope, expectedPlaintext) ||
                !testBytesEqual(
                    input.actionRandomnessCommitment,
                    expectedCommitment,
                )
            ) {
                throw new Error(
                    'The test action-randomness envelope is not authentic.',
                );
            }
            return Object.freeze({
                actionRandomnessCommitment:
                    input.actionRandomnessCommitment.slice(),
                actionRandomnessSessionIdentifier: '12'.repeat(32),
            });
        } finally {
            expectedPlaintext.fill(0);
            expectedCommitment.fill(0);
        }
    }

    public closeActionRandomness(
        identifier: string,
    ): ReturnType<BrowserActionStorageWorkerKernel['closeActionRandomness']> {
        void identifier;
        return Promise.resolve();
    }

    public deriveTargetReleaseAttempt(
        input: Parameters<
            BrowserActionStorageWorkerKernel['deriveTargetReleaseAttempt']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['deriveTargetReleaseAttempt']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement action randomness.'),
        );
    }

    public activeRootPresent(): boolean {
        return this.#activeRoot !== undefined;
    }

    public stagedRootPresent(): boolean {
        return this.#stagedRoot !== undefined;
    }

    public retainedRootMatchesExpected(): boolean {
        return (
            this.#activeRoot !== undefined &&
            testBytesEqual(this.#activeRoot, this.#actionStorageRoot)
        );
    }

    public lastEnvelopeNonce(): Uint8Array | undefined {
        return this.#lastEnvelopeNonce?.slice();
    }

    public lastOpenedLocalRecordBuffersAreZeroed(): boolean {
        return (
            this.#lastOpenedLocalRecordEnvelope !== undefined &&
            this.#lastOpenedLocalRecordPlaintext !== undefined &&
            this.#lastOpenedLocalRecordEnvelope.every((byte) => byte === 0) &&
            this.#lastOpenedLocalRecordPlaintext.every((byte) => byte === 0)
        );
    }

    public lastSealedLocalRecordBuffersAreZeroed(): boolean {
        return (
            this.#lastSealedLocalRecordEnvelope !== undefined &&
            this.#lastSealedLocalRecordPlaintext !== undefined &&
            this.#lastSealedLocalRecordEnvelope.every((byte) => byte === 0) &&
            this.#lastSealedLocalRecordPlaintext.every((byte) => byte === 0)
        );
    }

    public lastDeviceKeyIsNonExtractable(): boolean {
        return this.#lastDeviceKey?.extractable === false;
    }

    public async lastDeviceKeyExportIsRefused(): Promise<boolean> {
        if (this.#lastDeviceKey === undefined) {
            return false;
        }
        try {
            await this.#cryptoProvider.subtle.exportKey(
                'raw',
                this.#lastDeviceKey,
            );

            return false;
        } catch {
            return true;
        }
    }

    public decodeEnvelope(canonicalEnvelope: Uint8Array): Readonly<{
        canonicalAssociatedData: Uint8Array;
        ciphertext: Uint8Array;
        nonce: Uint8Array;
        tag: Uint8Array;
    }> {
        const expectedByteLength =
            associatedDataByteLength +
            nonceByteLength +
            testActionStorageRootByteLength +
            testDeviceWrappingTagByteLength;
        if (canonicalEnvelope.byteLength !== expectedByteLength) {
            throw new Error('Malformed test envelope.');
        }
        let offset = 0;
        const canonicalAssociatedData = canonicalEnvelope.slice(
            offset,
            (offset += associatedDataByteLength),
        );
        const nonce = canonicalEnvelope.slice(
            offset,
            (offset += nonceByteLength),
        );
        const ciphertext = canonicalEnvelope.slice(
            offset,
            (offset += testActionStorageRootByteLength),
        );
        const tag = canonicalEnvelope.slice(offset);

        return { canonicalAssociatedData, ciphertext, nonce, tag };
    }

    #encodeEnvelope(input: {
        canonicalAssociatedData: Uint8Array;
        ciphertext: Uint8Array;
        nonce: Uint8Array;
        tag: Uint8Array;
    }): Uint8Array {
        const encoded = new Uint8Array(
            associatedDataByteLength +
                nonceByteLength +
                testActionStorageRootByteLength +
                testDeviceWrappingTagByteLength,
        );
        let offset = 0;
        encoded.set(input.canonicalAssociatedData, offset);
        offset += associatedDataByteLength;
        encoded.set(input.nonce, offset);
        offset += nonceByteLength;
        encoded.set(input.ciphertext, offset);
        offset += testActionStorageRootByteLength;
        encoded.set(input.tag, offset);

        return encoded;
    }

    #replaceStagedRoot(root: Uint8Array): void {
        this.#stagedRoot?.fill(0);
        this.#stagedRoot = root.slice();
    }

    #requireActiveRoot(): Uint8Array {
        if (this.#activeRoot === undefined) {
            throw new Error('No accepted test storage root is active.');
        }
        return this.#activeRoot;
    }

    #closeAllRepairSessions(): void {
        for (const session of this.#repairSessions.values()) {
            session.namespaceBytes.fill(0);
            session.runtimeBuildManifestHash.fill(0);
        }
        this.#repairSessions.clear();
    }

    #repairContext(input: {
        namespaceBytes: Uint8Array;
        runtimeBuildManifestHash: Uint8Array;
    }): Uint8Array {
        return concatenateTestBytes(
            textEncoder.encode(
                'sealed-lattice/test/authenticated-repair-protection/v1',
            ),
            this.#requireActiveRoot(),
            input.runtimeBuildManifestHash,
            input.namespaceBytes,
        );
    }

    #repairSessionContext(identifier: string): Uint8Array {
        const session = this.#repairSessions.get(identifier);
        if (session === undefined) {
            throw new Error(
                'The test authenticated repair session is unavailable.',
            );
        }
        return this.#repairContext(session);
    }

    async #deriveRepairKey(repairContext: Uint8Array): Promise<CryptoKey> {
        const keyBytes = new Uint8Array(
            await this.#cryptoProvider.subtle.digest(
                'SHA-256',
                arrayBufferFromBytes(repairContext),
            ),
        );
        try {
            return await this.#cryptoProvider.subtle.importKey(
                'raw',
                arrayBufferFromBytes(keyBytes),
                'AES-GCM',
                false,
                ['encrypt', 'decrypt'],
            );
        } finally {
            keyBytes.fill(0);
        }
    }

    async #deriveTestLocalRecordKey(
        contextBytes: Uint8Array,
    ): Promise<CryptoKey> {
        const keyInput = concatenateTestBytes(
            this.#requireActiveRoot(),
            contextBytes,
        );
        try {
            const keyBytes = new Uint8Array(
                await this.#cryptoProvider.subtle.digest(
                    'SHA-256',
                    arrayBufferFromBytes(keyInput),
                ),
            );
            try {
                return await this.#cryptoProvider.subtle.importKey(
                    'raw',
                    arrayBufferFromBytes(keyBytes),
                    'AES-GCM',
                    false,
                    ['encrypt', 'decrypt'],
                );
            } finally {
                keyBytes.fill(0);
            }
        } finally {
            keyInput.fill(0);
        }
    }

    #associatedData(
        binding: BrowserActionStorageRootBinding,
        storageRootCommitment: Uint8Array,
    ): Uint8Array {
        const associatedData = new Uint8Array(associatedDataByteLength);
        let offset = 0;
        for (const value of [
            binding.suiteId,
            binding.ceremonyContextHash,
            binding.actionContextHash,
            binding.participantId,
            storageRootCommitment,
        ]) {
            if (value.byteLength !== 64) {
                throw new Error('Malformed test storage-root binding.');
            }
            associatedData.set(value, offset);
            offset += value.byteLength;
        }

        return associatedData;
    }

    async #deriveStorageRootCommitment(
        binding: BrowserActionStorageRootBinding,
        actionStorageRoot: Uint8Array,
    ): Promise<Uint8Array> {
        const input = new Uint8Array(64 * 4 + actionStorageRoot.byteLength);
        let offset = 0;
        for (const value of [
            binding.suiteId,
            binding.ceremonyContextHash,
            binding.actionContextHash,
            binding.participantId,
            actionStorageRoot,
        ]) {
            input.set(value, offset);
            offset += value.byteLength;
        }
        const digest = new Uint8Array(
            await this.#cryptoProvider.subtle.digest(
                'SHA-512',
                arrayBufferFromBytes(input),
            ),
        );
        input.fill(0);

        return digest;
    }
}
