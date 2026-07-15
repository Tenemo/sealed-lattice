import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    UntrustedExpectedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    copyBrowserDeviceWrappingState,
    createBrowserActionStorageCustodyForOwnedWorker,
    type BrowserDeviceWrappingState,
    type BrowserDeviceWrappingStateMutation,
    type BrowserDeviceWrappingStateStorage,
    BrowserActionStorageWorkerKernel,
    LocalStorageRecoveryExportMaterial,
    WorkerPreparedDeviceWrappingState,
    WorkerPreparedRecoveryState,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-internal';
import type {
    BrowserLocalRecordIdentifierInput,
    BrowserLocalRecordOpenInput,
    BrowserLocalRecordSealInput,
} from '#packages/types/src/browser-action-storage';

export const testActionStorageRootByteLength = 48;
export const testDeviceWrappingTagByteLength = 16;
export const testRecoveryText = 'A'.repeat(708);

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
    readonly #checksum = createTestBytes(16, 201);
    readonly #cryptoProvider: Crypto;
    #activeMutationIdentifier: Uint8Array | undefined;
    #activeRoot: Uint8Array | undefined;
    #lastDeviceKey: CryptoKey | undefined;
    #lastEnvelopeNonce: Uint8Array | undefined;
    #stagedRoot: Uint8Array | undefined;
    public importCallCount = 0;

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

    public async stageRecoveryValueImportAndDeviceWrapping(input: {
        binding: BrowserActionStorageRootBinding;
        caseInsensitiveRecoveryText: string;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
    }): Promise<WorkerPreparedRecoveryState> {
        this.importCallCount += 1;
        if (
            input.caseInsensitiveRecoveryText.toUpperCase() !== testRecoveryText
        ) {
            throw new Error('Wrong test recovery text.');
        }
        const preparedState = await this.createAndStageDeviceWrappingState({
            binding: input.binding,
        });
        if (
            !testBytesEqual(
                preparedState.storageRootCommitment,
                input.untrustedExpectedCommitment.storageRootCommitment,
            )
        ) {
            await this.discardStagedActionStorageRoot();
            throw new Error('Wrong untrusted expected test commitment.');
        }

        return {
            canonicalRecoveryText: testRecoveryText,
            ...preparedState,
        };
    }

    public commitStagedActionStorageRoot(input: {
        mutationIdentifier: Uint8Array;
    }): Promise<void> {
        if (
            this.#stagedRoot === undefined ||
            input.mutationIdentifier.byteLength !== 32
        ) {
            return Promise.reject(
                new Error('No staged test storage root or invalid version.'),
            );
        }
        this.#activeRoot?.fill(0);
        this.#activeMutationIdentifier?.fill(0);
        this.#activeRoot = this.#stagedRoot;
        this.#activeMutationIdentifier = input.mutationIdentifier.slice();
        this.#stagedRoot = undefined;

        return Promise.resolve();
    }

    public discardStagedActionStorageRoot(): Promise<void> {
        this.#stagedRoot?.fill(0);
        this.#stagedRoot = undefined;

        return Promise.resolve();
    }

    public destroyActiveActionStorageRoot(): Promise<void> {
        this.#activeRoot?.fill(0);
        this.#activeMutationIdentifier?.fill(0);
        this.#activeRoot = undefined;
        this.#activeMutationIdentifier = undefined;

        return Promise.resolve();
    }

    public prepareRecoveryExport(input: {
        activeMutationIdentifier: Uint8Array;
    }): Promise<LocalStorageRecoveryExportMaterial> {
        if (
            !this.retainedRootMatchesExpected() ||
            this.#activeMutationIdentifier === undefined ||
            !testBytesEqual(
                this.#activeMutationIdentifier,
                input.activeMutationIdentifier,
            )
        ) {
            return Promise.reject(
                new Error(
                    'No accepted version-bound test storage root is active.',
                ),
            );
        }

        return Promise.resolve({
            canonicalRecoveryText: testRecoveryText,
            recoveryChecksum: this.#checksum.slice(),
        });
    }

    public confirmRecoveryChecksum(input: {
        canonicalRecoveryText: string;
        confirmedChecksum: Uint8Array;
    }): Promise<void> {
        if (
            input.canonicalRecoveryText !== testRecoveryText ||
            !testBytesEqual(input.confirmedChecksum, this.#checksum)
        ) {
            return Promise.reject(new Error('Wrong test recovery checksum.'));
        }

        return Promise.resolve();
    }

    public async deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array> {
        const activeRoot = this.#requireActiveRoot();
        const identifierInput = concatenateTestBytes(
            activeRoot,
            this.#activeMutationIdentifier as Uint8Array,
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
            return concatenateTestBytes(nonce, ciphertext);
        } finally {
            contextBytes.fill(0);
        }
    }

    public async openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array> {
        const { envelope, ...expectedContext } = input;
        if (envelope.byteLength <= nonceByteLength + 16) {
            throw new Error('Malformed test local-record envelope.');
        }
        const contextBytes = serializeTestRecordContext(expectedContext);
        const recordKey = await this.#deriveTestLocalRecordKey(contextBytes);
        try {
            return new Uint8Array(
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

    public verifyActionStateRecovery(
        input: Parameters<
            BrowserActionStorageWorkerKernel['verifyActionStateRecovery']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['verifyActionStateRecovery']
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

    public openSealedActionRandomness(
        input: Parameters<
            BrowserActionStorageWorkerKernel['openSealedActionRandomness']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['openSealedActionRandomness']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement action randomness.'),
        );
    }

    public closeActionRandomness(
        identifier: string,
    ): ReturnType<BrowserActionStorageWorkerKernel['closeActionRandomness']> {
        void identifier;
        return Promise.reject(
            new Error('The test worker does not implement action randomness.'),
        );
    }

    public derivePersistentProofAttempt(
        input: Parameters<
            BrowserActionStorageWorkerKernel['derivePersistentProofAttempt']
        >[0],
    ): ReturnType<
        BrowserActionStorageWorkerKernel['derivePersistentProofAttempt']
    > {
        void input;
        return Promise.reject(
            new Error('The test worker does not implement action randomness.'),
        );
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

    public checksum(): Uint8Array {
        return this.#checksum.slice();
    }

    public activeRootPresent(): boolean {
        return this.#activeRoot !== undefined;
    }

    public stagedRootPresent(): boolean {
        return this.#stagedRoot !== undefined;
    }

    public activeMutationIdentifierMatches(
        mutationIdentifier: Uint8Array,
    ): boolean {
        return (
            this.#activeMutationIdentifier !== undefined &&
            testBytesEqual(this.#activeMutationIdentifier, mutationIdentifier)
        );
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
        if (
            this.#activeRoot === undefined ||
            this.#activeMutationIdentifier === undefined
        ) {
            throw new Error('No accepted test storage root is active.');
        }
        return this.#activeRoot;
    }

    async #deriveTestLocalRecordKey(
        contextBytes: Uint8Array,
    ): Promise<CryptoKey> {
        const keyInput = concatenateTestBytes(
            this.#requireActiveRoot(),
            this.#activeMutationIdentifier as Uint8Array,
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

class InMemoryDeviceWrappingStateStorage implements BrowserDeviceWrappingStateStorage {
    #state: BrowserDeviceWrappingState | undefined;

    public readState(): Promise<BrowserDeviceWrappingState | undefined> {
        return Promise.resolve(
            this.#state === undefined
                ? undefined
                : copyBrowserDeviceWrappingState(this.#state),
        );
    }

    public compareAndSwapState(
        mutation: BrowserDeviceWrappingStateMutation,
    ): Promise<boolean> {
        const matches =
            mutation.expectedMutationIdentifier === undefined
                ? this.#state === undefined
                : this.#state !== undefined &&
                  testBytesEqual(
                      this.#state.mutationIdentifier,
                      mutation.expectedMutationIdentifier,
                  );
        if (!matches) {
            return Promise.resolve(false);
        }
        this.#state =
            mutation.replacement === undefined
                ? undefined
                : copyBrowserDeviceWrappingState(mutation.replacement);

        return Promise.resolve(true);
    }
}

export const createActiveTestActionStorageCustody = async (input: {
    readonly actionStorageRoot: Uint8Array;
    readonly binding: BrowserActionStorageRootBinding;
    readonly cryptoProvider: Crypto;
}): Promise<BrowserActionStorageCustody> => {
    const custody = createBrowserActionStorageCustodyForOwnedWorker({
        assertExclusiveOwnership: () => undefined,
        binding: input.binding,
        cryptoProvider: input.cryptoProvider,
        storage: new InMemoryDeviceWrappingStateStorage(),
        workerKernel: new TestActionStorageWorkerKernel({
            actionStorageRoot: input.actionStorageRoot,
            cryptoProvider: input.cryptoProvider,
        }),
    });
    const snapshot = await custody.initialize();
    await custody.openIntoOwnedWorker({
        expectedSnapshot: snapshot,
        untrustedExpectedCommitment: {
            storageRootCommitment: snapshot.storageRootCommitment,
        },
    });

    return custody;
};
