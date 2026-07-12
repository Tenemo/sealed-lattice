import type {
    BrowserActionStorageRootBinding,
    ExternallyVerifiedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import type {
    BrowserActionStorageWorkerKernel,
    LocalStorageRecoveryExportMaterial,
    WorkerPreparedDeviceWrappingState,
    WorkerPreparedRecoveryState,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-internal';

export const testActionStorageRootByteLength = 48;
export const testDeviceWrappingTagByteLength = 16;
export const testRecoveryText = 'A'.repeat(708);

const associatedDataByteLength = 64 * 5;
const nonceByteLength = 12;

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
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        const envelope = this.decodeEnvelope(input.state.wrappedStorageRoot);
        const expectedAssociatedData = this.#associatedData(
            input.binding,
            input.externallyVerifiedCommitment.storageRootCommitment,
        );
        if (
            !testBytesEqual(
                envelope.canonicalAssociatedData,
                expectedAssociatedData,
            ) ||
            !testBytesEqual(
                input.state.storageRootCommitment,
                input.externallyVerifiedCommitment.storageRootCommitment,
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
                input.externallyVerifiedCommitment.storageRootCommitment,
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
        externallyVerifiedCommitment: ExternallyVerifiedStorageRootCommitment;
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
                input.externallyVerifiedCommitment.storageRootCommitment,
            )
        ) {
            await this.discardStagedActionStorageRoot();
            throw new Error('Wrong externally verified test commitment.');
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
