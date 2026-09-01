import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import {
    instantiateConstructionKernelCommandRuntime,
    type ConstructionKernelCommandRuntime,
    type FoundationKernelLoaderOptions,
} from './foundation-kernel/kernel-runtime.js';

const generateKeyPairCommand = 4;
const encryptMessageCommand = 5;
const decryptMessageCommand = 6;

export const pairEncryptionKeyGenerationRandomnessByteLength = 6_912;
export const pairEncryptionRandomnessByteLength = 896;
export const pairEncryptionKeyByteLength = 4_608;
export const pairDecryptionKeyByteLength = 1_152;
export const pairCiphertextByteLength = 1_088;
export const pairMessageByteLength = 32;

export type PairEncryptionKeyPair = Readonly<{
    encryptionKey: Uint8Array;
    decryptionKey: Uint8Array;
}>;

export type PairEncryptionRuntime = Readonly<{
    generateKeyPair(randomness: Uint8Array): PairEncryptionKeyPair;
    encrypt(
        encryptionKey: Uint8Array,
        message: Uint8Array,
        randomness: Uint8Array,
    ): Uint8Array;
    decrypt(decryptionKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}>;

const copyExactResponse = (
    bytes: Uint8Array,
    expectedLength: number,
    name: string,
): Uint8Array => {
    requireExactConstructionBytes(bytes, expectedLength, name);
    return Uint8Array.from(bytes);
};

export const openPairEncryptionRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): PairEncryptionRuntime => ({
    generateKeyPair: (randomness) => {
        requireExactConstructionBytes(
            randomness,
            pairEncryptionKeyGenerationRandomnessByteLength,
            'randomness',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(generateKeyPairCommand);
        request.writeBytes(randomness);
        return executeConstructionCommand(kernel, request, (reader) => {
            const encryptionKey = copyExactResponse(
                reader.readBytes(),
                pairEncryptionKeyByteLength,
                'encryptionKey',
            );
            const decryptionKey = copyExactResponse(
                reader.readBytes(),
                pairDecryptionKeyByteLength,
                'decryptionKey',
            );
            return { encryptionKey, decryptionKey };
        });
    },
    encrypt: (encryptionKey, message, randomness) => {
        requireExactConstructionBytes(
            encryptionKey,
            pairEncryptionKeyByteLength,
            'encryptionKey',
        );
        requireExactConstructionBytes(
            message,
            pairMessageByteLength,
            'message',
        );
        requireExactConstructionBytes(
            randomness,
            pairEncryptionRandomnessByteLength,
            'randomness',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encryptMessageCommand);
        request.writeBytes(encryptionKey);
        request.writeBytes(message);
        request.writeBytes(randomness);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyExactResponse(
                reader.readBytes(),
                pairCiphertextByteLength,
                'ciphertext',
            ),
        );
    },
    decrypt: (decryptionKey, ciphertext) => {
        requireExactConstructionBytes(
            decryptionKey,
            pairDecryptionKeyByteLength,
            'decryptionKey',
        );
        requireExactConstructionBytes(
            ciphertext,
            pairCiphertextByteLength,
            'ciphertext',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(decryptMessageCommand);
        request.writeBytes(decryptionKey);
        request.writeBytes(ciphertext);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyExactResponse(
                reader.readBytes(),
                pairMessageByteLength,
                'message',
            ),
        );
    },
});

export const createPairEncryptionRuntimeLoader = (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions = {},
): (() => Promise<PairEncryptionRuntime>) => {
    let runtimePromise: Promise<PairEncryptionRuntime> | undefined;
    return async () => {
        runtimePromise ??= instantiateConstructionKernelCommandRuntime(
            foundationKernelUrl,
            options,
        )
            .then(openPairEncryptionRuntime)
            .catch((error: unknown) => {
                runtimePromise = undefined;
                throw error;
            });
        return runtimePromise;
    };
};
