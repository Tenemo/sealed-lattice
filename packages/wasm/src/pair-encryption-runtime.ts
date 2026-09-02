import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import { type ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';

const generateKeyPairCommand = 4;

export const pairEncryptionKeyGenerationRandomnessByteLength = 64;
export const pairEncryptionRandomnessByteLength = 32;
export const pairEncryptionKeyByteLength = 1_184;
export const pairDecryptionKeyByteLength = 2_400;

export type PairEncryptionKeyPair = Readonly<{
    encryptionKey: Uint8Array;
    decryptionKey: Uint8Array;
}>;

export type PairEncryptionRuntime = Readonly<{
    generateKeyPair(randomness: Uint8Array): PairEncryptionKeyPair;
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
});
