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

const deriveVerificationKeyFragmentCommand = 1;
const signBodyIdentityFragmentCommand = 2;
const verifySignatureFragmentCommand = 3;
const chainValueByteLength = 48;
const messageByteLength = 64;
const chainCount = 131;
const maximumFragmentChainCount = 17;

export const actionSignatureKeyByteLength = chainValueByteLength * chainCount;

const forEachFragment = (
    input: Uint8Array,
    operation: (firstChain: number, inputFragment: Uint8Array) => Uint8Array,
): Uint8Array => {
    const output = new Uint8Array(actionSignatureKeyByteLength);
    for (
        let firstChain = 0;
        firstChain < chainCount;
        firstChain += maximumFragmentChainCount
    ) {
        const fragmentChainCount = Math.min(
            maximumFragmentChainCount,
            chainCount - firstChain,
        );
        const start = firstChain * chainValueByteLength;
        const end = start + fragmentChainCount * chainValueByteLength;
        const inputFragment = Uint8Array.from(input.subarray(start, end));
        try {
            const outputFragment = operation(firstChain, inputFragment);
            if (outputFragment.byteLength !== end - start) {
                throw new Error(
                    'The construction kernel returned the wrong fragment length.',
                );
            }
            output.set(outputFragment, start);
        } finally {
            inputFragment.fill(0);
        }
    }
    return output;
};

export type ActionSignatureRuntime = Readonly<{
    deriveVerificationKey(secretKey: Uint8Array): Uint8Array;
    signBodyIdentity(
        secretKey: Uint8Array,
        bodyIdentity: Uint8Array,
    ): Uint8Array;
    verifySignature(
        verificationKey: Uint8Array,
        bodyIdentity: Uint8Array,
        signature: Uint8Array,
    ): boolean;
}>;

export const openActionSignatureRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): ActionSignatureRuntime => ({
    deriveVerificationKey: (secretKey) => {
        requireExactConstructionBytes(
            secretKey,
            actionSignatureKeyByteLength,
            'secretKey',
        );
        return forEachFragment(secretKey, (firstChain, inputFragment) => {
            const request = new ConstructionCommandWriter();
            request.writeU8(deriveVerificationKeyFragmentCommand);
            request.writeU16(firstChain);
            request.writeBytes(inputFragment);
            return executeConstructionCommand(kernel, request, (reader) =>
                Uint8Array.from(reader.readBytes()),
            );
        });
    },
    signBodyIdentity: (secretKey, bodyIdentity) => {
        requireExactConstructionBytes(
            secretKey,
            actionSignatureKeyByteLength,
            'secretKey',
        );
        requireExactConstructionBytes(
            bodyIdentity,
            messageByteLength,
            'bodyIdentity',
        );
        return forEachFragment(secretKey, (firstChain, inputFragment) => {
            const request = new ConstructionCommandWriter();
            request.writeU8(signBodyIdentityFragmentCommand);
            request.writeU16(firstChain);
            request.writeFixed(bodyIdentity);
            request.writeBytes(inputFragment);
            return executeConstructionCommand(kernel, request, (reader) =>
                Uint8Array.from(reader.readBytes()),
            );
        });
    },
    verifySignature: (verificationKey, bodyIdentity, signature) => {
        requireExactConstructionBytes(
            verificationKey,
            actionSignatureKeyByteLength,
            'verificationKey',
        );
        requireExactConstructionBytes(
            bodyIdentity,
            messageByteLength,
            'bodyIdentity',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureKeyByteLength,
            'signature',
        );
        let isValid = true;
        for (
            let firstChain = 0;
            firstChain < chainCount;
            firstChain += maximumFragmentChainCount
        ) {
            const fragmentChainCount = Math.min(
                maximumFragmentChainCount,
                chainCount - firstChain,
            );
            const start = firstChain * chainValueByteLength;
            const end = start + fragmentChainCount * chainValueByteLength;
            const request = new ConstructionCommandWriter();
            request.writeU8(verifySignatureFragmentCommand);
            request.writeU16(firstChain);
            request.writeFixed(bodyIdentity);
            request.writeBytes(signature.subarray(start, end));
            request.writeBytes(verificationKey.subarray(start, end));
            isValid =
                executeConstructionCommand(kernel, request, (reader) => {
                    const result = reader.readU8();
                    if (result !== 0 && result !== 1) {
                        throw new Error(
                            'The construction kernel returned an invalid verification result.',
                        );
                    }
                    return result === 1;
                }) && isValid;
        }
        return isValid;
    },
});

export const createActionSignatureRuntimeLoader = (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions = {},
): (() => Promise<ActionSignatureRuntime>) => {
    let runtimePromise: Promise<ActionSignatureRuntime> | undefined;
    return async () => {
        runtimePromise ??= instantiateConstructionKernelCommandRuntime(
            foundationKernelUrl,
            options,
        )
            .then(openActionSignatureRuntime)
            .catch((error: unknown) => {
                runtimePromise = undefined;
                throw error;
            });
        return runtimePromise;
    };
};
