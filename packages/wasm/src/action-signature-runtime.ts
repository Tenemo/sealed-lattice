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

const generateKeyPairCommand = 1;
const signMessageCommand = 2;
const verifySignatureCommand = 3;
const deriveStatementIdentityCommand = 7;
const messageByteLength = 64;
const completionParticipantCount = 10;

export const actionSignatureKeyGenerationRandomnessByteLength = 32;
export const actionSignatureSigningRandomnessByteLength = 32;
export const actionSignatureSecretKeyByteLength = 4_032;
export const actionSignatureVerificationKeyByteLength = 1_952;
export const actionSignatureByteLength = 3_309;

type ActionSignatureKeyPair = Readonly<{
    secretKey: Uint8Array;
    verificationKey: Uint8Array;
}>;

export type ActionSignaturePurpose =
    | 'activation'
    | 'finality'
    | 'no-result-acknowledgement'
    | 'preparation'
    | 'source';

export type ActionSignatureRuntime = Readonly<{
    generateKeyPair(randomness: Uint8Array): ActionSignatureKeyPair;
    deriveStatementIdentity(
        signerPosition: number,
        purpose: ActionSignaturePurpose,
        bodyIdentity: Uint8Array,
    ): Uint8Array;
    signMessage(
        secretKey: Uint8Array,
        message: Uint8Array,
        signingRandomness: Uint8Array,
    ): Uint8Array;
    verifyMessage(
        verificationKey: Uint8Array,
        message: Uint8Array,
        signature: Uint8Array,
    ): boolean;
    signBodyIdentity(
        secretKey: Uint8Array,
        signerPosition: number,
        purpose: ActionSignaturePurpose,
        bodyIdentity: Uint8Array,
        signingRandomness: Uint8Array,
    ): Uint8Array;
    verifySignature(
        verificationKey: Uint8Array,
        signerPosition: number,
        purpose: ActionSignaturePurpose,
        bodyIdentity: Uint8Array,
        signature: Uint8Array,
    ): boolean;
}>;

const copyExactResponse = (
    bytes: Uint8Array,
    expectedLength: number,
    name: string,
): Uint8Array => {
    requireExactConstructionBytes(bytes, expectedLength, name);
    return Uint8Array.from(bytes);
};

const purposeCode = (purpose: ActionSignaturePurpose): number => {
    switch (purpose) {
        case 'preparation':
            return 1;
        case 'source':
            return 2;
        case 'finality':
            return 3;
        case 'activation':
            return 4;
        case 'no-result-acknowledgement':
            return 5;
    }
};

export const openActionSignatureRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): ActionSignatureRuntime => {
    const runtime: ActionSignatureRuntime = {
        generateKeyPair: (randomness) => {
            requireExactConstructionBytes(
                randomness,
                actionSignatureKeyGenerationRandomnessByteLength,
                'randomness',
            );
            const request = new ConstructionCommandWriter();
            request.writeU8(generateKeyPairCommand);
            request.writeBytes(randomness);
            return executeConstructionCommand(kernel, request, (reader) => ({
                secretKey: copyExactResponse(
                    reader.readBytes(),
                    actionSignatureSecretKeyByteLength,
                    'secretKey',
                ),
                verificationKey: copyExactResponse(
                    reader.readBytes(),
                    actionSignatureVerificationKeyByteLength,
                    'verificationKey',
                ),
            }));
        },
        deriveStatementIdentity: (signerPosition, purpose, bodyIdentity) => {
            if (
                !Number.isSafeInteger(signerPosition) ||
                signerPosition < 0 ||
                signerPosition >= completionParticipantCount
            ) {
                throw new RangeError(
                    'signerPosition is not a completion-roster position.',
                );
            }
            requireExactConstructionBytes(
                bodyIdentity,
                messageByteLength,
                'bodyIdentity',
            );
            const request = new ConstructionCommandWriter();
            request.writeU8(deriveStatementIdentityCommand);
            request.writeU16(completionParticipantCount);
            request.writeU16(signerPosition);
            request.writeU16(purposeCode(purpose));
            request.writeFixed(bodyIdentity);
            return executeConstructionCommand(kernel, request, (reader) =>
                copyExactResponse(
                    reader.readFixed(messageByteLength),
                    messageByteLength,
                    'statementIdentity',
                ),
            );
        },
        signMessage: (secretKey, message, signingRandomness) => {
            requireExactConstructionBytes(
                secretKey,
                actionSignatureSecretKeyByteLength,
                'secretKey',
            );
            requireExactConstructionBytes(
                message,
                messageByteLength,
                'message',
            );
            requireExactConstructionBytes(
                signingRandomness,
                actionSignatureSigningRandomnessByteLength,
                'signingRandomness',
            );
            const request = new ConstructionCommandWriter();
            request.writeU8(signMessageCommand);
            request.writeFixed(message);
            request.writeBytes(secretKey);
            request.writeBytes(signingRandomness);
            return executeConstructionCommand(kernel, request, (reader) =>
                copyExactResponse(
                    reader.readBytes(),
                    actionSignatureByteLength,
                    'signature',
                ),
            );
        },
        verifyMessage: (verificationKey, message, signature) => {
            requireExactConstructionBytes(
                verificationKey,
                actionSignatureVerificationKeyByteLength,
                'verificationKey',
            );
            requireExactConstructionBytes(
                message,
                messageByteLength,
                'message',
            );
            requireExactConstructionBytes(
                signature,
                actionSignatureByteLength,
                'signature',
            );
            const request = new ConstructionCommandWriter();
            request.writeU8(verifySignatureCommand);
            request.writeFixed(message);
            request.writeBytes(signature);
            request.writeBytes(verificationKey);
            return executeConstructionCommand(kernel, request, (reader) => {
                const result = reader.readU8();
                if (result !== 0 && result !== 1) {
                    throw new Error(
                        'The construction kernel returned an invalid verification result.',
                    );
                }
                return result === 1;
            });
        },
        signBodyIdentity: (
            secretKey,
            signerPosition,
            purpose,
            bodyIdentity,
            signingRandomness,
        ) =>
            runtime.signMessage(
                secretKey,
                runtime.deriveStatementIdentity(
                    signerPosition,
                    purpose,
                    bodyIdentity,
                ),
                signingRandomness,
            ),
        verifySignature: (
            verificationKey,
            signerPosition,
            purpose,
            bodyIdentity,
            signature,
        ) =>
            runtime.verifyMessage(
                verificationKey,
                runtime.deriveStatementIdentity(
                    signerPosition,
                    purpose,
                    bodyIdentity,
                ),
                signature,
            ),
    };
    return runtime;
};

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
