import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type {
    MlDsaSignatureProfile,
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import {
    canonicalJson,
    deriveCanonicalObjectHash,
    deriveMlDsaPublicKeyHash,
    deriveProtocolSignatureHash,
} from '#packages/crypto/src/index';

const textEncoder = new TextEncoder();
const mlDsa65SecretKeyByteLength = ml_dsa65.lengths.secretKey!;

export type MlDsaKeyPairFixture = {
    readonly publicKeyBytesHex: string;
    readonly publicKeyHash: ProtocolHash;
    readonly secretKeyBytesHex: string;
};

const isLowercaseHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

const decodeHexField = (
    value: string,
    expectedByteLength: number,
    fieldName: string,
): Uint8Array => {
    if (!isLowercaseHex(value)) {
        throw new Error(`${fieldName} must be lowercase canonical hex.`);
    }
    const bytes = hexToBytes(value);
    if (bytes.byteLength !== expectedByteLength) {
        throw new Error(
            `${fieldName} must be ${String(expectedByteLength)} bytes.`,
        );
    }

    return bytes;
};

const canonicalProtocolSignatureMessage = (
    signature: Pick<
        ProtocolSignatureEnvelope,
        'profile' | 'publicKeyHash' | 'signedRoot'
    >,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            messageDomain: 'sealed-lattice/protocol-signature',
            profile: signature.profile,
            publicKeyHash: signature.publicKeyHash,
            signedRoot: signature.signedRoot,
        }),
    );

export const createMlDsaSignatureProfileFixture = (
    overrides: Partial<MlDsaSignatureProfile> = {},
): MlDsaSignatureProfile => {
    const contextString = overrides.contextString ?? 'sealed-lattice:v1';

    return {
        algorithm: 'ML-DSA-65',
        mode: overrides.mode ?? 'PureMLDSA',
        contextString,
    };
};

export const createMlDsaKeyPairFixture = (
    seedLabel: string,
): MlDsaKeyPairFixture => {
    const seed = deriveCanonicalObjectHash({
        objectType: 'MlDsaKeyFixtureSeed',
        purpose: 'ml-dsa-fixture-seed',
        seedLabel,
    }).slice(0, 64);
    const keyPair = ml_dsa65.keygen(hexToBytes(seed));
    const publicKeyBytesHex = bytesToHex(keyPair.publicKey);

    return {
        publicKeyBytesHex,
        publicKeyHash: deriveMlDsaPublicKeyHash(publicKeyBytesHex),
        secretKeyBytesHex: bytesToHex(keyPair.secretKey),
    };
};

export const createProtocolSignatureFixture = (
    input: Omit<
        ProtocolSignatureEnvelope,
        'signatureBytesHex' | 'signatureHash'
    > & {
        readonly secretKeyBytesHex: string;
    },
): ProtocolSignatureEnvelope => {
    const secretKey = decodeHexField(
        input.secretKeyBytesHex,
        mlDsa65SecretKeyByteLength,
        'secretKeyBytesHex',
    );
    const message = canonicalProtocolSignatureMessage({
        profile: input.profile,
        publicKeyHash: input.publicKeyHash,
        signedRoot: input.signedRoot,
    });
    const signatureBytes = ml_dsa65.sign(message, secretKey, {
        context: textEncoder.encode(input.profile.contextString),
        extraEntropy: false,
    });
    const signature = {
        profile: input.profile,
        publicKeyBytesHex: input.publicKeyBytesHex,
        publicKeyHash: input.publicKeyHash,
        signatureBytesHex: bytesToHex(signatureBytes),
        signedRoot: input.signedRoot,
    };

    return {
        ...signature,
        signatureHash: deriveProtocolSignatureHash(signature),
    };
};
