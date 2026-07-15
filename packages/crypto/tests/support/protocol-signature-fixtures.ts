import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type {
    ProtocolHash,
    ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';

import {
    canonicalJson,
    deriveCanonicalObjectHash,
} from '#packages/crypto/src/index';

const textEncoder = new TextEncoder();
const supportedMlDsaContextString = 'sealed-lattice:v1';
const mlDsa65SecretKeyByteLength = ml_dsa65.lengths.secretKey!;

type MlDsaKeyPairFixture = {
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
    signature: Pick<ProtocolSignatureEnvelope, 'publicKeyHash' | 'signedRoot'>,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            messageDomain: 'sealed-lattice/protocol-signature',
            publicKeyHash: signature.publicKeyHash,
            signedRoot: signature.signedRoot,
        }),
    );

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
        publicKeyHash: deriveCanonicalObjectHash({
            objectType: 'MlDsa65PublicKeyHash',
            publicKeyBytesHex,
        }),
        secretKeyBytesHex: bytesToHex(keyPair.secretKey),
    };
};

export const createProtocolSignatureFixture = (
    input: Omit<ProtocolSignatureEnvelope, 'signatureBytesHex'> & {
        readonly secretKeyBytesHex: string;
    },
): ProtocolSignatureEnvelope => {
    const secretKey = decodeHexField(
        input.secretKeyBytesHex,
        mlDsa65SecretKeyByteLength,
        'secretKeyBytesHex',
    );
    const message = canonicalProtocolSignatureMessage({
        publicKeyHash: input.publicKeyHash,
        signedRoot: input.signedRoot,
    });
    const signatureBytes = ml_dsa65.sign(message, secretKey, {
        context: textEncoder.encode(supportedMlDsaContextString),
        extraEntropy: false,
    });

    return {
        publicKeyBytesHex: input.publicKeyBytesHex,
        publicKeyHash: input.publicKeyHash,
        signatureBytesHex: bytesToHex(signatureBytes),
        signedRoot: input.signedRoot,
    };
};
