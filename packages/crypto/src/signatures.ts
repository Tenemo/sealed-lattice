import { hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    SignatureVerificationResult,
} from '@sealed-lattice/types';

import { canonicalJson } from './canonical-json.js';
import { deriveCanonicalObjectHash } from './hashes.js';

const textEncoder = new TextEncoder();
const supportedMlDsaContextString = 'sealed-lattice:v1';
const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;

export type SignatureExpectation = Readonly<
    CanonicalSignedRootObject & {
        readonly publicKeyHash: ProtocolHash;
    }
>;

const emptySignatureVerificationResult = (
    code: ProtocolRefusalCode,
    message: string,
): SignatureVerificationResult => ({
    isValid: false,
    refusedObjects: [
        {
            code,
            message,
        },
    ],
});

const successfulSignatureVerification = (): SignatureVerificationResult => ({
    isValid: true,
    refusedObjects: [],
});

const isCanonicalInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && !Object.is(value, -0);

const isNonNegativeInteger = (value: number): boolean =>
    isCanonicalInteger(value) && value >= 0;

const isLowercaseHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

const isProtocolHashString = (value: string): boolean =>
    /^[0-9a-f]{128}$/u.test(value);

const isOptionalProtocolHash = (
    value: unknown,
): value is ProtocolHash | undefined =>
    value === undefined ||
    (typeof value === 'string' && isProtocolHashString(value));

const canonicalSignedRootValue = (
    signedRoot: CanonicalSignedRootObject,
): CanonicalSignedRootObject => ({
    objectType: signedRoot.objectType,
    ceremonyId: signedRoot.ceremonyId,
    ...(signedRoot.manifestHash === undefined
        ? {}
        : { manifestHash: signedRoot.manifestHash }),
    ...(signedRoot.objectRoot === undefined
        ? {}
        : { objectRoot: signedRoot.objectRoot }),
    ...(signedRoot.chunkMerkleRoot === undefined
        ? {}
        : { chunkMerkleRoot: signedRoot.chunkMerkleRoot }),
    ...(signedRoot.boardHeadHash === undefined
        ? {}
        : { boardHeadHash: signedRoot.boardHeadHash }),
    signerRole: signedRoot.signerRole,
    signerIdentity: signedRoot.signerIdentity,
    recoveryEpoch: signedRoot.recoveryEpoch,
    deviceEpoch: signedRoot.deviceEpoch,
    contextHash: signedRoot.contextHash,
});

const canonicalProtocolSignatureMessage = (
    signature: Pick<ProtocolSignatureEnvelope, 'publicKeyHash' | 'signedRoot'>,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            messageDomain: 'sealed-lattice/protocol-signature',
            publicKeyHash: signature.publicKeyHash,
            signedRoot: canonicalSignedRootValue(signature.signedRoot),
        }),
    );

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

export const deriveMlDsaPublicKeyHash = (
    publicKeyBytesHex: string,
): ProtocolHash => {
    decodeHexField(
        publicKeyBytesHex,
        mlDsa65PublicKeyByteLength,
        'publicKeyBytesHex',
    );

    return deriveCanonicalObjectHash({
        objectType: 'MlDsa65PublicKeyHash',
        publicKeyBytesHex,
    });
};

const validateSignatureMaterial = (
    signature: ProtocolSignatureEnvelope,
): SignatureVerificationResult | undefined => {
    try {
        decodeHexField(
            signature.publicKeyBytesHex,
            mlDsa65PublicKeyByteLength,
            'publicKeyBytesHex',
        );
        decodeHexField(
            signature.signatureBytesHex,
            mlDsa65SignatureByteLength,
            'signatureBytesHex',
        );
    } catch {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature envelope contains malformed ML-DSA key or signature bytes.',
        );
    }

    const expectedPublicKeyHash = deriveMlDsaPublicKeyHash(
        signature.publicKeyBytesHex,
    );
    if (signature.publicKeyHash !== expectedPublicKeyHash) {
        return emptySignatureVerificationResult(
            'WrongPublicKey',
            'Signature public key hash does not match the ML-DSA public key bytes.',
        );
    }

    return undefined;
};

const validateSignedRootShape = (
    signedRoot: CanonicalSignedRootObject,
): SignatureVerificationResult | undefined => {
    const signedRootRecord = signedRoot as Record<string, unknown>;
    const requiredFields = [
        'objectType',
        'ceremonyId',
        'signerRole',
        'signerIdentity',
        'recoveryEpoch',
        'deviceEpoch',
        'contextHash',
    ] as const;
    const missingField = requiredFields.find(
        (fieldName) =>
            !Object.prototype.hasOwnProperty.call(signedRootRecord, fieldName),
    );

    if (missingField !== undefined) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            `Signed roots must bind ${missingField}.`,
        );
    }
    const objectRootPresent = typeof signedRoot.objectRoot === 'string';
    const chunkMerkleRootPresent =
        typeof signedRoot.chunkMerkleRoot === 'string';

    if (!objectRootPresent && !chunkMerkleRootPresent) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed roots must bind an object root or chunk Merkle root.',
        );
    }
    if (objectRootPresent && chunkMerkleRootPresent) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed roots must bind exactly one object root or chunk Merkle root.',
        );
    }
    if (
        !isOptionalProtocolHash(signedRoot.objectRoot) ||
        !isOptionalProtocolHash(signedRoot.chunkMerkleRoot) ||
        !isOptionalProtocolHash(signedRoot.manifestHash) ||
        !isOptionalProtocolHash(signedRoot.boardHeadHash) ||
        !isProtocolHashString(signedRoot.contextHash)
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed-root hash bindings must be canonical hash strings when present.',
        );
    }
    if (
        !isNonNegativeInteger(signedRoot.recoveryEpoch) ||
        !isNonNegativeInteger(signedRoot.deviceEpoch)
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed root epochs must be non-negative integers.',
        );
    }
    if (
        signedRoot.ceremonyId.length === 0 ||
        signedRoot.signerIdentity.length === 0 ||
        signedRoot.contextHash.length === 0
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed roots must bind ceremony, signer identity, and context hash.',
        );
    }

    return undefined;
};

const validateExpectation = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): SignatureVerificationResult | undefined => {
    const { signedRoot } = signature;

    if (signedRoot.objectType !== expectation.objectType) {
        return emptySignatureVerificationResult(
            'WrongObjectType',
            'Signature root object type does not match the expected object.',
        );
    }
    if (signedRoot.signerRole !== expectation.signerRole) {
        return emptySignatureVerificationResult(
            'WrongSignerRole',
            'Signature root signer role does not match the expected role.',
        );
    }
    if (signedRoot.signerIdentity !== expectation.signerIdentity) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root signer identity does not match the expected identity.',
        );
    }
    if (signedRoot.ceremonyId !== expectation.ceremonyId) {
        return emptySignatureVerificationResult(
            'WrongCeremony',
            'Signature root ceremony does not match the expected ceremony.',
        );
    }
    if (signature.publicKeyHash !== expectation.publicKeyHash) {
        return emptySignatureVerificationResult(
            'WrongPublicKey',
            'Signature public key hash does not match the expected key.',
        );
    }
    if (signedRoot.manifestHash !== expectation.manifestHash) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root manifest hash does not match the expected manifest.',
        );
    }
    if (signedRoot.objectRoot !== expectation.objectRoot) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root object hash does not match the signed object.',
        );
    }
    if (signedRoot.chunkMerkleRoot !== expectation.chunkMerkleRoot) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root chunk Merkle root does not match the expected object.',
        );
    }
    if (signedRoot.boardHeadHash !== expectation.boardHeadHash) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root board-head hash does not match the expected head.',
        );
    }
    if (signedRoot.recoveryEpoch !== expectation.recoveryEpoch) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root recovery epoch does not match the expected object.',
        );
    }
    if (signedRoot.deviceEpoch !== expectation.deviceEpoch) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root device epoch does not match the expected object.',
        );
    }
    if (signedRoot.contextHash !== expectation.contextHash) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root context hash does not match the expected context.',
        );
    }

    return undefined;
};

const verifySignedObjectSignatureInner = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): SignatureVerificationResult => {
    const materialFailure = validateSignatureMaterial(signature);
    if (materialFailure !== undefined) {
        return materialFailure;
    }

    const shapeFailure = validateSignedRootShape(signature.signedRoot);
    if (shapeFailure !== undefined) {
        return shapeFailure;
    }

    const expectationFailure = validateExpectation(signature, expectation);
    if (expectationFailure !== undefined) {
        return expectationFailure;
    }

    const publicKeyBytes = decodeHexField(
        signature.publicKeyBytesHex,
        mlDsa65PublicKeyByteLength,
        'publicKeyBytesHex',
    );
    const signatureBytes = decodeHexField(
        signature.signatureBytesHex,
        mlDsa65SignatureByteLength,
        'signatureBytesHex',
    );
    const signatureValid = ml_dsa65.verify(
        signatureBytes,
        canonicalProtocolSignatureMessage({
            publicKeyHash: signature.publicKeyHash,
            signedRoot: signature.signedRoot,
        }),
        publicKeyBytes,
        {
            context: textEncoder.encode(supportedMlDsaContextString),
        },
    );

    if (!signatureValid) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'ML-DSA signature does not verify for the canonical signed root.',
        );
    }

    return successfulSignatureVerification();
};

export const verifySignedObjectSignature = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): SignatureVerificationResult => {
    try {
        return verifySignedObjectSignatureInner(signature, expectation);
    } catch {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature envelope is not a canonical ML-DSA signed-root envelope.',
        );
    }
};
