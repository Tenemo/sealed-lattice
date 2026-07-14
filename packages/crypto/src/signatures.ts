import { hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type {
    CanonicalSignedRootObject,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RefusalReason,
    VerificationResult,
} from '@sealed-lattice/types';

import { canonicalJson } from './canonical-json.js';
import { deriveCanonicalObjectHash } from './hashes.js';

const textEncoder = new TextEncoder();
const supportedMlDsaContextString = 'sealed-lattice:v1';
const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;

type SignatureExpectation = Readonly<
    CanonicalSignedRootObject & {
        readonly publicKeyHash: ProtocolHash;
    }
>;

const refusedSignatureVerification = (
    refusalReason: RefusalReason,
): VerificationResult<ProtocolSignatureEnvelope> => ({
    isValid: false,
    refusalReason,
});

const successfulSignatureVerification = (
    signature: ProtocolSignatureEnvelope,
): VerificationResult<ProtocolSignatureEnvelope> => ({
    isValid: true,
    value: signature,
});

const isCanonicalInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && !Object.is(value, -0);

const isNonNegativeInteger = (value: number): boolean =>
    isCanonicalInteger(value) && value >= 0;

const isLowercaseHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

const isProtocolHashString = (value: string): boolean =>
    /^[0-9a-f]{128}$/u.test(value);

const canonicalSignedRootValue = (
    signedRoot: CanonicalSignedRootObject,
): CanonicalSignedRootObject => ({
    objectType: signedRoot.objectType,
    ceremonyId: signedRoot.ceremonyId,
    manifestHash: signedRoot.manifestHash,
    objectRoot: signedRoot.objectRoot,
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

const deriveMlDsaPublicKeyHash = (publicKeyBytesHex: string): ProtocolHash => {
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
): VerificationResult<ProtocolSignatureEnvelope> | undefined => {
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
        return refusedSignatureVerification('invalidSignature');
    }

    const expectedPublicKeyHash = deriveMlDsaPublicKeyHash(
        signature.publicKeyBytesHex,
    );
    if (signature.publicKeyHash !== expectedPublicKeyHash) {
        return refusedSignatureVerification('wrongContext');
    }

    return undefined;
};

const validateSignedRootShape = (
    signedRoot: CanonicalSignedRootObject,
): VerificationResult<ProtocolSignatureEnvelope> | undefined => {
    const signedRootRecord = signedRoot as Record<string, unknown>;
    const requiredFields = [
        'objectType',
        'ceremonyId',
        'manifestHash',
        'objectRoot',
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
        return refusedSignatureVerification('wrongTypeOrLength');
    }
    if (
        !isProtocolHashString(signedRoot.manifestHash) ||
        !isProtocolHashString(signedRoot.objectRoot) ||
        !isProtocolHashString(signedRoot.contextHash)
    ) {
        return refusedSignatureVerification('wrongTypeOrLength');
    }
    if (
        !isNonNegativeInteger(signedRoot.recoveryEpoch) ||
        !isNonNegativeInteger(signedRoot.deviceEpoch)
    ) {
        return refusedSignatureVerification('wrongTypeOrLength');
    }
    if (
        signedRoot.ceremonyId.length === 0 ||
        signedRoot.signerIdentity.length === 0 ||
        signedRoot.contextHash.length === 0
    ) {
        return refusedSignatureVerification('wrongTypeOrLength');
    }

    return undefined;
};

const validateExpectation = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): VerificationResult<ProtocolSignatureEnvelope> | undefined => {
    const { signedRoot } = signature;

    if (signedRoot.objectType !== expectation.objectType) {
        return refusedSignatureVerification('wrongTypeOrLength');
    }
    if (signedRoot.signerRole !== expectation.signerRole) {
        return refusedSignatureVerification('wrongTypeOrLength');
    }
    if (signedRoot.signerIdentity !== expectation.signerIdentity) {
        return refusedSignatureVerification('wrongContext');
    }
    if (signedRoot.ceremonyId !== expectation.ceremonyId) {
        return refusedSignatureVerification('wrongContext');
    }
    if (signature.publicKeyHash !== expectation.publicKeyHash) {
        return refusedSignatureVerification('wrongContext');
    }
    if (signedRoot.manifestHash !== expectation.manifestHash) {
        return refusedSignatureVerification('wrongHashOrRoot');
    }
    if (signedRoot.objectRoot !== expectation.objectRoot) {
        return refusedSignatureVerification('wrongHashOrRoot');
    }
    if (signedRoot.recoveryEpoch !== expectation.recoveryEpoch) {
        return refusedSignatureVerification('wrongContext');
    }
    if (signedRoot.deviceEpoch !== expectation.deviceEpoch) {
        return refusedSignatureVerification('wrongContext');
    }
    if (signedRoot.contextHash !== expectation.contextHash) {
        return refusedSignatureVerification('wrongContext');
    }

    return undefined;
};

const verifySignedObjectSignatureInner = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): VerificationResult<ProtocolSignatureEnvelope> => {
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
        return refusedSignatureVerification('invalidSignature');
    }

    return successfulSignatureVerification(signature);
};

export const verifySignedObjectSignature = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): VerificationResult<ProtocolSignatureEnvelope> => {
    try {
        return verifySignedObjectSignatureInner(signature, expectation);
    } catch {
        return refusedSignatureVerification('invalidSignature');
    }
};
