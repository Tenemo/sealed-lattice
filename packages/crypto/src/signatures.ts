import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type {
    CanonicalSignedRootObject,
    MlDsaSignatureProfile,
    ProtocolDigest,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    SignatureVerificationResult,
    SignedObjectType,
    SignerRole,
} from '@sealed-lattice/types';

import { canonicalJson } from './canonical-json.js';
import { deriveProtocolDigest } from './digests.js';

const textEncoder = new TextEncoder();
const mlDsaContextByteLimit = 255;
const supportedMlDsaContextString = 'sealed-lattice:v1';
const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SecretKeyByteLength = ml_dsa65.lengths.secretKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;

export type SignatureExpectation = {
    readonly allowUnboundVerification?: boolean;
    readonly objectType?: SignedObjectType;
    readonly objectVersion?: number;
    readonly signerRole?: SignerRole;
    readonly signerIdentity?: string;
    readonly ceremonyId?: string;
    readonly publicKeyDigest?: ProtocolDigest;
    readonly manifestDigest?: ProtocolDigest | null;
    readonly objectRoot?: ProtocolDigest | null;
    readonly chunkMerkleRoot?: ProtocolDigest | null;
    readonly boardHeadDigest?: ProtocolDigest | null;
    readonly contextDigest?: ProtocolDigest;
    readonly byteLength?: number;
    readonly recoveryEpoch?: number;
    readonly deviceEpoch?: number;
};

export type MlDsaKeyPairFixture = {
    readonly publicKeyBytesHex: string;
    readonly publicKeyDigest: ProtocolDigest;
    readonly secretKeyBytesHex: string;
};

const emptySignatureVerificationResult = (
    code: ProtocolRefusalCode,
    message: string,
    objectDigest?: ProtocolDigest,
): SignatureVerificationResult => ({
    ok: false,
    statusLabels: [],
    acceptedDigests: [],
    refusedObjects: [
        {
            code,
            message,
            objectDigest,
        },
    ],
});

const successfulSignatureVerification = (
    signatureDigest: ProtocolDigest,
): SignatureVerificationResult => ({
    ok: true,
    statusLabels: [],
    acceptedDigests: [signatureDigest],
    refusedObjects: [],
});

const isCanonicalInteger = (value: number): boolean =>
    Number.isSafeInteger(value) && !Object.is(value, -0);

const isNonNegativeInteger = (value: number): boolean =>
    isCanonicalInteger(value) && value >= 0;

const isLowercaseHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

const isProtocolDigestString = (value: string): boolean =>
    /^[0-9a-f]{128}$/u.test(value);

const isProtocolDigestOrNull = (
    value: unknown,
): value is ProtocolDigest | null =>
    value === null ||
    (typeof value === 'string' && isProtocolDigestString(value));

const canonicalProtocolSignatureMessage = (
    signature: Pick<
        ProtocolSignatureEnvelope,
        'profile' | 'publicKeyDigest' | 'signedRoot'
    >,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            messageDomain: 'sealed-lattice/protocol-signature-v1',
            profile: signature.profile,
            publicKeyDigest: signature.publicKeyDigest,
            signedRoot: signature.signedRoot,
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

export const deriveMlDsaContextByteLength = (contextString: string): number =>
    textEncoder.encode(contextString).byteLength;

export const createMlDsaSignatureProfileFixture = (
    overrides: Partial<MlDsaSignatureProfile> = {},
): MlDsaSignatureProfile => {
    const contextString = overrides.contextString ?? 'sealed-lattice:v1';
    const contextStringByteLength =
        overrides.contextStringByteLength ??
        deriveMlDsaContextByteLength(contextString);

    return {
        algorithm: 'ML-DSA-65',
        mode: overrides.mode ?? 'PureMLDSA',
        providerName: overrides.providerName ?? 'deterministic-fixture',
        providerVersion: overrides.providerVersion ?? '1',
        providerBuildDigest:
            overrides.providerBuildDigest ??
            deriveProtocolDigest('ProviderBuildDigest', {
                providerName: 'deterministic-fixture',
                providerVersion: '1',
            }),
        fips204Version: overrides.fips204Version ?? 'FIPS 204',
        errataStatus: overrides.errataStatus ?? 'none',
        contextString,
        contextStringByteLength,
    };
};

export const deriveMlDsaPublicKeyDigest = (
    publicKeyBytesHex: string,
): ProtocolDigest => {
    decodeHexField(
        publicKeyBytesHex,
        mlDsa65PublicKeyByteLength,
        'publicKeyBytesHex',
    );

    return deriveProtocolDigest('PublicKeyDigest', {
        algorithm: 'ML-DSA-65',
        publicKeyBytesHex,
    });
};

export const createMlDsaKeyPairFixture = (
    seedLabel: string,
): MlDsaKeyPairFixture => {
    const seed = deriveProtocolDigest('MlDsaFixtureSeedDigest', {
        purpose: 'ml-dsa-fixture-seed',
        seedLabel,
    }).slice(0, 64);
    const keyPair = ml_dsa65.keygen(hexToBytes(seed));
    const publicKeyBytesHex = bytesToHex(keyPair.publicKey);

    return {
        publicKeyBytesHex,
        publicKeyDigest: deriveMlDsaPublicKeyDigest(publicKeyBytesHex),
        secretKeyBytesHex: bytesToHex(keyPair.secretKey),
    };
};

export const deriveCanonicalSignedRootDigest = (
    signedRoot: CanonicalSignedRootObject,
): ProtocolDigest => deriveProtocolDigest('SignedRootDigest', signedRoot);

export const deriveProtocolSignatureDigest = (
    signature: Omit<ProtocolSignatureEnvelope, 'signatureDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ProtocolSignatureEnvelopeDigest', {
        profile: signature.profile,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    });

export const createProtocolSignatureFixture = (
    input: Omit<
        ProtocolSignatureEnvelope,
        'signatureBytesHex' | 'signatureDigest'
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
        publicKeyDigest: input.publicKeyDigest,
        signedRoot: input.signedRoot,
    });
    const signatureBytes = ml_dsa65.sign(message, secretKey, {
        context: textEncoder.encode(input.profile.contextString),
        extraEntropy: false,
    });
    const signature = {
        profile: input.profile,
        publicKeyBytesHex: input.publicKeyBytesHex,
        publicKeyDigest: input.publicKeyDigest,
        signatureBytesHex: bytesToHex(signatureBytes),
        signedRoot: input.signedRoot,
    };

    return {
        ...signature,
        signatureDigest: deriveProtocolSignatureDigest(signature),
    };
};

const validateProfile = (
    signature: ProtocolSignatureEnvelope,
): SignatureVerificationResult | undefined => {
    const byteLength = deriveMlDsaContextByteLength(
        signature.profile.contextString,
    );

    if (signature.profile.algorithm !== 'ML-DSA-65') {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature profile must use ML-DSA-65.',
            signature.signatureDigest,
        );
    }
    if (signature.profile.mode !== 'PureMLDSA') {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Only PureMLDSA signatures are supported by this verifier.',
            signature.signatureDigest,
        );
    }
    if (
        signature.profile.providerName.length === 0 ||
        signature.profile.providerVersion.length === 0 ||
        !isProtocolDigestString(signature.profile.providerBuildDigest) ||
        signature.profile.fips204Version.length === 0 ||
        signature.profile.errataStatus.length === 0
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature profile metadata must be fully bound with canonical provider build material.',
            signature.signatureDigest,
        );
    }
    if (byteLength > mlDsaContextByteLimit) {
        return emptySignatureVerificationResult(
            'InvalidMlDsaContext',
            'ML-DSA context strings must be at most 255 bytes.',
            signature.signatureDigest,
        );
    }
    if (signature.profile.contextStringByteLength !== byteLength) {
        return emptySignatureVerificationResult(
            'InvalidMlDsaContext',
            'ML-DSA context string byte length does not match the profile.',
            signature.signatureDigest,
        );
    }
    if (signature.profile.contextString !== supportedMlDsaContextString) {
        return emptySignatureVerificationResult(
            'InvalidMlDsaContext',
            'ML-DSA context string does not match the supported protocol context.',
            signature.signatureDigest,
        );
    }

    return undefined;
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
            signature.signatureDigest,
        );
    }

    const expectedPublicKeyDigest = deriveMlDsaPublicKeyDigest(
        signature.publicKeyBytesHex,
    );
    if (signature.publicKeyDigest !== expectedPublicKeyDigest) {
        return emptySignatureVerificationResult(
            'WrongPublicKey',
            'Signature public key digest does not match the ML-DSA public key bytes.',
            signature.signatureDigest,
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
        'objectVersion',
        'ceremonyId',
        'manifestDigest',
        'boardHeadDigest',
        'objectRoot',
        'chunkMerkleRoot',
        'byteLength',
        'signerRole',
        'signerIdentity',
        'recoveryEpoch',
        'deviceEpoch',
        'contextDigest',
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
        !isProtocolDigestOrNull(signedRoot.objectRoot) ||
        !isProtocolDigestOrNull(signedRoot.chunkMerkleRoot) ||
        !isProtocolDigestOrNull(signedRoot.manifestDigest) ||
        !isProtocolDigestOrNull(signedRoot.boardHeadDigest) ||
        !isProtocolDigestString(signedRoot.contextDigest)
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed-root digest bindings must be canonical digest strings or null.',
        );
    }
    if (
        !isNonNegativeInteger(signedRoot.objectVersion) ||
        !isNonNegativeInteger(signedRoot.byteLength) ||
        !isNonNegativeInteger(signedRoot.recoveryEpoch) ||
        !isNonNegativeInteger(signedRoot.deviceEpoch)
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed root version, byte length, and epochs must be non-negative integers.',
        );
    }
    if (
        signedRoot.ceremonyId.length === 0 ||
        signedRoot.signerIdentity.length === 0 ||
        signedRoot.contextDigest.length === 0
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed roots must bind ceremony, signer identity, and context digest.',
        );
    }

    return undefined;
};

const validateExpectation = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation,
): SignatureVerificationResult | undefined => {
    const { signedRoot } = signature;
    const hasBoundRoot =
        expectation.objectRoot !== undefined ||
        expectation.chunkMerkleRoot !== undefined;
    const requiredBindingMissing =
        expectation.objectType === undefined ||
        expectation.objectVersion === undefined ||
        expectation.signerRole === undefined ||
        expectation.signerIdentity === undefined ||
        expectation.ceremonyId === undefined ||
        expectation.publicKeyDigest === undefined ||
        expectation.contextDigest === undefined ||
        !hasBoundRoot;

    if (
        expectation.allowUnboundVerification !== true &&
        requiredBindingMissing
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature verification requires explicit expected object, signer, context, key, and root bindings.',
            signature.signatureDigest,
        );
    }

    if (
        expectation.objectType !== undefined &&
        signedRoot.objectType !== expectation.objectType
    ) {
        return emptySignatureVerificationResult(
            'WrongObjectType',
            'Signature root object type does not match the expected object.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.objectVersion !== undefined &&
        signedRoot.objectVersion !== expectation.objectVersion
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root object version does not match the expected version.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.signerRole !== undefined &&
        signedRoot.signerRole !== expectation.signerRole
    ) {
        return emptySignatureVerificationResult(
            'WrongSignerRole',
            'Signature root signer role does not match the expected role.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.signerIdentity !== undefined &&
        signedRoot.signerIdentity !== expectation.signerIdentity
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root signer identity does not match the expected identity.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.ceremonyId !== undefined &&
        signedRoot.ceremonyId !== expectation.ceremonyId
    ) {
        return emptySignatureVerificationResult(
            'WrongCeremony',
            'Signature root ceremony does not match the expected ceremony.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.publicKeyDigest !== undefined &&
        signature.publicKeyDigest !== expectation.publicKeyDigest
    ) {
        return emptySignatureVerificationResult(
            'WrongPublicKey',
            'Signature public key digest does not match the expected key.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.manifestDigest !== undefined &&
        signedRoot.manifestDigest !== expectation.manifestDigest
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root manifest digest does not match the expected manifest.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.objectRoot !== undefined &&
        signedRoot.objectRoot !== expectation.objectRoot
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root object digest does not match the signed object.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.chunkMerkleRoot !== undefined &&
        signedRoot.chunkMerkleRoot !== expectation.chunkMerkleRoot
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root chunk Merkle root does not match the expected object.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.boardHeadDigest !== undefined &&
        signedRoot.boardHeadDigest !== expectation.boardHeadDigest
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root board-head digest does not match the expected head.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.byteLength !== undefined &&
        signedRoot.byteLength !== expectation.byteLength
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root byte length does not match the expected object.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.recoveryEpoch !== undefined &&
        signedRoot.recoveryEpoch !== expectation.recoveryEpoch
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root recovery epoch does not match the expected object.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.deviceEpoch !== undefined &&
        signedRoot.deviceEpoch !== expectation.deviceEpoch
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root device epoch does not match the expected object.',
            signature.signatureDigest,
        );
    }
    if (
        expectation.contextDigest !== undefined &&
        signedRoot.contextDigest !== expectation.contextDigest
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root context digest does not match the expected context.',
            signature.signatureDigest,
        );
    }

    return undefined;
};

const verifySignedObjectSignatureInner = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation = {},
): SignatureVerificationResult => {
    const profileFailure = validateProfile(signature);
    if (profileFailure !== undefined) {
        return profileFailure;
    }

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

    const expectedSignatureDigest = deriveProtocolSignatureDigest({
        profile: signature.profile,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    });
    if (signature.signatureDigest !== expectedSignatureDigest) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature digest does not verify for the canonical signed root.',
            signature.signatureDigest,
        );
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
            profile: signature.profile,
            publicKeyDigest: signature.publicKeyDigest,
            signedRoot: signature.signedRoot,
        }),
        publicKeyBytes,
        {
            context: textEncoder.encode(signature.profile.contextString),
        },
    );

    if (!signatureValid) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'ML-DSA signature does not verify for the canonical signed root.',
            signature.signatureDigest,
        );
    }

    return successfulSignatureVerification(signature.signatureDigest);
};

export const verifySignedObjectSignature = (
    signature: ProtocolSignatureEnvelope,
    expectation: SignatureExpectation = {},
): SignatureVerificationResult => {
    try {
        return verifySignedObjectSignatureInner(signature, expectation);
    } catch {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature envelope is not a canonical ML-DSA signed-root envelope.',
            (signature as Partial<ProtocolSignatureEnvelope> | undefined)
                ?.signatureDigest,
        );
    }
};
