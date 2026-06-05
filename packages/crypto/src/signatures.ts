import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type {
    CanonicalSignedRootObject,
    MlDsaSignatureProfile,
    ProtocolHash,
    ProtocolRefusalCode,
    ProtocolSignatureEnvelope,
    SignatureVerificationResult,
    SignedObjectType,
    SignerRole,
} from '@sealed-lattice/types';

import { canonicalJson } from './canonical-json.js';
import { deriveProtocolHash } from './hashes.js';

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
    readonly publicKeyHash?: ProtocolHash;
    readonly manifestHash?: ProtocolHash | null;
    readonly objectRoot?: ProtocolHash | null;
    readonly chunkMerkleRoot?: ProtocolHash | null;
    readonly boardHeadHash?: ProtocolHash | null;
    readonly contextHash?: ProtocolHash;
    readonly byteLength?: number;
    readonly recoveryEpoch?: number;
    readonly deviceEpoch?: number;
};

export type MlDsaKeyPairFixture = {
    readonly publicKeyBytesHex: string;
    readonly publicKeyHash: ProtocolHash;
    readonly secretKeyBytesHex: string;
};

const emptySignatureVerificationResult = (
    code: ProtocolRefusalCode,
    message: string,
    objectHash?: ProtocolHash,
): SignatureVerificationResult => ({
    ok: false,
    statusLabels: [],
    acceptedHashes: [],
    refusedObjects: [
        {
            code,
            message,
            objectHash,
        },
    ],
});

const successfulSignatureVerification = (
    signatureHash: ProtocolHash,
): SignatureVerificationResult => ({
    ok: true,
    statusLabels: [],
    acceptedHashes: [signatureHash],
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

const isProtocolHashOrNull = (value: unknown): value is ProtocolHash | null =>
    value === null ||
    (typeof value === 'string' && isProtocolHashString(value));

const canonicalProtocolSignatureMessage = (
    signature: Pick<
        ProtocolSignatureEnvelope,
        'profile' | 'publicKeyHash' | 'signedRoot'
    >,
): Uint8Array =>
    textEncoder.encode(
        canonicalJson({
            messageDomain: 'sealed-lattice/protocol-signature-v1',
            profile: signature.profile,
            publicKeyHash: signature.publicKeyHash,
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
        providerBuildHash:
            overrides.providerBuildHash ??
            deriveProtocolHash('ProviderBuildHash', {
                providerName: 'deterministic-fixture',
                providerVersion: '1',
            }),
        fips204Version: overrides.fips204Version ?? 'FIPS 204',
        errataStatus: overrides.errataStatus ?? 'none',
        contextString,
        contextStringByteLength,
    };
};

export const deriveMlDsaPublicKeyHash = (
    publicKeyBytesHex: string,
): ProtocolHash => {
    decodeHexField(
        publicKeyBytesHex,
        mlDsa65PublicKeyByteLength,
        'publicKeyBytesHex',
    );

    return deriveProtocolHash('PublicKeyHash', {
        algorithm: 'ML-DSA-65',
        publicKeyBytesHex,
    });
};

export const createMlDsaKeyPairFixture = (
    seedLabel: string,
): MlDsaKeyPairFixture => {
    const seed = deriveProtocolHash('ChallengeDomainHash', {
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

export const deriveProtocolSignatureHash = (
    signature: Omit<ProtocolSignatureEnvelope, 'signatureHash'>,
): ProtocolHash =>
    deriveProtocolHash('ProtocolSignatureEnvelopeHash', {
        profile: signature.profile,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyHash: signature.publicKeyHash,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    });

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
            signature.signatureHash,
        );
    }
    if (signature.profile.mode !== 'PureMLDSA') {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Only PureMLDSA signatures are supported by this verifier.',
            signature.signatureHash,
        );
    }
    if (
        signature.profile.providerName.length === 0 ||
        signature.profile.providerVersion.length === 0 ||
        !isProtocolHashString(signature.profile.providerBuildHash) ||
        signature.profile.fips204Version.length === 0 ||
        signature.profile.errataStatus.length === 0
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature profile metadata must be fully bound with canonical provider build material.',
            signature.signatureHash,
        );
    }
    if (byteLength > mlDsaContextByteLimit) {
        return emptySignatureVerificationResult(
            'InvalidMlDsaContext',
            'ML-DSA context strings must be at most 255 bytes.',
            signature.signatureHash,
        );
    }
    if (signature.profile.contextStringByteLength !== byteLength) {
        return emptySignatureVerificationResult(
            'InvalidMlDsaContext',
            'ML-DSA context string byte length does not match the profile.',
            signature.signatureHash,
        );
    }
    if (signature.profile.contextString !== supportedMlDsaContextString) {
        return emptySignatureVerificationResult(
            'InvalidMlDsaContext',
            'ML-DSA context string does not match the supported protocol context.',
            signature.signatureHash,
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
            signature.signatureHash,
        );
    }

    const expectedPublicKeyHash = deriveMlDsaPublicKeyHash(
        signature.publicKeyBytesHex,
    );
    if (signature.publicKeyHash !== expectedPublicKeyHash) {
        return emptySignatureVerificationResult(
            'WrongPublicKey',
            'Signature public key hash does not match the ML-DSA public key bytes.',
            signature.signatureHash,
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
        'manifestHash',
        'boardHeadHash',
        'objectRoot',
        'chunkMerkleRoot',
        'byteLength',
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
        !isProtocolHashOrNull(signedRoot.objectRoot) ||
        !isProtocolHashOrNull(signedRoot.chunkMerkleRoot) ||
        !isProtocolHashOrNull(signedRoot.manifestHash) ||
        !isProtocolHashOrNull(signedRoot.boardHeadHash) ||
        !isProtocolHashString(signedRoot.contextHash)
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signed-root hash bindings must be canonical hash strings or null.',
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

    if (
        expectation.objectType !== undefined &&
        signedRoot.objectType !== expectation.objectType
    ) {
        return emptySignatureVerificationResult(
            'WrongObjectType',
            'Signature root object type does not match the expected object.',
            signature.signatureHash,
        );
    }
    if (
        expectation.objectVersion !== undefined &&
        signedRoot.objectVersion !== expectation.objectVersion
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root object version does not match the expected version.',
            signature.signatureHash,
        );
    }
    if (
        expectation.signerRole !== undefined &&
        signedRoot.signerRole !== expectation.signerRole
    ) {
        return emptySignatureVerificationResult(
            'WrongSignerRole',
            'Signature root signer role does not match the expected role.',
            signature.signatureHash,
        );
    }
    if (
        expectation.signerIdentity !== undefined &&
        signedRoot.signerIdentity !== expectation.signerIdentity
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root signer identity does not match the expected identity.',
            signature.signatureHash,
        );
    }
    if (
        expectation.ceremonyId !== undefined &&
        signedRoot.ceremonyId !== expectation.ceremonyId
    ) {
        return emptySignatureVerificationResult(
            'WrongCeremony',
            'Signature root ceremony does not match the expected ceremony.',
            signature.signatureHash,
        );
    }
    if (
        expectation.publicKeyHash !== undefined &&
        signature.publicKeyHash !== expectation.publicKeyHash
    ) {
        return emptySignatureVerificationResult(
            'WrongPublicKey',
            'Signature public key hash does not match the expected key.',
            signature.signatureHash,
        );
    }
    if (
        expectation.manifestHash !== undefined &&
        signedRoot.manifestHash !== expectation.manifestHash
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root manifest hash does not match the expected manifest.',
            signature.signatureHash,
        );
    }
    if (
        expectation.objectRoot !== undefined &&
        signedRoot.objectRoot !== expectation.objectRoot
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root object hash does not match the signed object.',
            signature.signatureHash,
        );
    }
    if (
        expectation.chunkMerkleRoot !== undefined &&
        signedRoot.chunkMerkleRoot !== expectation.chunkMerkleRoot
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root chunk Merkle root does not match the expected object.',
            signature.signatureHash,
        );
    }
    if (
        expectation.boardHeadHash !== undefined &&
        signedRoot.boardHeadHash !== expectation.boardHeadHash
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root board-head hash does not match the expected head.',
            signature.signatureHash,
        );
    }
    if (
        expectation.byteLength !== undefined &&
        signedRoot.byteLength !== expectation.byteLength
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root byte length does not match the expected object.',
            signature.signatureHash,
        );
    }
    if (
        expectation.recoveryEpoch !== undefined &&
        signedRoot.recoveryEpoch !== expectation.recoveryEpoch
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root recovery epoch does not match the expected object.',
            signature.signatureHash,
        );
    }
    if (
        expectation.deviceEpoch !== undefined &&
        signedRoot.deviceEpoch !== expectation.deviceEpoch
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root device epoch does not match the expected object.',
            signature.signatureHash,
        );
    }
    if (
        expectation.contextHash !== undefined &&
        signedRoot.contextHash !== expectation.contextHash
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root context hash does not match the expected context.',
            signature.signatureHash,
        );
    }

    return undefined;
};

const hasExplicitSignatureExpectationBinding = (
    expectation: SignatureExpectation,
): boolean =>
    [
        expectation.objectType,
        expectation.objectVersion,
        expectation.signerRole,
        expectation.signerIdentity,
        expectation.ceremonyId,
        expectation.publicKeyHash,
        expectation.manifestHash,
        expectation.objectRoot,
        expectation.chunkMerkleRoot,
        expectation.boardHeadHash,
        expectation.contextHash,
        expectation.byteLength,
        expectation.recoveryEpoch,
        expectation.deviceEpoch,
    ].some((value) => value !== undefined);

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

    if (
        expectation.allowUnboundVerification !== true &&
        !hasExplicitSignatureExpectationBinding(expectation)
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature verification requires explicit expectation bindings.',
            signature.signatureHash,
        );
    }

    const expectationFailure = validateExpectation(signature, expectation);
    if (expectationFailure !== undefined) {
        return expectationFailure;
    }

    const expectedSignatureHash = deriveProtocolSignatureHash({
        profile: signature.profile,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyHash: signature.publicKeyHash,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    });
    if (signature.signatureHash !== expectedSignatureHash) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature hash does not verify for the canonical signed root.',
            signature.signatureHash,
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
            publicKeyHash: signature.publicKeyHash,
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
            signature.signatureHash,
        );
    }

    return successfulSignatureVerification(signature.signatureHash);
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
                ?.signatureHash,
        );
    }
};
