import { shake256 } from '@noble/hashes/sha3.js';
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

const textEncoder = new TextEncoder();
const hash512PreimagePrefix = textEncoder.encode('sealed.vote/v1/hash512');
const mlDsaContextByteLimit = 255;
const supportedMlDsaContextString = 'sealed-lattice:v1';
const mlDsa65PublicKeyByteLength = ml_dsa65.lengths.publicKey!;
const mlDsa65SecretKeyByteLength = ml_dsa65.lengths.secretKey!;
const mlDsa65SignatureByteLength = ml_dsa65.lengths.signature!;

export const protocolDigestNamespaceValues = [
    'BoardEntryDigest',
    'BoardRootDigest',
    'BoardPolicyDigest',
    'PollSpecDigest',
    'PublicKeyDigest',
    'RegistrationEntryDigest',
    'ReceiverKeyRegistrationDigest',
    'TrusteeSetupEntryDigest',
    'ElectionManifestDigest',
    'RosterDigest',
    'BoardHeadDigest',
    'RecoveryEpochUpdateDigest',
    'ActionContextDigest',
    'BallotPackageDigest',
    'BallotSetDigest',
    'CastReceiptDigest',
    'CloseRecordDigest',
    'WitnessCheckpointDigest',
    'ConflictingHeadEvidenceDigest',
    'InclusionProofDigest',
    'FirstComeOrderDigest',
    'DuplicateBallotPolicyDigest',
    'FirstComePolicyDigest',
    'TargetFinalityPolicyDigest',
    'WitnessPolicyDigest',
    'RecoveryPolicyDigest',
    'SignedRootDigest',
    'ProtocolSignatureEnvelopeDigest',
    'ProviderBuildDigest',
    'ThresholdProfileDigest',
    'HEParamDigest',
    'CiphertextRoot',
    'PlaintextRoot',
    'EvalKeyRoot',
    'TopKCircuitDigest',
    'RotSetDigest',
    'TargetLayoutDigest',
    'PublicSlotMaskDigest',
    'AggregateDerivationComponentDigest',
    'AggregateContributionDigest',
    'AggregateReadyRecordDigest',
    'AggregateSelectionPolicyDigest',
    'PostVotingClosedContextDigest',
    'EvaluationContextDigest',
    'TopKEvaluationRecordDigest',
    'TargetFinalityRecordDigest',
    'EvaluationReplayAttestationDigest',
    'TargetAcceptedRecordDigest',
    'TargetPreimageDigest',
    'TopKDecryptionShareDigest',
    'VerifiedTopKResultDigest',
    'EvaluationProofRoot',
    'CPADProfileDigest',
    'ThresholdDecryptionProfileDigest',
    'BridgeProofRecordDigest',
    'BridgeProofProfileId',
    'ProofPrimeParamDigest',
    'ProofPrimeCiphertextRoot',
    'ProofPrimePublicKeyRoot',
    'ProofPrimeToQDataKeyConsistencyDigest',
    'DerivedAggregateCiphertextRoot',
    'CanonicalCiphertextConventionDigest',
    'BFVBatchEncoderDigest',
    'BridgeLayoutDigest',
    'AggregateShareCommitmentDigest',
    'ShareCommitmentDigest',
    'BrakerskiProfileDigest',
    'BrakerskiDeltaDigest',
    'BrakerskiShareVerificationKeyRoot',
    'TargetDecryptionPreparationRecordDigest',
    'BrakerskiPreprocessRecordDigest',
    'BrakerskiPreprocessTokenDigest',
    'BrakerskiPreprocessUseRecordDigest',
    'QTargetDigest',
    'MobileProfileCertDigest',
    'BridgeMobileCertDigest',
    'BridgeBatchingCertDigest',
    'AggregateBridgeProverCertDigest',
    'EncryptedEnvelopeRoot',
] as const;

export type ProtocolDigestNamespace =
    (typeof protocolDigestNamespaceValues)[number];

type SignatureExpectation = {
    readonly objectType?: SignedObjectType;
    readonly objectVersion?: number;
    readonly signerRole?: SignerRole;
    readonly signerIdentity?: string;
    readonly ceremonyId?: string;
    readonly publicKeyDigest?: ProtocolDigest;
    readonly manifestHash?: ProtocolDigest | null;
    readonly objectRoot?: ProtocolDigest | null;
    readonly boardHeadHash?: ProtocolDigest | null;
    readonly contextDigest?: ProtocolDigest;
};

type MlDsaKeyPairFixture = {
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

const isNonNegativeInteger = (value: number): boolean =>
    Number.isInteger(value) && value >= 0;

const isLowercaseHex = (value: string): boolean =>
    /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0;

const isPlainObject = (
    value: unknown,
): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;

const normalizeHex = (value: string): string => value.toLowerCase();

const normalizeCanonicalValue = (value: unknown): unknown => {
    if (value === null) {
        return null;
    }
    if (typeof value === 'string' || typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value) || !Number.isInteger(value)) {
            throw new TypeError('Canonical numeric fields must be integers.');
        }

        return value;
    }
    if (Array.isArray(value)) {
        return value.map((entry) => normalizeCanonicalValue(entry));
    }
    if (isPlainObject(value)) {
        const normalized: Record<string, unknown> = {};
        for (const key of Object.keys(value).sort()) {
            const entry = value[key];
            if (entry === undefined) {
                throw new TypeError(
                    'Canonical objects cannot contain undefined.',
                );
            }
            normalized[key] = normalizeCanonicalValue(entry);
        }

        return normalized;
    }

    throw new TypeError('Unsupported canonical value.');
};

export const canonicalJson = (value: unknown): string =>
    JSON.stringify(normalizeCanonicalValue(value));

const appendVarUint = (output: number[], value: number): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            'Varuint values must be non-negative safe integers.',
        );
    }

    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        output.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }
};

const appendBytes = (output: number[], value: Uint8Array): void => {
    appendVarUint(output, value.byteLength);
    output.push(...value);
};

export const hash512 = (
    domain: string,
    parts: readonly Uint8Array[],
): Uint8Array => {
    const preimage = Array.from(hash512PreimagePrefix);

    appendBytes(preimage, textEncoder.encode(domain));
    appendVarUint(preimage, parts.length);
    for (const part of parts) {
        appendBytes(preimage, part);
    }

    return shake256(Uint8Array.from(preimage), { dkLen: 64 });
};

export const hash512Hex = (
    domain: string,
    parts: readonly Uint8Array[],
): string => bytesToHex(hash512(domain, parts));

const pascalCaseToKebabCase = (value: string): string =>
    value
        .replace(/([A-Z]+)([A-Z][a-z])/gu, '$1-$2')
        .replace(/([a-z0-9])([A-Z])/gu, '$1-$2')
        .toLowerCase();

export const resolveProtocolDigestDomain = (namespace: string): string => {
    if (namespace.startsWith('sealed-lattice-root/')) {
        return namespace;
    }
    if (!/^[A-Z][A-Za-z0-9]*$/u.test(namespace)) {
        throw new TypeError(
            'Protocol digest namespace must be a reserved PascalCase name or an explicit sealed-lattice-root domain.',
        );
    }

    return `sealed-lattice-root/${pascalCaseToKebabCase(namespace)}-v1`;
};

export const deriveProtocolDigest = (
    namespace: string,
    value: unknown,
): ProtocolDigest =>
    hash512Hex(resolveProtocolDigestDomain(namespace), [
        textEncoder.encode(canonicalJson(value)),
    ]);

export const derivePolicyDigest = (
    namespace: ProtocolDigestNamespace,
    policy: unknown,
): ProtocolDigest => deriveProtocolDigest(namespace, policy);

const canonicalSignedRootMessage = (
    signedRoot: CanonicalSignedRootObject,
): Uint8Array => textEncoder.encode(canonicalJson(signedRoot));

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
): ProtocolDigest =>
    deriveProtocolDigest('PublicKeyDigest', {
        algorithm: 'ML-DSA-65',
        publicKeyBytesHex: normalizeHex(publicKeyBytesHex),
    });

export const createMlDsaKeyPairFixture = (
    seedLabel: string,
): MlDsaKeyPairFixture => {
    const seed = deriveProtocolDigest('ProviderBuildDigest', {
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
        publicKeyBytesHex: normalizeHex(signature.publicKeyBytesHex),
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex: normalizeHex(signature.signatureBytesHex),
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
        normalizeHex(input.secretKeyBytesHex),
        mlDsa65SecretKeyByteLength,
        'secretKeyBytesHex',
    );
    const message = canonicalSignedRootMessage(input.signedRoot);
    const signatureBytes = ml_dsa65.sign(message, secretKey, {
        context: textEncoder.encode(input.profile.contextString),
        extraEntropy: false,
    });
    const signature = {
        profile: input.profile,
        publicKeyBytesHex: normalizeHex(input.publicKeyBytesHex),
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
        signature.profile.providerBuildHash.length === 0 ||
        signature.profile.fips204Version.length === 0 ||
        signature.profile.errataStatus.length === 0
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignature',
            'Signature profile metadata must be fully bound.',
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
            normalizeHex(signature.publicKeyBytesHex),
            mlDsa65PublicKeyByteLength,
            'publicKeyBytesHex',
        );
        decodeHexField(
            normalizeHex(signature.signatureBytesHex),
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
        normalizeHex(signature.publicKeyBytesHex),
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
        'manifestHash',
        'boardHeadHash',
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
        (signedRoot.objectRoot !== null && !objectRootPresent) ||
        (signedRoot.chunkMerkleRoot !== null && !chunkMerkleRootPresent) ||
        (signedRoot.manifestHash !== null &&
            typeof signedRoot.manifestHash !== 'string') ||
        (signedRoot.boardHeadHash !== null &&
            typeof signedRoot.boardHeadHash !== 'string')
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
        expectation.manifestHash !== undefined &&
        signedRoot.manifestHash !== expectation.manifestHash
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
        expectation.boardHeadHash !== undefined &&
        signedRoot.boardHeadHash !== expectation.boardHeadHash
    ) {
        return emptySignatureVerificationResult(
            'InvalidSignedRoot',
            'Signature root board-head digest does not match the expected head.',
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

export const verifySignedObjectSignature = (
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
        publicKeyBytesHex: normalizeHex(signature.publicKeyBytesHex),
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex: normalizeHex(signature.signatureBytesHex),
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
        normalizeHex(signature.publicKeyBytesHex),
        mlDsa65PublicKeyByteLength,
        'publicKeyBytesHex',
    );
    const signatureBytes = decodeHexField(
        normalizeHex(signature.signatureBytesHex),
        mlDsa65SignatureByteLength,
        'signatureBytesHex',
    );
    const signatureValid = ml_dsa65.verify(
        signatureBytes,
        canonicalSignedRootMessage(signature.signedRoot),
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
